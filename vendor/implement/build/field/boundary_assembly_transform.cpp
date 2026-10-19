#include "atfield/boundary_assembly_transform.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixup.h"
#if __has_include("llvm/MC/MCFixupKindInfo.h")
#include "llvm/MC/MCFixupKindInfo.h"
#endif
#include "llvm/MC/MCDirectives.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectStreamer.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/MCValue.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace llvm {
class MCStreamer;
class MCTargetStreamer;
class MCSubtargetInfo;
MCTargetStreamer *createX86ObjectTargetStreamer(MCStreamer &,
                                                const MCSubtargetInfo &);
} // namespace llvm

namespace atfield::boundary {
using namespace llvm;
namespace {

struct ReservedName {
  enum class Kind : std::uint8_t {
    None,
    Marker,
    After,
    Body,
    Pretouch,
    Unknown
  } kind{Kind::None};
  std::uint64_t id = 0;
};

struct FieldState {
  std::uint64_t id = 0;
  std::string marker;
  std::string after;
  std::string body;
  std::string pretouch;
  unsigned marker_hidden = 0;
  unsigned marker_calls = 0;
  unsigned body_global = 0;
  unsigned body_hidden = 0;
  unsigned body_labels = 0;
  unsigned body_first_instruction = 0;
  unsigned empty_body_close = 0;
  bool body_awaiting_instruction = false;
  bool body_saw_temporary_label = false;
  MCSection *marker_section = nullptr;
  MCSection *after_section = nullptr;
};

} // namespace

static bool decimal_id(StringRef suffix, std::uint64_t &id) {
  if (suffix.empty() || (suffix.size() > 1 && suffix.front() == '0')) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char c : suffix) {
    if (c < '0' || c > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<unsigned>(c - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
      return false;
    }
    value = (value * 10) + digit;
  }
  id = value;
  return value != 0;
}

static ReservedName reserved_name(StringRef name) {
  struct Prefix {
    StringRef text;
    ReservedName::Kind kind{ReservedName::Kind::None};
  };
  static constexpr Prefix prefixes[] = {
      {.text = "__atfield_marker_", .kind = ReservedName::Kind::Marker},
      {.text = "__atfield_after_marker_", .kind = ReservedName::Kind::After},
      {.text = "__atfield_body_", .kind = ReservedName::Kind::Body},
      {.text = "__atfield_pretouch_", .kind = ReservedName::Kind::Pretouch},
  };
  for (const Prefix &prefix : prefixes) {
    if (name.starts_with(prefix.text)) {
      std::uint64_t id = 0;
      if (!decimal_id(name.drop_front(prefix.text.size()), id)) {
        return {.kind = ReservedName::Kind::Unknown, .id = 0};
      }
      return {.kind = prefix.kind, .id = id};
    }
  }
  return {.kind = ReservedName::Kind::None, .id = 0};
}

static Error invalid(StringRef message) {
  return createStringError(inconvertibleErrorCode(), "boundary assembly: %s",
                           message.str().c_str());
}

namespace {

class StructuredStreamer final : public MCELFStreamer {
  const MCInstrInfo &InstrInfo;
  MCCodeEmitter *const Emitter;
  MCAsmBackend *const Backend;
  const MCSubtargetInfo &Subtarget;
  std::vector<FieldState> Fields;
  StringMap<unsigned> Names;
  std::string Failure;
  unsigned MarkerOpcode = 0;
  unsigned JumpOpcode = 0;
  bool Synthetic = false;
  bool ScanningExpression = false;

  FieldState *field_for_name(StringRef name, ReservedName *kind = nullptr) {
    const ReservedName parsed = reserved_name(name);
    if (kind != nullptr) {
      *kind = parsed;
    }
    if (parsed.kind == ReservedName::Kind::None ||
        parsed.kind == ReservedName::Kind::Unknown) {
      return nullptr;
    }
    auto it = Names.find(name);
    return it == Names.end() ? nullptr : &Fields[it->second];
  }

  const FieldState *field_for_name(StringRef name,
                                   ReservedName *kind = nullptr) const {
    const ReservedName parsed = reserved_name(name);
    if (kind != nullptr) {
      *kind = parsed;
    }
    if (parsed.kind == ReservedName::Kind::None ||
        parsed.kind == ReservedName::Kind::Unknown) {
      return nullptr;
    }
    auto it = Names.find(name);
    return it == Names.end() ? nullptr : &Fields[it->second];
  }

  void fail(StringRef message) {
    if (Failure.empty()) {
      Failure = message.str();
    }
  }

  [[nodiscard]] bool failed() const { return !Failure.empty(); }

  void scan_expr(const MCExpr *expr) {
    if (expr == nullptr || failed()) {
      return;
    }
    ScanningExpression = true;
    MCStreamer::visitUsedExpr(*expr);
    ScanningExpression = false;
  }

  [[nodiscard]] bool body_prefix_event() const {
    return llvm::any_of(Fields, [](const FieldState &field) {
      return field.body_awaiting_instruction;
    });
  }

  FieldState *awaiting_body() {
    for (FieldState &field : Fields) {
      if (field.body_awaiting_instruction) {
        return &field;
      }
    }
    return nullptr;
  }

  static bool is_matching_normal_close(StringRef name,
                                       const FieldState &field) {
    constexpr StringLiteral prefix{"__atfield_normal_close_"};
    std::uint64_t id = 0;
    return name.starts_with(prefix) &&
           decimal_id(name.drop_front(prefix.size()), id) && id == field.id;
  }

  [[nodiscard]] bool valid_opcode(unsigned opcode, StringRef name) const {
    return opcode < InstrInfo.getNumOpcodes() &&
           InstrInfo.getName(opcode) == name;
  }

  bool prove_encoding(const MCInst &inst, uint8_t first_byte,
                      const MCSymbol *target, bool require_none) {
    SmallVector<char, 16> encoded;
    SmallVector<MCFixup, 2> fixups;
    Emitter->encodeInstruction(inst, encoded, fixups, Subtarget);
    if (encoded.size() != 5 || fixups.size() != 1 ||
        static_cast<uint8_t>(encoded.front()) != first_byte) {
      return false;
    }
    bool is_pc_rel = false;
    is_pc_rel = fixups.front().isPCRel();
    if (fixups.front().getOffset() != 1 ||
        Backend->getFixupKindInfo(fixups.front().getKind()).TargetSize != 32 ||
        !is_pc_rel) {
      return false;
    }
    MCValue value;
    bool evaluated = false;
    evaluated =
        fixups.front().getValue()->evaluateAsRelocatable(value, nullptr);
    if (!evaluated) {
      return false;
    }
    const MCSymbol *symbol = value.getAddSym();
    const auto *sub_symbol = value.getSubSym();
    return symbol != nullptr && sub_symbol == nullptr &&
           value.getConstant() == 0 && symbol == target &&
           (!require_none || value.getSpecifier() == 0);
  }

  static bool is_plain_symbol_ref(const MCSymbolRefExpr *expr) {
    return expr->getSpecifier() == 0;
  }

  bool is_plt_symbol_ref(const MCSymbolRefExpr *expr) const {
    const std::optional<uint32_t> plt_specifier =
        getContext().getAsmInfo()->getSpecifierForName("PLT");
    return plt_specifier && expr->getSpecifier() == *plt_specifier;
  }

  static const MCSymbolRefExpr *create_plain_symbol_ref(const MCSymbol *symbol,
                                                        MCContext &context,
                                                        SMLoc loc) {
    return MCSymbolRefExpr::create(symbol, context, loc);
  }

  void emit_synthetic_attribute(MCSymbol *symbol, MCSymbolAttr attr) {
    Synthetic = true;
    MCELFStreamer::emitSymbolAttribute(symbol, attr);
    Synthetic = false;
  }

  void emit_synthetic_label(MCSymbol *symbol, SMLoc loc) {
    Synthetic = true;
    MCELFStreamer::emitLabel(symbol, loc);
    Synthetic = false;
  }

  void emit_replacement(FieldState &field, const MCInst &original,
                        const MCSubtargetInfo &sti) {
    const MCSymbol *pretouch = getContext().getOrCreateSymbol(field.pretouch);
    MCInst jump;
    jump.setOpcode(JumpOpcode);
    jump.setLoc(original.getLoc());
    jump.setFlags(original.getFlags());
    jump.addOperand(MCOperand::createExpr(
        create_plain_symbol_ref(pretouch, getContext(), original.getLoc())));
    if (!prove_encoding(jump, 0xe9, pretouch, true)) {
      fail("replacement is not an E9 rel32 jump");
      return;
    }
    MCELFStreamer::emitInstruction(jump, sti);
    MCSymbol *after = getContext().getOrCreateSymbol(field.after);
    emit_synthetic_attribute(after, MCSA_Global);
    emit_synthetic_attribute(after, MCSA_Hidden);
    emit_synthetic_label(after, original.getLoc());
    field.after_section = getCurrentSectionOnly();
  }

public:
  StructuredStreamer(MCContext &context, std::unique_ptr<MCAsmBackend> backend,
                     std::unique_ptr<MCObjectWriter> writer,
                     std::unique_ptr<MCCodeEmitter> emitter,
                     const MCInstrInfo &instr_info,
                     MCCodeEmitter *emitter_for_proof,
                     MCAsmBackend *backend_for_proof,
                     const MCSubtargetInfo &subtarget,
                     std::vector<FieldState> fields)
      : MCELFStreamer(context, std::move(backend), std::move(writer),
                      std::move(emitter)),
        InstrInfo(instr_info), Emitter(emitter_for_proof),
        Backend(backend_for_proof), Subtarget(subtarget),
        Fields(std::move(fields)) {
    for (unsigned index = 0; index < Fields.size(); ++index) {
      Names[Fields[index].marker] = index;
      Names[Fields[index].after] = index;
      Names[Fields[index].body] = index;
      Names[Fields[index].pretouch] = index;
    }
    for (unsigned opcode = 0; opcode < InstrInfo.getNumOpcodes(); ++opcode) {
      if (InstrInfo.getName(opcode) == "CALL64pcrel32") {
        MarkerOpcode = opcode;
      }
      if (InstrInfo.getName(opcode) == "JMP_4") {
        JumpOpcode = opcode;
      }
    }
    if (MarkerOpcode == 0U || JumpOpcode == 0U) {
      fail("x86 marker or jump opcode is unavailable");
    }
  }

  [[nodiscard]] StringRef failure() const { return Failure; }

  void visitUsedSymbol(const MCSymbol &symbol) override {
    if (ScanningExpression) {
      ReservedName kind;
      const FieldState *field = field_for_name(symbol.getName(), &kind);
      if (kind.kind == ReservedName::Kind::Unknown || field == nullptr) {
        if (kind.kind != ReservedName::Kind::None) {
          fail("unknown or noncanonical reserved expression");
        }
      } else if (kind.kind != ReservedName::Kind::None) {
        fail("reserved expression is not permitted here");
      }
    }
    MCELFStreamer::visitUsedSymbol(symbol);
  }

  bool emitSymbolAttribute(MCSymbol *symbol, MCSymbolAttr attribute) override {
    ReservedName kind;
    FieldState *field = field_for_name(symbol->getName(), &kind);
    if (kind.kind == ReservedName::Kind::None) {
      return MCELFStreamer::emitSymbolAttribute(symbol, attribute);
    }
    if (kind.kind == ReservedName::Kind::Unknown || field == nullptr) {
      fail("unknown or noncanonical reserved symbol attribute");
      return false;
    }
    if (kind.kind == ReservedName::Kind::Marker) {
      if (attribute == MCSA_Hidden && !Synthetic) {
        ++field->marker_hidden;
        return true;
      }
      fail("marker has an unsupported or duplicate attribute");
      return false;
    }
    if (kind.kind == ReservedName::Kind::Body && !Synthetic) {
      if (body_prefix_event()) {
        fail("body attribute occurs after a body label");
      } else if (attribute == MCSA_Global) {
        ++field->body_global;
      } else if (attribute == MCSA_Hidden) {
        ++field->body_hidden;
      } else {
        fail("body has an unsupported attribute");
      }
      if (failed()) {
        return false;
      }
      return MCELFStreamer::emitSymbolAttribute(symbol, attribute);
    }
    fail("after or pretouch has an input attribute");
    return false;
  }

  void emitLabel(MCSymbol *symbol, SMLoc loc = SMLoc()) override {
    ReservedName kind;
    FieldState *field = field_for_name(symbol->getName(), &kind);
    if (kind.kind == ReservedName::Kind::None) {
      if (FieldState *body = awaiting_body();
          body != nullptr &&
          is_matching_normal_close(symbol->getName(), *body) &&
          !body->body_saw_temporary_label) {
        body->body_awaiting_instruction = false;
        ++body->empty_body_close;
        MCELFStreamer::emitLabel(symbol, loc);
        return;
      }
      if (FieldState *body = awaiting_body();
          body != nullptr && symbol->isTemporary()) {
        body->body_saw_temporary_label = true;
      }
      if (body_prefix_event() && !symbol->isTemporary()) {
        fail(("nonlocal label '" + symbol->getName() +
              "' occurs before the first body instruction")
                 .str());
        return;
      }
      MCELFStreamer::emitLabel(symbol, loc);
      return;
    }
    if (kind.kind == ReservedName::Kind::Unknown || field == nullptr) {
      fail("unknown or noncanonical reserved label");
      return;
    }
    if (Synthetic) {
      MCELFStreamer::emitLabel(symbol, loc);
      return;
    }
    if (kind.kind == ReservedName::Kind::Body) {
      if (field->body_labels != 0 || field->body_global != 1 ||
          field->body_hidden != 1 || body_prefix_event()) {
        fail("body label event order or multiplicity is invalid");
        return;
      }
      ++field->body_labels;
      field->body_awaiting_instruction = true;
      MCELFStreamer::emitLabel(symbol, loc);
      return;
    }
    fail("input marker, after, or pretouch label is forbidden");
  }

  void emitLabelAtPos(MCSymbol *symbol, SMLoc loc, MCFragment &fragment,
                      uint64_t offset) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved label-at-position event is forbidden");
      return;
    }
    MCELFStreamer::emitLabelAtPos(symbol, loc, fragment, offset);
  }

  void emitInstruction(const MCInst &inst,
                       const MCSubtargetInfo &sti) override {
    if (failed()) {
      MCELFStreamer::emitInstruction(inst, sti);
      return;
    }
    if (FieldState *body = awaiting_body()) {
      body->body_awaiting_instruction = false;
      body->body_saw_temporary_label = false;
      ++body->body_first_instruction;
    }
    const bool opcode_is_marker =
        valid_opcode(inst.getOpcode(), "CALL64pcrel32");
    const auto *symbol_expr =
        opcode_is_marker && inst.getNumOperands() == 1 &&
                inst.getOperand(0).isExpr()
            ? dyn_cast<MCSymbolRefExpr>(inst.getOperand(0).getExpr())
            : nullptr;
    ReservedName kind;
    FieldState *field =
        symbol_expr != nullptr
            ? field_for_name(symbol_expr->getSymbol().getName(), &kind)
            : nullptr;
    if (opcode_is_marker && symbol_expr != nullptr && field != nullptr &&
        kind.kind == ReservedName::Kind::Marker &&
        (is_plain_symbol_ref(symbol_expr) || is_plt_symbol_ref(symbol_expr))) {
      if (field->body_labels != 0 || field->body_first_instruction != 0) {
        fail("marker occurs after the body");
        return;
      }
      if (field->marker_calls++ != 0 || field->marker_section != nullptr) {
        fail("marker call is duplicated");
      }
      field->marker_section = getCurrentSectionOnly();
      if (field->marker_section == nullptr ||
          !prove_encoding(inst, 0xe8, &symbol_expr->getSymbol(), false)) {
        fail("marker is not an E8 rel32 call");
        return;
      }
      emit_replacement(*field, inst, sti);
      return;
    }
    for (unsigned operand = 0; operand < inst.getNumOperands(); ++operand) {
      if (inst.getOperand(operand).isExpr()) {
        scan_expr(inst.getOperand(operand).getExpr());
      }
    }
    if (symbol_expr != nullptr && field != nullptr &&
        kind.kind != ReservedName::Kind::None) {
      fail("reserved reference is not a canonical marker call");
    }
    MCELFStreamer::emitInstruction(inst, sti);
  }

  void changeSection(MCSection *section, uint32_t subsection) override {
    if (body_prefix_event()) {
      fail("section change splits the body prefix");
      return;
    }
    MCELFStreamer::changeSection(section, subsection);
  }

  void emitBytes(StringRef data) override {
    if (body_prefix_event()) {
      fail("bytes occur before the first body instruction");
      return;
    }
    MCELFStreamer::emitBytes(data);
  }

  void emitBinaryData(StringRef data) override {
    if (body_prefix_event()) {
      fail("binary data occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitBinaryData(data);
  }

  void emitValueImpl(const MCExpr *value, unsigned size,
                     SMLoc loc = SMLoc()) override {
    scan_expr(value);
    if (body_prefix_event()) {
      fail("value occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitValueImpl(value, size, loc);
  }

  void emitRelocDirective(const MCExpr &offset, StringRef name,
                          const MCExpr *expr, SMLoc loc) override {
    scan_expr(&offset);
    scan_expr(expr);
    if (failed()) {
      return;
    }
    if (body_prefix_event()) {
      fail("relocation directive occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitRelocDirective(offset, name, expr, loc);
  }

  void emitIntValue(uint64_t value, unsigned size) override {
    if (body_prefix_event()) {
      fail("integer data occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitIntValue(value, size);
  }

  void emitIntValue(const APInt &value) override {
    if (body_prefix_event()) {
      fail("integer data occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitIntValue(value);
  }

  void emitULEB128Value(const MCExpr *value) override {
    scan_expr(value);
    if (body_prefix_event()) {
      fail("ULEB data occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitULEB128Value(value);
  }

  void emitSLEB128Value(const MCExpr *value) override {
    scan_expr(value);
    if (body_prefix_event()) {
      fail("SLEB data occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitSLEB128Value(value);
  }

  void emitFill(const MCExpr &num_bytes, uint64_t fill_value,
                SMLoc loc = SMLoc()) override {
    scan_expr(&num_bytes);
    if (body_prefix_event()) {
      fail("fill occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitFill(num_bytes, fill_value, loc);
  }

  void emitFill(const MCExpr &num_values, int64_t size, int64_t expr,
                SMLoc loc = SMLoc()) override {
    scan_expr(&num_values);
    if (body_prefix_event()) {
      fail("fill occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitFill(num_values, size, expr, loc);
  }

  void emitValueToAlignment(Align alignment, int64_t value, uint8_t value_size,
                            unsigned max_bytes_to_emit) override {
    if (body_prefix_event() && alignment.value() != 1) {
      fail("alignment occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitValueToAlignment(alignment, value, value_size,
                                        max_bytes_to_emit);
  }

  void emitCodeAlignment(Align alignment, const MCSubtargetInfo *sti,
                         unsigned max_bytes_to_emit = 0) override {
    if (body_prefix_event() && alignment.value() != 1) {
      fail("code alignment occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitCodeAlignment(alignment, sti, max_bytes_to_emit);
  }

  void emitNops(int64_t num_bytes, int64_t controlled_nop_length, SMLoc loc,
                const MCSubtargetInfo &sti) override {
    if (body_prefix_event() && num_bytes != 0) {
      fail("nop padding occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitNops(num_bytes, controlled_nop_length, loc, sti);
  }

  void emitZerofill(MCSection *section, MCSymbol *symbol = nullptr,
                    uint64_t size = 0, Align alignment = Align(1),
                    SMLoc loc = SMLoc()) override {
    if (symbol != nullptr) {
      ReservedName kind;
      if (field_for_name(symbol->getName(), &kind) != nullptr ||
          kind.kind != ReservedName::Kind::None) {
        fail("reserved zerofill symbol");
      }
    }
    if (body_prefix_event()) {
      fail("zerofill occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitZerofill(section, symbol, size, alignment, loc);
  }

  void emitCommonSymbol(MCSymbol *symbol, uint64_t size,
                        Align alignment) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved common symbol");
    }
    if (body_prefix_event()) {
      fail("common storage occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitCommonSymbol(symbol, size, alignment);
  }

  void emitLocalCommonSymbol(MCSymbol *symbol, uint64_t size,
                             Align alignment) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved local common symbol");
    }
    if (body_prefix_event()) {
      fail("common storage occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitLocalCommonSymbol(symbol, size, alignment);
  }

  void emitTBSSSymbol(MCSection *section, MCSymbol *symbol, uint64_t size,
                      Align alignment = Align(1)) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved TBSS symbol");
    }
    if (body_prefix_event()) {
      fail("TBSS storage occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitTBSSSymbol(section, symbol, size, alignment);
  }

  void emitAssignment(MCSymbol *symbol, const MCExpr *value) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved assignment target");
    }
    scan_expr(value);
    if (body_prefix_event()) {
      fail("assignment occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitAssignment(symbol, value);
  }

  void emitConditionalAssignment(MCSymbol *symbol,
                                 const MCExpr *value) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved conditional assignment target");
    }
    scan_expr(value);
    if (body_prefix_event()) {
      fail("assignment occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitConditionalAssignment(symbol, value);
  }

  void emitELFSize(MCSymbol *symbol, const MCExpr *value) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved ELF size symbol");
    }
    scan_expr(value);
    if (body_prefix_event()) {
      fail("ELF size occurs before the first body instruction");
      return;
    }
    MCELFStreamer::emitELFSize(symbol, value);
  }

  void emitWeakReference(MCSymbol *alias, const MCSymbol *symbol) override {
    ReservedName alias_kind;
    ReservedName symbol_kind;
    if ((field_for_name(alias->getName(), &alias_kind) != nullptr ||
         alias_kind.kind != ReservedName::Kind::None) ||
        (field_for_name(symbol->getName(), &symbol_kind) != nullptr ||
         symbol_kind.kind != ReservedName::Kind::None)) {
      fail("reserved weak reference");
    }
    MCELFStreamer::emitWeakReference(alias, symbol);
  }

  void emitCGProfileEntry(const MCSymbolRefExpr *from,
                          const MCSymbolRefExpr *to, uint64_t count) override {
    scan_expr(from);
    scan_expr(to);
    MCELFStreamer::emitCGProfileEntry(from, to, count);
  }

  void emitSymbolDesc(MCSymbol *symbol, unsigned desc) override {
    ReservedName kind;
    if (field_for_name(symbol->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None) {
      fail("reserved symbol descriptor");
    }
    MCELFStreamer::emitSymbolDesc(symbol, desc);
  }

  void emitELFSymverDirective(const MCSymbol *original, StringRef name,
                              bool keep_original) override {
    ReservedName kind;
    if (field_for_name(original->getName(), &kind) != nullptr ||
        kind.kind != ReservedName::Kind::None ||
        reserved_name(name).kind != ReservedName::Kind::None) {
      fail("reserved ELF symbol version");
    }
    MCELFStreamer::emitELFSymverDirective(original, name, keep_original);
  }

  bool validate_fields() {
    for (const FieldState &field : Fields) {
      if (field.marker_hidden != 1 || field.marker_calls != 1 ||
          field.body_global != 1 || field.body_hidden != 1 ||
          field.body_labels != 1 ||
          field.body_first_instruction + field.empty_body_close != 1 ||
          field.body_awaiting_instruction || field.after_section == nullptr ||
          field.after_section != field.marker_section) {
        fail("field event counts or section adjacency are invalid");
      }
    }
    return !failed();
  }
};

} // namespace

static Expected<std::vector<FieldState>>
make_fields(ArrayRef<BoundaryAssemblyField> input) {
  std::vector<FieldState> result;
  result.reserve(input.size());
  for (const BoundaryAssemblyField &source : input) {
    if (source.field_id == 0) {
      return invalid("field id is not canonical");
    }
    const std::string suffix = std::to_string(source.field_id);
    FieldState field;
    field.id = source.field_id;
    field.marker = "__atfield_marker_" + suffix;
    field.after = "__atfield_after_marker_" + suffix;
    field.body = "__atfield_body_" + suffix;
    field.pretouch = "__atfield_pretouch_" + suffix;
    if (source.after_marker != field.after || source.body != field.body) {
      return invalid("field name is not canonical");
    }
    for (const FieldState &existing : result) {
      if (existing.id == field.id || existing.marker == field.marker ||
          existing.after == field.after || existing.body == field.body ||
          existing.pretouch == field.pretouch) {
        return invalid("field id or name is duplicated");
      }
    }
    result.push_back(std::move(field));
  }
  return result;
}

Expected<std::vector<std::uint8_t>>
transform_boundary_assembly(StringRef assembly,
                            ArrayRef<BoundaryAssemblyField> fields) {
  auto states_or_error = make_fields(fields);
  if (!states_or_error) {
    return states_or_error.takeError();
  }

  if (InitializeNativeTarget() || InitializeNativeTargetAsmParser()) {
    return invalid("native x86 target support is unavailable");
  }

  const std::string triple_name = "x86_64-unknown-linux-gnu";
  const Triple triple(triple_name);
  std::string target_error;
  const Target *target = TargetRegistry::lookupTarget(triple, target_error);
  if (target == nullptr) {
    return invalid(target_error);
  }
  if (triple.getArch() != Triple::x86_64 || !triple.isOSBinFormatELF()) {
    return invalid("target is not x86_64 ELF");
  }

  SourceMgr source_manager;
  auto buffer = MemoryBuffer::getMemBufferCopy(assembly, "<boundary-assembly>");
  source_manager.AddNewSourceBuffer(std::move(buffer), SMLoc());
  const MCTargetOptions options;
  const std::unique_ptr<MCRegisterInfo> register_info(
      target->createMCRegInfo(triple));
  if (!register_info) {
    return invalid("target register information is unavailable");
  }
  const std::unique_ptr<MCAsmInfo> asm_info(
      target->createMCAsmInfo(*register_info, triple, options));
  const std::unique_ptr<MCSubtargetInfo> subtarget_info(
      target->createMCSubtargetInfo(triple, "generic", ""));
  const std::unique_ptr<MCInstrInfo> instr_info(target->createMCInstrInfo());
  if (!asm_info || !subtarget_info || !instr_info) {
    return invalid("target MC information is unavailable");
  }
  MCContext context(triple, asm_info.get(), register_info.get(),
                    subtarget_info.get(), &source_manager, &options);
  const std::unique_ptr<MCObjectFileInfo> object_file_info(
      target->createMCObjectFileInfo(context, false, false));
  if (!object_file_info) {
    return invalid("target object-file information is unavailable");
  }
  context.setObjectFileInfo(object_file_info.get());

  MCCodeEmitter *emitter_raw =
      target->createMCCodeEmitter(*instr_info, context);
  MCAsmBackend *backend_raw =
      target->createMCAsmBackend(*subtarget_info, *register_info, options);
  if (emitter_raw == nullptr || backend_raw == nullptr) {
    return invalid("target encoder or backend is unavailable");
  }
  std::unique_ptr<MCCodeEmitter> emitter(emitter_raw);
  std::unique_ptr<MCAsmBackend> backend(backend_raw);
  SmallVector<char, 4096> object_bytes;
  raw_svector_ostream output(object_bytes);
  std::unique_ptr<MCObjectWriter> writer = backend->createObjectWriter(output);
  if (!writer) {
    return invalid("target object writer is unavailable");
  }

  auto streamer = std::make_unique<StructuredStreamer>(
      context, std::move(backend), std::move(writer), std::move(emitter),
      *instr_info, emitter_raw, backend_raw, *subtarget_info,
      std::move(*states_or_error));
  streamer->setUseAssemblerInfoForParsing(true);

  std::unique_ptr<MCAsmParser> parser(
      createMCAsmParser(source_manager, context, *streamer, *asm_info));
  if (!parser) {
    return invalid("MC parser is unavailable");
  }
  std::unique_ptr<MCTargetAsmParser> target_parser(target->createMCAsmParser(
      *subtarget_info, *parser, *instr_info, options));
  if (!target_parser) {
    return invalid("x86 target parser is unavailable");
  }
  parser->setTargetParser(*target_parser);
  const bool parser_failed = parser->Run(false, true);
  if (parser_failed || context.hadError()) {
    return invalid("assembly parser rejected input");
  }
  if (!streamer->failure().empty()) {
    return invalid(streamer->failure());
  }
  if (!streamer->validate_fields()) {
    return invalid(streamer->failure());
  }
  streamer->finish();
  if (context.hadError() || !streamer->failure().empty()) {
    return invalid("assembly finalization failed");
  }
  if (object_bytes.empty()) {
    return invalid("assembler produced no ET_REL bytes");
  }
  return std::vector<std::uint8_t>(object_bytes.begin(), object_bytes.end());
}

} // namespace atfield::boundary
