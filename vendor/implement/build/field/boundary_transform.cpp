#include "atfield/boundary_transform.h"

#include "atfield/analyze/annotation_adapter.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalIFunc.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace atfield::boundary {
namespace {

using llvm::BasicBlock;
using llvm::CallInst;
using llvm::Function;
using llvm::FunctionType;
using llvm::GlobalValue;
using llvm::InlineAsm;
using llvm::Instruction;
using llvm::LLVMContext;
using llvm::Module;
using llvm::ReturnInst;
using llvm::StringLiteral;
using llvm::StringRef;
using llvm::Type;
using llvm::Use;
using llvm::Value;

constexpr StringLiteral kFieldEnterName{"field_enter"};
constexpr StringLiteral kFieldExitName{"field_exit"};

llvm::Error invalid(StringRef message) {
  return llvm::createStringError(
      std::make_error_code(std::errc::invalid_argument), "%s",
      message.str().c_str());
}

std::string id_suffix(std::uint64_t field_id) {
  return std::to_string(field_id);
}

std::uint64_t stable_field_id(std::uint64_t payload_ordinal,
                              std::uint64_t function_ordinal) {
  constexpr std::uint64_t offset_basis = 14695981039346656037ULL;
  constexpr std::uint64_t prime = 1099511628211ULL;
  std::uint64_t hash = offset_basis;
  const auto add_u64 = [&hash](std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
      const auto byte = static_cast<std::uint8_t>(value >> shift);
      hash = (hash ^ byte) * prime;
    }
  };
  add_u64(payload_ordinal);
  add_u64(function_ordinal);
  return hash == 0 ? 1 : hash;
}

bool reserved_name(StringRef name, StringRef prefix, std::uint64_t field_id) {
  return name == prefix.str() + id_suffix(field_id);
}

llvm::Error validate_fragment_field(const BoundaryFieldFragment &field,
                                    std::uint64_t payload_ordinal) {
  if (field.field_id == 0) {
    return invalid("field_id 0 is reserved");
  }
  if (field.field_order_key.payload_ordinal != payload_ordinal) {
    return invalid("field_order_key payload ordinal drifts from fragment");
  }
  if (field.function_name.empty()) {
    return invalid("field function_name is empty");
  }
  if (field.field_enter_ir.basic_block.empty()) {
    return invalid("field_enter_ir basic_block is empty");
  }

  if (!reserved_name(field.after_marker, kAfterMarkerPrefix, field.field_id) ||
      !reserved_name(field.body, kBodyPrefix, field.field_id) ||
      !reserved_name(field.normal_close, kNormalClosePrefix, field.field_id) ||
      !reserved_name(field.field_exit, kFieldExitPrefix, field.field_id)) {
    return invalid("field has a noncanonical reserved symbol name");
  }
  return llvm::Error::success();
}

llvm::Error validate_fragment_shape(const BoundaryTransformFragment &fragment) {
  std::set<std::uint64_t> ids;
  std::set<FieldOrderKey> order_keys;
  std::set<std::string> functions;
  for (std::size_t index = 0; index != fragment.fields.size(); ++index) {
    const BoundaryFieldFragment &field = fragment.fields[index];
    if (index != 0 &&
        !(fragment.fields[index - 1].field_order_key < field.field_order_key)) {
      return invalid("fragment fields are not in FieldOrderKey order");
    }
    if (!ids.insert(field.field_id).second ||
        !order_keys.insert(field.field_order_key).second ||
        !functions.insert(field.function_name).second) {
      return invalid("fragment field identity is duplicated");
    }
    if (llvm::Error error =
            validate_fragment_field(field, fragment.payload_ordinal)) {
      return error;
    }
  }
  return llvm::Error::success();
}

struct ReservedName {
  StringLiteral text;
  bool prefix{false};
};

constexpr ReservedName kReservedNames[] = {
    {.text = "__atfield_", .prefix = true},
    {.text = "__atfield_active", .prefix = false},
    {.text = "field_enter", .prefix = false},
    {.text = "field_exit", .prefix = false},
    {.text = "__atfield_field_enter_", .prefix = true},
    {.text = "__atfield_marker_", .prefix = true},
    {.text = "__atfield_after_marker_", .prefix = true},
    {.text = "__atfield_body_", .prefix = true},
    {.text = "__atfield_normal_close_", .prefix = true},
    {.text = "__atfield_field_exit_", .prefix = true},
    {.text = "__atfield_pretouch_", .prefix = true},
    {.text = "__atfield_anchor_p", .prefix = true},
    {.text = "__atfield_native_anchor_p", .prefix = true},
};

std::string canonical_asm_name(const Module &module, StringRef name) {
  bool no_mangle = false;
  if (!name.empty() && name.front() == '\1') {
    no_mangle = true;
    name = name.drop_front();
  } else if (name.starts_with("\\01")) {
    no_mangle = true;
    name = name.drop_front(3);
  }

  std::string canonical;
  if (!no_mangle) {
    const char global_prefix = module.getDataLayout().getGlobalPrefix();
    if (global_prefix != '\0') {
      canonical.push_back(global_prefix);
    }
  }
  canonical.append(name.data(), name.size());
  return canonical;
}

bool is_reserved_asm_name(const Module &module, StringRef name) {
  const std::string canonical = canonical_asm_name(module, name);
  return llvm::any_of(kReservedNames, [&](const ReservedName &reserved) {
    const std::string reserved_name = canonical_asm_name(module, reserved.text);
    return reserved.prefix ? StringRef(canonical).starts_with(reserved_name)
                           : canonical == reserved_name;
  });
}

bool is_asm_identifier_char(char character) {
  const unsigned char value = static_cast<unsigned char>(character);
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
         (value >= '0' && value <= '9') || character == '_' ||
         character == '.' || character == '$';
}

bool is_reserved_asm_token(const Module &module, StringRef token) {
  if (!token.empty() && token.front() == '\1') {
    token = token.drop_front();
  } else if (token.starts_with("\\01")) {
    token = token.drop_front(3);
  }

  return llvm::any_of(kReservedNames, [&](const ReservedName &reserved) {
    const std::string canonical = canonical_asm_name(module, reserved.text);
    return reserved.prefix ? token.starts_with(StringRef(canonical))
                           : token == StringRef(canonical);
  });
}

bool contains_reserved_asm_name(const Module &module, StringRef assembly) {
  std::size_t index = 0;
  while (index < assembly.size()) {
    const char character = assembly[index];
    if (character == '#' || (character == '/' && index + 1 < assembly.size() &&
                             assembly[index + 1] == '/')) {
      while (index < assembly.size() && assembly[index] != '\n' &&
             assembly[index] != '\r') {
        ++index;
      }
      continue;
    }
    if (character == '/' && index + 1 < assembly.size() &&
        assembly[index + 1] == '*') {
      index += 2;
      while (index + 1 < assembly.size() &&
             (assembly[index] != '*' || assembly[index + 1] != '/')) {
        ++index;
      }
      if (index + 1 < assembly.size()) {
        index += 2;
      }
      continue;
    }
    if (character == '"' || character == '\'') {
      const char quote = character;
      ++index;
      while (index < assembly.size()) {
        if (assembly[index] == '\\') {
          index += std::min<std::size_t>(2, assembly.size() - index);
        } else if (assembly[index] == quote) {
          ++index;
          break;
        } else {
          ++index;
        }
      }
      continue;
    }

    const std::size_t token_start = index;
    if (character == '\1') {
      ++index;
    } else if (assembly.drop_front(index).starts_with("\\01")) {
      index += 3;
    } else if (is_asm_identifier_char(character)) {
      // The token starts at the current character.
    } else {
      ++index;
      continue;
    }
    if (index == assembly.size() || !is_asm_identifier_char(assembly[index])) {
      index = token_start + 1;
      continue;
    }
    while (index < assembly.size() && is_asm_identifier_char(assembly[index])) {
      ++index;
    }
    if (is_reserved_asm_token(module, assembly.slice(token_start, index))) {
      return true;
    }
  }
  return false;
}

bool contains_reserved_constant(
    const Module &module, const llvm::Constant *value,
    llvm::SmallPtrSetImpl<const llvm::Constant *> &seen) {
  std::vector<const llvm::Constant *> pending;
  if (value != nullptr) {
    pending.push_back(value);
  }
  while (!pending.empty()) {
    const llvm::Constant *current = pending.back();
    pending.pop_back();
    if (!seen.insert(current).second) {
      continue;
    }
    if (const auto *global = llvm::dyn_cast<GlobalValue>(current)) {
      if (is_reserved_asm_name(module, global->getName())) {
        return true;
      }
    }
    for (unsigned index = current->getNumOperands(); index != 0; --index) {
      if (const auto *constant =
              llvm::dyn_cast<llvm::Constant>(current->getOperand(index - 1))) {
        pending.push_back(constant);
      }
    }
  }
  return false;
}

llvm::Error reject_reserved_values(const Module &module) {
  const auto reject_name = [&module](StringRef name,
                                     StringRef kind) -> llvm::Error {
    if (is_reserved_asm_name(module, name)) {
      return invalid(("input module " + kind.str() +
                      " uses a reserved runtime name: " + name.str()));
    }
    return llvm::Error::success();
  };

  for (const Function &function : module) {
    if (llvm::Error error = reject_name(function.getName(), "global")) {
      return error;
    }
  }
  for (const llvm::GlobalVariable &global : module.globals()) {
    if (llvm::Error error = reject_name(global.getName(), "global")) {
      return error;
    }
  }
  for (const llvm::GlobalAlias &alias : module.aliases()) {
    if (llvm::Error error = reject_name(alias.getName(), "alias")) {
      return error;
    }
  }
  for (const llvm::GlobalIFunc &ifunc : module.ifuncs()) {
    if (llvm::Error error = reject_name(ifunc.getName(), "ifunc")) {
      return error;
    }
  }

  llvm::SmallPtrSet<const llvm::Constant *, 32> seen_constants;
  for (const GlobalValue &global : module.global_values()) {
    for (const Use &use : global.operands()) {
      if (const auto *constant = llvm::dyn_cast<llvm::Constant>(use.get())) {
        if (contains_reserved_constant(module, constant, seen_constants)) {
          return invalid(
              "input module constant references a reserved runtime name");
        }
      }
    }
  }

  if (contains_reserved_asm_name(module, module.getModuleInlineAsm())) {
    return invalid("input module inline assembly contains a reserved name");
  }

  for (const Function &function : module) {
    for (const Instruction &instruction : llvm::instructions(function)) {
      for (const Use &use : instruction.operands()) {
        const Value *value = use.get();
        if (const auto *constant = llvm::dyn_cast<llvm::Constant>(value)) {
          llvm::SmallPtrSet<const llvm::Constant *, 8> instruction_constants;
          if (contains_reserved_constant(module, constant,
                                         instruction_constants)) {
            return invalid(
                "input module instruction constant references a reserved "
                "runtime name");
          }
        }
        if (const auto *global =
                llvm::dyn_cast<GlobalValue>(value->stripPointerCasts())) {
          if (is_reserved_asm_name(module, global->getName())) {
            return invalid(
                "input module instruction references a reserved runtime name");
          }
        }
        if (const auto *inline_asm = llvm::dyn_cast<InlineAsm>(value)) {
          if (contains_reserved_asm_name(module, inline_asm->getAsmString())) {
            return invalid(
                "input module function-local inline assembly contains a "
                "reserved name");
          }
        }
      }
    }
  }
  return llvm::Error::success();
}

llvm::Error validate_function_shape(const Function &function) {
  if (function.isDeclaration() || function.empty() || function.isVarArg() ||
      function.getCallingConv() != llvm::CallingConv::C ||
      function.hasFnAttribute(llvm::Attribute::NoReturn) ||
      function.hasFnAttribute(llvm::Attribute::Naked) ||
      function.hasPersonalityFn()) {
    return invalid("annotated function has an unsupported signature");
  }
  const Type *return_type = function.getReturnType();
  if (return_type->isLabelTy() || return_type->isMetadataTy() ||
      return_type->isTokenTy() || return_type->isScalableTy()) {
    return invalid("annotated function has an unsupported return type");
  }

  std::size_t returns = 0;
  for (const Instruction &instruction : llvm::instructions(function)) {
    if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
      if (call->isMustTailCall() || llvm::isa<llvm::InvokeInst>(call) ||
          llvm::isa<llvm::CallBrInst>(call)) {
        return invalid("annotated function has a non-normalizable call");
      }
      if (const Function *callee = call->getCalledFunction()) {
        if (callee->getName() == kFieldEnterName ||
            callee->getName() == kFieldExitName ||
            callee->getName().starts_with("__atfield_")) {
          return invalid("annotated function already contains boundary calls");
        }
      }
      if (call->getCalledFunction() == nullptr) {
        const Value *stripped = call->getCalledOperand()->stripPointerCasts();
        if (const auto *global = llvm::dyn_cast<GlobalValue>(stripped)) {
          if (global->getName() == kFieldEnterName ||
              global->getName() == kFieldExitName ||
              global->getName().starts_with("__atfield_")) {
            return invalid("annotated function has an indirect boundary call");
          }
        }
      }
    }
    if (llvm::isa<llvm::UnreachableInst>(instruction)) {
      const auto *call =
          llvm::dyn_cast_or_null<llvm::CallBase>(instruction.getPrevNode());
      const Function *callee =
          call == nullptr ? nullptr : call->getCalledFunction();
      const StringRef callee_name =
          callee == nullptr ? StringRef() : callee->getName();
      const bool terminal_noreturn =
          call != nullptr && call->doesNotReturn() &&
          (callee_name == "abort" || callee_name == "_Exit" ||
           callee_name == "_exit" || callee_name == "exit" ||
           callee_name == "quick_exit" || callee_name == "llvm.trap" ||
           callee_name == "__assert_fail" || callee_name == "__assert_rtn" ||
           callee_name == "__stack_chk_fail");
      if (!terminal_noreturn) {
        const std::string message =
            "annotated function " + function.getName().str() +
            " has an unsupported unreachable exit in block " +
            instruction.getParent()->getName().str() +
            " (expected a direct terminal noreturn call)";
        return invalid(message);
      }
      // This path ends the enclave execution (for example, the SGX tlibc
      // abort path). It has no normal continuation to return to its caller,
      // so it must remain outside the normal field_exit funnel.
      continue;
    }
    if (llvm::isa<llvm::ResumeInst>(instruction) ||
        llvm::isa<llvm::CleanupReturnInst>(instruction) ||
        llvm::isa<llvm::CatchSwitchInst>(instruction) ||
        llvm::isa<llvm::CatchReturnInst>(instruction) ||
        llvm::isa<llvm::IndirectBrInst>(instruction)) {
      const std::string message =
          "annotated function " + function.getName().str() +
          " has a non-normalizable exceptional or indirect exit";
      return invalid(message);
    }
    if (llvm::isa<llvm::ReturnInst>(instruction)) {
      ++returns;
    }
  }
  if (returns == 0) {
    return invalid("annotated function has no normal return");
  }
  return llvm::Error::success();
}

llvm::Error verify_runtime_declaration(Module &module, StringRef name,
                                       FunctionType *expected,
                                       Function *&result) {
  GlobalValue *value = module.getNamedValue(name);
  if (value == nullptr) {
    result =
        Function::Create(expected, GlobalValue::ExternalLinkage, name, &module);
    result->addFnAttr(llvm::Attribute::NoUnwind);
    return llvm::Error::success();
  }
  result = llvm::dyn_cast<Function>(value);
  if (result == nullptr || !result->isDeclaration() ||
      result->getFunctionType() != expected ||
      result->getCallingConv() != llvm::CallingConv::C ||
      result->getLinkage() != GlobalValue::ExternalLinkage ||
      result->hasFnAttribute(llvm::Attribute::NoReturn) ||
      result->hasFnAttribute(llvm::Attribute::ReadNone) ||
      result->hasFnAttribute(llvm::Attribute::ReadOnly) ||
      result->hasFnAttribute(llvm::Attribute::WriteOnly)) {
    return invalid(
        ("runtime declaration '" + name.str() + "' is incompatible"));
  }
  return llvm::Error::success();
}

CallInst *create_symbol_asm(BasicBlock *block, StringRef symbol,
                            Instruction *insert_before = nullptr) {
  LLVMContext &context = block->getContext();
  FunctionType *type = FunctionType::get(Type::getVoidTy(context), false);
  const std::string assembly = ".globl " + symbol.str() + "\n.hidden " +
                               symbol.str() + "\n" + symbol.str() + ":\n";
  InlineAsm *inline_asm = InlineAsm::get(
      type, assembly, "~{memory},~{dirflag},~{fpsr},~{flags}", true, false);
  CallInst *call = insert_before != nullptr
                       ? CallInst::Create(type, inline_asm, {}, "",
                                          insert_before->getIterator())
                       : CallInst::Create(type, inline_asm, {}, "", block);
  call->setCallingConv(llvm::CallingConv::C);
  call->addFnAttr(llvm::Attribute::NoUnwind);
  return call;
}

CallInst *create_runtime_call(BasicBlock *block, Function *runtime,
                              std::uint64_t field_id) {
  LLVMContext &context = block->getContext();
  Value *id = llvm::ConstantInt::get(Type::getInt64Ty(context), field_id);
  CallInst *call = CallInst::Create(runtime, {id}, "", block);
  call->setCallingConv(llvm::CallingConv::C);
  call->setTailCallKind(llvm::CallInst::TCK_NoTail);
  call->addFnAttr(llvm::Attribute::NoUnwind);
  return call;
}

CallInst *create_marker_call(BasicBlock *block, Function *marker) {
  CallInst *call = CallInst::Create(marker, {}, "", block);
  call->setCallingConv(llvm::CallingConv::C);
  call->setTailCallKind(llvm::CallInst::TCK_NoTail);
  call->addFnAttr(llvm::Attribute::NoUnwind);
  return call;
}

llvm::Expected<FieldEnterIRIdentity> transform_function(Function &function,
                                                        std::uint64_t field_id,
                                                        Function *field_enter,
                                                        Function *field_exit,
                                                        Module &module) {
  if (llvm::Error error = validate_function_shape(function)) {
    return error;
  }
  LLVMContext &context = module.getContext();
  const std::string id = id_suffix(field_id);
  BasicBlock *body = &function.getEntryBlock();
  body->setName("atfield.body." + id);
  BasicBlock *entry =
      BasicBlock::Create(context, "atfield.entry." + id, &function, body);

  const std::string marker_name = kMarkerPrefix.str() + id;
  const std::string field_enter_name = kFieldEnterPrefix.str() + id;
  const std::string body_name = kBodyPrefix.str() + id;
  const std::string close_name = kNormalClosePrefix.str() + id;
  const std::string exit_name = kFieldExitPrefix.str() + id;

  FunctionType *marker_type =
      FunctionType::get(Type::getVoidTy(context), false);
  Function *marker = Function::Create(marker_type, GlobalValue::ExternalLinkage,
                                      marker_name, &module);
  marker->setVisibility(GlobalValue::HiddenVisibility);
  marker->addFnAttr(llvm::Attribute::NoUnwind);

  BasicBlock *marker_block =
      BasicBlock::Create(context, "atfield.marker." + id, &function, body);
  // Keep the original entry block in place as the body so its existing
  // terminators and PHI predecessor labels remain valid. The marker path is a
  // new predecessor; on the original function-entry path a PHI had no
  // predecessor value, so preserve that undefined initial value explicitly.
  for (llvm::PHINode &phi : body->phis()) {
    phi.addIncoming(llvm::UndefValue::get(phi.getType()), marker_block);
  }
  BasicBlock *close_block =
      BasicBlock::Create(context, "atfield.normal-close." + id, &function);
  BasicBlock *exit_block =
      BasicBlock::Create(context, "atfield.field-exit." + id, &function);
  BasicBlock *return_block =
      BasicBlock::Create(context, "atfield.return." + id, &function);

  std::vector<std::pair<BasicBlock *, Value *>> returns;
  for (BasicBlock &block : function) {
    if (&block == entry || &block == marker_block || &block == close_block ||
        &block == exit_block || &block == return_block ||
        block.getTerminator() == nullptr) {
      continue;
    }
    if (auto *return_instruction =
            llvm::dyn_cast<ReturnInst>(block.getTerminator())) {
      Value *return_value = return_instruction->getReturnValue();
      if (!function.getReturnType()->isVoidTy() && return_value == nullptr) {
        return invalid("annotated function has a value-less return");
      }
      returns.emplace_back(&block, return_value);
    }
  }
  if (returns.empty()) {
    return invalid("annotated function has no normal return");
  }
  if (returns.size() > std::numeric_limits<unsigned>::max()) {
    return invalid("annotated function has too many normal returns");
  }
  for (const auto &return_pair : returns) {
    Instruction *terminator = return_pair.first->getTerminator();
    llvm::BranchInst::Create(close_block, terminator->getIterator());
    terminator->eraseFromParent();
  }

  llvm::PHINode *return_value = nullptr;
  if (!function.getReturnType()->isVoidTy()) {
    return_value = llvm::PHINode::Create(function.getReturnType(),
                                         static_cast<unsigned>(returns.size()),
                                         "atfield.return.value", close_block);
    for (const auto &return_pair : returns) {
      return_value->addIncoming(return_pair.second, return_pair.first);
    }
  }

  create_symbol_asm(entry, field_enter_name);
  CallInst *enter_call = create_runtime_call(entry, field_enter, field_id);
  llvm::BranchInst::Create(marker_block, entry);

  create_marker_call(marker_block, marker);
  llvm::BranchInst::Create(body, marker_block);

  auto body_insert = body->getFirstNonPHIOrDbgOrLifetime();
  if (body_insert == body->end()) {
    return invalid("annotated function body has no insertion point");
  }
  create_symbol_asm(body, body_name, &*body_insert);

  create_symbol_asm(close_block, close_name);
  llvm::BranchInst::Create(exit_block, close_block);

  create_symbol_asm(exit_block, exit_name);
  create_runtime_call(exit_block, field_exit, field_id);
  llvm::BranchInst::Create(return_block, exit_block);

  if (return_value != nullptr) {
    llvm::ReturnInst::Create(context, return_value, return_block);
  } else {
    llvm::ReturnInst::Create(context, return_block);
  }

  std::uint64_t ordinal = 0;
  bool found = false;
  FieldEnterIRIdentity identity;
  for (const BasicBlock &block : function) {
    for (const Instruction &instruction : block) {
      if (&instruction == enter_call) {
        identity.basic_block = block.getName().str();
        identity.instruction_ordinal = ordinal;
        found = true;
      }
      if (ordinal == std::numeric_limits<std::uint64_t>::max()) {
        return invalid("field_enter instruction ordinal overflows");
      }
      ++ordinal;
    }
  }
  if (!found) {
    return invalid("generated field_enter call is missing from transformed IR");
  }
  return identity;
}

} // namespace

llvm::Expected<BoundaryTransformFragment>
transform_module(Module &module, const BoundaryTransformOptions &options) {
  if (llvm::Error error = reject_reserved_values(module)) {
    return error;
  }

  auto annotations = atfield::analyze::AnnotationAdapter::discover(module);
  if (!annotations) {
    return annotations.takeError();
  }
  std::sort(annotations->begin(), annotations->end(),
            [](const auto &left, const auto &right) {
              return left.definition_ordinal < right.definition_ordinal;
            });

  std::vector<std::uint64_t> field_ids;
  field_ids.reserve(annotations->size());
  std::set<std::uint64_t> unique_ids;
  for (const auto &annotation : *annotations) {
    const std::uint64_t field_id =
        stable_field_id(options.payload_ordinal, annotation.definition_ordinal);
    if (!unique_ids.insert(field_id).second) {
      return invalid("stable Field ID collision within payload");
    }
    field_ids.push_back(field_id);
  }

  for (const auto &annotation : *annotations) {
    Function *function = module.getFunction(annotation.function_name);
    if (function == nullptr) {
      return invalid("annotation function is missing from module");
    }
    if (llvm::Error error = validate_function_shape(*function)) {
      return error;
    }
  }

  Function *field_enter = nullptr;
  Function *field_exit = nullptr;
  LLVMContext &context = module.getContext();
  FunctionType *field_enter_type = FunctionType::get(
      Type::getVoidTy(context), {Type::getInt64Ty(context)}, false);
  FunctionType *field_exit_type = FunctionType::get(
      Type::getVoidTy(context), {Type::getInt64Ty(context)}, false);
  if (!annotations->empty()) {
    if (llvm::Error error = verify_runtime_declaration(
            module, kFieldEnterName, field_enter_type, field_enter)) {
      return error;
    }
    if (llvm::Error error = verify_runtime_declaration(
            module, kFieldExitName, field_exit_type, field_exit)) {
      return error;
    }
  }

  std::vector<FieldEnterIRIdentity> identities;
  identities.reserve(annotations->size());
  for (std::size_t index = 0; index != annotations->size(); ++index) {
    Function *function =
        module.getFunction((*annotations)[index].function_name);
    auto identity = transform_function(*function, field_ids[index], field_enter,
                                       field_exit, module);
    if (!identity) {
      return identity.takeError();
    }
    identities.push_back(std::move(*identity));
  }

  std::string verification_text;
  llvm::raw_string_ostream verification_stream(verification_text);
  if (llvm::verifyModule(module, &verification_stream)) {
    return invalid(("transformed module failed LLVM verification: " +
                    verification_stream.str()));
  }

  BoundaryTransformFragment fragment;
  fragment.payload_ordinal = options.payload_ordinal;
  fragment.fields.reserve(annotations->size());
  for (std::size_t index = 0; index != annotations->size(); ++index) {
    const std::uint64_t field_id = field_ids[index];
    const std::string id = id_suffix(field_id);
    fragment.fields.push_back(
        {.field_id = field_id,
         .field_order_key = {.payload_ordinal = options.payload_ordinal,
                             .function_ordinal =
                                 (*annotations)[index].definition_ordinal},
         .stack_bytes = (*annotations)[index].stack_bytes,
         .function_name = (*annotations)[index].function_name,
         .field_enter_ir = identities[index],
         .after_marker = kAfterMarkerPrefix.str() + id,
         .body = kBodyPrefix.str() + id,
         .normal_close = kNormalClosePrefix.str() + id,
         .field_exit = kFieldExitPrefix.str() + id});
  }
  if (llvm::Error error = validate_fragment_shape(fragment)) {
    return error;
  }
  return fragment;
}

} // namespace atfield::boundary
