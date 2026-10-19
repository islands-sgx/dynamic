#include "atfield/analyze/annotation_adapter.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <system_error>
#include <vector>

namespace atfield::analyze {
namespace {

constexpr llvm::StringLiteral kAnnotationGlobal{"llvm.global.annotations"};
constexpr llvm::StringLiteral kFieldAnnotation{"atfield.field.v1"};
constexpr llvm::StringLiteral kStackAnnotationStem{"atfield.stack_bytes.v1"};
constexpr llvm::StringLiteral kStackAnnotationPrefix{"atfield.stack_bytes.v1:"};

llvm::Error adapter_error(const char *message) {
  return llvm::createStringError(
      std::make_error_code(std::errc::invalid_argument), "%s", message);
}

llvm::Expected<llvm::StringRef>
annotation_text(const llvm::Constant *annotation_record) {
  if (annotation_record->getNumOperands() != 5) {
    return adapter_error(
        "llvm.global.annotations record has unsupported operand count");
  }

  llvm::StringRef text;
  if (!llvm::getConstantStringInfo(annotation_record->getOperand(1), text)) {
    return adapter_error(
        "llvm.global.annotations record has a non-constant annotation string");
  }
  return text;
}

llvm::Expected<std::uint64_t> parse_stack_bytes(llvm::StringRef text) {
  if (text.empty()) {
    return adapter_error("atfield stack annotation is missing its byte bound");
  }

  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return adapter_error("atfield stack annotation is not canonical decimal");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
      return adapter_error("atfield stack annotation overflows uint64");
    }
    value = (value * 10) + digit;
  }
  if (text.front() == '0' || value == 0) {
    return adapter_error(
        "atfield stack annotation must be a canonical positive decimal");
  }
  return value;
}

} // namespace

llvm::Expected<std::vector<AnnotationDefinition>>
AnnotationAdapter::discover(const llvm::Module &module) {
  llvm::DenseMap<const llvm::Function *, std::uint64_t> definition_ordinals;
  std::uint64_t next_ordinal{0};
  for (const llvm::Function &function : module) {
    if (!function.isDeclaration()) {
      if (next_ordinal == std::numeric_limits<std::uint64_t>::max()) {
        return adapter_error("function definition ordinal overflows");
      }
      definition_ordinals.try_emplace(&function, next_ordinal++);
    }
  }

  const llvm::GlobalVariable *annotations =
      module.getGlobalVariable(kAnnotationGlobal, true);
  if (annotations == nullptr) {
    return std::vector<AnnotationDefinition>{};
  }
  if (annotations->isDeclaration()) {
    return adapter_error("llvm.global.annotations is only declared");
  }

  const llvm::ConstantArray *records =
      llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (records == nullptr) {
    return adapter_error("llvm.global.annotations is not a constant array");
  }

  struct Candidate {
    const llvm::Function *function;
    std::uint64_t definition_ordinal;
    bool field_seen;
    bool stack_seen;
    std::uint64_t stack_bytes;
  };
  std::vector<Candidate> candidates;
  llvm::DenseMap<const llvm::Function *, std::size_t> candidate_indices;

  for (const llvm::Use &record_use : records->operands()) {
    const llvm::ConstantStruct *record =
        llvm::dyn_cast<llvm::ConstantStruct>(record_use.get());
    if (record == nullptr) {
      return adapter_error(
          "llvm.global.annotations contains a non-struct record");
    }

    auto text_or_error = annotation_text(record);
    if (!text_or_error) {
      return text_or_error.takeError();
    }
    const llvm::StringRef text = *text_or_error;
    const bool is_field = text == kFieldAnnotation;
    const bool is_stack = text.starts_with(kStackAnnotationPrefix);
    if (!is_field && !is_stack) {
      if (text.starts_with(kFieldAnnotation) ||
          text.starts_with(kStackAnnotationStem)) {
        return adapter_error("malformed atfield annotation");
      }
      continue;
    }

    std::uint64_t stack_bytes = 0;
    if (is_stack) {
      auto parsed =
          parse_stack_bytes(text.drop_front(kStackAnnotationPrefix.size()));
      if (!parsed) {
        return parsed.takeError();
      }
      stack_bytes = *parsed;
    }

    const llvm::Value *annotated = record->getOperand(0)->stripPointerCasts();
    const llvm::Function *function = llvm::dyn_cast<llvm::Function>(annotated);
    if (function == nullptr) {
      return adapter_error(
          "atfield.field.v1 does not annotate a function definition");
    }
    const auto ordinal = definition_ordinals.find(function);
    if (ordinal == definition_ordinals.end()) {
      return adapter_error("atfield.field.v1 annotates a function declaration");
    }
    auto candidate_index = candidate_indices.find(function);
    if (candidate_index == candidate_indices.end()) {
      candidate_index =
          candidate_indices.try_emplace(function, candidates.size()).first;
      candidates.push_back({.function = function,
                            .definition_ordinal = ordinal->second,
                            .field_seen = false,
                            .stack_seen = false,
                            .stack_bytes = 0});
    }
    Candidate &candidate = candidates[candidate_index->second];
    if (is_field) {
      if (candidate.field_seen) {
        return adapter_error(
            "atfield.field.v1 annotates a function more than once");
      }
      candidate.field_seen = true;
    } else {
      if (candidate.stack_seen) {
        return adapter_error(
            "atfield stack annotation annotates a function more than once");
      }
      candidate.stack_seen = true;
      candidate.stack_bytes = stack_bytes;
    }
  }

  for (const Candidate &candidate : candidates) {
    if (!candidate.field_seen) {
      return adapter_error("stack_bytes annotation has no matching Field annotation");
    }
    if (!llvm::json::isUTF8(candidate.function->getName())) {
      return adapter_error("annotated function name is not valid UTF-8");
    }
  }

  llvm::sort(candidates, [](const Candidate &left, const Candidate &right) {
    return left.definition_ordinal < right.definition_ordinal;
  });

  std::vector<AnnotationDefinition> definitions;
  definitions.reserve(candidates.size());
  for (const Candidate &candidate : candidates) {
    definitions.push_back({.function_name = candidate.function->getName().str(),
                           .definition_ordinal = candidate.definition_ordinal,
                           .stack_bytes = candidate.stack_bytes});
  }
  return definitions;
}

} // namespace atfield::analyze
