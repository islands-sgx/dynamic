#ifndef ATFIELD_ANALYZE_ANNOTATION_ADAPTER_H
#define ATFIELD_ANALYZE_ANNOTATION_ADAPTER_H

#include "llvm/Support/Error.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class Module;
} // namespace llvm

namespace atfield::analyze {

struct AnnotationDefinition {
  std::string function_name;
  std::uint64_t definition_ordinal;
  std::uint64_t stack_bytes;
};

class AnnotationAdapter {
public:
  llvm::Expected<std::vector<AnnotationDefinition>> static discover(
      const llvm::Module &module);
};

} // namespace atfield::analyze

#endif
