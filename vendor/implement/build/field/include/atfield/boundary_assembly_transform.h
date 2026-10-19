#ifndef ATFIELD_BOUNDARY_ASSEMBLY_TRANSFORM_H
#define ATFIELD_BOUNDARY_ASSEMBLY_TRANSFORM_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"

#include <cstdint>
#include <string>
#include <vector>

namespace atfield::boundary {

struct BoundaryAssemblyField {
  std::uint64_t field_id{0};
  std::string after_marker;
  std::string body;
};

// Parse llc assembly with LLVM's MC parser and emit a verified x86_64 ET_REL.
// Reserved boundary symbols are recognized only through MCExpr structure; all
// ordinary events are forwarded to the stock MCELFStreamer implementation.
llvm::Expected<std::vector<std::uint8_t>>
transform_boundary_assembly(llvm::StringRef assembly,
                            llvm::ArrayRef<BoundaryAssemblyField> fields);

} // namespace atfield::boundary

#endif
