#ifndef ATFIELD_BOUNDARY_TRANSFORM_H
#define ATFIELD_BOUNDARY_TRANSFORM_H

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Error.h"

#include <cstdint>
#include <string>
#include <vector>

namespace atfield::boundary {

inline constexpr llvm::StringLiteral kFieldEnterPrefix{
    "__atfield_field_enter_"};
inline constexpr llvm::StringLiteral kMarkerPrefix{"__atfield_marker_"};
inline constexpr llvm::StringLiteral kAfterMarkerPrefix{
    "__atfield_after_marker_"};
inline constexpr llvm::StringLiteral kBodyPrefix{"__atfield_body_"};
inline constexpr llvm::StringLiteral kNormalClosePrefix{
    "__atfield_normal_close_"};
inline constexpr llvm::StringLiteral kFieldExitPrefix{
    "__atfield_field_exit_"};
inline constexpr llvm::StringLiteral kPretouchPrefix{
    "__atfield_pretouch_"};

struct FieldOrderKey {
  std::uint64_t payload_ordinal{0};
  std::uint64_t function_ordinal{0};

  friend bool operator==(const FieldOrderKey &left,
                         const FieldOrderKey &right) {
    return left.payload_ordinal == right.payload_ordinal &&
           left.function_ordinal == right.function_ordinal;
  }
  friend bool operator<(const FieldOrderKey &left,
                        const FieldOrderKey &right) {
    return left.payload_ordinal < right.payload_ordinal ||
           (left.payload_ordinal == right.payload_ordinal &&
            left.function_ordinal < right.function_ordinal);
  }
};

struct FieldEnterIRIdentity {
  std::string basic_block;
  std::uint64_t instruction_ordinal{0};
};

struct BoundaryFieldFragment {
  std::uint64_t field_id{0};
  FieldOrderKey field_order_key;
  std::uint64_t stack_bytes{0};
  std::string function_name;
  FieldEnterIRIdentity field_enter_ir;
  std::string after_marker;
  std::string body;
  std::string normal_close;
  std::string field_exit;
};

struct BoundaryTransformFragment {
  std::uint64_t payload_ordinal{0};
  std::vector<BoundaryFieldFragment> fields;
};

struct BoundaryTransformOptions {
  // Stable per-payload identity from the sample compiler wrapper.
  std::uint64_t payload_ordinal{0};
};

// The input module must already have completed ordinary optimization.  This
// operation performs only the boundary IR insertion and LLVM verification.
llvm::Expected<BoundaryTransformFragment>
transform_module(llvm::Module &module,
                 const BoundaryTransformOptions &options);

} // namespace atfield::boundary

#endif
