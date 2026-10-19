#define ATFIELD __attribute__((annotate("atfield.field.v1"), noinline))
namespace example { static ATFIELD int protected_cpp(int value) { return value * 3 + 1; } int caller(int value) { return protected_cpp(value); } }
