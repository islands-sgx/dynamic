#define ATFIELD __attribute__((annotate("atfield.field.v1"), noinline))

static volatile int sink;

ATFIELD int protected_choice(int value) {
  if (value == 17) {
    sink = value + 3;
    return sink;
  }
  sink = value * 2;
  return sink + 1;
}

int public_wrapper(int value) { return protected_choice(value); }
