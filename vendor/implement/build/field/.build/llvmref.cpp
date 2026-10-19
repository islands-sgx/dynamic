#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <string>
int main(int argc, char **argv) {
  if (argc == 2 && (llvm::StringRef(argv[1]) == "--help" ||
                    llvm::StringRef(argv[1]) == "-h")) {
    std::string text = "usage:\nhello\n";
    llvm::outs() << text;
    return 0;
  }
  return 1;
}
