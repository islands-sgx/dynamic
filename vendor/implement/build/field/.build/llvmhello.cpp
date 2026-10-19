#include "llvm/Support/raw_ostream.h"
#include <string>
int main(){ std::string s="hello LLVM\n"; llvm::outs() << s; }
