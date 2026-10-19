savedcmd_sgx-step.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o sgx-step.o @sgx-step.mod  ; /usr/src/linux-headers-7.0.0-38-generic/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --retpoline --rethunk --sls --stackval --static-call --uaccess --prefix=16  --link  --module sgx-step.o

sgx-step.o: $(wildcard /usr/src/linux-headers-7.0.0-38-generic/tools/objtool/objtool)
