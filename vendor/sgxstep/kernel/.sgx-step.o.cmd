savedcmd_sgx-step.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o sgx-step.o @sgx-step.mod  ; /home/meandssh/.local/state/node2-qe3-closed-loop-20261020/sgxstep-build-7/hdr/usr/src/linux-headers-7.0.14-islands-sgx7/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --retpoline --rethunk --sls --stackval --static-call --uaccess --prefix=16  --link  --module sgx-step.o

sgx-step.o: $(wildcard /home/meandssh/.local/state/node2-qe3-closed-loop-20261020/sgxstep-build-7/hdr/usr/src/linux-headers-7.0.14-islands-sgx7/tools/objtool/objtool)
