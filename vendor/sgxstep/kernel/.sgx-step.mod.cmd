savedcmd_sgx-step.mod := printf '%s\n'   sgxstep.o | awk '!x[$$0]++ { print("./"$$0) }' > sgx-step.mod
