# uRTS page readiness host helper

atfield_install_readiness_file() loads one ReadyTable v3 file after enclave creation, calls sgx_set_ecall_page_readiness_table(), then selects the requested backend. Call it before the first ordinary ECALL. The table setter deep-copies the data. The helper returns the SGX status; system_error_out carries errno for file I/O failures.

Choose ATFIELD_READINESS_BACKEND_KERNEL for the production path. This is the default uRTS backend. A failed ioctl returns an error and does not switch backends.

Choose ATFIELD_READINESS_BACKEND_USERSPACE only for explicit research runs before the kernel driver path is ready. uRTS checks every table RVA against the signed image's REG page layout and readable permissions, rejects non-debug enclaves, and reads one byte from each selector page before every target ECALL. TCS, SSA, and guard pages are excluded. Trace output records MR_ENCLAVE and the target RVA set.

This temporary backend does not hold EPC pages off the reclaimer and does not compare PTE PFNs. It supports boundary, pre-touch, business, and AEX experiments; it does not establish production kernel page-readiness success. Both backends use the same ReadyTable v3 built from the final signed ELF.
