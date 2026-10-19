Protect-only source overlay patches for Intel SGX.

- psw-readiness.patch is based on fork commit 7798c1b234ad1a7b2fd85be17d60fec6908f13a0.
  Every touched PSW path is byte-identical at 29787a0d; a zero-fuzz dry-run passed there.
- sdk-readiness.patch adds the public sgx_set_ecall_page_readiness_table declaration to the SDK source at that fork commit.
- Apply the matching patch to protect-only PSW and SDK derivations. Keep old raw and anchor sources unchanged.
