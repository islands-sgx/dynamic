#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "challenge_u.h"

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    const char *encl_path = getenv("ATFIELD_ENCLAVE_PATH");
    if (!encl_path || !*encl_path) encl_path = ENCLAVE_PATH;

    if (sgx_create_enclave(encl_path, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        fprintf(stderr, "Failed to create challenge enclave\n");
        return 1;
    }

    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
    if (ecall_init(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 2;
    if (ecall_configure_stage(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 3;

    uint8_t in_buf[32];
    uint8_t aux_buf[32];
    uint8_t out_buf[32] = {0};
    for (int i = 0; i < 32; i++) {
        in_buf[i] = (uint8_t)(0x42 + i);
        aux_buf[i] = (uint8_t)(0x90 ^ i);
    }

    /* Call 1 (sseq=0): unlatched state */
    if (ecall_Execute(eid, &retval, 0, in_buf, sizeof(in_buf), aux_buf, sizeof(aux_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 4;

    /* Latch latent state without touching any new enclave page */
    if (ecall_latch_phase(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS) return 5;

    /* Call 2 (sseq=1): latched state (identical L1 page set to sseq=0, but latent state differs) */
    if (ecall_Execute(eid, &retval, 0, in_buf, sizeof(in_buf), aux_buf, sizeof(aux_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 6;

    sgx_destroy_enclave(eid);
    puts("Challenge enclave functional checks: PASS");
    return 0;
}
