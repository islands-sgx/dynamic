#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "challenge_perm_u.h"

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    const char *encl_path = getenv("ATFIELD_ENCLAVE_PATH");
    if (!encl_path || !*encl_path) encl_path = ENCLAVE_PATH;

    if (sgx_create_enclave(encl_path, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        fprintf(stderr, "Failed to create challenge_perm enclave\n");
        return 1;
    }

    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
    if (ecall_gamma_reset(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 2;
    if (ecall_alpha_stage(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 3;

    uint8_t pay_buf[32];
    uint8_t meta_buf[32];
    uint8_t res_buf[32] = {0};
    for (int i = 0; i < 32; i++) {
        pay_buf[i] = (uint8_t)(0x42 + i);
        meta_buf[i] = (uint8_t)(0x90 ^ i);
    }

    /* Call 1 (sseq=0): step=0 */
    if (ecall_beta_run(eid, &retval, 0, pay_buf, sizeof(pay_buf), meta_buf, sizeof(meta_buf), res_buf, sizeof(res_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 4;
    if (ecall_delta_latch(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS) return 5;

    /* Call 2 (sseq=1): step=1 */
    if (ecall_beta_run(eid, &retval, 0, pay_buf, sizeof(pay_buf), meta_buf, sizeof(meta_buf), res_buf, sizeof(res_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 6;
    if (ecall_delta_latch(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS) return 7;

    /* Call 3 (sseq=2, 3rd position!): step=2 */
    if (ecall_beta_run(eid, &retval, 0, pay_buf, sizeof(pay_buf), meta_buf, sizeof(meta_buf), res_buf, sizeof(res_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 8;

    /* Producer -> Consumer Field 2 */
    uint8_t blob[64] = {0};
    if (ecall_epsilon_issue(eid, &retval, 0, blob, sizeof(blob)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 9;
    if (ecall_zeta_open(eid, &retval, 0, blob, sizeof(blob), res_buf, sizeof(res_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
        return 10;

    sgx_destroy_enclave(eid);
    puts("Challenge perm enclave functional checks: PASS");
    return 0;
}
