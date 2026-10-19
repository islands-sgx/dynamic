#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "exam_d_u.h"

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    const char *encl_path = getenv("ATFIELD_ENCLAVE_PATH");
    if (!encl_path || !*encl_path) encl_path = ENCLAVE_PATH;

    if (sgx_create_enclave(encl_path, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        return 1;
    }

    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
    if (examD_boot_ledger(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 2;
    if (examD_override_mode(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 3;

    uint8_t grant[64] = {0};
    uint8_t out_buf[32] = {0};
    if (examD_mint_grant(eid, &retval, 0, grant, sizeof(grant)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 4;
    if (examD_consume_grant(eid, &retval, 0, grant, sizeof(grant), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 5;

    uint8_t rec_buf[32], sig_buf[32];
    for (int i = 0; i < 32; i++) {
        rec_buf[i] = (uint8_t)(0x42 + i);
        sig_buf[i] = (uint8_t)(0x90 ^ i);
    }

    for (int step = 0; step < 4; step++) {
        if (examD_eval_record(eid, &retval, 0, rec_buf, sizeof(rec_buf), sig_buf, sizeof(sig_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
            return 6 + step * 2;
        if (step < 3) {
            if (examD_bump_cursor(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS)
                return 7 + step * 2;
        }
    }

    sgx_destroy_enclave(eid);
    puts("Exam D enclave functional checks: PASS");
    return 0;
}
