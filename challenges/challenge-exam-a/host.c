#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "exam_a_u.h"

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
    if (examA_boot_session(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 2;
    if (examA_set_policy(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 3;

    uint8_t cred[64] = {0};
    uint8_t out_buf[32] = {0};
    if (examA_mint_credential(eid, &retval, 0, cred, sizeof(cred)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 4;
    if (examA_audit_vault(eid, &retval, 0, cred, sizeof(cred), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 5;

    uint8_t frame_buf[32], hdr_buf[32];
    for (int i = 0; i < 32; i++) {
        frame_buf[i] = (uint8_t)(0x42 + i);
        hdr_buf[i] = (uint8_t)(0x90 ^ i);
    }

    if (examA_process_frame(eid, &retval, 0, frame_buf, sizeof(frame_buf), hdr_buf, sizeof(hdr_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 6;
    if (examA_step_epoch(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS) return 7;
    if (examA_process_frame(eid, &retval, 0, frame_buf, sizeof(frame_buf), hdr_buf, sizeof(hdr_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 8;
    if (examA_step_epoch(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS) return 9;
    if (examA_process_frame(eid, &retval, 0, frame_buf, sizeof(frame_buf), hdr_buf, sizeof(hdr_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 10;

    sgx_destroy_enclave(eid);
    puts("Exam A enclave functional checks: PASS");
    return 0;
}
