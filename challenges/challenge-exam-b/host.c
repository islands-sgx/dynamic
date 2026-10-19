#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "exam_b_u.h"

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
    if (examB_reset_context(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 2;
    if (examB_configure_gate(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 3;

    uint8_t tkt[64] = {0};
    uint8_t out_buf[32] = {0};
    if (examB_issue_ticket(eid, &retval, 0, tkt, sizeof(tkt)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 4;
    if (examB_verify_ticket(eid, &retval, 0, tkt, sizeof(tkt), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 5;

    uint8_t pkt_buf[32], tag_buf[32];
    for (int i = 0; i < 32; i++) {
        pkt_buf[i] = (uint8_t)(0x42 + i);
        tag_buf[i] = (uint8_t)(0x90 ^ i);
    }

    /* 4 calls to examB_transform_packet (sseq=0, 1, 2, 3), with C5 active at sseq=3 (4th position!) */
    for (int step = 0; step < 4; step++) {
        if (examB_transform_packet(eid, &retval, 0, pkt_buf, sizeof(pkt_buf), tag_buf, sizeof(tag_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
            return 6 + step * 2;
        if (step < 3) {
            if (examB_tick_clock(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS)
                return 7 + step * 2;
        }
    }

    sgx_destroy_enclave(eid);
    puts("Exam B enclave functional checks: PASS");
    return 0;
}
