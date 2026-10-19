#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "calibration_u.h"

int main(int argc, char **argv) {
    uint32_t repeat_cnt = 2;
    if (argc > 1) {
        repeat_cnt = (uint32_t)atoi(argv[1]);
        if (repeat_cnt == 0) repeat_cnt = 2;
    }
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    const char *encl_path = getenv("ATFIELD_ENCLAVE_PATH");
    if (!encl_path || !*encl_path) encl_path = ENCLAVE_PATH;

    if (sgx_create_enclave(encl_path, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        return 1;
    }
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
    uint8_t out_buf[16] = {0};
    if (ecall_run_calibration(eid, &retval, repeat_cnt, out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) {
        sgx_destroy_enclave(eid);
        return 2;
    }
    sgx_destroy_enclave(eid);
    puts("Calibration fixture functional checks: PASS");
    return 0;
}
