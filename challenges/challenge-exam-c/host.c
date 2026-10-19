#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sgx_urts.h"
#include "exam_c_u.h"

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
    if (examC_init_engine(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 2;
    if (examC_set_regime(eid, &retval, 0) != SGX_SUCCESS || retval != SGX_SUCCESS) return 3;

    uint8_t voucher[64] = {0};
    uint8_t out_buf[32] = {0};
    if (examC_seal_voucher(eid, &retval, 0, voucher, sizeof(voucher)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 4;
    if (examC_redeem_voucher(eid, &retval, 0, voucher, sizeof(voucher), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS) return 5;

    uint8_t pay_buf[32], aux_buf[32];
    for (int i = 0; i < 32; i++) {
        pay_buf[i] = (uint8_t)(0x42 + i);
        aux_buf[i] = (uint8_t)(0x90 ^ i);
    }

    for (int step = 0; step < 3; step++) {
        if (examC_dispatch_batch(eid, &retval, 0, pay_buf, sizeof(pay_buf), aux_buf, sizeof(aux_buf), out_buf, sizeof(out_buf)) != SGX_SUCCESS || retval != SGX_SUCCESS)
            return 6 + step * 2;
        if (step < 2) {
            if (examC_advance_phase(eid, &retval, 1) != SGX_SUCCESS || retval != SGX_SUCCESS)
                return 7 + step * 2;
        }
    }

    sgx_destroy_enclave(eid);
    puts("Exam C enclave functional checks: PASS");
    return 0;
}
