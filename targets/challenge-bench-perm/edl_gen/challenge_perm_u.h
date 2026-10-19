#ifndef CHALLENGE_PERM_U_H__
#define CHALLENGE_PERM_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_alpha_stage(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t stage_val);
sgx_status_t ecall_beta_run(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t ctl_flag, const uint8_t* pay_buf, size_t pay_len, const uint8_t* meta_buf, size_t meta_len, uint8_t* res_buf, size_t res_len);
sgx_status_t ecall_gamma_reset(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t init_seed);
sgx_status_t ecall_delta_latch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t latch_v);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
