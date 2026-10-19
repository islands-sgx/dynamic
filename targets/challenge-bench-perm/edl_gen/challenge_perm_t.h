#ifndef CHALLENGE_PERM_T_H__
#define CHALLENGE_PERM_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_alpha_stage(uint32_t stage_val);
sgx_status_t ecall_beta_run(uint32_t ctl_flag, const uint8_t* pay_buf, size_t pay_len, const uint8_t* meta_buf, size_t meta_len, uint8_t* res_buf, size_t res_len);
sgx_status_t ecall_gamma_reset(uint32_t init_seed);
sgx_status_t ecall_delta_latch(uint32_t latch_v);
sgx_status_t ecall_epsilon_issue(uint32_t kind_tag, uint8_t* blob_out, size_t blob_len);
sgx_status_t ecall_zeta_open(uint32_t action_id, const uint8_t* blob_in, size_t blob_len, uint8_t* res_buf, size_t res_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
