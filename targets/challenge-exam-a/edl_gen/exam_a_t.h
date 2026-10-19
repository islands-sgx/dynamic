#ifndef EXAM_A_T_H__
#define EXAM_A_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t examA_mint_credential(uint32_t cred_level, uint8_t* cred_out, size_t cred_len);
sgx_status_t examA_audit_vault(uint32_t audit_cmd, const uint8_t* cred_in, size_t cred_len, uint8_t* out_buf, size_t out_len);
sgx_status_t examA_set_policy(uint32_t policy_code);
sgx_status_t examA_step_epoch(uint32_t step_inc);
sgx_status_t examA_process_frame(uint32_t frame_mode, const uint8_t* frame_buf, size_t frame_len, const uint8_t* hdr_buf, size_t hdr_len, uint8_t* out_buf, size_t out_len);
sgx_status_t examA_boot_session(uint32_t boot_seed);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
