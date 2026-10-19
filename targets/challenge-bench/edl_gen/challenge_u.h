#ifndef CHALLENGE_U_H__
#define CHALLENGE_U_H__

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


sgx_status_t ecall_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t seed);
sgx_status_t ecall_configure_stage(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t stage_mode);
sgx_status_t ecall_advance_step(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t delta);
sgx_status_t ecall_Execute(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t op_mode, const uint8_t* in_buf, size_t in_len, const uint8_t* aux_buf, size_t aux_len, uint8_t* out_buf, size_t out_len);
sgx_status_t ecall_mint_token(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t token_profile, uint8_t* token_out, size_t token_len);
sgx_status_t ecall_consume_vault(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t vault_op, const uint8_t* token_in, size_t token_len, uint8_t* out_buf, size_t out_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
