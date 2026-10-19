#ifndef EXAM_D_U_H__
#define EXAM_D_U_H__

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


sgx_status_t examD_mint_grant(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t grant_scope, uint8_t* g_out, size_t g_len);
sgx_status_t examD_consume_grant(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t grant_op, const uint8_t* g_in, size_t g_len, uint8_t* out_buf, size_t out_len);
sgx_status_t examD_boot_ledger(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t ledger_seed);
sgx_status_t examD_override_mode(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t mode_code);
sgx_status_t examD_bump_cursor(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t cursor_inc);
sgx_status_t examD_eval_record(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t rec_op, const uint8_t* rec_buf, size_t rec_len, const uint8_t* sig_buf, size_t sig_len, uint8_t* out_buf, size_t out_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
