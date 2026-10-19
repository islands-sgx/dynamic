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
sgx_status_t ecall_latch_phase(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t phase_flag);
sgx_status_t ecall_Execute(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t op_mode, const uint8_t* in_buf, size_t in_len, const uint8_t* aux_buf, size_t aux_len, uint8_t* out_buf, size_t out_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
