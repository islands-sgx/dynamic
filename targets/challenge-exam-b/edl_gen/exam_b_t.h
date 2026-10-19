#ifndef EXAM_B_T_H__
#define EXAM_B_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t examB_tick_clock(uint32_t tick_step);
sgx_status_t examB_issue_ticket(uint32_t ticket_kind, uint8_t* tkt_out, size_t tkt_len);
sgx_status_t examB_configure_gate(uint32_t gate_code);
sgx_status_t examB_verify_ticket(uint32_t verify_cmd, const uint8_t* tkt_in, size_t tkt_len, uint8_t* out_buf, size_t out_len);
sgx_status_t examB_reset_context(uint32_t ctx_seed);
sgx_status_t examB_transform_packet(uint32_t pkt_mode, const uint8_t* pkt_buf, size_t pkt_len, const uint8_t* tag_buf, size_t tag_len, uint8_t* out_buf, size_t out_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
