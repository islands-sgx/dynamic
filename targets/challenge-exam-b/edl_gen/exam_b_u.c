#include "exam_b_u.h"
#include <errno.h>

typedef struct ms_examB_tick_clock_t {
	sgx_status_t ms_retval;
	uint32_t ms_tick_step;
} ms_examB_tick_clock_t;

typedef struct ms_examB_issue_ticket_t {
	sgx_status_t ms_retval;
	uint32_t ms_ticket_kind;
	uint8_t* ms_tkt_out;
	size_t ms_tkt_len;
} ms_examB_issue_ticket_t;

typedef struct ms_examB_configure_gate_t {
	sgx_status_t ms_retval;
	uint32_t ms_gate_code;
} ms_examB_configure_gate_t;

typedef struct ms_examB_verify_ticket_t {
	sgx_status_t ms_retval;
	uint32_t ms_verify_cmd;
	const uint8_t* ms_tkt_in;
	size_t ms_tkt_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examB_verify_ticket_t;

typedef struct ms_examB_reset_context_t {
	sgx_status_t ms_retval;
	uint32_t ms_ctx_seed;
} ms_examB_reset_context_t;

typedef struct ms_examB_transform_packet_t {
	sgx_status_t ms_retval;
	uint32_t ms_pkt_mode;
	const uint8_t* ms_pkt_buf;
	size_t ms_pkt_len;
	const uint8_t* ms_tag_buf;
	size_t ms_tag_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examB_transform_packet_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_exam_b = {
	0,
	{ NULL },
};
sgx_status_t examB_tick_clock(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t tick_step)
{
	sgx_status_t status;
	ms_examB_tick_clock_t ms;
	ms.ms_tick_step = tick_step;
	status = sgx_ecall(eid, 0, &ocall_table_exam_b, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examB_issue_ticket(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t ticket_kind, uint8_t* tkt_out, size_t tkt_len)
{
	sgx_status_t status;
	ms_examB_issue_ticket_t ms;
	ms.ms_ticket_kind = ticket_kind;
	ms.ms_tkt_out = tkt_out;
	ms.ms_tkt_len = tkt_len;
	status = sgx_ecall(eid, 1, &ocall_table_exam_b, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examB_configure_gate(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t gate_code)
{
	sgx_status_t status;
	ms_examB_configure_gate_t ms;
	ms.ms_gate_code = gate_code;
	status = sgx_ecall(eid, 2, &ocall_table_exam_b, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examB_verify_ticket(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t verify_cmd, const uint8_t* tkt_in, size_t tkt_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examB_verify_ticket_t ms;
	ms.ms_verify_cmd = verify_cmd;
	ms.ms_tkt_in = tkt_in;
	ms.ms_tkt_len = tkt_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 3, &ocall_table_exam_b, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examB_reset_context(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t ctx_seed)
{
	sgx_status_t status;
	ms_examB_reset_context_t ms;
	ms.ms_ctx_seed = ctx_seed;
	status = sgx_ecall(eid, 4, &ocall_table_exam_b, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examB_transform_packet(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t pkt_mode, const uint8_t* pkt_buf, size_t pkt_len, const uint8_t* tag_buf, size_t tag_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examB_transform_packet_t ms;
	ms.ms_pkt_mode = pkt_mode;
	ms.ms_pkt_buf = pkt_buf;
	ms.ms_pkt_len = pkt_len;
	ms.ms_tag_buf = tag_buf;
	ms.ms_tag_len = tag_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 5, &ocall_table_exam_b, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

