#include "exam_d_u.h"
#include <errno.h>

typedef struct ms_examD_mint_grant_t {
	sgx_status_t ms_retval;
	uint32_t ms_grant_scope;
	uint8_t* ms_g_out;
	size_t ms_g_len;
} ms_examD_mint_grant_t;

typedef struct ms_examD_consume_grant_t {
	sgx_status_t ms_retval;
	uint32_t ms_grant_op;
	const uint8_t* ms_g_in;
	size_t ms_g_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examD_consume_grant_t;

typedef struct ms_examD_boot_ledger_t {
	sgx_status_t ms_retval;
	uint32_t ms_ledger_seed;
} ms_examD_boot_ledger_t;

typedef struct ms_examD_override_mode_t {
	sgx_status_t ms_retval;
	uint32_t ms_mode_code;
} ms_examD_override_mode_t;

typedef struct ms_examD_bump_cursor_t {
	sgx_status_t ms_retval;
	uint32_t ms_cursor_inc;
} ms_examD_bump_cursor_t;

typedef struct ms_examD_eval_record_t {
	sgx_status_t ms_retval;
	uint32_t ms_rec_op;
	const uint8_t* ms_rec_buf;
	size_t ms_rec_len;
	const uint8_t* ms_sig_buf;
	size_t ms_sig_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examD_eval_record_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_exam_d = {
	0,
	{ NULL },
};
sgx_status_t examD_mint_grant(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t grant_scope, uint8_t* g_out, size_t g_len)
{
	sgx_status_t status;
	ms_examD_mint_grant_t ms;
	ms.ms_grant_scope = grant_scope;
	ms.ms_g_out = g_out;
	ms.ms_g_len = g_len;
	status = sgx_ecall(eid, 0, &ocall_table_exam_d, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examD_consume_grant(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t grant_op, const uint8_t* g_in, size_t g_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examD_consume_grant_t ms;
	ms.ms_grant_op = grant_op;
	ms.ms_g_in = g_in;
	ms.ms_g_len = g_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 1, &ocall_table_exam_d, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examD_boot_ledger(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t ledger_seed)
{
	sgx_status_t status;
	ms_examD_boot_ledger_t ms;
	ms.ms_ledger_seed = ledger_seed;
	status = sgx_ecall(eid, 2, &ocall_table_exam_d, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examD_override_mode(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t mode_code)
{
	sgx_status_t status;
	ms_examD_override_mode_t ms;
	ms.ms_mode_code = mode_code;
	status = sgx_ecall(eid, 3, &ocall_table_exam_d, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examD_bump_cursor(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t cursor_inc)
{
	sgx_status_t status;
	ms_examD_bump_cursor_t ms;
	ms.ms_cursor_inc = cursor_inc;
	status = sgx_ecall(eid, 4, &ocall_table_exam_d, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examD_eval_record(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t rec_op, const uint8_t* rec_buf, size_t rec_len, const uint8_t* sig_buf, size_t sig_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examD_eval_record_t ms;
	ms.ms_rec_op = rec_op;
	ms.ms_rec_buf = rec_buf;
	ms.ms_rec_len = rec_len;
	ms.ms_sig_buf = sig_buf;
	ms.ms_sig_len = sig_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 5, &ocall_table_exam_d, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

