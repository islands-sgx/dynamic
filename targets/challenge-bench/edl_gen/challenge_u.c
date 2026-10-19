#include "challenge_u.h"
#include <errno.h>

typedef struct ms_ecall_init_t {
	sgx_status_t ms_retval;
	uint32_t ms_seed;
} ms_ecall_init_t;

typedef struct ms_ecall_configure_stage_t {
	sgx_status_t ms_retval;
	uint32_t ms_stage_mode;
} ms_ecall_configure_stage_t;

typedef struct ms_ecall_advance_step_t {
	sgx_status_t ms_retval;
	uint32_t ms_delta;
} ms_ecall_advance_step_t;

typedef struct ms_ecall_Execute_t {
	sgx_status_t ms_retval;
	uint32_t ms_op_mode;
	const uint8_t* ms_in_buf;
	size_t ms_in_len;
	const uint8_t* ms_aux_buf;
	size_t ms_aux_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_ecall_Execute_t;

typedef struct ms_ecall_mint_token_t {
	sgx_status_t ms_retval;
	uint32_t ms_token_profile;
	uint8_t* ms_token_out;
	size_t ms_token_len;
} ms_ecall_mint_token_t;

typedef struct ms_ecall_consume_vault_t {
	sgx_status_t ms_retval;
	uint32_t ms_vault_op;
	const uint8_t* ms_token_in;
	size_t ms_token_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_ecall_consume_vault_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_challenge = {
	0,
	{ NULL },
};
sgx_status_t ecall_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t seed)
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	ms.ms_seed = seed;
	status = sgx_ecall(eid, 0, &ocall_table_challenge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_configure_stage(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t stage_mode)
{
	sgx_status_t status;
	ms_ecall_configure_stage_t ms;
	ms.ms_stage_mode = stage_mode;
	status = sgx_ecall(eid, 1, &ocall_table_challenge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_advance_step(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t delta)
{
	sgx_status_t status;
	ms_ecall_advance_step_t ms;
	ms.ms_delta = delta;
	status = sgx_ecall(eid, 2, &ocall_table_challenge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_Execute(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t op_mode, const uint8_t* in_buf, size_t in_len, const uint8_t* aux_buf, size_t aux_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_ecall_Execute_t ms;
	ms.ms_op_mode = op_mode;
	ms.ms_in_buf = in_buf;
	ms.ms_in_len = in_len;
	ms.ms_aux_buf = aux_buf;
	ms.ms_aux_len = aux_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 3, &ocall_table_challenge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_mint_token(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t token_profile, uint8_t* token_out, size_t token_len)
{
	sgx_status_t status;
	ms_ecall_mint_token_t ms;
	ms.ms_token_profile = token_profile;
	ms.ms_token_out = token_out;
	ms.ms_token_len = token_len;
	status = sgx_ecall(eid, 4, &ocall_table_challenge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_consume_vault(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t vault_op, const uint8_t* token_in, size_t token_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_ecall_consume_vault_t ms;
	ms.ms_vault_op = vault_op;
	ms.ms_token_in = token_in;
	ms.ms_token_len = token_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 5, &ocall_table_challenge, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

