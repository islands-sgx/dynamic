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

typedef struct ms_ecall_latch_phase_t {
	sgx_status_t ms_retval;
	uint32_t ms_phase_flag;
} ms_ecall_latch_phase_t;

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

sgx_status_t ecall_latch_phase(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t phase_flag)
{
	sgx_status_t status;
	ms_ecall_latch_phase_t ms;
	ms.ms_phase_flag = phase_flag;
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

