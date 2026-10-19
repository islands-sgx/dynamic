#include "challenge_perm_u.h"
#include <errno.h>

typedef struct ms_ecall_alpha_stage_t {
	sgx_status_t ms_retval;
	uint32_t ms_stage_val;
} ms_ecall_alpha_stage_t;

typedef struct ms_ecall_beta_run_t {
	sgx_status_t ms_retval;
	uint32_t ms_ctl_flag;
	const uint8_t* ms_pay_buf;
	size_t ms_pay_len;
	const uint8_t* ms_meta_buf;
	size_t ms_meta_len;
	uint8_t* ms_res_buf;
	size_t ms_res_len;
} ms_ecall_beta_run_t;

typedef struct ms_ecall_gamma_reset_t {
	sgx_status_t ms_retval;
	uint32_t ms_init_seed;
} ms_ecall_gamma_reset_t;

typedef struct ms_ecall_delta_latch_t {
	sgx_status_t ms_retval;
	uint32_t ms_latch_v;
} ms_ecall_delta_latch_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_challenge_perm = {
	0,
	{ NULL },
};
sgx_status_t ecall_alpha_stage(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t stage_val)
{
	sgx_status_t status;
	ms_ecall_alpha_stage_t ms;
	ms.ms_stage_val = stage_val;
	status = sgx_ecall(eid, 0, &ocall_table_challenge_perm, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_beta_run(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t ctl_flag, const uint8_t* pay_buf, size_t pay_len, const uint8_t* meta_buf, size_t meta_len, uint8_t* res_buf, size_t res_len)
{
	sgx_status_t status;
	ms_ecall_beta_run_t ms;
	ms.ms_ctl_flag = ctl_flag;
	ms.ms_pay_buf = pay_buf;
	ms.ms_pay_len = pay_len;
	ms.ms_meta_buf = meta_buf;
	ms.ms_meta_len = meta_len;
	ms.ms_res_buf = res_buf;
	ms.ms_res_len = res_len;
	status = sgx_ecall(eid, 1, &ocall_table_challenge_perm, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_gamma_reset(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t init_seed)
{
	sgx_status_t status;
	ms_ecall_gamma_reset_t ms;
	ms.ms_init_seed = init_seed;
	status = sgx_ecall(eid, 2, &ocall_table_challenge_perm, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_delta_latch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t latch_v)
{
	sgx_status_t status;
	ms_ecall_delta_latch_t ms;
	ms.ms_latch_v = latch_v;
	status = sgx_ecall(eid, 3, &ocall_table_challenge_perm, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

