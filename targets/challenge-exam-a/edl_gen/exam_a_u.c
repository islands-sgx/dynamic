#include "exam_a_u.h"
#include <errno.h>

typedef struct ms_examA_mint_credential_t {
	sgx_status_t ms_retval;
	uint32_t ms_cred_level;
	uint8_t* ms_cred_out;
	size_t ms_cred_len;
} ms_examA_mint_credential_t;

typedef struct ms_examA_audit_vault_t {
	sgx_status_t ms_retval;
	uint32_t ms_audit_cmd;
	const uint8_t* ms_cred_in;
	size_t ms_cred_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examA_audit_vault_t;

typedef struct ms_examA_set_policy_t {
	sgx_status_t ms_retval;
	uint32_t ms_policy_code;
} ms_examA_set_policy_t;

typedef struct ms_examA_step_epoch_t {
	sgx_status_t ms_retval;
	uint32_t ms_step_inc;
} ms_examA_step_epoch_t;

typedef struct ms_examA_process_frame_t {
	sgx_status_t ms_retval;
	uint32_t ms_frame_mode;
	const uint8_t* ms_frame_buf;
	size_t ms_frame_len;
	const uint8_t* ms_hdr_buf;
	size_t ms_hdr_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examA_process_frame_t;

typedef struct ms_examA_boot_session_t {
	sgx_status_t ms_retval;
	uint32_t ms_boot_seed;
} ms_examA_boot_session_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_exam_a = {
	0,
	{ NULL },
};
sgx_status_t examA_mint_credential(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t cred_level, uint8_t* cred_out, size_t cred_len)
{
	sgx_status_t status;
	ms_examA_mint_credential_t ms;
	ms.ms_cred_level = cred_level;
	ms.ms_cred_out = cred_out;
	ms.ms_cred_len = cred_len;
	status = sgx_ecall(eid, 0, &ocall_table_exam_a, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examA_audit_vault(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t audit_cmd, const uint8_t* cred_in, size_t cred_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examA_audit_vault_t ms;
	ms.ms_audit_cmd = audit_cmd;
	ms.ms_cred_in = cred_in;
	ms.ms_cred_len = cred_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 1, &ocall_table_exam_a, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examA_set_policy(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t policy_code)
{
	sgx_status_t status;
	ms_examA_set_policy_t ms;
	ms.ms_policy_code = policy_code;
	status = sgx_ecall(eid, 2, &ocall_table_exam_a, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examA_step_epoch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t step_inc)
{
	sgx_status_t status;
	ms_examA_step_epoch_t ms;
	ms.ms_step_inc = step_inc;
	status = sgx_ecall(eid, 3, &ocall_table_exam_a, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examA_process_frame(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t frame_mode, const uint8_t* frame_buf, size_t frame_len, const uint8_t* hdr_buf, size_t hdr_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examA_process_frame_t ms;
	ms.ms_frame_mode = frame_mode;
	ms.ms_frame_buf = frame_buf;
	ms.ms_frame_len = frame_len;
	ms.ms_hdr_buf = hdr_buf;
	ms.ms_hdr_len = hdr_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 4, &ocall_table_exam_a, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examA_boot_session(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t boot_seed)
{
	sgx_status_t status;
	ms_examA_boot_session_t ms;
	ms.ms_boot_seed = boot_seed;
	status = sgx_ecall(eid, 5, &ocall_table_exam_a, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

