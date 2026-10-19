#include "exam_c_u.h"
#include <errno.h>

typedef struct ms_examC_set_regime_t {
	sgx_status_t ms_retval;
	uint32_t ms_regime_id;
} ms_examC_set_regime_t;

typedef struct ms_examC_seal_voucher_t {
	sgx_status_t ms_retval;
	uint32_t ms_voucher_tier;
	uint8_t* ms_v_out;
	size_t ms_v_len;
} ms_examC_seal_voucher_t;

typedef struct ms_examC_redeem_voucher_t {
	sgx_status_t ms_retval;
	uint32_t ms_redeem_op;
	const uint8_t* ms_v_in;
	size_t ms_v_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examC_redeem_voucher_t;

typedef struct ms_examC_init_engine_t {
	sgx_status_t ms_retval;
	uint32_t ms_eng_seed;
} ms_examC_init_engine_t;

typedef struct ms_examC_dispatch_batch_t {
	sgx_status_t ms_retval;
	uint32_t ms_batch_op;
	const uint8_t* ms_pay_buf;
	size_t ms_pay_len;
	const uint8_t* ms_aux_buf;
	size_t ms_aux_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examC_dispatch_batch_t;

typedef struct ms_examC_advance_phase_t {
	sgx_status_t ms_retval;
	uint32_t ms_phase_step;
} ms_examC_advance_phase_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_exam_c = {
	0,
	{ NULL },
};
sgx_status_t examC_set_regime(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t regime_id)
{
	sgx_status_t status;
	ms_examC_set_regime_t ms;
	ms.ms_regime_id = regime_id;
	status = sgx_ecall(eid, 0, &ocall_table_exam_c, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examC_seal_voucher(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t voucher_tier, uint8_t* v_out, size_t v_len)
{
	sgx_status_t status;
	ms_examC_seal_voucher_t ms;
	ms.ms_voucher_tier = voucher_tier;
	ms.ms_v_out = v_out;
	ms.ms_v_len = v_len;
	status = sgx_ecall(eid, 1, &ocall_table_exam_c, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examC_redeem_voucher(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t redeem_op, const uint8_t* v_in, size_t v_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examC_redeem_voucher_t ms;
	ms.ms_redeem_op = redeem_op;
	ms.ms_v_in = v_in;
	ms.ms_v_len = v_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 2, &ocall_table_exam_c, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examC_init_engine(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t eng_seed)
{
	sgx_status_t status;
	ms_examC_init_engine_t ms;
	ms.ms_eng_seed = eng_seed;
	status = sgx_ecall(eid, 3, &ocall_table_exam_c, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examC_dispatch_batch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t batch_op, const uint8_t* pay_buf, size_t pay_len, const uint8_t* aux_buf, size_t aux_len, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_examC_dispatch_batch_t ms;
	ms.ms_batch_op = batch_op;
	ms.ms_pay_buf = pay_buf;
	ms.ms_pay_len = pay_len;
	ms.ms_aux_buf = aux_buf;
	ms.ms_aux_len = aux_len;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 4, &ocall_table_exam_c, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t examC_advance_phase(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t phase_step)
{
	sgx_status_t status;
	ms_examC_advance_phase_t ms;
	ms.ms_phase_step = phase_step;
	status = sgx_ecall(eid, 5, &ocall_table_exam_c, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

