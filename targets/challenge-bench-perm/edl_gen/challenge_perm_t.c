#include "challenge_perm_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_alpha_stage(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_alpha_stage_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_alpha_stage_t* ms = SGX_CAST(ms_ecall_alpha_stage_t*, pms);
	ms_ecall_alpha_stage_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_alpha_stage_t), ms, sizeof(ms_ecall_alpha_stage_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_alpha_stage(__in_ms.ms_stage_val);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_beta_run(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_beta_run_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_beta_run_t* ms = SGX_CAST(ms_ecall_beta_run_t*, pms);
	ms_ecall_beta_run_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_beta_run_t), ms, sizeof(ms_ecall_beta_run_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_pay_buf = __in_ms.ms_pay_buf;
	size_t _tmp_pay_len = __in_ms.ms_pay_len;
	size_t _len_pay_buf = _tmp_pay_len;
	uint8_t* _in_pay_buf = NULL;
	const uint8_t* _tmp_meta_buf = __in_ms.ms_meta_buf;
	size_t _tmp_meta_len = __in_ms.ms_meta_len;
	size_t _len_meta_buf = _tmp_meta_len;
	uint8_t* _in_meta_buf = NULL;
	uint8_t* _tmp_res_buf = __in_ms.ms_res_buf;
	size_t _tmp_res_len = __in_ms.ms_res_len;
	size_t _len_res_buf = _tmp_res_len;
	uint8_t* _in_res_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_pay_buf, _len_pay_buf);
	CHECK_UNIQUE_POINTER(_tmp_meta_buf, _len_meta_buf);
	CHECK_UNIQUE_POINTER(_tmp_res_buf, _len_res_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pay_buf != NULL && _len_pay_buf != 0) {
		if ( _len_pay_buf % sizeof(*_tmp_pay_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pay_buf = (uint8_t*)malloc(_len_pay_buf);
		if (_in_pay_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pay_buf, _len_pay_buf, _tmp_pay_buf, _len_pay_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_meta_buf != NULL && _len_meta_buf != 0) {
		if ( _len_meta_buf % sizeof(*_tmp_meta_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_meta_buf = (uint8_t*)malloc(_len_meta_buf);
		if (_in_meta_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_meta_buf, _len_meta_buf, _tmp_meta_buf, _len_meta_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res_buf != NULL && _len_res_buf != 0) {
		if ( _len_res_buf % sizeof(*_tmp_res_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_res_buf = (uint8_t*)malloc(_len_res_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res_buf, 0, _len_res_buf);
	}
	_in_retval = ecall_beta_run(__in_ms.ms_ctl_flag, (const uint8_t*)_in_pay_buf, _tmp_pay_len, (const uint8_t*)_in_meta_buf, _tmp_meta_len, _in_res_buf, _tmp_res_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_res_buf) {
		if (memcpy_verw_s(_tmp_res_buf, _len_res_buf, _in_res_buf, _len_res_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pay_buf) free(_in_pay_buf);
	if (_in_meta_buf) free(_in_meta_buf);
	if (_in_res_buf) free(_in_res_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_gamma_reset(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_gamma_reset_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_gamma_reset_t* ms = SGX_CAST(ms_ecall_gamma_reset_t*, pms);
	ms_ecall_gamma_reset_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_gamma_reset_t), ms, sizeof(ms_ecall_gamma_reset_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_gamma_reset(__in_ms.ms_init_seed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_delta_latch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_delta_latch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_delta_latch_t* ms = SGX_CAST(ms_ecall_delta_latch_t*, pms);
	ms_ecall_delta_latch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_delta_latch_t), ms, sizeof(ms_ecall_delta_latch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_delta_latch(__in_ms.ms_latch_v);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_alpha_stage, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_beta_run, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_gamma_reset, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_delta_latch, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


