#include "exam_c_t.h"

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

static sgx_status_t SGX_CDECL sgx_examC_set_regime(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examC_set_regime_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examC_set_regime_t* ms = SGX_CAST(ms_examC_set_regime_t*, pms);
	ms_examC_set_regime_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examC_set_regime_t), ms, sizeof(ms_examC_set_regime_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examC_set_regime(__in_ms.ms_regime_id);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examC_seal_voucher(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examC_seal_voucher_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examC_seal_voucher_t* ms = SGX_CAST(ms_examC_seal_voucher_t*, pms);
	ms_examC_seal_voucher_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examC_seal_voucher_t), ms, sizeof(ms_examC_seal_voucher_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_v_out = __in_ms.ms_v_out;
	size_t _tmp_v_len = __in_ms.ms_v_len;
	size_t _len_v_out = _tmp_v_len;
	uint8_t* _in_v_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_v_out, _len_v_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_v_out != NULL && _len_v_out != 0) {
		if ( _len_v_out % sizeof(*_tmp_v_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_v_out = (uint8_t*)malloc(_len_v_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_v_out, 0, _len_v_out);
	}
	_in_retval = examC_seal_voucher(__in_ms.ms_voucher_tier, _in_v_out, _tmp_v_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_v_out) {
		if (memcpy_verw_s(_tmp_v_out, _len_v_out, _in_v_out, _len_v_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_v_out) free(_in_v_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examC_redeem_voucher(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examC_redeem_voucher_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examC_redeem_voucher_t* ms = SGX_CAST(ms_examC_redeem_voucher_t*, pms);
	ms_examC_redeem_voucher_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examC_redeem_voucher_t), ms, sizeof(ms_examC_redeem_voucher_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_v_in = __in_ms.ms_v_in;
	size_t _tmp_v_len = __in_ms.ms_v_len;
	size_t _len_v_in = _tmp_v_len;
	uint8_t* _in_v_in = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_v_in, _len_v_in);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_v_in != NULL && _len_v_in != 0) {
		if ( _len_v_in % sizeof(*_tmp_v_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_v_in = (uint8_t*)malloc(_len_v_in);
		if (_in_v_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_v_in, _len_v_in, _tmp_v_in, _len_v_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out_buf != NULL && _len_out_buf != 0) {
		if ( _len_out_buf % sizeof(*_tmp_out_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out_buf = (uint8_t*)malloc(_len_out_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_buf, 0, _len_out_buf);
	}
	_in_retval = examC_redeem_voucher(__in_ms.ms_redeem_op, (const uint8_t*)_in_v_in, _tmp_v_len, _in_out_buf, _tmp_out_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_out_buf) {
		if (memcpy_verw_s(_tmp_out_buf, _len_out_buf, _in_out_buf, _len_out_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_v_in) free(_in_v_in);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examC_init_engine(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examC_init_engine_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examC_init_engine_t* ms = SGX_CAST(ms_examC_init_engine_t*, pms);
	ms_examC_init_engine_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examC_init_engine_t), ms, sizeof(ms_examC_init_engine_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examC_init_engine(__in_ms.ms_eng_seed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examC_dispatch_batch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examC_dispatch_batch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examC_dispatch_batch_t* ms = SGX_CAST(ms_examC_dispatch_batch_t*, pms);
	ms_examC_dispatch_batch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examC_dispatch_batch_t), ms, sizeof(ms_examC_dispatch_batch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_pay_buf = __in_ms.ms_pay_buf;
	size_t _tmp_pay_len = __in_ms.ms_pay_len;
	size_t _len_pay_buf = _tmp_pay_len;
	uint8_t* _in_pay_buf = NULL;
	const uint8_t* _tmp_aux_buf = __in_ms.ms_aux_buf;
	size_t _tmp_aux_len = __in_ms.ms_aux_len;
	size_t _len_aux_buf = _tmp_aux_len;
	uint8_t* _in_aux_buf = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_pay_buf, _len_pay_buf);
	CHECK_UNIQUE_POINTER(_tmp_aux_buf, _len_aux_buf);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

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
	if (_tmp_aux_buf != NULL && _len_aux_buf != 0) {
		if ( _len_aux_buf % sizeof(*_tmp_aux_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aux_buf = (uint8_t*)malloc(_len_aux_buf);
		if (_in_aux_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aux_buf, _len_aux_buf, _tmp_aux_buf, _len_aux_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out_buf != NULL && _len_out_buf != 0) {
		if ( _len_out_buf % sizeof(*_tmp_out_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out_buf = (uint8_t*)malloc(_len_out_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_buf, 0, _len_out_buf);
	}
	_in_retval = examC_dispatch_batch(__in_ms.ms_batch_op, (const uint8_t*)_in_pay_buf, _tmp_pay_len, (const uint8_t*)_in_aux_buf, _tmp_aux_len, _in_out_buf, _tmp_out_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_out_buf) {
		if (memcpy_verw_s(_tmp_out_buf, _len_out_buf, _in_out_buf, _len_out_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pay_buf) free(_in_pay_buf);
	if (_in_aux_buf) free(_in_aux_buf);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examC_advance_phase(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examC_advance_phase_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examC_advance_phase_t* ms = SGX_CAST(ms_examC_advance_phase_t*, pms);
	ms_examC_advance_phase_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examC_advance_phase_t), ms, sizeof(ms_examC_advance_phase_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examC_advance_phase(__in_ms.ms_phase_step);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_examC_set_regime, 0, 0},
		{(void*)(uintptr_t)sgx_examC_seal_voucher, 0, 0},
		{(void*)(uintptr_t)sgx_examC_redeem_voucher, 0, 0},
		{(void*)(uintptr_t)sgx_examC_init_engine, 0, 0},
		{(void*)(uintptr_t)sgx_examC_dispatch_batch, 0, 0},
		{(void*)(uintptr_t)sgx_examC_advance_phase, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


