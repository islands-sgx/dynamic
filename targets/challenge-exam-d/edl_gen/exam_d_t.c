#include "exam_d_t.h"

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

static sgx_status_t SGX_CDECL sgx_examD_mint_grant(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examD_mint_grant_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examD_mint_grant_t* ms = SGX_CAST(ms_examD_mint_grant_t*, pms);
	ms_examD_mint_grant_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examD_mint_grant_t), ms, sizeof(ms_examD_mint_grant_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_g_out = __in_ms.ms_g_out;
	size_t _tmp_g_len = __in_ms.ms_g_len;
	size_t _len_g_out = _tmp_g_len;
	uint8_t* _in_g_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_out, _len_g_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_out != NULL && _len_g_out != 0) {
		if ( _len_g_out % sizeof(*_tmp_g_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_g_out = (uint8_t*)malloc(_len_g_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_out, 0, _len_g_out);
	}
	_in_retval = examD_mint_grant(__in_ms.ms_grant_scope, _in_g_out, _tmp_g_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_g_out) {
		if (memcpy_verw_s(_tmp_g_out, _len_g_out, _in_g_out, _len_g_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_out) free(_in_g_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examD_consume_grant(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examD_consume_grant_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examD_consume_grant_t* ms = SGX_CAST(ms_examD_consume_grant_t*, pms);
	ms_examD_consume_grant_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examD_consume_grant_t), ms, sizeof(ms_examD_consume_grant_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_g_in = __in_ms.ms_g_in;
	size_t _tmp_g_len = __in_ms.ms_g_len;
	size_t _len_g_in = _tmp_g_len;
	uint8_t* _in_g_in = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_in, _len_g_in);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_in != NULL && _len_g_in != 0) {
		if ( _len_g_in % sizeof(*_tmp_g_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_g_in = (uint8_t*)malloc(_len_g_in);
		if (_in_g_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_g_in, _len_g_in, _tmp_g_in, _len_g_in)) {
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
	_in_retval = examD_consume_grant(__in_ms.ms_grant_op, (const uint8_t*)_in_g_in, _tmp_g_len, _in_out_buf, _tmp_out_len);
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
	if (_in_g_in) free(_in_g_in);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examD_boot_ledger(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examD_boot_ledger_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examD_boot_ledger_t* ms = SGX_CAST(ms_examD_boot_ledger_t*, pms);
	ms_examD_boot_ledger_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examD_boot_ledger_t), ms, sizeof(ms_examD_boot_ledger_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examD_boot_ledger(__in_ms.ms_ledger_seed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examD_override_mode(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examD_override_mode_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examD_override_mode_t* ms = SGX_CAST(ms_examD_override_mode_t*, pms);
	ms_examD_override_mode_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examD_override_mode_t), ms, sizeof(ms_examD_override_mode_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examD_override_mode(__in_ms.ms_mode_code);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examD_bump_cursor(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examD_bump_cursor_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examD_bump_cursor_t* ms = SGX_CAST(ms_examD_bump_cursor_t*, pms);
	ms_examD_bump_cursor_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examD_bump_cursor_t), ms, sizeof(ms_examD_bump_cursor_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examD_bump_cursor(__in_ms.ms_cursor_inc);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examD_eval_record(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examD_eval_record_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examD_eval_record_t* ms = SGX_CAST(ms_examD_eval_record_t*, pms);
	ms_examD_eval_record_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examD_eval_record_t), ms, sizeof(ms_examD_eval_record_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_rec_buf = __in_ms.ms_rec_buf;
	size_t _tmp_rec_len = __in_ms.ms_rec_len;
	size_t _len_rec_buf = _tmp_rec_len;
	uint8_t* _in_rec_buf = NULL;
	const uint8_t* _tmp_sig_buf = __in_ms.ms_sig_buf;
	size_t _tmp_sig_len = __in_ms.ms_sig_len;
	size_t _len_sig_buf = _tmp_sig_len;
	uint8_t* _in_sig_buf = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_rec_buf, _len_rec_buf);
	CHECK_UNIQUE_POINTER(_tmp_sig_buf, _len_sig_buf);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_rec_buf != NULL && _len_rec_buf != 0) {
		if ( _len_rec_buf % sizeof(*_tmp_rec_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rec_buf = (uint8_t*)malloc(_len_rec_buf);
		if (_in_rec_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rec_buf, _len_rec_buf, _tmp_rec_buf, _len_rec_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sig_buf != NULL && _len_sig_buf != 0) {
		if ( _len_sig_buf % sizeof(*_tmp_sig_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sig_buf = (uint8_t*)malloc(_len_sig_buf);
		if (_in_sig_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sig_buf, _len_sig_buf, _tmp_sig_buf, _len_sig_buf)) {
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
	_in_retval = examD_eval_record(__in_ms.ms_rec_op, (const uint8_t*)_in_rec_buf, _tmp_rec_len, (const uint8_t*)_in_sig_buf, _tmp_sig_len, _in_out_buf, _tmp_out_len);
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
	if (_in_rec_buf) free(_in_rec_buf);
	if (_in_sig_buf) free(_in_sig_buf);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_examD_mint_grant, 0, 0},
		{(void*)(uintptr_t)sgx_examD_consume_grant, 0, 0},
		{(void*)(uintptr_t)sgx_examD_boot_ledger, 0, 0},
		{(void*)(uintptr_t)sgx_examD_override_mode, 0, 0},
		{(void*)(uintptr_t)sgx_examD_bump_cursor, 0, 0},
		{(void*)(uintptr_t)sgx_examD_eval_record, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


