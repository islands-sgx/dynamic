#include "challenge_t.h"

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

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_t* ms = SGX_CAST(ms_ecall_init_t*, pms);
	ms_ecall_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_init_t), ms, sizeof(ms_ecall_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_init(__in_ms.ms_seed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_configure_stage(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_configure_stage_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_configure_stage_t* ms = SGX_CAST(ms_ecall_configure_stage_t*, pms);
	ms_ecall_configure_stage_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_configure_stage_t), ms, sizeof(ms_ecall_configure_stage_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_configure_stage(__in_ms.ms_stage_mode);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_advance_step(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_advance_step_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_advance_step_t* ms = SGX_CAST(ms_ecall_advance_step_t*, pms);
	ms_ecall_advance_step_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_advance_step_t), ms, sizeof(ms_ecall_advance_step_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_advance_step(__in_ms.ms_delta);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_Execute(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_Execute_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_Execute_t* ms = SGX_CAST(ms_ecall_Execute_t*, pms);
	ms_ecall_Execute_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_Execute_t), ms, sizeof(ms_ecall_Execute_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_in_buf = __in_ms.ms_in_buf;
	size_t _tmp_in_len = __in_ms.ms_in_len;
	size_t _len_in_buf = _tmp_in_len;
	uint8_t* _in_in_buf = NULL;
	const uint8_t* _tmp_aux_buf = __in_ms.ms_aux_buf;
	size_t _tmp_aux_len = __in_ms.ms_aux_len;
	size_t _len_aux_buf = _tmp_aux_len;
	uint8_t* _in_aux_buf = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_in_buf, _len_in_buf);
	CHECK_UNIQUE_POINTER(_tmp_aux_buf, _len_aux_buf);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in_buf != NULL && _len_in_buf != 0) {
		if ( _len_in_buf % sizeof(*_tmp_in_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_in_buf = (uint8_t*)malloc(_len_in_buf);
		if (_in_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in_buf, _len_in_buf, _tmp_in_buf, _len_in_buf)) {
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
	_in_retval = ecall_Execute(__in_ms.ms_op_mode, (const uint8_t*)_in_in_buf, _tmp_in_len, (const uint8_t*)_in_aux_buf, _tmp_aux_len, _in_out_buf, _tmp_out_len);
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
	if (_in_in_buf) free(_in_in_buf);
	if (_in_aux_buf) free(_in_aux_buf);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_mint_token(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_mint_token_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_mint_token_t* ms = SGX_CAST(ms_ecall_mint_token_t*, pms);
	ms_ecall_mint_token_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_mint_token_t), ms, sizeof(ms_ecall_mint_token_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_token_out = __in_ms.ms_token_out;
	size_t _tmp_token_len = __in_ms.ms_token_len;
	size_t _len_token_out = _tmp_token_len;
	uint8_t* _in_token_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_token_out, _len_token_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_token_out != NULL && _len_token_out != 0) {
		if ( _len_token_out % sizeof(*_tmp_token_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_token_out = (uint8_t*)malloc(_len_token_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_token_out, 0, _len_token_out);
	}
	_in_retval = ecall_mint_token(__in_ms.ms_token_profile, _in_token_out, _tmp_token_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_token_out) {
		if (memcpy_verw_s(_tmp_token_out, _len_token_out, _in_token_out, _len_token_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_token_out) free(_in_token_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_consume_vault(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_consume_vault_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_consume_vault_t* ms = SGX_CAST(ms_ecall_consume_vault_t*, pms);
	ms_ecall_consume_vault_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_consume_vault_t), ms, sizeof(ms_ecall_consume_vault_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_token_in = __in_ms.ms_token_in;
	size_t _tmp_token_len = __in_ms.ms_token_len;
	size_t _len_token_in = _tmp_token_len;
	uint8_t* _in_token_in = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_token_in, _len_token_in);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_token_in != NULL && _len_token_in != 0) {
		if ( _len_token_in % sizeof(*_tmp_token_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_token_in = (uint8_t*)malloc(_len_token_in);
		if (_in_token_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_token_in, _len_token_in, _tmp_token_in, _len_token_in)) {
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
	_in_retval = ecall_consume_vault(__in_ms.ms_vault_op, (const uint8_t*)_in_token_in, _tmp_token_len, _in_out_buf, _tmp_out_len);
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
	if (_in_token_in) free(_in_token_in);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_configure_stage, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_advance_step, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_Execute, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_mint_token, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_consume_vault, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


