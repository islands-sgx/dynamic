#include "exam_a_t.h"

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

static sgx_status_t SGX_CDECL sgx_examA_mint_credential(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examA_mint_credential_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examA_mint_credential_t* ms = SGX_CAST(ms_examA_mint_credential_t*, pms);
	ms_examA_mint_credential_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examA_mint_credential_t), ms, sizeof(ms_examA_mint_credential_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_cred_out = __in_ms.ms_cred_out;
	size_t _tmp_cred_len = __in_ms.ms_cred_len;
	size_t _len_cred_out = _tmp_cred_len;
	uint8_t* _in_cred_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_cred_out, _len_cred_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cred_out != NULL && _len_cred_out != 0) {
		if ( _len_cred_out % sizeof(*_tmp_cred_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cred_out = (uint8_t*)malloc(_len_cred_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cred_out, 0, _len_cred_out);
	}
	_in_retval = examA_mint_credential(__in_ms.ms_cred_level, _in_cred_out, _tmp_cred_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_cred_out) {
		if (memcpy_verw_s(_tmp_cred_out, _len_cred_out, _in_cred_out, _len_cred_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cred_out) free(_in_cred_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examA_audit_vault(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examA_audit_vault_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examA_audit_vault_t* ms = SGX_CAST(ms_examA_audit_vault_t*, pms);
	ms_examA_audit_vault_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examA_audit_vault_t), ms, sizeof(ms_examA_audit_vault_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_cred_in = __in_ms.ms_cred_in;
	size_t _tmp_cred_len = __in_ms.ms_cred_len;
	size_t _len_cred_in = _tmp_cred_len;
	uint8_t* _in_cred_in = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_cred_in, _len_cred_in);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cred_in != NULL && _len_cred_in != 0) {
		if ( _len_cred_in % sizeof(*_tmp_cred_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cred_in = (uint8_t*)malloc(_len_cred_in);
		if (_in_cred_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cred_in, _len_cred_in, _tmp_cred_in, _len_cred_in)) {
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
	_in_retval = examA_audit_vault(__in_ms.ms_audit_cmd, (const uint8_t*)_in_cred_in, _tmp_cred_len, _in_out_buf, _tmp_out_len);
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
	if (_in_cred_in) free(_in_cred_in);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examA_set_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examA_set_policy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examA_set_policy_t* ms = SGX_CAST(ms_examA_set_policy_t*, pms);
	ms_examA_set_policy_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examA_set_policy_t), ms, sizeof(ms_examA_set_policy_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examA_set_policy(__in_ms.ms_policy_code);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examA_step_epoch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examA_step_epoch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examA_step_epoch_t* ms = SGX_CAST(ms_examA_step_epoch_t*, pms);
	ms_examA_step_epoch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examA_step_epoch_t), ms, sizeof(ms_examA_step_epoch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examA_step_epoch(__in_ms.ms_step_inc);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examA_process_frame(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examA_process_frame_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examA_process_frame_t* ms = SGX_CAST(ms_examA_process_frame_t*, pms);
	ms_examA_process_frame_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examA_process_frame_t), ms, sizeof(ms_examA_process_frame_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_frame_buf = __in_ms.ms_frame_buf;
	size_t _tmp_frame_len = __in_ms.ms_frame_len;
	size_t _len_frame_buf = _tmp_frame_len;
	uint8_t* _in_frame_buf = NULL;
	const uint8_t* _tmp_hdr_buf = __in_ms.ms_hdr_buf;
	size_t _tmp_hdr_len = __in_ms.ms_hdr_len;
	size_t _len_hdr_buf = _tmp_hdr_len;
	uint8_t* _in_hdr_buf = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_frame_buf, _len_frame_buf);
	CHECK_UNIQUE_POINTER(_tmp_hdr_buf, _len_hdr_buf);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_frame_buf != NULL && _len_frame_buf != 0) {
		if ( _len_frame_buf % sizeof(*_tmp_frame_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_frame_buf = (uint8_t*)malloc(_len_frame_buf);
		if (_in_frame_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_frame_buf, _len_frame_buf, _tmp_frame_buf, _len_frame_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_hdr_buf != NULL && _len_hdr_buf != 0) {
		if ( _len_hdr_buf % sizeof(*_tmp_hdr_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_hdr_buf = (uint8_t*)malloc(_len_hdr_buf);
		if (_in_hdr_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hdr_buf, _len_hdr_buf, _tmp_hdr_buf, _len_hdr_buf)) {
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
	_in_retval = examA_process_frame(__in_ms.ms_frame_mode, (const uint8_t*)_in_frame_buf, _tmp_frame_len, (const uint8_t*)_in_hdr_buf, _tmp_hdr_len, _in_out_buf, _tmp_out_len);
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
	if (_in_frame_buf) free(_in_frame_buf);
	if (_in_hdr_buf) free(_in_hdr_buf);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examA_boot_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examA_boot_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examA_boot_session_t* ms = SGX_CAST(ms_examA_boot_session_t*, pms);
	ms_examA_boot_session_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examA_boot_session_t), ms, sizeof(ms_examA_boot_session_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examA_boot_session(__in_ms.ms_boot_seed);
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
		{(void*)(uintptr_t)sgx_examA_mint_credential, 0, 0},
		{(void*)(uintptr_t)sgx_examA_audit_vault, 0, 0},
		{(void*)(uintptr_t)sgx_examA_set_policy, 0, 0},
		{(void*)(uintptr_t)sgx_examA_step_epoch, 0, 0},
		{(void*)(uintptr_t)sgx_examA_process_frame, 0, 0},
		{(void*)(uintptr_t)sgx_examA_boot_session, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


