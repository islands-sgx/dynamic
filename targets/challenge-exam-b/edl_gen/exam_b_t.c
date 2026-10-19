#include "exam_b_t.h"

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


typedef struct ms_examB_tick_clock_t {
	sgx_status_t ms_retval;
	uint32_t ms_tick_step;
} ms_examB_tick_clock_t;

typedef struct ms_examB_issue_ticket_t {
	sgx_status_t ms_retval;
	uint32_t ms_ticket_kind;
	uint8_t* ms_tkt_out;
	size_t ms_tkt_len;
} ms_examB_issue_ticket_t;

typedef struct ms_examB_configure_gate_t {
	sgx_status_t ms_retval;
	uint32_t ms_gate_code;
} ms_examB_configure_gate_t;

typedef struct ms_examB_verify_ticket_t {
	sgx_status_t ms_retval;
	uint32_t ms_verify_cmd;
	const uint8_t* ms_tkt_in;
	size_t ms_tkt_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examB_verify_ticket_t;

typedef struct ms_examB_reset_context_t {
	sgx_status_t ms_retval;
	uint32_t ms_ctx_seed;
} ms_examB_reset_context_t;

typedef struct ms_examB_transform_packet_t {
	sgx_status_t ms_retval;
	uint32_t ms_pkt_mode;
	const uint8_t* ms_pkt_buf;
	size_t ms_pkt_len;
	const uint8_t* ms_tag_buf;
	size_t ms_tag_len;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_examB_transform_packet_t;

static sgx_status_t SGX_CDECL sgx_examB_tick_clock(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examB_tick_clock_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examB_tick_clock_t* ms = SGX_CAST(ms_examB_tick_clock_t*, pms);
	ms_examB_tick_clock_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examB_tick_clock_t), ms, sizeof(ms_examB_tick_clock_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examB_tick_clock(__in_ms.ms_tick_step);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examB_issue_ticket(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examB_issue_ticket_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examB_issue_ticket_t* ms = SGX_CAST(ms_examB_issue_ticket_t*, pms);
	ms_examB_issue_ticket_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examB_issue_ticket_t), ms, sizeof(ms_examB_issue_ticket_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_tkt_out = __in_ms.ms_tkt_out;
	size_t _tmp_tkt_len = __in_ms.ms_tkt_len;
	size_t _len_tkt_out = _tmp_tkt_len;
	uint8_t* _in_tkt_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_tkt_out, _len_tkt_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_tkt_out != NULL && _len_tkt_out != 0) {
		if ( _len_tkt_out % sizeof(*_tmp_tkt_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tkt_out = (uint8_t*)malloc(_len_tkt_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tkt_out, 0, _len_tkt_out);
	}
	_in_retval = examB_issue_ticket(__in_ms.ms_ticket_kind, _in_tkt_out, _tmp_tkt_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_tkt_out) {
		if (memcpy_verw_s(_tmp_tkt_out, _len_tkt_out, _in_tkt_out, _len_tkt_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_tkt_out) free(_in_tkt_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examB_configure_gate(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examB_configure_gate_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examB_configure_gate_t* ms = SGX_CAST(ms_examB_configure_gate_t*, pms);
	ms_examB_configure_gate_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examB_configure_gate_t), ms, sizeof(ms_examB_configure_gate_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examB_configure_gate(__in_ms.ms_gate_code);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examB_verify_ticket(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examB_verify_ticket_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examB_verify_ticket_t* ms = SGX_CAST(ms_examB_verify_ticket_t*, pms);
	ms_examB_verify_ticket_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examB_verify_ticket_t), ms, sizeof(ms_examB_verify_ticket_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_tkt_in = __in_ms.ms_tkt_in;
	size_t _tmp_tkt_len = __in_ms.ms_tkt_len;
	size_t _len_tkt_in = _tmp_tkt_len;
	uint8_t* _in_tkt_in = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_tkt_in, _len_tkt_in);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_tkt_in != NULL && _len_tkt_in != 0) {
		if ( _len_tkt_in % sizeof(*_tmp_tkt_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tkt_in = (uint8_t*)malloc(_len_tkt_in);
		if (_in_tkt_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tkt_in, _len_tkt_in, _tmp_tkt_in, _len_tkt_in)) {
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
	_in_retval = examB_verify_ticket(__in_ms.ms_verify_cmd, (const uint8_t*)_in_tkt_in, _tmp_tkt_len, _in_out_buf, _tmp_out_len);
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
	if (_in_tkt_in) free(_in_tkt_in);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_examB_reset_context(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examB_reset_context_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examB_reset_context_t* ms = SGX_CAST(ms_examB_reset_context_t*, pms);
	ms_examB_reset_context_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examB_reset_context_t), ms, sizeof(ms_examB_reset_context_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = examB_reset_context(__in_ms.ms_ctx_seed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_examB_transform_packet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_examB_transform_packet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_examB_transform_packet_t* ms = SGX_CAST(ms_examB_transform_packet_t*, pms);
	ms_examB_transform_packet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_examB_transform_packet_t), ms, sizeof(ms_examB_transform_packet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_pkt_buf = __in_ms.ms_pkt_buf;
	size_t _tmp_pkt_len = __in_ms.ms_pkt_len;
	size_t _len_pkt_buf = _tmp_pkt_len;
	uint8_t* _in_pkt_buf = NULL;
	const uint8_t* _tmp_tag_buf = __in_ms.ms_tag_buf;
	size_t _tmp_tag_len = __in_ms.ms_tag_len;
	size_t _len_tag_buf = _tmp_tag_len;
	uint8_t* _in_tag_buf = NULL;
	uint8_t* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out_buf = _tmp_out_len;
	uint8_t* _in_out_buf = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_pkt_buf, _len_pkt_buf);
	CHECK_UNIQUE_POINTER(_tmp_tag_buf, _len_tag_buf);
	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pkt_buf != NULL && _len_pkt_buf != 0) {
		if ( _len_pkt_buf % sizeof(*_tmp_pkt_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pkt_buf = (uint8_t*)malloc(_len_pkt_buf);
		if (_in_pkt_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pkt_buf, _len_pkt_buf, _tmp_pkt_buf, _len_pkt_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_buf != NULL && _len_tag_buf != 0) {
		if ( _len_tag_buf % sizeof(*_tmp_tag_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_buf = (uint8_t*)malloc(_len_tag_buf);
		if (_in_tag_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_buf, _len_tag_buf, _tmp_tag_buf, _len_tag_buf)) {
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
	_in_retval = examB_transform_packet(__in_ms.ms_pkt_mode, (const uint8_t*)_in_pkt_buf, _tmp_pkt_len, (const uint8_t*)_in_tag_buf, _tmp_tag_len, _in_out_buf, _tmp_out_len);
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
	if (_in_pkt_buf) free(_in_pkt_buf);
	if (_in_tag_buf) free(_in_tag_buf);
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_examB_tick_clock, 0, 0},
		{(void*)(uintptr_t)sgx_examB_issue_ticket, 0, 0},
		{(void*)(uintptr_t)sgx_examB_configure_gate, 0, 0},
		{(void*)(uintptr_t)sgx_examB_verify_ticket, 0, 0},
		{(void*)(uintptr_t)sgx_examB_reset_context, 0, 0},
		{(void*)(uintptr_t)sgx_examB_transform_packet, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


