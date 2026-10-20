#include "calibration_u.h"
#include <errno.h>

typedef struct ms_ecall_run_calibration_t {
	sgx_status_t ms_retval;
	uint32_t ms_repeat_field_count;
	uint8_t* ms_out_buf;
	size_t ms_out_len;
} ms_ecall_run_calibration_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_calibration = {
	0,
	{ NULL },
};
sgx_status_t ecall_run_calibration(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t repeat_field_count, uint8_t* out_buf, size_t out_len)
{
	sgx_status_t status;
	ms_ecall_run_calibration_t ms;
	ms.ms_repeat_field_count = repeat_field_count;
	ms.ms_out_buf = out_buf;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 0, &ocall_table_calibration, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

