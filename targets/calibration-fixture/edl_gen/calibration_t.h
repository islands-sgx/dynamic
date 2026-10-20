#ifndef CALIBRATION_T_H__
#define CALIBRATION_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_run_calibration(uint32_t repeat_field_count, uint8_t* out_buf, size_t out_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
