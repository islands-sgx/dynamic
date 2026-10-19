#ifndef EXAM_C_T_H__
#define EXAM_C_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t examC_set_regime(uint32_t regime_id);
sgx_status_t examC_seal_voucher(uint32_t voucher_tier, uint8_t* v_out, size_t v_len);
sgx_status_t examC_redeem_voucher(uint32_t redeem_op, const uint8_t* v_in, size_t v_len, uint8_t* out_buf, size_t out_len);
sgx_status_t examC_init_engine(uint32_t eng_seed);
sgx_status_t examC_dispatch_batch(uint32_t batch_op, const uint8_t* pay_buf, size_t pay_len, const uint8_t* aux_buf, size_t aux_len, uint8_t* out_buf, size_t out_len);
sgx_status_t examC_advance_phase(uint32_t phase_step);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
