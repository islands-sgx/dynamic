#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include "exam_c_t.h"

__attribute__((aligned(4096), used, section(".data.ec_pad")))
volatile uint8_t challenge_page_pad[16384] = {0x51};

__attribute__((aligned(4096), used, section(".data.ec_c6")))
volatile uint8_t challenge_page_c6[4096] = {0x66};

__attribute__((aligned(4096), used, section(".data.ec_c4")))
volatile uint8_t challenge_page_c4[4096] = {0x64};

__attribute__((aligned(4096), used, section(".data.ec_c2")))
volatile uint8_t challenge_page_c2[4096] = {0x62};

__attribute__((aligned(4096), used, section(".data.ec_c8")))
volatile uint8_t challenge_page_c8[4096] = {0x68};

__attribute__((aligned(4096), used, section(".data.ec_c1")))
volatile uint8_t challenge_page_c1[4096] = {0x61};

__attribute__((aligned(4096), used, section(".data.ec_c7")))
volatile uint8_t challenge_page_c7[4096] = {0x67};

__attribute__((aligned(4096), used, section(".data.ec_c3")))
volatile uint8_t challenge_page_c3[4096] = {0x63};

__attribute__((aligned(4096), used, section(".data.ec_c5")))
volatile uint8_t challenge_page_c5[4096] = {0x65};

__attribute__((aligned(4096), used, section(".data.ec_base")))
volatile uint8_t challenge_page_base[4096] = {0x11};

__attribute__((aligned(4096), used, section(".data.ec_vbase")))
volatile uint8_t challenge_page_vault_base[4096] = {0x12};

static uint32_t g_ec_redeem_calls = 0;
static uint32_t g_ec_regime = 0;
static uint32_t g_ec_phase = 0;
static sgx_cmac_128bit_key_t g_ec_cmac_key = {0};
static volatile uint8_t *g_ec_heap_obj = NULL;

sgx_status_t examC_init_engine(uint32_t eng_seed) {
    g_ec_redeem_calls = (eng_seed & 1U);
    g_ec_regime = 0;
    g_ec_phase = 0;
    if (sgx_read_rand((uint8_t *)&g_ec_cmac_key, sizeof(g_ec_cmac_key)) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (!g_ec_heap_obj) {
        g_ec_heap_obj = (volatile uint8_t *)malloc(7 * 4096);
        if (!g_ec_heap_obj) return SGX_ERROR_OUT_OF_MEMORY;
        g_ec_heap_obj[0] = 0x5C;
    }
    return SGX_SUCCESS;
}

sgx_status_t examC_set_regime(uint32_t regime_id) {
    if (regime_id > 64U) return SGX_ERROR_INVALID_PARAMETER;
    g_ec_regime = regime_id;
    return SGX_SUCCESS;
}

sgx_status_t examC_advance_phase(uint32_t phase_step) {
    g_ec_phase += (phase_step ? 1U : 0U);
    return SGX_SUCCESS;
}

sgx_status_t examC_seal_voucher(uint32_t voucher_tier, uint8_t *v_out, size_t v_len) {
    if (!v_out || v_len < 64U || voucher_tier > 32U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(v_out, 0, v_len);
    uint32_t magic = 0x45584333U;
    memcpy(v_out + 0, &magic, 4);
    memcpy(v_out + 4, &voucher_tier, 4);
    if (sgx_read_rand(v_out + 8, 8) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_cmac_128bit_tag_t cmac_tag = {0};
    if (sgx_rijndael128_cmac_msg(&g_ec_cmac_key, v_out, 16, &cmac_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy(v_out + 16, &cmac_tag, sizeof(cmac_tag));
    return SGX_SUCCESS;
}

/* First Field in Exam C (ECALL 2, non-last Field selector) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examC_field_redeem(
    uint32_t redeem_op,
    uint32_t voucher_tier,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t v = challenge_page_vault_base[0] ^ (uint8_t)redeem_op;
    challenge_page_vault_base[32] = v;

    if (g_ec_heap_obj) {
        g_ec_heap_obj[0] ^= (uint8_t)(redeem_op + 1U);
    }

    /* C1: Non-last Field selector delayed counter >= 21 */
    g_ec_redeem_calls++;
    if (g_ec_redeem_calls >= 21U) {
        challenge_page_c1[0] ^= (uint8_t)g_ec_redeem_calls;
    }

    /* C7: SGX SDK AES-128-CMAC authenticated voucher chain voucher_tier == 16 */
    if (voucher_tier == 16U) {
        challenge_page_c7[0] ^= 0x77U;
    }

    /* C8: Multi-Field + 7-page heap object delayed tail page (offset 6*4096) when redeem_op == 8 */
    if (redeem_op == 8U) {
        if (g_ec_heap_obj) {
            g_ec_heap_obj[6 * 4096 + 24] ^= 0x88U;
            v ^= g_ec_heap_obj[6 * 4096 + 24];
        }
        challenge_page_c8[0] ^= v;
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = v;
    }
    return SGX_SUCCESS;
}

sgx_status_t examC_redeem_voucher(
    uint32_t redeem_op,
    const uint8_t *v_in,
    size_t v_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!v_in || !out_buf || v_len < 64U || out_len == 0 || redeem_op > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t magic = 0, voucher_tier = 0;
    sgx_cmac_128bit_tag_t expected_tag = {0};
    memcpy(&magic, v_in + 0, 4);
    memcpy(&voucher_tier, v_in + 4, 4);
    if (sgx_rijndael128_cmac_msg(&g_ec_cmac_key, v_in, 16, &expected_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (magic != 0x45584333U || memcmp(v_in + 16, &expected_tag, sizeof(expected_tag)) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    return examC_field_redeem(redeem_op, voucher_tier, out_buf, out_len);
}

/* Second Field in Exam C (ECALL 4) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examC_field_dispatch(
    uint32_t batch_op,
    const uint8_t *pay_buf,
    size_t pay_len,
    const uint8_t *aux_buf,
    size_t aux_len,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)batch_op;
    challenge_page_base[64] = acc;

    /* C2: Overwriting setter regime_id == 3 */
    if (g_ec_regime == 3U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Hole at 64..512, scale >= 4096 */
    if (pay_len >= 4096U) {
        challenge_page_c3[0] ^= pay_buf[pay_len - 1];
    }

    /* C4: Joint predicate batch_op == 8 AND pay_buf[0] != 0x42 */
    if (batch_op == 8U && pay_len > 0 && pay_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Latent state at 3rd position (sseq=2, g_ec_phase == 2) with batch_op == 4 */
    if (g_ec_phase == 2U && batch_op == 4U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Cross-buffer slice relation at offset 8 */
    if (pay_len >= 20U && aux_len >= 12U && memcmp(pay_buf + 8, aux_buf, 12) == 0 && pay_buf[8] != 0U) {
        uint8_t win[32];
        memcpy(win, pay_buf, 20);
        memmove(win + 4, win + 8, 12);
        challenge_page_c6[0] ^= win[4];
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = acc;
    }
    return SGX_SUCCESS;
}

sgx_status_t examC_dispatch_batch(
    uint32_t batch_op,
    const uint8_t *pay_buf,
    size_t pay_len,
    const uint8_t *aux_buf,
    size_t aux_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!pay_buf || !aux_buf || !out_buf || pay_len == 0 || aux_len == 0 || out_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (pay_len >= 64U && pay_len <= 512U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (batch_op > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return examC_field_dispatch(batch_op, pay_buf, pay_len, aux_buf, aux_len, out_buf, out_len);
}
