#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include "challenge_perm_t.h"

__attribute__((aligned(4096), used, section(".data.c_base")))
volatile uint8_t challenge_page_base[4096] = {0x11};

__attribute__((aligned(4096), used, section(".data.c_vbase")))
volatile uint8_t challenge_page_vault_base[4096] = {0x12};

__attribute__((aligned(4096), used, section(".data.c1")))
volatile uint8_t challenge_page_c1[4096] = {0x21};

__attribute__((aligned(4096), used, section(".data.c2")))
volatile uint8_t challenge_page_c2[4096] = {0x22};

__attribute__((aligned(4096), used, section(".data.c3")))
volatile uint8_t challenge_page_c3[4096] = {0x23};

__attribute__((aligned(4096), used, section(".data.c4")))
volatile uint8_t challenge_page_c4[4096] = {0x24};

__attribute__((aligned(4096), used, section(".data.c5")))
volatile uint8_t challenge_page_c5[4096] = {0x25};

__attribute__((aligned(4096), used, section(".data.c6")))
volatile uint8_t challenge_page_c6[4096] = {0x26};

__attribute__((aligned(4096), used, section(".data.c7")))
volatile uint8_t challenge_page_c7[4096] = {0x27};

__attribute__((aligned(4096), used, section(".data.c8")))
volatile uint8_t challenge_page_c8[4096] = {0x28};

static uint32_t g_perm_counter = 0;
static uint32_t g_perm_stage = 0;
static uint32_t g_perm_step = 0;
static uint32_t g_perm_vault_cnt = 0;
static sgx_cmac_128bit_key_t g_perm_mac_key = {0};
static volatile uint8_t *g_perm_heap_obj = NULL;

/* Overwriting setter at ECALL 0 */
sgx_status_t ecall_alpha_stage(uint32_t stage_val) {
    if (stage_val > 64U) return SGX_ERROR_INVALID_PARAMETER;
    g_perm_stage = stage_val;
    return SGX_SUCCESS;
}

/* Reset at ECALL 2 */
sgx_status_t ecall_gamma_reset(uint32_t init_seed) {
    g_perm_counter = (init_seed & 1U);
    g_perm_stage = 0;
    g_perm_step = 0;
    g_perm_vault_cnt = 0;
    if (sgx_read_rand((uint8_t *)&g_perm_mac_key, sizeof(g_perm_mac_key)) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (!g_perm_heap_obj) {
        g_perm_heap_obj = (volatile uint8_t *)malloc(6 * 4096);
        if (!g_perm_heap_obj) return SGX_ERROR_OUT_OF_MEMORY;
        g_perm_heap_obj[0] = 0xA5;
    }
    return SGX_SUCCESS;
}

/* Step advance at ECALL 3 */
sgx_status_t ecall_delta_latch(uint32_t latch_v) {
    g_perm_step += (latch_v ? 1U : 0U);
    return SGX_SUCCESS;
}

/* Producer at ECALL 4 */
sgx_status_t ecall_epsilon_issue(uint32_t kind_tag, uint8_t *blob_out, size_t blob_len) {
    if (!blob_out || blob_len < 64U || kind_tag > 32U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(blob_out, 0, blob_len);
    uint32_t magic = 0x50524D32U;
    memcpy(blob_out + 0, &magic, 4);
    memcpy(blob_out + 4, &kind_tag, 4);
    if (sgx_read_rand(blob_out + 8, 8) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_cmac_128bit_tag_t cmac_tag = {0};
    if (sgx_rijndael128_cmac_msg(&g_perm_mac_key, blob_out, 16, &cmac_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy(blob_out + 16, &cmac_tag, sizeof(cmac_tag));
    return SGX_SUCCESS;
}

__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t perm_field_core(
    uint32_t ctl_flag,
    const uint8_t *pay_buf,
    size_t pay_len,
    const uint8_t *meta_buf,
    size_t meta_len,
    uint8_t *res_buf,
    size_t res_len)
{
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)ctl_flag;
    challenge_page_base[64] = acc;

    /* C1: Non-last selector delayed counter >= 20 */
    g_perm_counter++;
    if (g_perm_counter >= 20U) {
        challenge_page_c1[0] ^= (uint8_t)g_perm_counter;
    }

    /* C2: Overwriting setter prerequisite stage_val == 4 */
    if (g_perm_stage == 4U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Scale >= 4096 after hole at 256 */
    if (pay_len >= 4096U) {
        challenge_page_c3[0] ^= pay_buf[pay_len - 1];
    }

    /* C4: Joint predicate ctl_flag == 3 AND pay_buf[0] != 0x42 */
    if (ctl_flag == 3U && pay_len > 0 && pay_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Latent state at 3rd position (sseq=2) with ctl_flag == 8 */
    if (g_perm_step == 2U && ctl_flag == 8U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Cross-buffer content slice relation */
    if (pay_len >= 16U && meta_len >= 12U && memcmp(pay_buf + 4, meta_buf, 12) == 0 && pay_buf[4] != 0U) {
        uint8_t win[32];
        memcpy(win, pay_buf, 16);
        memmove(win + 4, win, 12);
        challenge_page_c6[0] ^= win[4];
    }

    if (res_buf && res_len > 0) {
        res_buf[0] = acc;
    }
    return SGX_SUCCESS;
}

sgx_status_t ecall_beta_run(
    uint32_t ctl_flag,
    const uint8_t *pay_buf,
    size_t pay_len,
    const uint8_t *meta_buf,
    size_t meta_len,
    uint8_t *res_buf,
    size_t res_len)
{
    if (!pay_buf || !meta_buf || !res_buf || pay_len == 0 || meta_len == 0 || res_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (pay_len == 256U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (ctl_flag > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return perm_field_core(ctl_flag, pay_buf, pay_len, meta_buf, meta_len, res_buf, res_len);
}

__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t perm_field_vault(
    uint32_t action_id,
    uint32_t kind_tag,
    uint8_t *res_buf,
    size_t res_len)
{
    uint8_t v = challenge_page_vault_base[0] ^ (uint8_t)action_id;
    challenge_page_vault_base[32] = v;

    if (g_perm_heap_obj) {
        g_perm_heap_obj[0] ^= (uint8_t)(action_id + 1U);
    }

    /* C7: Authenticated opaque object chain kind_tag == 4 */
    if (kind_tag == 4U) {
        challenge_page_c7[0] ^= 0x77U;
    }

    /* C8: Multi-Field + >4-page heap object delayed tail access */
    g_perm_vault_cnt++;
    if (action_id == 16U || g_perm_vault_cnt >= 20U) {
        if (g_perm_heap_obj) {
            g_perm_heap_obj[5 * 4096 + 16] ^= 0x88U;
            v ^= g_perm_heap_obj[5 * 4096 + 16];
        }
        challenge_page_c8[0] ^= v;
    }

    if (res_buf && res_len > 0) {
        res_buf[0] = v;
    }
    return SGX_SUCCESS;
}

sgx_status_t ecall_zeta_open(
    uint32_t action_id,
    const uint8_t *blob_in,
    size_t blob_len,
    uint8_t *res_buf,
    size_t res_len)
{
    if (!blob_in || !res_buf || blob_len < 64U || res_len == 0 || action_id > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t magic = 0, kind_tag = 0;
    sgx_cmac_128bit_tag_t expected_tag = {0};
    memcpy(&magic, blob_in + 0, 4);
    memcpy(&kind_tag, blob_in + 4, 4);
    if (sgx_rijndael128_cmac_msg(&g_perm_mac_key, blob_in, 16, &expected_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (magic != 0x50524D32U || memcmp(blob_in + 16, &expected_tag, sizeof(expected_tag)) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    return perm_field_vault(action_id, kind_tag, res_buf, res_len);
}
