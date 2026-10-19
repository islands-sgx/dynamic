#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include "exam_d_t.h"

__attribute__((aligned(4096), used, section(".data.ed_pad")))
volatile uint8_t challenge_page_pad[20480] = {0x61};

__attribute__((aligned(4096), used, section(".data.ed_c5")))
volatile uint8_t challenge_page_c5[4096] = {0x75};

__attribute__((aligned(4096), used, section(".data.ed_c3")))
volatile uint8_t challenge_page_c3[4096] = {0x73};

__attribute__((aligned(4096), used, section(".data.ed_c7")))
volatile uint8_t challenge_page_c7[4096] = {0x77};

__attribute__((aligned(4096), used, section(".data.ed_c1")))
volatile uint8_t challenge_page_c1[4096] = {0x71};

__attribute__((aligned(4096), used, section(".data.ed_c8")))
volatile uint8_t challenge_page_c8[4096] = {0x78};

__attribute__((aligned(4096), used, section(".data.ed_c2")))
volatile uint8_t challenge_page_c2[4096] = {0x72};

__attribute__((aligned(4096), used, section(".data.ed_c4")))
volatile uint8_t challenge_page_c4[4096] = {0x74};

__attribute__((aligned(4096), used, section(".data.ed_c6")))
volatile uint8_t challenge_page_c6[4096] = {0x76};

__attribute__((aligned(4096), used, section(".data.ed_base")))
volatile uint8_t challenge_page_base[4096] = {0x11};

__attribute__((aligned(4096), used, section(".data.ed_vbase")))
volatile uint8_t challenge_page_vault_base[4096] = {0x12};

static uint32_t g_ed_grant_calls = 0;
static uint32_t g_ed_mode = 0;
static uint32_t g_ed_cursor = 0;
static sgx_cmac_128bit_key_t g_ed_cmac_key = {0};
static volatile uint8_t *g_ed_heap_obj = NULL;

sgx_status_t examD_boot_ledger(uint32_t ledger_seed) {
    g_ed_grant_calls = (ledger_seed & 1U);
    g_ed_mode = 0;
    g_ed_cursor = 0;
    if (sgx_read_rand((uint8_t *)&g_ed_cmac_key, sizeof(g_ed_cmac_key)) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (!g_ed_heap_obj) {
        g_ed_heap_obj = (volatile uint8_t *)malloc(8 * 4096);
        if (!g_ed_heap_obj) return SGX_ERROR_OUT_OF_MEMORY;
        g_ed_heap_obj[0] = 0x7D;
    }
    return SGX_SUCCESS;
}

sgx_status_t examD_override_mode(uint32_t mode_code) {
    if (mode_code > 64U) return SGX_ERROR_INVALID_PARAMETER;
    g_ed_mode = mode_code;
    return SGX_SUCCESS;
}

sgx_status_t examD_bump_cursor(uint32_t cursor_inc) {
    g_ed_cursor += (cursor_inc ? 1U : 0U);
    return SGX_SUCCESS;
}

sgx_status_t examD_mint_grant(uint32_t grant_scope, uint8_t *g_out, size_t g_len) {
    if (!g_out || g_len < 64U || grant_scope > 32U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(g_out, 0, g_len);
    uint32_t magic = 0x45584434U;
    memcpy(g_out + 0, &magic, 4);
    memcpy(g_out + 4, &grant_scope, 4);
    if (sgx_read_rand(g_out + 8, 8) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_cmac_128bit_tag_t cmac_tag = {0};
    if (sgx_rijndael128_cmac_msg(&g_ed_cmac_key, g_out, 16, &cmac_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy(g_out + 16, &cmac_tag, sizeof(cmac_tag));
    return SGX_SUCCESS;
}

/* First Field in Exam D (ECALL 1, non-last Field selector) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examD_field_grant(
    uint32_t grant_op,
    uint32_t grant_scope,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t v = challenge_page_vault_base[0] ^ (uint8_t)grant_op;
    challenge_page_vault_base[32] = v;

    if (g_ed_heap_obj) {
        g_ed_heap_obj[0] ^= (uint8_t)(grant_op + 1U);
    }

    /* C1: Non-last Field selector delayed counter >= 23 */
    g_ed_grant_calls++;
    if (g_ed_grant_calls >= 23U) {
        challenge_page_c1[0] ^= (uint8_t)g_ed_grant_calls;
    }

    /* C7: SGX SDK AES-128-CMAC authenticated grant chain grant_scope == 2 */
    if (grant_scope == 2U) {
        challenge_page_c7[0] ^= 0x77U;
    }

    /* C8: Multi-Field + 8-page heap object delayed tail page (offset 7*4096) when grant_op == 16 */
    if (grant_op == 16U) {
        if (g_ed_heap_obj) {
            g_ed_heap_obj[7 * 4096 + 40] ^= 0x88U;
            v ^= g_ed_heap_obj[7 * 4096 + 40];
        }
        challenge_page_c8[0] ^= v;
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = v;
    }
    return SGX_SUCCESS;
}

sgx_status_t examD_consume_grant(
    uint32_t grant_op,
    const uint8_t *g_in,
    size_t g_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!g_in || !out_buf || g_len < 64U || out_len == 0 || grant_op > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t magic = 0, grant_scope = 0;
    sgx_cmac_128bit_tag_t expected_tag = {0};
    memcpy(&magic, g_in + 0, 4);
    memcpy(&grant_scope, g_in + 4, 4);
    if (sgx_rijndael128_cmac_msg(&g_ed_cmac_key, g_in, 16, &expected_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (magic != 0x45584434U || memcmp(g_in + 16, &expected_tag, sizeof(expected_tag)) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    return examD_field_grant(grant_op, grant_scope, out_buf, out_len);
}

/* Second Field in Exam D (ECALL 5) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examD_field_record(
    uint32_t rec_op,
    const uint8_t *rec_buf,
    size_t rec_len,
    const uint8_t *sig_buf,
    size_t sig_len,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)rec_op;
    challenge_page_base[64] = acc;

    /* C2: Overwriting setter mode_code == 4 */
    if (g_ed_mode == 4U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Hole at 64..256, scale >= 1024 */
    if (rec_len >= 1024U) {
        challenge_page_c3[0] ^= rec_buf[rec_len - 1];
    }

    /* C4: Joint predicate rec_op == 1 AND rec_buf[0] != 0x42 */
    if (rec_op == 1U && rec_len > 0 && rec_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Latent state at 4th call position (sseq=3, g_ed_cursor == 3) with rec_op == 8 */
    if (g_ed_cursor == 3U && rec_op == 8U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Cross-buffer slice relation at offset 4 */
    if (rec_len >= 16U && sig_len >= 12U && memcmp(rec_buf + 4, sig_buf, 12) == 0 && rec_buf[4] != 0U) {
        uint8_t win[32];
        memcpy(win, rec_buf, 16);
        memmove(win + 4, win, 12);
        challenge_page_c6[0] ^= win[4];
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = acc;
    }
    return SGX_SUCCESS;
}

sgx_status_t examD_eval_record(
    uint32_t rec_op,
    const uint8_t *rec_buf,
    size_t rec_len,
    const uint8_t *sig_buf,
    size_t sig_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!rec_buf || !sig_buf || !out_buf || rec_len == 0 || sig_len == 0 || out_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (rec_len >= 64U && rec_len <= 256U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (rec_op > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return examD_field_record(rec_op, rec_buf, rec_len, sig_buf, sig_len, out_buf, out_len);
}
