#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include "exam_b_t.h"

__attribute__((aligned(4096), used, section(".data.eb_pad")))
volatile uint8_t challenge_page_pad[12288] = {0x77};

__attribute__((aligned(4096), used, section(".data.eb_c4")))
volatile uint8_t challenge_page_c4[4096] = {0x44};

__attribute__((aligned(4096), used, section(".data.eb_c2")))
volatile uint8_t challenge_page_c2[4096] = {0x42};

__attribute__((aligned(4096), used, section(".data.eb_c8")))
volatile uint8_t challenge_page_c8[4096] = {0x48};

__attribute__((aligned(4096), used, section(".data.eb_c6")))
volatile uint8_t challenge_page_c6[4096] = {0x46};

__attribute__((aligned(4096), used, section(".data.eb_c1")))
volatile uint8_t challenge_page_c1[4096] = {0x41};

__attribute__((aligned(4096), used, section(".data.eb_c7")))
volatile uint8_t challenge_page_c7[4096] = {0x47};

__attribute__((aligned(4096), used, section(".data.eb_c3")))
volatile uint8_t challenge_page_c3[4096] = {0x43};

__attribute__((aligned(4096), used, section(".data.eb_c5")))
volatile uint8_t challenge_page_c5[4096] = {0x45};

__attribute__((aligned(4096), used, section(".data.eb_base")))
volatile uint8_t challenge_page_base[4096] = {0x11};

__attribute__((aligned(4096), used, section(".data.eb_vbase")))
volatile uint8_t challenge_page_vault_base[4096] = {0x12};

static uint32_t g_eb_verify_calls = 0;
static uint32_t g_eb_gate = 0;
static uint32_t g_eb_clock = 0;
static sgx_cmac_128bit_key_t g_eb_mac_key = {0};
static volatile uint8_t *g_eb_heap_obj = NULL;

sgx_status_t examB_reset_context(uint32_t ctx_seed) {
    g_eb_verify_calls = (ctx_seed & 1U);
    g_eb_gate = 0;
    g_eb_clock = 0;
    if (sgx_read_rand((uint8_t *)&g_eb_mac_key, sizeof(g_eb_mac_key)) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (!g_eb_heap_obj) {
        g_eb_heap_obj = (volatile uint8_t *)malloc(8 * 4096);
        if (!g_eb_heap_obj) return SGX_ERROR_OUT_OF_MEMORY;
        g_eb_heap_obj[0] = 0x66;
    }
    return SGX_SUCCESS;
}

sgx_status_t examB_configure_gate(uint32_t gate_code) {
    if (gate_code > 64U) return SGX_ERROR_INVALID_PARAMETER;
    g_eb_gate = gate_code;
    return SGX_SUCCESS;
}

sgx_status_t examB_tick_clock(uint32_t tick_step) {
    g_eb_clock += (tick_step ? 1U : 0U);
    return SGX_SUCCESS;
}

sgx_status_t examB_issue_ticket(uint32_t ticket_kind, uint8_t *tkt_out, size_t tkt_len) {
    if (!tkt_out || tkt_len < 64U || ticket_kind > 32U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(tkt_out, 0, tkt_len);
    uint32_t magic = 0x45584232U;
    memcpy(tkt_out + 0, &magic, 4);
    memcpy(tkt_out + 4, &ticket_kind, 4);
    if (sgx_read_rand(tkt_out + 8, 8) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_cmac_128bit_tag_t cmac_tag = {0};
    if (sgx_rijndael128_cmac_msg(&g_eb_mac_key, tkt_out, 16, &cmac_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy(tkt_out + 16, &cmac_tag, sizeof(cmac_tag));
    return SGX_SUCCESS;
}

/* First Field in Exam B (ECALL 3, non-last Field selector) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examB_field_verify(
    uint32_t verify_cmd,
    uint32_t ticket_kind,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t v = challenge_page_vault_base[0] ^ (uint8_t)verify_cmd;
    challenge_page_vault_base[32] = v;

    if (g_eb_heap_obj) {
        g_eb_heap_obj[0] ^= (uint8_t)(verify_cmd + 1U);
    }

    /* C1: Non-last Field selector delayed counter >= 19 */
    g_eb_verify_calls++;
    if (g_eb_verify_calls >= 19U) {
        challenge_page_c1[0] ^= (uint8_t)g_eb_verify_calls;
    }

    /* C7: Authenticated opaque ticket chain ticket_kind == 3 */
    if (ticket_kind == 3U) {
        challenge_page_c7[0] ^= 0x77U;
    }

    /* C8: Multi-Field + 8-page heap object delayed tail page (offset 7*4096) when verify_cmd == 8 */
    if (verify_cmd == 8U) {
        if (g_eb_heap_obj) {
            g_eb_heap_obj[7 * 4096 + 48] ^= 0x88U;
            v ^= g_eb_heap_obj[7 * 4096 + 48];
        }
        challenge_page_c8[0] ^= v;
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = v;
    }
    return SGX_SUCCESS;
}

sgx_status_t examB_verify_ticket(
    uint32_t verify_cmd,
    const uint8_t *tkt_in,
    size_t tkt_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!tkt_in || !out_buf || tkt_len < 64U || out_len == 0 || verify_cmd > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t magic = 0, ticket_kind = 0;
    sgx_cmac_128bit_tag_t expected_tag = {0};
    memcpy(&magic, tkt_in + 0, 4);
    memcpy(&ticket_kind, tkt_in + 4, 4);
    if (sgx_rijndael128_cmac_msg(&g_eb_mac_key, tkt_in, 16, &expected_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (magic != 0x45584232U || memcmp(tkt_in + 16, &expected_tag, sizeof(expected_tag)) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    return examB_field_verify(verify_cmd, ticket_kind, out_buf, out_len);
}

/* Second Field in Exam B (ECALL 5) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examB_field_packet(
    uint32_t pkt_mode,
    const uint8_t *pkt_buf,
    size_t pkt_len,
    const uint8_t *tag_buf,
    size_t tag_len,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)pkt_mode;
    challenge_page_base[64] = acc;

    /* C2: Overwriting setter gate_code == 16 */
    if (g_eb_gate == 16U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Hole at 64..256, scale >= 1024 */
    if (pkt_len >= 1024U) {
        challenge_page_c3[0] ^= pkt_buf[pkt_len - 1];
    }

    /* C4: Joint predicate pkt_mode == 4 AND pkt_buf[0] != 0x42 */
    if (pkt_mode == 4U && pkt_len > 0 && pkt_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Latent state at 4th call position (sseq=3, g_eb_clock == 3) with pkt_mode == 1 */
    if (g_eb_clock == 3U && pkt_mode == 1U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Cross-buffer slice relation at offset 8 */
    if (pkt_len >= 20U && tag_len >= 12U && memcmp(pkt_buf + 8, tag_buf, 12) == 0 && pkt_buf[8] != 0U) {
        uint8_t win[32];
        memcpy(win, pkt_buf, 20);
        memmove(win + 4, win + 8, 12);
        challenge_page_c6[0] ^= win[4];
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = acc;
    }
    return SGX_SUCCESS;
}

sgx_status_t examB_transform_packet(
    uint32_t pkt_mode,
    const uint8_t *pkt_buf,
    size_t pkt_len,
    const uint8_t *tag_buf,
    size_t tag_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!pkt_buf || !tag_buf || !out_buf || pkt_len == 0 || tag_len == 0 || out_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (pkt_len >= 64U && pkt_len <= 256U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (pkt_mode > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return examB_field_packet(pkt_mode, pkt_buf, pkt_len, tag_buf, tag_len, out_buf, out_len);
}
