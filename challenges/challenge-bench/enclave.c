#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include "challenge_t.h"

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

static uint32_t g_call_counter = 0;
static uint32_t g_stage_mode = 0;
static uint32_t g_latent_step = 0;
static uint32_t g_vault_counter = 0;
static sgx_cmac_128bit_key_t g_boot_mac_key = {0};
static volatile uint8_t *g_large_heap_obj = NULL;

sgx_status_t ecall_init(uint32_t seed) {
    g_call_counter = (seed & 1U);
    g_stage_mode = 0;
    g_latent_step = 0;
    g_vault_counter = 0;
    if (sgx_read_rand((uint8_t *)&g_boot_mac_key, sizeof(g_boot_mac_key)) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (!g_large_heap_obj) {
        /* 6-page (> 4 pages) heap allocation: init only touches page 0 (head page) */
        g_large_heap_obj = (volatile uint8_t *)malloc(6 * 4096);
        if (!g_large_heap_obj) return SGX_ERROR_OUT_OF_MEMORY;
        g_large_heap_obj[0] = 0x5A;
    }
    return SGX_SUCCESS;
}

/* Overwriting setter: a subsequent normal call with stage_mode=0 WILL overwrite g_stage_mode back to 0! */
sgx_status_t ecall_configure_stage(uint32_t stage_mode) {
    if (stage_mode > 64U) return SGX_ERROR_INVALID_PARAMETER;
    g_stage_mode = stage_mode;
    return SGX_SUCCESS;
}

sgx_status_t ecall_advance_step(uint32_t delta) {
    g_latent_step += (delta ? 1U : 0U);
    return SGX_SUCCESS;
}

/* Producer of authenticated opaque token (64 bytes: [magic:4][profile:4][nonce:8][mac:8][pad:40]) */
sgx_status_t ecall_mint_token(uint32_t token_profile, uint8_t *token_out, size_t token_len) {
    if (!token_out || token_len < 64U || token_profile > 32U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(token_out, 0, token_len);
    uint32_t magic = 0x544F4B31U;
    memcpy(token_out + 0, &magic, 4);
    memcpy(token_out + 4, &token_profile, 4);
    if (sgx_read_rand(token_out + 8, 8) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_cmac_128bit_tag_t cmac_tag = {0};
    if (sgx_rijndael128_cmac_msg(&g_boot_mac_key, token_out, 16, &cmac_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy(token_out + 16, &cmac_tag, sizeof(cmac_tag));
    return SGX_SUCCESS;
}

__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t challenge_field_primary(
    uint32_t op_mode,
    const uint8_t *in_buf,
    size_t in_len,
    const uint8_t *aux_buf,
    size_t aux_len,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)op_mode;
    challenge_page_base[64] = acc;

    /* C1: Non-last Field selector delayed counter branch (> 16 calls: requires >= 18 calls) */
    g_call_counter++;
    if (g_call_counter >= 18U) {
        challenge_page_c1[0] ^= (uint8_t)g_call_counter;
    }

    /* C2: Overwriting setter prerequisite (requires replace_scalar on ecall_configure_stage(2)) */
    if (g_stage_mode == 2U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Non-monotonic length hole (64..256 rejected in S0; >= 1024 touches C3) */
    if (in_len >= 1024U) {
        challenge_page_c3[0] ^= in_buf[in_len - 1];
    }

    /* C4: Joint 2-parameter predicate (op_mode == 2 AND in_buf[0] != 0x42) */
    if (op_mode == 2U && in_len > 0 && in_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Latent state at 3rd call position (sseq=2 where g_latent_step == 2 and op_mode == 16) */
    if (g_latent_step == 2U && op_mode == 16U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Cross-buffer content slice relation (aux_buf[0..11] == in_buf[4..15]) + in-enclave overlap */
    if (in_len >= 16U && aux_len >= 12U && memcmp(in_buf + 4, aux_buf, 12) == 0 && in_buf[4] != 0U) {
        uint8_t win[32];
        memcpy(win, in_buf, 16);
        memmove(win + 4, win, 12);
        challenge_page_c6[0] ^= win[4];
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = acc;
    }
    return SGX_SUCCESS;
}

sgx_status_t ecall_Execute(
    uint32_t op_mode,
    const uint8_t *in_buf,
    size_t in_len,
    const uint8_t *aux_buf,
    size_t aux_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!in_buf || !aux_buf || !out_buf || in_len == 0 || aux_len == 0 || out_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (in_len >= 64U && in_len <= 256U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (op_mode > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return challenge_field_primary(op_mode, in_buf, in_len, aux_buf, aux_len, out_buf, out_len);
}

__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t challenge_field_vault(
    uint32_t vault_op,
    uint32_t token_profile,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t v = challenge_page_vault_base[0] ^ (uint8_t)vault_op;
    challenge_page_vault_base[32] = v;

    /* Always touch head page (page 0) of the >4-page heap object on every vault entry */
    if (g_large_heap_obj) {
        g_large_heap_obj[0] ^= (uint8_t)(vault_op + 1U);
    }

    /* C7: Authenticated opaque object chain (requires ecall_mint_token replaced with token_profile == 2) */
    if (token_profile == 2U) {
        challenge_page_c7[0] ^= 0x77U;
    }

    /* C8: Multi-Field + >4-page heap object delayed tail access (page 5 = offset 5*4096 + challenge_page_c8) */
    g_vault_counter++;
    if (vault_op == 3U || g_vault_counter >= 20U) {
        if (g_large_heap_obj) {
            g_large_heap_obj[5 * 4096 + 16] ^= 0x88U;
            v ^= g_large_heap_obj[5 * 4096 + 16];
        }
        challenge_page_c8[0] ^= v;
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = v;
    }
    return SGX_SUCCESS;
}

sgx_status_t ecall_consume_vault(
    uint32_t vault_op,
    const uint8_t *token_in,
    size_t token_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!token_in || !out_buf || token_len < 64U || out_len == 0 || vault_op > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t magic = 0, token_profile = 0;
    sgx_cmac_128bit_tag_t expected_tag = {0};
    memcpy(&magic, token_in + 0, 4);
    memcpy(&token_profile, token_in + 4, 4);
    if (sgx_rijndael128_cmac_msg(&g_boot_mac_key, token_in, 16, &expected_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (magic != 0x544F4B31U || memcmp(token_in + 16, &expected_tag, sizeof(expected_tag)) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    return challenge_field_vault(vault_op, token_profile, out_buf, out_len);
}
