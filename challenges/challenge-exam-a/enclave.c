#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include "exam_a_t.h"

__attribute__((aligned(4096), used, section(".data.ea_pad")))
volatile uint8_t challenge_page_pad[8192] = {0x99};

__attribute__((aligned(4096), used, section(".data.ea_c8")))
volatile uint8_t challenge_page_c8[4096] = {0x38};

__attribute__((aligned(4096), used, section(".data.ea_c7")))
volatile uint8_t challenge_page_c7[4096] = {0x37};

__attribute__((aligned(4096), used, section(".data.ea_c6")))
volatile uint8_t challenge_page_c6[4096] = {0x36};

__attribute__((aligned(4096), used, section(".data.ea_c5")))
volatile uint8_t challenge_page_c5[4096] = {0x35};

__attribute__((aligned(4096), used, section(".data.ea_c4")))
volatile uint8_t challenge_page_c4[4096] = {0x34};

__attribute__((aligned(4096), used, section(".data.ea_c3")))
volatile uint8_t challenge_page_c3[4096] = {0x33};

__attribute__((aligned(4096), used, section(".data.ea_c2")))
volatile uint8_t challenge_page_c2[4096] = {0x32};

__attribute__((aligned(4096), used, section(".data.ea_c1")))
volatile uint8_t challenge_page_c1[4096] = {0x31};

__attribute__((aligned(4096), used, section(".data.ea_base")))
volatile uint8_t challenge_page_base[4096] = {0x11};

__attribute__((aligned(4096), used, section(".data.ea_vbase")))
volatile uint8_t challenge_page_vault_base[4096] = {0x12};

static uint32_t g_ea_audit_calls = 0;
static uint32_t g_ea_policy = 0;
static uint32_t g_ea_epoch = 0;
static sgx_cmac_128bit_key_t g_ea_mac_key = {0};
static volatile uint8_t *g_ea_heap_obj = NULL;

sgx_status_t examA_boot_session(uint32_t boot_seed) {
    g_ea_audit_calls = (boot_seed & 1U);
    g_ea_policy = 0;
    g_ea_epoch = 0;
    if (sgx_read_rand((uint8_t *)&g_ea_mac_key, sizeof(g_ea_mac_key)) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (!g_ea_heap_obj) {
        g_ea_heap_obj = (volatile uint8_t *)malloc(7 * 4096);
        if (!g_ea_heap_obj) return SGX_ERROR_OUT_OF_MEMORY;
        g_ea_heap_obj[0] = 0x33;
    }
    return SGX_SUCCESS;
}

sgx_status_t examA_set_policy(uint32_t policy_code) {
    if (policy_code > 64U) return SGX_ERROR_INVALID_PARAMETER;
    g_ea_policy = policy_code;
    return SGX_SUCCESS;
}

sgx_status_t examA_step_epoch(uint32_t step_inc) {
    g_ea_epoch += (step_inc ? 1U : 0U);
    return SGX_SUCCESS;
}

sgx_status_t examA_mint_credential(uint32_t cred_level, uint8_t *cred_out, size_t cred_len) {
    if (!cred_out || cred_len < 64U || cred_level > 32U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(cred_out, 0, cred_len);
    uint32_t magic = 0x45584131U;
    memcpy(cred_out + 0, &magic, 4);
    memcpy(cred_out + 4, &cred_level, 4);
    if (sgx_read_rand(cred_out + 8, 8) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_cmac_128bit_tag_t cmac_tag = {0};
    if (sgx_rijndael128_cmac_msg(&g_ea_mac_key, cred_out, 16, &cmac_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy(cred_out + 16, &cmac_tag, sizeof(cmac_tag));
    return SGX_SUCCESS;
}

/* First Field in Exam A (at ECALL 1, non-last Field selector!) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examA_field_vault(
    uint32_t audit_cmd,
    uint32_t cred_level,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t v = challenge_page_vault_base[0] ^ (uint8_t)audit_cmd;
    challenge_page_vault_base[32] = v;

    if (g_ea_heap_obj) {
        g_ea_heap_obj[0] ^= (uint8_t)(audit_cmd + 1U);
    }

    /* C1: Non-last Field selector (ECALL 1) delayed counter >= 22 */
    g_ea_audit_calls++;
    if (g_ea_audit_calls >= 22U) {
        challenge_page_c1[0] ^= (uint8_t)g_ea_audit_calls;
    }

    /* C7: Authenticated opaque credential chain cred_level == 8 */
    if (cred_level == 8U) {
        challenge_page_c7[0] ^= 0x77U;
    }

    /* C8: Multi-Field + 7-page heap object delayed tail page (offset 6*4096) when audit_cmd == 4 */
    if (audit_cmd == 4U) {
        if (g_ea_heap_obj) {
            g_ea_heap_obj[6 * 4096 + 32] ^= 0x88U;
            v ^= g_ea_heap_obj[6 * 4096 + 32];
        }
        challenge_page_c8[0] ^= v;
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = v;
    }
    return SGX_SUCCESS;
}

sgx_status_t examA_audit_vault(
    uint32_t audit_cmd,
    const uint8_t *cred_in,
    size_t cred_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!cred_in || !out_buf || cred_len < 64U || out_len == 0 || audit_cmd > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t magic = 0, cred_level = 0;
    sgx_cmac_128bit_tag_t expected_tag = {0};
    memcpy(&magic, cred_in + 0, 4);
    memcpy(&cred_level, cred_in + 4, 4);
    if (sgx_rijndael128_cmac_msg(&g_ea_mac_key, cred_in, 16, &expected_tag) != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    if (magic != 0x45584131U || memcmp(cred_in + 16, &expected_tag, sizeof(expected_tag)) != 0) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    return examA_field_vault(audit_cmd, cred_level, out_buf, out_len);
}

/* Second Field in Exam A (at ECALL 4) */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t examA_field_compute(
    uint32_t frame_mode,
    const uint8_t *frame_buf,
    size_t frame_len,
    const uint8_t *hdr_buf,
    size_t hdr_len,
    uint8_t *out_buf,
    size_t out_len)
{
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)frame_mode;
    challenge_page_base[64] = acc;

    /* C2: Overwriting setter policy_code == 8 */
    if (g_ea_policy == 8U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Hole at 64..512, scale >= 4096 */
    if (frame_len >= 4096U) {
        challenge_page_c3[0] ^= frame_buf[frame_len - 1];
    }

    /* C4: Joint predicate frame_mode == 16 AND frame_buf[0] != 0x42 */
    if (frame_mode == 16U && frame_len > 0 && frame_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Latent state at 3rd position (sseq=2) with frame_mode == 3 */
    if (g_ea_epoch == 2U && frame_mode == 3U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Cross-buffer slice relation at offset 4 */
    if (frame_len >= 16U && hdr_len >= 12U && memcmp(frame_buf + 4, hdr_buf, 12) == 0 && frame_buf[4] != 0U) {
        uint8_t win[32];
        memcpy(win, frame_buf, 16);
        memmove(win + 4, win, 12);
        challenge_page_c6[0] ^= win[4];
    }

    if (out_buf && out_len > 0) {
        out_buf[0] = acc;
    }
    return SGX_SUCCESS;
}

sgx_status_t examA_process_frame(
    uint32_t frame_mode,
    const uint8_t *frame_buf,
    size_t frame_len,
    const uint8_t *hdr_buf,
    size_t hdr_len,
    uint8_t *out_buf,
    size_t out_len)
{
    if (!frame_buf || !hdr_buf || !out_buf || frame_len == 0 || hdr_len == 0 || out_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (frame_len >= 64U && frame_len <= 512U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (frame_mode > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return examA_field_compute(frame_mode, frame_buf, frame_len, hdr_buf, hdr_len, out_buf, out_len);
}
