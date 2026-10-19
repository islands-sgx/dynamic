#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sgx_trts.h>
#include "challenge_t.h"


#define CHALLENGE_FIELD_ID 0x4348414c4c454e47ULL

__attribute__((aligned(4096), used, section(".data.c_base")))
volatile uint8_t challenge_page_base[4096] = {0x11};

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

static uint32_t g_call_counter = 0;
static uint32_t g_stage_armed = 0;
static uint32_t g_phase_latched = 0;

sgx_status_t ecall_init(uint32_t seed) {
    g_call_counter = (seed & 1U);
    g_stage_armed = 0;
    g_phase_latched = 0;
    return SGX_SUCCESS;
}

sgx_status_t ecall_configure_stage(uint32_t stage_mode) {
    if (stage_mode == 2U) {
        g_stage_armed = 1U;
    }
    return SGX_SUCCESS;
}

sgx_status_t ecall_latch_phase(uint32_t phase_flag) {
    if (phase_flag == 1U) {
        g_phase_latched = 1U;
    }
    return SGX_SUCCESS;
}

__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t challenge_field_work(
    uint32_t op_mode,
    const uint8_t *in_buf,
    size_t in_len,
    const uint8_t *aux_buf,
    size_t aux_len,
    uint8_t *out_buf,
    size_t out_len)
{

    /* Base page always accessed on every valid Field entry */
    uint8_t acc = challenge_page_base[0] ^ (uint8_t)op_mode;
    challenge_page_base[64] = acc;

    /* C1: Late counter-triggered branch (requires >= 12 stateful Field entries) */
    g_call_counter++;
    if (g_call_counter >= 12U) {
        challenge_page_c1[0] ^= (uint8_t)g_call_counter;
    }

    /* C2: Cross-interface non-zero prerequisite (requires ecall_configure_stage(2) earlier in enclave) */
    if (g_stage_armed == 1U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: Non-monotonic length hole (64..256 rejected in S0; >= 1024 reaches here and touches C3) */
    if (in_len >= 1024U) {
        challenge_page_c3[0] ^= in_buf[in_len - 1];
    }

    /* C4: Joint 2-parameter predicate (op_mode == 2 AND in_buf[0] != 0x42) */
    if (op_mode == 2U && in_len > 0 && in_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: Identical prefix page set with distinct latent state (sseq=1 where g_phase_latched==1 and op_mode==16) */
    if (g_phase_latched == 1U && op_mode == 16U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: Overlapping / aliased buffer pair (aux_buf aliases in_buf + 4 on host) */
    if (in_len >= 16U && aux_len >= 12U && memcmp(in_buf + 4, aux_buf, 12) == 0 && in_buf[4] != 0U) {
        challenge_page_c6[0] ^= aux_buf[0];
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
    /* C3 non-monotonic length rejection hole at S0: reject [64, 256], allow 32 and >= 512 */
    if (in_len >= 64U && in_len <= 256U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (op_mode > 64U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return challenge_field_work(op_mode, in_buf, in_len, aux_buf, aux_len, out_buf, out_len);
}
