#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sgx_trts.h>
#include "challenge_perm_t.h"


#define CHALLENGE_PERM_FIELD_ID 0x5045524d464c4431ULL

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

static uint32_t g_perm_counter = 0;
static uint32_t g_perm_stage = 0;
static uint32_t g_perm_latched = 0;

/* Shuffled ECALL 0: stage configuration (threshold changed to 16U) */
sgx_status_t ecall_alpha_stage(uint32_t stage_val) {
    if (stage_val == 16U) {
        g_perm_stage = 1U;
    }
    return SGX_SUCCESS;
}

/* Shuffled ECALL 2: reset */
sgx_status_t ecall_gamma_reset(uint32_t init_seed) {
    g_perm_counter = (init_seed & 1U);
    g_perm_stage = 0;
    g_perm_latched = 0;
    return SGX_SUCCESS;
}

/* Shuffled ECALL 3: latch */
sgx_status_t ecall_delta_latch(uint32_t latch_v) {
    if (latch_v == 1U) {
        g_perm_latched = 1U;
    }
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

    /* C1: mutated threshold >= 20 calls */
    g_perm_counter++;
    if (g_perm_counter >= 20U) {
        challenge_page_c1[0] ^= (uint8_t)g_perm_counter;
    }

    /* C2: prerequisite ecall_alpha_stage(16) */
    if (g_perm_stage == 1U) {
        acc ^= challenge_page_c2[0];
    }

    /* C3: mutated scale threshold >= 4096 (with hole at 256) */
    if (pay_len >= 4096U) {
        challenge_page_c3[0] ^= pay_buf[pay_len - 1];
    }

    /* C4: joint predicate ctl_flag == 1 AND pay_buf[0] != 0x42 */
    if (ctl_flag == 1U && pay_len > 0 && pay_buf[0] != 0x42U) {
        acc ^= challenge_page_c4[0];
    }

    /* C5: latent state at sseq=1 with ctl_flag == 2 */
    if (g_perm_latched == 1U && ctl_flag == 2U) {
        challenge_page_c5[0] ^= 0x55U;
    }

    /* C6: aliased buffer pair */
    if (pay_len >= 16U && meta_len >= 12U && memcmp(pay_buf + 4, meta_buf, 12) == 0 && pay_buf[4] != 0U) {
        challenge_page_c6[0] ^= meta_buf[0];
    }

    if (res_buf && res_len > 0) {
        res_buf[0] = acc;
    }

    return SGX_SUCCESS;
}

/* Shuffled ECALL 1: Field ECALL */
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
