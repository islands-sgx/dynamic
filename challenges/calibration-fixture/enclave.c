#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "calibration_t.h"

/* Padding to isolate calibration symbols onto distinct 4KB pages */
__attribute__((aligned(4096), used, section(".text.cal_pad0")))
void cal_text_pad0(void) { __asm__ volatile("nop"); }

/* 1. Code page (X): page-aligned target function in .text.cal_code */
__attribute__((aligned(4096), noinline, used, section(".text.cal_code")))
uint8_t cal_code_target_fn(uint8_t x) {
    __asm__ volatile("" : "+r"(x) : : "memory");
    return (uint8_t)(x ^ 0x37U);
}

__attribute__((aligned(4096), used, section(".text.cal_pad1")))
void cal_text_pad1(void) { __asm__ volatile("nop"); }

/* 2. RX page read as data: page-aligned function in .text.cal_rx_data whose machine bytes are read as data (never called in S3) */
__attribute__((aligned(4096), noinline, used, section(".text.cal_rx_data")))
uint8_t cal_rx_data_table_fn(uint8_t v) {
    __asm__ volatile("" : "+r"(v) : : "memory");
    return (uint8_t)(v ^ 0x5AU);
}

__attribute__((aligned(4096), used, section(".text.cal_pad2")))
void cal_text_pad2(void) { __asm__ volatile("nop"); }

/* 3. Read-only data page (R): page-aligned .rodata page */
__attribute__((aligned(4096), used, section(".rodata.cal_ro")))
const volatile uint8_t cal_rodata_page[4096] = {
    0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
};

__attribute__((aligned(4096), used, section(".rodata.cal_ropad")))
const uint8_t cal_rodata_pad[4096] = {0x01};

/* 4. Writable data page (W): page-aligned .data page */
__attribute__((aligned(4096), used, section(".data.cal_rw")))
volatile uint8_t cal_writable_page[4096] = {0x42};

__attribute__((aligned(4096), used, section(".data.cal_rwpad")))
volatile uint8_t cal_writable_pad[4096] = {0x02};

/* 5. Cross-page read/write buffer (2 pages = 8192 bytes) */
__attribute__((aligned(4096), used, section(".data.cal_cross")))
volatile uint8_t cal_cross_page_buf[8192] = {0x18};

__attribute__((aligned(4096), used, section(".data.cal_crosspad")))
volatile uint8_t cal_cross_pad[4096] = {0x03};

/* 6. Temporary deep stack frame helper (allocates & dirties 4 stack pages, then returns before Gate D) */
__attribute__((noinline))
__attribute__((noinline))
static uint8_t cal_deep_stack_helper(uint8_t seed) {
    volatile uint8_t tmp_stack[4 * 4096];
    __asm__ volatile("" : : "r"(tmp_stack) : "memory");
    /* Touch from top of stack downward page-by-page so SGX stack expansion / PTEs cover all 4 pages */
    for (int pg = 3; pg >= 0; pg--) {
        tmp_stack[pg * 4096 + 64] = (uint8_t)(seed ^ (uint8_t)(pg + 1));
    }
    return (uint8_t)(tmp_stack[64] ^ tmp_stack[4096 + 64] ^ tmp_stack[8192 + 64] ^ tmp_stack[12288 + 64]);
}

/* Annotated Field body */
__attribute__((annotate("atfield.field.v1"), noinline))
sgx_status_t cal_field_entry(uint32_t iter_idx, uint8_t *out_byte) {
    /* (a) Code page X execution */
    uint8_t acc = cal_code_target_fn((uint8_t)iter_idx);
    /* (b) RX page read as data */
    const volatile uint8_t *rx_bytes = (const volatile uint8_t *)&cal_rx_data_table_fn;
    acc ^= rx_bytes[iter_idx & 0x7U];
    /* (c) Read-only page R access */
    acc ^= cal_rodata_page[(iter_idx * 31U) & 0xFFU];
    /* (d) Writable page W access (sets D bit) */
    cal_writable_page[64] ^= (uint8_t)(acc + 1U);
    acc ^= cal_writable_page[64];
    /* (e) Cross-page write across page 0 (offset 4095) and page 1 (offset 4096) */
    cal_cross_page_buf[4095] ^= (uint8_t)(acc + 3U);
    cal_cross_page_buf[4096] ^= (uint8_t)(acc + 5U);
    acc ^= (uint8_t)(cal_cross_page_buf[4095] ^ cal_cross_page_buf[4096]);
    /* (f) Temporary 4-page deep stack frame that returns before Gate D */
    acc ^= cal_deep_stack_helper(acc);

    if (out_byte) {
        *out_byte = acc;
    }
    return SGX_SUCCESS;
}

/* Outer ECALL: touches all target pages in S0/S1 FIRST, then enters cal_field_entry (repeatedly if requested) */
sgx_status_t ecall_run_calibration(uint32_t repeat_field_count, uint8_t *out_buf, size_t out_len) {
    if (!out_buf || out_len == 0 || repeat_field_count == 0 || repeat_field_count > 8U) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t final_acc = 0;
    for (uint32_t i = 0; i < repeat_field_count; i++) {
        if (repeat_field_count >= 2U) {
            /* S0/S1 pre-access to all target pages before Gate B */
            uint8_t pre = cal_code_target_fn((uint8_t)(i + 100U));
            pre ^= ((const volatile uint8_t *)&cal_rx_data_table_fn)[0];
            pre ^= cal_rodata_page[0];
            cal_writable_page[0] ^= pre;
            cal_cross_page_buf[0] ^= pre;
            cal_cross_page_buf[4096] ^= pre;
            pre ^= cal_deep_stack_helper(pre);
        }

        uint8_t step_out = 0;
        sgx_status_t st = cal_field_entry(i + 1U, &step_out);
        if (st != SGX_SUCCESS) {
            return st;
        }
        final_acc ^= step_out;
    }
    out_buf[0] = final_acc;
    return SGX_SUCCESS;
}
