#ifndef ATFIELD_NATIVE_TRACE_STATE_H
#define ATFIELD_NATIVE_TRACE_STATE_H
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define ATFIELD_TRACE_SCHEMA "atfield-canonical-trace-v1"
#define ATFIELD_TRACE_SELECTOR_COUNT 64
static const char *const atfield_run_start_record_keys[] = {
    "schema", "record_type", "run_id", "layout_epoch", "bundle_manifest_sha256", "instance_generation",
    "sample", "mode", "start_time", "selected_enclave_sha256", "seed_id", "argv"
};
static const char *const atfield_ecall_record_keys[] = {
    "schema", "record_type", "run_id", "layout_epoch", "bundle_manifest_sha256", "instance_generation",
    "call_seq", "selector_ordinal", "selector_seq", "tag", "elapsed_ns", "sgx_status",
    "abi_return_type", "abi_return_value", "out_status_i32", "measurement_valid",
    "measurement_invalid_reasons", "fields", "aex", "business_result"
};
static inline int atfield_parse_hex_range(const char *text, uint64_t *start, uint64_t *end) {
    if (!text || !start || !end) return -1;
    const char *p = text;
    uint64_t values[2] = {0, 0};
    for (unsigned part = 0; part < 2; part++) {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        const char *first = p;
        uint64_t value = 0;
        while (*p) {
            unsigned digit;
            if (*p >= '0' && *p <= '9') digit = (unsigned)(*p - '0');
            else if (*p >= 'a' && *p <= 'f') digit = (unsigned)(*p - 'a') + 10u;
            else if (*p >= 'A' && *p <= 'F') digit = (unsigned)(*p - 'A') + 10u;
            else break;
            if (value > (UINT64_MAX - digit) / 16u) return -1;
            value = value * 16u + digit;
            p++;
        }
        if (p == first) return -1;
        values[part] = value;
        if (part == 0) {
            if (*p != ':') return -1;
            p++;
        } else if (*p != '\0') {
            return -1;
        }
    }
    if (values[0] >= values[1] || (values[0] & 0xfffu) || (values[1] & 0xfffu)) return -1;
    *start = values[0];
    *end = values[1];
    return 0;
}
static inline int atfield_parse_layout_gate_range(const char *spec, int *found, uint64_t *start, uint64_t *end) {
    if (!found || !start || !end) return -1;
    *found = 0;
    *start = 0;
    *end = 0;
    if (!spec) return 0;
    const char *token = spec;
    for (;;) {
        const char *token_end = strchr(token, ';');
        if (!token_end) token_end = token + strlen(token);
        if ((size_t)(token_end - token) >= 5u && memcmp(token, "gate=", 5u) == 0) {
            if (*found) return -1;
            *found = 1;
            size_t value_len = (size_t)(token_end - (token + 5));
            char value[128];
            if (!value_len || value_len >= sizeof(value)) return -1;
            memcpy(value, token + 5, value_len);
            value[value_len] = '\0';
            if (atfield_parse_hex_range(value, start, end) != 0) return -1;
        }
        if (*token_end == '\0') break;
        token = token_end + 1;
    }
    return 0;
}
static inline int atfield_range_within_enclave(uint64_t start, uint64_t end, uint64_t enclave_size) {
    return start < end && !(start & 0xfffu) && !(end & 0xfffu) && end <= enclave_size;
}
static inline int atfield_rva_in_half_open_range(uint64_t rva, uint64_t start, uint64_t end) {
    return start < end && rva >= start && rva < end;
}
static inline int atfield_rva_excluded_by_gate_range(uint64_t rva, int configured, uint64_t start, uint64_t end) {
    return configured && atfield_rva_in_half_open_range(rva, start, end);
}
static inline int atfield_create_allowed(int live) { return !live; }
static inline void atfield_reset_selectors(int counters[ATFIELD_TRACE_SELECTOR_COUNT]) { if (counters) memset(counters, 0, sizeof(int) * ATFIELD_TRACE_SELECTOR_COUNT); }
static inline int atfield_next_u64(uint64_t *counter, uint64_t *value) {
    if (!counter || !value || *counter == UINT64_MAX) return -1;
    *value = (*counter)++; return 0;
}
static inline int atfield_next_selector(int counters[ATFIELD_TRACE_SELECTOR_COUNT], int ordinal, int *value) {
    if (!counters || !value || ordinal < 0 || ordinal >= ATFIELD_TRACE_SELECTOR_COUNT || counters[ordinal] < 0 || counters[ordinal] == INT_MAX) return -1;
    *value = counters[ordinal]++; return 0;
}
static inline int atfield_eid_is_current(int live, uint64_t current, uint64_t requested) { return live && current == requested; }
static inline int atfield_buffers_ready(const void *const *buffers, size_t count) {
    if (!buffers) return count == 0;
    for (size_t i = 0; i < count; i++) if (!buffers[i]) return 0;
    return 1;
}
static inline int atfield_mutex_try_enter(pthread_mutex_t *mutex) { return mutex && pthread_mutex_trylock(mutex) == 0; }
static inline void atfield_or_words(uint64_t *dst, const uint64_t *src, size_t count) {
    if (!dst || !src) return;
    for (size_t i = 0; i < count; i++) dst[i] |= src[i];
}
static inline void atfield_phase_completeness_merge(uint8_t complete[4], uint32_t mask, int page_set_complete) {
    if (!complete) return;
    for (unsigned i = 0; i < 4; i++) complete[i] = (uint8_t)(complete[i] && page_set_complete && ((mask & (1u << i)) != 0));
}

typedef enum {
    ATFIELD_AEX_UNEXPECTED = 0,
    ATFIELD_AEX_PROTOCOL_GATE_A = 1,
    ATFIELD_AEX_PROTOCOL_GATE_B = 2,
    ATFIELD_AEX_PROTOCOL_GATE_C = 3
} atfield_aex_class_t;

static inline atfield_aex_class_t atfield_classify_aex_event(
    int use_4gate_enabled,
    uint32_t gate_enable,
    uint32_t in_gate_spin,
    uint32_t host_gate,
    uint32_t current_stage,
    int ipi_mask,
    int strict_mode,
    int any_strict_healed,
    int gate_range_configured,
    uint64_t gate_start_rva,
    uint64_t gate_end_rva,
    int rip_rva_valid,
    uint64_t rip_rva)
{
    if (!use_4gate_enabled || !gate_enable || any_strict_healed ||
        !gate_range_configured || !rip_rva_valid ||
        !atfield_rva_in_half_open_range(rip_rva, gate_start_rva, gate_end_rva)) {
        return ATFIELD_AEX_UNEXPECTED;
    }
    if (in_gate_spin == 10u && host_gate == 10u && current_stage == 1u && (ipi_mask & 1)) {
        return ATFIELD_AEX_PROTOCOL_GATE_A;
    }
    if (in_gate_spin == 30u && host_gate == 30u && current_stage == 2u && ((ipi_mask & 2) || strict_mode == 2)) {
        return ATFIELD_AEX_PROTOCOL_GATE_B;
    }
    if (in_gate_spin == 50u && host_gate == 50u && current_stage == 3u && (ipi_mask & 4)) {
        return ATFIELD_AEX_PROTOCOL_GATE_C;
    }
    return ATFIELD_AEX_UNEXPECTED;
}

static inline unsigned atfield_stage_index_from_state(uint32_t current_stage, uint32_t host_gate) {
    if (current_stage == 1u) return 0u; /* S0_BRIDGE / Gate A */
    if (current_stage == 2u) return 1u; /* S1_ENTER / Gate B */
    if (current_stage == 3u) {
        return host_gate == 50u ? 2u : 3u; /* Gate C (S2_PRETOUCH) vs S3_BODY */
    }
    if (current_stage == 4u) return 4u; /* POST_FIELD / Gate D */
    return 0u;
}

static inline uint32_t atfield_verified_phase_mask(
    uint32_t gate_mask,
    uint32_t ipi_verified_mask,
    uint32_t required_ipi_mask,
    uint32_t s3_active_aex_count,
    int heap_walk_truncated,
    int heap_pread_failures)
{
    uint32_t out = 0;
    if ((gate_mask & 1u) && ((required_ipi_mask & 1u) == 0 || (ipi_verified_mask & 1u))) out |= 1u;
    if ((gate_mask & 2u) && ((required_ipi_mask & 2u) == 0 || (ipi_verified_mask & 2u))) out |= 2u;
    if ((gate_mask & 4u) && ((required_ipi_mask & 4u) == 0 || (ipi_verified_mask & 4u))) out |= 4u;
    if ((gate_mask & 8u) &&
        (out == 7u) &&
        ((ipi_verified_mask & ~required_ipi_mask) == 0) &&
        s3_active_aex_count == 0 &&
        !heap_walk_truncated &&
        !heap_pread_failures) {
        out |= 8u;
    }
    return out;
}

#endif
