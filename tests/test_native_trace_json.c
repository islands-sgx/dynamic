#include <stdio.h>
#include <string.h>
#include "../src/native_trace_json.h"
#include "../src/native_trace_state.h"
#include "../src/readiness_contract.h"
#include <limits.h>

static int test_json_string_array(void);

static int stream_matches(FILE *fp, const char *expected) {
    if (fflush(fp) != 0 || fseek(fp, 0, SEEK_SET) != 0) return 0;
    char actual[1024];
    size_t n = fread(actual, 1, sizeof(actual), fp);
    return n == strlen(expected) && memcmp(actual, expected, n) == 0 && fgetc(fp) == EOF;
}

static int test_readiness_sha_policy(void) {
    static const char valid_sha[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    if (atfield_readiness_sha_invalid(0, NULL)) return 60;
    if (!atfield_readiness_sha_invalid(1, NULL)) return 61;
    if (atfield_readiness_sha_invalid(0, valid_sha)) return 62;
    if (atfield_readiness_sha_invalid(1, valid_sha)) return 63;
    if (!atfield_readiness_sha_invalid(0, "missing")) return 64;
    return 0;
}
static int test_string_escaping(void) {
    const char input[] = "quote:\" backslash:\\ backspace:\b formfeed:\f newline:\n carriage:\r tab:\t control:\001 invalid_byte:\377";
    const char expected[] = "\"quote:\\\" backslash:\\\\ backspace:\\b formfeed:\\f newline:\\n carriage:\\r tab:\\t control:\\u0001 invalid_byte:\\u00ff\"";
    FILE *fp = tmpfile();
    if (!fp) return 1;
    int ok = atfield_json_write_string(fp, input) == 0 && stream_matches(fp, expected);
    if (fclose(fp) != 0) return 2;
    return ok ? 0 : 3;
}

static int test_page_effect_keeps_both_ad_bits(void) {
    const char expected[] = "{\"rva\":\"0x2000\",\"a\":true,\"d\":true}";
    FILE *fp = tmpfile();
    if (!fp) return 4;
    int ok = atfield_json_write_page_effect(fp, 0x2000, 1, 1) == 0 && stream_matches(fp, expected);
    if (fclose(fp) != 0) return 5;
    return ok ? 0 : 6;
}


static int write_filtered_page_effects(FILE *fp, const uint64_t *rvas,
                                        const int *a_bits, const int *d_bits,
                                        size_t count, uint64_t gate_start, uint64_t gate_end) {
    if (fputs("[", fp) < 0) return -1;
    int first = 1;
    for (size_t i = 0; i < count; i++) {
        if (atfield_rva_excluded_by_gate_range(rvas[i], 1, gate_start, gate_end)) continue;
        if (!first && fputc(',', fp) == EOF) return -1;
        if (atfield_json_write_page_effect(fp, rvas[i], a_bits[i], d_bits[i]) != 0) return -1;
        first = 0;
    }
    return fputc(']', fp) == EOF ? -1 : 0;
}

static int test_canonical_field_phase_fixture(void) {
    const char expected[] = "{\"field_id\":\"0x1\",\"phases\":{\"S0_BRIDGE\":{\"page_size\":4096,\"complete\":true,\"page_effects\":[{\"rva\":\"0x5000\",\"a\":true,\"d\":true}]},\"S1_ENTER\":{\"page_size\":4096,\"complete\":true,\"page_effects\":[{\"rva\":\"0x5000\",\"a\":true,\"d\":true}]},\"S2_PRETOUCH\":{\"page_size\":4096,\"complete\":true,\"page_effects\":[{\"rva\":\"0x5000\",\"a\":true,\"d\":true}]},\"S3_BODY\":{\"page_size\":4096,\"complete\":true,\"page_effects\":[{\"rva\":\"0x5000\",\"a\":true,\"d\":true}]}}}";
    static const char *const phase_names[] = {"S0_BRIDGE", "S1_ENTER", "S2_PRETOUCH", "S3_BODY"};
    const uint64_t rvas[] = {0x2000, 0x3000, 0x5000};
    const int a_bits[] = {1, 1, 1};
    const int d_bits[] = {1, 1, 1};
    FILE *fp = tmpfile();
    if (!fp) return 22;
    int ok = fputs("{\"field_id\":\"0x1\",\"phases\":{", fp) >= 0;
    for (size_t i = 0; ok && i < sizeof(phase_names) / sizeof(phase_names[0]); i++) {
        if (i && fputc(',', fp) == EOF) ok = 0;
        if (ok && fprintf(fp, "\"%s\":{\"page_size\":4096,\"complete\":true,\"page_effects\":", phase_names[i]) < 0) ok = 0;
        if (ok && write_filtered_page_effects(fp, rvas, a_bits, d_bits,
                                              sizeof(rvas) / sizeof(rvas[0]),
                                              0x2000, 0x4000) != 0) ok = 0;
        if (ok && fputc('}', fp) == EOF) ok = 0;
    }
    if (ok && fputs("}}", fp) < 0) ok = 0;
    if (ok) ok = stream_matches(fp, expected);
    if (fclose(fp) != 0) return 23;
    return ok ? 0 : 24;
}

static int test_gate_helper_range_contract(void) {
    uint64_t start = 0, end = 0;
    int found = 0;
    if (atfield_parse_layout_gate_range("tcs=1000;gate=2000:4000;stack=5000:7000",
                                        &found, &start, &end) != 0 ||
        !found || start != 0x2000 || end != 0x4000) return 25;
    if (!atfield_range_within_enclave(start, end, 0x8000) ||
        atfield_range_within_enclave(start, end, 0x3000)) return 26;
    if (!atfield_rva_excluded_by_gate_range(0x2000, 1, start, end) ||
        !atfield_rva_excluded_by_gate_range(0x3000, 1, start, end) ||
        atfield_rva_excluded_by_gate_range(0x1000, 1, start, end) ||
        atfield_rva_excluded_by_gate_range(0x4000, 1, start, end)) return 27;
    if (atfield_parse_layout_gate_range("gate=2000", &found, &start, &end) == 0) return 28;
    if (atfield_parse_layout_gate_range("gate=2000:3001", &found, &start, &end) == 0) return 29;
    if (atfield_parse_layout_gate_range("gate=2000:4000;gate=4000:5000",
                                        &found, &start, &end) == 0) return 30;
    if (atfield_parse_layout_gate_range("other=2000", &found, &start, &end) != 0 || found) return 31;
    return 0;
}

static int test_canonical_key_fixture(void) {
    static const char *const expected_run[] = {
        "schema", "record_type", "run_id", "layout_epoch", "bundle_manifest_sha256", "instance_generation",
        "sample", "mode", "start_time", "selected_enclave_sha256", "seed_id", "argv"
    };
    static const char *const expected_ecall[] = {
        "schema", "record_type", "run_id", "layout_epoch", "bundle_manifest_sha256", "instance_generation",
        "call_seq", "selector_ordinal", "selector_seq", "tag", "elapsed_ns", "sgx_status",
        "abi_return_type", "abi_return_value", "out_status_i32", "measurement_valid",
        "measurement_invalid_reasons", "fields", "aex", "business_result"
    };
    if (sizeof(expected_run) != sizeof(atfield_run_start_record_keys) ||
        sizeof(expected_ecall) != sizeof(atfield_ecall_record_keys)) return 7;
    for (size_t i = 0; i < sizeof(expected_run) / sizeof(expected_run[0]); i++)
        if (strcmp(expected_run[i], atfield_run_start_record_keys[i]) != 0) return 8;
    for (size_t i = 0; i < sizeof(expected_ecall) / sizeof(expected_ecall[0]); i++)
        if (strcmp(expected_ecall[i], atfield_ecall_record_keys[i]) != 0) return 8;
    return 0;
}

static int test_watcher_buffer_failure_seam(void) {
    int ready = 1;
    const void *ok[] = {&ready, &ready, &ready};
    const void *bad[] = {&ready, NULL, &ready};
    return atfield_buffers_ready(ok, 3) && !atfield_buffers_ready(bad, 3) ? 0 : 9;
}

static int test_sequence_state(void) {
    uint64_t call = 0, value = UINT64_MAX;
    int selectors[ATFIELD_TRACE_SELECTOR_COUNT] = {0};
    int seq = -1;
    if (atfield_next_u64(&call, &value) || value != 0) return 10;
    if (atfield_next_u64(&call, &value) || value != 1) return 11;
    if (atfield_next_selector(selectors, 7, &seq) || seq != 0) return 12;
    if (atfield_next_selector(selectors, 7, &seq) || seq != 1) return 13;
    if (atfield_next_selector(selectors, 8, &seq) || seq != 0) return 14;
    atfield_reset_selectors(selectors);
    if (atfield_next_selector(selectors, 7, &seq) || seq != 0) return 15;
    if (atfield_next_u64(&(uint64_t){UINT64_MAX}, &value) == 0) return 16;
    return 0;
}

static int test_eid_and_concurrency_rejection(void) {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    if (!atfield_create_allowed(0) || atfield_create_allowed(1)) return 17;
    if (atfield_eid_is_current(1, 9, 9) != 1 || atfield_eid_is_current(1, 9, 10) != 0 || atfield_eid_is_current(0, 9, 9) != 0) return 18;
    if (pthread_mutex_lock(&mutex) != 0) return 19;
    int rejected = !atfield_mutex_try_enter(&mutex);
    pthread_mutex_unlock(&mutex);
    int admitted = atfield_mutex_try_enter(&mutex);
    if (admitted) pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);
    return rejected && admitted ? 0 : 20;
}

static int test_repeated_field_or_and_completeness(void) {
    uint64_t first[2] = {1u, 0u}, second[2] = {0u, 2u}, merged[2] = {0u, 0u};
    uint8_t complete[4] = {1, 1, 1, 1};
    atfield_or_words(merged, first, 2);
    atfield_or_words(merged, second, 2);
    atfield_phase_completeness_merge(complete, 0x0f, 1);
    atfield_phase_completeness_merge(complete, 0x07, 1);
    return merged[0] == 1u && merged[1] == 2u && complete[0] && complete[1] && complete[2] && !complete[3] ? 0 : 21;
}


static int test_aex_classification_and_verified_phase_mask(void) {
    /* Gate A spin inside gate helper range [0x30000, 0x31000) is classified as PROTOCOL_GATE_A */
    if (atfield_classify_aex_event(1, 1, 10u, 10u, 1u, 7, 0, 0, 1, 0x30000, 0x31000, 1, 0x30040) !=
        ATFIELD_AEX_PROTOCOL_GATE_A) return 32;
    /* Gate B spin inside gate helper range */
    if (atfield_classify_aex_event(1, 1, 30u, 30u, 2u, 7, 0, 0, 1, 0x30000, 0x31000, 1, 0x30100) !=
        ATFIELD_AEX_PROTOCOL_GATE_B) return 33;
    /* Gate C spin in C-flush mode (ipi_mask=7) -> PROTOCOL_GATE_C */
    if (atfield_classify_aex_event(1, 1, 50u, 50u, 3u, 7, 0, 0, 1, 0x30000, 0x31000, 1, 0x30200) !=
        ATFIELD_AEX_PROTOCOL_GATE_C) return 34;
    /* Gate C spin in C-preserve-TLB mode (ipi_mask=3) MUST NOT be classified as protocol gate */
    if (atfield_classify_aex_event(1, 1, 50u, 50u, 3u, 3, 0, 0, 1, 0x30000, 0x31000, 1, 0x30200) !=
        ATFIELD_AEX_UNEXPECTED) return 35;
    /* RIP outside gate helper range (e.g. S3_BODY at 0x7050) is ALWAYS UNEXPECTED even if in_gate_spin is forged */
    if (atfield_classify_aex_event(1, 1, 50u, 50u, 3u, 7, 0, 0, 1, 0x30000, 0x31000, 1, 0x7050) !=
        ATFIELD_AEX_UNEXPECTED) return 36;
    /* S3_BODY (host_gate=60, current_stage=3) is ALWAYS UNEXPECTED and maps to stage index 3 (S3_BODY) */
    if (atfield_classify_aex_event(1, 1, 0u, 60u, 3u, 7, 0, 0, 1, 0x30000, 0x31000, 1, 0x7050) !=
        ATFIELD_AEX_UNEXPECTED) return 37;
    if (atfield_stage_index_from_state(3u, 60u) != 3u) return 38;
    if (atfield_stage_index_from_state(3u, 50u) != 2u) return 39;
    /* Outside-window requires all independent Gate D closure evidence. */
    if (!atfield_proven_outside_field_window(4u, 0u, 80u, 1, 1, 1)) return 45;
    if (atfield_proven_outside_field_window(3u, 0u, 80u, 1, 1, 1)) return 46;
    if (atfield_proven_outside_field_window(4u, 1u, 80u, 1, 1, 1)) return 47;
    if (atfield_proven_outside_field_window(4u, 0u, 70u, 1, 1, 1)) return 48;
    if (atfield_proven_outside_field_window(4u, 0u, 80u, 0, 1, 1)) return 49;
    if (atfield_proven_outside_field_window(4u, 0u, 80u, 1, 0, 1)) return 50;
    if (atfield_proven_outside_field_window(4u, 0u, 80u, 1, 1, 0)) return 51;

    /* Verified phase mask requires all gates, all required IPIs, 0 S3 AEXs, and no heap errors */
    if (atfield_verified_phase_mask(0x0fu, 0x07u, 0x07u, 0u, 0, 0) != 0x0fu) return 40;
    if (atfield_verified_phase_mask(0x0fu, 0x03u, 0x03u, 0u, 0, 0) != 0x0fu) return 41;
    if (atfield_verified_phase_mask(0x0fu, 0x03u, 0x07u, 0u, 0, 0) == 0x0fu) return 42;
    if (atfield_verified_phase_mask(0x0fu, 0x07u, 0x07u, 1u, 0, 0) == 0x0fu) return 43;
    /* Missing Gate D (gate_mask == 0x07u instead of 0x0fu) must fail verification */
    if (atfield_verified_phase_mask(0x07u, 0x07u, 0x07u, 0u, 0, 0) == 0x0fu) return 44;
    return 0;
}

int main(void) {
    int rc = test_readiness_sha_policy();
    if (rc) return rc;
    rc = test_string_escaping();
    if (rc) return rc;
    rc = test_json_string_array();
    if (rc) return rc;
    rc = test_page_effect_keeps_both_ad_bits();
    if (rc) return rc;
    rc = test_canonical_field_phase_fixture();
    if (rc) return rc;
    rc = test_gate_helper_range_contract();
    if (rc) return rc;
    rc = test_canonical_key_fixture();
    if (rc) return rc;
    rc = test_watcher_buffer_failure_seam();
    if (rc) return rc;
    rc = test_sequence_state();
    if (rc) return rc;
    rc = test_eid_and_concurrency_rejection();
    if (rc) return rc;
    rc = test_repeated_field_or_and_completeness();
    if (rc) return rc;
    return test_aex_classification_and_verified_phase_mask();
}
static int test_json_string_array(void) {
    const char input[] = "[\"--sm4-check\",\"a b\",\"quote:\\\"\",\"slash:\\\\\",\"unicode:\\u4f60\\u597d\"]";
    FILE *fp = tmpfile();
    if (!fp) return 60;
    int ok = atfield_json_write_string_array(fp, input) == 0 && stream_matches(fp, input);
    if (fclose(fp) != 0) return 61;
    if (!ok) return 62;

    fp = tmpfile();
    if (!fp) return 63;
    ok = atfield_json_write_string_array(fp, NULL) == 0 && stream_matches(fp, "[]");
    if (fclose(fp) != 0) return 64;
    if (!ok) return 65;

    static const char *const invalid[] = {
        "[--sm4-check]", "[\"trailing\",]", "[\"bad\\q\"]", "[\"truncated\\u]", "[\"x\"] false",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        fp = tmpfile();
        if (!fp) return 66;
        ok = atfield_json_write_string_array(fp, invalid[i]) != 0 && stream_matches(fp, "");
        if (fclose(fp) != 0) return 67;
        if (!ok) return 68;
    }
    return 0;
}
