#define _GNU_SOURCE
#include "interpose_mutation.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #x); \
    exit(1); \
} } while (0)

#define SPEC_SIZE 144u
#define PROJECTION_HEADER_SIZE 120u
#define ECALL_HEADER_SIZE 28u
#define PARAM_HEADER_SIZE 56u

static const char BUNDLE_SHA[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LAYOUT_SHA[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char ABI_SHA[] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

typedef struct {
    uint32_t target;
    uint32_t direct_out;
    uint32_t bound_size;
    uint32_t reserved;
    void *buffer;
    int32_t retval;
    uint32_t tail;
} marshal_t;

_Static_assert(offsetof(marshal_t, target) == 0, "target offset");
_Static_assert(offsetof(marshal_t, direct_out) == 4, "direct output offset");
_Static_assert(offsetof(marshal_t, bound_size) == 8, "bound offset");
_Static_assert(offsetof(marshal_t, buffer) == 16, "pointer offset");
_Static_assert(offsetof(marshal_t, retval) == 24, "retval offset");

static unsigned raw_ecall_calls;

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32));
}
static void digest_bytes(uint8_t *p, char digit) {
    const uint8_t b = digit <= '9' ? (uint8_t)(digit - '0') :
        (uint8_t)(digit - 'a' + 10);
    memset(p, (int)((b << 4) | b), 32);
}

static void set_param(uint8_t *p, uint16_t index, uint16_t flags,
    uint32_t offset, uint32_t size, uint32_t element_size,
    uint8_t direction, uint8_t category, uint8_t sign, uint8_t type_kind,
    uint8_t pointer_depth, uint8_t element_category, uint8_t element_sign,
    uint8_t element_kind, uint8_t size_source, uint8_t count_source,
    uint16_t size_param, uint16_t count_param,
    uint64_t size_literal, uint64_t count_literal) {
    memset(p, 0, PARAM_HEADER_SIZE);
    put16(p, index); put16(p + 2, flags);
    put32(p + 4, offset); put32(p + 8, size); put32(p + 12, element_size);
    p[16] = direction; p[17] = category; p[18] = sign; p[19] = type_kind;
    p[20] = pointer_depth; p[21] = element_category; p[22] = element_sign;
    p[23] = element_kind; p[24] = size_source; p[25] = count_source;
    put16(p + 26, size_param); put16(p + 28, count_param);
    put64(p + 32, size_literal); put64(p + 40, count_literal);
}

typedef struct {
    uint8_t count_literal_two;
    uint8_t nonintegral;
    uint8_t target_type_kind;
    uint8_t target_category;
    uint8_t target_scalar_flag;
} projection_options_t;

static size_t make_projection(uint8_t *out, projection_options_t options) {
    const uint16_t param_count = 4;
    const uint32_t ecall_len = ECALL_HEADER_SIZE + param_count * PARAM_HEADER_SIZE;
    const uint32_t total = PROJECTION_HEADER_SIZE + ecall_len;
    memset(out, 0, total);
    memcpy(out, "ATFMAR\0\0", 8);
    put16(out + 8, 1); put16(out + 10, PROJECTION_HEADER_SIZE);
    put32(out + 12, total); put32(out + 16, 1);
    digest_bytes(out + 24, 'a'); digest_bytes(out + 56, 'b'); digest_bytes(out + 88, 'c');

    uint8_t *e = out + PROJECTION_HEADER_SIZE;
    put32(e, ecall_len); put32(e + 4, 0); put32(e + 8, sizeof(marshal_t));
    put16(e + 12, param_count); put16(e + 14, 3);
    put32(e + 16, offsetof(marshal_t, retval)); put16(e + 20, sizeof(int32_t));
    e[22] = ATFIELD_MUTATION_CAT_INTEGER; e[23] = 1;
    e[24] = ATFIELD_MUTATION_TYPE_BUILTIN;

    uint8_t *p = e + ECALL_HEADER_SIZE;
    const uint16_t scalar_flags = (1u << 2) | (options.target_scalar_flag ? (1u << 6) : 0);
    set_param(p + 0 * PARAM_HEADER_SIZE, 0, scalar_flags,
        offsetof(marshal_t, target), sizeof(uint32_t), 0,
        ATFIELD_MUTATION_DIR_IN, options.target_category, 0, options.target_type_kind,
        0, 0, 0, 0, 0, 0, UINT16_MAX, UINT16_MAX, 0, 0);
    set_param(p + 1 * PARAM_HEADER_SIZE, 1, (1u << 2) | (1u << 6),
        offsetof(marshal_t, direct_out), sizeof(uint32_t), 0,
        ATFIELD_MUTATION_DIR_OUT, ATFIELD_MUTATION_CAT_INTEGER, 0,
        ATFIELD_MUTATION_TYPE_BUILTIN, 0, 0, 0, 0, 0, 0,
        UINT16_MAX, UINT16_MAX, 0, 0);
    set_param(p + 2 * PARAM_HEADER_SIZE, 2, (1u << 2) | (1u << 6),
        offsetof(marshal_t, bound_size), sizeof(uint32_t), 0,
        ATFIELD_MUTATION_DIR_IN, ATFIELD_MUTATION_CAT_INTEGER, 0,
        ATFIELD_MUTATION_TYPE_BUILTIN, 0, 0, 0, 0, 0, 0,
        UINT16_MAX, UINT16_MAX, 0, 0);

    uint8_t *ptr = p + 3 * PARAM_HEADER_SIZE;
    if (options.nonintegral) {
        set_param(ptr, 3, (1u << 0) | (1u << 2),
            offsetof(marshal_t, buffer), sizeof(void *), 4,
            ATFIELD_MUTATION_DIR_OUT, ATFIELD_MUTATION_CAT_POINTER, 255,
            ATFIELD_MUTATION_TYPE_POINTER, 1,
            ATFIELD_MUTATION_CAT_INTEGER, 1, ATFIELD_MUTATION_TYPE_BUILTIN,
            ATFIELD_MUTATION_BOUND_SOURCE_LITERAL,
            ATFIELD_MUTATION_BOUND_SOURCE_LITERAL,
            UINT16_MAX, UINT16_MAX, 3, 2);
    } else {
        set_param(ptr, 3, (1u << 0) | (1u << 2),
            offsetof(marshal_t, buffer), sizeof(void *), 4,
            ATFIELD_MUTATION_DIR_OUT, ATFIELD_MUTATION_CAT_POINTER, 255,
            ATFIELD_MUTATION_TYPE_POINTER, 1,
            ATFIELD_MUTATION_CAT_INTEGER, 1, ATFIELD_MUTATION_TYPE_BUILTIN,
            ATFIELD_MUTATION_BOUND_SOURCE_PARAM,
            options.count_literal_two ? ATFIELD_MUTATION_BOUND_SOURCE_LITERAL : 0,
            2, UINT16_MAX, 0, options.count_literal_two ? 2 : 0);
    }
    return total;
}

static size_t make_mutation_spec(uint8_t *out, uint64_t occurrence,
    uint32_t param_index, uint8_t kind, uint8_t width,
    uint64_t expected, uint64_t replacement) {
    memset(out, 0, SPEC_SIZE);
    memcpy(out, "ATFMUT\0\0", 8);
    put16(out + 8, 1); put16(out + 10, ATFIELD_MUTATION_HEADER_BYTES);
    put32(out + 12, SPEC_SIZE); put32(out + 16, 1);
    digest_bytes(out + 24, 'a'); digest_bytes(out + 56, 'b');

    const size_t rule = ATFIELD_MUTATION_HEADER_BYTES;
    put32(out + rule, ATFIELD_MUTATION_RULE_HEADER_BYTES + ATFIELD_MUTATION_SCALAR_TLV_BYTES);
    put16(out + rule + 4, 1); put32(out + rule + 8, 0);
    put64(out + rule + 12, occurrence); put16(out + rule + 20, 1);

    const size_t op = rule + ATFIELD_MUTATION_RULE_HEADER_BYTES;
    put16(out + op, 1); put32(out + op + 4, ATFIELD_MUTATION_SCALAR_TLV_BYTES);
    put32(out + op + 8, param_index); out[op + 12] = kind; out[op + 13] = width;
    put64(out + op + 16, expected); put64(out + op + 24, replacement);
    return SPEC_SIZE;
}

static void store_file(const char *path, const uint8_t *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = write(fd, data + offset, length - offset);
        CHECK(n > 0);
        offset += (size_t)n;
    }
    CHECK(close(fd) == 0);
}

static void load_projection(atfield_marshal_spec_t *spec, projection_options_t options,
    uint8_t *blob, size_t *blob_size) {
    *blob_size = make_projection(blob, options);
    char path[128];
    snprintf(path, sizeof(path), "/tmp/atfield-marshal-%ld.bin", (long)getpid());
    store_file(path, blob, *blob_size);
    CHECK(atfield_marshal_spec_load(spec, path, BUNDLE_SHA, LAYOUT_SHA, ABI_SHA) == 0);
    CHECK(unlink(path) == 0);
}

static void load_candidate(atfield_mutation_state_t *state, uint8_t *blob,
    uint64_t occurrence, uint32_t param, uint8_t width,
    uint64_t expected, uint64_t replacement) {
    const size_t n = make_mutation_spec(blob, occurrence, param, 0, width, expected, replacement);
    CHECK(atfield_mutation_load_spec_bytes(state, blob, n, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_mutation_bind_run(state, 7, 1) == 0);
}

static void raw_ecall(void *opaque) {
    marshal_t *ms = (marshal_t *)opaque;
    raw_ecall_calls++;
    ms->direct_out = 77;
    if (ms->buffer) *(int32_t *)ms->buffer = 88;
    ms->retval = -9;
}

static int invoke_once(atfield_mutation_state_t *state,
    const atfield_mutation_layout_t *layout, uint64_t selector_seq,
    marshal_t *original, atfield_call_capture_record_t *record) {
    marshal_t working;
    memset(&working, 0xA5, sizeof(working));
    int rc = atfield_mutation_before_ecall(state, 7, 1, raw_ecall_calls,
        0, selector_seq, layout, original, &working, sizeof(working), record);
    void *call_ms = rc == 1 ? (void *)&working : (void *)original;
    const unsigned before = raw_ecall_calls;
    raw_ecall(call_ms);
    CHECK(raw_ecall_calls == before + 1);
    CHECK(atfield_mutation_after_ecall(state, layout, call_ms, original, record) == 0);
    return rc;
}

static void init_ms(marshal_t *ms, uint32_t target, uint32_t bound, int32_t *buffer) {
    memset(ms, 0, sizeof(*ms));
    ms->target = target;
    ms->bound_size = bound;
    ms->buffer = buffer;
}

static void test_projection_abi_binding(void) {
    atfield_marshal_spec_t spec;
    uint8_t bytes[512];
    size_t length = make_projection(bytes, (projection_options_t){0,0,ATFIELD_MUTATION_TYPE_BUILTIN,ATFIELD_MUTATION_CAT_INTEGER,1});
    char path[128];
    snprintf(path, sizeof(path), "/tmp/atfield-abi-%ld.bin", (long)getpid());
    store_file(path, bytes, length);
    CHECK(atfield_marshal_spec_load(&spec, path, BUNDLE_SHA, LAYOUT_SHA,
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd") == -1);
    CHECK(strcmp(atfield_marshal_spec_error(&spec), "abi_digest_mismatch") == 0);
    CHECK(unlink(path) == 0);
}

static void test_pass_through(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512];
    size_t projection_size;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &projection_size);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    CHECK(layout != NULL);
    atfield_mutation_state_t state;
    atfield_mutation_init_disabled(&state);
    int32_t buffer = 0;
    marshal_t original;
    init_ms(&original, 42, 4, &buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &original, &record) == 0);
    CHECK(raw_ecall_calls == 1);
    CHECK(original.target == 42 && original.direct_out == 77 && original.retval == -9);
    CHECK(buffer == 88);
    CHECK(record.input_count == 2);
    CHECK(record.inputs[0].parameter_index == 0 && record.inputs[0].before_bits == 42);
    CHECK(record.output_count == 2);
    CHECK(record.outputs[0].parameter_index == 1 && record.outputs[0].before_bits == 77);
    CHECK(record.outputs[1].parameter_index == 3 && record.outputs[1].before_bits == 88);
    CHECK(record.has_retval && record.retval.before_bits == UINT64_C(0xfffffffffffffff7));
}

static void test_single_replacement_and_capture(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t projection_size;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &projection_size);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    CHECK(layout != NULL);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 42, 99);

    int32_t buffer = 0;
    marshal_t original;
    init_ms(&original, 42, 4, &buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &original, &record) == 1);
    CHECK(raw_ecall_calls == 1);
    CHECK(original.target == 42); /* clone keeps replacement out of wrapper-local input */
    CHECK(original.direct_out == 77 && original.retval == -9);
    CHECK(buffer == 88); /* pointer buffer is shared and copied back by the ABI */
    CHECK(record.mutation.target && record.mutation.matched && record.mutation.applied);
    CHECK(record.mutation.expected_bits == 42 && record.mutation.observed_bits == 42);
    CHECK(record.mutation.replacement_bits == 99);
    CHECK(record.output_count == 2 && record.has_retval);
    CHECK(atfield_mutation_finalize(&state) == 0);

    char path[] = "/tmp/atfield-capture-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0); CHECK(close(fd) == 0); CHECK(unlink(path) == 0);
    atfield_call_capture_t capture;
    CHECK(atfield_call_capture_open(&capture, path, "candidate-1", BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_call_capture_write_ecall(&capture, &record, 0) == 0);
    CHECK(atfield_call_capture_close(&capture, &state) == 0);
    FILE *fp = fopen(path, "rb");
    CHECK(fp != NULL);
    char jsonl[4096];
    size_t n = fread(jsonl, 1, sizeof(jsonl) - 1, fp);
    CHECK(!ferror(fp)); CHECK(fclose(fp) == 0); jsonl[n] = 0;
    CHECK(unlink(path) == 0);
    CHECK(strstr(jsonl, "\"type\":\"capture_start\"") != NULL);
    CHECK(strstr(jsonl, "\"type\":\"ecall\"") != NULL);
    CHECK(strstr(jsonl, "\"schema\":\"atfield-call-capture-v1\"") != NULL);
    CHECK(strstr(jsonl, "\"expected_bits\":\"0x0000002a\"") != NULL);
    CHECK(strstr(jsonl, "\"observed_bits\":\"0x0000002a\"") != NULL);
    CHECK(strstr(jsonl, "\"replacement_bits\":\"0x00000063\"") != NULL);
    CHECK(strstr(jsonl, "\"applied\":true") != NULL);
    CHECK(strstr(jsonl, "\"capture_end\"") == NULL); /* runner owns end */
}

static void test_unmatched_target_invalid(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 9, 0, 4, 42, 99);
    int32_t buffer = 0; marshal_t ms; init_ms(&ms, 42, 4, &buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &ms, &record) == 0);
    CHECK(atfield_mutation_finalize(&state) == -1);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "target_occurrence_missed") == 0);
    CHECK(raw_ecall_calls == 1 && ms.target == 42);
}

static void test_duplicate_target_invalid(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 42, 99);
    int32_t buffer = 0; marshal_t first, second;
    init_ms(&first, 42, 4, &buffer); init_ms(&second, 42, 4, &buffer);
    atfield_call_capture_record_t a, b;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &first, &a) == 1);
    CHECK(invoke_once(&state, layout, 0, &second, &b) == -1);
    CHECK(raw_ecall_calls == 2); /* one raw ECALL for each host invocation */
    CHECK(state.rule.hit_count == 2);
    CHECK(atfield_mutation_finalize(&state) == -1);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "duplicate_hit") == 0);
}

static void test_width_overflow_and_spec_digest(void) {
    uint8_t mutation[256];
    atfield_mutation_state_t state;
    size_t n = make_mutation_spec(mutation, 0, 0, 0, 4, 42, UINT64_C(0x100000000));
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n, BUNDLE_SHA, LAYOUT_SHA) == -1);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "spec_width_overflow") == 0);
    /* Signed-width encoding must already carry canonical sign extension. */
    n = make_mutation_spec(mutation, 0, 0, 1, 1, UINT64_C(0x80), UINT64_C(0x7f));
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n, BUNDLE_SHA, LAYOUT_SHA) == -1);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "spec_width_overflow") == 0);
    n = make_mutation_spec(mutation, 0, 0, 1, 1,
        UINT64_C(0xffffffffffffff80), UINT64_C(0x7f));
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n, BUNDLE_SHA, LAYOUT_SHA) == 0);
    n = make_mutation_spec(mutation, 0, 0, 0, 4, 42, 99);
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n,
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        LAYOUT_SHA) == -1);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "abi_digest_mismatch") == 0);
}

static void test_size_count_growth_rejected(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){1,0,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 2, 4, 4, 8);
    int32_t buffer[2] = {0}; marshal_t ms; init_ms(&ms, 42, 4, buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &ms, &record) == -1);
    CHECK(raw_ecall_calls == 1);
    CHECK(strcmp(record.mutation.reason, "pointer_bound_grew") == 0);
    CHECK(ms.bound_size == 4); /* invalid candidate is transparent to the host input */
}

static void test_nonintegral_size_count_rejected(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){0,1,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 42, 99);
    int32_t buffer[2] = {0}; marshal_t ms; init_ms(&ms, 42, 4, buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &ms, &record) == -1);
    CHECK(raw_ecall_calls == 1);
    CHECK(strcmp(record.mutation.reason, "pointer_bound_unproven") == 0);
}

static void test_compiler_scalar_proof(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    /* A compiler-probed enum is eligible when the projection explicitly marks it. */
    load_projection(&spec, (projection_options_t){0,0,ATFIELD_MUTATION_TYPE_ENUM,ATFIELD_MUTATION_CAT_ENUM,1}, projection, &n);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 42, 44);
    int32_t buffer = 0; marshal_t ms; init_ms(&ms, 42, 4, &buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, atfield_marshal_spec_get(&spec, 0), 0, &ms, &record) == 1);
    CHECK(raw_ecall_calls == 1 && ms.target == 42);
    CHECK(atfield_mutation_finalize(&state) == 0);

    /* A resolved named integer is eligible when compiler proof is present. */
    load_projection(&spec, (projection_options_t){0,0,ATFIELD_MUTATION_TYPE_NAMED,ATFIELD_MUTATION_CAT_INTEGER,1}, projection, &n);
    load_candidate(&state, mutation, 0, 0, 4, 42, 45);
    init_ms(&ms, 42, 4, &buffer);
    CHECK(invoke_once(&state, atfield_marshal_spec_get(&spec, 0), 0, &ms, &record) == 1);
    CHECK(ms.target == 42 && raw_ecall_calls == 2);
    CHECK(atfield_mutation_finalize(&state) == 0);

    /* The compiler proof bit, not a guessed C type name, gates the operation. */
    load_projection(&spec, (projection_options_t){0,0,ATFIELD_MUTATION_TYPE_NAMED,ATFIELD_MUTATION_CAT_INTEGER,0}, projection, &n);
    load_candidate(&state, mutation, 0, 0, 4, 42, 44);
    init_ms(&ms, 42, 4, &buffer);
    CHECK(invoke_once(&state, atfield_marshal_spec_get(&spec, 0), 0, &ms, &record) == -1);
    CHECK(strcmp(record.mutation.reason, "unsupported_mutation_layout") == 0);
    CHECK(raw_ecall_calls == 3);

    /* Unknown named typedefs retain category=other and are rejected. */
    load_projection(&spec, (projection_options_t){0,0,ATFIELD_MUTATION_TYPE_NAMED,255,0}, projection, &n);
    load_candidate(&state, mutation, 0, 0, 4, 42, 44);
    init_ms(&ms, 42, 4, &buffer);
    CHECK(invoke_once(&state, atfield_marshal_spec_get(&spec, 0), 0, &ms, &record) == -1);
    CHECK(strcmp(record.mutation.reason, "unsupported_mutation_layout") == 0);
    CHECK(raw_ecall_calls == 4);
}


static void test_expected_mismatch_invalid(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 43, 99);
    int32_t buffer = 0; marshal_t ms; init_ms(&ms, 42, 4, &buffer);
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    CHECK(invoke_once(&state, layout, 0, &ms, &record) == -1);
    CHECK(raw_ecall_calls == 1 && ms.target == 42);
    CHECK(record.mutation.target && record.mutation.has_observed);
    CHECK(record.mutation.observed_bits == 42 && !record.mutation.applied);
    CHECK(strcmp(record.mutation.reason, "expected_value_mismatch") == 0);
    CHECK(atfield_mutation_finalize(&state) == -1);
}

static void test_multiple_eid_rejected(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 42, 99);
    int32_t buffer = 0; marshal_t ms; init_ms(&ms, 42, 4, &buffer);
    marshal_t working;
    atfield_call_capture_record_t record;
    raw_ecall_calls = 0;
    int rc = atfield_mutation_before_ecall(&state, 8, 1, 0, 0, 0, layout,
        &ms, &working, sizeof(working), &record);
    CHECK(rc == -1);
    raw_ecall(&ms);
    CHECK(atfield_mutation_after_ecall(&state, layout, &ms, &ms, &record) == 0);
    CHECK(raw_ecall_calls == 1 && ms.target == 42);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "multiple_eids") == 0);
}

typedef struct {
    atfield_mutation_state_t *state;
    const atfield_mutation_layout_t *layout;
    marshal_t *ms;
    int rc;
} thread_call_t;

static void *call_from_other_thread(void *opaque) {
    thread_call_t *ctx = (thread_call_t *)opaque;
    marshal_t working;
    atfield_call_capture_record_t record;
    ctx->rc = atfield_mutation_before_ecall(ctx->state, 7, 1, 0, 0, 0,
        ctx->layout, ctx->ms, &working, sizeof(working), &record);
    raw_ecall(ctx->rc == 1 ? (void *)&working : (void *)ctx->ms);
    (void)atfield_mutation_after_ecall(ctx->state, ctx->layout,
        ctx->rc == 1 ? (const void *)&working : (const void *)ctx->ms,
        ctx->ms, &record);
    return NULL;
}

static void test_multiple_threads_rejected(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &n);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    atfield_mutation_state_t state;
    load_candidate(&state, mutation, 0, 0, 4, 42, 99);
    int32_t buffer = 0; marshal_t ms; init_ms(&ms, 42, 4, &buffer);
    thread_call_t ctx = {&state, layout, &ms, 0};
    pthread_t thread;
    raw_ecall_calls = 0;
    CHECK(pthread_create(&thread, NULL, call_from_other_thread, &ctx) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(ctx.rc == -1 && raw_ecall_calls == 1 && ms.target == 42);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "multiple_threads") == 0);
}


static void test_buffer_mutation_and_capture(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512], mutation[256];
    size_t n = make_projection(projection, (projection_options_t){0,0,1,1,1});
    /* Change param 3 (buffer) from DIR_OUT to DIR_IN so it is an input buffer of bound_size bytes */
    uint8_t *p3 = projection + PROJECTION_HEADER_SIZE + ECALL_HEADER_SIZE + 3 * PARAM_HEADER_SIZE;
    p3[16] = ATFIELD_MUTATION_DIR_IN;
    char ppath[] = "/tmp/atfield-proj-buf-XXXXXX";
    int pfd = mkstemp(ppath);
    CHECK(pfd >= 0);
    CHECK(write(pfd, projection, n) == (ssize_t)n);
    CHECK(close(pfd) == 0);
    CHECK(atfield_marshal_spec_load(&spec, ppath, BUNDLE_SHA, LAYOUT_SHA, ABI_SHA) == 0);
    CHECK(unlink(ppath) == 0);

    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    CHECK(layout != NULL);

    /* Build a buffer XOR mutation rule (op_type=2, sub_op=1=xor_byte) on param 3 at byte_offset=1: 0x22 -> 0x23 */
    memset(mutation, 0, SPEC_SIZE);
    memcpy(mutation, "ATFMUT\0\0", 8);
    put16(mutation + 8, 1); put16(mutation + 10, 88);
    put32(mutation + 12, SPEC_SIZE); put32(mutation + 16, 1);
    digest_bytes(mutation + 24, 'a'); digest_bytes(mutation + 56, 'b');
    uint8_t *rule = mutation + 88;
    put32(rule, 56); put16(rule + 4, 1); put16(rule + 6, 0);
    put32(rule + 8, 0); put64(rule + 12, 0); put16(rule + 20, 1);
    uint8_t *op = rule + 24;
    put16(op, ATFIELD_MUTATION_OP_MUTATE_BUFFER);
    put16(op + 2, ATFIELD_BUF_OP_XOR_BYTE);
    put32(op + 4, 32);
    put32(op + 8, 3); /* param_index = 3 */
    put32(op + 12, 1); /* byte_offset = 1 */
    put32(op + 16, 1); /* slice_length = 1 */
    put32(op + 20, 0x22); /* expected byte at offset 1 */
    put64(op + 24, 0x23); /* replacement byte at offset 1 */

    atfield_mutation_state_t state;
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, SPEC_SIZE, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);

    uint8_t in_buf[192];
    for (size_t i = 0; i < sizeof(in_buf); i++) in_buf[i] = (uint8_t)i;
    in_buf[0] = 0x11; in_buf[1] = 0x22; in_buf[2] = 0x33; in_buf[3] = 0x44;
    marshal_t ms;
    init_ms(&ms, 42, sizeof(in_buf), (int32_t *)in_buf);
    marshal_t working;
    atfield_call_capture_record_t record;
    int rc = atfield_mutation_before_ecall(&state, 7, 1, 0, 0, 0, layout, &ms, &working, sizeof(working), &record);
    CHECK(rc == 1);
    /* Caller's input buffer is untouched; working.buffer points to a mutated clone */
    CHECK(in_buf[1] == 0x22);
    CHECK(working.buffer != in_buf);
    CHECK(((uint8_t *)working.buffer)[0] == 0x11);
    CHECK(((uint8_t *)working.buffer)[1] == 0x23);
    CHECK(((uint8_t *)working.buffer)[2] == 0x33);
    CHECK(record.buffer_input_count == 1);
    CHECK(record.buffer_inputs[0].parameter_index == 3 && record.buffer_inputs[0].byte_length == sizeof(in_buf));
    CHECK(record.buffer_inputs[0].prefix_length == ATFIELD_CAPTURE_MAX_BUF_PREFIX_BYTES);
    unsigned char expected_sha[SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    char expected_hex[65];
    CHECK(SHA256((const unsigned char *)working.buffer, sizeof(in_buf), expected_sha) != NULL);
    for (size_t i = 0; i < sizeof(expected_sha); i++) {
        expected_hex[i * 2] = hex[expected_sha[i] >> 4];
        expected_hex[i * 2 + 1] = hex[expected_sha[i] & 0x0f];
    }
    expected_hex[64] = '\0';
    CHECK(strcmp(record.buffer_inputs[0].sha256, expected_hex) == 0);
    CHECK(atfield_mutation_after_ecall(&state, layout, &working, &ms, &record) == 0);
    CHECK(atfield_mutation_finalize(&state) == 0);
}


typedef struct {
    uint32_t count;
    uint32_t pad;
    int32_t *in_arr;
    int32_t *out_arr;
    int32_t *in_slice;
    int32_t retval;
    uint32_t tail;
} linked_ms_t;

static void test_linked_expansion_and_alias_and_budget(void) {
    /* Stage 2 acceptance scenario:
     * One scalar length (param 0: count, element_size=4) simultaneously controls:
     * - param 1: [in, count=count] int32_t *in_arr
     * - param 2: [out, count=count] int32_t *out_arr
     * - param 3: [in, count=1] int32_t *in_slice (aliased to &in_arr[1], offset 4 bytes)
     */
    uint8_t proj[512];
    const uint16_t param_count = 4;
    const uint32_t ecall_len = ECALL_HEADER_SIZE + param_count * PARAM_HEADER_SIZE;
    const uint32_t total = PROJECTION_HEADER_SIZE + ecall_len;
    memset(proj, 0, total);
    memcpy(proj, "ATFMAR\0\0", 8);
    put16(proj + 8, 1); put16(proj + 10, PROJECTION_HEADER_SIZE);
    put32(proj + 12, total); put32(proj + 16, 1);
    digest_bytes(proj + 24, 'a'); digest_bytes(proj + 56, 'b'); digest_bytes(proj + 88, 'c');

    uint8_t *e = proj + PROJECTION_HEADER_SIZE;
    put32(e, ecall_len); put32(e + 4, 0); put32(e + 8, sizeof(linked_ms_t));
    put16(e + 12, param_count); put16(e + 14, 3);
    put32(e + 16, offsetof(linked_ms_t, retval)); put16(e + 20, sizeof(int32_t));
    e[22] = ATFIELD_MUTATION_CAT_INTEGER; e[23] = 1; e[24] = ATFIELD_MUTATION_TYPE_BUILTIN;

    uint8_t *p = e + ECALL_HEADER_SIZE;
    /* param 0: uint32_t count */
    set_param(p + 0 * PARAM_HEADER_SIZE, 0, (1u << 2) | (1u << 6),
        offsetof(linked_ms_t, count), sizeof(uint32_t), 0,
        ATFIELD_MUTATION_DIR_IN, ATFIELD_MUTATION_CAT_INTEGER, 0, ATFIELD_MUTATION_TYPE_BUILTIN,
        0, 0, 0, 0, 0, 0, UINT16_MAX, UINT16_MAX, 0, 0);
    /* param 1: [in, count=param 0] int32_t *in_arr */
    set_param(p + 1 * PARAM_HEADER_SIZE, 1, (1u << 0) | (1u << 2),
        offsetof(linked_ms_t, in_arr), sizeof(void *), 4,
        ATFIELD_MUTATION_DIR_IN, ATFIELD_MUTATION_CAT_POINTER, 255, ATFIELD_MUTATION_TYPE_POINTER,
        1, ATFIELD_MUTATION_CAT_INTEGER, 1, ATFIELD_MUTATION_TYPE_BUILTIN,
        0, ATFIELD_MUTATION_BOUND_SOURCE_PARAM, UINT16_MAX, 0, 0, 0);
    /* param 2: [out, count=param 0] int32_t *out_arr */
    set_param(p + 2 * PARAM_HEADER_SIZE, 2, (1u << 0) | (1u << 2),
        offsetof(linked_ms_t, out_arr), sizeof(void *), 4,
        ATFIELD_MUTATION_DIR_OUT, ATFIELD_MUTATION_CAT_POINTER, 255, ATFIELD_MUTATION_TYPE_POINTER,
        1, ATFIELD_MUTATION_CAT_INTEGER, 1, ATFIELD_MUTATION_TYPE_BUILTIN,
        0, ATFIELD_MUTATION_BOUND_SOURCE_PARAM, UINT16_MAX, 0, 0, 0);
    /* param 3: [in, count=1] int32_t *in_slice */
    set_param(p + 3 * PARAM_HEADER_SIZE, 3, (1u << 0) | (1u << 2),
        offsetof(linked_ms_t, in_slice), sizeof(void *), 4,
        ATFIELD_MUTATION_DIR_IN, ATFIELD_MUTATION_CAT_POINTER, 255, ATFIELD_MUTATION_TYPE_POINTER,
        1, ATFIELD_MUTATION_CAT_INTEGER, 1, ATFIELD_MUTATION_TYPE_BUILTIN,
        0, ATFIELD_MUTATION_BOUND_SOURCE_LITERAL, UINT16_MAX, UINT16_MAX, 0, 1);

    atfield_marshal_spec_t spec;
    char ppath[] = "/tmp/atfield-proj-linked-XXXXXX";
    int pfd = mkstemp(ppath);
    CHECK(pfd >= 0);
    CHECK(write(pfd, proj, total) == (ssize_t)total);
    CHECK(close(pfd) == 0);
    CHECK(atfield_marshal_spec_load(&spec, ppath, BUNDLE_SHA, LAYOUT_SHA, ABI_SHA) == 0);
    CHECK(unlink(ppath) == 0);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    CHECK(layout != NULL);

    /* 1. Mutate count: 2 -> 8 in exec_mode=1 (expands both in_arr and out_arr from 8B to 32B, preserves alias in_slice == in_arr + 1) */
    uint8_t mutation[256];
    make_mutation_spec(mutation, 0, 0, 0, 4, 2, 8);
    /* Set rule flags: targetGen=1, execMode=1 -> 0x0101 at rule + 6 */
    put16(mutation + ATFIELD_MUTATION_HEADER_BYTES + 6, 0x0101u);

    atfield_mutation_state_t state;
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, SPEC_SIZE, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);

    int32_t orig_in[2] = {101, 202};
    int32_t orig_out[2] = {7, 8};
    linked_ms_t ms;
    memset(&ms, 0, sizeof(ms));
    ms.count = 2;
    ms.in_arr = orig_in;
    ms.out_arr = orig_out;
    ms.in_slice = &orig_in[1]; /* alias slice at +4 bytes */

    linked_ms_t working;
    atfield_call_capture_record_t record;
    int rc = atfield_mutation_before_ecall(&state, 7, 1, 0, 0, 0, layout, &ms, &working, sizeof(working), &record);
    CHECK(rc == 1);
    CHECK(working.count == 8);
    CHECK(working.in_arr != orig_in);
    CHECK(working.out_arr != orig_out);
    /* Alias preserved in new allocation! */
    CHECK(working.in_slice == working.in_arr + 1);
    CHECK(working.in_arr[0] == 101 && working.in_arr[1] == 202);
    CHECK(*working.in_slice == 202);
    /* Extended tail is deterministically zero-filled */
    for (int i = 2; i < 8; i++) CHECK(working.in_arr[i] == 0);
    /* Simulated enclave writes 8 elements into expanded out_arr without overflowing orig_out[2] */
    for (int i = 0; i < 8; i++) working.out_arr[i] = 1000 + i;
    working.retval = 0;
    /* Captured buffer input records expanded 32-byte length */
    CHECK(record.buffer_input_count == 2);
    CHECK(record.buffer_inputs[0].parameter_index == 1 && record.buffer_inputs[0].byte_length == 32);
    CHECK(record.buffer_inputs[1].parameter_index == 3 && record.buffer_inputs[1].byte_length == 4);
    CHECK(atfield_mutation_after_ecall(&state, layout, &working, &ms, &record) == 0);
    /* Caller's smaller 2-element output buffer was NOT overwritten by the 8-element probe output */
    CHECK(orig_out[0] == 7 && orig_out[1] == 8);
    CHECK(atfield_mutation_finalize(&state) == 0);

    /* 2. Over-budget candidate: count 2 -> 30000 (120,000 bytes > 64 KiB per-buffer budget) -> expansion_budget_exceeded */
    make_mutation_spec(mutation, 0, 0, 0, 4, 2, 30000);
    put16(mutation + ATFIELD_MUTATION_HEADER_BYTES + 6, 0x0101u);
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, SPEC_SIZE, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);
    rc = atfield_mutation_before_ecall(&state, 7, 1, 0, 0, 0, layout, &ms, &working, sizeof(working), &record);
    CHECK(rc == -1);
    CHECK(!record.mutation.applied);
    CHECK(strcmp(record.mutation.reason, "expansion_budget_exceeded") == 0);
}

/* Stage: explicit, recorded prefix-call mutation (spec v2). */
static size_t make_mutation_spec_v2(uint8_t *out,
    uint32_t target_sel, uint64_t target_occ, uint32_t target_param,
    uint64_t target_expected, uint64_t target_replacement,
    uint32_t pre_sel, uint64_t pre_occ, uint32_t pre_param,
    uint32_t pre_offset, uint8_t pre_width,
    uint64_t pre_expected, uint64_t pre_replacement) {
    const size_t total = ATFIELD_MUTATION_HEADER_BYTES + ATFIELD_MUTATION_RULE_HEADER_BYTES
        + ATFIELD_MUTATION_SCALAR_TLV_BYTES + ATFIELD_MUTATION_PREFIX_TLV_BYTES;
    memset(out, 0, total);
    memcpy(out, "ATFMUT\0\0", 8);
    put16(out + 8, 2); put16(out + 10, ATFIELD_MUTATION_HEADER_BYTES);
    put32(out + 12, (uint32_t)total); put32(out + 16, 1);
    digest_bytes(out + 24, 'a'); digest_bytes(out + 56, 'b');

    const size_t rule = ATFIELD_MUTATION_HEADER_BYTES;
    put32(out + rule, (uint32_t)(total - rule));
    put16(out + rule + 4, 1);
    put16(out + rule + 6, 0); /* target gen 1, exec_mode 0 */
    put32(out + rule + 8, target_sel);
    put64(out + rule + 12, target_occ);
    put16(out + rule + 20, 2);
    put16(out + rule + 22, 0);

    const size_t op = rule + ATFIELD_MUTATION_RULE_HEADER_BYTES;
    put16(out + op, 1); put16(out + op + 2, 0);
    put32(out + op + 4, ATFIELD_MUTATION_SCALAR_TLV_BYTES);
    put32(out + op + 8, target_param);
    out[op + 12] = 0; out[op + 13] = 4; put16(out + op + 14, 0);
    put64(out + op + 16, target_expected);
    put64(out + op + 24, target_replacement);

    const size_t pre = op + ATFIELD_MUTATION_SCALAR_TLV_BYTES;
    put16(out + pre, ATFIELD_MUTATION_OP_PREFIX_MUTATE); put16(out + pre + 2, 0);
    put32(out + pre + 4, ATFIELD_MUTATION_PREFIX_TLV_BYTES);
    put32(out + pre + 8, pre_sel);
    put64(out + pre + 12, pre_occ);
    put32(out + pre + 20, pre_param);
    out[pre + 24] = ATFIELD_MUTATION_SCALAR_UNSIGNED;
    out[pre + 25] = pre_width;
    put16(out + pre + 26, 0);
    put32(out + pre + 28, pre_offset);
    put64(out + pre + 32, pre_expected);
    put64(out + pre + 40, pre_replacement);
    return total;
}

static void test_explicit_prefix_mutation(void) {
    atfield_marshal_spec_t spec;
    uint8_t projection[512];
    size_t projection_size;
    load_projection(&spec, (projection_options_t){0,0,ATFIELD_MUTATION_TYPE_BUILTIN,ATFIELD_MUTATION_CAT_INTEGER,1},
        projection, &projection_size);
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    CHECK(layout != NULL);
    spec.parameters[0][3].direction = ATFIELD_MUTATION_DIR_INOUT;

    uint8_t mutation[512];
    const size_t n = make_mutation_spec_v2(mutation,
        0, 1, 0, 42, 7,                    /* target: param0 42 -> 7 at occurrence 1 */
        0, 0, 3, 0, 4, 0x11223344u, 0xAABBCCDDu); /* prefix: buffer param3 @occurrence 0 */
    atfield_mutation_state_t state;
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(state.rule.prefix_op_count == 1);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);

    int32_t backing[2] = {(int32_t)0x11223344, 0x55667788};
    marshal_t ms;
    init_ms(&ms, 42, 8, backing);
    marshal_t working;
    atfield_call_capture_record_t record;

    /* Prefix call (occurrence 0): pass-through marshal, recorded + applied write */
    int rc = atfield_mutation_before_ecall(&state, 7, 1, 0, 0, 0, layout,
        &ms, &working, sizeof(working), &record);
    CHECK(rc == 0);
    CHECK(backing[0] == (int32_t)0xAABBCCDDu);
    CHECK(backing[1] == 0x55667788);
    CHECK(record.mutation.matched == 1);
    CHECK(record.mutation.target == 0);
    CHECK(record.mutation.applied == 1);
    CHECK(record.mutation.parameter_index == 3);
    CHECK(record.mutation.observed_bits == 0x11223344u);
    CHECK(record.mutation.replacement_bits == 0xAABBCCDDu);
    CHECK(strcmp(record.mutation.reason, "applied") == 0);
    CHECK(record.buffer_input_count == 1);
    CHECK(memcmp(record.buffer_inputs[0].prefix_bytes, backing, sizeof(backing)) == 0);
    CHECK(atfield_mutation_after_ecall(&state, layout, &ms, &ms, &record) == 0);

    /* Target call (occurrence 1): scalar replacement applies */
    ms.target = 42;
    rc = atfield_mutation_before_ecall(&state, 7, 1, 1, 0, 1, layout,
        &ms, &working, sizeof(working), &record);
    CHECK(rc == 1);
    CHECK(working.target == 7);
    CHECK(record.mutation.target == 1);
    CHECK(atfield_mutation_finalize(&state) == 0);

    /* Unplanned calls are never written */
    CHECK(backing[0] == (int32_t)0xAABBCCDDu && backing[1] == 0x55667788);

    /* Mismatched expected value fails visibly, never silently */
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);
    backing[0] = 0x99999999;
    init_ms(&ms, 42, 8, backing);
    rc = atfield_mutation_before_ecall(&state, 7, 1, 0, 0, 0, layout,
        &ms, &working, sizeof(working), &record);
    CHECK(rc == -1);
    CHECK(record.mutation.applied == 0);
    CHECK(strcmp(record.mutation.reason, "expected_value_mismatch") == 0);
    CHECK(backing[0] == (int32_t)0x99999999);

    /* finalize requires every planned prefix op to have applied */
    CHECK(atfield_mutation_load_spec_bytes(&state, mutation, n, BUNDLE_SHA, LAYOUT_SHA) == 0);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);
    init_ms(&ms, 42, 8, backing);
    backing[0] = (int32_t)0x11223344;
    rc = atfield_mutation_before_ecall(&state, 7, 1, 1, 0, 1, layout,
        &ms, &working, sizeof(working), &record);
    CHECK(rc == -1);
    CHECK(record.mutation.applied == 0);
    CHECK(atfield_mutation_finalize(&state) == -1);
    CHECK(strcmp(atfield_mutation_invalid_reason(&state), "prefix_mutation_missed") == 0);
}

int main(void) {
    test_projection_abi_binding();
    test_pass_through();
    test_single_replacement_and_capture();
    test_unmatched_target_invalid();
    test_duplicate_target_invalid();
    test_width_overflow_and_spec_digest();
    test_expected_mismatch_invalid();
    test_multiple_eid_rejected();
    test_multiple_threads_rejected();
    test_size_count_growth_rejected();
    test_nonintegral_size_count_rejected();
    test_compiler_scalar_proof();
    test_buffer_mutation_and_capture();
    test_linked_expansion_and_alias_and_budget();
    test_explicit_prefix_mutation();
    puts("native mutation tests: PASS");
    return 0;
}
