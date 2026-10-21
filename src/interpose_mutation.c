#define _GNU_SOURCE
#include "interpose_mutation.h"

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "native SGX mutation requires the x86 little-endian ABI"
#endif

#define MUTATION_MAX_MARSHAL_SIZE (1024u * 1024u)
#define MUTATION_MAX_RUN_ID 128u
#define MUTATION_RULE_TYPE 1u
#define MUTATION_OP_REPLACE_SCALAR 1u
#define MARSHAL_PARAM_POINTER (1u << 0)
#define MARSHAL_PARAM_ARRAY_DECAY (1u << 1)
#define MARSHAL_PARAM_REPLAY_SUPPORTED (1u << 2)
#define MARSHAL_PARAM_USER_CHECK (1u << 3)
#define MARSHAL_PARAM_STRING (1u << 4)
#define MARSHAL_PARAM_WSTRING (1u << 5)
#define MARSHAL_PARAM_SCALAR_MUTATION_SUPPORTED (1u << 6)
#define MARSHAL_ECALL_REPLAY_SUPPORTED (1u << 0)
#define MARSHAL_ECALL_HAS_RETVAL (1u << 1)

static void copy_text(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    dst[0] = '\0';
    if (!src) return;
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void mutation_invalid(atfield_mutation_state_t *state, const char *reason) {
    if (!state) return;
    state->invalid = 1;
    if (!state->invalid_reason[0]) copy_text(state->invalid_reason, sizeof(state->invalid_reason), reason);
}

static void capture_failed(atfield_call_capture_t *capture, const char *reason) {
    if (!capture) return;
    capture->failed = 1;
    if (!capture->failure_reason[0]) copy_text(capture->failure_reason, sizeof(capture->failure_reason), reason);
}

static int digest_valid(const char *s) {
    if (!s || strlen(s) != ATFIELD_MUTATION_DIGEST_HEX) return 0;
    for (size_t i = 0; i < ATFIELD_MUTATION_DIGEST_HEX; i++) {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int digest_to_bytes(const char *hex, uint8_t out[32]) {
    if (!digest_valid(hex) || !out) return -1;
    for (size_t i = 0; i < 32; i++) {
        const int hi = hex_nibble(hex[i * 2]);
        const int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    unsigned int diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned int)(a[i] ^ b[i]);
    return diff == 0;
}

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

static int read_bounded_file(const char *path, size_t limit, uint8_t **out, size_t *out_size) {
    if (!path || !*path || !out || !out_size) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long end = ftell(fp);
    if (end < 0 || (unsigned long)end > limit || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -2;
    }
    size_t n = (size_t)end;
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (!buf) { fclose(fp); return -3; }
    size_t got = fread(buf, 1, n, fp);
    int read_error = ferror(fp);
    int close_error = fclose(fp);
    if (got != n || read_error || close_error) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_size = n;
    return 0;
}

static int value_kind_width_canonical(uint8_t kind, uint8_t width, uint64_t bits) {
    if (width != 1 && width != 2 && width != 4 && width != 8) return 0;
    const unsigned int nbits = (unsigned int)width * 8u;
    const uint64_t mask = nbits == 64 ? UINT64_MAX : ((UINT64_C(1) << nbits) - 1u);
    if (kind == ATFIELD_MUTATION_SCALAR_UNSIGNED) return (bits & ~mask) == 0;
    if (kind != ATFIELD_MUTATION_SCALAR_SIGNED) return 0;
    const uint64_t low = bits & mask;
    const uint64_t sign = UINT64_C(1) << (nbits - 1u);
    const uint64_t extended = (low & sign) ? (low | ~mask) : low;
    return bits == extended;
}

static uint64_t normalize_bits(uint8_t kind, uint8_t width, uint64_t bits) {
    const unsigned int nbits = (unsigned int)width * 8u;
    const uint64_t mask = nbits == 64 ? UINT64_MAX : ((UINT64_C(1) << nbits) - 1u);
    uint64_t result = bits & mask;
    if (kind == ATFIELD_MUTATION_SCALAR_SIGNED && nbits < 64 &&
        (result & (UINT64_C(1) << (nbits - 1u)))) result |= ~mask;
    return result;
}

/* The compiler-probed category, width and signedness are authoritative. ABI named/enum types fail closed. */
static int scalar_kind_from_layout(
    uint8_t type_kind,
    uint8_t category,
    int8_t signedness,
    size_t width,
    uint8_t *kind,
    uint8_t *width_bytes)
{
    if ((type_kind != ATFIELD_MUTATION_TYPE_BUILTIN &&
         type_kind != ATFIELD_MUTATION_TYPE_NAMED &&
         type_kind != ATFIELD_MUTATION_TYPE_ENUM) ||
        (category != ATFIELD_MUTATION_CAT_INTEGER &&
         category != ATFIELD_MUTATION_CAT_CHARACTER &&
         category != ATFIELD_MUTATION_CAT_ENUM &&
         category != ATFIELD_MUTATION_CAT_BOOLEAN) ||
        (signedness != 0 && signedness != 1) ||
        (width != 1 && width != 2 && width != 4 && width != 8)) return -1;
    if (category == ATFIELD_MUTATION_CAT_BOOLEAN &&
        (signedness != 0 || width != 1)) return -1;
    if (kind) *kind = signedness ? ATFIELD_MUTATION_SCALAR_SIGNED : ATFIELD_MUTATION_SCALAR_UNSIGNED;
    if (width_bytes) *width_bytes = (uint8_t)width;
    return 0;
}

static int signedness_byte_valid(uint8_t value) {
    return value == 0 || value == 1 || value == 255;
}

static int category_byte_valid(uint8_t value) {
    return value == ATFIELD_MUTATION_CAT_INTEGER ||
        value == ATFIELD_MUTATION_CAT_CHARACTER ||
        value == ATFIELD_MUTATION_CAT_ENUM ||
        value == ATFIELD_MUTATION_CAT_BOOLEAN ||
        value == ATFIELD_MUTATION_CAT_POINTER ||
        value == ATFIELD_MUTATION_CAT_RECORD ||
        value == ATFIELD_MUTATION_CAT_UNION ||
        value == ATFIELD_MUTATION_CAT_ARRAY ||
        value == 255;
}

static int type_kind_byte_valid(uint8_t value) {
    return value == ATFIELD_MUTATION_TYPE_BUILTIN ||
        value == ATFIELD_MUTATION_TYPE_NAMED ||
        value == ATFIELD_MUTATION_TYPE_ENUM ||
        value == ATFIELD_MUTATION_TYPE_STRUCT ||
        value == ATFIELD_MUTATION_TYPE_UNION ||
        value == ATFIELD_MUTATION_TYPE_POINTER ||
        value == 255;
}

static int source_byte_valid(uint8_t value) {
    return value == ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
        value == ATFIELD_MUTATION_BOUND_SOURCE_LITERAL ||
        value == ATFIELD_MUTATION_BOUND_SOURCE_PARAM;
}

static int param_sources_valid(const atfield_mutation_layout_t *layout) {
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (!source_byte_valid(p->size_source) || !source_byte_valid(p->count_source)) return 0;
        if (p->size_source == ATFIELD_MUTATION_BOUND_SOURCE_PARAM) {
            if (p->size_parameter_index >= layout->parameter_count || p->size_literal != 0) return 0;
        } else if (p->size_parameter_index != UINT16_MAX ||
                   (p->size_source == ATFIELD_MUTATION_BOUND_SOURCE_NONE && p->size_literal != 0)) return 0;
        if (p->count_source == ATFIELD_MUTATION_BOUND_SOURCE_PARAM) {
            if (p->count_parameter_index >= layout->parameter_count || p->count_literal != 0) return 0;
        } else if (p->count_parameter_index != UINT16_MAX ||
                   (p->count_source == ATFIELD_MUTATION_BOUND_SOURCE_NONE && p->count_literal != 0)) return 0;
        if (p->fixed_array_element_count &&
            (p->size_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
             p->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE)) return 0;
    }
    return 1;
}

static int checked_range(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

static int ranges_overlap(size_t a, size_t asize, size_t b, size_t bsize) {
    return asize && bsize && a < b + bsize && b < a + asize;
}

static const atfield_mutation_param_layout_t *find_param(
    const atfield_mutation_layout_t *layout,
    uint32_t index)
{
    if (!layout) return NULL;
    for (size_t i = 0; i < layout->parameter_count; i++)
        if (layout->parameters[i].parameter_index == index) return &layout->parameters[i];
    return NULL;
}

static int descriptor_valid(
    const atfield_mutation_state_t *state,
    const atfield_mutation_layout_t *layout,
    int selector)
{
    uint8_t layout_bundle[32], layout_sha[32], abi_sha[32], expected_bundle[32], expected_layout[32];
    if (!layout || layout->schema_version != 1 || !layout->compiler_probed ||
        layout->selector_ordinal != selector || selector < 0 || selector >= 64 ||
        layout->marshal_size > MUTATION_MAX_MARSHAL_SIZE ||
        layout->parameter_count > ATFIELD_MUTATION_MAX_PARAMS ||
        (layout->parameter_count && !layout->parameters) ||
        !digest_valid(layout->bundle_manifest_sha256) ||
        !digest_valid(layout->marshal_layout_sha256) ||
        !digest_valid(layout->edl_abi_sha256) ||
        digest_to_bytes(layout->bundle_manifest_sha256, layout_bundle) ||
        digest_to_bytes(layout->marshal_layout_sha256, layout_sha) ||
        digest_to_bytes(layout->edl_abi_sha256, abi_sha)) return 0;
    (void)abi_sha;
    if (state && state->configured &&
        (digest_to_bytes(state->bundle_manifest_sha256, expected_bundle) != 0 ||
         digest_to_bytes(state->marshal_layout_sha256, expected_layout) != 0 ||
         !bytes_equal(layout_bundle, expected_bundle, 32) ||
         !bytes_equal(layout_sha, expected_layout, 32))) return 0;
    if (!param_sources_valid(layout)) return 0;

    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (p->parameter_index != i || p->direction > ATFIELD_MUTATION_DIR_INOUT ||
            !category_byte_valid(p->type_category) ||
            !signedness_byte_valid((uint8_t)p->signedness) ||
            !type_kind_byte_valid(p->type_kind) ||
            !checked_range(p->ms_offset, p->ms_size, layout->marshal_size)) return 0;
        if (p->is_pointer) {
            if (p->ms_size != sizeof(void *) ||
                !(p->pointer_depth == 1 || (p->pointer_depth == 0 && p->array_decay)) ||
                p->type_category != ATFIELD_MUTATION_CAT_POINTER) return 0;
        } else if (p->pointer_depth || p->type_category == ATFIELD_MUTATION_CAT_POINTER ||
                   p->array_decay) return 0;
        if (p->element_size > UINT32_MAX ||
            (p->element_type_category && !category_byte_valid(p->element_type_category)) ||
            !signedness_byte_valid((uint8_t)p->element_signedness) ||
            (p->element_type_kind && !type_kind_byte_valid(p->element_type_kind)) ||
            (p->element_size && (!p->element_type_category || !p->element_type_kind))) return 0;
        for (size_t j = 0; j < i; j++) {
            const atfield_mutation_param_layout_t *q = &layout->parameters[j];
            if (ranges_overlap(p->ms_offset, p->ms_size, q->ms_offset, q->ms_size)) return 0;
        }
    }
    if (layout->has_retval) {
        if (!category_byte_valid(layout->retval_type_category) ||
            !signedness_byte_valid((uint8_t)layout->retval_signedness) ||
            !type_kind_byte_valid(layout->retval_type_kind) ||
            !checked_range(layout->retval_offset, layout->retval_size, layout->marshal_size)) return 0;
        for (size_t i = 0; i < layout->parameter_count; i++) {
            const atfield_mutation_param_layout_t *p = &layout->parameters[i];
            if (ranges_overlap(layout->retval_offset, layout->retval_size, p->ms_offset, p->ms_size)) return 0;
        }
    } else if (layout->retval_offset || layout->retval_size ||
               layout->retval_type_category || layout->retval_signedness ||
               layout->retval_type_kind) return 0;
    if (!layout->marshal_size && (layout->parameter_count || layout->has_retval)) return 0;
    return 1;
}

/* Projection v1 contains no strings: all offsets and scalar classifications come from Bundle. */
void atfield_marshal_spec_init(atfield_marshal_spec_t *spec) {
    if (spec) memset(spec, 0, sizeof(*spec));
}

static int projection_error(atfield_marshal_spec_t *spec, const char *reason) {
    if (spec) copy_text(spec->error, sizeof(spec->error), reason);
    return -1;
}

static int projection_parse(
    atfield_marshal_spec_t *spec,
    const uint8_t *bytes,
    size_t length,
    const char *bundle_sha,
    const char *layout_sha,
    const char *abi_sha)
{
    static const uint8_t magic[8] = {'A','T','F','M','A','R',0,0};
    uint8_t want_bundle[32], want_layout[32], want_abi[32];
    if (!digest_valid(bundle_sha) || !digest_valid(layout_sha) || !digest_valid(abi_sha) ||
        digest_to_bytes(bundle_sha, want_bundle) || digest_to_bytes(layout_sha, want_layout) ||
        digest_to_bytes(abi_sha, want_abi))
        return projection_error(spec, "marshal_digest_binding_invalid");
    if (!bytes || length < ATFIELD_MARSHAL_HEADER_BYTES ||
        length > ATFIELD_MARSHAL_MAX_SPEC_BYTES)
        return projection_error(spec, "marshal_projection_size_invalid");
    if (memcmp(bytes, magic, sizeof(magic)) != 0 ||
        read_le16(bytes + 8) != 1 ||
        read_le16(bytes + 10) != ATFIELD_MARSHAL_HEADER_BYTES ||
        read_le32(bytes + 12) != length ||
        read_le32(bytes + 20) != 0)
        return projection_error(spec, "marshal_projection_header_invalid");
    const uint32_t ecall_count = read_le32(bytes + 16);
    if (ecall_count == 0 || ecall_count > ATFIELD_MARSHAL_MAX_ECALLS)
        return projection_error(spec, "marshal_projection_ecall_count_invalid");
    if (!bytes_equal(bytes + 24, want_bundle, 32) ||
        !bytes_equal(bytes + 56, want_layout, 32) ||
        !bytes_equal(bytes + 88, want_abi, 32))
        return projection_error(spec, "abi_digest_mismatch");

    copy_text(spec->bundle_manifest_sha256, sizeof(spec->bundle_manifest_sha256), bundle_sha);
    copy_text(spec->marshal_layout_sha256, sizeof(spec->marshal_layout_sha256), layout_sha);
    copy_text(spec->edl_abi_sha256, sizeof(spec->edl_abi_sha256), abi_sha);
    size_t at = ATFIELD_MARSHAL_HEADER_BYTES;
    int previous_ordinal = -1;

    for (uint32_t ei = 0; ei < ecall_count; ei++) {
        if (length - at < ATFIELD_MARSHAL_ECALL_HEADER_BYTES)
            return projection_error(spec, "marshal_ecall_truncated");
        const uint8_t *ep = bytes + at;
        const uint32_t record_len = read_le32(ep);
        const uint32_t ordinal = read_le32(ep + 4);
        const uint32_t ms_size = read_le32(ep + 8);
        const uint16_t param_count = read_le16(ep + 12);
        const uint16_t flags = read_le16(ep + 14);
        const uint32_t ret_offset = read_le32(ep + 16);
        const uint16_t ret_size = read_le16(ep + 20);
        const uint8_t ret_category = ep[22];
        const uint8_t ret_signed = ep[23];
        const uint8_t ret_kind = ep[24];
        const uint8_t reserved_byte = ep[25];
        const uint16_t reserved_word = read_le16(ep + 26);
        if (record_len < ATFIELD_MARSHAL_ECALL_HEADER_BYTES ||
            record_len > length - at || ordinal >= 64 ||
            (int)ordinal <= previous_ordinal || ms_size > MUTATION_MAX_MARSHAL_SIZE ||
            param_count > ATFIELD_MUTATION_MAX_PARAMS ||
            (flags & ~(MARSHAL_ECALL_REPLAY_SUPPORTED | MARSHAL_ECALL_HAS_RETVAL)) ||
            reserved_byte || reserved_word)
            return projection_error(spec, "marshal_ecall_header_invalid");
        const int has_retval = (flags & MARSHAL_ECALL_HAS_RETVAL) != 0;
        if (has_retval) {
            if (!category_byte_valid(ret_category) || !signedness_byte_valid(ret_signed) ||
                !type_kind_byte_valid(ret_kind) || !checked_range(ret_offset, ret_size, ms_size))
                return projection_error(spec, "marshal_retval_invalid");
        } else if (ret_offset || ret_size || ret_category || ret_signed || ret_kind) {
            return projection_error(spec, "marshal_void_retval_not_zero");
        }

        atfield_mutation_layout_t *layout = &spec->ecalls[ei];
        memset(layout, 0, sizeof(*layout));
        layout->schema_version = 1;
        layout->compiler_probed = 1;
        layout->selector_ordinal = (int)ordinal;
        layout->marshal_size = ms_size;
        layout->bundle_manifest_sha256 = spec->bundle_manifest_sha256;
        layout->marshal_layout_sha256 = spec->marshal_layout_sha256;
        layout->edl_abi_sha256 = spec->edl_abi_sha256;
        layout->parameter_count = param_count;
        layout->parameters = spec->parameters[ei];
        layout->replay_supported = (flags & MARSHAL_ECALL_REPLAY_SUPPORTED) != 0;
        layout->has_retval = has_retval;
        layout->retval_offset = ret_offset;
        layout->retval_size = ret_size;
        layout->retval_type_category = ret_category;
        layout->retval_signedness = ret_signed == 255 ? -1 : (int8_t)ret_signed;
        layout->retval_type_kind = ret_kind;

        size_t cursor = at + ATFIELD_MARSHAL_ECALL_HEADER_BYTES;
        for (uint16_t pi = 0; pi < param_count; pi++) {
            if (cursor > at + record_len ||
                at + record_len - cursor < ATFIELD_MARSHAL_PARAM_HEADER_BYTES)
                return projection_error(spec, "marshal_param_truncated");
            const uint8_t *pp = bytes + cursor;
            atfield_mutation_param_layout_t *p = &spec->parameters[ei][pi];
            const uint16_t param_index = read_le16(pp);
            const uint16_t pflags = read_le16(pp + 2);
            p->parameter_index = param_index;
            p->is_pointer = (pflags & MARSHAL_PARAM_POINTER) != 0;
            p->array_decay = (pflags & MARSHAL_PARAM_ARRAY_DECAY) != 0;
            p->replay_supported = (pflags & MARSHAL_PARAM_REPLAY_SUPPORTED) != 0;
            p->scalar_mutation_supported = (pflags & MARSHAL_PARAM_SCALAR_MUTATION_SUPPORTED) != 0;
            p->is_user_check = (pflags & MARSHAL_PARAM_USER_CHECK) != 0;
            p->is_string = (pflags & MARSHAL_PARAM_STRING) != 0;
            p->is_wstring = (pflags & MARSHAL_PARAM_WSTRING) != 0;
            p->ms_offset = read_le32(pp + 4);
            p->ms_size = read_le32(pp + 8);
            p->element_size = read_le32(pp + 12);
            p->direction = pp[16];
            p->type_category = pp[17];
            p->signedness = pp[18] == 255 ? -1 : (int8_t)pp[18];
            p->type_kind = pp[19];
            p->pointer_depth = pp[20];
            p->element_type_category = pp[21];
            p->element_signedness = pp[22] == 255 ? -1 : (int8_t)pp[22];
            p->element_type_kind = pp[23];
            p->size_source = pp[24];
            p->count_source = pp[25];
            p->size_parameter_index = read_le16(pp + 26);
            p->count_parameter_index = read_le16(pp + 28);
            const uint16_t reserved = read_le16(pp + 30);
            p->size_literal = read_le64(pp + 32);
            p->count_literal = read_le64(pp + 40);
            p->fixed_array_element_count = read_le64(pp + 48);
            if ((pflags & ~UINT16_C(0x007f)) || reserved || param_index != pi ||
                pp[16] > ATFIELD_MUTATION_DIR_INOUT ||
                !category_byte_valid(pp[17]) || !signedness_byte_valid(pp[18]) ||
                !type_kind_byte_valid(pp[19]) ||
                !(pp[21] == 0 || category_byte_valid(pp[21])) ||
                !signedness_byte_valid(pp[22]) ||
                !(pp[23] == 0 || type_kind_byte_valid(pp[23])) ||
                !source_byte_valid(pp[24]) || !source_byte_valid(pp[25]))
                return projection_error(spec, "marshal_param_header_invalid");
            cursor += ATFIELD_MARSHAL_PARAM_HEADER_BYTES;
        }
        if (cursor != at + record_len)
            return projection_error(spec, "marshal_ecall_record_length_invalid");
        if (!descriptor_valid(NULL, layout, (int)ordinal))
            return projection_error(spec, "marshal_projection_layout_invalid");
        previous_ordinal = (int)ordinal;
        at += record_len;
    }
    if (at != length) return projection_error(spec, "marshal_projection_trailing_bytes");
    spec->ecall_count = ecall_count;
    spec->loaded = 1;
    return 0;
}

int atfield_marshal_spec_load(
    atfield_marshal_spec_t *spec,
    const char *path,
    const char *bundle_manifest_sha256,
    const char *marshal_layout_sha256,
    const char *edl_abi_sha256)
{
    if (!spec) return -1;
    atfield_marshal_spec_init(spec);
    uint8_t *bytes = NULL;
    size_t length = 0;
    int file_rc = read_bounded_file(path, ATFIELD_MARSHAL_MAX_SPEC_BYTES, &bytes, &length);
    if (file_rc != 0)
        return projection_error(spec, file_rc == -2 ? "marshal_projection_too_large" : "marshal_projection_read_failed");
    const int rc = projection_parse(spec, bytes, length, bundle_manifest_sha256,
                                    marshal_layout_sha256, edl_abi_sha256);
    free(bytes);
    return rc;
}

const atfield_mutation_layout_t *atfield_marshal_spec_get(
    const atfield_marshal_spec_t *spec,
    int selector_ordinal)
{
    if (!spec || !spec->loaded || selector_ordinal < 0) return NULL;
    for (size_t i = 0; i < spec->ecall_count; i++)
        if (spec->ecalls[i].selector_ordinal == selector_ordinal) return &spec->ecalls[i];
    return NULL;
}

const char *atfield_marshal_spec_error(const atfield_marshal_spec_t *spec) {
    return spec ? spec->error : "marshal_spec_missing";
}

static int scalar_bits_canonical(uint8_t kind, uint8_t width, uint64_t bits) {
    return value_kind_width_canonical(kind, width, bits);
}

void atfield_mutation_init_disabled(atfield_mutation_state_t *state) {
    if (state) memset(state, 0, sizeof(*state));
}

static int mutation_parse_error(atfield_mutation_state_t *state, const char *reason) {
    mutation_invalid(state, reason);
    return -1;
}

int atfield_mutation_load_spec_bytes(
    atfield_mutation_state_t *state,
    const uint8_t *bytes,
    size_t length,
    const char *bundle_manifest_sha256,
    const char *marshal_layout_sha256)
{
    static const uint8_t magic[8] = {'A','T','F','M','U','T',0,0};
    uint8_t expected_bundle[32], expected_layout[32];
    if (!state) return -1;
    atfield_mutation_init_disabled(state);
    state->configured = 1;
    if (!digest_valid(bundle_manifest_sha256) || !digest_valid(marshal_layout_sha256) ||
        digest_to_bytes(bundle_manifest_sha256, expected_bundle) ||
        digest_to_bytes(marshal_layout_sha256, expected_layout))
        return mutation_parse_error(state, "bundle_layout_binding_missing");
    if (!bytes || length < ATFIELD_MUTATION_HEADER_BYTES ||
        length > ATFIELD_MUTATION_MAX_SPEC_BYTES)
        return mutation_parse_error(state, "spec_size_invalid");
    if (memcmp(bytes, magic, sizeof(magic)) != 0 ||
        read_le16(bytes + 8) != ATFIELD_MUTATION_SPEC_VERSION ||
        read_le16(bytes + 10) != ATFIELD_MUTATION_HEADER_BYTES ||
        read_le32(bytes + 12) != length ||
        read_le32(bytes + 16) != 1 ||
        read_le32(bytes + 20) != 0)
        return mutation_parse_error(state, "spec_header_invalid");
    if (!bytes_equal(bytes + 24, expected_bundle, 32) ||
        !bytes_equal(bytes + 56, expected_layout, 32))
        return mutation_parse_error(state, "abi_digest_mismatch");

    const size_t rule_at = ATFIELD_MUTATION_HEADER_BYTES;
    if (length - rule_at != ATFIELD_MUTATION_RULE_HEADER_BYTES +
                            ATFIELD_MUTATION_SCALAR_TLV_BYTES)
        return mutation_parse_error(state, "spec_rule_length_invalid");
    const uint32_t rule_len = read_le32(bytes + rule_at);
    const uint16_t rule_type = read_le16(bytes + rule_at + 4);
    const uint16_t rule_flags = read_le16(bytes + rule_at + 6);
    const uint32_t selector = read_le32(bytes + rule_at + 8);
    const uint64_t occurrence = read_le64(bytes + rule_at + 12);
    const uint16_t op_count = read_le16(bytes + rule_at + 20);
    const uint16_t rule_reserved = read_le16(bytes + rule_at + 22);
    const uint64_t target_gen = (rule_flags & 0x00ffu) ? (uint64_t)(rule_flags & 0x00ffu) : 1u;
    const uint8_t exec_mode = (uint8_t)((rule_flags >> 8) & 0x00ffu);
    if (rule_len != length - rule_at || rule_type != MUTATION_RULE_TYPE ||
        exec_mode > 4u || rule_reserved || selector >= 64 || op_count != 1)
        return mutation_parse_error(state, "spec_rule_invalid");

    const size_t op_at = rule_at + ATFIELD_MUTATION_RULE_HEADER_BYTES;
    const uint16_t op_type = read_le16(bytes + op_at);
    const uint16_t op_flags = read_le16(bytes + op_at + 2);
    const uint32_t op_len = read_le32(bytes + op_at + 4);
    const uint32_t parameter_index = read_le32(bytes + op_at + 8);
    if (op_len != ATFIELD_MUTATION_SCALAR_TLV_BYTES)
        return mutation_parse_error(state, "spec_operation_invalid");

    atfield_mutation_scalar_op_t parsed_op;
    memset(&parsed_op, 0, sizeof(parsed_op));
    parsed_op.op_type = op_type;
    parsed_op.sub_op = op_flags;
    parsed_op.parameter_index = parameter_index;

    if (op_type == ATFIELD_MUTATION_OP_REPLACE_SCALAR) {
        const uint8_t kind = bytes[op_at + 12];
        const uint8_t width = bytes[op_at + 13];
        const uint16_t op_reserved = read_le16(bytes + op_at + 14);
        const uint64_t expected_bits = read_le64(bytes + op_at + 16);
        const uint64_t replacement_bits = read_le64(bytes + op_at + 24);
        if (op_flags || op_reserved || parameter_index >= ATFIELD_MUTATION_MAX_PARAMS)
            return mutation_parse_error(state, "spec_operation_invalid");
        if (!scalar_bits_canonical(kind, width, expected_bits) ||
            !scalar_bits_canonical(kind, width, replacement_bits))
            return mutation_parse_error(state, "spec_width_overflow");
        parsed_op.kind = kind;
        parsed_op.width_bytes = width;
        parsed_op.expected_bits = expected_bits;
        parsed_op.replacement_bits = replacement_bits;
    } else if (op_type == ATFIELD_MUTATION_OP_MUTATE_BUFFER) {
        const uint32_t byte_offset = read_le32(bytes + op_at + 12);
        const uint32_t slice_length = read_le32(bytes + op_at + 16);
        const uint32_t expected_u32 = read_le32(bytes + op_at + 20);
        const uint64_t replacement_bits = read_le64(bytes + op_at + 24);
        if (parameter_index >= ATFIELD_MUTATION_MAX_PARAMS ||
            (op_flags != ATFIELD_BUF_OP_XOR_BYTE &&
             op_flags != ATFIELD_BUF_OP_FILL_SLICE &&
             op_flags != ATFIELD_BUF_OP_WRITE_LE))
            return mutation_parse_error(state, "spec_operation_invalid");
        uint8_t width = 1;
        if (op_flags == ATFIELD_BUF_OP_XOR_BYTE) {
            if (slice_length != 1 || expected_u32 > 0xffu || replacement_bits > 0xffu)
                return mutation_parse_error(state, "spec_width_overflow");
        } else if (op_flags == ATFIELD_BUF_OP_FILL_SLICE) {
            if (slice_length < 1 || slice_length > 65536u || expected_u32 > 0xffu || replacement_bits > 0xffu)
                return mutation_parse_error(state, "spec_width_overflow");
        } else {
            if (slice_length != 1 && slice_length != 2 && slice_length != 4 && slice_length != 8)
                return mutation_parse_error(state, "spec_width_overflow");
            width = (uint8_t)slice_length;
            if (!scalar_bits_canonical(ATFIELD_MUTATION_SCALAR_UNSIGNED, width, replacement_bits))
                return mutation_parse_error(state, "spec_width_overflow");
        }
        parsed_op.kind = ATFIELD_MUTATION_SCALAR_UNSIGNED;
        parsed_op.width_bytes = width;
        parsed_op.byte_offset = byte_offset;
        parsed_op.slice_length = slice_length;
        parsed_op.expected_bits = (uint64_t)expected_u32;
        parsed_op.replacement_bits = replacement_bits;
    } else if (op_type == ATFIELD_MUTATION_OP_EXTEND_HISTORY) {
        const uint32_t byte_offset = read_le32(bytes + op_at + 12);
        const uint64_t expected_bits = read_le64(bytes + op_at + 16);
        const uint64_t replacement_bits = read_le64(bytes + op_at + 24);
        if (op_flags < 1 || op_flags > 4 ||
            (parameter_index != UINT32_MAX && parameter_index >= ATFIELD_MUTATION_MAX_PARAMS) ||
            expected_bits > 0xffu || replacement_bits > 0xffu)
            return mutation_parse_error(state, "spec_operation_invalid");
        parsed_op.kind = ATFIELD_MUTATION_SCALAR_UNSIGNED;
        parsed_op.width_bytes = 1;
        parsed_op.byte_offset = byte_offset;
        parsed_op.slice_length = 1;
        parsed_op.expected_bits = expected_bits;
        parsed_op.replacement_bits = replacement_bits;
    } else {
        return mutation_parse_error(state, "spec_operation_invalid");
    }

    state->rule.target_generation = target_gen;
    state->rule.exec_mode = (op_type == ATFIELD_MUTATION_OP_EXTEND_HISTORY && exec_mode == 0)
        ? (uint8_t)op_flags
        : exec_mode;
    state->rule.selector_ordinal = (int)selector;
    state->rule.occurrence = occurrence;
    state->rule.operation_count = 1;
    state->rule.operations[0] = parsed_op;
    copy_text(state->bundle_manifest_sha256, sizeof(state->bundle_manifest_sha256), bundle_manifest_sha256);
    copy_text(state->marshal_layout_sha256, sizeof(state->marshal_layout_sha256), marshal_layout_sha256);
    state->enabled = 1;
    return 0;
}

int atfield_mutation_load_spec(
    atfield_mutation_state_t *state,
    const char *path,
    const char *bundle_manifest_sha256,
    const char *marshal_layout_sha256)
{
    if (!state) return -1;
    atfield_mutation_init_disabled(state);
    if (!path || !*path) return 0;
    state->configured = 1;
    uint8_t *bytes = NULL;
    size_t length = 0;
    int rc = read_bounded_file(path, ATFIELD_MUTATION_MAX_SPEC_BYTES, &bytes, &length);
    if (rc != 0) return mutation_parse_error(state, rc == -2 ? "mutation_spec_too_large" : "mutation_spec_read_failed");
    rc = atfield_mutation_load_spec_bytes(state, bytes, length,
                                          bundle_manifest_sha256, marshal_layout_sha256);
    free(bytes);
    return rc;
}

int atfield_mutation_bind_run(atfield_mutation_state_t *state, uint64_t eid, uint64_t generation) {
    if (!state || !state->configured || !state->enabled) return state && state->invalid ? -1 : 0;
    if (!eid || !generation) {
        mutation_invalid(state, "invalid_run_identity");
        return -1;
    }
    if (!state->run_bound) {
        state->bound_eid = eid;
        state->bound_generation = generation;
        state->owner_thread = pthread_self();
        state->run_bound = 1;
        return 0;
    }
    if (state->bound_eid != eid) mutation_invalid(state, "multiple_eids");
    else if (state->bound_generation != generation) mutation_invalid(state, "multiple_generations");
    else if (!pthread_equal(state->owner_thread, pthread_self())) mutation_invalid(state, "multiple_threads");
    return state->invalid ? -1 : 0;
}

static void set_mutation_reason(
    atfield_mutation_state_t *state,
    atfield_call_capture_record_t *record,
    const char *reason)
{
    mutation_invalid(state, reason);
    copy_text(record->mutation.reason, sizeof(record->mutation.reason), reason);
}

static int format_hex_bits(uint8_t width, uint64_t bits, char out[19]) {
    if (width != 1 && width != 2 && width != 4 && width != 8) return -1;
    const unsigned int nbits = (unsigned int)width * 8u;
    const uint64_t mask = nbits == 64 ? UINT64_MAX : ((UINT64_C(1) << nbits) - 1u);
    const int n = snprintf(out, 19, "0x%0*" PRIx64, (int)width * 2, bits & mask);
    return n == (int)(2 + width * 2) ? 0 : -1;
}

static int reason_code_safe(const char *s) {
    if (!s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (!( (*p >= 'a' && *p <= 'z') || *p == '_' || (*p >= '0' && *p <= '9') )) return 0;
    return 1;
}

static int run_id_safe(const char *s) {
    if (!s || !*s || strlen(s) > MUTATION_MAX_RUN_ID) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' )) return 0;
    return 1;
}

int atfield_call_capture_open(
    atfield_call_capture_t *capture,
    const char *path,
    const char *run_id,
    const char *bundle_manifest_sha256,
    const char *marshal_layout_sha256)
{
    if (!capture) return -1;
    memset(capture, 0, sizeof(*capture));
    if (!path || !*path) return 0;
    if (!run_id_safe(run_id) || !digest_valid(bundle_manifest_sha256) ||
        !digest_valid(marshal_layout_sha256)) {
        capture_failed(capture, "capture_binding_invalid");
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        capture_failed(capture, "capture_open_failed");
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(path);
        capture_failed(capture, "capture_open_failed");
        return -1;
    }
    capture->fp = fp;
    capture->enabled = 1;
    copy_text(capture->run_id, sizeof(capture->run_id), run_id);
    copy_text(capture->bundle_manifest_sha256, sizeof(capture->bundle_manifest_sha256), bundle_manifest_sha256);
    copy_text(capture->marshal_layout_sha256, sizeof(capture->marshal_layout_sha256), marshal_layout_sha256);
    if (fprintf(fp, "{\"type\":\"capture_start\",\"schema\":\"%s\",\"run_id\":\"%s\","
                "\"bundle_manifest_sha256\":\"%s\",\"marshal_layout_sha256\":\"%s\"}\n",
                ATFIELD_CALL_CAPTURE_SCHEMA, capture->run_id,
                capture->bundle_manifest_sha256, capture->marshal_layout_sha256) < 0 ||
        fflush(fp) != 0) {
        capture_failed(capture, "capture_start_write_failed");
        fclose(fp);
        capture->fp = NULL;
        capture->enabled = 0;
        return -1;
    }
    return 0;
}

static int write_scalar_json(
    FILE *fp,
    const atfield_mutation_value_t *value,
    int include_index)
{
    char bits[19];
    if (!fp || !value || format_hex_bits(value->width_bytes, value->before_bits, bits) != 0) return -1;
    if (include_index) {
        return fprintf(fp, "{\"param_index\":%u,\"width_bytes\":%u,\"signedness\":\"%s\",\"bits\":\"%s\"}",
            value->parameter_index, value->width_bytes,
            value->kind == ATFIELD_MUTATION_SCALAR_SIGNED ? "signed" : "unsigned", bits) < 0 ? -1 : 0;
    }
    return fprintf(fp, "{\"width_bytes\":%u,\"signedness\":\"%s\",\"bits\":\"%s\"}",
        value->width_bytes,
        value->kind == ATFIELD_MUTATION_SCALAR_SIGNED ? "signed" : "unsigned", bits) < 0 ? -1 : 0;
}

int atfield_call_capture_write_ecall(
    atfield_call_capture_t *capture,
    const atfield_call_capture_record_t *record,
    int transport_status)
{
    if (!capture || !capture->enabled) return 0;
    if (!capture->fp || !record || !record->initialized || capture->failed) {
        capture_failed(capture, "capture_record_invalid");
        return -1;
    }
    FILE *fp = capture->fp;
    if (fprintf(fp, "{\"type\":\"ecall\",\"schema\":\"%s\",\"generation\":%" PRIu64
        ",\"call_seq\":%" PRIu64 ",\"selector_ordinal\":%d,\"selector_seq\":%" PRIu64
        ",\"transport_status\":%d,\"scalar_inputs\":[",
        ATFIELD_CALL_CAPTURE_SCHEMA, record->generation, record->call_seq,
        record->selector_ordinal, record->selector_seq, transport_status) < 0) goto failed;
    for (size_t i = 0; i < record->input_count; i++) {
        if ((i && fputc(',', fp) == EOF) || write_scalar_json(fp, &record->inputs[i], 1) != 0) goto failed;
    }
    if (fputs("],\"retval\":", fp) < 0) goto failed;
    if (record->has_retval) {
        if (write_scalar_json(fp, &record->retval, 0) != 0) goto failed;
    } else if (fputs("null", fp) < 0) goto failed;
    if (fputs(",\"scalar_outputs\":[", fp) < 0) goto failed;
    for (size_t i = 0; i < record->output_count; i++) {
        if ((i && fputc(',', fp) == EOF) || write_scalar_json(fp, &record->outputs[i], 1) != 0) goto failed;
    }
    if (fputs("],\"mutation\":", fp) < 0) goto failed;
    if (record->mutation.target) {
        char expected[19], observed[19], replacement[19];
        if (format_hex_bits(record->mutation.width_bytes, record->mutation.expected_bits, expected) != 0 ||
            format_hex_bits(record->mutation.width_bytes, record->mutation.replacement_bits, replacement) != 0 ||
            !reason_code_safe(record->mutation.reason)) goto failed;
        const char *sign = record->mutation.kind == ATFIELD_MUTATION_SCALAR_SIGNED ? "signed" : "unsigned";
        if (fprintf(fp, "{\"param_index\":%u,\"width_bytes\":%u,\"signedness\":\"%s\","
                    "\"expected_bits\":\"%s\",\"observed_bits\":",
                    record->mutation.parameter_index, record->mutation.width_bytes,
                    sign, expected) < 0) goto failed;
        if (record->mutation.has_observed) {
            if (format_hex_bits(record->mutation.width_bytes, record->mutation.observed_bits, observed) != 0 ||
                fprintf(fp, "\"%s\"", observed) < 0) goto failed;
        } else if (fputs("null", fp) < 0) goto failed;
        if (fprintf(fp, ",\"replacement_bits\":\"%s\",\"applied\":%s,\"reason\":",
                    replacement, record->mutation.applied ? "true" : "false") < 0) goto failed;
        if (record->mutation.reason[0]) {
            if (fprintf(fp, "\"%s\"}", record->mutation.reason) < 0) goto failed;
        } else if (fputs("null}", fp) < 0) goto failed;
    } else if (fputs("null", fp) < 0) goto failed;
    const char *cap_buf_env = getenv("ATFIELD_CAPTURE_BUFFERS");
    if (cap_buf_env && strcmp(cap_buf_env, "1") == 0) {
        if (fputs(",\"buffer_inputs\":[", fp) < 0) goto failed;
        for (size_t bi = 0; bi < record->buffer_input_count; bi++) {
            const atfield_captured_buffer_t *b = &record->buffer_inputs[bi];
            const char *dir_s = b->direction == ATFIELD_MUTATION_DIR_INOUT ? "inout" : "in";
            if ((bi && fputc(',', fp) == EOF) ||
                fprintf(fp, "{\"param_index\":%u,\"direction\":\"%s\",\"is_string\":%s,"
                            "\"element_size\":%u,\"byte_length\":%u,\"fnv1a64\":\"0x%016" PRIx64 "\","
                            "\"prefix_hex\":\"",
                        b->parameter_index, dir_s, b->is_string ? "true" : "false",
                        b->element_size, b->byte_length, b->fnv1a64) < 0) goto failed;
            for (uint32_t k = 0; k < b->prefix_length; k++) {
                if (fprintf(fp, "%02x", b->prefix_bytes[k]) < 0) goto failed;
            }
            if (fputs("\"}", fp) < 0) goto failed;
        }
        if (fputc(']', fp) == EOF) goto failed;
    }
    if (fputs("}\n", fp) < 0 || fflush(fp) != 0) goto failed;
    capture->ecall_count++;
    if (record->mutation.target) capture->mutation_target_count++;
    if (record->mutation.matched) capture->mutation_matched_count++;
    if (record->mutation.applied) capture->mutation_applied_count++;
    return 0;
failed:
    capture_failed(capture, "capture_ecall_write_failed");
    return -1;
}

int atfield_call_capture_close(
    atfield_call_capture_t *capture,
    atfield_mutation_state_t *mutation)
{
    int rc = 0;
    if (mutation && atfield_mutation_finalize(mutation) != 0) rc = -1;
    if (!capture) return rc;
    if (!capture->enabled) return capture->failed ? -1 : rc;
    if (capture->fp) {
        if (fflush(capture->fp) != 0) {
            capture_failed(capture, "capture_flush_failed");
            rc = -1;
        }
        if (fclose(capture->fp) != 0) {
            capture_failed(capture, "capture_close_failed");
            rc = -1;
        }
        capture->fp = NULL;
    }
    capture->enabled = 0;
    return capture->failed ? -1 : rc;
}

static void capture_add_value(
    atfield_mutation_value_t *value,
    uint32_t index,
    uint8_t storage,
    uint8_t kind,
    uint8_t width,
    uint64_t bits)
{
    memset(value, 0, sizeof(*value));
    value->parameter_index = index;
    value->storage = storage;
    value->kind = kind;
    value->width_bytes = width;
    value->before_bits = normalize_bits(kind, width, bits);
}

static uint64_t read_scalar(const void *base, size_t offset, uint8_t width) {
    uint64_t bits = 0;
    memcpy(&bits, (const uint8_t *)base + offset, width);
    return bits;
}

static void write_scalar(void *base, size_t offset, uint8_t width, uint64_t bits) {
    memcpy((uint8_t *)base + offset, &bits, width);
}

static int read_bound_source(
    const atfield_mutation_layout_t *layout,
    const atfield_mutation_param_layout_t *param,
    const void *marshal,
    int is_size,
    uint64_t *value)
{
    const uint8_t source = is_size ? param->size_source : param->count_source;
    const uint64_t literal = is_size ? param->size_literal : param->count_literal;
    const uint16_t source_index = is_size ? param->size_parameter_index : param->count_parameter_index;
    if (source == ATFIELD_MUTATION_BOUND_SOURCE_LITERAL) {
        *value = literal;
        return 0;
    }
    if (source != ATFIELD_MUTATION_BOUND_SOURCE_PARAM) return -1;
    const atfield_mutation_param_layout_t *bound_param = find_param(layout, source_index);
    uint8_t kind = 0, width = 0;
    if (!bound_param || bound_param->is_pointer ||
        bound_param->direction == ATFIELD_MUTATION_DIR_OUT ||
        scalar_kind_from_layout(bound_param->type_kind, bound_param->type_category,
            bound_param->signedness, bound_param->ms_size, &kind, &width) != 0) return -1;
    const uint64_t bits = normalize_bits(kind, width, read_scalar(marshal, bound_param->ms_offset, width));
    if (kind == ATFIELD_MUTATION_SCALAR_UNSIGNED) {
        *value = bits;
        return 0;
    }
    int64_t signed_value = 0;
    memcpy(&signed_value, &bits, sizeof(signed_value));
    if (signed_value < 0) return -1;
    *value = (uint64_t)signed_value;
    return 0;
}

static int pointer_one_level(const atfield_mutation_param_layout_t *param) {
    return param && (param->pointer_depth == 1 ||
        (param->pointer_depth == 0 && param->array_decay));
}

static int pointer_bytes(
    const atfield_mutation_layout_t *layout,
    const atfield_mutation_param_layout_t *param,
    const void *marshal,
    size_t *result)
{
    *result = 0;
    if (!param->is_pointer || param->is_user_check || !pointer_one_level(param) ||
        !param->replay_supported || param->is_wstring) return -1;
    if (param->is_string) {
        if (param->direction != ATFIELD_MUTATION_DIR_IN ||
            param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
            param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
            param->fixed_array_element_count) return -1;
        return 1;
    }
    if ((param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE &&
         param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_LITERAL &&
         param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_PARAM) ||
        (param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE &&
         param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_LITERAL &&
         param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_PARAM)) return -1;
    if (param->fixed_array_element_count &&
        (param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
         param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE)) return -1;

    uint64_t size_value = 0, count_value = 0;
    int have_size = param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE;
    int have_count = param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE;
    if (param->fixed_array_element_count) {
        have_count = 1;
        count_value = param->fixed_array_element_count;
    } else {
        if (have_size && read_bound_source(layout, param, marshal, 1, &size_value) != 0) return -1;
        if (have_count && read_bound_source(layout, param, marshal, 0, &count_value) != 0) return -1;
    }

    if (!param->element_size) {
        /* The compiler projection marks void* as an unsized element; [size] is byte-precise. */
        if (have_size && !have_count && !param->fixed_array_element_count) {
            if (!size_value) return -1;
            if (size_value > SIZE_MAX) return -1;
            *result = (size_t)size_value;
            return 0;
        }
        return -1;
    }

    if (!have_size) size_value = param->element_size;
    if (!have_count) count_value = 1;
    if (count_value && size_value > UINT64_MAX / count_value) return -1;
    const uint64_t total = size_value * count_value;
    const int is_sized_record = (param->element_type_category == ATFIELD_MUTATION_CAT_RECORD &&
                                 have_size && !have_count);
    if ((!is_sized_record && total % param->element_size != 0) || total > SIZE_MAX) return -1;
    *result = (size_t)total;
    return 0;
}

static int mutation_pointer_supported(
    const atfield_mutation_layout_t *layout,
    const atfield_mutation_param_layout_t *param)
{
    if (!param->replay_supported || param->is_user_check ||
        !pointer_one_level(param) || param->is_wstring) return 0;
    if (param->is_string) return param->direction == ATFIELD_MUTATION_DIR_IN &&
        param->size_source == ATFIELD_MUTATION_BOUND_SOURCE_NONE &&
        param->count_source == ATFIELD_MUTATION_BOUND_SOURCE_NONE &&
        param->fixed_array_element_count == 0;
    if (param->fixed_array_element_count &&
        (param->size_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
         param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE)) return 0;
    if (!param->element_size) {
        if (param->size_source == ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
            param->count_source != ATFIELD_MUTATION_BOUND_SOURCE_NONE ||
            param->fixed_array_element_count) return 0;
    } else if (param->element_type_kind != ATFIELD_MUTATION_TYPE_BUILTIN &&
               param->element_type_kind != ATFIELD_MUTATION_TYPE_ENUM &&
               param->element_type_kind != ATFIELD_MUTATION_TYPE_STRUCT &&
               param->element_type_kind != ATFIELD_MUTATION_TYPE_UNION &&
               !(param->element_type_kind == ATFIELD_MUTATION_TYPE_NAMED &&
                 (param->element_type_category == ATFIELD_MUTATION_CAT_INTEGER ||
                  param->element_type_category == ATFIELD_MUTATION_CAT_CHARACTER ||
                  param->element_type_category == ATFIELD_MUTATION_CAT_ENUM ||
                  param->element_type_category == ATFIELD_MUTATION_CAT_BOOLEAN ||
                  param->element_type_category == ATFIELD_MUTATION_CAT_RECORD ||
                  param->element_type_category == ATFIELD_MUTATION_CAT_UNION))) return 0;

    const uint16_t source_params[] = {param->size_parameter_index, param->count_parameter_index};
    const uint8_t sources[] = {param->size_source, param->count_source};
    for (size_t i = 0; i < 2; i++) {
        if (sources[i] != ATFIELD_MUTATION_BOUND_SOURCE_PARAM) continue;
        {
            const atfield_mutation_param_layout_t *bound = find_param(layout, source_params[i]);
            uint8_t kind = 0, width = 0;
            if (!bound || bound->is_pointer || bound->direction == ATFIELD_MUTATION_DIR_OUT ||
                scalar_kind_from_layout(bound->type_kind, bound->type_category,
                    bound->signedness, bound->ms_size, &kind, &width) != 0) return 0;
        }
    }
    return 1;
}

static int pointer_capacity_check(
    const atfield_mutation_layout_t *layout,
    const void *original_ms,
    const void *working_ms)
{
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (!p->is_pointer) continue;
        if (!mutation_pointer_supported(layout, p)) return -1;
        void *orig = NULL, *work = NULL;
        memcpy(&orig, (const uint8_t *)original_ms + p->ms_offset, sizeof(orig));
        memcpy(&work, (const uint8_t *)working_ms + p->ms_offset, sizeof(work));
        if (orig != work) return -1;
        size_t old_bytes = 0, new_bytes = 0;
        const int old_rc = pointer_bytes(layout, p, original_ms, &old_bytes);
        const int new_rc = pointer_bytes(layout, p, working_ms, &new_bytes);
        if (old_rc == 1 && new_rc == 1) continue;
        if (old_rc || new_rc) return -1;
        if ((!orig && old_bytes) || (!work && new_bytes)) return -1;
        if ((orig && old_bytes > UINTPTR_MAX - (uintptr_t)orig) ||
            (work && new_bytes > UINTPTR_MAX - (uintptr_t)work)) return -1;
        if (new_bytes > old_bytes) return -2;
    }
    return 0;
}

static int mutation_layout_supported(
    const atfield_mutation_layout_t *layout,
    const atfield_mutation_scalar_op_t *op)
{
    if (!layout->replay_supported || !op) return -1;
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (p->is_pointer) {
            if (!mutation_pointer_supported(layout, p)) return -1;
        } else {
            uint8_t kind = 0, width = 0;
            if (!p->replay_supported ||
                scalar_kind_from_layout(p->type_kind, p->type_category, p->signedness,
                    p->ms_size, &kind, &width) != 0) return -1;
        }
    }
    if (layout->has_retval) {
        uint8_t kind = 0, width = 0;
        if (scalar_kind_from_layout(layout->retval_type_kind, layout->retval_type_category,
                layout->retval_signedness, layout->retval_size, &kind, &width) != 0) return -1;
    }
    const atfield_mutation_param_layout_t *p = find_param(layout, op->parameter_index);
    uint8_t kind = 0, width = 0;
    if (!p || p->is_pointer || !p->scalar_mutation_supported ||
        p->direction == ATFIELD_MUTATION_DIR_OUT ||
        scalar_kind_from_layout(p->type_kind, p->type_category, p->signedness,
                                p->ms_size, &kind, &width) != 0 ||
        kind != op->kind || width != op->width_bytes) return -1;
    if (p->type_category == ATFIELD_MUTATION_CAT_BOOLEAN &&
        ((op->expected_bits & 1u) != op->expected_bits ||
         (op->replacement_bits & 1u) != op->replacement_bits)) return -1;
    return 0;
}

static uint64_t fnv1a64_bytes(const uint8_t *data, size_t len) {
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= UINT64_C(0x100000001b3);
    }
    return h;
}

static int resolve_buffer_extent(
    const atfield_mutation_layout_t *layout,
    const atfield_mutation_param_layout_t *p,
    const void *marshal,
    const uint8_t **out_ptr,
    size_t *out_bytes)
{
    *out_ptr = NULL;
    *out_bytes = 0;
    if (!p || !p->is_pointer || !mutation_pointer_supported(layout, p)) return -1;
    const uint8_t *ptr = NULL;
    memcpy(&ptr, (const uint8_t *)marshal + p->ms_offset, sizeof(ptr));
    if (!ptr) return 0;
    size_t bytes = 0;
    if (p->is_string) {
        size_t slen = strnlen((const char *)ptr, 65536u);
        if (slen >= 65536u) return -1;
        bytes = slen + 1u;
    } else {
        if (pointer_bytes(layout, p, marshal, &bytes) != 0) return -1;
    }
    if (bytes > (1024u * 1024u)) return -1;
    *out_ptr = ptr;
    *out_bytes = bytes;
    return 0;
}

static void capture_inputs(
    atfield_call_capture_record_t *record,
    const atfield_mutation_layout_t *layout,
    const void *marshal)
{
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (p->direction == ATFIELD_MUTATION_DIR_OUT) continue;
        if (!p->is_pointer) {
            uint8_t kind = 0, width = 0;
            if (scalar_kind_from_layout(p->type_kind, p->type_category, p->signedness,
                                        p->ms_size, &kind, &width) != 0) continue;
            atfield_mutation_value_t *v = &record->inputs[record->input_count++];
            capture_add_value(v, p->parameter_index, ATFIELD_MUTATION_STORAGE_DIRECT,
                              kind, width, read_scalar(marshal, p->ms_offset, width));
            continue;
        }
        const uint8_t *ptr = NULL;
        size_t bytes = 0;
        if (resolve_buffer_extent(layout, p, marshal, &ptr, &bytes) == 0 && ptr && bytes > 0) {
            atfield_captured_buffer_t *b = &record->buffer_inputs[record->buffer_input_count++];
            memset(b, 0, sizeof(*b));
            b->parameter_index = p->parameter_index;
            b->direction = p->direction;
            b->is_string = p->is_string;
            b->element_size = (uint32_t)(p->element_size ? p->element_size : 1u);
            b->byte_length = (uint32_t)bytes;
            b->prefix_length = bytes < ATFIELD_CAPTURE_MAX_BUF_PREFIX_BYTES
                ? (uint32_t)bytes
                : ATFIELD_CAPTURE_MAX_BUF_PREFIX_BYTES;
            b->fnv1a64 = fnv1a64_bytes(ptr, bytes);
            memcpy(b->prefix_bytes, ptr, b->prefix_length);
        }
    }
}

static void capture_outputs(
    atfield_call_capture_record_t *record,
    const atfield_mutation_layout_t *layout,
    const void *marshal)
{
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (p->direction != ATFIELD_MUTATION_DIR_OUT &&
            p->direction != ATFIELD_MUTATION_DIR_INOUT) continue;
        if (!p->is_pointer) {
            uint8_t kind = 0, width = 0;
            if (scalar_kind_from_layout(p->type_kind, p->type_category, p->signedness,
                    p->ms_size, &kind, &width) != 0) continue;
            atfield_mutation_value_t *v = &record->outputs[record->output_count++];
            capture_add_value(v, p->parameter_index, ATFIELD_MUTATION_STORAGE_DIRECT,
                kind, width, read_scalar(marshal, p->ms_offset, width));
            continue;
        }
        if (!p->replay_supported || p->is_user_check || p->is_string || p->is_wstring) continue;
        uint8_t kind = 0, width = 0;
        if (scalar_kind_from_layout(p->element_type_kind, p->element_type_category,
                p->element_signedness, p->element_size, &kind, &width) != 0) continue;
        size_t bytes = 0;
        if (pointer_bytes(layout, p, marshal, &bytes) != 0 || bytes != width) continue;
        void *ptr = NULL;
        memcpy(&ptr, (const uint8_t *)marshal + p->ms_offset, sizeof(ptr));
        if (!ptr) continue;
        atfield_mutation_value_t *v = &record->outputs[record->output_count++];
        capture_add_value(v, p->parameter_index, ATFIELD_MUTATION_STORAGE_POINTEE,
            kind, width, read_scalar(ptr, 0, width));
    }
    if (layout->has_retval) {
        uint8_t kind = 0, width = 0;
        if (scalar_kind_from_layout(layout->retval_type_kind, layout->retval_type_category,
                layout->retval_signedness, layout->retval_size, &kind, &width) == 0) {
            capture_add_value(&record->retval, UINT32_MAX, ATFIELD_MUTATION_STORAGE_DIRECT,
                kind, width, read_scalar(marshal, layout->retval_offset, width));
            record->has_retval = 1;
        }
    }
}

static void init_record(
    atfield_call_capture_record_t *record,
    uint64_t generation,
    uint64_t call_seq,
    int selector,
    uint64_t selector_seq,
    const atfield_mutation_layout_t *layout)
{
    memset(record, 0, sizeof(*record));
    record->initialized = 1;
    record->capture_complete = 1;
    record->generation = generation;
    record->call_seq = call_seq;
    record->selector_ordinal = selector;
    record->selector_seq = selector_seq;
    if (layout) {
        record->marshal_size = layout->marshal_size;
        if (digest_valid(layout->bundle_manifest_sha256))
            copy_text(record->bundle_manifest_sha256, sizeof(record->bundle_manifest_sha256), layout->bundle_manifest_sha256);
        if (digest_valid(layout->marshal_layout_sha256))
            copy_text(record->marshal_layout_sha256, sizeof(record->marshal_layout_sha256), layout->marshal_layout_sha256);
    }
}

static int mutation_guard(
    atfield_mutation_state_t *state,
    uint64_t eid,
    uint64_t generation,
    atfield_call_capture_record_t *record)
{
    if (!state->run_bound) { set_mutation_reason(state, record, "run_not_bound"); return -1; }
    if (state->bound_eid != eid) { set_mutation_reason(state, record, "multiple_eids"); return -1; }
    if (state->bound_generation != generation) { set_mutation_reason(state, record, "multiple_generations"); return -1; }
    if (!pthread_equal(state->owner_thread, pthread_self())) {
        set_mutation_reason(state, record, "multiple_threads");
        return -1;
    }
    return 0;
}

int atfield_mutation_before_ecall(
    atfield_mutation_state_t *state,
    uint64_t eid,
    uint64_t generation,
    uint64_t call_seq,
    int selector_ordinal,
    uint64_t selector_seq,
    const atfield_mutation_layout_t *layout,
    const void *original_ms,
    void *working_ms,
    size_t working_capacity,
    atfield_call_capture_record_t *record)
{
    if (!record) return -1;
    init_record(record, generation, call_seq, selector_ordinal, selector_seq, layout);
    if (!descriptor_valid(state, layout, selector_ordinal)) {
        record->capture_complete = 0;
        if (state && state->enabled) {
            record->mutation.target = selector_ordinal == state->rule.selector_ordinal &&
                selector_seq == state->rule.occurrence;
            if (record->mutation.target) {
                record->mutation.matched = 1;
                record->mutation.parameter_index = state->rule.operations[0].parameter_index;
                record->mutation.kind = state->rule.operations[0].kind;
                record->mutation.width_bytes = state->rule.operations[0].width_bytes;
                record->mutation.expected_bits = state->rule.operations[0].expected_bits;
                record->mutation.replacement_bits = state->rule.operations[0].replacement_bits;
            }
            set_mutation_reason(state, record, "marshal_layout_invalid");
            return -1;
        }
        return 0;
    }
    record->layout_validated = 1;
    record->has_marshaled_block = layout->marshal_size != 0;
    if (layout->marshal_size && !original_ms) {
        record->capture_complete = 0;
        if (state && state->enabled) {
            set_mutation_reason(state, record, "marshal_block_missing");
            return -1;
        }
        return 0;
    }
    if (layout->marshal_size) capture_inputs(record, layout, original_ms);

    if (!state || !state->configured || !state->enabled) {
        if (state && state->invalid) {
            /* An invalid configured candidate stays pass-through and produces no false target. */
        }
        return 0;
    }
    const uint64_t want_gen = state->rule.target_generation ? state->rule.target_generation : 1u;
    if (generation != want_gen) return 0;
    if (mutation_guard(state, eid, generation, record) != 0) return -1;

    const atfield_mutation_scalar_op_t *op = &state->rule.operations[0];
    if (selector_ordinal != state->rule.selector_ordinal ||
        selector_seq != state->rule.occurrence) return 0;
    record->mutation.target = 1;
    record->mutation.matched = 1;
    record->mutation.parameter_index = op->parameter_index == UINT32_MAX ? 0u : op->parameter_index;
    record->mutation.kind = op->kind;
    record->mutation.width_bytes = op->width_bytes ? op->width_bytes : 1u;
    record->mutation.expected_bits = op->expected_bits;
    record->mutation.replacement_bits = op->replacement_bits;

    if (state->rule.hit_count++) {
        set_mutation_reason(state, record, "duplicate_hit");
        return -1;
    }
    const uint16_t eff_op_type = op->op_type ? op->op_type : ATFIELD_MUTATION_OP_REPLACE_SCALAR;
    if (eff_op_type == ATFIELD_MUTATION_OP_REPLACE_SCALAR) {
        if (mutation_layout_supported(layout, op) != 0) {
            set_mutation_reason(state, record, "unsupported_mutation_layout");
            return -1;
        }
        const atfield_mutation_param_layout_t *param = find_param(layout, op->parameter_index);
        if (!param || !original_ms) {
            set_mutation_reason(state, record, "target_parameter_unavailable");
            return -1;
        }
        const uint64_t observed = normalize_bits(op->kind, op->width_bytes,
            read_scalar(original_ms, param->ms_offset, op->width_bytes));
        record->mutation.has_observed = 1;
        record->mutation.observed_bits = observed;
        if (observed != op->expected_bits) {
            set_mutation_reason(state, record, "expected_value_mismatch");
            return -1;
        }
        if (!working_ms || !layout->marshal_size || working_capacity < layout->marshal_size) {
            set_mutation_reason(state, record, "marshal_clone_unavailable");
            return -1;
        }
        memcpy(working_ms, original_ms, layout->marshal_size);
        write_scalar(working_ms, param->ms_offset, op->width_bytes, op->replacement_bits);
        int bound_rc = pointer_capacity_check(layout, original_ms, working_ms);
        if (bound_rc == -2) {
            set_mutation_reason(state, record, "pointer_bound_grew");
            return -1;
        }
        if (bound_rc != 0) {
            set_mutation_reason(state, record, "pointer_bound_unproven");
            return -1;
        }
        if (state->rule.exec_mode >= 1) {
            for (size_t i = 0; i < layout->parameter_count; i++) {
                const atfield_mutation_param_layout_t *p = &layout->parameters[i];
                if (!p->is_pointer) continue;
                const uint8_t *orig_ptr = NULL;
                size_t orig_b = 0;
                if (resolve_buffer_extent(layout, p, original_ms, &orig_ptr, &orig_b) != 0) {
                    set_mutation_reason(state, record, "pointer_bound_unproven");
                    return -1;
                }
                if (orig_ptr && orig_b > 0) {
                    void *clone = calloc(1, orig_b);
                    if (!clone) {
                        set_mutation_reason(state, record, "marshal_clone_unavailable");
                        return -1;
                    }
                    memcpy(clone, orig_ptr, orig_b);
                    state->rule.cloned_buffers[i] = clone;
                    state->rule.cloned_sizes[i] = orig_b;
                    state->rule.orig_ptrs[i] = (void *)orig_ptr;
                    memcpy((uint8_t *)working_ms + p->ms_offset, &clone, sizeof(clone));
                }
            }
        }
        for (size_t ii = 0; ii < record->input_count; ii++) {
            if (record->inputs[ii].parameter_index == op->parameter_index) {
                record->inputs[ii].before_bits = normalize_bits(op->kind, op->width_bytes, op->replacement_bits);
            }
        }
        state->rule.applied = 1;
        record->mutation.applied = 1;
        copy_text(record->mutation.reason, sizeof(record->mutation.reason), "applied");
        return 1;
    }

    if (!layout->replay_supported) {
        set_mutation_reason(state, record, "unsupported_mutation_layout");
        return -1;
    }
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (p->is_pointer && !mutation_pointer_supported(layout, p)) {
            set_mutation_reason(state, record, "unsupported_mutation_layout");
            return -1;
        }
    }
    if (eff_op_type == ATFIELD_MUTATION_OP_EXTEND_HISTORY && op->parameter_index == UINT32_MAX) {
        record->mutation.has_observed = 0;
        if (layout->marshal_size > 0) {
            if (!working_ms || !original_ms || working_capacity < layout->marshal_size) {
                set_mutation_reason(state, record, "marshal_clone_unavailable");
                return -1;
            }
            memcpy(working_ms, original_ms, layout->marshal_size);
            for (size_t i = 0; i < layout->parameter_count; i++) {
                const atfield_mutation_param_layout_t *p = &layout->parameters[i];
                if (!p->is_pointer) continue;
                const uint8_t *orig_ptr = NULL;
                size_t orig_b = 0;
                if (resolve_buffer_extent(layout, p, original_ms, &orig_ptr, &orig_b) != 0) {
                    set_mutation_reason(state, record, "pointer_bound_unproven");
                    return -1;
                }
                if (orig_ptr && orig_b > 0) {
                    void *clone = calloc(1, orig_b);
                    if (!clone) {
                        set_mutation_reason(state, record, "marshal_clone_unavailable");
                        return -1;
                    }
                    memcpy(clone, orig_ptr, orig_b);
                    state->rule.cloned_buffers[i] = clone;
                    state->rule.cloned_sizes[i] = orig_b;
                    state->rule.orig_ptrs[i] = (void *)orig_ptr;
                    memcpy((uint8_t *)working_ms + p->ms_offset, &clone, sizeof(clone));
                }
            }
        }
        state->rule.applied = 1;
        record->mutation.applied = 1;
        copy_text(record->mutation.reason, sizeof(record->mutation.reason), "applied");
        return layout->marshal_size > 0 ? 1 : 0;
    }

    const atfield_mutation_param_layout_t *param = find_param(layout, op->parameter_index);
    if (!param || !param->is_pointer || !original_ms ||
        (param->direction != ATFIELD_MUTATION_DIR_IN && param->direction != ATFIELD_MUTATION_DIR_INOUT)) {
        set_mutation_reason(state, record, "target_parameter_unavailable");
        return -1;
    }
    const uint8_t *target_orig_ptr = NULL;
    size_t target_bytes = 0;
    if (resolve_buffer_extent(layout, param, original_ms, &target_orig_ptr, &target_bytes) != 0 ||
        !target_orig_ptr || target_bytes == 0) {
        set_mutation_reason(state, record, "target_parameter_unavailable");
        return -1;
    }
    if (op->byte_offset >= target_bytes || op->slice_length < 1 ||
        op->byte_offset + op->slice_length > target_bytes) {
        set_mutation_reason(state, record, "buffer_offset_out_of_bounds");
        return -1;
    }
    const uint8_t obs_w = (eff_op_type == ATFIELD_MUTATION_OP_MUTATE_BUFFER &&
                           op->sub_op == ATFIELD_BUF_OP_WRITE_LE) ? op->width_bytes : 1u;
    const uint64_t observed = read_scalar(target_orig_ptr, op->byte_offset, obs_w);
    record->mutation.has_observed = 1;
    record->mutation.observed_bits = observed;
    uint64_t eff_replacement_bits = op->replacement_bits;
    if (observed != op->expected_bits) {
        if (eff_op_type != ATFIELD_MUTATION_OP_MUTATE_BUFFER) {
            set_mutation_reason(state, record, "expected_value_mismatch");
            return -1;
        }
        if (op->sub_op == ATFIELD_BUF_OP_XOR_BYTE) {
            uint8_t xor_mask = (uint8_t)((op->expected_bits ^ op->replacement_bits) & 0xffu);
            if (xor_mask == 0) xor_mask = 0x01u;
            eff_replacement_bits = (uint64_t)((observed ^ xor_mask) & 0xffu);
        }
    }
    if (!working_ms || !layout->marshal_size || working_capacity < layout->marshal_size) {
        set_mutation_reason(state, record, "marshal_clone_unavailable");
        return -1;
    }
    memcpy(working_ms, original_ms, layout->marshal_size);
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (!p->is_pointer) continue;
        if (state->rule.exec_mode == 0 && eff_op_type == ATFIELD_MUTATION_OP_MUTATE_BUFFER &&
            i != op->parameter_index) continue;
        const uint8_t *orig_ptr = NULL;
        size_t orig_b = 0;
        if (resolve_buffer_extent(layout, p, original_ms, &orig_ptr, &orig_b) != 0) {
            set_mutation_reason(state, record, "pointer_bound_unproven");
            return -1;
        }
        if (orig_ptr && orig_b > 0) {
            void *clone = calloc(1, orig_b);
            if (!clone) {
                set_mutation_reason(state, record, "marshal_clone_unavailable");
                return -1;
            }
            memcpy(clone, orig_ptr, orig_b);
            state->rule.cloned_buffers[i] = clone;
            state->rule.cloned_sizes[i] = orig_b;
            state->rule.orig_ptrs[i] = (void *)orig_ptr;
            memcpy((uint8_t *)working_ms + p->ms_offset, &clone, sizeof(clone));
        }
    }
    uint8_t *mut_buf = (uint8_t *)state->rule.cloned_buffers[op->parameter_index];
    if (!mut_buf) {
        set_mutation_reason(state, record, "marshal_clone_unavailable");
        return -1;
    }
    if (eff_op_type == ATFIELD_MUTATION_OP_EXTEND_HISTORY ||
        op->sub_op == ATFIELD_BUF_OP_XOR_BYTE) {
        mut_buf[op->byte_offset] = (uint8_t)(eff_replacement_bits & 0xffu);
    } else if (op->sub_op == ATFIELD_BUF_OP_FILL_SLICE) {
        memset(mut_buf + op->byte_offset, (int)(eff_replacement_bits & 0xffu), op->slice_length);
        if (param->is_string && target_bytes > 0) mut_buf[target_bytes - 1] = 0;
    } else if (op->sub_op == ATFIELD_BUF_OP_WRITE_LE) {
        write_scalar(mut_buf, op->byte_offset, op->width_bytes, eff_replacement_bits);
    }
    for (size_t bi = 0; bi < record->buffer_input_count; bi++) {
        if (record->buffer_inputs[bi].parameter_index == op->parameter_index) {
            record->buffer_inputs[bi].fnv1a64 = fnv1a64_bytes(mut_buf, target_bytes);
            memcpy(record->buffer_inputs[bi].prefix_bytes, mut_buf, record->buffer_inputs[bi].prefix_length);
        }
    }
    state->rule.applied = 1;
    record->mutation.applied = 1;
    copy_text(record->mutation.reason, sizeof(record->mutation.reason), "applied");
    return 1;
}

static void cleanup_cloned_buffers(
    atfield_mutation_state_t *state,
    const atfield_mutation_layout_t *layout,
    int copyback_inout)
{
    if (!state) return;
    for (size_t i = 0; i < ATFIELD_MUTATION_MAX_PARAMS; i++) {
        if (!state->rule.cloned_buffers[i]) continue;
        if (copyback_inout && layout && i < layout->parameter_count &&
            layout->parameters[i].direction == ATFIELD_MUTATION_DIR_INOUT &&
            state->rule.orig_ptrs[i] && state->rule.cloned_sizes[i] > 0) {
            memcpy(state->rule.orig_ptrs[i], state->rule.cloned_buffers[i], state->rule.cloned_sizes[i]);
        }
        free(state->rule.cloned_buffers[i]);
        state->rule.cloned_buffers[i] = NULL;
        state->rule.cloned_sizes[i] = 0;
        state->rule.orig_ptrs[i] = NULL;
    }
}

static void copyback_direct_outputs(
    const atfield_mutation_layout_t *layout,
    const void *completed_ms,
    void *original_ms)
{
    if (!completed_ms || !original_ms || completed_ms == original_ms) return;
    for (size_t i = 0; i < layout->parameter_count; i++) {
        const atfield_mutation_param_layout_t *p = &layout->parameters[i];
        if (p->is_pointer || (p->direction != ATFIELD_MUTATION_DIR_OUT &&
            p->direction != ATFIELD_MUTATION_DIR_INOUT)) continue;
        uint8_t kind = 0, width = 0;
        if (scalar_kind_from_layout(p->type_kind, p->type_category, p->signedness,
                p->ms_size, &kind, &width) == 0)
            memcpy((uint8_t *)original_ms + p->ms_offset,
                   (const uint8_t *)completed_ms + p->ms_offset, width);
    }
    if (layout->has_retval) {
        uint8_t kind = 0, width = 0;
        if (scalar_kind_from_layout(layout->retval_type_kind, layout->retval_type_category,
                layout->retval_signedness, layout->retval_size, &kind, &width) == 0)
            memcpy((uint8_t *)original_ms + layout->retval_offset,
                   (const uint8_t *)completed_ms + layout->retval_offset, width);
    }
}

int atfield_mutation_after_ecall(
    atfield_mutation_state_t *state,
    const atfield_mutation_layout_t *layout,
    const void *completed_ms,
    void *original_ms,
    atfield_call_capture_record_t *record)
{
    if (!record || !record->initialized || !record->layout_validated) {
        cleanup_cloned_buffers(state, layout, 0);
        return 0;
    }
    if (!descriptor_valid(state, layout, record->selector_ordinal) ||
        layout->marshal_size != record->marshal_size ||
        (layout->marshal_size && !completed_ms)) {
        cleanup_cloned_buffers(state, layout, 0);
        if (record->mutation.target && state && state->enabled)
            set_mutation_reason(state, record, "marshal_layout_changed_after_call");
        return -1;
    }
    if (!layout->marshal_size) {
        cleanup_cloned_buffers(state, layout, 0);
        return 0;
    }
    capture_outputs(record, layout, completed_ms);
    const int is_inplace = (!state || (state->rule.exec_mode == 0 &&
        state->rule.operations[0].op_type != ATFIELD_MUTATION_OP_EXTEND_HISTORY));
    if (record->mutation.applied && is_inplace) {
        copyback_direct_outputs(layout, completed_ms, original_ms);
    }
    cleanup_cloned_buffers(state, layout, record->mutation.applied && is_inplace);
    return 0;
}

int atfield_mutation_finalize(atfield_mutation_state_t *state) {
    if (!state) return -1;
    state->finalized = 1;
    if (!state->configured || !state->enabled) return state->invalid ? -1 : 0;
    if (state->rule.hit_count == 0) mutation_invalid(state, "target_occurrence_missed");
    else if (state->rule.hit_count != 1) mutation_invalid(state, "duplicate_hit");
    else if (!state->rule.applied && !state->invalid) mutation_invalid(state, "mutation_not_applied");
    return state->invalid ? -1 : 0;
}

int atfield_mutation_is_valid(const atfield_mutation_state_t *state) {
    return state && !state->invalid;
}

const char *atfield_mutation_invalid_reason(const atfield_mutation_state_t *state) {
    return state && state->invalid_reason[0] ? state->invalid_reason : "";
}
