#ifndef ATFIELD_NATIVE_TRACE_JSON_H
#define ATFIELD_NATIVE_TRACE_JSON_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

/* Write a JSON string value, escaping quotes, backslashes, and control bytes. */
static int atfield_json_write_string(FILE *out, const char *value) {
    if (!out) return -1;
    if (!value) value = "";
    if (fputc('"', out) == EOF) return -1;
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        const char *escape = NULL;
        switch (*p) {
            case '"': escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default: break;
        }
        if (escape) {
            for (const char *q = escape; *q; q++)
                if (fputc((unsigned char)*q, out) == EOF) return -1;
        } else if (*p < 0x20) {
            static const char hex[] = "0123456789abcdef";
            const char control_escape[] = {'\\', 'u', '0', '0', hex[*p >> 4], hex[*p & 0x0f]};
            for (size_t i = 0; i < sizeof(control_escape); i++)
                if (fputc((unsigned char)control_escape[i], out) == EOF) return -1;
        } else if (*p < 0x80) {
            if (fputc(*p, out) == EOF) return -1;
        } else {
            size_t width = 0;
            uint32_t codepoint = 0;
            uint32_t minimum = 0;
            if (*p >= 0xc2 && *p <= 0xdf) {
                width = 2; codepoint = *p & 0x1f; minimum = 0x80;
            } else if (*p >= 0xe0 && *p <= 0xef) {
                width = 3; codepoint = *p & 0x0f; minimum = 0x800;
            } else if (*p >= 0xf0 && *p <= 0xf4) {
                width = 4; codepoint = *p & 0x07; minimum = 0x10000;
            }
            int valid_utf8 = width != 0;
            for (size_t i = 1; valid_utf8 && i < width; i++) {
                if (p[i] == 0 || (p[i] & 0xc0) != 0x80) {
                    valid_utf8 = 0;
                } else {
                    codepoint = (codepoint << 6) | (p[i] & 0x3f);
                }
            }
            if (valid_utf8 && codepoint >= minimum && codepoint <= 0x10ffff &&
                !(codepoint >= 0xd800 && codepoint <= 0xdfff)) {
                for (size_t i = 0; i < width; i++)
                    if (fputc(p[i], out) == EOF) return -1;
                p += width - 1;
            } else {
                static const char hex[] = "0123456789abcdef";
                const char byte_escape[] = {'\\', 'u', '0', '0', hex[*p >> 4], hex[*p & 0x0f]};
                for (size_t i = 0; i < sizeof(byte_escape); i++)
                    if (fputc((unsigned char)byte_escape[i], out) == EOF) return -1;
            }
        }
    }
    return fputc('"', out) == EOF ? -1 : 0;
}

static int atfield_json_write_page_effect(FILE *out, uint64_t rva, int a, int d) {
    if (!out) return -1;
    if (fprintf(out, "{\"rva\":\"0x%" PRIx64 "\",\"a\":%s,\"d\":%s}",
                rva, a ? "true" : "false", d ? "true" : "false") < 0)
        return -1;
    return 0;
}

static const char *atfield_json_skip_space(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static int atfield_json_write_string_array(FILE *out, const char *json) {
    if (!out) return -1;
    if (!json) return fputs("[]", out) == EOF ? -1 : 0;

    const char *p = atfield_json_skip_space(json);
    if (*p != '[') return -1;
    p++;
    p = atfield_json_skip_space(p);
    if (*p == ']') {
        p++;
    } else {
        for (;;) {
            if (*p != '"') return -1;
            p++;
            for (;;) {
                const unsigned char c = (unsigned char)*p;
                if (c == '\0') return -1;
                if (c == '"') {
                    p++;
                    break;
                }
                if (c < 0x20) return -1;
                if (c != '\\') {
                    p++;
                    continue;
                }
                p++;
                if (*p == '\0') return -1;
                if (*p == '"' || *p == '\\' || *p == '/' || *p == 'b' ||
                    *p == 'f' || *p == 'n' || *p == 'r' || *p == 't') {
                    p++;
                    continue;
                }
                if (*p != 'u') return -1;
                p++;
                for (int i = 0; i < 4; i++) {
                    if (*p == '\0') return -1;
                    const char h = *p++;
                    if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                          (h >= 'A' && h <= 'F'))) return -1;
                }
            }
            p = atfield_json_skip_space(p);
            if (*p == ']') {
                p++;
                break;
            }
            if (*p != ',') return -1;
            p++;
            p = atfield_json_skip_space(p);
        }
    }
    p = atfield_json_skip_space(p);
    if (*p != '\0') return -1;
    return fputs(json, out) == EOF ? -1 : 0;
}

/* Diagnostic-only Gate C post-clear checkpoint. Sparse effects are raw A/D values;
 * omitted tracked pages are zero only when complete is true. */
static int atfield_json_write_gatec_postclear(FILE *out,
                                               const uint64_t *rvas,
                                               const uint64_t *ad,
                                               size_t page_count,
                                               size_t observation_count,
                                               size_t checkpoint_count,
                                               size_t checked_page_count,
                                               int complete,
                                               uint64_t a_mask,
                                               uint64_t d_mask) {
    if (!out || (page_count && (!rvas || !ad))) return -1;
    if (fprintf(out, "{\"page_size\":4096,\"checkpoint_scope\":\"ecall_field_or\","
                     "\"complete\":%s,\"observation_count\":%zu,"
                     "\"checkpoint_count\":%zu,\"checked_page_count_per_complete_checkpoint\":%zu,"
                     "\"nonzero_page_count\":",
                complete ? "true" : "false", observation_count, checkpoint_count,
                complete ? page_count : checked_page_count) < 0) return -1;
    size_t nonzero = 0;
    for (size_t i = 0; i < page_count; i++)
        if (ad[i] & (a_mask | d_mask)) nonzero++;
    if (fprintf(out, "%zu,\"page_effects\":[", nonzero) < 0) return -1;
    int first = 1;
    for (size_t i = 0; i < page_count; i++) {
        int a = (ad[i] & a_mask) != 0;
        int d = (ad[i] & d_mask) != 0;
        if (!a && !d) continue;
        if ((!first && fputc(',', out) == EOF) ||
            atfield_json_write_page_effect(out, rvas[i], a, d) != 0) return -1;
        first = 0;
    }
    return fputs("]}", out) == EOF ? -1 : 0;
}

#endif /* ATFIELD_NATIVE_TRACE_JSON_H */
