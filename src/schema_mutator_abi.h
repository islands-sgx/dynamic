#ifndef ATFIELD_SCHEMA_MUTATOR_ABI_H
#define ATFIELD_SCHEMA_MUTATOR_ABI_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SCHEMA_ECALLS 32
#define MAX_SCHEMA_PARAMS 16
#define MAX_MS_FRAME_BYTES 256

typedef enum {
    BOUND_NONE = 0,
    BOUND_COUNT = 1,
    BOUND_SIZE = 2
} bound_kind_t;

typedef enum {
    DIR_VAL = 0,
    DIR_IN = 1,
    DIR_OUT = 2,
    DIR_INOUT = 3
} param_dir_t;

typedef struct {
    char name[64];
    uint32_t ms_offset;
    uint32_t ms_size;
    uint32_t elem_size;
    uint8_t is_pointer;
    uint8_t ptr_depth;
    uint8_t direction;       /* param_dir_t */
    uint8_t is_string;
    uint8_t is_user_check;
    uint8_t bound_kind;      /* bound_kind_t */
    int32_t bound_ms_offset; /* -1 if none */
    uint32_t bound_ms_size;
    int64_t static_count;    /* -1 if none */
    uint8_t replay_supported;
} param_schema_t;

typedef struct {
    int32_t ecall_index;
    char name[64];
    uint32_t ms_size;
    uint8_t has_retval;
    uint32_t retval_offset;
    uint32_t retval_size;
    uint8_t replay_supported;
    uint32_t num_params;
    param_schema_t params[MAX_SCHEMA_PARAMS];
} ecall_schema_t;

typedef struct {
    uint8_t valid;
    uint32_t ms_size;
    uint8_t ms_bytes[MAX_MS_FRAME_BYTES];
    void *orig_ptrs[MAX_SCHEMA_PARAMS];
    uintptr_t region_base[MAX_SCHEMA_PARAMS];
    size_t region_len[MAX_SCHEMA_PARAMS];
    size_t param_byte_len[MAX_SCHEMA_PARAMS];
    size_t param_usable_len[MAX_SCHEMA_PARAMS];
    int32_t alias_owner[MAX_SCHEMA_PARAMS]; /* index j <= i of region owner */
    size_t alias_delta[MAX_SCHEMA_PARAMS];  /* byte offset within owner region */
    uint8_t *master_copy[MAX_SCHEMA_PARAMS];
    uint8_t *work_copy[MAX_SCHEMA_PARAMS];
    size_t work_alloc_len[MAX_SCHEMA_PARAMS];
} typed_ms_snapshot_t;

typedef struct {
    uint8_t has_retval;
    int64_t retval_i64;
} abi_outcome_t;

static inline int check_ms_frame_capacity(const ecall_schema_t *es, size_t ms_size) {
    if (!es) return -EINVAL;
    if (!es->replay_supported) return -ENOTSUP;
    if (ms_size != es->ms_size || ms_size > MAX_MS_FRAME_BYTES) return -EOVERFLOW;
    return 0;
}

static inline int read_scalar_u64(const uint8_t *ms, size_t ms_size, uint32_t off, uint32_t sz, uint64_t *out) {
    if (ms_size > MAX_MS_FRAME_BYTES || (size_t)off + (size_t)sz > ms_size) return -ERANGE;
    const uint8_t *p = ms + off;
    switch (sz) {
        case 1: *out = *(const uint8_t *)p; return 0;
        case 2: *out = *(const uint16_t *)p; return 0;
        case 4: *out = *(const uint32_t *)p; return 0;
        case 8: *out = *(const uint64_t *)p; return 0;
        default: return -EINVAL;
    }
}

static inline int write_scalar_u64(uint8_t *ms, size_t ms_size, uint32_t off, uint32_t sz, uint64_t val) {
    if (ms_size > MAX_MS_FRAME_BYTES || (size_t)off + (size_t)sz > ms_size) return -ERANGE;
    uint8_t *p = ms + off;
    switch (sz) {
        case 1: *(uint8_t *)p = (uint8_t)val; return 0;
        case 2: *(uint16_t *)p = (uint16_t)val; return 0;
        case 4: *(uint32_t *)p = (uint32_t)val; return 0;
        case 8: *(uint64_t *)p = (uint64_t)val; return 0;
        default: return -EINVAL;
    }
}

static inline int compute_param_byte_len(
    const uint8_t *ms,
    size_t ms_size,
    const param_schema_t *ps,
    size_t *out_byte_len,
    size_t *out_usable_mutation_len
) {
    if (!ms || !ps || !out_byte_len || !out_usable_mutation_len) return -EINVAL;
    if (ms_size > MAX_MS_FRAME_BYTES || (size_t)ps->ms_offset + (size_t)ps->ms_size > ms_size) return -ERANGE;
    if (!ps->is_pointer) {
        *out_byte_len = ps->ms_size;
        *out_usable_mutation_len = ps->ms_size;
        return 0;
    }
    if (!ps->replay_supported || ps->is_user_check || ps->ptr_depth > 1) {
        return -ENOTSUP;
    }
    if (ps->ms_size != sizeof(void *)) return -EINVAL;
    void *ptr = *(void *const *)(ms + ps->ms_offset);
    if (!ptr) {
        *out_byte_len = 0;
        *out_usable_mutation_len = 0;
        return 0;
    }
    if (ps->is_string) {
        size_t slen = strlen((const char *)ptr);
        if (slen == SIZE_MAX) return -EOVERFLOW;
        *out_byte_len = slen + 1;
        *out_usable_mutation_len = slen;
        return 0;
    }
    uint64_t count = 0;
    uint64_t elem_sz = ps->elem_size ? ps->elem_size : 1;
    if (ps->bound_kind == BOUND_COUNT || ps->bound_kind == BOUND_SIZE) {
        if (ps->bound_ms_offset >= 0) {
            int rc = read_scalar_u64(ms, ms_size, (uint32_t)ps->bound_ms_offset, ps->bound_ms_size, &count);
            if (rc != 0) return rc;
        } else if (ps->static_count >= 0) {
            count = (uint64_t)ps->static_count;
        } else {
            return -ENOTSUP;
        }
        if (ps->bound_kind == BOUND_SIZE) {
            elem_sz = 1;
        }
    } else if (ps->static_count >= 0) {
        count = (uint64_t)ps->static_count;
    } else {
        return -ENOTSUP;
    }
    size_t total = 0;
    if (__builtin_mul_overflow((size_t)count, (size_t)elem_sz, &total)) {
        return -EOVERFLOW;
    }
    *out_byte_len = total;
    *out_usable_mutation_len = total;
    return 0;
}

static inline void free_typed_snapshot(typed_ms_snapshot_t *snap) {
    if (!snap) return;
    for (int i = 0; i < MAX_SCHEMA_PARAMS; i++) {
        free(snap->master_copy[i]);
        free(snap->work_copy[i]);
        snap->master_copy[i] = NULL;
        snap->work_copy[i] = NULL;
    }
    memset(snap, 0, sizeof(*snap));
}

static inline int typed_snapshot_ms(
    const uint8_t *ms,
    size_t ms_size,
    const ecall_schema_t *es,
    typed_ms_snapshot_t *snap
) {
    if (!ms || !es || !snap) return -EINVAL;
    free_typed_snapshot(snap);
    int crc = check_ms_frame_capacity(es, ms_size);
    if (crc != 0) return crc;
    for (uint32_t i = 0; i < es->num_params; i++) {
        if (!es->params[i].replay_supported || es->params[i].is_user_check) {
            return -ENOTSUP;
        }
    }
    snap->ms_size = (uint32_t)ms_size;
    if (ms_size > 0) memcpy(snap->ms_bytes, ms, ms_size);

    /* Pass 1: compute byte_len and merge any identical or overlapping pointer spans [base, base + len) */
    for (uint32_t i = 0; i < es->num_params; i++) {
        snap->alias_owner[i] = -1;
        const param_schema_t *ps = &es->params[i];
        if (!ps->is_pointer) continue;
        size_t blen = 0, ulen = 0;
        int rc = compute_param_byte_len(ms, ms_size, ps, &blen, &ulen);
        if (rc != 0) {
            free_typed_snapshot(snap);
            return rc;
        }
        void *optr = *(void *const *)(ms + ps->ms_offset);
        snap->orig_ptrs[i] = optr;
        snap->param_byte_len[i] = blen;
        snap->param_usable_len[i] = ulen;
        if (!optr) continue;

        uintptr_t lo_i = (uintptr_t)optr;
        uintptr_t hi_i = lo_i + (blen > 0 ? blen : 1);
        int32_t found_owner = -1;
        for (uint32_t j = 0; j < i; j++) {
            if (!es->params[j].is_pointer || !snap->orig_ptrs[j] || snap->alias_owner[j] != (int32_t)j)
                continue;
            uintptr_t lo_j = snap->region_base[j];
            uintptr_t hi_j = lo_j + (snap->region_len[j] > 0 ? snap->region_len[j] : 1);
            /* Overlap or identical base (including p and p + 4!) */
            if (lo_i == lo_j || (lo_i < hi_j && lo_j < hi_i)) {
                found_owner = (int32_t)j;
                uintptr_t new_lo = lo_i < lo_j ? lo_i : lo_j;
                uintptr_t new_hi = hi_i > hi_j ? hi_i : hi_j;
                snap->region_base[j] = new_lo;
                if (snap->param_byte_len[j] == 0 && blen == 0) {
                    snap->region_len[j] = 0;
                } else {
                    snap->region_len[j] = (size_t)(new_hi - new_lo);
                }
                break;
            }
        }
        if (found_owner >= 0) {
            snap->alias_owner[i] = found_owner;
        } else {
            snap->alias_owner[i] = (int32_t)i;
            snap->region_base[i] = lo_i;
            snap->region_len[i] = blen;
        }
    }

    /* Pass 2: allocate master_copy and work_copy per region owner, and compute alias_delta[i] */
    for (uint32_t i = 0; i < es->num_params; i++) {
        if (!es->params[i].is_pointer || !snap->orig_ptrs[i]) continue;
        int32_t owner = snap->alias_owner[i];
        snap->alias_delta[i] = (size_t)((uintptr_t)snap->orig_ptrs[i] - snap->region_base[owner]);
        if (owner != (int32_t)i) continue;
        size_t rlen = snap->region_len[i];
        size_t alloc_sz = rlen > 0 ? rlen : 1;
        snap->master_copy[i] = (uint8_t *)calloc(1, alloc_sz);
        snap->work_copy[i] = (uint8_t *)calloc(1, alloc_sz);
        if (!snap->master_copy[i] || !snap->work_copy[i]) {
            free_typed_snapshot(snap);
            return -ENOMEM;
        }
        snap->work_alloc_len[i] = alloc_sz;
        if (rlen > 0) {
            memcpy(snap->master_copy[i], (const void *)snap->region_base[i], rlen);
            memcpy(snap->work_copy[i], (const void *)snap->region_base[i], rlen);
        }
    }
    snap->valid = 1;
    return 0;
}

static inline int typed_restore_ms_for_replay(
    typed_ms_snapshot_t *snap,
    const ecall_schema_t *es,
    uint8_t *ms_out
) {
    if (!snap || !snap->valid || !es || !ms_out) return -EINVAL;
    int crc = check_ms_frame_capacity(es, snap->ms_size);
    if (crc != 0) return crc;
    if (snap->ms_size > 0) memcpy(ms_out, snap->ms_bytes, snap->ms_size);
    for (uint32_t i = 0; i < es->num_params; i++) {
        if (!es->params[i].is_pointer || !snap->orig_ptrs[i]) continue;
        if (snap->alias_owner[i] == (int32_t)i && snap->region_len[i] > 0) {
            memcpy(snap->work_copy[i], snap->master_copy[i], snap->region_len[i]);
        }
    }
    for (uint32_t i = 0; i < es->num_params; i++) {
        const param_schema_t *ps = &es->params[i];
        if (!ps->is_pointer) continue;
        if (!snap->orig_ptrs[i]) {
            *(void **)(ms_out + ps->ms_offset) = NULL;
            continue;
        }
        int32_t owner = snap->alias_owner[i];
        *(void **)(ms_out + ps->ms_offset) = snap->work_copy[owner] + snap->alias_delta[i];
    }
    return 0;
}

/* Alias-preserving bounded XOR mutation inside a restored snapshot */
static inline int mutate_xor_in_snapshot(
    typed_ms_snapshot_t *snap,
    const ecall_schema_t *es,
    uint8_t *ms_work,
    uint32_t param_idx,
    size_t byte_idx,
    uint8_t mask
) {
    if (!snap || !snap->valid || !es || !ms_work || param_idx >= es->num_params) return -EINVAL;
    const param_schema_t *ps = &es->params[param_idx];
    if (!ps->is_pointer || (ps->direction != DIR_IN && ps->direction != DIR_INOUT)) return -EINVAL;
    if (!snap->orig_ptrs[param_idx]) return -ERANGE;
    size_t ulen = snap->param_usable_len[param_idx];
    if (ulen == 0 || byte_idx >= ulen) return -ERANGE;
    int rrc = typed_restore_ms_for_replay(snap, es, ms_work);
    if (rrc != 0) return rrc;
    int32_t owner = snap->alias_owner[param_idx];
    uint8_t *target_buf = snap->work_copy[owner] + snap->alias_delta[param_idx];
    target_buf[byte_idx] ^= mask;
    return 0;
}

/* Coordinated scalar mutation: updates scalar parameter AND reallocates all dependent [in]/[out]/[inout] buffers! */
static inline int mutate_scalar_and_rebind_buffers(
    typed_ms_snapshot_t *snap,
    const ecall_schema_t *es,
    uint8_t *ms_work,
    uint32_t scalar_param_idx,
    uint64_t new_val
) {
    if (!snap || !snap->valid || !es || !ms_work || scalar_param_idx >= es->num_params) return -EINVAL;
    const param_schema_t *ps_scalar = &es->params[scalar_param_idx];
    if (ps_scalar->is_pointer) return -EINVAL;
    int rrc = typed_restore_ms_for_replay(snap, es, ms_work);
    if (rrc != 0) return rrc;
    int wrc = write_scalar_u64(ms_work, es->ms_size, ps_scalar->ms_offset, ps_scalar->ms_size, new_val);
    if (wrc != 0) return wrc;

    /* Check every pointer parameter bound to this scalar's ms_offset and expand owner work_copy if needed */
    size_t needed_owner_len[MAX_SCHEMA_PARAMS] = {0};
    for (uint32_t i = 0; i < es->num_params; i++) {
        needed_owner_len[i] = snap->region_len[i];
    }
    for (uint32_t i = 0; i < es->num_params; i++) {
        const param_schema_t *ps = &es->params[i];
        if (!ps->is_pointer || !snap->orig_ptrs[i]) continue;
        if (ps->bound_ms_offset == (int32_t)ps_scalar->ms_offset) {
            size_t new_blen = 0, new_ulen = 0;
            int lrc = compute_param_byte_len(ms_work, es->ms_size, ps, &new_blen, &new_ulen);
            if (lrc != 0) return lrc;
            int32_t owner = snap->alias_owner[i];
            size_t req = snap->alias_delta[i] + new_blen;
            if (req > needed_owner_len[owner]) {
                needed_owner_len[owner] = req;
            }
        }
    }
    for (uint32_t owner = 0; owner < es->num_params; owner++) {
        if (!es->params[owner].is_pointer || !snap->orig_ptrs[owner] || snap->alias_owner[owner] != (int32_t)owner)
            continue;
        size_t req = needed_owner_len[owner];
        if (req > snap->work_alloc_len[owner]) {
            uint8_t *new_work = (uint8_t *)calloc(1, req);
            if (!new_work) return -ENOMEM;
            size_t orig_len = snap->region_len[owner];
            if (orig_len > 0) {
                /* Populate expanded buffer by repeating original seed bytes so [in] data remains valid */
                for (size_t b = 0; b < req; b++) {
                    new_work[b] = snap->master_copy[owner][b % orig_len];
                }
            }
            free(snap->work_copy[owner]);
            snap->work_copy[owner] = new_work;
            snap->work_alloc_len[owner] = req;
        }
    }
    for (uint32_t i = 0; i < es->num_params; i++) {
        const param_schema_t *ps = &es->params[i];
        if (!ps->is_pointer || !snap->orig_ptrs[i]) continue;
        int32_t owner = snap->alias_owner[i];
        *(void **)(ms_work + ps->ms_offset) = snap->work_copy[owner] + snap->alias_delta[i];
    }
    return 0;
}

static inline int read_ecall_abi_outcome(
    const uint8_t *ms,
    size_t ms_size,
    const ecall_schema_t *es,
    abi_outcome_t *out
) {
    if (!out) return -EINVAL;
    out->has_retval = 0;
    out->retval_i64 = 0;
    if (!ms || !es || !es->has_retval || es->retval_size == 0) {
        return 0;
    }
    uint64_t uval = 0;
    int rc = read_scalar_u64(ms, ms_size, es->retval_offset, es->retval_size, &uval);
    if (rc != 0) return rc;
    out->has_retval = 1;
    if (es->retval_size == 4) {
        out->retval_i64 = (int64_t)(int32_t)(uint32_t)uval;
    } else if (es->retval_size == 2) {
        out->retval_i64 = (int64_t)(int16_t)(uint16_t)uval;
    } else if (es->retval_size == 1) {
        out->retval_i64 = (int64_t)(int8_t)(uint8_t)uval;
    } else {
        out->retval_i64 = (int64_t)uval;
    }
    return 0;
}

#endif /* ATFIELD_SCHEMA_MUTATOR_ABI_H */
