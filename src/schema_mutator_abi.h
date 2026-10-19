#ifndef ATFIELD_SCHEMA_MUTATOR_ABI_H
#define ATFIELD_SCHEMA_MUTATOR_ABI_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SCHEMA_ECALLS 32
#define MAX_SCHEMA_PARAMS 16

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
    uint8_t ms_bytes[256];
    void *orig_ptrs[MAX_SCHEMA_PARAMS];
    size_t byte_lens[MAX_SCHEMA_PARAMS];
    int32_t alias_of[MAX_SCHEMA_PARAMS]; /* -1 if primary owner, else index j < i */
    uint8_t *master_copy[MAX_SCHEMA_PARAMS];
    uint8_t *work_copy[MAX_SCHEMA_PARAMS];
} typed_ms_snapshot_t;

typedef struct {
    uint8_t has_retval;
    int64_t retval_i64;
} abi_outcome_t;

static inline int read_scalar_u64(const uint8_t *ms, size_t ms_size, uint32_t off, uint32_t sz, uint64_t *out) {
    if ((size_t)off + (size_t)sz > ms_size) return -ERANGE;
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
    if ((size_t)off + (size_t)sz > ms_size) return -ERANGE;
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
    if ((size_t)ps->ms_offset + (size_t)ps->ms_size > ms_size) return -ERANGE;
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
        *out_usable_mutation_len = slen; /* do not flip terminating NUL */
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

static inline int mutate_xor_bounded(
    uint8_t *ms_work,
    const uint8_t *ms_orig,
    size_t ms_size,
    const param_schema_t *ps,
    size_t byte_idx,
    uint8_t mask,
    void **out_temp_alloc
) {
    if (!ms_work || !ms_orig || !ps || !out_temp_alloc) return -EINVAL;
    *out_temp_alloc = NULL;
    if (!ps->is_pointer || (ps->direction != DIR_IN && ps->direction != DIR_INOUT)) {
        return -EINVAL;
    }
    size_t alloc_len = 0, usable_len = 0;
    int rc = compute_param_byte_len(ms_orig, ms_size, ps, &alloc_len, &usable_len);
    if (rc != 0) return rc;
    if (usable_len == 0 || byte_idx >= usable_len) {
        return -ERANGE;
    }
    void *orig_ptr = *(void *const *)(ms_orig + ps->ms_offset);
    if (!orig_ptr) return -ERANGE;
    uint8_t *clone = (uint8_t *)malloc(alloc_len);
    if (!clone) return -ENOMEM;
    memcpy(clone, orig_ptr, alloc_len);
    clone[byte_idx] ^= mask;
    memcpy(ms_work, ms_orig, ms_size);
    *(void **)(ms_work + ps->ms_offset) = clone;
    *out_temp_alloc = clone;
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
    if (!es->replay_supported || ms_size != es->ms_size || ms_size > sizeof(snap->ms_bytes)) {
        return -ENOTSUP;
    }
    for (uint32_t i = 0; i < es->num_params; i++) {
        if (!es->params[i].replay_supported || es->params[i].is_user_check) {
            return -ENOTSUP;
        }
    }
    snap->ms_size = (uint32_t)ms_size;
    memcpy(snap->ms_bytes, ms, ms_size);
    for (uint32_t i = 0; i < es->num_params; i++) {
        snap->alias_of[i] = -1;
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
        snap->byte_lens[i] = blen;
        if (!optr) continue;

        /* Check if optr aliases an earlier pointer parameter j < i */
        for (uint32_t j = 0; j < i; j++) {
            if (es->params[j].is_pointer && snap->orig_ptrs[j] == optr && snap->alias_of[j] == -1) {
                snap->alias_of[i] = (int32_t)j;
                if (blen > snap->byte_lens[j]) {
                    uint8_t *nm = (uint8_t *)realloc(snap->master_copy[j], blen ? blen : 1);
                    uint8_t *nw = (uint8_t *)realloc(snap->work_copy[j], blen ? blen : 1);
                    if (!nm || !nw) {
                        free_typed_snapshot(snap);
                        return -ENOMEM;
                    }
                    memcpy(nm, optr, blen);
                    memcpy(nw, optr, blen);
                    snap->master_copy[j] = nm;
                    snap->work_copy[j] = nw;
                    snap->byte_lens[j] = blen;
                }
                break;
            }
        }
        if (snap->alias_of[i] >= 0) continue;

        size_t alloc_sz = blen > 0 ? blen : 1;
        snap->master_copy[i] = (uint8_t *)calloc(1, alloc_sz);
        snap->work_copy[i] = (uint8_t *)calloc(1, alloc_sz);
        if (!snap->master_copy[i] || !snap->work_copy[i]) {
            free_typed_snapshot(snap);
            return -ENOMEM;
        }
        if (blen > 0) {
            memcpy(snap->master_copy[i], optr, blen);
            memcpy(snap->work_copy[i], optr, blen);
        }
    }
    snap->valid = 1;
    return 0;
}

static inline int typed_restore_ms_for_replay(
    const typed_ms_snapshot_t *snap,
    const ecall_schema_t *es,
    uint8_t *ms_out
) {
    if (!snap || !snap->valid || !es || !ms_out) return -EINVAL;
    memcpy(ms_out, snap->ms_bytes, snap->ms_size);
    for (uint32_t i = 0; i < es->num_params; i++) {
        const param_schema_t *ps = &es->params[i];
        if (!ps->is_pointer) continue;
        if (!snap->orig_ptrs[i]) {
            *(void **)(ms_out + ps->ms_offset) = NULL;
            continue;
        }
        int32_t owner = (snap->alias_of[i] >= 0) ? snap->alias_of[i] : (int32_t)i;
        if (snap->byte_lens[owner] > 0) {
            memcpy(snap->work_copy[owner], snap->master_copy[owner], snap->byte_lens[owner]);
        }
        *(void **)(ms_out + ps->ms_offset) = snap->work_copy[owner];
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
