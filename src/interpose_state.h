#ifndef ATFIELD_INTERPOSE_STATE_H
#define ATFIELD_INTERPOSE_STATE_H

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "libsgxstep/pt.h"
#include "kernel/sgxstep_ioctl.h"
#include "schema_mutator_abi.h"
#include "native_trace_state.h"

#define GATE_SHARED_VA 0x700000000000ULL
#define MAX_TRACKED_PAGES 16384
#define MAX_FIELD_OBS_PER_ECALL 128
#define MAX_CHUNKS_PER_OBS 16384
#define MAX_FAULT_EVENTS_PER_ECALL 512

typedef uint64_t sgx_enclave_id_t;
typedef int sgx_status_t;

typedef struct {
    volatile uint32_t host_gate;          /* 0x00 */
    volatile uint32_t gate_enable;        /* 0x04 */
    volatile uint64_t use_alt_rsp_in_s2;  /* 0x08 */
    volatile uint64_t saved_rsp;          /* 0x10 */
    volatile uint32_t encl_heartbeat;     /* 0x18 */
    volatile uint32_t reserved0;          /* 0x1c */
    volatile uint64_t active_field_id;    /* 0x20 */
    volatile uint64_t tsc_s2_start;       /* 0x28 */
    volatile uint64_t tsc_s2_end;         /* 0x30 */
    volatile uint64_t tsc_s3_start;       /* 0x38 */
    volatile uint64_t tsc_s3_end;         /* 0x40 */
    volatile uint64_t gateD_rsp;          /* 0x48 */
    volatile uint32_t current_stage;      /* 0x50: 0=S0, 1=S1, 2=S2, 3=S3, 4=POST */
    volatile uint32_t total_aex_count;    /* 0x54 */
    volatile uint32_t gate_ipi_aex_count; /* 0x58 */
    volatile uint32_t in_gate_spin;       /* 0x5c */
    uint8_t pad[0x100 - 0x60];
    uint64_t scratch_rax;                 /* 0x100 */
    uint64_t scratch_rcx;                 /* 0x108 */
    uint64_t scratch_rdx;                 /* 0x110 */
    uint64_t scratch_flags;               /* 0x118 */
} gate_shared_t;

typedef struct {
    uint32_t aex_seq;
    int page_idx;
    uint64_t page_rva;
    uint64_t encl_rip_rva;
    uint64_t effective_addr_rva;
    int ea_verified;
    uint32_t exitinfo;
    uint32_t active_flag;
    char stage[16];
    int pte_healed_observed;
    uint64_t aep_pte;
    uint64_t final_pte;
    char confirmed_access_kind[12];      /* "X", "R", "W" ONLY when EA/RIP verified, else "unknown" */
    char inferred_post_window_kind[24];  /* "W_inferred_post_d", "R_inferred_post_a", or "none" */
} fault_event_t;

typedef struct {
    uint64_t field_id;
    uint64_t tsc_s2;
    uint64_t tsc_s3;
    uint32_t gate_mask;                  /* bit 0..3 set when S0..S3 snapshots exist */
    uint64_t gateB_rsp_rva;
    uint64_t gateD_rsp_rva;
    uint32_t ipi_aex_verified_mask;
    uint32_t s3_active_aex_count;
    int heap_walk_truncated;
    int heap_pread_failures;
    uint64_t *s0_ad;
    uint64_t *s1_ad;
    uint64_t *s2_ad;
    uint64_t *s3_ad;
    uint64_t heap_lo_rva;
    uint64_t heap_hi_rva;
    int num_live_chunks;
    uint64_t chunk_spans[MAX_CHUNKS_PER_OBS][2];
} field_obs_t;

extern int fd_step;
int fd_self_mem = -1;
static int lock_fd = -1;
static int trace_fd = -1;
static FILE *trace_fp = NULL;
static pthread_mutex_t collector_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t phase_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reason_mutex = PTHREAD_MUTEX_INITIALIZER;
static int live_enclave = 0;
static sgx_enclave_id_t live_enclave_id = 0;
static int watcher_init_failed = 0;
static int gate_buffers_ready = 0;
static volatile int collector_disabled_after_fork = 0;
static int g_shared_owned = 0;
static uint64_t encl_base = 0;
static uint64_t encl_size = 0;
static uint64_t tcs_rva = 0;
static uint64_t ssa_rva = 0;
static uint64_t gm_rva = 0;
static uint64_t atfield_active_rva = 0;
static uint64_t pretouch_start_rva = 0;
static uint64_t pretouch_end_rva = 0;
static uint64_t gate_helper_start_rva = 0;
static uint64_t gate_helper_end_rva = 0;
static int gate_helper_range_configured = 0;
static uint64_t stack_lo_rva = 0;
static uint64_t stack_hi_rva = 0;

static volatile uint64_t *pte_slots[MAX_TRACKED_PAGES];
static uint64_t orig_ptes[MAX_TRACKED_PAGES];
static uint64_t page_rvas[MAX_TRACKED_PAGES];
static uint8_t page_is_pretouch[MAX_TRACKED_PAGES];
static uint8_t page_is_exec[MAX_TRACKED_PAGES];
static int num_pages = 0;
static int page_table_truncated = 0;

static gate_shared_t *g_shared = NULL;
static volatile uint8_t *ipi_dummy_page = NULL;
static int ipi_mask = 7;
static int use_4gate = 1;
static int encl_cpu = -1;
static int watch_cpu = -1;

static inline int atfield_parse_cpu_env(const char *raw) {
    if (!raw || !*raw) return -1;
    char *end = NULL;
    long val = strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || val < 0 || val >= CPU_SETSIZE) return -2;
    return (int)val;
}
static int allow_fast_forward = 0;

static volatile int watcher_ready __attribute__((aligned(4096))) = 0;
static volatile int watcher_stop __attribute__((aligned(4096))) = 0;
static pthread_t watcher_thread;
static int watcher_started = 0;

static int cur_obs_count = 0;
static int watcher_active_slot = -1;
static volatile uint32_t gate_a_ipi_aex_count = 0;
static volatile uint32_t gate_b_ipi_aex_count = 0;
static volatile uint32_t gate_c_ipi_aex_count = 0;
static volatile uint32_t unexpected_aex_count = 0;
static volatile uint32_t unexpected_stage_aex[5] = {0, 0, 0, 0, 0};
static volatile uint32_t in_aep_handler = 0;
static int obs_truncated = 0;
static field_obs_t cur_obs[MAX_FIELD_OBS_PER_ECALL];

static int syscall_error_count = 0;
static int ipi_flush_failure_count = 0;
static int mutation_oob_rejected_count = 0;
static char last_invalid_reason[128] = "";

static int strict_mode = 0;
static int strict_config_invalid = 0;
static uint8_t strict_selector_has_map[64];
static uint8_t strict_allowed_page[64][MAX_TRACKED_PAGES];
static volatile uint8_t strict_retracted[MAX_TRACKED_PAGES];
static int active_strict_selector = -1;

static int cur_fault_count = 0;
static int fault_events_truncated = 0;
static fault_event_t cur_faults[MAX_FAULT_EVENTS_PER_ECALL];

static ecall_schema_t g_ecall_schemas[MAX_SCHEMA_ECALLS];
static uint8_t g_has_ecall_schema[MAX_SCHEMA_ECALLS] = {0};
static typed_ms_snapshot_t g_state_snaps[MAX_SCHEMA_ECALLS];

static uint64_t call_seq = 0;
static uint64_t trace_merged_ad[4][MAX_TRACKED_PAGES];
static int selector_seq[64] = {0};
static uint64_t instance_generation = 0;
static int pending_concurrent_ecall = 0;
static int pending_concurrent_lifecycle = 0;
static int trace_io_failed = 0;
static int trace_started = 0;
static int trace_metadata_valid = 0;
#define MAX_TRACE_INCOMPLETE_REASONS 32
static int trace_reason_count = 0;
static char trace_reasons[MAX_TRACE_INCOMPLETE_REASONS][128];

static int trace_printf(const char *fmt, ...);
static int trace_write_json_string(const char *s);
static int trace_write_page_effect(uint64_t rva, int a, int d);

static volatile int in_measured_ecall = 0;
static int aep_hooked = 0;
static void *aep_trampoline_va = NULL;
static uint64_t aep_patch_va = 0;
static uint8_t aep_original_bytes[5];
static int aep_patch_saved = 0;
static uint64_t vdso_det_va_saved = 0;
static uint8_t vdso_det_original = 0;
static int vdso_det_saved = 0;
static uint64_t vdso_ptr_va_saved = 0;
static uint64_t vdso_ptr_original = 0;
static int vdso_ptr_saved = 0;

typedef struct {
    const void *data;
    size_t size;
} sgx_page_readiness_table_t;

typedef sgx_status_t (*real_create_fn_t)(const char *, int, void *, int *, sgx_enclave_id_t *, void *);
typedef sgx_status_t (*real_ecall_fn_t)(sgx_enclave_id_t, int, const void *, void *);
typedef sgx_status_t (*real_destroy_fn_t)(sgx_enclave_id_t);
typedef sgx_status_t (*set_ready_table_fn_t)(sgx_enclave_id_t, const sgx_page_readiness_table_t *);
typedef sgx_status_t (*set_ready_backend_fn_t)(sgx_enclave_id_t, uint32_t);

static real_create_fn_t real_sgx_create_enclave = NULL;
static real_ecall_fn_t real_sgx_ecall = NULL;
static real_destroy_fn_t real_sgx_destroy_enclave = NULL;
static int pure_prod_mode = 0;

static void dump_enclave_vmas_if_requested(void);
static void cleanup_interpose(void);

static void mark_invalid(const char *reason) {
    if (!reason || !*reason) return;
    pthread_mutex_lock(&reason_mutex);
    /* AEX event truncation is diagnostic loss; page effects and gate completeness are separate. */
    if (strcmp(reason, "fault_events_truncated") == 0) {
        pthread_mutex_unlock(&reason_mutex);
        return;
    }
    for (int i = 0; i < trace_reason_count; i++) {
        if (strcmp(trace_reasons[i], reason) == 0) {
            pthread_mutex_unlock(&reason_mutex);
            return;
        }
    }
    if (!last_invalid_reason[0]) {
        strncpy(last_invalid_reason, reason, sizeof(last_invalid_reason) - 1);
        last_invalid_reason[sizeof(last_invalid_reason) - 1] = '\0';
    }
    if (trace_reason_count < MAX_TRACE_INCOMPLETE_REASONS) {
        strncpy(trace_reasons[trace_reason_count], reason, sizeof(trace_reasons[trace_reason_count]) - 1);
        trace_reasons[trace_reason_count][sizeof(trace_reasons[trace_reason_count]) - 1] = '\0';
        trace_reason_count++;
    } else if (strcmp(trace_reasons[MAX_TRACE_INCOMPLETE_REASONS - 1], "incomplete_reason_list_truncated") != 0) {
        strncpy(trace_reasons[MAX_TRACE_INCOMPLETE_REASONS - 1], "incomplete_reason_list_truncated",
                sizeof(trace_reasons[MAX_TRACE_INCOMPLETE_REASONS - 1]) - 1);
    }
    pthread_mutex_unlock(&reason_mutex);
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        syscall_error_count++;
        mark_invalid("clock_gettime_failed");
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void checked_flush_tlb(uint64_t va) {
    invpg_t param = { .adrs = va };
    step_open();
    if (fd_step >= 0) (void)fcntl(fd_step, F_SETFD, FD_CLOEXEC);
    if (ioctl(fd_step, SGX_STEP_IOCTL_INVPG, &param) < 0) {
        syscall_error_count++;
        mark_invalid("ioctl_invpg_failed");
    }
}

static inline void clear_ad_only(void) {
    for (int i = 0; i < num_pages; i++) {
        uint64_t v = *pte_slots[i];
        if (v & (A_MASK | D_MASK)) {
            *pte_slots[i] = v & ~(A_MASK | D_MASK);
            checked_flush_tlb(encl_base + page_rvas[i]);
        }
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static inline void snapshot_ad(uint64_t *dst) {
    for (int i = 0; i < num_pages; i++) {
        dst[i] = *pte_slots[i] & (A_MASK | D_MASK);
    }
}

static const char *stage_name_from_code(uint32_t code, uint32_t active_val, uint64_t rip_rva) {
    if (use_4gate && g_shared && g_shared->gate_enable) {
        switch (code) {
            case 0: return "S0_BRIDGE";
            case 1: return "S1_ENTER";
            case 2: return "S2_PRETOUCH";
            case 3: return "S3_BODY";
            case 4: return "POST_FIELD";
            default: return "UNKNOWN";
        }
    }
    if (active_val != 0) {
        if (rip_rva >= pretouch_start_rva && rip_rva < pretouch_end_rva)
            return "S2_PRETOUCH";
        return "S3_BODY";
    }
    return "S0_OR_POST";
}

static void write_ad_json_array(FILE *out, const uint64_t *ad, int include_pretouch) {
    (void)out;
    if (!ad) {
        trace_printf("[]");
        return;
    }
    trace_printf("[");
    int first = 1;
    for (int i = 0; i < num_pages; i++) {
        if (!include_pretouch && page_is_pretouch[i]) continue;
        if (atfield_rva_excluded_by_gate_range(page_rvas[i], gate_helper_range_configured,
                                               gate_helper_start_rva, gate_helper_end_rva)) continue;
        int a = (ad[i] & A_MASK) != 0;
        int d = (ad[i] & D_MASK) != 0;
        if (a || d) {
            trace_printf("%s", first ? "" : ",");
            trace_write_page_effect(page_rvas[i], a, d);
            first = 0;
        }
    }
    trace_printf("]");
}

static sgx_status_t execute_one_measured_ecall(
    sgx_enclave_id_t eid, int index, const void *ocall_table, void *ms,
    const char *tag, int enable_gate_for_this_call);
static void dump_enclave_vmas_if_requested(void);
static void cleanup_interpose(void);

#endif /* ATFIELD_INTERPOSE_STATE_H */
