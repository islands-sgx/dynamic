#define _GNU_SOURCE
#include <dlfcn.h>
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
static FILE *trace_fp = NULL;
static uint64_t encl_base = 0;
static uint64_t encl_size = 0;
static uint64_t tcs_rva = 0;
static uint64_t ssa_rva = 0;
static uint64_t gm_rva = 0;
static uint64_t atfield_active_rva = 0;
static uint64_t pretouch_start_rva = 0;
static uint64_t pretouch_end_rva = 0;
static uint64_t gate_helper_rva = 0;
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
static int use_4gate = 0;
static int encl_cpu = 45;
static int watch_cpu = 1;
static int allow_fast_forward = 0;

static volatile int watcher_ready __attribute__((aligned(4096))) = 0;
static volatile int watcher_stop __attribute__((aligned(4096))) = 0;
static pthread_t watcher_thread;
static int watcher_started = 0;

static int cur_obs_count = 0;
static int obs_truncated = 0;
static field_obs_t cur_obs[MAX_FIELD_OBS_PER_ECALL];
static uint64_t ecall_post_ad[MAX_TRACKED_PAGES];

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

static int call_seq = 0;
static int selector_seq[64] = {0};
static int fast_forwarded_calls = 0;

static volatile int in_measured_ecall = 0;
static int aep_hooked = 0;
static void *aep_trampoline_va = NULL;

typedef sgx_status_t (*real_create_fn_t)(const char *, int, void *, int *, sgx_enclave_id_t *, void *);
typedef sgx_status_t (*real_ecall_fn_t)(sgx_enclave_id_t, int, const void *, void *);
typedef sgx_status_t (*real_destroy_fn_t)(sgx_enclave_id_t);

static real_create_fn_t real_sgx_create_enclave = NULL;
static real_ecall_fn_t real_sgx_ecall = NULL;
static real_destroy_fn_t real_sgx_destroy_enclave = NULL;

static void dump_enclave_vmas_if_requested(void);
static void cleanup_interpose(void);

static void mark_invalid(const char *reason) {
    if (!last_invalid_reason[0]) {
        strncpy(last_invalid_reason, reason, sizeof(last_invalid_reason) - 1);
    }
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
    if (ioctl(fd_step, SGX_STEP_IOCTL_INVPG, &param) < 0) {
        syscall_error_count++;
        mark_invalid("ioctl_invpg_failed");
    }
}

static inline void clear_ad_only(void) {
    for (int i = 0; i < num_pages; i++) {
        uint64_t v = *pte_slots[i];
        if (v & (A_MASK | D_MASK))
            *pte_slots[i] = v & ~(A_MASK | D_MASK);
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

static void classify_confirmed_access_kind(fault_event_t *fe, uint64_t final_pte) {
    fe->final_pte = final_pte;
    fe->ea_verified = 0;
    fe->effective_addr_rva = 0;
    if (final_pte & D_MASK) {
        snprintf(fe->inferred_post_window_kind, sizeof(fe->inferred_post_window_kind), "W_inferred_post_d");
    } else if (final_pte & A_MASK) {
        snprintf(fe->inferred_post_window_kind, sizeof(fe->inferred_post_window_kind), "R_inferred_post_a");
    } else {
        snprintf(fe->inferred_post_window_kind, sizeof(fe->inferred_post_window_kind), "none");
    }

    if (fe->encl_rip_rva != 0 && (fe->encl_rip_rva & ~0xfffULL) == fe->page_rva) {
        fe->effective_addr_rva = fe->encl_rip_rva;
        fe->ea_verified = 1;
        snprintf(fe->confirmed_access_kind, sizeof(fe->confirmed_access_kind), "X");
        return;
    }
    /* Verify exact RIP-relative effective address EA = encl_rip_rva + insn_len + disp32 against fe->page_rva */
    if (fe->encl_rip_rva != 0 && fd_self_mem >= 0 && encl_base) {
        uint8_t insn[8] = {0};
        if (pread(fd_self_mem, insn, sizeof(insn), encl_base + fe->encl_rip_rva) == sizeof(insn)) {
            if (insn[0] == 0xf0 && insn[1] == 0x80 && insn[2] == 0x0d) {
                /* lock orb $0, disp32(%rip) : 8-byte instruction */
                int32_t disp = *(int32_t *)(insn + 3);
                uint64_t ea_rva = (uint64_t)((int64_t)fe->encl_rip_rva + 8LL + (int64_t)disp);
                fe->effective_addr_rva = ea_rva;
                if ((ea_rva & ~0xfffULL) == fe->page_rva) {
                    fe->ea_verified = 1;
                    snprintf(fe->confirmed_access_kind, sizeof(fe->confirmed_access_kind), "W");
                    return;
                }
            } else if (insn[0] == 0x8a && insn[1] == 0x05) {
                /* movb disp32(%rip), %al : 6-byte instruction */
                int32_t disp = *(int32_t *)(insn + 2);
                uint64_t ea_rva = (uint64_t)((int64_t)fe->encl_rip_rva + 6LL + (int64_t)disp);
                fe->effective_addr_rva = ea_rva;
                if ((ea_rva & ~0xfffULL) == fe->page_rva) {
                    fe->ea_verified = 1;
                    snprintf(fe->confirmed_access_kind, sizeof(fe->confirmed_access_kind), "R");
                    return;
                }
            }
        }
    }
    /* Never upgrade post-window D/A bit guesses to confirmed_access_kind! */
    snprintf(fe->confirmed_access_kind, sizeof(fe->confirmed_access_kind), "unknown");
}

void on_aex_event(uint64_t tcs_va, uint64_t rax_mode) {
    (void)tcs_va;
    if (rax_mode == 2) return;
    if (ipi_dummy_page) {
        volatile uint8_t d = *ipi_dummy_page;
        (void)d;
    }
    if (!g_shared || !in_measured_ecall || !encl_base) return;
    uint32_t seq = __atomic_add_fetch(&g_shared->total_aex_count, 1, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&g_shared->in_gate_spin, __ATOMIC_ACQUIRE)) {
        __atomic_add_fetch(&g_shared->gate_ipi_aex_count, 1, __ATOMIC_SEQ_CST);
        return;
    }

    uint32_t active_val = 0;
    if (atfield_active_rva && fd_self_mem >= 0 && encl_base) {
        if (pread(fd_self_mem, &active_val, 4, encl_base + atfield_active_rva) != 4) {
            syscall_error_count++;
            mark_invalid("pread_atfield_active_failed");
        }
    }
    uint64_t encl_rip = 0;
    uint32_t exitinfo = 0;
    if (ssa_rva && fd_self_mem >= 0 && encl_base) {
        if (pread(fd_self_mem, &encl_rip, 8, encl_base + ssa_rva + 0xfd0) != 8) {
            syscall_error_count++;
        }
        if (pread(fd_self_mem, &exitinfo, 4, encl_base + ssa_rva + 0xfe8) != 4) {
            syscall_error_count++;
        }
    }
    uint64_t rip_rva = (encl_rip >= encl_base && encl_rip < encl_base + encl_size) ? (encl_rip - encl_base) : 0;
    uint32_t st_code = g_shared->current_stage;

    for (int i = 0; i < num_pages; i++) {
        if (strict_retracted[i] == 1) {
            uint64_t pte_now = *pte_slots[i];
            if (PRESENT(pte_now)) {
                strict_retracted[i] = 2;
                if (cur_fault_count < MAX_FAULT_EVENTS_PER_ECALL) {
                    fault_event_t *fe = &cur_faults[cur_fault_count++];
                    fe->aex_seq = seq;
                    fe->page_idx = i;
                    fe->page_rva = page_rvas[i];
                    fe->encl_rip_rva = rip_rva;
                    fe->exitinfo = exitinfo;
                    fe->active_flag = active_val;
                    snprintf(fe->stage, sizeof(fe->stage), "%s", stage_name_from_code(st_code, active_val, rip_rva));
                    fe->pte_healed_observed = 1;
                    fe->aep_pte = pte_now;
                    classify_confirmed_access_kind(fe, pte_now);
                } else {
                    fault_events_truncated = 1;
                    mark_invalid("fault_events_truncated");
                }
            }
        }
    }
}

static void install_urts_aep_hook(void) {
    if (aep_hooked) return;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        syscall_error_count++;
        mark_invalid("fopen_maps_failed");
        return;
    }
    char line[512];
    uint64_t urts_rx_start = 0, urts_rx_end = 0, urts_rx_off = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "libsgx_urts.so")) continue;
        uint64_t s, e, off;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s %lx", &s, &e, perms, &off) == 4) {
            if (strstr(perms, "x")) {
                urts_rx_start = s;
                urts_rx_end = e;
                urts_rx_off = off;
                break;
            }
        }
    }
    fclose(fp);
    if (!urts_rx_start) {
        syscall_error_count++;
        mark_invalid("urts_rx_segment_not_found");
        return;
    }

    uint64_t urts_base = urts_rx_start - urts_rx_off;
    uint64_t vdso_det_va = urts_base + 0x6a840;
    uint64_t vdso_ptr_va = urts_base + 0x3e8128;
    if (mprotect((void *)(vdso_det_va & ~0xfffULL), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        *(uint8_t *)vdso_det_va = 0xc3;
        __builtin___clear_cache((char *)vdso_det_va, (char *)(vdso_det_va + 1));
    }
    *(uint64_t *)vdso_ptr_va = 0;

    uint64_t aep_va = 0;
    const uint8_t pat[] = {0x0f, 0x01, 0xd7, 0x0f, 0x0b};
    uint64_t cand = urts_base + 0x6ab2f;
    if (cand >= urts_rx_start && cand + 5 <= urts_rx_end && memcmp((void *)cand, pat, 5) == 0) {
        aep_va = cand;
    } else {
        for (uint64_t p = urts_rx_start; p + 16 <= urts_rx_end; p++) {
            if (memcmp((void *)p, pat, 5) == 0) {
                aep_va = p;
                break;
            }
        }
    }
    if (!aep_va) {
        syscall_error_count++;
        mark_invalid("urts_aep_bytes_not_found");
        return;
    }

    for (int64_t delta = -0x20000000LL; delta <= 0x20000000LL; delta += 0x100000LL) {
        uint64_t try_va = (aep_va + delta) & ~0xfffULL;
        void *m = mmap((void *)try_va, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (m != MAP_FAILED) {
            aep_trampoline_va = m;
            break;
        }
    }
    if (!aep_trampoline_va) {
        syscall_error_count++;
        mark_invalid("aep_trampoline_mmap_failed");
        return;
    }

    uint8_t *t = (uint8_t *)aep_trampoline_va;
    int k = 0;
    const uint8_t prolog[] = {
        0x9c, 0x55, 0x50, 0x51, 0x52, 0x56, 0x57,
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x48, 0x89, 0xe5,
        0x48, 0x83, 0xe4, 0xf0,
        0x48, 0x89, 0xdf,
        0x48, 0x89, 0xc6,
        0x48, 0xb8
    };
    memcpy(t + k, prolog, sizeof(prolog));
    k += sizeof(prolog);
    uint64_t fn_addr = (uint64_t)(uintptr_t)&on_aex_event;
    memcpy(t + k, &fn_addr, 8);
    k += 8;
    const uint8_t epilog[] = {
        0xff, 0xd0,
        0x48, 0x89, 0xec,
        0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
        0x5f, 0x5e, 0x5a, 0x59, 0x58,
        0x5d,
        0x48, 0x83, 0xf8, 0x02,
        0x74, 0x06,
        0x9d,
        0x0f, 0x01, 0xd7,
        0x0f, 0x0b,
        0x9d
    };
    memcpy(t + k, epilog, sizeof(epilog));
    k += sizeof(epilog);
    uint64_t eenterp_va = urts_base + 0x6aac9;
    int64_t rel_ee = (int64_t)eenterp_va - (int64_t)((uintptr_t)(t + k) + 5);
    int32_t rel32_ee = (int32_t)rel_ee;
    t[k++] = 0xe9;
    memcpy(t + k, &rel32_ee, 4);
    k += 4;

    uint64_t aep_page = aep_va & ~0xfffULL;
    if (mprotect((void *)aep_page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        syscall_error_count++;
        mark_invalid("mprotect_urts_aep_failed");
        return;
    }
    int64_t rel = (int64_t)(uintptr_t)aep_trampoline_va - (int64_t)(aep_va + 5);
    int32_t rel32 = (int32_t)rel;
    uint8_t jmp_patch[5];
    jmp_patch[0] = 0xe9;
    memcpy(jmp_patch + 1, &rel32, 4);
    memcpy((void *)aep_va, jmp_patch, 5);
    __builtin___clear_cache((char *)aep_va, (char *)(aep_va + 5));
    aep_hooked = 1;
}

static int trigger_tlb_shootdown_ipi_verified(void) {
    __atomic_store_n(&g_shared->in_gate_spin, 1, __ATOMIC_SEQ_CST);
    uint32_t before = __atomic_load_n(&g_shared->gate_ipi_aex_count, __ATOMIC_ACQUIRE);
    uint64_t t_start = monotonic_ns();
    int verified = 0;

    while (!__atomic_load_n(&watcher_stop, __ATOMIC_ACQUIRE)) {
        if (mprotect((void *)ipi_dummy_page, 4096, PROT_READ) != 0 ||
            mprotect((void *)ipi_dummy_page, 4096, PROT_READ | PROT_WRITE) != 0) {
            syscall_error_count++;
            mark_invalid("mprotect_ipi_failed");
            break;
        }
        uint64_t round_start = monotonic_ns();
        while (monotonic_ns() - round_start < 2000000ULL) {
            if (__atomic_load_n(&g_shared->gate_ipi_aex_count, __ATOMIC_ACQUIRE) > before) {
                verified = 1;
                break;
            }
            __asm__ volatile("pause" ::: "memory");
        }
        if (verified) break;
        if (monotonic_ns() - t_start > 50000000ULL) {
            ipi_flush_failure_count++;
            mark_invalid("ipi_aex_not_observed_within_50ms");
            break;
        }
    }
    __atomic_store_n(&g_shared->in_gate_spin, 0, __ATOMIC_SEQ_CST);
    return verified;
}

static void walk_dlmalloc_at_gate(field_obs_t *obs) {
    obs->heap_lo_rva = 0;
    obs->heap_hi_rva = 0;
    obs->num_live_chunks = 0;
    obs->heap_walk_truncated = 0;
    obs->heap_pread_failures = 0;
    if (!gm_rva || fd_self_mem < 0 || !encl_base) return;
    uint8_t mstate_buf[0x40];
    if (pread(fd_self_mem, mstate_buf, sizeof(mstate_buf), encl_base + gm_rva) != sizeof(mstate_buf)) {
        obs->heap_pread_failures++;
        return;
    }
    uint64_t least_addr = *(uint64_t *)(mstate_buf + 0x18);
    uint64_t top_addr = *(uint64_t *)(mstate_buf + 0x28);
    if (least_addr <= encl_base || top_addr < least_addr || top_addr >= encl_base + encl_size)
        return;
    obs->heap_lo_rva = least_addr - encl_base;
    obs->heap_hi_rva = top_addr - encl_base;
    uint64_t cur = obs->heap_lo_rva;
    int hops = 0;
    while (cur < obs->heap_hi_rva) {
        if (hops >= 65536) {
            obs->heap_walk_truncated = 1;
            mark_invalid("heap_walk_hops_exceeded");
            break;
        }
        uint64_t hdr[2] = {0, 0};
        if (pread(fd_self_mem, hdr, 16, encl_base + cur) != 16) {
            obs->heap_pread_failures++;
            mark_invalid("heap_chunk_pread_failed");
            break;
        }
        uint64_t sz = hdr[1] & ~7ULL;
        int cinuse = (hdr[1] >> 1) & 1;
        if (sz < 16 || cur + sz > obs->heap_hi_rva + 0x100000) {
            obs->heap_walk_truncated = 1;
            mark_invalid("heap_chunk_corrupt_size");
            break;
        }
        if (cinuse) {
            uint64_t c_lo = (cur >= 16) ? ((cur - 16) & ~0xfffULL) : 0;
            uint64_t c_hi = (cur + sz + 16 + 0xfffULL) & ~0xfffULL;
            if (obs->num_live_chunks > 0 &&
                obs->chunk_spans[obs->num_live_chunks - 1][0] == c_lo &&
                obs->chunk_spans[obs->num_live_chunks - 1][1] == c_hi) {
                /* Same page span as previous live chunk: already covered */
            } else if (obs->num_live_chunks < MAX_CHUNKS_PER_OBS) {
                obs->chunk_spans[obs->num_live_chunks][0] = c_lo;
                obs->chunk_spans[obs->num_live_chunks][1] = c_hi;
                obs->num_live_chunks++;
            } else {
                obs->heap_walk_truncated = 1;
                mark_invalid("heap_live_chunks_exceeded");
            }
        }
        cur += sz;
        hops++;
    }
}

static void arm_strict_ptes_for_selector(int sel) {
    if (sel < 0 || sel >= 64 || !strict_selector_has_map[sel]) {
        strict_config_invalid = 1;
        mark_invalid("missing_strict_selector_map");
        return;
    }
    for (int i = 0; i < num_pages; i++) {
        if (!strict_allowed_page[sel][i]) {
            strict_retracted[i] = 1;
            *pte_slots[i] = 0;
        } else {
            strict_retracted[i] = 0;
        }
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static void disarm_and_check_strict_ptes(const char *fallback_stage) {
    /* First update final_pte and confirmed_access_kind for all faults already captured by AEP */
    for (int fi = 0; fi < cur_fault_count; fi++) {
        fault_event_t *fe = &cur_faults[fi];
        if (fe->page_idx >= 0 && fe->page_idx < num_pages) {
            classify_confirmed_access_kind(fe, *pte_slots[fe->page_idx]);
        }
    }
    for (int i = 0; i < num_pages; i++) {
        if (strict_retracted[i] == 1) {
            uint64_t pte_now = *pte_slots[i];
            if (PRESENT(pte_now)) {
                strict_retracted[i] = 2;
                if (cur_fault_count < MAX_FAULT_EVENTS_PER_ECALL) {
                    fault_event_t *fe = &cur_faults[cur_fault_count++];
                    fe->aex_seq = g_shared ? g_shared->total_aex_count : 0;
                    fe->page_idx = i;
                    fe->page_rva = page_rvas[i];
                    fe->encl_rip_rva = 0;
                    fe->exitinfo = 0;
                    fe->active_flag = 0;
                    snprintf(fe->stage, sizeof(fe->stage), "%s", fallback_stage);
                    fe->pte_healed_observed = 1;
                    fe->aep_pte = pte_now;
                    classify_confirmed_access_kind(fe, pte_now);
                }
            }
        }
        *pte_slots[i] = orig_ptes[i];
        strict_retracted[i] = 0;
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static void *watcher_loop(void *arg) {
    (void)arg;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(watch_cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        syscall_error_count++;
        mark_invalid("watcher_setaffinity_failed");
    }
    __atomic_store_n(&watcher_ready, 1, __ATOMIC_RELEASE);

    uint64_t *tmp_s0 = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
    uint64_t *tmp_s1 = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
    uint64_t *tmp_s2 = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
    uint32_t cur_ipi_ok_mask = 0;
    uint32_t s3_start_aex = 0;

    while (!__atomic_load_n(&watcher_stop, __ATOMIC_ACQUIRE)) {
        uint32_t g = __atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE);
        if (g == 10) {
            cur_ipi_ok_mask = 0;
            snapshot_ad(tmp_s0);
            if (ipi_mask & 1) {
                if (trigger_tlb_shootdown_ipi_verified()) cur_ipi_ok_mask |= 1;
            }
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 20, __ATOMIC_RELEASE);
        } else if (g == 30) {
            snapshot_ad(tmp_s1);
            if (strict_mode == 2 && active_strict_selector >= 0) {
                arm_strict_ptes_for_selector(active_strict_selector);
            }
            if ((ipi_mask & 2) || strict_mode == 2) {
                if (trigger_tlb_shootdown_ipi_verified()) cur_ipi_ok_mask |= 2;
            }
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 40, __ATOMIC_RELEASE);
        } else if (g == 50) {
            snapshot_ad(tmp_s2);
            if (ipi_mask & 4) {
                if (trigger_tlb_shootdown_ipi_verified()) cur_ipi_ok_mask |= 4;
            }
            clear_ad_only();
            s3_start_aex = __atomic_load_n(&g_shared->total_aex_count, __ATOMIC_ACQUIRE);
            __atomic_store_n(&g_shared->host_gate, 60, __ATOMIC_RELEASE);
        } else if (g == 70) {
            uint32_t s3_end_aex = __atomic_load_n(&g_shared->total_aex_count, __ATOMIC_ACQUIRE);
            if (strict_mode == 2 && active_strict_selector >= 0) {
                disarm_and_check_strict_ptes("S2_OR_S3_FIELD");
            }
            int slot = cur_obs_count;
            if (slot < MAX_FIELD_OBS_PER_ECALL) {
                field_obs_t *o = &cur_obs[slot];
                if (!o->s0_ad) {
                    o->s0_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                    o->s1_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                    o->s2_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                    o->s3_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                }
                o->field_id = g_shared->active_field_id;
                o->tsc_s2 = g_shared->tsc_s2_end - g_shared->tsc_s2_start;
                o->tsc_s3 = g_shared->tsc_s3_end - g_shared->tsc_s3_start;
                o->gateB_rsp_rva = g_shared->saved_rsp ? (g_shared->saved_rsp - encl_base) : 0;
                o->gateD_rsp_rva = g_shared->gateD_rsp ? (g_shared->gateD_rsp - encl_base) : 0;
                o->ipi_aex_verified_mask = cur_ipi_ok_mask;
                o->s3_active_aex_count = s3_end_aex - s3_start_aex;
                memcpy(o->s0_ad, tmp_s0, sizeof(uint64_t) * num_pages);
                memcpy(o->s1_ad, tmp_s1, sizeof(uint64_t) * num_pages);
                memcpy(o->s2_ad, tmp_s2, sizeof(uint64_t) * num_pages);
                snapshot_ad(o->s3_ad);
                walk_dlmalloc_at_gate(o);
                cur_obs_count = slot + 1;
            } else {
                obs_truncated = 1;
                mark_invalid("field_obs_per_ecall_truncated");
            }
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 80, __ATOMIC_RELEASE);
        } else {
            __asm__ volatile("pause" ::: "memory");
        }
    }
    free(tmp_s0);
    free(tmp_s1);
    free(tmp_s2);
    return NULL;
}

static void parse_schema_spec_env(void) {
    const char *spec = getenv("ATFIELD_SCHEMA_SPEC");
    if (!spec || !*spec) return;
    memset(g_ecall_schemas, 0, sizeof(g_ecall_schemas));
    memset(g_has_ecall_schema, 0, sizeof(g_has_ecall_schema));
    char *copy = strdup(spec);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ";", &saveptr); tok; tok = strtok_r(NULL, ";", &saveptr)) {
        if (tok[0] == 'E' && tok[1] == ':') {
            int idx = 0, has_ret = 0, rep_ok = 0;
            unsigned int ms_sz = 0, ret_off = 0, ret_sz = 0, np = 0;
            if (sscanf(tok, "E:%d:%u:%d:%u:%u:%d:%u", &idx, &ms_sz, &has_ret, &ret_off, &ret_sz, &rep_ok, &np) == 7) {
                if (idx >= 0 && idx < MAX_SCHEMA_ECALLS) {
                    ecall_schema_t *es = &g_ecall_schemas[idx];
                    es->ecall_index = idx;
                    es->ms_size = ms_sz;
                    es->has_retval = (uint8_t)has_ret;
                    es->retval_offset = ret_off;
                    es->retval_size = ret_sz;
                    es->replay_supported = (uint8_t)rep_ok;
                    es->num_params = np <= MAX_SCHEMA_PARAMS ? np : MAX_SCHEMA_PARAMS;
                    g_has_ecall_schema[idx] = 1;
                }
            }
        } else if (tok[0] == 'P' && tok[1] == ':') {
            int idx = 0, pidx = 0, is_ptr = 0, pdepth = 0, dir = 0, is_str = 0, is_uc = 0, bkind = 0, boff = -1, rep_ok = 0;
            unsigned int moff = 0, msz = 0, esz = 0, bsz = 0;
            long long scnt = -1;
            if (sscanf(tok, "P:%d:%d:%u:%u:%u:%d:%d:%d:%d:%d:%d:%d:%u:%lld:%d",
                       &idx, &pidx, &moff, &msz, &esz, &is_ptr, &pdepth, &dir, &is_str, &is_uc, &bkind, &boff, &bsz, &scnt, &rep_ok) == 15) {
                if (idx >= 0 && idx < MAX_SCHEMA_ECALLS && pidx >= 0 && pidx < MAX_SCHEMA_PARAMS) {
                    param_schema_t *ps = &g_ecall_schemas[idx].params[pidx];
                    ps->ms_offset = moff;
                    ps->ms_size = msz;
                    ps->elem_size = esz;
                    ps->is_pointer = (uint8_t)is_ptr;
                    ps->ptr_depth = (uint8_t)pdepth;
                    ps->direction = (uint8_t)dir;
                    ps->is_string = (uint8_t)is_str;
                    ps->is_user_check = (uint8_t)is_uc;
                    ps->bound_kind = (uint8_t)bkind;
                    ps->bound_ms_offset = boff;
                    ps->bound_ms_size = bsz;
                    ps->static_count = (int64_t)scnt;
                    ps->replay_supported = (uint8_t)rep_ok;
                }
            }
        }
    }
    free(copy);
}

static void setup_enclave_ptes(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        syscall_error_count++;
        mark_invalid("fopen_maps_failed");
        return;
    }
    char line[512];
    uint64_t first = 0, last = 0;
    typedef struct { uint64_t start, end; char perms[8]; } vma_t;
    vma_t vmas[128];
    int nvmas = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "/dev/sgx_enclave") && !strstr(line, "/dev/sgx/enclave"))
            continue;
        uint64_t s, e;
        char p[8];
        if (sscanf(line, "%lx-%lx %7s", &s, &e, p) == 3 && nvmas < 128) {
            if (!first) first = s;
            if (e > last) last = e;
            vmas[nvmas].start = s;
            vmas[nvmas].end = e;
            strncpy(vmas[nvmas].perms, p, 7);
            nvmas++;
        }
    }
    fclose(fp);
    encl_base = first;
    encl_size = last - first;

    uint64_t excl_ranges[64][2];
    int n_excl = 0;
    const char *spec = getenv("ATFIELD_LAYOUT_SPEC");
    if (spec) {
        const char *p;
        if ((p = strstr(spec, "tcs="))) tcs_rva = strtoull(p + 4, NULL, 16);
        if ((p = strstr(spec, "ssa="))) ssa_rva = strtoull(p + 4, NULL, 16);
        if ((p = strstr(spec, "gm="))) gm_rva = strtoull(p + 3, NULL, 16);
        if ((p = strstr(spec, "active="))) atfield_active_rva = strtoull(p + 7, NULL, 16);
        if ((p = strstr(spec, "pretouch="))) {
            char *endp = NULL;
            pretouch_start_rva = strtoull(p + 9, &endp, 16);
            if (endp && *endp == ':') pretouch_end_rva = strtoull(endp + 1, NULL, 16);
        }
        if ((p = strstr(spec, "gate="))) gate_helper_rva = strtoull(p + 5, NULL, 16);
        if ((p = strstr(spec, "stack="))) {
            char *endp = NULL;
            stack_lo_rva = strtoull(p + 6, &endp, 16);
            if (endp && *endp == ':') stack_hi_rva = strtoull(endp + 1, NULL, 16);
        }
        if ((p = strstr(spec, "excl="))) {
            p += 5;
            while (*p && *p != ';' && n_excl < 64) {
                char *mid = NULL, *nxt = NULL;
                uint64_t lo = strtoull(p, &mid, 16);
                if (!mid || *mid != ':') break;
                uint64_t hi = strtoull(mid + 1, &nxt, 16);
                excl_ranges[n_excl][0] = lo;
                excl_ranges[n_excl][1] = hi;
                n_excl++;
                if (!nxt || *nxt != ',') break;
                p = nxt + 1;
            }
        }
    }

    if (tcs_rva && fd_self_mem >= 0) {
        uint64_t flags = 0;
        if (pread(fd_self_mem, &flags, 8, encl_base + tcs_rva + 8) != 8) {
            syscall_error_count++;
            mark_invalid("pread_tcs_failed");
        }
        flags |= 1ULL;
        if (pwrite(fd_self_mem, &flags, 8, encl_base + tcs_rva + 8) != 8) {
            syscall_error_count++;
            mark_invalid("pwrite_tcs_failed");
        }
    }

    num_pages = 0;
    page_table_truncated = 0;
    for (int i = 0; i < nvmas; i++) {
        if (vmas[i].perms[0] != 'r') continue;
        int is_x = (strchr(vmas[i].perms, 'x') != NULL) ? 1 : 0;
        for (uint64_t va = vmas[i].start; va < vmas[i].end; va += 0x1000) {
            uint64_t rva = va - encl_base;
            int is_ctl = 0;
            for (int k = 0; k < n_excl; k++) {
                if (rva >= excl_ranges[k][0] && rva < excl_ranges[k][1]) {
                    is_ctl = 1;
                    break;
                }
            }
            if (is_ctl) continue;
            volatile uint8_t b = *(volatile uint8_t *)(uintptr_t)va;
            (void)b;
            address_mapping_t *m = get_mappings((void *)(uintptr_t)va);
            if (m && PRESENT(m->pmd) && !PMD_PS(m->pmd) && PRESENT(m->pte)) {
                if (num_pages < MAX_TRACKED_PAGES) {
                    pte_slots[num_pages] = remap(phys_address(m, PTE));
                    orig_ptes[num_pages] = *pte_slots[num_pages];
                    page_rvas[num_pages] = rva;
                    page_is_pretouch[num_pages] = (rva >= pretouch_start_rva && rva < pretouch_end_rva) ? 1 : 0;
                    page_is_exec[num_pages] = (uint8_t)is_x;
                    num_pages++;
                } else {
                    page_table_truncated = 1;
                    mark_invalid("page_table_truncated");
                }
            } else {
                syscall_error_count++;
                mark_invalid("get_mappings_missing_pte");
            }
            if (m) free(m);
        }
    }

    memset(strict_selector_has_map, 0, sizeof(strict_selector_has_map));
    memset(strict_allowed_page, 0, sizeof(strict_allowed_page));
    strict_config_invalid = 0;
    strict_mode = 0;
    const char *sm = getenv("ATFIELD_STRICT_MODE");
    if (sm && strcmp(sm, "field") == 0) strict_mode = 2;
    else if (sm && strcmp(sm, "ecall") == 0) strict_mode = 1;

    const char *strict_path = getenv("ATFIELD_STRICT_READY_FILE");
    if (strict_path && *strict_path) {
        if (!strict_mode) strict_mode = 1;
        FILE *sf = fopen(strict_path, "r");
        if (!sf) {
            strict_config_invalid = 1;
            mark_invalid("strict_ready_file_open_failed");
        } else {
            char *sline = (char *)malloc(262144);
            int any_loaded = 0;
            while (sline && fgets(sline, 262144, sf)) {
                char *cur = sline;
                char *nxt = NULL;
                unsigned long sel = strtoul(cur, &nxt, 10);
                if (nxt == cur || sel >= 64) continue;
                strict_selector_has_map[sel] = 1;
                any_loaded = 1;
                cur = nxt;
                while (*cur) {
                    while (*cur == ' ' || *cur == '\t') cur++;
                    if (*cur == '\n' || *cur == '\0') break;
                    uint64_t rva = strtoull(cur, &nxt, 16);
                    if (nxt == cur) break;
                    for (int i = 0; i < num_pages; i++) {
                        if (page_rvas[i] == rva) {
                            strict_allowed_page[sel][i] = 1;
                            break;
                        }
                    }
                    cur = nxt;
                }
            }
            free(sline);
            fclose(sf);
            if (!any_loaded) {
                strict_config_invalid = 1;
                mark_invalid("strict_ready_file_empty");
            }
        }
    } else if (strict_mode != 0) {
        strict_config_invalid = 1;
        mark_invalid("strict_mode_without_file");
    }
}

static void write_ad_json_array(FILE *out, const uint64_t *ad, int include_pretouch) {
    fprintf(out, "[");
    int first = 1;
    for (int i = 0; i < num_pages; i++) {
        if (!include_pretouch && page_is_pretouch[i]) continue;
        if (page_rvas[i] == gate_helper_rva) continue;
        if (ad[i] & (A_MASK | D_MASK)) {
            fprintf(out, "%s{\"rva\":\"0x%lx\",\"ad\":\"%s\"}",
                    first ? "" : ",",
                    (unsigned long)page_rvas[i],
                    (ad[i] & D_MASK) ? "D" : "A");
            first = 0;
        }
    }
    fprintf(out, "]");
}

sgx_status_t sgx_create_enclave(
    const char *file_name,
    const int debug,
    void *launch_token,
    int *launch_token_updated,
    sgx_enclave_id_t *enclave_id,
    void *misc_attr)
{
    if (!real_sgx_create_enclave)
        real_sgx_create_enclave = (real_create_fn_t)dlsym(RTLD_NEXT, "sgx_create_enclave");
    if (!real_sgx_ecall)
        real_sgx_ecall = (real_ecall_fn_t)dlsym(RTLD_NEXT, "sgx_ecall");
    if (!real_sgx_destroy_enclave)
        real_sgx_destroy_enclave = (real_destroy_fn_t)dlsym(RTLD_NEXT, "sgx_destroy_enclave");

    const char *override_encl = getenv("ATFIELD_ENCLAVE_PATH");
    const char *actual_encl = (override_encl && *override_encl) ? override_encl : file_name;

    if (getenv("ATFIELD_ENCL_CPU")) encl_cpu = atoi(getenv("ATFIELD_ENCL_CPU"));
    if (getenv("ATFIELD_WATCH_CPU")) watch_cpu = atoi(getenv("ATFIELD_WATCH_CPU"));
    if (getenv("ATFIELD_IPI_MASK")) ipi_mask = atoi(getenv("ATFIELD_IPI_MASK"));
    if (getenv("ATFIELD_USE_4GATE")) use_4gate = atoi(getenv("ATFIELD_USE_4GATE"));
    if (getenv("ATFIELD_ALLOW_FAST_FORWARD")) allow_fast_forward = atoi(getenv("ATFIELD_ALLOW_FAST_FORWARD"));

    parse_schema_spec_env();

    const char *trace_out = getenv("ATFIELD_TRACE_OUT");
    if (trace_out && *trace_out && !trace_fp) {
        trace_fp = fopen(trace_out, "a");
    }

    lock_fd = open("/tmp/atfield_sgxstep.lock", O_CREAT | O_RDWR, 0666);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        syscall_error_count++;
        mark_invalid("lock_acquire_failed");
    }

    if (fd_self_mem < 0) {
        fd_self_mem = open("/proc/self/mem", O_RDWR);
        if (fd_self_mem < 0) {
            syscall_error_count++;
            mark_invalid("open_proc_self_mem_failed");
        }
    }

    if (!g_shared) {
        void *sh = mmap((void *)GATE_SHARED_VA, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (sh == MAP_FAILED) {
            sh = (void *)GATE_SHARED_VA;
        }
        memset(sh, 0, 4096);
        g_shared = (gate_shared_t *)sh;
    } else {
        memset((void *)g_shared, 0, 4096);
    }
    if (getenv("ATFIELD_ALT_RSP_S2"))
        g_shared->use_alt_rsp_in_s2 = (uint64_t)atoi(getenv("ATFIELD_ALT_RSP_S2"));

    if (!ipi_dummy_page) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            syscall_error_count++;
            mark_invalid("mmap_ipi_dummy_failed");
        } else {
            ipi_dummy_page = (volatile uint8_t *)p;
            *ipi_dummy_page = 1;
        }
    }

    install_urts_aep_hook();

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        syscall_error_count++;
        mark_invalid("main_setaffinity_cpu0_failed");
    }

    sgx_status_t st = real_sgx_create_enclave(actual_encl, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
    if (st != 0) return st;

    setup_enclave_ptes();

    __atomic_store_n(&watcher_ready, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&watcher_stop, 0, __ATOMIC_SEQ_CST);
    if (pthread_create(&watcher_thread, NULL, watcher_loop, NULL) != 0) {
        syscall_error_count++;
        mark_invalid("pthread_create_watcher_failed");
    } else {
        while (!__atomic_load_n(&watcher_ready, __ATOMIC_ACQUIRE)) {
            __asm__ volatile("pause");
        }
        watcher_started = 1;
    }

    CPU_ZERO(&set);
    CPU_SET(encl_cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        syscall_error_count++;
        mark_invalid("encl_setaffinity_failed");
    }
    if (ipi_dummy_page) *ipi_dummy_page = 2;
    *(volatile uint8_t *)g_shared = 0;

    return st;
}

static sgx_status_t execute_one_measured_ecall(
    sgx_enclave_id_t eid,
    int index,
    const void *ocall_table,
    void *ms,
    const char *tag,
    int enable_gate_for_this_call)
{
    cur_obs_count = 0;
    obs_truncated = 0;
    cur_fault_count = 0;
    fault_events_truncated = 0;
    g_shared->host_gate = 0;
    g_shared->current_stage = 0;
    g_shared->total_aex_count = 0;
    g_shared->gate_ipi_aex_count = 0;
    g_shared->in_gate_spin = 0;
    g_shared->gate_enable = (use_4gate && enable_gate_for_this_call) ? 1 : 0;

    if (ipi_dummy_page) {
        volatile uint8_t d = *ipi_dummy_page;
        (void)d;
    }

    active_strict_selector = -1;
    int strict_enforced_for_call = 0;
    if (strict_mode != 0) {
        if (strict_config_invalid || index < 0 || index >= 64) {
            strict_config_invalid = 1;
            mark_invalid("strict_selector_out_of_range_or_invalid");
        } else if (strict_selector_has_map[index]) {
            active_strict_selector = index;
            strict_enforced_for_call = strict_mode;
            if (strict_mode == 1) {
                arm_strict_ptes_for_selector(index);
            }
        }
    }

    for (int i = 0; i < num_pages; i++) {
        checked_flush_tlb(encl_base + page_rvas[i]);
    }
    clear_ad_only();

    __atomic_store_n(&in_measured_ecall, 1, __ATOMIC_SEQ_CST);
    uint64_t t0 = monotonic_ns();
    sgx_status_t st = real_sgx_ecall(eid, index, ocall_table, ms);
    uint64_t elapsed_ns = monotonic_ns() - t0;
    __atomic_store_n(&in_measured_ecall, 0, __ATOMIC_SEQ_CST);

    snapshot_ad(ecall_post_ad);

    if (strict_mode == 1 && active_strict_selector >= 0) {
        disarm_and_check_strict_ptes("ECALL_WINDOW");
    } else if (strict_mode == 2 && active_strict_selector >= 0) {
        disarm_and_check_strict_ptes("EARLY_EXIT_OR_AEX");
    }
    active_strict_selector = -1;

    int any_heap_err = 0;
    for (int f = 0; f < cur_obs_count; f++) {
        if (cur_obs[f].heap_walk_truncated || cur_obs[f].heap_pread_failures) any_heap_err = 1;
    }
    int measurement_invalid = (
        syscall_error_count > 0 ||
        ipi_flush_failure_count > 0 ||
        page_table_truncated != 0 ||
        obs_truncated != 0 ||
        fault_events_truncated != 0 ||
        strict_config_invalid != 0 ||
        mutation_oob_rejected_count != 0 ||
        any_heap_err != 0
    ) ? 1 : 0;

    /* Read ABI return slot strictly according to g_ecall_schemas[index] */
    abi_outcome_t abi = {0, 0};
    int has_out_status_ptr = 0;
    int32_t out_status_val = 0;
    if (index >= 0 && index < MAX_SCHEMA_ECALLS && g_has_ecall_schema[index] && ms) {
        const ecall_schema_t *es = &g_ecall_schemas[index];
        read_ecall_abi_outcome((const uint8_t *)ms, es->ms_size, es, &abi);
        if (!es->has_retval && es->num_params > 0 && es->params[0].is_pointer &&
            es->params[0].direction == DIR_OUT && es->params[0].elem_size == 4 && es->params[0].static_count == 1) {
            int32_t *sptr = *(int32_t **)((uint8_t *)ms + es->params[0].ms_offset);
            if (sptr) {
                has_out_status_ptr = 1;
                out_status_val = *sptr;
            }
        }
    } else if (ms) {
        abi.has_retval = 1;
        abi.retval_i64 = *(int32_t *)ms;
    }

    char ms_ret_json[32];
    if (abi.has_retval) {
        snprintf(ms_ret_json, sizeof(ms_ret_json), "%" PRId64, abi.retval_i64);
    } else {
        snprintf(ms_ret_json, sizeof(ms_ret_json), "null");
    }

    if (trace_fp) {
        fprintf(trace_fp,
                "{\"call_seq\":%d,\"ecall_index\":%d,\"selector_seq\":%d,\"tag\":\"%s\","
                "\"sgx_status\":%d,\"abi_return_type\":\"%s\",\"ms_retval\":%s,\"ms_retval_i32\":%d,"
                "\"has_out_status_i32\":%d,\"out_status_i32\":%d,"
                "\"elapsed_ns\":%" PRIu64 ","
                "\"total_aex_count\":%u,\"gate_ipi_aex_count\":%u,"
                "\"measurement_invalid\":%d,\"invalid_reason\":\"%s\","
                "\"syscall_errors\":%d,\"ipi_flush_failures\":%d,\"mutation_oob_rejected\":%d,"
                "\"fast_forwarded_prior\":%d,"
                "\"strict_mode\":%d,\"strict_non_ready_fault_count\":%d,\"fault_events\":[",
                call_seq, index, (index >= 0 && index < 64) ? selector_seq[index] : -1,
                tag ? tag : "normal",
                st, abi.has_retval ? "scalar" : "void", ms_ret_json,
                abi.has_retval ? (int32_t)abi.retval_i64 : 0,
                has_out_status_ptr, out_status_val,
                elapsed_ns,
                g_shared->total_aex_count, g_shared->gate_ipi_aex_count,
                measurement_invalid, last_invalid_reason,
                syscall_error_count, ipi_flush_failure_count, mutation_oob_rejected_count,
                fast_forwarded_calls,
                strict_enforced_for_call, cur_fault_count);
        for (int fi = 0; fi < cur_fault_count; fi++) {
            fault_event_t *fe = &cur_faults[fi];
            fprintf(trace_fp,
                    "%s{\"aex_seq\":%u,\"page_rva\":\"0x%" PRIx64 "\",\"encl_rip_rva\":\"0x%" PRIx64 "\","
                    "\"effective_addr_rva\":\"0x%" PRIx64 "\",\"ea_verified\":%s,"
                    "\"exitinfo\":\"0x%x\",\"active_flag\":%u,\"stage\":\"%s\","
                    "\"pte_healed_observed\":%s,\"confirmed_access_kind\":\"%s\","
                    "\"inferred_post_window_kind\":\"%s\","
                    "\"access_kind\":\"%s\",\"aep_pte\":\"0x%" PRIx64 "\",\"final_pte\":\"0x%" PRIx64 "\"}",
                    fi ? "," : "", fe->aex_seq, fe->page_rva, fe->encl_rip_rva,
                    fe->effective_addr_rva, fe->ea_verified ? "true" : "false",
                    fe->exitinfo, fe->active_flag, fe->stage,
                    fe->pte_healed_observed ? "true" : "false",
                    fe->confirmed_access_kind, fe->inferred_post_window_kind,
                    fe->confirmed_access_kind, fe->aep_pte, fe->final_pte);
        }
        fprintf(trace_fp, "],\"ecall_ad\":");
        write_ad_json_array(trace_fp, ecall_post_ad, 0);
        fprintf(trace_fp, ",\"fields\":[");
        for (int f = 0; f < cur_obs_count; f++) {
            field_obs_t *o = &cur_obs[f];
            fprintf(trace_fp,
                    "%s{\"field_id\":\"0x%016" PRIx64 "\",\"tsc_s2\":%" PRIu64 ",\"tsc_s3\":%" PRIu64 ","
                    "\"gateB_rsp_rva\":\"0x%" PRIx64 "\",\"gateD_rsp_rva\":\"0x%" PRIx64 "\","
                    "\"ipi_aex_verified_mask\":%u,\"s3_active_aex_count\":%u,"
                    "\"heap_walk_truncated\":%d,\"heap_pread_failures\":%d,"
                    "\"heap_lo_rva\":\"0x%" PRIx64 "\",\"heap_hi_rva\":\"0x%" PRIx64 "\","
                    "\"live_chunks\":%d,\"s0\":",
                    f ? "," : "", o->field_id, o->tsc_s2, o->tsc_s3,
                    o->gateB_rsp_rva, o->gateD_rsp_rva,
                    o->ipi_aex_verified_mask, o->s3_active_aex_count,
                    o->heap_walk_truncated, o->heap_pread_failures,
                    o->heap_lo_rva, o->heap_hi_rva, o->num_live_chunks);
            write_ad_json_array(trace_fp, o->s0_ad, 0);
            fprintf(trace_fp, ",\"s1\":");
            write_ad_json_array(trace_fp, o->s1_ad, 0);
            fprintf(trace_fp, ",\"s2\":");
            write_ad_json_array(trace_fp, o->s2_ad, 0);
            fprintf(trace_fp, ",\"s3\":");
            write_ad_json_array(trace_fp, o->s3_ad, 0);
            fprintf(trace_fp, ",\"s3_pretouch_seg\":");
            write_ad_json_array(trace_fp, o->s3_ad, 1);
            fprintf(trace_fp, ",\"chunks\":[");
            for (int c = 0; c < o->num_live_chunks; c++) {
                fprintf(trace_fp, "%s[\"0x%" PRIx64 "\",\"0x%" PRIx64 "\"]",
                        c ? "," : "", o->chunk_spans[c][0], o->chunk_spans[c][1]);
            }
            fprintf(trace_fp, "]}");
        }
        fprintf(trace_fp, "]}\n");
        fflush(trace_fp);
    }
    return st;
}

typedef struct {
    uint32_t datalen;
    uint8_t data[];
} ehsm_data_wire_t;

static void run_interventions_if_matching(
    sgx_enclave_id_t eid,
    int index,
    const void *ocall_table,
    void *ms)
{
    const char *spec = getenv("ATFIELD_INTERVENTION");
    if (!spec || !*spec || !ms || index < 0 || index >= MAX_SCHEMA_ECALLS) return;
    int sseq = selector_seq[index];
    const ecall_schema_t *es = g_has_ecall_schema[index] ? &g_ecall_schemas[index] : NULL;

    char *copy = strdup(spec);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ";", &saveptr); tok; tok = strtok_r(NULL, ";", &saveptr)) {
        int t_idx = -1, t_seq = -1, p_idx = -1;
        unsigned long off = 0, sub = 0, val = 0;

        if (sscanf(tok, "repeat:%d:%d:%lu", &t_idx, &t_seq, &val) == 3) {
            if (t_idx == index && t_seq == sseq && es) {
                typed_ms_snapshot_t local_snap = {0};
                if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                    uint8_t ms_work[256] = {0};
                    for (unsigned long r = 1; r <= val; r++) {
                        typed_restore_ms_for_replay(&local_snap, es, ms_work);
                        char tag[64];
                        snprintf(tag, sizeof(tag), "generic_repeat_%lu_of_%lu", r, val);
                        execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                    }
                    free_typed_snapshot(&local_snap);
                }
            }
        } else if (sscanf(tok, "xor_param:%d:%d:%d:%lu:%lu", &t_idx, &t_seq, &p_idx, &sub, &val) == 5) {
            /* Alias-preserving, strictly bounded XOR mutation inside a typed snapshot */
            if (t_idx == index && t_seq == sseq && es && p_idx >= 0 && (uint32_t)p_idx < es->num_params) {
                typed_ms_snapshot_t local_snap = {0};
                if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                    uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                    int mrc = mutate_xor_in_snapshot(&local_snap, es, ms_work, (uint32_t)p_idx, sub, (uint8_t)val);
                    if (mrc == 0) {
                        char tag[64];
                        snprintf(tag, sizeof(tag), "schema_xor_p%d_byte_%lu", p_idx, sub);
                        execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                    } else if (mrc != -ERANGE) {
                        mutation_oob_rejected_count++;
                        mark_invalid("mutation_xor_param_schema_error");
                    }
                    free_typed_snapshot(&local_snap);
                } else {
                    mutation_oob_rejected_count++;
                    mark_invalid("xor_param_snapshot_failed");
                }
            }
        } else if (sscanf(tok, "null_param:%d:%d:%d", &t_idx, &t_seq, &p_idx) == 3) {
            if (t_idx == index && t_seq == sseq && es && p_idx >= 0 && (uint32_t)p_idx < es->num_params) {
                const param_schema_t *ps = &es->params[p_idx];
                if (ps->is_pointer) {
                    typed_ms_snapshot_t local_snap = {0};
                    if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                        uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                        typed_restore_ms_for_replay(&local_snap, es, ms_work);
                        *(void **)(ms_work + ps->ms_offset) = NULL;
                        char tag[64];
                        snprintf(tag, sizeof(tag), "schema_null_p%d", p_idx);
                        execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                        free_typed_snapshot(&local_snap);
                    }
                }
            }
        } else if (sscanf(tok, "set_scalar:%d:%d:%d:%lu", &t_idx, &t_seq, &p_idx, &val) == 4) {
            if (t_idx == index && t_seq == sseq && es && p_idx >= 0 && (uint32_t)p_idx < es->num_params) {
                const param_schema_t *ps = &es->params[p_idx];
                if (!ps->is_pointer) {
                    typed_ms_snapshot_t local_snap = {0};
                    if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                        uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                        if (mutate_scalar_and_rebind_buffers(&local_snap, es, ms_work, (uint32_t)p_idx, val) == 0) {
                            char tag[64];
                            snprintf(tag, sizeof(tag), "schema_scalar_p%d_val_%lu", p_idx, val);
                            execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                        } else {
                            mutation_oob_rejected_count++;
                            mark_invalid("mutate_scalar_and_rebind_failed");
                        }
                        free_typed_snapshot(&local_snap);
                    } else {
                        mutation_oob_rejected_count++;
                        mark_invalid("set_scalar_snapshot_failed");
                    }
                }
            }
        } else if (strncmp(tok, "typed_state_probe:", 18) == 0) {
            int tgt_idx = -1, cap_seq = -1, trig_idx = -1, trig_seq = -1;
            if (sscanf(tok, "typed_state_probe:%d:%d:%d:%d", &tgt_idx, &cap_seq, &trig_idx, &trig_seq) == 4) {
                if (index == tgt_idx && sseq == cap_seq && es) {
                    int src = typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &g_state_snaps[tgt_idx]);
                    if (src != 0) {
                        mutation_oob_rejected_count++;
                        mark_invalid("typed_state_probe_snapshot_unsupported");
                    }
                }
            }
        } else if (strncmp(tok, "scale_bound_v2:", 15) == 0) {
            /* Generic schema-typed buffer scaling:
             * scale_bound_v2:<ecall_idx>:<sseq>:<mode>:<cnt1_off>:<new_cnt1>:<cnt2_off>:<new_cnt2>
             * Allocates each bound [in]/[out]/[inout] buffer strictly according to its OWN bound_ms_offset and elem_size!
             */
            int sc_idx = -1, sc_seq = -1, sc_mode = 0;
            long cnt1_off = -1, cnt2_off = -1;
            unsigned long new_cnt1 = 0, new_cnt2 = 0;
            if (sscanf(tok, "scale_bound_v2:%d:%d:%d:%ld:%lu:%ld:%lu",
                       &sc_idx, &sc_seq, &sc_mode, &cnt1_off, &new_cnt1, &cnt2_off, &new_cnt2) == 7) {
                if (sc_idx == index && sc_seq == sseq && es) {
                    if (check_ms_frame_capacity(es, es->ms_size) != 0) {
                        mutation_oob_rejected_count++;
                        mark_invalid("scale_bound_v2_ms_frame_too_large");
                        continue;
                    }
                    uint8_t ms_clone[MAX_MS_FRAME_BYTES] = {0};
                    memcpy(ms_clone, ms, es->ms_size);
                    /* Update scalar count/size slots first */
                    for (uint32_t pi = 0; pi < es->num_params; pi++) {
                        const param_schema_t *ps = &es->params[pi];
                        if (!ps->is_pointer) {
                            if ((long)ps->ms_offset == cnt1_off) {
                                write_scalar_u64(ms_clone, es->ms_size, ps->ms_offset, ps->ms_size, new_cnt1);
                            } else if ((long)ps->ms_offset == cnt2_off && new_cnt2 > 0) {
                                write_scalar_u64(ms_clone, es->ms_size, ps->ms_offset, ps->ms_size, new_cnt2);
                            }
                        }
                    }
                    void *allocs[MAX_SCHEMA_PARAMS] = {0};
                    int alloc_ok = 1;
                    for (uint32_t pi = 0; pi < es->num_params; pi++) {
                        const param_schema_t *ps = &es->params[pi];
                        if (!ps->is_pointer) continue;
                        size_t orig_blen = 0, orig_ulen = 0, new_blen = 0, new_ulen = 0;
                        if (compute_param_byte_len((const uint8_t *)ms, es->ms_size, ps, &orig_blen, &orig_ulen) != 0 ||
                            compute_param_byte_len(ms_clone, es->ms_size, ps, &new_blen, &new_ulen) != 0) {
                            alloc_ok = 0;
                            mutation_oob_rejected_count++;
                            mark_invalid("scale_bound_v2_length_overflow_or_invalid");
                            break;
                        }
                        uint8_t *buf = (uint8_t *)calloc(1, new_blen ? new_blen : 8);
                        if (!buf) {
                            alloc_ok = 0;
                            break;
                        }
                        allocs[pi] = buf;
                        const uint8_t *orig_ptr = *(const uint8_t *const *)((const uint8_t *)ms + ps->ms_offset);
                        if ((ps->direction == DIR_IN || ps->direction == DIR_INOUT) && orig_ptr && orig_blen > 0 && new_blen > 0) {
                            size_t esz = (ps->bound_kind == BOUND_SIZE) ? 1 : (ps->elem_size ? ps->elem_size : 1);
                            size_t orig_elems = orig_blen / esz;
                            size_t new_elems = new_blen / esz;
                            if (orig_elems == 0) orig_elems = 1;
                            for (size_t ei = 0; ei < new_elems; ei++) {
                                for (size_t b = 0; b < esz; b++) {
                                    uint8_t sb = orig_ptr[(ei % orig_elems) * esz + b];
                                    if (sc_mode == 0) {
                                        buf[ei * esz + b] = (uint8_t)((sb + (ei * 2 + 1) * (b + 1)) & 0xff);
                                    } else if (sc_mode == 1) {
                                        buf[ei * esz + b] = sb;
                                    } else {
                                        buf[ei * esz + b] = (uint8_t)(sb ^ 0xaa ^ (ei & 0xff));
                                    }
                                }
                            }
                        }
                        *(void **)(ms_clone + ps->ms_offset) = buf;
                    }
                    if (alloc_ok) {
                        char tag[96];
                        snprintf(tag, sizeof(tag), "schema_scale_cnt_%lu_q_%lu_m_%d", new_cnt1, new_cnt2, sc_mode);
                        execute_one_measured_ecall(eid, index, ocall_table, ms_clone, tag, 1);
                    }
                    for (int pi = 0; pi < MAX_SCHEMA_PARAMS; pi++) free(allocs[pi]);
                }
            }
        } else if (sscanf(tok, "ehsm_sizes:%d", &t_seq) == 1 && index == 2 && sseq == t_seq) {
            const uint32_t sizes[] = {1, 15, 16, 17, 64, 256, 1024, 4096, 6144, 6145};
            for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
                uint32_t plen = sizes[si];
                uint32_t pt_wire_sz = sizeof(uint32_t) + plen;
                uint32_t ct_wire_sz = sizeof(uint32_t) + plen + 28;
                ehsm_data_wire_t *pt = (ehsm_data_wire_t *)calloc(1, pt_wire_sz + 64);
                ehsm_data_wire_t *ct = (ehsm_data_wire_t *)calloc(1, ct_wire_sz + 64);
                ehsm_data_wire_t *dt = (ehsm_data_wire_t *)calloc(1, pt_wire_sz + 64);
                pt->datalen = plen;
                for (uint32_t b = 0; b < plen; b++) pt->data[b] = (uint8_t)(b * 131 + 17);
                ct->datalen = plen + 28;
                dt->datalen = plen;

                uint8_t ms_enc[72];
                memcpy(ms_enc, ms, 72);
                *(void **)(ms_enc + 40) = pt;
                *(uint64_t *)(ms_enc + 48) = pt_wire_sz;
                *(void **)(ms_enc + 56) = ct;
                *(uint64_t *)(ms_enc + 64) = ct_wire_sz;

                char tag[64];
                snprintf(tag, sizeof(tag), "domain_ehsm_encrypt_len_%u", plen);
                execute_one_measured_ecall(eid, 2, ocall_table, ms_enc, tag, 1);

                if (*(int *)ms_enc == 0 && plen <= 6144) {
                    uint8_t ms_dec[72];
                    memcpy(ms_dec, ms_enc, 72);
                    *(void **)(ms_dec + 40) = ct;
                    *(uint64_t *)(ms_dec + 48) = ct_wire_sz;
                    *(void **)(ms_dec + 56) = dt;
                    *(uint64_t *)(ms_dec + 64) = pt_wire_sz;
                    snprintf(tag, sizeof(tag), "domain_ehsm_decrypt_valid_len_%u", plen);
                    execute_one_measured_ecall(eid, 3, ocall_table, ms_dec, tag, 1);

                    if (plen == 1024) {
                        ct->data[plen + 20] ^= 0xFF;
                        snprintf(tag, sizeof(tag), "domain_ehsm_decrypt_bad_tag_len_%u", plen);
                        execute_one_measured_ecall(eid, 3, ocall_table, ms_dec, tag, 1);
                    }
                }
                free(pt);
                free(ct);
                free(dt);
            }
        }
    }
    free(copy);
}

sgx_status_t sgx_ecall(
    sgx_enclave_id_t eid,
    int index,
    const void *ocall_table,
    void *ms)
{
    if (!real_sgx_ecall)
        real_sgx_ecall = (real_ecall_fn_t)dlsym(RTLD_NEXT, "sgx_ecall");

    run_interventions_if_matching(eid, index, ocall_table, ms);
    int sseq = (index >= 0 && index < 64) ? selector_seq[index] : 0;

    /* Support stopping BEFORE host_normal on a one-shot/CALL_ONCE negative probe if requested */
    const char *stop_before_normal = getenv("ATFIELD_STOP_BEFORE_NORMAL_ECALL");
    if (stop_before_normal && *stop_before_normal) {
        int sb_idx = -1, sb_seq = -1;
        if (sscanf(stop_before_normal, "%d:%d", &sb_idx, &sb_seq) == 2 && index == sb_idx && sseq == sb_seq) {
            dump_enclave_vmas_if_requested();
            cleanup_interpose();
            _exit(0);
        }
    }

    sgx_status_t st;
    if (allow_fast_forward && sseq >= 32 && sseq < 995) {
        g_shared->gate_enable = 0;
        fast_forwarded_calls++;
        st = real_sgx_ecall(eid, index, ocall_table, ms);
    } else {
        st = execute_one_measured_ecall(eid, index, ocall_table, ms, "host_normal", 1);
    }

    /* Post-call typed state replay trigger */
    const char *spec_post = getenv("ATFIELD_INTERVENTION");
    if (spec_post && *spec_post) {
        char *cp = strdup(spec_post);
        char *sp = NULL;
        for (char *tk = strtok_r(cp, ";", &sp); tk; tk = strtok_r(NULL, ";", &sp)) {
            int tgt_idx = -1, cap_seq = -1, trig_idx = -1, trig_seq = -1;
            if (sscanf(tk, "typed_state_probe:%d:%d:%d:%d", &tgt_idx, &cap_seq, &trig_idx, &trig_seq) == 4) {
                if (index == trig_idx && sseq == trig_seq &&
                    tgt_idx >= 0 && tgt_idx < MAX_SCHEMA_ECALLS &&
                    g_has_ecall_schema[tgt_idx] && g_state_snaps[tgt_idx].valid) {
                    uint8_t ms_replay[256] = {0};
                    if (typed_restore_ms_for_replay(&g_state_snaps[tgt_idx], &g_ecall_schemas[tgt_idx], ms_replay) == 0) {
                        char tag[64];
                        snprintf(tag, sizeof(tag), "cold_state_replay_ecall_%d_after_%d_%d", tgt_idx, trig_idx, trig_seq);
                        execute_one_measured_ecall(eid, tgt_idx, ocall_table, ms_replay, tag, 1);
                    }
                }
            }
        }
        free(cp);
    }

    const char *stop_after = getenv("ATFIELD_STOP_AFTER_CALL");
    if (stop_after && *stop_after && call_seq >= atoi(stop_after)) {
        dump_enclave_vmas_if_requested();
        cleanup_interpose();
        _exit(0);
    }
    const char *stop_after_sel = getenv("ATFIELD_STOP_AFTER_SELECTOR");
    if (stop_after_sel && *stop_after_sel) {
        int sa_idx = -1, sa_seq = -1;
        if (sscanf(stop_after_sel, "%d:%d", &sa_idx, &sa_seq) == 2 && index == sa_idx && sseq == sa_seq) {
            dump_enclave_vmas_if_requested();
            cleanup_interpose();
            _exit(0);
        }
    }

    call_seq++;
    if (index >= 0 && index < 64) selector_seq[index]++;
    return st;
}

static int vmas_dumped = 0;
static void dump_enclave_vmas_if_requested(void) {
    const char *dump_dir = getenv("ATFIELD_DUMP_DIR");
    if (vmas_dumped || !dump_dir || !*dump_dir || !encl_base || fd_self_mem < 0) return;
    vmas_dumped = 1;
    char path[512];
    snprintf(path, sizeof(path), "%s/meta.txt", dump_dir);
    FILE *mf = fopen(path, "w");
    if (!mf) return;
    fprintf(mf, "BASE 0x%lx\n", (unsigned long)encl_base);
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, "/dev/sgx_enclave") && !strstr(line, "/dev/sgx/enclave"))
            continue;
        uint64_t s, e;
        char p[8];
        if (sscanf(line, "%lx-%lx %7s", &s, &e, p) == 3 && p[0] == 'r') {
            uint64_t lo = s - encl_base, hi = e - encl_base;
            fprintf(mf, "VMA 0x%lx 0x%lx %s\n", (unsigned long)lo, (unsigned long)hi, p);
            if ((hi - lo) == 0x3000 && strcmp(p, "rw-s") == 0) continue;
            size_t sz = (size_t)(hi - lo);
            uint8_t *buf = (uint8_t *)malloc(sz);
            if (buf && pread(fd_self_mem, buf, sz, s) == (ssize_t)sz) {
                char binpath[512];
                snprintf(binpath, sizeof(binpath), "%s/rva_%06lx_%06lx.bin",
                         dump_dir, (unsigned long)lo, (unsigned long)hi);
                FILE *bf = fopen(binpath, "wb");
                if (bf) {
                    fwrite(buf, 1, sz, bf);
                    fclose(bf);
                }
            }
            free(buf);
        }
    }
    fclose(maps);
    fclose(mf);
}

static void cleanup_interpose(void) {
    if (watcher_started) {
        __atomic_store_n(&watcher_stop, 1, __ATOMIC_RELEASE);
        pthread_join(watcher_thread, NULL);
        watcher_started = 0;
    }
    for (int i = 0; i < num_pages; i++) {
        if (pte_slots[i]) *pte_slots[i] = orig_ptes[i];
    }
    encl_base = 0;
    num_pages = 0;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (trace_fp) {
        fflush(trace_fp);
        fclose(trace_fp);
        trace_fp = NULL;
    }
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        lock_fd = -1;
    }
}

sgx_status_t sgx_destroy_enclave(sgx_enclave_id_t eid) {
    if (!real_sgx_destroy_enclave)
        real_sgx_destroy_enclave = (real_destroy_fn_t)dlsym(RTLD_NEXT, "sgx_destroy_enclave");
    dump_enclave_vmas_if_requested();
    cleanup_interpose();
    return real_sgx_destroy_enclave(eid);
}

__attribute__((destructor))
static void on_exit_interpose(void) {
    dump_enclave_vmas_if_requested();
    cleanup_interpose();
}
