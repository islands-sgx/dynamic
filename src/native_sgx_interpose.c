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

#define GATE_SHARED_VA 0x700000000000ULL
#define MAX_TRACKED_PAGES 16384
#define MAX_FIELD_OBS_PER_ECALL 128
#define MAX_CHUNKS_PER_OBS 2048
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
    uint64_t page_rva;
    uint64_t encl_rip_rva;
    uint32_t exitinfo;
    uint32_t active_flag;
    char stage[16];
    char access_kind[4]; /* "X", "R", "W" */
    uint64_t healed_pte;
} fault_event_t;

typedef struct {
    uint64_t field_id;
    uint64_t tsc_s2;
    uint64_t tsc_s3;
    uint64_t gateB_rsp_rva;
    uint64_t gateD_rsp_rva;
    uint32_t ipi_aex_verified_mask; /* bit 0=GateA, bit 1=GateB, bit 2=GateC */
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
static char last_invalid_reason[128] = "";

/* Strict readiness state:
 * strict_mode: 0=off, 1=ecall window (EENTER..EEXIT), 2=field window (Gate B..Gate D)
 */
static int strict_mode = 0;
static int strict_config_invalid = 0;
static uint8_t strict_selector_has_map[64];
static uint8_t strict_allowed_page[64][MAX_TRACKED_PAGES];
static volatile uint8_t strict_retracted[MAX_TRACKED_PAGES];
static int active_strict_selector = -1;

static int cur_fault_count = 0;
static int fault_events_truncated = 0;
static fault_event_t cur_faults[MAX_FAULT_EVENTS_PER_ECALL];
static uint32_t s2_end_aex_snapshot = 0;


static uint8_t cached_ms_frame[64][256];
static void *cached_ptr_clones[64][32];
static void *cached_ptr_orig[64][32];
static int cached_ms_valid[64] = {0};

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

/* Called from aep_trampoline on CPU 45 on EVERY hardware AEX (#PF or interrupt) */
void on_aex_event(uint64_t tcs_va, uint64_t rax_mode) {
    if (rax_mode == 2) return;
    (void)tcs_va;
    /* Touch ipi_dummy_page on CPU 45 so CPU 45 always holds ipi_dummy_page in its TLB for future mprotect IPIs */
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

    /* Check if any retracted page (strict_retracted[i] == 1) was just re-populated by kernel sgx_vma_fault */
    for (int i = 0; i < num_pages; i++) {
        if (strict_retracted[i] == 1) {
            uint64_t pte_now = *pte_slots[i];
            if (PRESENT(pte_now)) {
                strict_retracted[i] = 2;
                if (cur_fault_count < MAX_FAULT_EVENTS_PER_ECALL) {
                    fault_event_t *fe = &cur_faults[cur_fault_count++];
                    fe->aex_seq = seq;
                    fe->page_rva = page_rvas[i];
                    fe->encl_rip_rva = rip_rva;
                    fe->exitinfo = exitinfo;
                    fe->active_flag = active_val;
                    snprintf(fe->stage, sizeof(fe->stage), "%s", stage_name_from_code(st_code, active_val, rip_rva));
                    const char *ak = (pte_now & D_MASK) ? "W" : (page_is_exec[i] ? "X" : "R");
                    snprintf(fe->access_kind, sizeof(fe->access_kind), "%s", ak);
                    fe->healed_pte = pte_now;
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

    /* Force libsgx_urts.so.2 to use __morestack + get_aep() instead of vDSO so our AEP trampoline intercepts 100% of AEXs */
    uint64_t urts_base = urts_rx_start - urts_rx_off;
    uint64_t vdso_det_va = urts_base + 0x6a840;
    uint64_t vdso_ptr_va = urts_base + 0x3e8128;
    if (mprotect((void *)(vdso_det_va & ~0xfffULL), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        *(uint8_t *)vdso_det_va = 0xc3; /* retq */
        __builtin___clear_cache((char *)vdso_det_va, (char *)(vdso_det_va + 1));
    }
    *(uint64_t *)vdso_ptr_va = 0;

    /* Locate get_aep pattern: f3 0f 1e fa 48 8d 05 ec ff ff ff c3, preceded at -9 by 0f 01 d7 0f 0b */
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

    /* Map trampoline page within +-1GB of aep_va */
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

    /* Emit trampoline:
     * pushfq (9C)
     * pushq %rbp (55)
     * pushq %rax (50); pushq %rcx (51); pushq %rdx (52); pushq %rsi (56); pushq %rdi (57)
     * pushq %r8 (41 50); pushq %r9 (41 51); pushq %r10 (41 52); pushq %r11 (41 53)
     * movq %rsp, %rbp (48 89 E5)
     * andq $-16, %rsp (48 83 E4 F0)
     * movq %rbx, %rdi (48 89 DF)
     * movabsq $on_aex_event, %rax (48 B8 <u64>)
     * callq *%rax (FF D0)
     * movq %rbp, %rsp (48 89 EC)
     * popq %r11 (41 5B); popq %r10 (41 5A); popq %r9 (41 59); popq %r8 (41 58)
     * popq %rdi (5F); popq %rsi (5E); popq %rdx (5A); popq %rcx (59); popq %rax (58)
     * popq %rbp (5D)
     * popfq (9D)
     * enclu (0F 01 D7)
     * ud2 (0F 0B)
     */
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

/* Trigger cross-core TLB shootdown IPI and verify that CPU 45 actually took an AEX */
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
            if (obs->num_live_chunks < MAX_CHUNKS_PER_OBS) {
                obs->chunk_spans[obs->num_live_chunks][0] = cur;
                obs->chunk_spans[obs->num_live_chunks][1] = cur + sz;
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
    for (int i = 0; i < num_pages; i++) {
        if (strict_retracted[i] == 1) {
            uint64_t pte_now = *pte_slots[i];
            if (PRESENT(pte_now)) {
                /* Catch any PTE re-populated if AEP hook didn't already mark it 2 */
                strict_retracted[i] = 2;
                if (cur_fault_count < MAX_FAULT_EVENTS_PER_ECALL) {
                    fault_event_t *fe = &cur_faults[cur_fault_count++];
                    fe->aex_seq = g_shared ? g_shared->total_aex_count : 0;
                    fe->page_rva = page_rvas[i];
                    fe->encl_rip_rva = 0;
                    fe->exitinfo = 0;
                    fe->active_flag = 0;
                    snprintf(fe->stage, sizeof(fe->stage), "%s", fallback_stage);
                    const char *ak = (pte_now & D_MASK) ? "W" : (page_is_exec[i] ? "X" : "R");
                    snprintf(fe->access_kind, sizeof(fe->access_kind), "%s", ak);
                    fe->healed_pte = pte_now;
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
                /* Field-window strict PTE=0: retract all non-allowed pages at Gate B! */
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

    /* Touch ipi_dummy_page on CPU 45 before EENTER so CPU 45 holds its translation */
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
        /* Ensure PTEs are restored even if ECALL exited early before Gate D */
        disarm_and_check_strict_ptes("EARLY_EXIT_OR_AEX");
    }
    active_strict_selector = -1;

    int measurement_invalid = (
        syscall_error_count > 0 ||
        ipi_flush_failure_count > 0 ||
        page_table_truncated != 0 ||
        obs_truncated != 0 ||
        fault_events_truncated != 0 ||
        strict_config_invalid != 0
    ) ? 1 : 0;

    int retval_i32 = ms ? *(int *)ms : 0;
    if (trace_fp) {
        fprintf(trace_fp,
                "{\"call_seq\":%d,\"ecall_index\":%d,\"selector_seq\":%d,\"tag\":\"%s\","
                "\"sgx_status\":%d,\"ms_retval_i32\":%d,\"elapsed_ns\":%" PRIu64 ","
                "\"total_aex_count\":%u,\"gate_ipi_aex_count\":%u,"
                "\"measurement_invalid\":%d,\"invalid_reason\":\"%s\","
                "\"syscall_errors\":%d,\"ipi_flush_failures\":%d,"
                "\"fast_forwarded_prior\":%d,"
                "\"strict_mode\":%d,\"strict_non_ready_fault_count\":%d,\"fault_events\":[",
                call_seq, index, (index >= 0 && index < 64) ? selector_seq[index] : -1,
                tag ? tag : "normal",
                st, retval_i32, elapsed_ns,
                g_shared->total_aex_count, g_shared->gate_ipi_aex_count,
                measurement_invalid, last_invalid_reason,
                syscall_error_count, ipi_flush_failure_count,
                fast_forwarded_calls,
                strict_enforced_for_call, cur_fault_count);
        for (int fi = 0; fi < cur_fault_count; fi++) {
            fault_event_t *fe = &cur_faults[fi];
            fprintf(trace_fp,
                    "%s{\"aex_seq\":%u,\"page_rva\":\"0x%" PRIx64 "\",\"encl_rip_rva\":\"0x%" PRIx64 "\","
                    "\"exitinfo\":\"0x%x\",\"active_flag\":%u,\"stage\":\"%s\",\"access_kind\":\"%s\","
                    "\"healed_pte\":\"0x%" PRIx64 "\"}",
                    fi ? "," : "", fe->aex_seq, fe->page_rva, fe->encl_rip_rva,
                    fe->exitinfo, fe->active_flag, fe->stage, fe->access_kind, fe->healed_pte);
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

static void dump_enclave_vmas_if_requested(void);
static void cleanup_interpose(void);
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
    if (!spec || !*spec || !ms) return;
    int sseq = (index >= 0 && index < 64) ? selector_seq[index] : 0;

    char *copy = strdup(spec);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ";", &saveptr); tok; tok = strtok_r(NULL, ";", &saveptr)) {
        int t_idx = -1, t_seq = -1;
        unsigned long off = 0, sub = 0, val = 0;
        if (sscanf(tok, "repeat:%d:%d:%lu", &t_idx, &t_seq, &val) == 3) {
            if (t_idx == index && t_seq == sseq) {
                for (unsigned long r = 1; r <= val; r++) {
                    char tag[64];
                    snprintf(tag, sizeof(tag), "generic_repeat_%lu_of_%lu", r, val);
                    execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                }
            }
        } else if (sscanf(tok, "null_ptr:%d:%d:%lu", &t_idx, &t_seq, &off) == 3) {
            if (t_idx == index && t_seq == sseq) {
                void **slot = (void **)((uint8_t *)ms + off);
                void *saved = *slot;
                *slot = NULL;
                char tag[64];
                snprintf(tag, sizeof(tag), "schema_null_off_%lu", off);
                execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                *slot = saved;
            }
        } else if (sscanf(tok, "set_u32:%d:%d:%lu:%lu", &t_idx, &t_seq, &off, &val) == 4) {
            if (t_idx == index && t_seq == sseq) {
                uint32_t *slot = (uint32_t *)((uint8_t *)ms + off);
                uint32_t saved = *slot;
                *slot = (uint32_t)val;
                char tag[64];
                snprintf(tag, sizeof(tag), "schema_u32_off_%lu_val_%lu", off, val);
                execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                *slot = saved;
            }
        } else if (sscanf(tok, "set_u64:%d:%d:%lu:%lu", &t_idx, &t_seq, &off, &val) == 4) {
            if (t_idx == index && t_seq == sseq) {
                uint64_t *slot = (uint64_t *)((uint8_t *)ms + off);
                uint64_t saved = *slot;
                *slot = (uint64_t)val;
                char tag[64];
                snprintf(tag, sizeof(tag), "schema_u64_off_%lu_val_%lu", off, val);
                execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                *slot = saved;
            }
        } else if (sscanf(tok, "xor_buf:%d:%d:%lu:%lu:%lu", &t_idx, &t_seq, &off, &sub, &val) == 5) {
            if (t_idx == index && t_seq == sseq) {
                uint8_t *buf = *(uint8_t **)((uint8_t *)ms + off);
                if (buf) {
                    buf[sub] ^= (uint8_t)val;
                    char tag[64];
                    snprintf(tag, sizeof(tag), "schema_xor_off_%lu_byte_%lu", off, sub);
                    execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                    buf[sub] ^= (uint8_t)val;
                }
            }
        } else if (strncmp(tok, "state_probe:", 12) == 0) {
            int tgt_idx = -1, cap_seq = -1, trig_idx = -1, trig_seq = -1;
            unsigned long ms_sz = 0;
            if (sscanf(tok, "state_probe:%d:%d:%d:%d:%lu", &tgt_idx, &cap_seq, &trig_idx, &trig_seq, &ms_sz) == 5) {
                if (index == tgt_idx && sseq == cap_seq && ms_sz > 0 && ms_sz <= 256 && tgt_idx >= 0 && tgt_idx < 64) {
                    memcpy(cached_ms_frame[tgt_idx], ms, ms_sz);
                    /* Also snapshot every pointer-like 8B slot pointing into user space so buffer contents survive until replay */
                    for (unsigned long off = 0; off + 8 <= ms_sz; off += 8) {
                        uint64_t v = *(uint64_t *)((uint8_t *)ms + off);
                        if (off >= 8 && v > 0x10000ULL && v < 0x7fffffffffffULL && msync((void *)(uintptr_t)(v & ~0xfffULL), 4096, MS_ASYNC) == 0) {
                            void *clone = calloc(1, 8192);
                            if (clone) {
                                uint32_t adj_sz = (off + 12 <= ms_sz) ? *(uint32_t *)((uint8_t *)ms + off + 8) : 128;
                                size_t copy_sz = (adj_sz > 0 && adj_sz <= 8192) ? (size_t)adj_sz : 128;
                                memcpy(clone, (void *)(uintptr_t)v, copy_sz);
                                cached_ptr_clones[tgt_idx][off / 8] = clone;
                                *(void **)(cached_ms_frame[tgt_idx] + off) = clone;
                            }
                        }
                    }
                    cached_ms_valid[tgt_idx] = 1;
                }
            }
        } else if (strncmp(tok, "scale_bound:", 12) == 0) {
            int sc_idx = -1, sc_seq = -1, sc_mode = 0;
            unsigned long ms_sz = 0, cnt_off = 0, cnt_sz = 0, new_cnt = 0, ptr_off = 0, elem_sz = 0;
            unsigned long cnt2_off = 0, cnt2_sz = 0, new_cnt2 = 0, ptr2_off = 0, elem2_sz = 0, out2_off = 0, out2_elem_sz = 0;
            if (sscanf(tok, "scale_bound:%d:%d:%lu:%lu:%lu:%lu:%lu:%lu:%d:%lu:%lu:%lu:%lu:%lu:%lu:%lu",
                       &sc_idx, &sc_seq, &ms_sz, &cnt_off, &cnt_sz, &new_cnt, &ptr_off, &elem_sz, &sc_mode,
                       &cnt2_off, &cnt2_sz, &new_cnt2, &ptr2_off, &elem2_sz, &out2_off, &out2_elem_sz) == 16) {
                /* Generic schema-driven buffer scaling derived purely from edl_schema.json count=/size= bindings */
                if (sc_idx == index && sc_seq == sseq && ms_sz > 0 && ms_sz <= 256) {
                    uint8_t ms_clone[256];
                    memcpy(ms_clone, ms, ms_sz);
                    uint8_t *orig_ptr1 = *(uint8_t **)((uint8_t *)ms + ptr_off);
                    uint64_t orig_cnt1 = (cnt_sz == 8) ? *(uint64_t *)((uint8_t *)ms + cnt_off) : *(uint32_t *)((uint8_t *)ms + cnt_off);
                    size_t alloc1 = (size_t)(new_cnt * elem_sz);
                    uint8_t *buf1 = (uint8_t *)calloc(1, alloc1 ? alloc1 : 64);
                    for (size_t i = 0; i < new_cnt; i++) {
                        for (size_t b = 0; b < elem_sz; b++) {
                            uint8_t seed_b = (orig_ptr1 && orig_cnt1 > 0) ? orig_ptr1[(i % orig_cnt1) * elem_sz + b] : (uint8_t)(i + b);
                            if (sc_mode == 0) {
                                /* Unique strided elements derived from seed */
                                uint64_t v = ((uint64_t)seed_b) + (i * 2 + 1) * (b + 1);
                                buf1[i * elem_sz + b] = (uint8_t)(v & 0xff);
                            } else if (sc_mode == 1) {
                                /* Exact repetition of seed elements (triggers duplicate/collision buckets) */
                                buf1[i * elem_sz + b] = seed_b;
                            } else {
                                /* High-bit / boundary pattern */
                                buf1[i * elem_sz + b] = (uint8_t)(seed_b ^ 0xaa ^ (i & 0xff));
                            }
                        }
                    }
                    *(void **)(ms_clone + ptr_off) = buf1;
                    if (cnt_sz == 8) *(uint64_t *)(ms_clone + cnt_off) = new_cnt;
                    else *(uint32_t *)(ms_clone + cnt_off) = (uint32_t)new_cnt;

                    uint8_t *buf2 = NULL, *out2 = NULL;
                    if (elem2_sz > 0 && new_cnt2 > 0) {
                        buf2 = (uint8_t *)calloc(new_cnt2, elem2_sz);
                        for (size_t i = 0; i < new_cnt2; i++) {
                            if (sc_mode == 1 && elem2_sz == elem_sz && i < new_cnt) {
                                memcpy(buf2 + i * elem2_sz, buf1 + (i % new_cnt) * elem_sz, elem2_sz);
                            } else {
                                for (size_t b = 0; b < elem2_sz; b++)
                                    buf2[i * elem2_sz + b] = (uint8_t)((i * 17 + b * 31) & 0xff);
                            }
                        }
                        *(void **)(ms_clone + ptr2_off) = buf2;
                        if (cnt2_sz == 8) *(uint64_t *)(ms_clone + cnt2_off) = new_cnt2;
                        else *(uint32_t *)(ms_clone + cnt2_off) = (uint32_t)new_cnt2;
                    }
                    if (out2_elem_sz > 0 && new_cnt2 > 0) {
                        out2 = (uint8_t *)calloc(new_cnt2, out2_elem_sz);
                        *(void **)(ms_clone + out2_off) = out2;
                    }
                    char tag[96];
                    snprintf(tag, sizeof(tag), "schema_scale_cnt_%lu_q_%lu_m_%d", new_cnt, new_cnt2, sc_mode);
                    execute_one_measured_ecall(eid, index, ocall_table, ms_clone, tag, 1);
                    free(buf1);
                    free(buf2);
                    free(out2);
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
                *(uint32_t *)(ms_enc + 48) = pt_wire_sz;
                *(void **)(ms_enc + 56) = ct;
                *(uint32_t *)(ms_enc + 64) = ct_wire_sz;

                char tag[64];
                snprintf(tag, sizeof(tag), "domain_ehsm_encrypt_len_%u", plen);
                execute_one_measured_ecall(eid, 2, ocall_table, ms_enc, tag, 1);

                if (*(int *)ms_enc == 0 && plen <= 6144) {
                    uint8_t ms_dec[72];
                    memcpy(ms_dec, ms_enc, 72);
                    *(void **)(ms_dec + 40) = ct;
                    *(uint32_t *)(ms_dec + 48) = ct_wire_sz;
                    *(void **)(ms_dec + 56) = dt;
                    *(uint32_t *)(ms_dec + 64) = pt_wire_sz;
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
        } else if (sscanf(tok, "signal_scales:%d", &t_seq) == 1 && index == 0 && sseq == t_seq) {
            const struct { size_t n_rec; size_t n_q; int mode; const char *name; } cases[] = {
                {16, 16, 0, "domain_scale_16_16_mixed"},
                {128, 64, 0, "domain_scale_128_64_mixed"},
                {512, 128, 1, "domain_scale_512_128_all_hit"},
                {1024, 256, 2, "domain_scale_1024_256_all_miss"},
                {2048, 512, 3, "domain_scale_2048_512_dups"},
                {4096, 1024, 0, "domain_scale_4096_1024_large"},
            };
            for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
                size_t nr = cases[ci].n_rec;
                size_t nq = cases[ci].n_q;
                uint64_t *rec = (uint64_t *)calloc(nr, sizeof(uint64_t));
                uint64_t *qry = (uint64_t *)calloc(nq, sizeof(uint64_t));
                uint8_t *res = (uint8_t *)calloc(nq, 1);
                for (size_t i = 0; i < nr; i++) {
                    rec[i] = (cases[ci].mode == 3) ? (0x10000000ULL + (i % 7)) : (0x10000000ULL + i * 2);
                }
                for (size_t i = 0; i < nq; i++) {
                    if (cases[ci].mode == 1) qry[i] = rec[i % nr];
                    else if (cases[ci].mode == 2) qry[i] = 0x90000000ULL + i;
                    else qry[i] = (i & 1) ? rec[i % nr] : (0x90000000ULL + i);
                }
                uint8_t ms_clone[48];
                memcpy(ms_clone, ms, 48);
                *(void **)(ms_clone + 8) = rec;
                *(size_t *)(ms_clone + 16) = nr;
                *(void **)(ms_clone + 24) = qry;
                *(size_t *)(ms_clone + 32) = nq;
                *(void **)(ms_clone + 40) = res;
                execute_one_measured_ecall(eid, 0, ocall_table, ms_clone, cases[ci].name, 1);
                free(rec);
                free(qry);
                free(res);
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
    sgx_status_t st;
    /* By default (allow_fast_forward == 0), EVERY SINGLE ECALL is measured and checked (no skipping!). */
    if (allow_fast_forward && sseq >= 32 && sseq < 995) {
        g_shared->gate_enable = 0;
        fast_forwarded_calls++;
        st = real_sgx_ecall(eid, index, ocall_table, ms);
    } else {
        st = execute_one_measured_ecall(eid, index, ocall_table, ms, "host_normal", 1);
    }
    const char *spec_post = getenv("ATFIELD_INTERVENTION");
    if (spec_post && *spec_post) {
        char *cp = strdup(spec_post);
        char *sp = NULL;
        for (char *tk = strtok_r(cp, ";", &sp); tk; tk = strtok_r(NULL, ";", &sp)) {
            int tgt_idx = -1, cap_seq = -1, trig_idx = -1, trig_seq = -1;
            unsigned long ms_sz = 0;
            if (sscanf(tk, "state_probe:%d:%d:%d:%d:%lu", &tgt_idx, &cap_seq, &trig_idx, &trig_seq, &ms_sz) == 5) {
                if (index == trig_idx && sseq == trig_seq && tgt_idx >= 0 && tgt_idx < 64 && cached_ms_valid[tgt_idx]) {
                    char tag[64];
                    snprintf(tag, sizeof(tag), "lstar_state_probe_ecall_%d_after_%d_%d", tgt_idx, trig_idx, trig_seq);
                    execute_one_measured_ecall(eid, tgt_idx, ocall_table, cached_ms_frame[tgt_idx], tag, 1);
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
