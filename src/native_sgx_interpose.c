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
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "libsgxstep/pt.h"

#define GATE_SHARED_VA 0x700000000000ULL
#define MAX_TRACKED_PAGES 4096
#define MAX_FIELD_OBS_PER_ECALL 16

typedef uint64_t sgx_enclave_id_t;
typedef int sgx_status_t;

typedef struct {
    volatile uint32_t host_gate;        /* 0x00 */
    volatile uint32_t gate_enable;      /* 0x04 */
    volatile uint64_t use_alt_rsp_in_s2;/* 0x08 */
    volatile uint64_t saved_rsp;        /* 0x10 */
    volatile uint32_t encl_heartbeat;   /* 0x18 */
    volatile uint32_t reserved0;        /* 0x1c */
    volatile uint64_t active_field_id;  /* 0x20 */
    volatile uint64_t tsc_s2_start;     /* 0x28 */
    volatile uint64_t tsc_s2_end;       /* 0x30 */
    volatile uint64_t tsc_s3_start;     /* 0x38 */
    volatile uint64_t tsc_s3_end;       /* 0x40 */
    volatile uint64_t gateD_rsp;        /* 0x48 */
    uint8_t pad[0x100 - 0x50];
    uint64_t scratch_rax;               /* 0x100 */
    uint64_t scratch_rcx;               /* 0x108 */
    uint64_t scratch_rdx;               /* 0x110 */
} gate_shared_t;

typedef struct {
    uint64_t field_id;
    uint64_t tsc_s2;
    uint64_t tsc_s3;
    uint64_t gateB_rsp_rva;
    uint64_t gateD_rsp_rva;
    uint64_t s0_ad[MAX_TRACKED_PAGES];
    uint64_t s1_ad[MAX_TRACKED_PAGES];
    uint64_t s2_ad[MAX_TRACKED_PAGES];
    uint64_t s3_ad[MAX_TRACKED_PAGES];
    uint64_t heap_lo_rva;
    uint64_t heap_hi_rva;
    int num_live_chunks;
    uint64_t chunk_spans[1024][2];
} field_obs_t;

int fd_self_mem = -1;
static int lock_fd = -1;
static FILE *trace_fp = NULL;
static uint64_t encl_base = 0;
static uint64_t encl_size = 0;
static uint64_t tcs_rva = 0;
static uint64_t gm_rva = 0;
static uint64_t pretouch_start_rva = 0;
static uint64_t pretouch_end_rva = 0;
static uint64_t gate_helper_rva = 0;
static uint64_t stack_lo_rva = 0;
static uint64_t stack_hi_rva = 0;
static uint64_t rw_data_va = 0;
static size_t rw_data_sz = 0;

static volatile uint64_t *pte_slots[MAX_TRACKED_PAGES];
static uint64_t orig_ptes[MAX_TRACKED_PAGES];
static uint64_t page_rvas[MAX_TRACKED_PAGES];
static int page_is_pretouch[MAX_TRACKED_PAGES];
static int num_pages = 0;

static gate_shared_t *g_shared = NULL;
static void *ipi_dummy_page = NULL;
static int ipi_mask = 7;
static int use_4gate = 0;
static int encl_cpu = 45;
static int watch_cpu = 1;

static volatile int watcher_ready __attribute__((aligned(4096))) = 0;
static volatile int watcher_stop __attribute__((aligned(4096))) = 0;
static volatile int strict_pte_active __attribute__((aligned(4096))) = 0;
static volatile int strict_pte_restored __attribute__((aligned(4096))) = 0;
static volatile uint64_t strict_call_start_ns __attribute__((aligned(4096))) = 0;
static pthread_t watcher_thread;
static int watcher_started = 0;

static int cur_obs_count = 0;
static field_obs_t cur_obs[MAX_FIELD_OBS_PER_ECALL];
static uint64_t ecall_post_ad[MAX_TRACKED_PAGES];

static uint8_t strict_ready_loaded = 0;
static uint8_t strict_selector_has_map[32];
static uint8_t strict_allowed_page[32][MAX_TRACKED_PAGES];

static int call_seq = 0;
static int selector_seq[64] = {0};

typedef sgx_status_t (*real_create_fn_t)(const char *, int, void *, int *, sgx_enclave_id_t *, void *);
typedef sgx_status_t (*real_ecall_fn_t)(sgx_enclave_id_t, int, const void *, void *);
typedef sgx_status_t (*real_destroy_fn_t)(sgx_enclave_id_t);

static real_create_fn_t real_sgx_create_enclave = NULL;
static real_ecall_fn_t real_sgx_ecall = NULL;
static real_destroy_fn_t real_sgx_destroy_enclave = NULL;

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
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

static inline void trigger_tlb_shootdown_ipi(void) {
    mprotect(ipi_dummy_page, 4096, PROT_READ);
    mprotect(ipi_dummy_page, 4096, PROT_READ | PROT_WRITE);
    uint32_t hb = __atomic_load_n(&g_shared->encl_heartbeat, __ATOMIC_ACQUIRE);
    uint64_t t0 = monotonic_ns();
    while (__atomic_load_n(&g_shared->encl_heartbeat, __ATOMIC_ACQUIRE) == hb &&
           !__atomic_load_n(&watcher_stop, __ATOMIC_ACQUIRE)) {
        if (monotonic_ns() - t0 > 50000000ULL) break;
        __asm__ volatile("pause" ::: "memory");
    }
}

static void walk_dlmalloc_at_gate(field_obs_t *obs) {
    obs->heap_lo_rva = 0;
    obs->heap_hi_rva = 0;
    obs->num_live_chunks = 0;
    if (!gm_rva || fd_self_mem < 0 || !encl_base) return;
    uint8_t mstate_buf[0x40];
    if (pread(fd_self_mem, mstate_buf, sizeof(mstate_buf), encl_base + gm_rva) != sizeof(mstate_buf))
        return;
    uint64_t least_addr = *(uint64_t *)(mstate_buf + 0x18);
    uint64_t top_addr = *(uint64_t *)(mstate_buf + 0x28);
    if (least_addr <= encl_base || top_addr < least_addr || top_addr >= encl_base + encl_size)
        return;
    obs->heap_lo_rva = least_addr - encl_base;
    obs->heap_hi_rva = top_addr - encl_base;
    uint64_t cur = obs->heap_lo_rva;
    int hops = 0;
    while (cur < obs->heap_hi_rva && hops < 4096) {
        uint64_t hdr[2] = {0, 0};
        if (pread(fd_self_mem, hdr, 16, encl_base + cur) != 16)
            break;
        uint64_t sz = hdr[1] & ~7ULL;
        int cinuse = (hdr[1] >> 1) & 1;
        if (sz < 16 || cur + sz > obs->heap_hi_rva + 0x100000)
            break;
        if (cinuse && obs->num_live_chunks < 1024) {
            obs->chunk_spans[obs->num_live_chunks][0] = cur;
            obs->chunk_spans[obs->num_live_chunks][1] = cur + sz;
            obs->num_live_chunks++;
        }
        cur += sz;
        hops++;
    }
}

static void *watcher_loop(void *arg) {
    (void)arg;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(watch_cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    __atomic_store_n(&watcher_ready, 1, __ATOMIC_RELEASE);

    uint64_t tmp_s0[MAX_TRACKED_PAGES];
    uint64_t tmp_s1[MAX_TRACKED_PAGES];
    uint64_t tmp_s2[MAX_TRACKED_PAGES];

    while (!__atomic_load_n(&watcher_stop, __ATOMIC_ACQUIRE)) {
        uint32_t g = __atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE);
        if (g == 10) {
            snapshot_ad(tmp_s0);
            if (ipi_mask & 1) trigger_tlb_shootdown_ipi();
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 20, __ATOMIC_RELEASE);
        } else if (g == 30) {
            snapshot_ad(tmp_s1);
            if (ipi_mask & 2) trigger_tlb_shootdown_ipi();
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 40, __ATOMIC_RELEASE);
        } else if (g == 50) {
            snapshot_ad(tmp_s2);
            if (ipi_mask & 4) trigger_tlb_shootdown_ipi();
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 60, __ATOMIC_RELEASE);
        } else if (g == 70) {
            int slot = cur_obs_count;
            if (slot < MAX_FIELD_OBS_PER_ECALL) {
                field_obs_t *o = &cur_obs[slot];
                o->field_id = g_shared->active_field_id;
                o->tsc_s2 = g_shared->tsc_s2_end - g_shared->tsc_s2_start;
                o->tsc_s3 = g_shared->tsc_s3_end - g_shared->tsc_s3_start;
                o->gateB_rsp_rva = g_shared->saved_rsp ? (g_shared->saved_rsp - encl_base) : 0;
                o->gateD_rsp_rva = g_shared->gateD_rsp ? (g_shared->gateD_rsp - encl_base) : 0;
                memcpy(o->s0_ad, tmp_s0, sizeof(uint64_t) * num_pages);
                memcpy(o->s1_ad, tmp_s1, sizeof(uint64_t) * num_pages);
                memcpy(o->s2_ad, tmp_s2, sizeof(uint64_t) * num_pages);
                snapshot_ad(o->s3_ad);
                walk_dlmalloc_at_gate(o);
                cur_obs_count = slot + 1;
            }
            clear_ad_only();
            __atomic_store_n(&g_shared->host_gate, 80, __ATOMIC_RELEASE);
        } else {
            if (__atomic_load_n(&strict_pte_active, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&strict_pte_restored, __ATOMIC_ACQUIRE)) {
                uint64_t start_ns = __atomic_load_n(&strict_call_start_ns, __ATOMIC_ACQUIRE);
                if (start_ns && monotonic_ns() - start_ns > 2000000000ULL) {
                    for (int i = 0; i < num_pages; i++) {
                        *pte_slots[i] = orig_ptes[i];
                    }
                    __atomic_thread_fence(__ATOMIC_SEQ_CST);
                    __atomic_store_n(&strict_pte_restored, 1, __ATOMIC_RELEASE);
                }
            }
            __asm__ volatile("pause" ::: "memory");
        }
    }
    return NULL;
}

static void setup_enclave_ptes(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    uint64_t first = 0, last = 0;
    typedef struct { uint64_t start, end; char perms[8]; } vma_t;
    vma_t vmas[64];
    int nvmas = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "/dev/sgx_enclave") && !strstr(line, "/dev/sgx/enclave"))
            continue;
        uint64_t s, e;
        char p[8];
        if (sscanf(line, "%lx-%lx %7s", &s, &e, p) == 3) {
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

    uint64_t excl_ranges[32][2];
    int n_excl = 0;
    const char *spec = getenv("ATFIELD_LAYOUT_SPEC");
    if (spec) {
        const char *p;
        if ((p = strstr(spec, "tcs="))) tcs_rva = strtoull(p + 4, NULL, 16);
        if ((p = strstr(spec, "gm="))) gm_rva = strtoull(p + 3, NULL, 16);
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
            while (*p && *p != ';' && n_excl < 32) {
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
        pread(fd_self_mem, &flags, 8, encl_base + tcs_rva + 8);
        flags |= 1ULL;
        pwrite(fd_self_mem, &flags, 8, encl_base + tcs_rva + 8);
    }

    num_pages = 0;
    for (int i = 0; i < nvmas; i++) {
        if (strcmp(vmas[i].perms, "rw-s") == 0 && (vmas[i].end - vmas[i].start) != 0x3000 && rw_data_va == 0) {
            rw_data_va = vmas[i].start;
            rw_data_sz = (size_t)(vmas[i].end - vmas[i].start);
        }
        if (vmas[i].perms[0] != 'r') continue;
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
            if (m && PRESENT(m->pmd) && !PMD_PS(m->pmd) && PRESENT(m->pte) && num_pages < MAX_TRACKED_PAGES) {
                pte_slots[num_pages] = remap(phys_address(m, PTE));
                orig_ptes[num_pages] = *pte_slots[num_pages];
                page_rvas[num_pages] = rva;
                page_is_pretouch[num_pages] = (rva >= pretouch_start_rva && rva < pretouch_end_rva) ? 1 : 0;
                num_pages++;
            }
            if (m) free(m);
        }
    }

    strict_ready_loaded = 0;
    memset(strict_selector_has_map, 0, sizeof(strict_selector_has_map));
    memset(strict_allowed_page, 0, sizeof(strict_allowed_page));
    const char *strict_path = getenv("ATFIELD_STRICT_READY_FILE");
    if (strict_path && *strict_path) {
        FILE *sf = fopen(strict_path, "r");
        if (sf) {
            char sline[65536];
            while (fgets(sline, sizeof(sline), sf)) {
                char *cur = sline;
                char *nxt = NULL;
                unsigned long sel = strtoul(cur, &nxt, 10);
                if (nxt == cur || sel >= 32) continue;
                strict_selector_has_map[sel] = 1;
                strict_ready_loaded = 1;
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
            fclose(sf);
        }
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

    const char *trace_out = getenv("ATFIELD_TRACE_OUT");
    if (trace_out && *trace_out && !trace_fp) {
        trace_fp = fopen(trace_out, "a");
    }

    lock_fd = open("/tmp/atfield_sgxstep.lock", O_CREAT | O_RDWR, 0666);
    if (lock_fd >= 0) flock(lock_fd, LOCK_EX);

    fd_self_mem = open("/proc/self/mem", O_RDWR);

    void *sh = mmap((void *)GATE_SHARED_VA, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (sh == MAP_FAILED) {
        sh = (void *)GATE_SHARED_VA;
    }
    memset(sh, 0, 4096);
    g_shared = (gate_shared_t *)sh;
    if (getenv("ATFIELD_ALT_RSP_S2"))
        g_shared->use_alt_rsp_in_s2 = (uint64_t)atoi(getenv("ATFIELD_ALT_RSP_S2"));

    ipi_dummy_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *(volatile uint8_t *)ipi_dummy_page = 1;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    sgx_status_t st = real_sgx_create_enclave(actual_encl, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
    if (st != 0) return st;

    setup_enclave_ptes();

    __atomic_store_n(&watcher_ready, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&watcher_stop, 0, __ATOMIC_SEQ_CST);
    pthread_create(&watcher_thread, NULL, watcher_loop, NULL);
    while (!__atomic_load_n(&watcher_ready, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }
    watcher_started = 1;

    CPU_ZERO(&set);
    CPU_SET(encl_cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    *(volatile uint8_t *)ipi_dummy_page = 2;
    *(volatile uint8_t *)sh = 0;

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
    g_shared->host_gate = 0;
    g_shared->gate_enable = (use_4gate && enable_gate_for_this_call) ? 1 : 0;

    int apply_strict = (strict_ready_loaded && index >= 0 && index < 32 && strict_selector_has_map[index]);
    if (apply_strict) {
        for (int i = 0; i < num_pages; i++) {
            if (!strict_allowed_page[index][i]) {
                *pte_slots[i] = 0;
            }
        }
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        __atomic_store_n(&strict_pte_restored, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&strict_call_start_ns, monotonic_ns(), __ATOMIC_RELEASE);
        __atomic_store_n(&strict_pte_active, 1, __ATOMIC_RELEASE);
    }

    for (int i = 0; i < num_pages; i++) {
        flush_tlb((void *)(uintptr_t)(encl_base + page_rvas[i]));
    }
    clear_ad_only();

    uint64_t t0 = monotonic_ns();
    sgx_status_t st = real_sgx_ecall(eid, index, ocall_table, ms);
    uint64_t elapsed_ns = monotonic_ns() - t0;

    snapshot_ad(ecall_post_ad);

    int faulted_non_ready = 0;
    if (apply_strict) {
        __atomic_store_n(&strict_call_start_ns, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&strict_pte_active, 0, __ATOMIC_RELEASE);
        faulted_non_ready = __atomic_load_n(&strict_pte_restored, __ATOMIC_ACQUIRE);
        for (int i = 0; i < num_pages; i++) {
            *pte_slots[i] = orig_ptes[i];
        }
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }

    int retval_i32 = ms ? *(int *)ms : 0;
    if (trace_fp) {
        fprintf(trace_fp,
                "{\"call_seq\":%d,\"ecall_index\":%d,\"selector_seq\":%d,\"tag\":\"%s\","
                "\"sgx_status\":%d,\"ms_retval_i32\":%d,\"elapsed_ns\":%" PRIu64 ","
                "\"strict_pte_enforced\":%d,\"strict_non_ready_faulted\":%d,\"ecall_ad\":",
                call_seq, index, selector_seq[index], tag ? tag : "normal",
                st, retval_i32, elapsed_ns, apply_strict, faulted_non_ready);
        write_ad_json_array(trace_fp, ecall_post_ad, 0);
        fprintf(trace_fp, ",\"fields\":[");
        for (int f = 0; f < cur_obs_count; f++) {
            field_obs_t *o = &cur_obs[f];
            fprintf(trace_fp,
                    "%s{\"field_id\":\"0x%016" PRIx64 "\",\"tsc_s2\":%" PRIu64 ",\"tsc_s3\":%" PRIu64 ","
                    "\"gateB_rsp_rva\":\"0x%" PRIx64 "\",\"gateD_rsp_rva\":\"0x%" PRIx64 "\","
                    "\"heap_lo_rva\":\"0x%" PRIx64 "\",\"heap_hi_rva\":\"0x%" PRIx64 "\","
                    "\"live_chunks\":%d,\"s0\":",
                    f ? "," : "", o->field_id, o->tsc_s2, o->tsc_s3,
                    o->gateB_rsp_rva, o->gateD_rsp_rva,
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


static uint8_t *save_rw_data(void) {
    if (!rw_data_va || !rw_data_sz || fd_self_mem < 0) return NULL;
    uint8_t *buf = (uint8_t *)malloc(rw_data_sz);
    if (buf) pread(fd_self_mem, buf, rw_data_sz, rw_data_va);
    return buf;
}
static void restore_rw_data(uint8_t *buf) {
    if (!buf) return;
    if (rw_data_va && rw_data_sz && fd_self_mem >= 0)
        pwrite(fd_self_mem, buf, rw_data_sz, rw_data_va);
    free(buf);
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
    if (!spec || !*spec || !ms) return;
    int sseq = selector_seq[index];

    char *copy = strdup(spec);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ";", &saveptr); tok; tok = strtok_r(NULL, ";", &saveptr)) {
        int t_idx = -1, t_seq = -1;
        unsigned long off = 0, sub = 0, val = 0;
        if (sscanf(tok, "repeat:%d:%d:%lu", &t_idx, &t_seq, &val) == 3) {
            if (t_idx == index && t_seq == sseq) {
                for (unsigned long r = 1; r <= val; r++) {
                    int measure = (r <= 2 || r + 2 >= val);
                    if (measure) {
                        char tag[64];
                        snprintf(tag, sizeof(tag), "repeat_%lu_of_%lu", r, val);
                        execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                    } else {
                        g_shared->gate_enable = 0;
                        real_sgx_ecall(eid, index, ocall_table, ms);
                    }
                }
            }
        } else if (sscanf(tok, "null_ptr:%d:%d:%lu", &t_idx, &t_seq, &off) == 3) {
            if (t_idx == index && t_seq == sseq) {
                void **slot = (void **)((uint8_t *)ms + off);
                void *saved = *slot;
                *slot = NULL;
                char tag[64];
                snprintf(tag, sizeof(tag), "mutate_null_off_%lu", off);
                execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                *slot = saved;
            }
        } else if (sscanf(tok, "set_u32:%d:%d:%lu:%lu", &t_idx, &t_seq, &off, &val) == 4) {
            if (t_idx == index && t_seq == sseq) {
                uint32_t *slot = (uint32_t *)((uint8_t *)ms + off);
                uint32_t saved = *slot;
                *slot = (uint32_t)val;
                char tag[64];
                snprintf(tag, sizeof(tag), "mutate_u32_off_%lu_val_%lu", off, val);
                execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                *slot = saved;
            }
        } else if (sscanf(tok, "xor_buf:%d:%d:%lu:%lu:%lu", &t_idx, &t_seq, &off, &sub, &val) == 5) {
            if (t_idx == index && t_seq == sseq) {
                uint8_t *buf = *(uint8_t **)((uint8_t *)ms + off);
                if (buf) {
                    buf[sub] ^= (uint8_t)val;
                    char tag[64];
                    snprintf(tag, sizeof(tag), "mutate_xor_off_%lu_byte_%lu", off, sub);
                    execute_one_measured_ecall(eid, index, ocall_table, ms, tag, 1);
                    buf[sub] ^= (uint8_t)val;
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
                snprintf(tag, sizeof(tag), "ehsm_encrypt_len_%u", plen);
                execute_one_measured_ecall(eid, 2, ocall_table, ms_enc, tag, 1);

                if (*(int *)ms_enc == 0 && plen <= 6144) {
                    uint8_t ms_dec[72];
                    memcpy(ms_dec, ms_enc, 72);
                    *(void **)(ms_dec + 40) = ct;
                    *(uint32_t *)(ms_dec + 48) = ct_wire_sz;
                    *(void **)(ms_dec + 56) = dt;
                    *(uint32_t *)(ms_dec + 64) = pt_wire_sz;
                    snprintf(tag, sizeof(tag), "ehsm_decrypt_valid_len_%u", plen);
                    execute_one_measured_ecall(eid, 3, ocall_table, ms_dec, tag, 1);

                    if (plen == 1024) {
                        ct->data[plen + 20] ^= 0xFF;
                        snprintf(tag, sizeof(tag), "ehsm_decrypt_bad_tag_len_%u", plen);
                        execute_one_measured_ecall(eid, 3, ocall_table, ms_dec, tag, 1);
                    }
                }
                free(pt);
                free(ct);
                free(dt);
            }
        } else if (sscanf(tok, "signal_scales:%d", &t_seq) == 1 && index == 0 && sseq == t_seq) {
            const struct { size_t n_rec; size_t n_q; int mode; const char *name; } cases[] = {
                {16, 16, 0, "scale_16_16_mixed"},
                {128, 64, 0, "scale_128_64_mixed"},
                {512, 128, 1, "scale_512_128_all_hit"},
                {1024, 256, 2, "scale_1024_256_all_miss"},
                {2048, 512, 3, "scale_2048_512_dups"},
                {4096, 1024, 0, "scale_4096_1024_large"},
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
    if (sseq >= 32 && sseq < 995 && !getenv("ATFIELD_MEASURE_ALL")) {
        g_shared->gate_enable = 0;
        st = real_sgx_ecall(eid, index, ocall_table, ms);
    } else {
        st = execute_one_measured_ecall(eid, index, ocall_table, ms, "host_normal", 1);
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
