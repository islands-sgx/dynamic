#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sgx_urts.h>
#include "Enclave_u.h"
#include "libsgxstep/pt.h"

#define GATE_SHARED_VA 0x700000000000ULL

typedef struct {
    volatile uint32_t host_gate;
    volatile uint32_t gate_enable;
    volatile uint64_t use_alt_rsp_in_s2;
    volatile uint64_t saved_rsp;
    volatile uint32_t encl_heartbeat;
} gate_shared_t;

int fd_self_mem = -1;

typedef struct {
    uint64_t rva;
    uint64_t end;
    char perms[8];
} vma_info_t;

static vma_info_t vmas[64];
static int num_vmas = 0;
static uint64_t encl_base = 0;
static uint64_t tcs_rva = 0;
static uint64_t gate_helper_rva = 0x049000;
static volatile uint64_t *pte_slots[4096];
static uint64_t page_rvas[4096];
static const char *page_perms[4096];
static int num_pages = 0;

static gate_shared_t *g_shared = NULL;
static volatile int watcher_ready __attribute__((aligned(4096))) = 0;
static volatile int encl_done __attribute__((aligned(4096))) = 0;
static void *ipi_dummy_page = NULL;
static int ipi_mask = 7;
static uint64_t drop_rva_at_gateA = 0xFFFFFFFFULL;
static uint64_t orig_ptes[4096]; /* bit 0: Gate A IPI, bit 1: Gate B IPI, bit 2: Gate C IPI */

static uint64_t gateA_ad[4096] __attribute__((aligned(4096)));
static uint64_t gateB_ad[4096] __attribute__((aligned(4096)));
static uint64_t gateC_ad[4096] __attribute__((aligned(4096)));
static uint64_t gateD_ad[4096] __attribute__((aligned(4096)));

static void parse_enclave_maps(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    uint64_t first = 0;
    num_vmas = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "/dev/sgx_enclave") && !strstr(line, "/dev/sgx/enclave"))
            continue;
        uint64_t start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
            if (!first) first = start;
            vmas[num_vmas].rva = start - first;
            vmas[num_vmas].end = end - first;
            strncpy(vmas[num_vmas].perms, perms, 7);
            if ((end - start) == 0x3000 && strcmp(perms, "rw-s") == 0)
                tcs_rva = start - first;
            if ((end - start) == 0x4000 && strcmp(perms, "r-xs") == 0)
                gate_helper_rva = (end - first) - 0x1000;
            num_vmas++;
        }
    }
    fclose(fp);
    encl_base = first;
}

static void acquire_and_map_ptes(void) {
    uint64_t flags = 0;
    pread(fd_self_mem, &flags, 8, encl_base + tcs_rva + 8);
    flags |= 1ULL;
    pwrite(fd_self_mem, &flags, 8, encl_base + tcs_rva + 8);
    num_pages = 0;
    for (int i = 0; i < num_vmas; i++) {
        if (vmas[i].perms[0] != 'r') continue;
        for (uint64_t rva = vmas[i].rva; rva < vmas[i].end; rva += 0x1000) {
            volatile uint8_t b = *(volatile uint8_t *)(uintptr_t)(encl_base + rva);
            (void)b;
            address_mapping_t *m = get_mappings((void *)(uintptr_t)(encl_base + rva));
            if (m && PRESENT(m->pmd) && !PMD_PS(m->pmd) && PRESENT(m->pte)) {
                pte_slots[num_pages] = remap(phys_address(m, PTE));
                orig_ptes[num_pages] = *pte_slots[num_pages];
                page_rvas[num_pages] = rva;
                page_perms[num_pages] = vmas[i].perms;
                num_pages++;
            }
            if (m) free(m);
        }
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

static inline void trigger_tlb_shootdown_ipi(void) {
    mprotect(ipi_dummy_page, 4096, PROT_READ);
    mprotect(ipi_dummy_page, 4096, PROT_READ | PROT_WRITE);
    uint32_t hb = __atomic_load_n(&g_shared->encl_heartbeat, __ATOMIC_ACQUIRE);
    while (__atomic_load_n(&g_shared->encl_heartbeat, __ATOMIC_ACQUIRE) == hb &&
           !__atomic_load_n(&encl_done, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause" ::: "memory");
    }
}

static void *watcher_fn(void *arg) {
    (void)arg;
    cpu_set_t set;
    int watch_cpu = getenv("ATFIELD_WATCH_CPU") ? atoi(getenv("ATFIELD_WATCH_CPU")) : 0;
    CPU_ZERO(&set);
    CPU_SET(watch_cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    __atomic_store_n(&watcher_ready, 1, __ATOMIC_RELEASE);

    /* Gate A: end of S0 (before field_enter(2)) */
    while (__atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE) != 10 &&
           !__atomic_load_n(&encl_done, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause" ::: "memory");
    }
    snapshot_ad(gateA_ad);
    if (drop_rva_at_gateA != 0xFFFFFFFFULL) {
        for (int i = 0; i < num_pages; i++) {
            if (page_rvas[i] == drop_rva_at_gateA)
                *pte_slots[i] = 0;
        }
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }
    if (ipi_mask & 1)
        trigger_tlb_shootdown_ipi();
    clear_ad_only();
    __atomic_store_n(&g_shared->host_gate, 20, __ATOMIC_RELEASE);

    /* Gate B: end of S1 (after field_enter(2), before .atfield_pretouch_2) */
    while (__atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE) != 30 &&
           !__atomic_load_n(&encl_done, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause" ::: "memory");
    }
    snapshot_ad(gateB_ad);
    if (ipi_mask & 2)
        trigger_tlb_shootdown_ipi();
    clear_ad_only();
    __atomic_store_n(&g_shared->host_gate, 40, __ATOMIC_RELEASE);

    /* Gate C: end of S2 (after .atfield_pretouch_2, before sample_workload()) */
    while (__atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE) != 50 &&
           !__atomic_load_n(&encl_done, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause" ::: "memory");
    }
    snapshot_ad(gateC_ad);
    if (ipi_mask & 4)
        trigger_tlb_shootdown_ipi();
    clear_ad_only();
    __atomic_store_n(&g_shared->host_gate, 60, __ATOMIC_RELEASE);

    /* Gate D: end of S3 (after sample_workload() + field_exit(2)) */
    while (__atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE) != 70 &&
           !__atomic_load_n(&encl_done, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause" ::: "memory");
    }
    snapshot_ad(gateD_ad);
    if (__atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE) == 70)
        __atomic_store_n(&g_shared->host_gate, 80, __ATOMIC_RELEASE);

    return NULL;
}

static void print_stage(const char *label, const uint64_t *ad) {
    printf("%s:", label);
    for (int i = 0; i < num_pages; i++) {
        if (page_rvas[i] == gate_helper_rva)
            continue; /* dedicated 4-gate spin helper page */
        if (ad[i] & A_MASK)
            printf(" 0x%06lx(%s)", page_rvas[i], (ad[i] & D_MASK) ? "D" : "A");
    }
    printf("\n");
}

/* Manifest of byte patches applied to enclave memory after input(round).
 * File format (whitespace separated, one record per line):
 *   <rva_hex> <hexbytes>
 * e.g. "29620 1100000000000000" writes u64 17 at enclave RVA 0x29620. */
static int apply_patches(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("patch file"); return -1; }
    char line[4096];
    int applied = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '#') { if (*p == '#') goto next; p++; }
        if (*p == '\n' || *p == '\0') continue;
        uint64_t rva = strtoull(p, &p, 16);
        while (*p == ' ' || *p == '\t') p++;
        int n = 0; uint8_t buf[64];
        while (*p && *p != '\n' && *p != ' ' && *p != '\t') {
            unsigned v;
            if (sscanf(p, "%02x", &v) != 1) { fclose(fp); return -1; }
            buf[n++] = (uint8_t)v;
            p += 2;
            if (n >= (int)sizeof(buf)) break;
        }
        if (n > 0) {
            pwrite(fd_self_mem, buf, n, encl_base + rva);
            printf("PATCH rva=0x%06lx bytes=%d\n", (unsigned long)rva, n);
            applied++;
        }
next:   ;
    }
    fclose(fp);
    return applied;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <signed.so> [round_arg] [ipi_mask=0..7] [alt_rsp_s2=0|1] [drop_rva_hex|-] [patch_file|-]\n", argv[0]);
        return 1;
    }
    const char *encl_path = argv[1];
    int round_arg = argc > 2 ? atoi(argv[2]) : 0;
    ipi_mask = argc > 3 ? atoi(argv[3]) : 7;
    int alt_rsp_s2 = argc > 4 ? atoi(argv[4]) : 0;
    if (argc > 5 && strcmp(argv[5], "-")) drop_rva_at_gateA = strtoull(argv[5], NULL, 16);
    const char *patch_file = (argc > 6 && strcmp(argv[6], "-")) ? argv[6] : NULL;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    void *sh = mmap((void *)GATE_SHARED_VA, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (sh == MAP_FAILED) {
        perror("mmap GATE_SHARED_VA");
        return 1;
    }
    memset(sh, 0, 4096);
    g_shared = (gate_shared_t *)sh;
    g_shared->use_alt_rsp_in_s2 = (uint64_t)alt_rsp_s2;

    ipi_dummy_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *(volatile uint8_t *)ipi_dummy_page = 1;

    int lock_fd = open("/tmp/atfield_sgxstep.lock", O_CREAT | O_RDWR, 0666);
    if (lock_fd >= 0) flock(lock_fd, LOCK_EX);
    fd_self_mem = open("/proc/self/mem", O_RDWR);
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    if (sgx_create_enclave(encl_path, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        fprintf(stderr, "sgx_create_enclave failed\n");
        return 1;
    }
    parse_enclave_maps();

    int ret = -1;
    fixture(eid, &ret);
    acquire_and_map_ptes();
    secret(eid, &ret);
    uint8_t out_buf[4112] = {0};
    size_t out_sz = 0;
    if (!getenv("ATFIELD_COLD_CALL") || atoi(getenv("ATFIELD_COLD_CALL")) == 0)
        verification(eid, &ret, out_buf, sizeof(out_buf), &out_sz);
    input(eid, &ret, (uint64_t)round_arg);
    if (patch_file)
        apply_patches(patch_file);

    g_shared->host_gate = 0;
    g_shared->gate_enable = 1;
    __atomic_store_n(&watcher_ready, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&encl_done, 0, __ATOMIC_SEQ_CST);

    pthread_t th;
    pthread_create(&th, NULL, watcher_fn, NULL);
    while (!__atomic_load_n(&watcher_ready, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("pause");
    }

    /* Migrate enclave thread to isolated nohz_full CPU 44 */
    int encl_cpu = getenv("ATFIELD_ENCL_CPU") ? atoi(getenv("ATFIELD_ENCL_CPU")) : 44;
    CPU_ZERO(&set);
    CPU_SET(encl_cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    *(volatile uint8_t *)ipi_dummy_page = 2;
    *(volatile uint8_t *)sh = 0;

    for (int i = 0; i < num_pages; i++) {
        flush_tlb((void *)(uintptr_t)(encl_base + page_rvas[i]));
    }
    clear_ad_only();

    uint64_t cyc = 0;
    sgx_status_t st = timing(eid, &ret, &cyc);
    __atomic_store_n(&encl_done, 1, __ATOMIC_RELEASE);
    pthread_join(th, NULL);

    printf("ROUND=%d ipi_mask=%d alt_rsp_s2=%d st=0x%x ret=%d",
           round_arg, ipi_mask, alt_rsp_s2, st, ret);
    if (alt_rsp_s2 && g_shared->saved_rsp)
        printf(" gateB_rsp_rva=0x%06lx", (unsigned long)(g_shared->saved_rsp - encl_base));
    printf("\n");
    print_stage("  S0(GateA)", gateA_ad);
    print_stage("  S1(GateB)", gateB_ad);
    print_stage("  S2(GateC)", gateC_ad);
    print_stage("  S3(GateD)", gateD_ad);

    for (int i = 0; i < num_pages; i++) *pte_slots[i] = orig_ptes[i];
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    sgx_destroy_enclave(eid);
    return 0;
}
