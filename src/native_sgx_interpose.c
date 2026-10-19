#include "interpose_state.h"
#include "interpose_4gate_aep.h"
#include "interpose_interventions.h"

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
    if (getenv("ATFIELD_PURE_PROD")) pure_prod_mode = atoi(getenv("ATFIELD_PURE_PROD"));

    parse_schema_spec_env();

    const char *trace_out = getenv("ATFIELD_TRACE_OUT");
    if (trace_out && *trace_out && !trace_fp) {
        trace_fp = fopen(trace_out, "a");
    }

    if (pure_prod_mode) {
        if (!g_shared) {
            void *sh = mmap((void *)GATE_SHARED_VA, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (sh == MAP_FAILED) sh = (void *)GATE_SHARED_VA;
            memset(sh, 0, 4096);
            g_shared = (gate_shared_t *)sh;
        }
        sgx_status_t st_prod = real_sgx_create_enclave(actual_encl, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
        if (st_prod != 0) return st_prod;

        /* Unconditional symmetric initial VMA pre-fault at enclave creation time (outside ECALL timing):
         * Faults all non-excluded REG pages so Raw, No-PreTouch, and Group A/B/C start from identical present leaf PTEs. */
        if (fd_self_mem < 0) fd_self_mem = open("/proc/self/mem", O_RDWR);
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[512];
            uint64_t first = 0;
            typedef struct { uint64_t s, e; char p[8]; } lvma_t;
            lvma_t lvmas[128];
            int nlv = 0;
            uint64_t ltcs = 0;
            while (fgets(line, sizeof(line), fp)) {
                if (!strstr(line, "/dev/sgx_enclave") && !strstr(line, "/dev/sgx/enclave")) continue;
                uint64_t s, e;
                char p[8];
                if (sscanf(line, "%lx-%lx %7s", &s, &e, p) == 3 && nlv < 128) {
                    if (!first) first = s;
                    if ((e - s) == 0x3000 && strcmp(p, "rw-s") == 0) {
                        ltcs = s - first;
                    }
                    lvmas[nlv].s = s; lvmas[nlv].e = e; strncpy(lvmas[nlv].p, p, 7); nlv++;
                }
            }
            fclose(fp);
            uint64_t ex[64][2]; int nex = 0;
            const char *sp = getenv("ATFIELD_LAYOUT_SPEC");
            if (sp) {
                const char *q;
                if (!ltcs && (q = strstr(sp, "tcs="))) ltcs = strtoull(q + 4, NULL, 16);
                if ((q = strstr(sp, "excl="))) {
                    q += 5;
                    while (*q && *q != ';' && nex < 64) {
                        char *m1 = NULL, *m2 = NULL;
                        ex[nex][0] = strtoull(q, &m1, 16);
                        if (!m1 || *m1 != ':') break;
                        ex[nex][1] = strtoull(m1 + 1, &m2, 16);
                        nex++;
                        if (!m2 || *m2 != ',') break;
                        q = m2 + 1;
                    }
                }
            }
            if (ltcs && fd_self_mem >= 0 && first) {
                uint64_t flg = 0;
                if (pread(fd_self_mem, &flg, 8, first + ltcs + 8) == 8) {
                    flg |= 1ULL;
                    pwrite(fd_self_mem, &flg, 8, first + ltcs + 8);
                }
            }
            for (int i = 0; i < nlv; i++) {
                if (lvmas[i].p[0] != 'r') continue;
                int is_w = (strchr(lvmas[i].p, 'w') != NULL);
                for (uint64_t va = lvmas[i].s; va < lvmas[i].e; va += 0x1000) {
                    uint64_t rva = va - first;
                    int skip = (rva == ltcs);
                    for (int k = 0; k < nex; k++) {
                        if (rva >= ex[k][0] && rva < ex[k][1]) { skip = 1; break; }
                    }
                    if (!skip) {
                        if (is_w) {
                            __atomic_fetch_or((volatile uint8_t *)(uintptr_t)va, 0, __ATOMIC_RELAXED);
                        } else {
                            volatile uint8_t b = *(volatile uint8_t *)(uintptr_t)va;
                            (void)b;
                        }
                    }
                }
            }
        }

        const char *ready_path = getenv("ATFIELD_READY_TABLE");
        if (ready_path && *ready_path) {
            set_ready_table_fn_t fn_tbl = (set_ready_table_fn_t)dlsym(RTLD_DEFAULT, "sgx_set_ecall_page_readiness_table");
            set_ready_backend_fn_t fn_be = (set_ready_backend_fn_t)dlsym(RTLD_DEFAULT, "atfield_sgx_set_ecall_page_readiness_backend");
            FILE *rf = fopen(ready_path, "rb");
            if (!rf || !fn_tbl || !fn_be) {
                syscall_error_count++;
                mark_invalid("readiness_open_or_dlsym_failed");
                if (rf) fclose(rf);
            } else {
                fseek(rf, 0, SEEK_END);
                long rsz = ftell(rf);
                fseek(rf, 0, SEEK_SET);
                uint8_t *rbuf = (uint8_t *)malloc((size_t)rsz);
                if (!rbuf || fread(rbuf, 1, (size_t)rsz, rf) != (size_t)rsz) {
                    syscall_error_count++;
                    mark_invalid("readiness_fread_failed");
                } else {
                    sgx_page_readiness_table_t tbl = { .data = rbuf, .size = (size_t)rsz };
                    if (fn_tbl(*enclave_id, &tbl) != 0 || fn_be(*enclave_id, 0U /* ATFIELD_READINESS_BACKEND_KERNEL */) != 0) {
                        syscall_error_count++;
                        mark_invalid("readiness_install_ioctl_failed");
                    }
                }
                free(rbuf);
                fclose(rf);
            }
        }
        return st_prod;
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

    ipi_dummy_prot_rw = 1;
    mprotect((void *)ipi_dummy_page, 4096, PROT_READ | PROT_WRITE);
    *ipi_dummy_page = 1;
    __atomic_store_n(&watcher_ready, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&watcher_stop, 0, __ATOMIC_SEQ_CST);
    if (use_4gate || strict_mode == 2) {
        if (pthread_create(&watcher_thread, NULL, watcher_loop, NULL) != 0) {
            syscall_error_count++;
            mark_invalid("pthread_create_watcher_failed");
        } else {
            while (!__atomic_load_n(&watcher_ready, __ATOMIC_ACQUIRE)) {
                __asm__ volatile("pause");
            }
            watcher_started = 1;
        }
    }

    if (use_4gate || strict_mode == 2) {
        for (int slot = 0; slot < MAX_FIELD_OBS_PER_ECALL; slot++) {
            field_obs_t *o = &cur_obs[slot];
            if (!o->s0_ad) {
                o->s0_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                o->s1_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                o->s2_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
                o->s3_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
            }
        }
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

static uint64_t cur_ecall_acquire_ns = 0;
static uint64_t cur_ecall_release_ns = 0;
typedef int (*real_encl_acq_fn_t)(void *, uint64_t, uint64_t, uint64_t);
typedef int (*real_encl_rel_fn_t)(void *);
static real_encl_acq_fn_t real_encl_acq_fn = NULL;
static real_encl_rel_fn_t real_encl_rel_fn = NULL;

int enclave_pages_acquire(void *base_address, uint64_t selector, uint64_t table_ptr, uint64_t table_bytes) {
    if (!real_encl_acq_fn)
        real_encl_acq_fn = (real_encl_acq_fn_t)dlsym(RTLD_NEXT, "enclave_pages_acquire");
    uint64_t ti0 = monotonic_ns();
    int rc = real_encl_acq_fn(base_address, selector, table_ptr, table_bytes);
    if (__atomic_load_n(&in_measured_ecall, __ATOMIC_RELAXED))
        cur_ecall_acquire_ns += monotonic_ns() - ti0;
    return rc;
}

int enclave_pages_release(void *base_address) {
    if (!real_encl_rel_fn)
        real_encl_rel_fn = (real_encl_rel_fn_t)dlsym(RTLD_NEXT, "enclave_pages_release");
    uint64_t ti0 = monotonic_ns();
    int rc = real_encl_rel_fn(base_address);
    if (__atomic_load_n(&in_measured_ecall, __ATOMIC_RELAXED))
        cur_ecall_release_ns += monotonic_ns() - ti0;
    return rc;
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

    if (use_4gate || strict_mode != 0) {
        for (int i = 0; i < num_pages; i++) {
            checked_flush_tlb(encl_base + page_rvas[i]);
        }
        clear_ad_only();
    }

    cur_ecall_acquire_ns = 0;
    cur_ecall_release_ns = 0;
    __atomic_store_n(&in_measured_ecall, 1, __ATOMIC_SEQ_CST);
    uint64_t t0 = monotonic_ns();
    sgx_status_t st = real_sgx_ecall(eid, index, ocall_table, ms);
    uint64_t elapsed_ns = monotonic_ns() - t0;
    __atomic_store_n(&in_measured_ecall, 0, __ATOMIC_SEQ_CST);
    uint64_t acq_ns = cur_ecall_acquire_ns;
    uint64_t rel_ns = cur_ecall_release_ns;
    uint64_t body_ns = (elapsed_ns > acq_ns + rel_ns) ? (elapsed_ns - acq_ns - rel_ns) : 0;

    if (use_4gate || strict_mode != 0) {
        snapshot_ad(ecall_post_ad);
    } else {
        memset(ecall_post_ad, 0, sizeof(uint64_t) * num_pages);
    }

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
                "\"elapsed_ns\":%" PRIu64 ",\"acquire_ns\":%" PRIu64 ",\"encl_body_ns\":%" PRIu64 ",\"release_ns\":%" PRIu64 ","
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
                elapsed_ns, acq_ns, body_ns, rel_ns,
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

    sgx_status_t st = execute_one_measured_ecall(eid, index, ocall_table, ms, "host_normal", 1);

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
    if (!pure_prod_mode) {
        cpu_set_t sys_set;
        CPU_ZERO(&sys_set);
        CPU_SET(0, &sys_set);
        sched_setaffinity(0, sizeof(sys_set), &sys_set);
    }
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
