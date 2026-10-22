#include "interpose_state.h"
#include "interpose_4gate_aep.h"
#include "interpose_interventions.h"
#include "native_trace_json.h"
#include "interpose_mutation.h"

static int readiness_installed = 0;
static atfield_marshal_spec_t call_marshal_spec;
static atfield_mutation_state_t call_mutation_state;
static atfield_call_capture_t call_capture;
static int mutation_engine_initialized = 0;
static int mutation_engine_requested = 0;
static int mutation_cleanup_done = 0;

#define TRACE_SCHEMA ATFIELD_TRACE_SCHEMA

static int trace_contract_error_reported = 0;

static void trace_note_contract_failure(const char *reason) {
    mark_invalid(reason);
    if (!trace_contract_error_reported) {
        fprintf(stderr, "ATFIELD_TRACE_ERROR:%s\n", reason);
        trace_contract_error_reported = 1;
    }
}

static void trace_note_io_failure(const char *reason) {
    trace_io_failed = 1;
    trace_note_contract_failure(reason);
}

/* A separate, append-only cost journal survives capture parsing failures and
 * records entry before an ECALL that may terminate the process. */
static void journal_lifecycle(const char *event, int selector, uint64_t seq, uint64_t occurrence) {
    const char *destination = getenv("ATFIELD_LIFECYCLE_PATH");
    if (!destination || !*destination) return;
    const int fd = open(destination, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) { trace_note_io_failure("lifecycle_open_failed"); return; }
    char line[256];
    const int length = snprintf(line, sizeof(line),
        "{\"event\":\"%s\",\"generation\":%" PRIu64 ",\"callSeq\":%" PRIu64
        ",\"selectorOrdinal\":%d,\"selectorSeq\":%" PRIu64 "}\n",
        event, instance_generation, seq, selector, occurrence);
    if (length <= 0 || (size_t)length >= sizeof(line) ||
        write(fd, line, (size_t)length) != length)
        trace_note_io_failure("lifecycle_write_failed");
    if (close(fd) != 0) trace_note_io_failure("lifecycle_close_failed");
}

static int trace_printf(const char *fmt, ...) {
    if (!trace_fp || trace_io_failed) return -1;
    va_list ap;
    va_start(ap, fmt);
    int rc = vfprintf(trace_fp, fmt, ap);
    va_end(ap);
    if (rc < 0) {
        trace_note_io_failure("trace_write_failed");
    }
    return rc;
}

static int trace_write_json_string(const char *s) {
    if (!trace_fp || trace_io_failed) return -1;
    if (atfield_json_write_string(trace_fp, s) != 0) {
        trace_note_io_failure("trace_write_failed");
        return -1;
    }
    return 0;
}

static int trace_write_page_effect(uint64_t rva, int a, int d) {
    if (!trace_fp || trace_io_failed) return -1;
    if (atfield_json_write_page_effect(trace_fp, rva, a, d) != 0) {
        trace_note_io_failure("trace_write_failed");
        return -1;
    }
    return 0;
}

static int trace_write_json_env(const char *name) {
    const char *value = getenv(name);
    if (!value) return trace_printf("null");
    return trace_write_json_string(value);
}

static int trace_write_reasons(void) {
    char copy[MAX_TRACE_INCOMPLETE_REASONS][128];
    pthread_mutex_lock(&reason_mutex);
    int count = trace_reason_count;
    memcpy(copy, trace_reasons, sizeof(copy));
    pthread_mutex_unlock(&reason_mutex);
    if (trace_printf("[") < 0) return -1;
    for (int i = 0; i < count; i++) {
        if (i && trace_printf(",") < 0) return -1;
        if (trace_write_json_string(copy[i]) < 0) return -1;
    }
    return trace_printf("]");
}

static int trace_flush_checked(void) {
    if (!trace_fp || trace_io_failed) return -1;
    if (fflush(trace_fp) != 0) {
        trace_note_io_failure("trace_flush_failed");
        return -1;
    }
    return 0;
}

static void mutation_engine_initialize(void) {
    if (mutation_engine_initialized) return;
    mutation_engine_initialized = 1;
    atfield_marshal_spec_init(&call_marshal_spec);
    atfield_mutation_init_disabled(&call_mutation_state);
    memset(&call_capture, 0, sizeof(call_capture));

    const char *capture_path = getenv("ATFIELD_CALL_CAPTURE_PATH");
    const char *mutation_path = getenv("ATFIELD_MUTATION_SPEC_PATH");
    const char *marshal_path = getenv("ATFIELD_MARSHAL_SPEC_PATH");
    const char *bundle_sha = getenv("ATFIELD_BUNDLE_MANIFEST_SHA256");
    const char *marshal_sha = getenv("ATFIELD_MARSHAL_LAYOUT_SHA256");
    const char *edl_abi_sha = getenv("ATFIELD_EDL_ABI_SHA256");
    const int capture_requested = capture_path && *capture_path;
    const int mutation_requested = mutation_path && *mutation_path;
    mutation_engine_requested = capture_requested || mutation_requested;
    if (!mutation_engine_requested) return;

    if (!capture_requested) {
        mark_invalid("call_capture_path_missing");
    }
    if (!marshal_path || !*marshal_path || !bundle_sha || !*bundle_sha ||
        !marshal_sha || !*marshal_sha || !edl_abi_sha || !*edl_abi_sha) {
        mark_invalid("marshal_projection_binding_missing");
    } else if (atfield_marshal_spec_load(&call_marshal_spec, marshal_path,
            bundle_sha, marshal_sha, edl_abi_sha) != 0) {
        mark_invalid(atfield_marshal_spec_error(&call_marshal_spec));
    }

    if (mutation_requested) {
        if (!capture_requested) {
            /* A mutation without its replay evidence cannot be accepted. */
            if (!bundle_sha || !marshal_sha ||
                atfield_mutation_load_spec(&call_mutation_state, mutation_path,
                    bundle_sha, marshal_sha) != 0) {
                const char *reason = atfield_mutation_invalid_reason(&call_mutation_state);
                mark_invalid(reason && *reason ? reason : "mutation_spec_binding_missing");
            } else {
                call_mutation_state.enabled = 0;
                mark_invalid("call_capture_path_missing");
            }
        } else if (!bundle_sha || !marshal_sha) {
            mark_invalid("mutation_spec_binding_missing");
        } else if (atfield_mutation_load_spec(&call_mutation_state, mutation_path,
                       bundle_sha, marshal_sha) != 0) {
            const char *reason = atfield_mutation_invalid_reason(&call_mutation_state);
            mark_invalid(reason && *reason ? reason : "mutation_spec_load_failed");
        }
    }

    if (capture_requested) {
        if (!bundle_sha || !marshal_sha || !getenv("ATFIELD_RUN_ID") ||
            atfield_call_capture_open(&call_capture, capture_path,
                getenv("ATFIELD_RUN_ID"), bundle_sha, marshal_sha) != 0) {
            mark_invalid(call_capture.failure_reason[0] ?
                call_capture.failure_reason : "call_capture_open_failed");
            call_mutation_state.enabled = 0;
        }
    }
}

static int trace_metadata_check(void) {
    static const char *required[] = {
        "ATFIELD_RUN_ID", "ATFIELD_BUNDLE_MANIFEST_SHA256", "ATFIELD_LAYOUT_EPOCH",
        "ATFIELD_SAMPLE", "ATFIELD_MODE", "ATFIELD_ENCLAVE_SHA256"
    };
    trace_metadata_valid = 1;
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        const char *v = getenv(required[i]);
        if (v && *v) continue;
        trace_metadata_valid = 0;
        if (strcmp(required[i], "ATFIELD_RUN_ID") == 0) trace_note_contract_failure("run_id_missing");
        else if (strcmp(required[i], "ATFIELD_BUNDLE_MANIFEST_SHA256") == 0) trace_note_contract_failure("bundle_manifest_sha256_missing");
        else if (strcmp(required[i], "ATFIELD_LAYOUT_EPOCH") == 0) trace_note_contract_failure("layout_epoch_missing");
        else if (strcmp(required[i], "ATFIELD_SAMPLE") == 0) trace_note_contract_failure("sample_missing");
        else if (strcmp(required[i], "ATFIELD_MODE") == 0) trace_note_contract_failure("mode_missing");
        else if (strcmp(required[i], "ATFIELD_ENCLAVE_SHA256") == 0) trace_note_contract_failure("selected_enclave_sha256_missing");
    }
    return trace_metadata_valid;
}

static void trace_emit_run_start(void) {
    if (!trace_fp || trace_started) return;
    trace_metadata_check();
    struct timespec ts = {0, 0};
    char start_time[64] = "";
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        struct tm tm_utc;
        if (gmtime_r(&ts.tv_sec, &tm_utc)) {
            strftime(start_time, sizeof(start_time), "%Y-%m-%dT%H:%M:%S", &tm_utc);
            size_t used = strlen(start_time);
            snprintf(start_time + used, sizeof(start_time) - used, ".%09ldZ", ts.tv_nsec);
        }
    }
    if (!start_time[0]) trace_note_contract_failure("trace_start_time_missing");
    trace_printf("{\"schema\":\"%s\",\"record_type\":\"run_start\",\"run_id\":", TRACE_SCHEMA);
    trace_write_json_env("ATFIELD_RUN_ID");
    trace_printf(",\"layout_epoch\":");
    trace_write_json_env("ATFIELD_LAYOUT_EPOCH");
    trace_printf(",\"bundle_manifest_sha256\":");
    trace_write_json_env("ATFIELD_BUNDLE_MANIFEST_SHA256");
    trace_printf(",\"instance_generation\":null,\"sample\":");
    trace_write_json_env("ATFIELD_SAMPLE");
    trace_printf(",\"mode\":");
    trace_write_json_env("ATFIELD_MODE");
    trace_printf(",\"start_time\":");
    if (start_time[0]) trace_write_json_string(start_time); else trace_printf("null");
    trace_printf(",\"selected_enclave_sha256\":");
    trace_write_json_env("ATFIELD_ENCLAVE_SHA256");
    const char *seed_id = getenv("ATFIELD_SEED_ID");
    if (seed_id && *seed_id) {
        trace_printf(",\"seed_id\":");
        trace_write_json_string(seed_id);
    }
    trace_printf(",\"argv\":[]}\n");
    trace_started = 1;
    trace_flush_checked();
    pthread_mutex_lock(&reason_mutex);
    trace_reason_count = 0;
    last_invalid_reason[0] = '\0';
    pthread_mutex_unlock(&reason_mutex);
}

static int ensure_shared_mapping(void) {
    if (g_shared) return 0;
    void *sh = mmap((void *)GATE_SHARED_VA, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (sh == MAP_FAILED) {
        trace_note_contract_failure("fixed_gate_shared_mmap_failed");
        if (trace_fp) trace_flush_checked();
        return -1;
    }
    memset(sh, 0, 4096);
    g_shared = (gate_shared_t *)sh;
    g_shared_owned = 1;
    return 0;
}

static void collector_atfork_child(void) {
    if (trace_fd >= 0) close(trace_fd);
    if (lock_fd >= 0) close(lock_fd);
    if (fd_self_mem >= 0) close(fd_self_mem);
    if (fd_step >= 0) close(fd_step);
    fd_step = -1;
    extern int fd_mem;
    if (fd_mem >= 0) close(fd_mem);
    fd_mem = -1;
    trace_fd = -1;
    lock_fd = -1;
    fd_self_mem = -1;
    trace_fp = NULL;
    call_capture.fp = NULL;
    call_capture.enabled = 0;
    trace_io_failed = 1;
    trace_started = 1;
    collector_disabled_after_fork = 1;
    use_4gate = 0;
    live_enclave = 0;
    watcher_started = 0;
    num_pages = 0;
    g_shared = NULL;
    ipi_dummy_page = NULL;
    __atomic_store_n(&watcher_stop, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&watcher_ready, 0, __ATOMIC_RELEASE);
}

__attribute__((constructor))
static void register_collector_atfork(void) {
    (void)pthread_atfork(NULL, NULL, collector_atfork_child);
}

static void trace_note_successful_create(void) {
    if (instance_generation == UINT64_MAX) {
        mark_invalid("instance_generation_overflow");
        return;
    }
    instance_generation++;
    journal_lifecycle("enclave_created", -1, 0, 0);
    atfield_reset_selectors(selector_seq);
    const uint64_t want_gen = call_mutation_state.rule.target_generation
        ? call_mutation_state.rule.target_generation : 1u;
    if (call_mutation_state.enabled && instance_generation == want_gen &&
        atfield_mutation_bind_run(&call_mutation_state, live_enclave_id, instance_generation) != 0) {
        const char *reason = atfield_mutation_invalid_reason(&call_mutation_state);
        mark_invalid(reason && *reason ? reason : "mutation_run_binding_failed");
    }
}

static void close_mutation_capture(void);

static int make_current_stack_ready(void) {
    volatile unsigned char stack_marker = 0;
    const uintptr_t stack_addr = (uintptr_t)&stack_marker;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return -1;
    char line[512];
    int result = -1;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3 ||
            strncmp(perms, "rw-p", 4) != 0 ||
            stack_addr < start || stack_addr >= end) continue;
        result = mlock((void *)(uintptr_t)start, (size_t)(end - start));
        break;
    }
    fclose(maps);
    return result;
}

sgx_status_t sgx_create_enclave(
    const char *file_name,
    const int debug,
    void *launch_token,
    int *launch_token_updated,
    sgx_enclave_id_t *enclave_id,
    void *misc_attr)
{
    if (collector_disabled_after_fork) return -1;
    if (!atfield_mutex_try_enter(&collector_mutex)) {
        __atomic_store_n(&pending_concurrent_lifecycle, 1, __ATOMIC_RELEASE);
        static const char err[] = "ATFIELD_TRACE_ERROR:concurrent_create_rejected\n";
        (void)write(STDERR_FILENO, err, sizeof(err) - 1);
        return -1;
    }
    if (!atfield_create_allowed(live_enclave)) {
        trace_note_contract_failure("second_live_enclave_rejected");
        pthread_mutex_unlock(&collector_mutex);
        return -1;
    }
    const uint16_t create_op_type = call_mutation_state.rule.operation_count > 0
        ? call_mutation_state.rule.operations[0].op_type : 0u;
    if (call_mutation_state.enabled &&
        create_op_type != ATFIELD_MUTATION_OP_EXTEND_HISTORY &&
        call_mutation_state.rule.exec_mode >= 1 &&
        call_mutation_state.rule.hit_count > 0 &&
        call_mutation_state.rule.applied) {
        close_mutation_capture();
        pthread_mutex_unlock(&collector_mutex);
        _exit(0);
    }
    if (!real_sgx_create_enclave)
        real_sgx_create_enclave = (real_create_fn_t)dlsym(RTLD_NEXT, "sgx_create_enclave");
    if (!real_sgx_ecall)
        real_sgx_ecall = (real_ecall_fn_t)dlsym(RTLD_NEXT, "sgx_ecall");
    if (!real_sgx_destroy_enclave)
        real_sgx_destroy_enclave = (real_destroy_fn_t)dlsym(RTLD_NEXT, "sgx_destroy_enclave");

    const char *override_encl = getenv("ATFIELD_ENCLAVE_PATH");
    const char *actual_encl = (override_encl && *override_encl) ? override_encl : file_name;

    encl_cpu = atfield_parse_cpu_env(getenv("ATFIELD_ENCL_CPU"));
    watch_cpu = atfield_parse_cpu_env(getenv("ATFIELD_WATCH_CPU"));
    if (getenv("ATFIELD_PURE_PROD")) pure_prod_mode = atoi(getenv("ATFIELD_PURE_PROD"));
    if (pure_prod_mode) use_4gate = 0;
    else use_4gate = 1;
    if (getenv("ATFIELD_USE_4GATE")) use_4gate = atoi(getenv("ATFIELD_USE_4GATE"));
    const char *mode_env = getenv("ATFIELD_MODE");
    if (mode_env && strcmp(mode_env, "verify-pretouch") == 0) {
        ipi_mask = 3;
    } else {
        ipi_mask = 7;
    }
    if (getenv("ATFIELD_IPI_MASK")) ipi_mask = atoi(getenv("ATFIELD_IPI_MASK"));
    if (getenv("ATFIELD_ALLOW_FAST_FORWARD")) allow_fast_forward = atoi(getenv("ATFIELD_ALLOW_FAST_FORWARD"));

    parse_schema_spec_env();

    const char *trace_out = getenv("ATFIELD_TRACE_PATH");
    if (trace_out && *trace_out && !trace_fp) {
        int flags = O_WRONLY | O_CREAT | O_CLOEXEC | (trace_started ? O_APPEND : O_EXCL);
        int trace_fd = open(trace_out, flags, 0644);
        if (trace_fd < 0) {
            trace_note_io_failure(trace_started ? "trace_reopen_failed" : "trace_open_fresh_file_failed");
        } else {
            trace_fp = fdopen(trace_fd, trace_started ? "a" : "w");
            if (!trace_fp) {
                close(trace_fd);
                if (!trace_started) unlink(trace_out);
                trace_note_io_failure("trace_fdopen_failed");
            } else {
                trace_fd = fileno(trace_fp);
                if (!trace_started) trace_emit_run_start();
            }
        }
    } else if (!trace_out || !*trace_out) {
        trace_note_contract_failure("trace_path_missing");
    }

    mutation_engine_initialize();

    if (pure_prod_mode) {
        if (ensure_shared_mapping() != 0) {
            cleanup_interpose();
            pthread_mutex_unlock(&collector_mutex);
            return -1;
        }
        sgx_status_t st_prod = real_sgx_create_enclave(actual_encl, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
        if (st_prod != 0) { cleanup_interpose(); pthread_mutex_unlock(&collector_mutex); return st_prod; }
        live_enclave = 1; live_enclave_id = *enclave_id;
        trace_note_successful_create();

        /* Unconditional symmetric initial VMA pre-fault at enclave creation time (outside ECALL timing):
         * Faults all non-excluded REG pages so Raw, No-PreTouch, and Group A/B/C start from identical present leaf PTEs. */
        if (fd_self_mem < 0) fd_self_mem = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
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

        const char *req_ready_env = getenv("ATFIELD_REQUIRE_READINESS");
        int readiness_req = (req_ready_env && atoi(req_ready_env) != 0);
        const char *ready_path = getenv("ATFIELD_READY_TABLE");
        if (readiness_req && (!ready_path || !*ready_path)) {
            syscall_error_count++;
            mark_invalid("required_ready_table_env_missing");
            if (trace_fp) trace_flush_checked();
            _exit(71);
        }
        if (ready_path && *ready_path) {
            set_ready_table_fn_t fn_tbl = (set_ready_table_fn_t)dlsym(RTLD_DEFAULT, "sgx_set_ecall_page_readiness_table");
            set_ready_backend_fn_t fn_be = (set_ready_backend_fn_t)dlsym(RTLD_DEFAULT, "atfield_sgx_set_ecall_page_readiness_backend");
            FILE *rf = fopen(ready_path, "rb");
            if (!rf || !fn_tbl || !fn_be) {
                syscall_error_count++;
                mark_invalid("readiness_open_or_dlsym_failed");
                if (rf) fclose(rf);
                if (trace_fp) trace_flush_checked();
                _exit(71);
            }
            fseek(rf, 0, SEEK_END);
            long rsz = ftell(rf);
            fseek(rf, 0, SEEK_SET);
            uint8_t *rbuf = (rsz > 0) ? (uint8_t *)malloc((size_t)rsz) : NULL;
            if (!rbuf || fread(rbuf, 1, (size_t)rsz, rf) != (size_t)rsz) {
                free(rbuf);
                fclose(rf);
                syscall_error_count++;
                mark_invalid("readiness_fread_failed");
                if (trace_fp) trace_flush_checked();
                _exit(71);
            }
            fclose(rf);
            sgx_page_readiness_table_t tbl = { .data = rbuf, .size = (size_t)rsz };
            if (fn_tbl(*enclave_id, &tbl) != 0 || fn_be(*enclave_id, 0U /* ATFIELD_READINESS_BACKEND_KERNEL */) != 0) {
                free(rbuf);
                syscall_error_count++;
                mark_invalid("readiness_install_ioctl_failed");
                if (trace_fp) trace_flush_checked();
                _exit(71);
            }
            free(rbuf);
            __atomic_store_n(&readiness_installed, 1, __ATOMIC_SEQ_CST);
        } else {
            __atomic_store_n(&readiness_installed, 0, __ATOMIC_SEQ_CST);
        }
        pthread_mutex_unlock(&collector_mutex);
        return st_prod;
    }

    lock_fd = open("/tmp/atfield_sgxstep.lock", O_CREAT | O_RDWR | O_CLOEXEC, 0666);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        syscall_error_count++;
        mark_invalid("lock_acquire_failed");
    }

    if (fd_self_mem < 0) {
        fd_self_mem = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
        if (fd_self_mem < 0) {
            syscall_error_count++;
            mark_invalid("open_proc_self_mem_failed");
        }
    }

    if (ensure_shared_mapping() != 0) {
        cleanup_interpose();
        pthread_mutex_unlock(&collector_mutex);
        return -1;
    }
    memset((void *)g_shared, 0, 4096);
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
    if (watch_cpu >= 0) {
        CPU_ZERO(&set);
        CPU_SET(watch_cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {
            syscall_error_count++;
            trace_note_contract_failure("main_setaffinity_watch_cpu_failed");
        }
    }

    sgx_status_t st = real_sgx_create_enclave(actual_encl, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
    if (st != 0) { cleanup_interpose(); pthread_mutex_unlock(&collector_mutex); return st; }
    live_enclave = 1; live_enclave_id = *enclave_id;
    trace_note_successful_create();

    setup_enclave_ptes();

    ipi_dummy_prot_rw = 1;
    mprotect((void *)ipi_dummy_page, 4096, PROT_READ | PROT_WRITE);
    *ipi_dummy_page = 1;
    __atomic_store_n(&watcher_ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&watcher_init_failed, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&watcher_stop, 0, __ATOMIC_RELEASE);
    gate_buffers_ready = 0;
    int watcher_required = (use_4gate || strict_mode == 2);
    if (watcher_required) {
        gate_buffers_ready = 1;
        for (int slot = 0; slot < MAX_FIELD_OBS_PER_ECALL; slot++) {
            field_obs_t *o = &cur_obs[slot];
            if (!o->s0_ad) o->s0_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
            if (!o->s1_ad) o->s1_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
            if (!o->s2_ad) o->s2_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
            if (!o->s3_ad) o->s3_ad = (uint64_t *)calloc(MAX_TRACKED_PAGES, sizeof(uint64_t));
            const void *obs_buffers[] = {o->s0_ad, o->s1_ad, o->s2_ad, o->s3_ad};
            if (!atfield_buffers_ready(obs_buffers, sizeof(obs_buffers) / sizeof(obs_buffers[0]))) gate_buffers_ready = 0;
        }
        if (!gate_buffers_ready) {
            for (int slot = 0; slot < MAX_FIELD_OBS_PER_ECALL; slot++) {
                field_obs_t *o = &cur_obs[slot];
                free(o->s0_ad); free(o->s1_ad); free(o->s2_ad); free(o->s3_ad);
                o->s0_ad = o->s1_ad = o->s2_ad = o->s3_ad = NULL;
            }
            use_4gate = 0;
            if (strict_mode == 2) strict_mode = 0;
            mark_invalid("field_observation_buffers_alloc_failed");
        }
    }
    if (encl_cpu < 0 || watch_cpu < 0 || encl_cpu == watch_cpu) {
        trace_note_contract_failure("invalid_or_missing_cpu_configuration");
        use_4gate = 0;
        if (strict_mode == 2) strict_mode = 0;
        watcher_required = 0;
    }
    if (watcher_required && gate_buffers_ready) {
        if (pthread_create(&watcher_thread, NULL, watcher_loop, NULL) != 0) {
            syscall_error_count++;
            trace_note_contract_failure("pthread_create_watcher_failed");
            use_4gate = 0;
            if (strict_mode == 2) strict_mode = 0;
        } else {
            while (!__atomic_load_n(&watcher_ready, __ATOMIC_ACQUIRE) &&
                   !__atomic_load_n(&watcher_init_failed, __ATOMIC_ACQUIRE))
                __asm__ volatile("pause" ::: "memory");
            if (__atomic_load_n(&watcher_init_failed, __ATOMIC_ACQUIRE)) {
                pthread_join(watcher_thread, NULL);
                trace_note_contract_failure("watcher_init_or_setaffinity_failed");
                use_4gate = 0;
                if (strict_mode == 2) strict_mode = 0;
            } else {
                watcher_started = 1;
            }
        }
    }

    if (encl_cpu >= 0 && make_current_stack_ready() != 0) {
        syscall_error_count++;
        trace_note_contract_failure("host_stack_readiness_failed");
        use_4gate = 0;
    }
    if (encl_cpu >= 0) {
        cpu_set_t verify_set;
        CPU_ZERO(&set);
        CPU_ZERO(&verify_set);
        CPU_SET(encl_cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0 ||
            sched_getaffinity(0, sizeof(verify_set), &verify_set) != 0 ||
            CPU_COUNT(&verify_set) != 1 || !CPU_ISSET(encl_cpu, &verify_set)) {
            syscall_error_count++;
            trace_note_contract_failure("encl_setaffinity_failed");
            use_4gate = 0;
        }
    }
    if (ipi_dummy_page) *ipi_dummy_page = 2;
    *(volatile uint8_t *)g_shared = 0;

    pthread_mutex_unlock(&collector_mutex);
    return st;
}

static uint64_t cur_ecall_acquire_ns = 0;
static uint64_t cur_ecall_release_ns = 0;
static int cur_ecall_acquire_calls = 0;
static int cur_ecall_acquire_rc = 0;
static int cur_ecall_release_calls = 0;
static int cur_ecall_release_rc = 0;
typedef int (*real_encl_acq_fn_t)(void *, uint64_t, uint64_t, uint64_t);
typedef int (*real_encl_rel_fn_t)(void *);
static real_encl_acq_fn_t real_encl_acq_fn = NULL;
static real_encl_rel_fn_t real_encl_rel_fn = NULL;

int enclave_pages_acquire(void *base_address, uint64_t selector, uint64_t table_ptr, uint64_t table_bytes) {
    if (!real_encl_acq_fn)
        real_encl_acq_fn = (real_encl_acq_fn_t)dlsym(RTLD_NEXT, "enclave_pages_acquire");
    uint64_t ti0 = monotonic_ns();
    int rc = real_encl_acq_fn(base_address, selector, table_ptr, table_bytes);
    if (__atomic_load_n(&in_measured_ecall, __ATOMIC_RELAXED)) {
        cur_ecall_acquire_ns += monotonic_ns() - ti0;
        cur_ecall_acquire_calls++;
        cur_ecall_acquire_rc = rc;
    }
    if (rc != 0) {
        syscall_error_count++;
        mark_invalid("enclave_pages_acquire_failed");
    }
    return rc;
}

int enclave_pages_release(void *base_address) {
    if (!real_encl_rel_fn)
        real_encl_rel_fn = (real_encl_rel_fn_t)dlsym(RTLD_NEXT, "enclave_pages_release");
    uint64_t ti0 = monotonic_ns();
    int rc = real_encl_rel_fn(base_address);
    if (__atomic_load_n(&in_measured_ecall, __ATOMIC_RELAXED)) {
        cur_ecall_release_ns += monotonic_ns() - ti0;
        cur_ecall_release_calls++;
        cur_ecall_release_rc = rc;
    }
    if (rc != 0) {
        syscall_error_count++;
        mark_invalid("enclave_pages_release_failed");
    }
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
    uint64_t record_seq = 0;
    int record_selector_seq = 0;
    if (atfield_next_u64(&call_seq, &record_seq) != 0) mark_invalid("call_seq_overflow");
    if (atfield_next_selector(selector_seq, index, &record_selector_seq) != 0) {
        mark_invalid("selector_ordinal_out_of_range");
        record_selector_seq = 0;
    }
    pthread_mutex_lock(&phase_mutex);
    cur_obs_count = 0;
    watcher_active_slot = -1;
    obs_truncated = 0;
    cur_fault_count = 0;
    fault_events_truncated = 0;
    pthread_mutex_unlock(&phase_mutex);
    g_shared->host_gate = 0;
    g_shared->current_stage = 0;
    g_shared->active_field_id = 0;
    g_shared->total_aex_count = 0;
    g_shared->gate_ipi_aex_count = 0;
    g_shared->in_gate_spin = 0;
    __atomic_store_n(&gate_a_ipi_aex_count, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&gate_b_ipi_aex_count, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&gate_c_ipi_aex_count, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&unexpected_aex_count, 0, __ATOMIC_RELEASE);
    for (int si = 0; si < 5; si++) __atomic_store_n(&unexpected_stage_aex[si], 0, __ATOMIC_RELEASE);
    __atomic_store_n(&outside_window_aex_count, 0, __ATOMIC_RELEASE);
    for (int si = 0; si < 5; si++) __atomic_store_n(&outside_window_stage_aex[si], 0, __ATOMIC_RELEASE);

    g_shared->gate_enable = (use_4gate && enable_gate_for_this_call) ? 1 : 0;
    uint32_t required_gates = (use_4gate && enable_gate_for_this_call) ? 0x0fu : 0u;
    const char *ecall_mode_env = getenv("ATFIELD_MODE");
    if (!pure_prod_mode && (!use_4gate || !enable_gate_for_this_call)) {
        mark_invalid("four_gate_not_enabled");
    }
    if (!pure_prod_mode && strict_mode == 0 && ecall_mode_env) {
        if (strcmp(ecall_mode_env, "verify-pretouch") == 0 && ipi_mask != 3) {
            mark_invalid("verification_mode_requires_preserve_tlb_ipi_mask_3");
        } else if ((strcmp(ecall_mode_env, "profile") == 0 || strcmp(ecall_mode_env, "explore") == 0) && ipi_mask != 7) {
            mark_invalid("acquisition_mode_requires_c_flush_ipi_mask_7");
        }
    }

    if (ipi_dummy_page) {
        volatile uint8_t d = *ipi_dummy_page;
        (void)d;
    }

    active_strict_selector = -1;
    if (strict_mode != 0) {
        if (strict_config_invalid || index < 0 || index >= 64) {
            strict_config_invalid = 1;
            mark_invalid("strict_selector_out_of_range_or_invalid");
        } else if (strict_selector_has_map[index]) {
            active_strict_selector = index;
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
    cur_ecall_acquire_calls = 0;
    cur_ecall_acquire_rc = 0;
    cur_ecall_release_calls = 0;
    cur_ecall_release_rc = 0;
    atfield_call_capture_record_t capture_record;
    memset(&capture_record, 0, sizeof(capture_record));
    const int capture_active = mutation_engine_initialized &&
        (call_capture.enabled || call_mutation_state.configured || call_mutation_state.invalid);
    const atfield_mutation_layout_t *capture_layout = NULL;
    void *working_ms = NULL;
    int mutation_rc = 0;
    void *call_ms = ms;
    if (capture_active) {
        capture_layout = atfield_marshal_spec_get(&call_marshal_spec, index);
        const uint64_t want_gen = call_mutation_state.rule.target_generation
            ? call_mutation_state.rule.target_generation : 1u;
        if (call_mutation_state.enabled && capture_layout && capture_layout->marshal_size &&
            instance_generation == want_gen &&
            index == call_mutation_state.rule.selector_ordinal &&
            (uint64_t)record_selector_seq == call_mutation_state.rule.occurrence) {
            working_ms = malloc(capture_layout->marshal_size);
        }
        mutation_rc = atfield_mutation_before_ecall(&call_mutation_state, eid,
            instance_generation, record_seq, index, (uint64_t)record_selector_seq,
            capture_layout, ms, working_ms,
            working_ms && capture_layout ? capture_layout->marshal_size : 0,
            &capture_record);
        if (mutation_rc == 1) call_ms = working_ms;
        else if (mutation_rc < 0) {
            const char *reason = atfield_mutation_invalid_reason(&call_mutation_state);
            mark_invalid(reason && *reason ? reason : "native_mutation_rejected");
        }
        if (!capture_record.capture_complete) mark_invalid("call_capture_layout_incomplete");
    }

    if (capture_layout && capture_layout->marshal_size > 0 && call_ms) {
        for (size_t pi = 0; pi < capture_layout->parameter_count; pi++) {
            const atfield_mutation_param_layout_t *p = &capture_layout->parameters[pi];
            if (!p->is_pointer || p->is_user_check) continue;
            uint8_t *uptr = NULL;
            memcpy(&uptr, (const uint8_t *)call_ms + p->ms_offset, sizeof(uptr));
            if (!uptr) continue;
            size_t ulen = 0;
            if (p->is_string) ulen = strnlen((const char *)uptr, 65536u) + 1u;
            else if (p->fixed_array_element_count && p->element_size)
                ulen = (size_t)(p->fixed_array_element_count * p->element_size);
            else if (p->size_source == ATFIELD_MUTATION_BOUND_SOURCE_LITERAL)
                ulen = (size_t)p->size_literal;
            else if (p->count_source == ATFIELD_MUTATION_BOUND_SOURCE_LITERAL && p->element_size)
                ulen = (size_t)(p->count_literal * p->element_size);
            else if (p->size_source == ATFIELD_MUTATION_BOUND_SOURCE_PARAM && p->size_parameter_index < capture_layout->parameter_count) {
                uint64_t sv = 0;
                const atfield_mutation_param_layout_t *bp = &capture_layout->parameters[p->size_parameter_index];
                memcpy(&sv, (const uint8_t *)call_ms + bp->ms_offset, bp->ms_size <= 8 ? bp->ms_size : 8);
                ulen = (size_t)sv;
            } else if (p->count_source == ATFIELD_MUTATION_BOUND_SOURCE_PARAM && p->count_parameter_index < capture_layout->parameter_count && p->element_size) {
                uint64_t cv = 0;
                const atfield_mutation_param_layout_t *bp = &capture_layout->parameters[p->count_parameter_index];
                memcpy(&cv, (const uint8_t *)call_ms + bp->ms_offset, bp->ms_size <= 8 ? bp->ms_size : 8);
                ulen = (size_t)(cv * p->element_size);
            } else if (p->element_size) {
                ulen = p->element_size;
            }
            if (ulen > 0 && ulen <= (16u * 1024u * 1024u)) {
                const int writable = (p->direction == ATFIELD_MUTATION_DIR_OUT || p->direction == ATFIELD_MUTATION_DIR_INOUT);
                for (size_t off = 0; off < ulen; off += 4096u) {
                    volatile uint8_t b = uptr[off];
                    if (writable) ((volatile uint8_t *)uptr)[off] = b;
                }
                volatile uint8_t bend = uptr[ulen - 1u];
                if (writable) ((volatile uint8_t *)uptr)[ulen - 1u] = bend;
            }
        }
    } else if (call_ms) {
        const uintptr_t *words = (const uintptr_t *)call_ms;
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, "/dev/sgx")) continue;
                uintptr_t vs = 0, ve = 0;
                char perms[8] = {0};
                if (sscanf(line, "%lx-%lx %7s", &vs, &ve, perms) != 3) continue;
                if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
                if (vs == (uintptr_t)g_shared || vs == (uintptr_t)ipi_dummy_page) continue;
                for (int wi = 0; wi < 12; wi++) {
                    uintptr_t cand_p = words[wi];
                    if (cand_p >= vs && cand_p < ve && (ve - cand_p) <= (4u * 1024u * 1024u)) {
                        for (uintptr_t a = cand_p & ~(uintptr_t)0xfffu; a < ve; a += 4096u) {
                            volatile uint8_t b = *(volatile uint8_t *)a;
                            *(volatile uint8_t *)a = b;
                        }
                        break;
                    }
                }
            }
            fclose(maps);
        }
    }
    journal_lifecycle("ecall_enter", index, record_seq, (uint64_t)record_selector_seq);
    __atomic_store_n(&in_measured_ecall, 1, __ATOMIC_SEQ_CST);
    uint64_t t0 = monotonic_ns();
    sgx_status_t st = real_sgx_ecall(eid, index, ocall_table, call_ms);
    uint64_t elapsed_ns = monotonic_ns() - t0;
    uint32_t host_gate_at_return = __atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE);
    for (int spin = 0; spin < 100000 &&
         (host_gate_at_return == 10 || host_gate_at_return == 30 || host_gate_at_return == 50 || host_gate_at_return == 70);
         spin++) {
        __asm__ volatile("pause" ::: "memory");
        host_gate_at_return = __atomic_load_n(&g_shared->host_gate, __ATOMIC_ACQUIRE);
    }
    __atomic_store_n(&in_measured_ecall, 0, __ATOMIC_SEQ_CST);
    journal_lifecycle("ecall_return", index, record_seq, (uint64_t)record_selector_seq);
    abi_outcome_t abi_pre = {0, 0};
    int has_out_status_pre = 0;
    int32_t out_status_pre = 0;
    if (index >= 0 && index < MAX_SCHEMA_ECALLS && g_has_ecall_schema[index] && call_ms) {
        const ecall_schema_t *es = &g_ecall_schemas[index];
        read_ecall_abi_outcome((const uint8_t *)call_ms, es->ms_size, es, &abi_pre);
        if (!es->has_retval && es->num_params > 0 && es->params[0].is_pointer &&
            es->params[0].direction == DIR_OUT && es->params[0].elem_size == 4 && es->params[0].static_count == 1) {
            int32_t *sptr = *(int32_t **)((uint8_t *)call_ms + es->params[0].ms_offset);
            if (sptr) {
                has_out_status_pre = 1;
                out_status_pre = *sptr;
            }
        }
    } else if (call_ms) {
        abi_pre.has_retval = 1;
        abi_pre.retval_i64 = *(int32_t *)call_ms;
    }
    if (capture_active) {
        if (atfield_mutation_after_ecall(&call_mutation_state, capture_layout,
                call_ms, ms, &capture_record) != 0)
            mark_invalid("native_mutation_after_ecall_failed");
        if (call_capture.enabled &&
            atfield_call_capture_write_ecall(&call_capture, &capture_record, st) != 0)
            mark_invalid(call_capture.failure_reason[0] ?
                call_capture.failure_reason : "call_capture_write_failed");
    }
    free(working_ms);
    pthread_mutex_lock(&phase_mutex);
    uint32_t req_ipi_mask = (uint32_t)(ipi_mask & 7);
    if (strict_mode == 2 && active_strict_selector >= 0) req_ipi_mask |= 2u;
    int gate_sequence_incomplete = 0;
    if (!required_gates || watcher_active_slot != -1) {
        gate_sequence_incomplete = 1;
    } else if (cur_obs_count == 0) {
        if (host_gate_at_return != 0 || g_shared->current_stage != 0 || g_shared->active_field_id != 0) {
            gate_sequence_incomplete = 1;
        }
    } else {
        if (host_gate_at_return != 80) gate_sequence_incomplete = 1;
        for (int f = 0; f < cur_obs_count; f++) {
            uint32_t vmask = atfield_verified_phase_mask(
                cur_obs[f].gate_mask,
                cur_obs[f].ipi_aex_verified_mask,
                req_ipi_mask,
                cur_obs[f].s3_active_aex_count,
                cur_obs[f].heap_walk_truncated,
                cur_obs[f].heap_pread_failures);
            if (vmask != 0x0fu) {
                gate_sequence_incomplete = 1;
            }
            if ((ipi_mask & 4) != 0 && cur_obs[f].s3_ad) {
                int any_s3_page = 0;
                for (int pi = 0; pi < num_pages; pi++) {
                    if (page_is_pretouch[pi]) continue;
                    if (atfield_rva_excluded_by_gate_range(page_rvas[pi], gate_helper_range_configured, gate_helper_start_rva, gate_helper_end_rva)) continue;
                    if (cur_obs[f].s3_ad[pi] & (A_MASK | D_MASK)) { any_s3_page = 1; break; }
                }
                if (!any_s3_page) {
                    mark_invalid("empty_field_s3_observation");
                    gate_sequence_incomplete = 1;
                }
            }
        }
    }
    if (gate_sequence_incomplete) mark_invalid("required_gate_sequence_incomplete");
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

    /* Use ABI return slot captured from call_ms before working_ms teardown */
    abi_outcome_t abi = abi_pre;
    int has_out_status_ptr = has_out_status_pre;
    int32_t out_status_val = out_status_pre;

    char ms_ret_json[32];
    if (abi.has_retval) {
        snprintf(ms_ret_json, sizeof(ms_ret_json), "%" PRId64, abi.retval_i64);
    } else {
        snprintf(ms_ret_json, sizeof(ms_ret_json), "null");
    }

    if (instance_generation == 0) trace_note_contract_failure("instance_generation_missing");
    if (!trace_metadata_valid) trace_metadata_check();
    if (page_table_truncated) mark_invalid("page_table_truncated");
    if (obs_truncated) mark_invalid("field_observations_truncated");
    if (any_heap_err) mark_invalid("heap_observation_incomplete");
    if (syscall_error_count) mark_invalid("collector_syscall_error");
    if (ipi_flush_failure_count) mark_invalid("ipi_flush_failed");
    if (strict_config_invalid) mark_invalid("strict_configuration_invalid");
    if (mutation_oob_rejected_count) mark_invalid("mutation_rejected");
    if (trace_io_failed) mark_invalid("trace_io_failed");

    int measurement_invalid = (
        syscall_error_count > 0 ||
        ipi_flush_failure_count > 0 ||
        page_table_truncated != 0 ||
        obs_truncated != 0 ||
        strict_config_invalid != 0 ||
        mutation_oob_rejected_count != 0 ||
        any_heap_err != 0 ||
        gate_sequence_incomplete != 0 ||
        !trace_metadata_valid ||
        instance_generation == 0 ||
        trace_io_failed != 0
    ) ? 1 : 0;

    if (__atomic_exchange_n(&pending_concurrent_ecall, 0, __ATOMIC_ACQ_REL))
        mark_invalid("concurrent_ecall_rejected");
    if (__atomic_exchange_n(&pending_concurrent_lifecycle, 0, __ATOMIC_ACQ_REL))
        mark_invalid("concurrent_lifecycle_call_rejected");
    uint32_t total_aex = g_shared ? __atomic_load_n(&g_shared->total_aex_count, __ATOMIC_ACQUIRE) : 0;
    uint32_t gate_aex = g_shared ? __atomic_load_n(&g_shared->gate_ipi_aex_count, __ATOMIC_ACQUIRE) : 0;
    uint32_t gate_a_aex = __atomic_load_n(&gate_a_ipi_aex_count, __ATOMIC_ACQUIRE);
    uint32_t gate_b_aex = __atomic_load_n(&gate_b_ipi_aex_count, __ATOMIC_ACQUIRE);
    uint32_t gate_c_aex = __atomic_load_n(&gate_c_ipi_aex_count, __ATOMIC_ACQUIRE);
    uint32_t unexp_aex = __atomic_load_n(&unexpected_aex_count, __ATOMIC_ACQUIRE);
    uint32_t outside_aex = __atomic_load_n(&outside_window_aex_count, __ATOMIC_ACQUIRE);
    uint32_t unexp_stage[5], outside_stage[5];
    uint32_t unexp_stage_sum = 0, outside_stage_sum = 0;
    for (int si = 0; si < 5; si++) {
        unexp_stage[si] = __atomic_load_n(&unexpected_stage_aex[si], __ATOMIC_ACQUIRE);
        outside_stage[si] = __atomic_load_n(&outside_window_stage_aex[si], __ATOMIC_ACQUIRE);
        unexp_stage_sum += unexp_stage[si];
        outside_stage_sum += outside_stage[si];
    }
    if (unexp_aex > 0 || cur_fault_count != (int)outside_aex ||
        total_aex != gate_aex + unexp_aex + outside_aex ||
        gate_aex != gate_a_aex + gate_b_aex + gate_c_aex ||
        unexp_aex != unexp_stage_sum || outside_aex != outside_stage_sum ||
        (cur_obs_count == 0 && gate_aex > 0)) {
        mark_invalid("unexpected_aex_observed");
        measurement_invalid = 1;
    }
    pthread_mutex_lock(&reason_mutex);
    int has_invalid_reasons = trace_reason_count != 0;
    pthread_mutex_unlock(&reason_mutex);
    measurement_invalid = measurement_invalid || has_invalid_reasons;

    if (trace_fp && !trace_io_failed) {
        trace_printf("{\"schema\":\"%s\",\"record_type\":\"ecall\",\"run_id\":", TRACE_SCHEMA);
        trace_write_json_env("ATFIELD_RUN_ID");
        trace_printf(",\"layout_epoch\":");
        trace_write_json_env("ATFIELD_LAYOUT_EPOCH");
        trace_printf(",\"bundle_manifest_sha256\":");
        trace_write_json_env("ATFIELD_BUNDLE_MANIFEST_SHA256");
        trace_printf(",\"instance_generation\":%" PRIu64 ",\"call_seq\":%" PRIu64, instance_generation, record_seq);
        trace_printf(",\"selector_ordinal\":%d,\"selector_seq\":%d,\"tag\":", index, record_selector_seq);
        trace_write_json_string(tag ? tag : "host_normal");
        trace_printf(",\"elapsed_ns\":%" PRIu64 ",\"sgx_status\":%d,\"abi_return_type\":\"%s\",\"abi_return_value\":%s,\"out_status_i32\":",
                     elapsed_ns, st, abi.has_retval ? "scalar" : "void", abi.has_retval ? ms_ret_json : "null");
        if (has_out_status_ptr) trace_printf("%d", out_status_val); else trace_printf("null");
        trace_printf(",\"measurement_valid\":%s,\"measurement_invalid_reasons\":",
                     measurement_invalid ? "false" : "true");
        trace_write_reasons();
        trace_printf(",\"fields\":[");
        int first_field = 1;
        for (int f = 0; f < cur_obs_count; f++) {
            field_obs_t *first = &cur_obs[f];
            int already_emitted = 0;
            for (int prior = 0; prior < f; prior++)
                if (cur_obs[prior].field_id == first->field_id) { already_emitted = 1; break; }
            if (already_emitted) continue;
            memset(trace_merged_ad, 0, sizeof(trace_merged_ad));
            uint8_t complete[4] = {1, 1, 1, 1};
            for (int j = f; j < cur_obs_count; j++) {
                field_obs_t *obs = &cur_obs[j];
                if (obs->field_id != first->field_id) continue;
                const uint64_t *src[4] = {obs->s0_ad, obs->s1_ad, obs->s2_ad, obs->s3_ad};
                uint32_t vmask = atfield_verified_phase_mask(
                    obs->gate_mask,
                    obs->ipi_aex_verified_mask,
                    req_ipi_mask,
                    obs->s3_active_aex_count,
                    obs->heap_walk_truncated,
                    obs->heap_pread_failures);
                atfield_phase_completeness_merge(complete, vmask, !page_table_truncated && !obs_truncated);
                if (vmask == 0x0fu) {
                    for (int phase = 0; phase < 4; phase++)
                        if (src[phase] && (vmask & (1u << phase)))
                            atfield_or_words(trace_merged_ad[phase], src[phase], (size_t)num_pages);
                }
            }
            trace_printf("%s{\"field_id\":\"0x%016" PRIx64 "\",\"phases\":{",
                         first_field ? "" : ",", first->field_id);
            first_field = 0;
            static const char *phase_names[] = {"S0_BRIDGE", "S1_ENTER", "S2_PRETOUCH", "S3_BODY"};
            for (int gi = 0; gi < 4; gi++) {
                trace_printf("%s\"%s\":{\"page_size\":4096,\"complete\":%s,\"page_effects\":",
                             gi ? "," : "", phase_names[gi], complete[gi] ? "true" : "false");
                int any_snapshot = 0;
                for (int j = f; j < cur_obs_count; j++)
                    if (cur_obs[j].field_id == first->field_id && (cur_obs[j].gate_mask & (1u << gi))) { any_snapshot = 1; break; }
                write_ad_json_array(trace_fp, (complete[gi] && any_snapshot) ? trace_merged_ad[gi] : NULL, 0);
                trace_printf("}");
            }
            trace_printf("}}");
        }
        trace_printf("],\"aex\":{\"count\":%u,\"protocol_gate_count\":%u,\"unexpected_count\":%u,\"outside_window_count\":%u,"
                     "\"by_gate\":{\"GATE_A\":%u,\"GATE_B\":%u,\"GATE_C\":%u},"
                     "\"by_stage\":{"
                     "\"S0_BRIDGE\":{\"protocol_gate\":%u,\"unexpected\":%u,\"outside_window\":%u},"
                     "\"S1_ENTER\":{\"protocol_gate\":%u,\"unexpected\":%u,\"outside_window\":%u},"
                     "\"S2_PRETOUCH\":{\"protocol_gate\":%u,\"unexpected\":%u,\"outside_window\":%u},"
                     "\"S3_BODY\":{\"protocol_gate\":0,\"unexpected\":%u,\"outside_window\":%u},"
                     "\"POST_FIELD\":{\"protocol_gate\":0,\"unexpected\":%u,\"outside_window\":%u}"
                     "},\"fault_events\":[",
                     total_aex, gate_aex, unexp_aex, outside_aex,
                     gate_a_aex, gate_b_aex, gate_c_aex,
                     gate_a_aex, unexp_stage[0], outside_stage[0],
                     gate_b_aex, unexp_stage[1], outside_stage[1],
                     gate_c_aex, unexp_stage[2], outside_stage[2],
                     unexp_stage[3], outside_stage[3],
                     unexp_stage[4], outside_stage[4]);
        for (int fi = 0; fi < cur_fault_count; fi++) {
            fault_event_t *fe = &cur_faults[fi];
            trace_printf("%s{\"aex_seq\":%u,\"page_rva\":\"0x%" PRIx64 "\",\"encl_rip_rva\":\"0x%" PRIx64 "\",\"effective_addr_rva\":\"0x%" PRIx64 "\",\"ea_verified\":%s,\"exitinfo\":\"0x%x\",\"active_flag\":%u,\"active_flag_valid\":%s,\"host_gate\":%u,\"watcher_slot_closed\":%s,\"strict_retractions_clear\":%s,\"outside_window\":%s,\"stage\":",
                         fi ? "," : "", fe->aex_seq, fe->page_rva, fe->encl_rip_rva, fe->effective_addr_rva,
                         fe->ea_verified ? "true" : "false", fe->exitinfo, fe->active_flag,
                         fe->active_flag_valid ? "true" : "false", fe->host_gate,
                         fe->watcher_slot_closed ? "true" : "false",
                         fe->strict_retractions_clear ? "true" : "false",
                         fe->outside_window ? "true" : "false");
            trace_write_json_string(fe->stage);
            trace_printf(",\"pte_healed_observed\":%s,\"confirmed_access_kind\":",
                         fe->pte_healed_observed ? "true" : "false");
            trace_write_json_string(fe->confirmed_access_kind);
            trace_printf(",\"inferred_post_window_kind\":");
            trace_write_json_string(fe->inferred_post_window_kind);
            trace_printf("}");
        }
        trace_printf("]},\"business_result\":{\"status\":");
        if (has_out_status_ptr) trace_printf("%d", out_status_val); else trace_printf("null");
        trace_printf(",\"value\":%s,\"source\":", abi.has_retval ? ms_ret_json : "null");
        trace_write_json_string(has_out_status_ptr ? "out_status_i32" : (abi.has_retval ? "abi_return_value" : "unavailable"));
        trace_printf("}}\n");
        trace_flush_checked();
    }
    pthread_mutex_unlock(&phase_mutex);
    return st;
}

sgx_status_t sgx_ecall(
    sgx_enclave_id_t eid,
    int index,
    const void *ocall_table,
    void *ms)
{
    if (collector_disabled_after_fork) return -1;
    if (!real_sgx_ecall)
        real_sgx_ecall = (real_ecall_fn_t)dlsym(RTLD_NEXT, "sgx_ecall");
    if (!atfield_mutex_try_enter(&collector_mutex)) {
        __atomic_store_n(&pending_concurrent_ecall, 1, __ATOMIC_RELEASE);
        static const char err[] = "ATFIELD_TRACE_ERROR:concurrent_ecall_rejected\n";
        (void)write(STDERR_FILENO, err, sizeof(err) - 1);
        return -1;
    }
    if (!atfield_eid_is_current(live_enclave, live_enclave_id, eid)) {
        trace_note_contract_failure("ecall_for_noncurrent_eid_rejected");
        pthread_mutex_unlock(&collector_mutex);
        return -1;
    }

    int sseq_before = (index >= 0 && index < 64) ? selector_seq[index] : 0;
    int was_replaced = 0;
    sgx_status_t replaced_st = 0;
    if (!mutation_engine_requested) {
        run_interventions_if_matching(eid, index, ocall_table, ms, &was_replaced, &replaced_st);
    } else if (getenv("ATFIELD_INTERVENTION")) {
        mark_invalid("legacy_intervention_conflicts_with_call_capture");
    }
    int sseq = sseq_before;

    /* Support stopping BEFORE host_normal on an isolated probe if requested */
    const char *stop_before_normal = getenv("ATFIELD_STOP_BEFORE_NORMAL_ECALL");
    if (stop_before_normal && *stop_before_normal) {
        int sb_idx = -1, sb_seq = -1;
        if (sscanf(stop_before_normal, "%d:%d", &sb_idx, &sb_seq) == 2 && index == sb_idx && sseq == sb_seq) {
            dump_enclave_vmas_if_requested();
            close_mutation_capture();
            cleanup_interpose();
            pthread_mutex_unlock(&collector_mutex);
            _exit(0);
        }
    }

    const uint64_t want_gen = call_mutation_state.rule.target_generation
        ? call_mutation_state.rule.target_generation : 1u;
    const uint16_t rule_op_type = call_mutation_state.rule.operation_count > 0
        ? call_mutation_state.rule.operations[0].op_type : 0u;
    if (call_mutation_state.enabled &&
        rule_op_type != ATFIELD_MUTATION_OP_EXTEND_HISTORY &&
        call_mutation_state.rule.exec_mode >= 1 &&
        call_mutation_state.rule.hit_count > 0 &&
        call_mutation_state.rule.applied) {
        dump_enclave_vmas_if_requested();
        close_mutation_capture();
        cleanup_interpose();
        pthread_mutex_unlock(&collector_mutex);
        _exit(0);
    }
    if (!was_replaced && call_mutation_state.enabled &&
        rule_op_type == ATFIELD_MUTATION_OP_EXTEND_HISTORY &&
        call_mutation_state.rule.exec_mode >= 1 &&
        instance_generation == want_gen &&
        index == call_mutation_state.rule.selector_ordinal &&
        (uint64_t)sseq == call_mutation_state.rule.occurrence &&
        call_mutation_state.rule.hit_count == 0) {
        const uint8_t rep_cnt = call_mutation_state.rule.exec_mode;
        for (uint8_t r = 0; r < rep_cnt; r++) {
            if (r == 0) {
                (void)execute_one_measured_ecall(eid, index, ocall_table, ms, "mutated_precall", 1);
            } else {
                const atfield_mutation_layout_t *cl = atfield_marshal_spec_get(&call_marshal_spec, index);
                void *sandbox_ms = NULL;
                void *sandbox_bufs[ATFIELD_MUTATION_MAX_PARAMS] = {0};
                int clone_ok = 1;
                if (cl && cl->marshal_size > 0 && ms) {
                    sandbox_ms = malloc(cl->marshal_size);
                    if (!sandbox_ms) clone_ok = 0;
                    else {
                        memcpy(sandbox_ms, ms, cl->marshal_size);
                        for (size_t pi = 0; pi < cl->parameter_count; pi++) {
                            const atfield_mutation_param_layout_t *p = &cl->parameters[pi];
                            if (!p->is_pointer) continue;
                            const uint8_t *optr = NULL;
                            memcpy(&optr, (const uint8_t *)ms + p->ms_offset, sizeof(optr));
                            if (!optr) continue;
                            size_t blen = 0;
                            if (p->is_string) blen = strnlen((const char *)optr, 65536u) + 1u;
                            else if (p->fixed_array_element_count && p->element_size)
                                blen = (size_t)(p->fixed_array_element_count * p->element_size);
                            else if (p->size_source == ATFIELD_MUTATION_BOUND_SOURCE_LITERAL)
                                blen = (size_t)p->size_literal;
                            else if (p->count_source == ATFIELD_MUTATION_BOUND_SOURCE_LITERAL && p->element_size)
                                blen = (size_t)(p->count_literal * p->element_size);
                            else if (p->size_source == ATFIELD_MUTATION_BOUND_SOURCE_PARAM && p->size_parameter_index < cl->parameter_count) {
                                uint64_t sv = 0;
                                const atfield_mutation_param_layout_t *bp = &cl->parameters[p->size_parameter_index];
                                memcpy(&sv, (const uint8_t *)ms + bp->ms_offset, bp->ms_size <= 8 ? bp->ms_size : 8);
                                blen = (size_t)sv;
                            } else if (p->count_source == ATFIELD_MUTATION_BOUND_SOURCE_PARAM && p->count_parameter_index < cl->parameter_count && p->element_size) {
                                uint64_t cv = 0;
                                const atfield_mutation_param_layout_t *bp = &cl->parameters[p->count_parameter_index];
                                memcpy(&cv, (const uint8_t *)ms + bp->ms_offset, bp->ms_size <= 8 ? bp->ms_size : 8);
                                blen = (size_t)(cv * p->element_size);
                            } else if (p->element_size) {
                                blen = p->element_size;
                            }
                            if (blen > 0 && blen <= (1024u * 1024u)) {
                                void *cb = calloc(1, blen);
                                if (!cb) { clone_ok = 0; break; }
                                memcpy(cb, optr, blen);
                                sandbox_bufs[pi] = cb;
                                memcpy((uint8_t *)sandbox_ms + p->ms_offset, &cb, sizeof(cb));
                            }
                        }
                    }
                }
                if (clone_ok) {
                    (void)execute_one_measured_ecall(eid, index, ocall_table,
                        sandbox_ms ? sandbox_ms : ms, "mutated_precall", 1);
                }
                for (size_t pi = 0; pi < ATFIELD_MUTATION_MAX_PARAMS; pi++) free(sandbox_bufs[pi]);
                free(sandbox_ms);
            }
        }
    }
    sgx_status_t st = was_replaced
        ? replaced_st
        : execute_one_measured_ecall(eid, index, ocall_table, ms, "host_normal", 1);

    const char *stop_after = getenv("ATFIELD_STOP_AFTER_CALL");
    if (stop_after && *stop_after && call_seq >= (uint64_t)strtoull(stop_after, NULL, 10)) {
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

    pthread_mutex_unlock(&collector_mutex);
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
        pte_slots[i] = NULL;
        orig_ptes[i] = 0;
        page_rvas[i] = 0;
        page_is_pretouch[i] = 0;
        page_is_exec[i] = 0;
    }
    encl_base = 0;
    encl_size = 0;
    num_pages = 0;
    page_table_truncated = 0;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    restore_urts_aep_hook();
    /* call_capture is closed at process exit in close_mutation_capture() so multi-generation runs stay complete. */
    if (trace_fp) {
        trace_flush_checked();
        if (fclose(trace_fp) != 0) trace_note_io_failure("trace_close_failed");
        trace_fp = NULL;
        trace_fd = -1;
    }
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        lock_fd = -1;
    }
    if (fd_self_mem >= 0) {
        close(fd_self_mem);
        fd_self_mem = -1;
    }
    if (fd_step >= 0) {
        close(fd_step);
        fd_step = -1;
    }
    extern int fd_mem;
    if (fd_mem >= 0) {
        close(fd_mem);
        fd_mem = -1;
    }
    if (ipi_dummy_page) {
        munmap((void *)ipi_dummy_page, 4096);
        ipi_dummy_page = NULL;
    }
    if (g_shared && g_shared_owned) munmap((void *)g_shared, 4096);
    g_shared = NULL;
    g_shared_owned = 0;
    for (int i = 0; i < MAX_FIELD_OBS_PER_ECALL; i++) {
        free(cur_obs[i].s0_ad); free(cur_obs[i].s1_ad); free(cur_obs[i].s2_ad); free(cur_obs[i].s3_ad);
        memset(&cur_obs[i], 0, sizeof(cur_obs[i]));
    }
    cur_obs_count = 0;
    watcher_active_slot = -1;
    gate_buffers_ready = 0;
    watcher_ready = 0;
    watcher_init_failed = 0;
    watcher_stop = 0;
    cur_fault_count = 0;
    fault_events_truncated = 0;
    __atomic_store_n(&readiness_installed, 0, __ATOMIC_RELEASE);
    active_strict_selector = -1;
    for (int i = 0; i < MAX_TRACKED_PAGES; i++) strict_retracted[i] = 0;
}

sgx_status_t sgx_destroy_enclave(sgx_enclave_id_t eid) {
    if (collector_disabled_after_fork) return -1;
    if (!real_sgx_destroy_enclave)
        real_sgx_destroy_enclave = (real_destroy_fn_t)dlsym(RTLD_NEXT, "sgx_destroy_enclave");
    if (!atfield_mutex_try_enter(&collector_mutex)) {
        __atomic_store_n(&pending_concurrent_lifecycle, 1, __ATOMIC_RELEASE);
        static const char err[] = "ATFIELD_TRACE_ERROR:concurrent_destroy_rejected\n";
        (void)write(STDERR_FILENO, err, sizeof(err) - 1);
        return -1;
    }
    if (!atfield_eid_is_current(live_enclave, live_enclave_id, eid)) {
        trace_note_contract_failure("destroy_for_noncurrent_eid_rejected");
        pthread_mutex_unlock(&collector_mutex);
        return -1;
    }
    dump_enclave_vmas_if_requested();
    cleanup_interpose();
    sgx_status_t st = real_sgx_destroy_enclave(eid);
    if (st == 0) {
        live_enclave = 0;
        live_enclave_id = 0;
    } else {
        trace_note_contract_failure("current_eid_destroy_failed");
    }

    pthread_mutex_unlock(&collector_mutex);
    return st;
}

static void close_mutation_capture(void) {
    if (!mutation_cleanup_done && mutation_engine_initialized) {
        mutation_cleanup_done = 1;
        if (atfield_call_capture_close(&call_capture, &call_mutation_state) != 0) {
            const char *reason = atfield_mutation_invalid_reason(&call_mutation_state);
            mark_invalid(reason && *reason ? reason :
                (call_capture.failure_reason[0] ? call_capture.failure_reason :
                 "call_capture_close_failed"));
        }
    }
}

__attribute__((destructor))
static void on_exit_interpose(void) {
    dump_enclave_vmas_if_requested();
    close_mutation_capture();
    cleanup_interpose();
}
