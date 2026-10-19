#ifndef ATFIELD_INTERPOSE_4GATE_AEP_H
#define ATFIELD_INTERPOSE_4GATE_AEP_H

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

    int recorded_strict = 0;
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
                    recorded_strict = 1;
                } else {
                    fault_events_truncated = 1;
                    mark_invalid("fault_events_truncated");
                }
            }
        }
    }
    (void)recorded_strict;
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
    uint64_t vdso_det_va = urts_base + 0x6abd0;
    uint64_t vdso_ptr_va = urts_base + 0x3ec128;
    if (mprotect((void *)(vdso_det_va & ~0xfffULL), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        *(uint8_t *)vdso_det_va = 0xc3;
        __builtin___clear_cache((char *)vdso_det_va, (char *)(vdso_det_va + 1));
    }
    *(uint64_t *)vdso_ptr_va = 0;

    uint64_t aep_va = 0;
    const uint8_t pat[] = {0x0f, 0x01, 0xd7, 0x0f, 0x0b};
    uint64_t cand = urts_base + 0x6aebf;
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
    uint64_t eenterp_va = aep_va - 0x66;
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

static int ipi_dummy_prot_rw = 1;

static int trigger_tlb_shootdown_ipi_verified(void) {
    __atomic_store_n(&g_shared->in_gate_spin, 1, __ATOMIC_SEQ_CST);
    uint32_t before = __atomic_load_n(&g_shared->gate_ipi_aex_count, __ATOMIC_ACQUIRE);
    uint64_t t_start = monotonic_ns();
    int verified = 0;

    while (!__atomic_load_n(&watcher_stop, __ATOMIC_ACQUIRE)) {
        int next_prot = ipi_dummy_prot_rw ? PROT_READ : (PROT_READ | PROT_WRITE);
        if (mprotect((void *)ipi_dummy_page, 4096, next_prot) != 0) {
            syscall_error_count++;
            mark_invalid("mprotect_ipi_failed");
            break;
        }
        ipi_dummy_prot_rw = !ipi_dummy_prot_rw;
        uint64_t round_start = monotonic_ns();
        while (monotonic_ns() - round_start < 1000000ULL) {
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
    /* Wait briefly for CPU 45 to finish returning from on_aex_event before opening gate */
    for (int spin = 0; spin < 200; spin++) {
        __asm__ volatile("pause" ::: "memory");
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

#endif /* ATFIELD_INTERPOSE_4GATE_AEP_H */
