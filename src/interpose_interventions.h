#ifndef ATFIELD_INTERPOSE_INTERVENTIONS_H
#define ATFIELD_INTERPOSE_INTERVENTIONS_H

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
        }
    }
    free(copy);
}

#endif /* ATFIELD_INTERPOSE_INTERVENTIONS_H */
