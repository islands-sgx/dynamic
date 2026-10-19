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
    void *ms,
    int *out_was_replaced,
    sgx_status_t *out_replaced_status)
{
    if (out_was_replaced) *out_was_replaced = 0;
    if (out_replaced_status) *out_replaced_status = 0;
    const char *spec = getenv("ATFIELD_INTERVENTION");
    if (!spec || !*spec || !ms || index < 0 || index >= MAX_SCHEMA_ECALLS) return;
    int sseq = selector_seq[index];
    const ecall_schema_t *es = g_has_ecall_schema[index] ? &g_ecall_schemas[index] : NULL;

    char *copy = strdup(spec);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ";", &saveptr); tok; tok = strtok_r(NULL, ";", &saveptr)) {
        int t_idx = -1, t_seq = -1, p_idx = -1, p_idx2 = -1;
        unsigned long sub = 0, val = 0, val2 = 0;

        if (sscanf(tok, "repeat:%d:%d:%lu", &t_idx, &t_seq, &val) == 3) {
            if (t_idx == index && t_seq == sseq && es) {
                typed_ms_snapshot_t local_snap = {0};
                if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                    uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
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
        } else if (sscanf(tok, "replace_scalar:%d:%d:%d:%lu", &t_idx, &t_seq, &p_idx, &val) == 4) {
            /* In-place call replacement:
             * - Modifies scalar parameter p_idx at (t_idx, t_seq)
             * - Refuses if any [out]/[inout] buffer bound would exceed the host's allocated capacity
             * - Executes the ECALL ONCE, writing [out]/[inout] data and ms_retval directly back to the host's ms!
             */
            if (t_idx == index && t_seq == sseq && es && p_idx >= 0 && (uint32_t)p_idx < es->num_params) {
                const param_schema_t *ps = &es->params[p_idx];
                if (!ps->is_pointer && check_ms_frame_capacity(es, es->ms_size) == 0) {
                    uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                    memcpy(ms_work, ms, es->ms_size);
                    if (write_scalar_u64(ms_work, es->ms_size, ps->ms_offset, ps->ms_size, val) == 0) {
                        int cap_ok = 1;
                        void *in_allocs[MAX_SCHEMA_PARAMS] = {0};
                        for (uint32_t pi = 0; pi < es->num_params; pi++) {
                            const param_schema_t *ppi = &es->params[pi];
                            if (!ppi->is_pointer) continue;
                            size_t orig_b = 0, orig_u = 0, new_b = 0, new_u = 0;
                            if (compute_param_byte_len((const uint8_t *)ms, es->ms_size, ppi, &orig_b, &orig_u) != 0 ||
                                compute_param_byte_len(ms_work, es->ms_size, ppi, &new_b, &new_u) != 0) {
                                cap_ok = 0;
                                break;
                            }
                            if (new_b > orig_b) {
                                if (ppi->direction == DIR_OUT || ppi->direction == DIR_INOUT) {
                                    /* Host output buffer capacity cannot accommodate enlarged output */
                                    cap_ok = 0;
                                    break;
                                }
                                /* Pure [in] buffer can be safely reallocated for the single replaced call */
                                uint8_t *nbuf = (uint8_t *)calloc(1, new_b ? new_b : 8);
                                if (!nbuf) { cap_ok = 0; break; }
                                const uint8_t *optr = *(const uint8_t *const *)((const uint8_t *)ms + ppi->ms_offset);
                                if (optr && orig_b > 0) memcpy(nbuf, optr, orig_b);
                                in_allocs[pi] = nbuf;
                                *(void **)(ms_work + ppi->ms_offset) = nbuf;
                            }
                        }
                        if (cap_ok) {
                            char tag[72];
                            snprintf(tag, sizeof(tag), "replace_scalar_p%d_val_%lu", p_idx, val);
                            sgx_status_t rst = execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                            if (es->has_retval && (size_t)es->retval_offset + (size_t)es->retval_size <= es->ms_size) {
                                memcpy((uint8_t *)ms + es->retval_offset, ms_work + es->retval_offset, es->retval_size);
                            }
                            if (out_was_replaced) *out_was_replaced = 1;
                            if (out_replaced_status) *out_replaced_status = rst;
                        }
                        for (int pi = 0; pi < MAX_SCHEMA_PARAMS; pi++) free(in_allocs[pi]);
                    }
                }
            }
        } else if (sscanf(tok, "replace_xor:%d:%d:%d:%lu:%lu", &t_idx, &t_seq, &p_idx, &sub, &val) == 5) {
            /* In-place byte XOR replacement on an [in] or [inout] pointer parameter:
             * Executes ONCE and hands [out]/[inout] buffers + ms_retval back to the host.
             */
            if (t_idx == index && t_seq == sseq && es && p_idx >= 0 && (uint32_t)p_idx < es->num_params) {
                const param_schema_t *ps = &es->params[p_idx];
                size_t orig_b = 0, orig_u = 0;
                if (ps->is_pointer && (ps->direction == DIR_IN || ps->direction == DIR_INOUT) &&
                    check_ms_frame_capacity(es, es->ms_size) == 0 &&
                    compute_param_byte_len((const uint8_t *)ms, es->ms_size, ps, &orig_b, &orig_u) == 0 &&
                    sub < orig_u) {
                    uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                    memcpy(ms_work, ms, es->ms_size);
                    uint8_t *orig_ptr = *(uint8_t **)((uint8_t *)ms + ps->ms_offset);
                    if (orig_ptr) {
                        uint8_t *tmp_in = NULL;
                        if (ps->direction == DIR_IN) {
                            tmp_in = (uint8_t *)calloc(1, orig_b ? orig_b : 8);
                            if (tmp_in) {
                                memcpy(tmp_in, orig_ptr, orig_b);
                                tmp_in[sub] ^= (uint8_t)val;
                                *(void **)(ms_work + ps->ms_offset) = tmp_in;
                            }
                        } else {
                            orig_ptr[sub] ^= (uint8_t)val;
                        }
                        char tag[72];
                        snprintf(tag, sizeof(tag), "replace_xor_p%d_byte_%lu", p_idx, sub);
                        sgx_status_t rst = execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                        if (es->has_retval && (size_t)es->retval_offset + (size_t)es->retval_size <= es->ms_size) {
                            memcpy((uint8_t *)ms + es->retval_offset, ms_work + es->retval_offset, es->retval_size);
                        }
                        free(tmp_in);
                        if (out_was_replaced) *out_was_replaced = 1;
                        if (out_replaced_status) *out_replaced_status = rst;
                    }
                }
            }
        } else if (sscanf(tok, "joint_scalar_xor:%d:%d:%d:%lu:%d:%lu:%lu", &t_idx, &t_seq, &p_idx, &val, &p_idx2, &sub, &val2) == 7) {
            /* Joint 2-parameter mutation: scalar p_idx = val (with buffer rebind) + XOR byte sub of pointer p_idx2 */
            if (t_idx == index && t_seq == sseq && es &&
                p_idx >= 0 && (uint32_t)p_idx < es->num_params &&
                p_idx2 >= 0 && (uint32_t)p_idx2 < es->num_params) {
                typed_ms_snapshot_t local_snap = {0};
                if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                    uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                    if (mutate_scalar_and_rebind_buffers(&local_snap, es, ms_work, (uint32_t)p_idx, val) == 0) {
                        const param_schema_t *ps2 = &es->params[p_idx2];
                        size_t blen2 = 0, ulen2 = 0;
                        if (ps2->is_pointer && compute_param_byte_len(ms_work, es->ms_size, ps2, &blen2, &ulen2) == 0) {
                            uint8_t *ptr2 = *(uint8_t **)(ms_work + ps2->ms_offset);
                            if (ptr2 && sub < ulen2) {
                                ptr2[sub] ^= (uint8_t)val2;
                                char tag[80];
                                snprintf(tag, sizeof(tag), "schema_joint_s%d_%lu_x%d_%lu", p_idx, val, p_idx2, sub);
                                execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                            }
                        }
                    }
                    free_typed_snapshot(&local_snap);
                }
            }
        } else if (sscanf(tok, "aliased_pair:%d:%d:%d:%d:%lu", &t_idx, &t_seq, &p_idx, &p_idx2, &sub) == 5) {
            /* Overlapping/aliased buffer pair probe between pointer p_idx and pointer p_idx2 shifted by sub bytes */
            if (t_idx == index && t_seq == sseq && es &&
                p_idx >= 0 && (uint32_t)p_idx < es->num_params &&
                p_idx2 >= 0 && (uint32_t)p_idx2 < es->num_params) {
                const param_schema_t *pa = &es->params[p_idx];
                const param_schema_t *pb = &es->params[p_idx2];
                if (pa->is_pointer && pb->is_pointer) {
                    typed_ms_snapshot_t local_snap = {0};
                    if (typed_snapshot_ms((const uint8_t *)ms, es->ms_size, es, &local_snap) == 0) {
                        uint8_t ms_work[MAX_MS_FRAME_BYTES] = {0};
                        typed_restore_ms_for_replay(&local_snap, es, ms_work);
                        size_t la = local_snap.param_byte_len[p_idx];
                        size_t lb = local_snap.param_byte_len[p_idx2];
                        size_t shared_sz = (la > lb + sub ? la : lb + sub) + 64;
                        uint8_t *shared_buf = (uint8_t *)calloc(1, shared_sz);
                        if (shared_buf) {
                            if (local_snap.master_copy[p_idx] && la > 0)
                                memcpy(shared_buf, local_snap.master_copy[p_idx], la);
                            *(void **)(ms_work + pa->ms_offset) = shared_buf;
                            *(void **)(ms_work + pb->ms_offset) = shared_buf + sub;
                            char tag[80];
                            snprintf(tag, sizeof(tag), "schema_alias_p%d_p%d_off_%lu", p_idx, p_idx2, sub);
                            execute_one_measured_ecall(eid, index, ocall_table, ms_work, tag, 1);
                            free(shared_buf);
                        }
                        free_typed_snapshot(&local_snap);
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
            /* Generic schema-typed buffer scaling with C flexible-array header preservation:
             * If an [in]/[inout] [size=] struct begins with a uint32_t header equal to (orig_blen - 4),
             * preserve the (total_bytes = 4 + payload_len) invariant and synchronized [inout]/[out] framing delta.
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

                    /* Detect if cnt1_off binds a flexible-array struct (orig_blen >= 4 && *(uint32_t*)ptr == orig_blen - 4) */
                    int is_flex_struct = 0;
                    size_t orig_primary_payload = 0;
                    if (sc_mode != 2) {
                    for (uint32_t pi = 0; pi < es->num_params; pi++) {
                        const param_schema_t *ps = &es->params[pi];
                        if (ps->is_pointer && ps->bound_kind == BOUND_SIZE && (long)ps->bound_ms_offset == cnt1_off) {
                            size_t ob = 0, ou = 0;
                            const uint8_t *op = *(const uint8_t *const *)((const uint8_t *)ms + ps->ms_offset);
                            if (op && compute_param_byte_len((const uint8_t *)ms, es->ms_size, ps, &ob, &ou) == 0 && ob >= 4) {
                                uint32_t hdr_len = *(const uint32_t *)op;
                                if ((size_t)hdr_len + 4 == ob) {
                                    is_flex_struct = 1;
                                    orig_primary_payload = hdr_len;
                                    break;
                                }
                            }
                        }
                    }

                    }
                    /* Update scalar count/size slots */
                    for (uint32_t pi = 0; pi < es->num_params; pi++) {
                        const param_schema_t *ps = &es->params[pi];
                        if (!ps->is_pointer) {
                            if ((long)ps->ms_offset == cnt1_off) {
                                uint64_t v = is_flex_struct ? (uint64_t)(new_cnt1 + 4) : (uint64_t)new_cnt1;
                                write_scalar_u64(ms_clone, es->ms_size, ps->ms_offset, ps->ms_size, v);
                            } else if ((long)ps->ms_offset == cnt2_off && new_cnt2 > 0) {
                                uint64_t v = is_flex_struct ? (uint64_t)(new_cnt2 + 4) : (uint64_t)new_cnt2;
                                write_scalar_u64(ms_clone, es->ms_size, ps->ms_offset, ps->ms_size, v);
                            }
                        }
                    }

                    /* If is_flex_struct, also scale any companion [inout]/[out] flexible-array buffer whose original payload >= orig_primary_payload */
                    if (is_flex_struct) {
                        for (uint32_t pi = 0; pi < es->num_params; pi++) {
                            const param_schema_t *ps = &es->params[pi];
                            if (ps->is_pointer && (ps->direction == DIR_OUT || ps->direction == DIR_INOUT) &&
                                ps->bound_kind == BOUND_SIZE && ps->bound_ms_offset >= 0 &&
                                (long)ps->bound_ms_offset != cnt1_off) {
                                size_t ob = 0, ou = 0;
                                const uint8_t *op = *(const uint8_t *const *)((const uint8_t *)ms + ps->ms_offset);
                                if (op && compute_param_byte_len((const uint8_t *)ms, es->ms_size, ps, &ob, &ou) == 0 && ob >= 4) {
                                    uint32_t hdr_len = *(const uint32_t *)op;
                                    if ((size_t)hdr_len + 4 == ob && hdr_len >= orig_primary_payload) {
                                        size_t delta = hdr_len - orig_primary_payload;
                                        size_t new_out_total = 4 + new_cnt1 + delta;
                                        write_scalar_u64(ms_clone, es->ms_size, (uint32_t)ps->bound_ms_offset, ps->bound_ms_size, new_out_total);
                                    }
                                }
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
                        int param_is_flex = 0;
                        if (sc_mode != 2 && orig_ptr && orig_blen >= 4 && (*(const uint32_t *)orig_ptr) + 4 == orig_blen && new_blen >= 4) {
                            param_is_flex = 1;
                        }
                        if ((ps->direction == DIR_IN || ps->direction == DIR_INOUT) && orig_ptr && orig_blen > 0 && new_blen > 0) {
                            if (param_is_flex) {
                                *(uint32_t *)buf = (uint32_t)(new_blen - 4);
                                size_t orig_pay = orig_blen - 4;
                                size_t new_pay = new_blen - 4;
                                for (size_t bi = 0; bi < new_pay; bi++) {
                                    uint8_t sb = orig_pay ? orig_ptr[4 + (bi % orig_pay)] : (uint8_t)(bi & 0xff);
                                    buf[4 + bi] = (sc_mode == 0) ? (uint8_t)((sb + bi * 31U) & 0xff) : sb;
                                }
                            } else {
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
