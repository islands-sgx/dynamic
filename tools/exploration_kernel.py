#!/usr/bin/env python3
"""Unified Exploration Kernel for ATField-SGX Dynamic Workset Acquisition.

Both the synthetic challenge enclaves (dev & blind exam sets) and the real SGX applications
(qe3, signal-cds, sgxwallet, ehsm, ehsm-opt-1, ehsm-opt-2) execute this exact same kernel,
differing only in the thin execution adapter (`runner_fn`) and optional budget ceiling.

Two scheduling modes share the exact same candidate space, operators, and seed workflow:
  1. `fixed_round_robin`: Deterministic round-robin across operator families and call positions.
  2. `feedback_guided`: Uses concrete S3 page-effect sets `frozenset((rva, eff))` and business
     return categories to save productive intervention plans, spawn compound follow-up candidates,
     and prioritize productive families/positions while preserving anti-starvation base turns.
"""
from __future__ import annotations

import random
import time
from pathlib import Path
from typing import Callable

from generic_explorer import (
    AUDIT_OF_LEGACY_HEURISTICS,
    build_scale_bound_v2_spec,
    generate_schema_mutations_for_ecall,
    get_scalable_bound_offsets,
)

# Declared general exploration domain constants (shared across all targets, never tuned to blind exam values)
DECLARED_CONTROL_SCALAR_DOMAIN = (0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 32, 99)
DECLARED_BOUND_SCALAR_DOMAIN = (0, 1, 16)
DECLARED_SCALE_PROGRESSION = (16, 64, 256, 512, 1024, 4096, 16384, 65536, 262144)
DECLARED_HISTORY_DEPTHS = (24, 64, 256, 1024)
FAMILY_ORDER = ("replace_prefix", "scale", "joint", "slice_rel", "boundary", "history", "content")


def extract_concrete_record_feedback(rec: dict) -> dict:
    """Extract randomness-invariant concrete feedback from a single ECALL trace record:
    - Concrete S3 (page_rva, effect) set (NOT just page count!)
    - Business return category (0 = success, 1 = business rejection, 2 = transport error)
    - Heap span in pages & stack depth bucket
    """
    s3_effects: set[tuple[int, str]] = set()
    s3_pages: set[int] = set()
    heap_pages = 0
    stack_bucket = 0
    field_ids: list[str] = []

    for fobs in rec.get("fields", []):
        fid = fobs.get("field_id", "")
        if fid:
            field_ids.append(fid)
        lo = int(fobs.get("heap_lo_rva", "0x0"), 16)
        hi = int(fobs.get("heap_hi_rva", "0x0"), 16)
        if hi > lo:
            heap_pages = max(heap_pages, (hi - lo) // 4096)
        gb = int(fobs.get("gateB_rsp_rva", "0x0"), 16)
        gd = int(fobs.get("gateD_rsp_rva", "0x0"), 16)
        if gb and gd:
            stack_bucket = max(stack_bucket, abs(gb - gd) // 4096)
        for item in fobs.get("s3", []):
            rva = int(item["rva"], 16)
            ad = item["ad"]
            s3_pages.add(rva)
            s3_effects.add((rva, "A"))
            if ad == "D":
                s3_effects.add((rva, "D"))

    if rec.get("sgx_status", 0) != 0:
        ret_cat = 2
    elif rec.get("abi_return_type") == "void":
        ret_cat = 0 if (not rec.get("has_out_status_i32") or rec.get("out_status_i32", 0) == 0) else 1
    else:
        ret_cat = 0 if rec.get("ms_retval", 0) == 0 else 1

    # Concrete state-observation key: uses frozenset(s3_effects), NOT page count, and never merges
    # different call positions even if their page sets coincide.
    state_obs_key = (
        rec.get("ecall_index", -1),
        1 if field_ids else 0,
        ret_cat,
        frozenset(s3_effects),
        heap_pages,
        stack_bucket,
    )
    return {
        "entered_field": bool(field_ids),
        "field_ids": field_ids,
        "ret_cat": ret_cat,
        "s3_pages": frozenset(s3_pages),
        "s3_effects": frozenset(s3_effects),
        "heap_pages": heap_pages,
        "stack_bucket": stack_bucket,
        "state_obs_key": state_obs_key,
    }


def build_unified_candidate_queues(
    edl_schema: dict,
    selectors: list[dict],
    seed_records: list[dict],
    rng_seed: int = 101,
) -> tuple[dict[str, list[dict]], dict]:
    """Build the unified per-family candidate queues from EDL schema and seed L1 trace.
    Removes 'only first 2 positions' and 'only last selector' assumptions:
    - Collects up to 4 distinct observed selector_seq positions per Field selector (e.g. sseq=0, 1, 2, last)
      and records any remaining positions in unexplored_frontier.
    - Schedules history scans (starting at depth=24 > 16) across ALL Field-bearing selectors.
    - Uses true in-place replacement (`replace_scalar`) for setup/producer prefix continuation.
    """
    rng = random.Random(rng_seed)
    ecalls_by_idx = {e["ecall_index"]: e for e in edl_schema["ecalls"]}
    field_selectors = [s["ecall_index"] for s in selectors if s["reachable_fields"]]
    non_field_selectors = [s["ecall_index"] for s in selectors if not s["reachable_fields"]]

    all_observed_field_sseqs: dict[int, list[int]] = {}
    all_observed_setup_sseqs: dict[int, list[int]] = {}
    for rec in seed_records:
        idx = rec["ecall_index"]
        sseq = rec["selector_seq"]
        if rec.get("fields"):
            lst = all_observed_field_sseqs.setdefault(idx, [])
            if sseq not in lst:
                lst.append(sseq)
        else:
            lst = all_observed_setup_sseqs.setdefault(idx, [])
            if sseq not in lst:
                lst.append(sseq)

    selected_field_positions: list[tuple[int, int]] = []
    unexplored_positions: dict[int, list[int]] = {}
    for idx in field_selectors:
        obs = all_observed_field_sseqs.get(idx, [0])
        if len(obs) <= 4:
            chosen = list(obs)
            skipped = []
        else:
            chosen = [obs[0], obs[1], obs[2], obs[-1]]
            skipped = [s for s in obs if s not in chosen]
        for sseq in chosen:
            selected_field_positions.append((idx, sseq))
        if skipped:
            unexplored_positions[idx] = skipped

    queues: dict[str, list[dict]] = {f: [] for f in FAMILY_ORDER}

    # 1. replace_prefix: True in-place replacement (`replace_scalar`) on setup/producer calls
    # (executes ONCE at the original call position and hands [out]/[inout] buffers + retval to host!)
    producer_or_setup_indices = list(non_field_selectors) + [
        idx for idx in field_selectors if len(field_selectors) > 1
    ]
    for p_idx_ecall in producer_or_setup_indices:
        ec = ecalls_by_idx.get(p_idx_ecall)
        if not ec or not ec.get("replay_supported", True):
            continue
        bound_offs = {
            p.get("bound_ms_offset")
            for p in ec.get("params", [])
            if p.get("is_pointer") and p.get("bound_ms_offset") is not None
        }
        sseqs = all_observed_setup_sseqs.get(p_idx_ecall, all_observed_field_sseqs.get(p_idx_ecall, [0]))[:2]
        for sseq in sseqs:
            for pidx, p in enumerate(ec.get("params", [])):
                if not p.get("is_pointer") and p.get("ms_offset") not in bound_offs:
                    vals = list(DECLARED_CONTROL_SCALAR_DOMAIN[:10])
                    rng.shuffle(vals)
                    for val in vals:
                        queues["replace_prefix"].append({
                            "family": "replace_prefix",
                            "subkind": "in_place_prefix_replacement",
                            "ecall_index": p_idx_ecall,
                            "selector_seq": sseq,
                            "param_index": pidx,
                            "scalar_val": val,
                            "spec": f"replace_scalar:{p_idx_ecall}:{sseq}:{pidx}:{val}",
                            "stop_after": "",
                            "stop_before": "",
                            "allow_nonzero_rc": True,
                            "tag": f"replace_prefix_e{p_idx_ecall}_s{sseq}_p{pidx}_v{val}",
                            "desc": f"In-place replacement {ec['name']}@{sseq}.{p['name']}={val} + host continuation",
                        })

    # 2. scale: Multi-scale expansion on scalable Field selectors (first steps queued; larger steps spawned by feedback or queued)
    for idx in field_selectors:
        ec = ecalls_by_idx.get(idx)
        if not ec or get_scalable_bound_offsets(ec) is None:
            continue
        sseq0 = all_observed_field_sseqs.get(idx, [0])[0]
        for sc in (16, 64, 256, 512, 1024, 4096):
            q_sc = min(sc, 1024)
            specs = [
                build_scale_bound_v2_spec(ec, sc, q_sc, mode=m, selector_seq=sseq0)
                for m in (0, 2)
            ]
            spec_str = ";".join(s for s in specs if s)
            if spec_str:
                queues["scale"].append({
                    "family": "scale",
                    "subkind": "feedback_scale_expansion",
                    "ecall_index": idx,
                    "selector_seq": sseq0,
                    "scale": sc,
                    "spec": spec_str,
                    "stop_after": f"{idx}:{sseq0}",
                    "stop_before": "",
                    "allow_nonzero_rc": False,
                    "tag": f"scale_e{idx}_s{sseq0}_n{sc}",
                    "desc": f"Scale expansion n={sc} (flex+raw branches) on {ec['name']}@{sseq0}",
                })

    # 3. Interleave boundary, joint, slice_rel, and content across ALL selected_field_positions (sseq=0, 1, 2, ...)
    per_pos_buckets: dict[str, list[list[dict]]] = {
        "boundary": [],
        "joint": [],
        "slice_rel": [],
        "content": [],
    }
    for idx, sseq in selected_field_positions:
        ec = ecalls_by_idx.get(idx)
        if not ec or not ec.get("replay_supported", True):
            continue
        params = ec.get("params", [])
        bound_offs = {
            p.get("bound_ms_offset")
            for p in params
            if p.get("is_pointer") and p.get("bound_ms_offset") is not None
        }
        b_list, j_list, a_list, c_list = [], [], [], []
        scalar_params = []
        in_ptr_params = []
        all_ptr_params = []

        for pidx, p in enumerate(params):
            if p.get("ms_offset") is None or not p.get("param_replay_supported", True):
                continue
            pname = p["name"]
            direction = p.get("direction", "val")
            if p.get("is_pointer"):
                all_ptr_params.append((pidx, p))
                if direction in ("in", "inout"):
                    in_ptr_params.append((pidx, p))
                    static_b = p.get("static_byte_len")
                    is_str = p.get("is_string", False)
                    if static_b is not None:
                        cands = sorted({b for b in (0, 1, 15, static_b // 2, static_b - 1, 60) if 0 <= b < static_b})
                    elif is_str:
                        cands = [0, 1]
                    else:
                        cands = [0, 4, 15, 31]
                    for byte_idx in cands:
                        mask = 0xFF if byte_idx in (0, 60) else 0xAA
                        c_list.append({
                            "family": "content",
                            "subkind": "isolated_single_mutation_replay",
                            "ecall_index": idx,
                            "selector_seq": sseq,
                            "param_index": pidx,
                            "byte_offset": byte_idx,
                            "spec": f"xor_param:{idx}:{sseq}:{pidx}:{byte_idx}:{mask}",
                            "stop_after": "",
                            "stop_before": f"{idx}:{sseq}",
                            "allow_nonzero_rc": False,
                            "tag": f"xor_e{idx}_s{sseq}_p{pidx}_b{byte_idx}",
                            "desc": f"Bounded XOR {ec['name']}@{sseq}.{pname}[{byte_idx}] ^= 0x{mask:02x}",
                        })
            else:
                scalar_params.append((pidx, p))
                is_bound = p.get("ms_offset") in bound_offs
                dom = list(DECLARED_BOUND_SCALAR_DOMAIN if is_bound else DECLARED_CONTROL_SCALAR_DOMAIN)
                rng.shuffle(dom)
                for val in dom:
                    # For control scalars, use in-place replace_scalar so both current call and downstream calls see the state!
                    op_name = "set_scalar" if is_bound else "replace_scalar"
                    stop_bef = f"{idx}:{sseq}" if is_bound else ""
                    b_list.append({
                        "family": "boundary",
                        "subkind": "in_place_scalar_boundary" if not is_bound else "isolated_single_mutation_replay",
                        "ecall_index": idx,
                        "selector_seq": sseq,
                        "param_index": pidx,
                        "scalar_val": val,
                        "is_control_scalar": not is_bound,
                        "spec": f"{op_name}:{idx}:{sseq}:{pidx}:{val}",
                        "stop_after": f"{idx}:{sseq}" if not is_bound else "",
                        "stop_before": stop_bef,
                        "allow_nonzero_rc": not is_bound,
                        "tag": f"scalar_e{idx}_s{sseq}_p{pidx}_v{val}",
                        "desc": f"Scalar boundary ({op_name}) {ec['name']}@{sseq}.{pname}={val}",
                    })

        # Order control scalars ahead of bound-length scalars at each position
        b_list.sort(key=lambda x: (0 if x.get("is_control_scalar") else 1))

        # Joint 2-parameter candidates
        for spidx, sp in scalar_params[:2]:
            for ppidx, pp in in_ptr_params[:2]:
                jvals = [1, 2, 3, 4, 7, 16]
                rng.shuffle(jvals)
                for jval in jvals:
                    j_list.append({
                        "family": "joint",
                        "subkind": "joint_two_param_mutation",
                        "ecall_index": idx,
                        "selector_seq": sseq,
                        "param_index": spidx,
                        "scalar_val": jval,
                        "spec": f"joint_scalar_xor:{idx}:{sseq}:{spidx}:{jval}:{ppidx}:0:255",
                        "stop_after": "",
                        "stop_before": f"{idx}:{sseq}",
                        "allow_nonzero_rc": False,
                        "tag": f"joint_e{idx}_s{sseq}_s{spidx}_{jval}_x{ppidx}_0",
                        "desc": f"Joint 2-param {ec['name']}@{sseq}: {sp['name']}={jval} & {pp['name']}[0]^=0xff",
                    })

        # Cross-buffer content slice relation candidates
        if len(all_ptr_params) >= 2:
            p0_idx, p0 = all_ptr_params[0]
            p1_idx, p1 = all_ptr_params[1]
            for shift in (4, 8):
                a_list.append({
                    "family": "slice_rel",
                    "subkind": "cross_buffer_slice_relation",
                    "ecall_index": idx,
                    "selector_seq": sseq,
                    "spec": f"aliased_pair:{idx}:{sseq}:{p0_idx}:{p1_idx}:{shift}",
                    "stop_after": "",
                    "stop_before": f"{idx}:{sseq}",
                    "allow_nonzero_rc": False,
                    "tag": f"slice_rel_e{idx}_s{sseq}_p{p0_idx}_p{p1_idx}_off{shift}",
                    "desc": f"Cross-buffer slice relation {ec['name']}@{sseq}: {p1['name']} := {p0['name']}+{shift}",
                })

        per_pos_buckets["boundary"].append(b_list)
        per_pos_buckets["joint"].append(j_list)
        per_pos_buckets["slice_rel"].append(a_list)
        per_pos_buckets["content"].append(c_list)

    for fam, pos_lists in per_pos_buckets.items():
        max_len = max((len(lst) for lst in pos_lists), default=0)
        for i in range(max_len):
            for lst in pos_lists:
                if i < len(lst):
                    queues[fam].append(lst[i])

    # 4. Cold-state replay candidates added to content family
    if non_field_selectors and len(field_selectors) > 1:
        trig_idx = non_field_selectors[0]
        for idx in field_selectors:
            ec = ecalls_by_idx.get(idx)
            if not ec or not ec.get("replay_supported", True):
                continue
            cap_seq = all_observed_field_sseqs.get(idx, [0])[0]
            queues["content"].insert(0, {
                "family": "content",
                "subkind": "cold_enclave_state_replay",
                "ecall_index": idx,
                "selector_seq": cap_seq,
                "spec": f"typed_state_probe:{idx}:{cap_seq}:{trig_idx}:1",
                "stop_after": "",
                "stop_before": "",
                "allow_nonzero_rc": False,
                "tag": f"cold_replay_e{idx}_cap{cap_seq}_after_e{trig_idx}",
                "desc": f"Cold-enclave state replay of {ec['name']}@{cap_seq} after ecall {trig_idx}",
            })

    # 5. history: Interleave history depth scans across ALL Field-bearing selectors (starting at depth=24 > 16!)
    for depth in DECLARED_HISTORY_DEPTHS:
        for idx in field_selectors:
            ec = ecalls_by_idx.get(idx)
            if not ec or not ec.get("replay_supported", True):
                continue
            # All Field selectors get depth=24 and depth=64; primary steady-state selector also gets 256, 1024
            if depth > 64 and idx != field_selectors[-1]:
                continue
            sseq0 = all_observed_field_sseqs.get(idx, [0])[0]
            queues["history"].append({
                "family": "history",
                "subkind": "quadrupling_history_scan",
                "ecall_index": idx,
                "selector_seq": sseq0,
                "history_depth": depth,
                "spec": f"repeat:{idx}:{sseq0}:{depth}",
                "stop_after": f"{idx}:{sseq0}",
                "stop_before": "",
                "allow_nonzero_rc": True,
                "tag": f"history_e{idx}_s{sseq0}_n{depth}",
                "desc": f"History accumulation (depth={depth}) on {ec['name']}@{sseq0}",
            })

    frontier_meta = {
        "observed_field_positions": {str(k): v for k, v in all_observed_field_sseqs.items()},
        "selected_field_positions": [list(x) for x in selected_field_positions],
        "unexplored_positions": {str(k): v for k, v in unexplored_positions.items()},
    }
    return queues, frontier_meta


class ExplorationKernel:
    """Single Unified Exploration Kernel shared by all synthetic challenge enclaves and real applications."""

    def __init__(
        self,
        *,
        sample: str,
        edl_schema: dict,
        selectors: list[dict],
        runner_fn: Callable[[dict], dict],
        mode: str = "feedback_guided",
        rng_seed: int = 101,
        max_enclave_creations: int | None = None,
        max_total_ecalls: int | None = None,
    ) -> None:
        if mode not in ("fixed_round_robin", "feedback_guided"):
            raise ValueError(f"Unsupported ExplorationKernel mode: {mode}")
        self.sample = sample
        self.edl_schema = edl_schema
        self.selectors = selectors
        self.runner_fn = runner_fn
        self.mode = mode
        self.rng_seed = rng_seed
        self.max_enclave_creations = max_enclave_creations
        self.max_total_ecalls = max_total_ecalls

        self.ecalls_by_idx = {e["ecall_index"]: e for e in edl_schema["ecalls"]}
        self.field_selectors = {s["ecall_index"] for s in selectors if s["reachable_fields"]}

        # Concrete feedback state (never conflates page count with concrete page set!)
        self.cumulative_s3_effects: set[tuple[int, str]] = set()
        self.cumulative_s3_pages: set[int] = set()
        self.max_heap_pages_by_ecall: dict[int, int] = {}
        self.seen_state_obs_keys: set[tuple] = set()
        self.productive_plans: list[dict] = []
        self.follow_up_queue: list[dict] = []
        self.selection_trace: list[dict] = []
        self.feedback_decisions: list[dict] = []
        self.failed_repeat_selectors: dict[int, str] = {}
        self.stagnant_scale_selectors: dict[int, int] = {}

        # Cost accounting
        self.enclave_creations = 0
        self.total_ecalls = 0
        self.valid_field_ecalls = 0
        self.expected_s0_rejections = 0
        self.non_field_setup_ecalls = 0
        self.measurement_invalid_runs = 0
        self.stop_reason = "candidates_exhausted"

    def _can_continue(self) -> bool:
        if self.max_enclave_creations is not None and self.enclave_creations >= self.max_enclave_creations:
            self.stop_reason = f"stop_budget_cap_reached:enclaves={self.max_enclave_creations}"
            return False
        if self.max_total_ecalls is not None and self.total_ecalls >= self.max_total_ecalls:
            self.stop_reason = f"stop_budget_cap_reached:ecalls={self.max_total_ecalls}"
            return False
        return True

    def _execute_plan(self, plan: dict) -> tuple[dict, dict]:
        self.enclave_creations += 1
        res = self.runner_fn(plan)
        if res.get("measurement_invalid", False):
            self.measurement_invalid_runs += 1
        recs = res.get("records") or []
        self.total_ecalls += len(recs)

        run_s3_effects: set[tuple[int, str]] = set()
        run_s3_pages: set[int] = set()
        new_state_keys = 0
        heap_grew = False
        any_valid_field_return = False

        for rec in recs:
            fb = extract_concrete_record_feedback(rec)
            if fb["state_obs_key"] not in self.seen_state_obs_keys:
                self.seen_state_obs_keys.add(fb["state_obs_key"])
                new_state_keys += 1
            if fb["entered_field"]:
                self.valid_field_ecalls += 1
                if fb["ret_cat"] == 0:
                    any_valid_field_return = True
                run_s3_effects |= fb["s3_effects"]
                run_s3_pages |= fb["s3_pages"]
                eidx = rec.get("ecall_index", -1)
                prev_hp = self.max_heap_pages_by_ecall.get(eidx, 0)
                if fb["heap_pages"] > prev_hp:
                    self.max_heap_pages_by_ecall[eidx] = fb["heap_pages"]
                    heap_grew = True
            else:
                if rec.get("ecall_index") in self.field_selectors and fb["ret_cat"] != 0:
                    self.expected_s0_rejections += 1
                else:
                    self.non_field_setup_ecalls += 1

        new_concrete_effects = run_s3_effects - self.cumulative_s3_effects
        new_concrete_pages = run_s3_pages - self.cumulative_s3_pages
        self.cumulative_s3_effects |= run_s3_effects
        self.cumulative_s3_pages |= run_s3_pages

        delta = {
            "new_effects_set": sorted(( hex(r), e ) for r, e in new_concrete_effects),
            "new_effects_count": len(new_concrete_effects),
            "new_pages_count": len(new_concrete_pages),
            "new_state_keys": new_state_keys,
            "heap_grew": heap_grew,
            "any_valid_field_return": any_valid_field_return,
            "returncode": res.get("returncode", 0),
        }
        self.selection_trace.append({
            "step": self.enclave_creations,
            "tag": plan.get("tag", "seed"),
            "family": plan.get("family", "seed"),
            "spec": plan.get("spec", ""),
            "new_effects_count": len(new_concrete_effects),
            "new_state_keys": new_state_keys,
            "heap_grew": heap_grew,
        })
        return res, delta

    def _update_feedback_and_spawn(self, plan: dict, delta: dict, queues: dict[str, list[dict]], spawned_tags: set[str]) -> None:
        """Genuine feedback update:
        - Saves productive plans that discovered concrete new S3 effects or new valid business return states.
        - Spawns targeted follow-up plans around productive scalar values, call positions, or scales.
        - Records non-repeatable failures and scale stagnation.
        """
        fam = plan.get("family", "")
        eidx = plan.get("ecall_index", -1)
        sseq = plan.get("selector_seq", 0)

        if fam == "history" and delta["returncode"] != 0:
            reason = f"repeat_attempt_failed_rc_{delta['returncode']}"
            self.failed_repeat_selectors[eidx] = reason
            # Prune remaining deeper history repeats on this selector
            queues["history"] = [q for q in queues["history"] if q.get("ecall_index") != eidx]
            self.feedback_decisions.append({
                "tag": plan["tag"],
                "decision": reason,
            })
            return

        if fam == "scale":
            sc = plan.get("scale", 0)
            if not delta["any_valid_field_return"]:
                self.feedback_decisions.append({
                    "tag": plan["tag"],
                    "scale": sc,
                    "decision": "continue_past_rejected_scale",
                })
                return
            if delta["new_effects_count"] > 0 or delta["heap_grew"]:
                self.stagnant_scale_selectors[eidx] = 0
                # Spawn larger scale step (up to 262144) if not already queued
                next_sc = sc * 4
                if 4096 < next_sc <= 262144:
                    ec = self.ecalls_by_idx.get(eidx)
                    if ec:
                        sp = build_scale_bound_v2_spec(ec, next_sc, min(next_sc, 1024), mode=0, selector_seq=sseq)
                        ntag = f"scale_e{eidx}_s{sseq}_n{next_sc}"
                        if sp and ntag not in spawned_tags:
                            spawned_tags.add(ntag)
                            self.follow_up_queue.append({
                                "family": "scale",
                                "subkind": "feedback_scale_expansion",
                                "ecall_index": eidx,
                                "selector_seq": sseq,
                                "scale": next_sc,
                                "spec": sp,
                                "stop_after": f"{eidx}:{sseq}",
                                "stop_before": "",
                                "allow_nonzero_rc": False,
                                "tag": ntag,
                                "desc": f"Feedback-spawned scale step n={next_sc} on {ec['name']}@{sseq}",
                            })
                            self.feedback_decisions.append({
                                "tag": plan["tag"],
                                "scale": sc,
                                "decision": f"spawn_scale_{next_sc}",
                            })
                        elif next_sc >= 262144:
                            self.feedback_decisions.append({
                                "tag": plan["tag"],
                                "scale": sc,
                                "decision": "stop_budget_cap_reached",
                            })
            else:
                stag = self.stagnant_scale_selectors.get(eidx, 0) + 1
                self.stagnant_scale_selectors[eidx] = stag
                if stag >= 2:
                    queues["scale"] = [q for q in queues["scale"] if q.get("ecall_index") != eidx]
                    self.feedback_decisions.append({
                        "tag": plan["tag"],
                        "scale": sc,
                        "decision": "stop_stagnant_2_rounds",
                    })

        # If a boundary, replace_prefix, or content plan discovered new concrete effects or a new valid return state,
        # save it to productive_plans and spawn a follow-up around it!
        if delta["new_effects_count"] > 0 or (delta["any_valid_field_return"] and delta["new_state_keys"] > 0):
            self.productive_plans.append({
                "tag": plan["tag"],
                "family": fam,
                "spec": plan["spec"],
                "new_effects": delta["new_effects_set"],
            })
            if fam == "boundary" and plan.get("scalar_val") is not None:
                # Spawn a joint scalar+XOR probe at the same (eidx, sseq) using this productive scalar value!
                ec = self.ecalls_by_idx.get(eidx)
                val = plan["scalar_val"]
                pidx = plan.get("param_index", 0)
                if ec:
                    for ppidx, pp in enumerate(ec.get("params", [])):
                        if pp.get("is_pointer") and pp.get("direction") in ("in", "inout"):
                            ftag = f"feedback_joint_e{eidx}_s{sseq}_p{pidx}_v{val}_x{ppidx}"
                            if ftag not in spawned_tags:
                                spawned_tags.add(ftag)
                                self.follow_up_queue.append({
                                    "family": "joint",
                                    "subkind": "feedback_spawned_joint",
                                    "ecall_index": eidx,
                                    "selector_seq": sseq,
                                    "spec": f"joint_scalar_xor:{eidx}:{sseq}:{pidx}:{val}:{ppidx}:0:255",
                                    "stop_after": "",
                                    "stop_before": f"{eidx}:{sseq}",
                                    "allow_nonzero_rc": False,
                                    "tag": ftag,
                                    "desc": f"Feedback-spawned joint probe around productive {ec['name']}@{sseq} val={val}",
                                })
                                self.feedback_decisions.append({
                                    "tag": plan["tag"],
                                    "decision": f"spawn_followup_{ftag}",
                                })
                            break

    def run(self) -> dict:
        t0 = time.monotonic()
        seed_plan = {
            "run_id": "layer0_and_layer1_unmodified_host",
            "layer": "layer1_full_host",
            "subkind": "unmodified_host_full_trace",
            "family": "seed",
            "tag": "L0_L1_seed",
            "spec": "",
            "stop_after": "",
            "stop_before": "",
            "allow_nonzero_rc": False,
            "desc": "Unmodified host binary full execution (Layer 0 + Layer 1)",
        }
        res0, _ = self._execute_plan(seed_plan)
        queues, frontier_meta = build_unified_candidate_queues(
            self.edl_schema,
            self.selectors,
            res0.get("records") or [],
            rng_seed=self.rng_seed,
        )
        spawned_tags: set[str] = {
            cand["tag"] for q in queues.values() for cand in q
        }

        fam_idx = 0
        turn = 0
        while self._can_continue():
            # In feedback_guided mode, every odd turn executes a feedback-spawned follow-up if available
            if self.mode == "feedback_guided" and (turn % 2 == 1) and self.follow_up_queue:
                cand = self.follow_up_queue.pop(0)
            else:
                # Base round-robin turn across non-empty families (guarantees every family and position gets budget)
                avail_fams = [f for f in FAMILY_ORDER if queues.get(f)]
                if not avail_fams:
                    if self.mode == "feedback_guided" and self.follow_up_queue:
                        cand = self.follow_up_queue.pop(0)
                    else:
                        self.stop_reason = "candidates_exhausted"
                        break
                else:
                    fam = avail_fams[fam_idx % len(avail_fams)]
                    fam_idx += 1
                    cand = queues[fam].pop(0)

            turn += 1
            plan = {
                "run_id": f"layer2_{cand['tag']}",
                "layer": "layer2_generic_schema",
                **cand,
            }
            _, delta = self._execute_plan(plan)
            if self.mode == "feedback_guided":
                self._update_feedback_and_spawn(plan, delta, queues, spawned_tags)

        remaining_by_family = {f: len(q) for f, q in queues.items() if q}
        return {
            "sample": self.sample,
            "mode": self.mode,
            "rng_seed": self.rng_seed,
            "stop_reason": self.stop_reason,
            "wall_clock_sec": round(time.monotonic() - t0, 3),
            "enclave_creations": self.enclave_creations,
            "total_ecalls_executed": self.total_ecalls,
            "valid_field_entering_ecalls": self.valid_field_ecalls,
            "expected_s0_rejections": self.expected_s0_rejections,
            "non_field_setup_ecalls": self.non_field_setup_ecalls,
            "measurement_invalid_runs": self.measurement_invalid_runs,
            "confirmed_s3_pages": len(self.cumulative_s3_pages),
            "confirmed_s3_effects": len(self.cumulative_s3_effects),
            "productive_plans": self.productive_plans,
            "feedback_decisions": self.feedback_decisions,
            "selection_trace": self.selection_trace,
            "unexplored_frontier": {
                **frontier_meta,
                "failed_repeat_selectors": {str(k): v for k, v in self.failed_repeat_selectors.items()},
                "remaining_candidates_by_family": remaining_by_family,
                "remaining_followup_candidates": len(self.follow_up_queue),
            },
        }
