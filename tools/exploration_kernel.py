#!/usr/bin/env python3
"""Unified Exploration Kernel for ATField-SGX Dynamic Workset Acquisition.

Both the synthetic challenge enclaves (dev, regression, and blind exam sets) and the real SGX
applications (qe3, signal-cds, sgxwallet, ehsm, ehsm-opt-1, ehsm-opt-2) execute this exact same
kernel, differing only in the thin execution adapter (`runner_fn`) and optional budget ceiling.

Three scheduling modes share the exact same candidate space, operators, and seed workflow:
  1. `fixed_round_robin`: Pure 1-for-1 round-robin across operator families and call positions.
  2. `static_priority_no_feedback`: Same candidate domain and static structural family schedule
     as `feedback_guided`, but with runtime feedback disabled (isolates static priority vs feedback).
  3. `feedback_guided`: Uses concrete per-Field S3 page-effect sets `frozenset((fid, rva, eff))`
     and per-(selector, sseq, Field) business state keys to save productive intervention plans,
     spawn compound follow-up candidates on new effects or new valid states, reprioritize active
     slots into `secondary_branch_queue` with periodic anti-starvation turns, and demote stagnant
     scale/history sequences into `low_priority_queue`.
"""
from __future__ import annotations

import random
import time
from typing import Callable

from acceptance_validator import extract_valid_s3_effects, is_valid_measurement_run
from generic_explorer import (
    build_scale_bound_v2_spec,
    get_scalable_bound_offsets,
)

# Declared general exploration domain constants (shared across all targets, never tuned to blind exam values)
DECLARED_CONTROL_SCALAR_DOMAIN = (0, 1, 2, 3, 4, 8, 16, 99)
DECLARED_BOUND_SCALAR_DOMAIN = (0, 1, 16)
DECLARED_SCALE_PROGRESSION = (16, 64, 256, 512, 1024, 4096, 16384, 65536, 262144)
DECLARED_HISTORY_DEPTHS = (24, 64, 256, 1024)
FAMILY_ORDER = ("replace_prefix", "scale", "joint", "slice_rel", "boundary", "history", "content")


def extract_concrete_record_feedback(rec: dict) -> dict:
    """Extract randomness-invariant concrete feedback from a single ECALL trace record:
    - Concrete per-Field S3 `(field_id, page_rva, effect)` set (never merges across Fields or counts!)
    - Business return category (0 = success, 1 = business rejection, 2 = transport error)
    - Call position (`selector_seq`) and Field identity included in `state_obs_key`
    - Heap span in pages & stack depth bucket
    """
    s3_field_effects: set[tuple[str, int, str]] = set()
    s3_field_pages: set[tuple[str, int]] = set()
    s3_rva_effects: set[tuple[int, str]] = set()
    s3_rva_pages: set[int] = set()
    heap_pages = 0
    rsp_endpoint_delta_bucket = 0
    observed_stack_pages = 0
    field_ids: list[str] = []

    for fobs in rec.get("fields", []):
        fid = str(fobs.get("field_id", "0x0"))
        if fid:
            field_ids.append(fid)
        lo = int(fobs.get("heap_lo_rva", "0x0"), 16)
        hi = int(fobs.get("heap_hi_rva", "0x0"), 16)
        if hi > lo:
            heap_pages = max(heap_pages, (hi - lo) // 4096)
        gb = int(fobs.get("gateB_rsp_rva", "0x0"), 16)
        gd = int(fobs.get("gateD_rsp_rva", "0x0"), 16)
        if gb and gd:
            rsp_endpoint_delta_bucket = max(rsp_endpoint_delta_bucket, abs(gb - gd) // 4096)
        rsp_anchor = max(gb, gd)
        stack_win_lo = max(0, min(gb, gd) - 16 * 4096) if (gb and gd) else 0
        stack_win_hi = rsp_anchor + 4 * 4096 if rsp_anchor else 0
        f_stack_rvas: set[int] = set()
        for rva, eff in extract_valid_s3_effects(fobs):
            s3_field_pages.add((fid, rva))
            s3_rva_pages.add(rva)
            s3_field_effects.add((fid, rva, eff))
            s3_rva_effects.add((rva, eff))
            if rsp_anchor and stack_win_lo <= rva <= stack_win_hi:
                f_stack_rvas.add(rva)
        observed_stack_pages = max(observed_stack_pages, len(f_stack_rvas))

    if rec.get("sgx_status", 0) != 0:
        ret_cat = 2
    elif rec.get("abi_return_type") == "void":
        ret_cat = 0 if (not rec.get("has_out_status_i32") or rec.get("out_status_i32", 0) == 0) else 1
    else:
        ret_cat = 0 if rec.get("ms_retval", 0) == 0 else 1

    state_obs_key = (
        rec.get("ecall_index", -1),
        rec.get("selector_seq", 0),
        tuple(sorted(set(field_ids))),
        ret_cat,
        frozenset(s3_field_effects),
        heap_pages,
        rsp_endpoint_delta_bucket,
        observed_stack_pages,
    )
    return {
        "entered_field": bool(field_ids),
        "field_ids": field_ids,
        "ret_cat": ret_cat,
        "s3_field_pages": frozenset(s3_field_pages),
        "s3_field_effects": frozenset(s3_field_effects),
        "s3_pages": frozenset(s3_rva_pages),
        "s3_effects": frozenset(s3_rva_effects),
        "heap_pages": heap_pages,
        "rsp_endpoint_delta_bucket": rsp_endpoint_delta_bucket,
        "observed_stack_pages": observed_stack_pages,
        "state_obs_key": state_obs_key,
    }


def build_unified_candidate_queues(
    edl_schema: dict,
    selectors: list[dict],
    seed_records: list[dict],
    rng_seed: int = 101,
) -> tuple[dict[str, list[dict]], dict]:
    """Build the unified per-family candidate queues from EDL schema and seed L1 trace.
    All scheduling modes (`fixed_round_robin`, `static_priority_no_feedback`, `feedback_guided`)
    receive this exact same candidate pool:
    - Collects up to 4 distinct observed selector_seq positions per Field selector (e.g. sseq=0, 1, 2, last)
      and records any remaining positions in unexplored_frontier.
    - Schedules full scale progression (16..262144) across all scalable Field selectors.
    - Schedules full history depth progression (24, 64, 256, 1024) uniformly across ALL Field-bearing
      selectors (no `field_selectors[-1]` bias).
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

    # 1. replace_prefix: True in-place replacement (`replace_scalar`) interleaved across all non-Field setup/producer calls
    per_setup_lists: list[list[dict]] = []
    sorted_non_field = sorted(
        non_field_selectors,
        key=lambda idx: (
            0 if any(p.get("is_pointer") and p.get("direction") in ("out", "inout") for p in ecalls_by_idx.get(idx, {}).get("params", [])) else 1,
            idx,
        ),
    )
    for p_idx_ecall in sorted_non_field:
        ec = ecalls_by_idx.get(p_idx_ecall)
        if not ec or not ec.get("replay_supported", True):
            continue
        bound_offs = {
            p.get("bound_ms_offset")
            for p in ec.get("params", [])
            if p.get("is_pointer") and p.get("bound_ms_offset") is not None
        }
        sseqs = all_observed_setup_sseqs.get(p_idx_ecall, [0])[:1]
        this_ec_list: list[dict] = []
        for sseq in sseqs:
            for pidx, p in enumerate(ec.get("params", [])):
                if not p.get("is_pointer") and p.get("ms_offset") not in bound_offs:
                    vals = [v for v in DECLARED_CONTROL_SCALAR_DOMAIN if v not in (0, 99)]
                    rng.shuffle(vals)
                    for val in vals:
                        this_ec_list.append({
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
        if this_ec_list:
            per_setup_lists.append(this_ec_list)
    max_rp = max((len(x) for x in per_setup_lists), default=0)
    for i in range(max_rp):
        for lst in per_setup_lists:
            if i < len(lst):
                queues["replace_prefix"].append(lst[i])

    # 2. scale: Full progression (16..262144) queued across all scalable Field selectors (identical domain across modes)
    for sc in DECLARED_SCALE_PROGRESSION:
        for idx in field_selectors:
            ec = ecalls_by_idx.get(idx)
            if not ec or get_scalable_bound_offsets(ec) is None:
                continue
            sseq0 = all_observed_field_sseqs.get(idx, [0])[0]
            q_sc = min(sc, 1024)
            modes = (0, 2) if sc <= 4096 else (0,)
            specs = [
                build_scale_bound_v2_spec(ec, sc, q_sc, mode=m, selector_seq=sseq0)
                for m in modes
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
                    "desc": f"Scale expansion n={sc} on {ec['name']}@{sseq0}",
                })

    # 3. boundary, joint, slice_rel, content: Interleaved across ALL selected (idx, sseq) positions!
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
                if is_bound:
                    dom = [1, 16] if sseq == 0 else []
                else:
                    dom = [v for v in DECLARED_CONTROL_SCALAR_DOMAIN if v != 0 and (v != 99 or sseq == 0)]
                rng.shuffle(dom)
                for val in dom:
                    op_name = "set_scalar" if is_bound else "replace_scalar"
                    stop_bef = f"{idx}:{sseq}" if is_bound else ""
                    target_list = c_list if is_bound else b_list
                    target_fam = "content" if is_bound else "boundary"
                    target_list.append({
                        "family": target_fam,
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

        b_list.sort(key=lambda x: (0 if x.get("is_control_scalar") else 1))

        if sseq == 0:
            control_scalars = [(spidx, sp) for spidx, sp in scalar_params if sp.get("ms_offset") not in bound_offs]
            for spidx, sp in (control_scalars or scalar_params[:1]):
                for ppidx, pp in in_ptr_params[:1]:
                    jvals = [1, 2, 3, 4, 8, 16]
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

            if len(all_ptr_params) >= 2:
                p0_idx, p0 = all_ptr_params[0]
                p1_idx, p1 = all_ptr_params[1]
                for shift in (4, 8):
                    a_list.append({
                        "family": "slice_rel",
                        "subkind": "cross_buffer_slice_relation",
                        "ecall_index": idx,
                        "selector_seq": sseq,
                        "param_index": p0_idx,
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

    # 5. history: Interleave ALL declared history depths (24, 64, 256, 1024) uniformly across ALL Field selectors
    for depth in DECLARED_HISTORY_DEPTHS:
        for idx in field_selectors:
            ec = ecalls_by_idx.get(idx)
            if not ec or not ec.get("replay_supported", True):
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
        if mode not in ("fixed_round_robin", "static_priority_no_feedback", "feedback_guided"):
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

        # Concrete per-Field feedback state (never merges across Fields or collapses call positions!)
        self.cumulative_s3_field_effects: set[tuple[str, int, str]] = set()
        self.cumulative_s3_field_pages: set[tuple[str, int]] = set()
        self.cumulative_s3_effects: set[tuple[int, str]] = set()
        self.cumulative_s3_pages: set[int] = set()
        self.max_heap_pages_by_ecall: dict[int, int] = {}
        self.scale_s3_effects_by_ecall: dict[int, set[tuple[str, int, str]]] = {}
        self.scale_max_heap_by_ecall: dict[int, int] = {}
        self.seen_state_obs_keys: set[tuple] = set()
        self.productive_plans: list[dict] = []
        self.follow_up_queue: list[dict] = []
        self.secondary_branch_queue: list[dict] = []
        self.low_priority_queue: list[dict] = []
        self.selection_trace: list[dict] = []
        self.feedback_decisions: list[dict] = []
        self.failed_repeat_selectors: dict[int, str] = {}
        self.stagnant_scale_selectors: dict[int, int] = {}
        self.stagnant_history_selectors: dict[int, int] = {}
        self.slot_zero_gain_streak: dict[tuple, int] = {}

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
        recs = res.get("records") or []
        self.total_ecalls += len(recs)
        req_ipi = (4 if plan.get("family") == "history" else 7) if "ipi_mask" in res else None
        valid_meas, meas_reasons = is_valid_measurement_run(
            res,
            allow_nonzero_rc=bool(plan.get("allow_nonzero_rc", False) or plan.get("family", "seed") != "seed"),
            require_ipi_mask=req_ipi,
            require_nonempty_s3=True,
            require_aex_counter=True,
        )
        if not valid_meas:
            self.measurement_invalid_runs += 1
            delta = {
                "measurement_invalid": True,
                "invalid_reasons": meas_reasons,
                "new_effects_set": [],
                "new_effects_count": 0,
                "new_pages_count": 0,
                "new_state_keys": 0,
                "target_new_state_keys": 0,
                "heap_grew": False,
                "any_valid_field_return": False,
                "returncode": res.get("returncode", -1),
            }
            self.selection_trace.append({
                "step": self.enclave_creations,
                "tag": plan.get("tag", "seed"),
                "family": plan.get("family", "seed"),
                "spec": plan.get("spec", ""),
                "source_queue": plan.get("_source_queue", "seed"),
                "measurement_invalid": True,
                "invalid_reasons": meas_reasons,
                "new_effects_count": 0,
                "new_state_keys": 0,
                "target_new_state_keys": 0,
                "heap_grew": False,
            })
            return res, delta

        run_s3_field_effects: set[tuple[str, int, str]] = set()
        run_s3_field_pages: set[tuple[str, int]] = set()
        run_s3_effects: set[tuple[int, str]] = set()
        run_s3_pages: set[int] = set()
        new_state_keys = 0
        target_new_state_keys = 0
        heap_grew = False
        any_valid_field_return = False

        target_eidx = plan.get("ecall_index", -1)
        for rec in recs:
            fb = extract_concrete_record_feedback(rec)
            is_target_call = (
                target_eidx < 0
                or plan.get("family") == "replace_prefix"
                or (rec.get("ecall_index") == target_eidx and rec.get("tag") != "host_normal")
            )
            if fb["state_obs_key"] not in self.seen_state_obs_keys:
                self.seen_state_obs_keys.add(fb["state_obs_key"])
                new_state_keys += 1
                if is_target_call and fb["entered_field"] and fb["ret_cat"] == 0:
                    target_new_state_keys += 1
            if fb["entered_field"]:
                self.valid_field_ecalls += 1
                if fb["ret_cat"] == 0 and is_target_call:
                    any_valid_field_return = True
                run_s3_field_effects |= fb["s3_field_effects"]
                run_s3_field_pages |= fb["s3_field_pages"]
                run_s3_effects |= fb["s3_effects"]
                run_s3_pages |= fb["s3_pages"]
                eidx = rec.get("ecall_index", -1)
                prev_hp = self.max_heap_pages_by_ecall.get(eidx, 0)
                if fb["heap_pages"] > prev_hp:
                    self.max_heap_pages_by_ecall[eidx] = fb["heap_pages"]
                    heap_grew = True
                if plan.get("family") == "seed" and rec.get("selector_seq") == 0:
                    self.scale_s3_effects_by_ecall.setdefault(eidx, set()).update(fb["s3_field_effects"])
                    self.scale_max_heap_by_ecall[eidx] = max(self.scale_max_heap_by_ecall.get(eidx, 0), fb["heap_pages"])
                elif plan.get("family") == "scale" and rec.get("ecall_index") == target_eidx and rec.get("tag") != "host_normal":
                    sc_effs = self.scale_s3_effects_by_ecall.setdefault(eidx, set())
                    if fb["s3_field_effects"] - sc_effs:
                        sc_effs.update(fb["s3_field_effects"])
                    prev_sc_hp = self.scale_max_heap_by_ecall.get(eidx, 0)
                    if fb["heap_pages"] > prev_sc_hp:
                        self.scale_max_heap_by_ecall[eidx] = fb["heap_pages"]
                        heap_grew = True
            else:
                if rec.get("ecall_index") in self.field_selectors and fb["ret_cat"] != 0:
                    self.expected_s0_rejections += 1
                else:
                    self.non_field_setup_ecalls += 1

        new_concrete_field_effects = run_s3_field_effects - self.cumulative_s3_field_effects
        new_concrete_field_pages = run_s3_field_pages - self.cumulative_s3_field_pages
        self.cumulative_s3_field_effects |= run_s3_field_effects
        self.cumulative_s3_field_pages |= run_s3_field_pages
        self.cumulative_s3_effects |= run_s3_effects
        self.cumulative_s3_pages |= run_s3_pages

        delta = {
            "new_effects_set": sorted((fid, hex(r), e) for fid, r, e in new_concrete_field_effects),
            "new_effects_count": len(new_concrete_field_effects),
            "new_pages_count": len(new_concrete_field_pages),
            "new_state_keys": new_state_keys,
            "target_new_state_keys": target_new_state_keys,
            "heap_grew": heap_grew,
            "any_valid_field_return": any_valid_field_return,
            "returncode": res.get("returncode", 0),
        }
        self.selection_trace.append({
            "step": self.enclave_creations,
            "tag": plan.get("tag", "seed"),
            "family": plan.get("family", "seed"),
            "spec": plan.get("spec", ""),
            "source_queue": plan.get("_source_queue", "seed"),
            "measurement_invalid": False,
            "new_effects_count": len(new_concrete_field_effects),
            "new_state_keys": new_state_keys,
            "target_new_state_keys": target_new_state_keys,
            "heap_grew": heap_grew,
        })
        return res, delta

    def _update_feedback_and_spawn(self, plan: dict, delta: dict, queues: dict[str, list[dict]], spawned_tags: set[str]) -> None:
        """Genuine feedback update:
        - Saves productive plans that discovered concrete new per-Field S3 effects OR new valid business states.
        - Spawns targeted follow-up plans around productive scalar values (including when new_state_keys > 0
          without new pages or heap growth!).
        - Moves remaining candidates of a hit slot into `secondary_branch_queue` (which receives periodic
          anti-starvation turns and runs immediately after first-pass structural slots, before `low_priority_queue`).
        - Demotes S0-rejected non-scalable selectors and stagnant scale/history tails into `low_priority_queue`.
        """
        if delta.get("measurement_invalid", False):
            self.feedback_decisions.append({
                "tag": plan.get("tag", ""),
                "decision": f"measurement_invalid_ignored:{','.join(delta.get('invalid_reasons', []))}",
            })
            return
        fam = plan.get("family", "")
        eidx = plan.get("ecall_index", -1)
        sseq = plan.get("selector_seq", 0)

        if fam == "history":
            if delta["returncode"] != 0:
                reason = f"repeat_attempt_failed_rc_{delta['returncode']}"
                self.failed_repeat_selectors[eidx] = reason
                queues["history"] = [q for q in queues["history"] if q.get("ecall_index") != eidx]
                self.feedback_decisions.append({
                    "tag": plan["tag"],
                    "decision": reason,
                })
                return
            if delta["new_effects_count"] == 0 and not delta["heap_grew"]:
                hstag = self.stagnant_history_selectors.get(eidx, 0) + 1
                self.stagnant_history_selectors[eidx] = hstag
                if hstag >= 1 and plan.get("history_depth", 0) >= 64:
                    kept = [q for q in queues["history"] if q.get("ecall_index") != eidx]
                    demoted = [q for q in queues["history"] if q.get("ecall_index") == eidx]
                    queues["history"] = kept
                    self.low_priority_queue.extend(demoted)
                    self.feedback_decisions.append({
                        "tag": plan["tag"],
                        "decision": "demote_history_stagnant_at_64",
                    })
                    return
            else:
                self.stagnant_history_selectors[eidx] = 0
                next_hd = plan.get("history_depth", 0) * 4
                for idx_q, q in enumerate(queues.get("history", [])):
                    if q.get("ecall_index") == eidx and q.get("history_depth") == next_hd:
                        promoted = queues["history"].pop(idx_q)
                        self.follow_up_queue.append(promoted)
                        self.feedback_decisions.append({
                            "tag": plan["tag"],
                            "decision": f"promote_history_{next_hd}_on_e{eidx}",
                        })
                        break

        if fam == "scale":
            sc = plan.get("scale", 0)
            if not delta["any_valid_field_return"]:
                rej_key = ("scale_rej", eidx)
                rstreak = self.slot_zero_gain_streak.get(rej_key, 0) + 1
                self.slot_zero_gain_streak[rej_key] = rstreak
                if rstreak >= 2 and self.slot_zero_gain_streak.get(("scale_entered", eidx), 0) == 0 and queues.get("scale"):
                    kept = [q for q in queues["scale"] if q.get("ecall_index") != eidx]
                    demoted = [q for q in queues["scale"] if q.get("ecall_index") == eidx]
                    queues["scale"] = kept
                    self.low_priority_queue.extend(demoted)
                    self.feedback_decisions.append({
                        "tag": plan["tag"],
                        "scale": sc,
                        "decision": f"demote_non_scalable_selector_e{eidx}",
                    })
                else:
                    self.feedback_decisions.append({
                        "tag": plan["tag"],
                        "scale": sc,
                        "decision": "continue_past_rejected_scale",
                    })
                return
            self.slot_zero_gain_streak[("scale_entered", eidx)] = 1
            if delta["heap_grew"] or (sc < 4096 and delta["new_effects_count"] > 0):
                self.stagnant_scale_selectors[eidx] = 0
                next_sc = sc * 4
                if 16 < next_sc <= (262144 if delta["heap_grew"] else 4096):
                    promoted = None
                    for idx_q, q in enumerate(queues.get("scale", [])):
                        if q.get("ecall_index") == eidx and q.get("scale") == next_sc:
                            promoted = queues["scale"].pop(idx_q)
                            break
                    if promoted is not None:
                        self.follow_up_queue.append(promoted)
                        self.feedback_decisions.append({
                            "tag": plan["tag"],
                            "scale": sc,
                            "decision": f"promote_scale_{next_sc}",
                        })
            elif sc >= 4096 and not delta["heap_grew"]:
                kept = [q for q in queues["scale"] if q.get("ecall_index") != eidx]
                demoted = [q for q in queues["scale"] if q.get("ecall_index") == eidx]
                queues["scale"] = kept
                self.low_priority_queue.extend(demoted)
                self.feedback_decisions.append({
                    "tag": plan["tag"],
                    "scale": sc,
                    "decision": "demote_stagnant_superpage_scale",
                })

        if fam == "joint":
            if not delta["any_valid_field_return"]:
                jrej_key = ("joint_rej", eidx)
                jr = self.slot_zero_gain_streak.get(jrej_key, 0) + 1
                self.slot_zero_gain_streak[jrej_key] = jr
                if jr >= 2 and self.slot_zero_gain_streak.get(("joint_entered", eidx), 0) == 0 and queues.get("joint"):
                    kept = [q for q in queues["joint"] if q.get("ecall_index") != eidx]
                    demoted = [q for q in queues["joint"] if q.get("ecall_index") == eidx]
                    queues["joint"] = kept
                    self.low_priority_queue.extend(demoted)
                    self.feedback_decisions.append({
                        "tag": plan["tag"],
                        "decision": f"demote_s0_rejected_joint_selector_e{eidx}",
                    })
            else:
                self.slot_zero_gain_streak[("joint_entered", eidx)] = 1

        # Active-slot reprioritization (heuristic priority shift to secondary_branch_queue):
        # When a parameter slot (fam, eidx, sseq, pidx) discovers concrete new S3 effects,
        # move its remaining enum candidates to `secondary_branch_queue` so unhit slots get immediate
        # turns first, and then `secondary_branch_queue` explores multi-branch values on this slot!
        slot_key = (fam, eidx, sseq, plan.get("param_index", -1))
        if fam in ("replace_prefix", "boundary", "joint", "slice_rel") and delta["new_effects_count"] > 0 and queues.get(fam):
            kept, reprioritized = [], []
            for q in queues[fam]:
                qkey = (q.get("family"), q.get("ecall_index", -1), q.get("selector_seq", 0), q.get("param_index", -1))
                if qkey == slot_key:
                    reprioritized.append(q)
                else:
                    kept.append(q)
            if reprioritized:
                queues[fam] = kept
                self.secondary_branch_queue.extend(reprioritized)
                self.feedback_decisions.append({
                    "tag": plan["tag"],
                    "decision": f"reprioritize_slot_after_hit_{fam}_e{eidx}_s{sseq}_p{plan.get('param_index')}_count_{len(reprioritized)}",
                })

        # Case A: Plan discovered concrete new per-Field S3 effects or heap growth
        if delta["new_effects_count"] > 0 or delta["heap_grew"]:
            self.productive_plans.append({
                "tag": plan["tag"],
                "family": fam,
                "spec": plan["spec"],
                "reason": "new_concrete_effects_or_heap",
                "new_effects": delta["new_effects_set"],
            })
        # Case B: No new pages or heap growth, but a new valid Field-entering state key was observed!
        elif delta["target_new_state_keys"] > 0 and delta["any_valid_field_return"]:
            self.productive_plans.append({
                "tag": plan["tag"],
                "family": fam,
                "spec": plan["spec"],
                "reason": "new_valid_state_key_without_new_pages",
                "new_effects": [],
            })
            if fam == "boundary" and plan.get("scalar_val") is not None:
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
                                    "param_index": pidx,
                                    "scalar_val": val,
                                    "spec": f"joint_scalar_xor:{eidx}:{sseq}:{pidx}:{val}:{ppidx}:0:255",
                                    "stop_after": "",
                                    "stop_before": f"{eidx}:{sseq}",
                                    "allow_nonzero_rc": False,
                                    "tag": ftag,
                                    "desc": f"Feedback-spawned joint probe around state-changing {ec['name']}@{sseq} val={val}",
                                })
                                self.feedback_decisions.append({
                                    "tag": plan["tag"],
                                    "decision": f"spawn_state_novelty_followup_{ftag}",
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
        all_generated_specs: set[str] = {
            cand["spec"] for q in queues.values() for cand in q if cand.get("spec")
        }

        frontier_snapshots_by_step: dict[int, list[str]] = {}

        def snapshot_remaining_specs() -> list[str]:
            return (
                [c["spec"] for c in self.follow_up_queue if c.get("spec")]
                + [c["spec"] for q in queues.values() for c in q if c.get("spec")]
                + [c["spec"] for c in self.secondary_branch_queue if c.get("spec")]
                + [c["spec"] for c in self.low_priority_queue if c.get("spec")]
            )

        fam_idx = 0
        turn = 0
        while self._can_continue():
            if self.mode == "feedback_guided" and self.follow_up_queue:
                cand = self.follow_up_queue.pop(0)
                cand["_source_queue"] = "follow_up_queue"
            elif self.mode == "feedback_guided" and self.secondary_branch_queue and turn > 0 and turn % 16 == 0:
                cand = self.secondary_branch_queue.pop(0)
                cand["_source_queue"] = "secondary_branch_queue_periodic"
            elif self.mode == "feedback_guided" and self.low_priority_queue and turn > 0 and turn % 28 == 14:
                cand = self.low_priority_queue.pop(0)
                cand["_source_queue"] = "low_priority_queue_periodic"
            elif self.mode in ("feedback_guided", "static_priority_no_feedback") and queues.get("content") and turn > 0 and turn % 36 == 26:
                cand = queues["content"].pop(0)
                cand["_source_queue"] = "content_periodic"
            elif self.mode in ("feedback_guided", "static_priority_no_feedback"):
                structural_fams = [f for f in ("replace_prefix", "scale", "joint", "slice_rel", "boundary", "history") if queues.get(f)]
                if structural_fams:
                    if turn % 2 == 1:
                        fam = max(structural_fams, key=lambda f: len(queues[f]))
                    else:
                        fam = structural_fams[fam_idx % len(structural_fams)]
                        fam_idx += 1
                    cand = queues[fam].pop(0)
                    cand["_source_queue"] = f"primary_{fam}"
                elif self.secondary_branch_queue:
                    cand = self.secondary_branch_queue.pop(0)
                    cand["_source_queue"] = "secondary_branch_queue_drain"
                elif self.low_priority_queue:
                    cand = self.low_priority_queue.pop(0)
                    cand["_source_queue"] = "low_priority_queue_drain"
                elif queues.get("content"):
                    cand = queues["content"].pop(0)
                    cand["_source_queue"] = "content_drain"
                else:
                    self.stop_reason = "candidates_exhausted"
                    break
            else:
                avail_fams = [f for f in FAMILY_ORDER if queues.get(f)]
                if not avail_fams:
                    if self.secondary_branch_queue:
                        cand = self.secondary_branch_queue.pop(0)
                        cand["_source_queue"] = "secondary_branch_queue_drain"
                    elif self.low_priority_queue:
                        cand = self.low_priority_queue.pop(0)
                        cand["_source_queue"] = "low_priority_queue_drain"
                    else:
                        self.stop_reason = "candidates_exhausted"
                        break
                else:
                    fam = avail_fams[fam_idx % len(avail_fams)]
                    fam_idx += 1
                    cand = queues[fam].pop(0)
                    cand["_source_queue"] = f"round_robin_{fam}"

            turn += 1
            plan = {
                "run_id": f"layer2_{cand['tag']}",
                "layer": "layer2_generic_schema",
                **cand,
            }
            _, delta = self._execute_plan(plan)
            if self.mode == "feedback_guided":
                self._update_feedback_and_spawn(plan, delta, queues, spawned_tags)
            if self.enclave_creations in (68, 128, 256):
                frontier_snapshots_by_step[self.enclave_creations] = snapshot_remaining_specs()

        remaining_by_family = {f: len(q) for f, q in queues.items() if q}
        all_deferred = self.secondary_branch_queue + self.low_priority_queue
        low_prio_by_family: dict[str, int] = {}
        for q in all_deferred:
            f = q.get("family", "unknown")
            low_prio_by_family[f] = low_prio_by_family.get(f, 0) + 1
        for f_c in self.follow_up_queue:
            if f_c.get("spec"):
                all_generated_specs.add(f_c["spec"])
        for s_t in self.selection_trace:
            if s_t.get("spec"):
                all_generated_specs.add(s_t["spec"])
        remaining_specs = [
            c["spec"]
            for q in queues.values()
            for c in q
            if c.get("spec")
        ] + [c["spec"] for c in all_deferred if c.get("spec")] + [c["spec"] for c in self.follow_up_queue if c.get("spec")]
        unexplored_hist = [
            f"ecall_{q.get('ecall_index')}@{q.get('selector_seq')}:depth={q.get('history_depth')}"
            for q in (queues.get("history", []) + [x for x in all_deferred if x.get("family") == "history"])
        ]
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
            "confirmed_s3_field_pages": len(self.cumulative_s3_field_pages),
            "confirmed_s3_field_effects": len(self.cumulative_s3_field_effects),
            "confirmed_s3_pages": len(self.cumulative_s3_pages),
            "confirmed_s3_effects": len(self.cumulative_s3_effects),
            "productive_plans": self.productive_plans,
            "feedback_decisions": self.feedback_decisions,
            "selection_trace": self.selection_trace,
            "unexplored_frontier": {
                **frontier_meta,
                "failed_repeat_selectors": {str(k): v for k, v in self.failed_repeat_selectors.items()},
                "remaining_candidates_by_family": remaining_by_family,
                "remaining_secondary_branch_candidates": len(self.secondary_branch_queue),
                "remaining_low_priority_by_family": low_prio_by_family,
                "remaining_low_priority_candidates": len(all_deferred),
                "remaining_low_priority_tags": [c["tag"] for c in all_deferred],
                "remaining_followup_candidates": len(self.follow_up_queue),
                "remaining_specs": remaining_specs,
                "frontier_snapshots_by_step": frontier_snapshots_by_step,
                "all_generated_specs_count": len(all_generated_specs),
                "unexplored_history_depths": unexplored_hist,
                "total_unexplored_candidates": (
                    sum(remaining_by_family.values())
                    + len(all_deferred)
                    + len(self.follow_up_queue)
                ),
            },
        }
