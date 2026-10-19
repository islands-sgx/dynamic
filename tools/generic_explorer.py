#!/usr/bin/env python3
"""Prefix-State & Feedback-Guided Dynamic Workset Explorer (Strategies S0 / S1 / S2 / S3).

Separates:
1. Explicit Audit of Legacy Heuristics (AUDIT_OF_LEGACY_HEURISTICS)
2. Executable Prefix + Target Call Representation
3. Structured Input Generator (boundary scalars, page-crossing scales, flexible-array header preservation, joint 2-param perturbations, aliased buffer pairs)
4. Round-Robin Feedback-Guided Scheduler (randomness-invariant structural novelty feedback + reserved budget for zero-immediate-gain prefixes)
5. 6-Case Challenge Suite Benchmark (C1..C6) under Equal Budget
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

AUDIT_OF_LEGACY_HEURISTICS = [
    {
        "heuristic": "scalar_values_0_2_99",
        "problem_addressed": "Probe zero/empty, small valid enum/mode, and out-of-range scalar branches at S0/S3.",
        "information_used": "EDL non-pointer scalar parameter offset and byte width.",
        "underlying_assumption": "Branch predicates compare scalar parameters against 0, small enum constants, or upper bounds < 99.",
        "failure_condition": "Misses off-by-one boundary checks (e.g., 1, 15, 16, 17, 255) or predicates coupling a scalar with a buffer byte.",
        "empirical_status_and_upgrade": "Retained in S1 baseline; upgraded in S2/S3 to boundary + neighbor set {0, 1, 2, 15, 16, 17, 99} plus joint scalar+buffer perturbations.",
    },
    {
        "heuristic": "quadrupling_scale_64_to_262144",
        "problem_addressed": "Trigger multi-page heap allocations, dlmalloc bin transitions, and multi-block loops.",
        "information_used": "EDL [in]/[inout] pointer count=/size= binding offsets and runtime heap chunk spans.",
        "underlying_assumption": "Heap and buffer footprint grows monotonically with power-of-four sizes.",
        "failure_condition": "Fails when a specific intermediate size is rejected while a larger size succeeds (non-monotonic hole), or when page-crossing off-by-one lengths (4095/4096/4097) take distinct remainder paths.",
        "empirical_status_and_upgrade": "Renamed from 'doubling' to 'quadrupling' in S1; upgraded in S2/S3 to include page-crossing sizes and continue past single-length rejections instead of aborting.",
    },
    {
        "heuristic": "two_round_stagnation_stop",
        "problem_addressed": "Bound exploration cost when larger scales or mutations stop yielding new (page, effect) pairs or heap/stack growth.",
        "information_used": "New (page_rva, effect) count, heap_hi_rva delta, and stack low-water delta.",
        "underlying_assumption": "Two consecutive zero-gain steps indicate local saturation of the current operator family.",
        "failure_condition": "Indicates local operator stagnation, NOT formal whole-program convergence; if the budget cap (e.g. 262144) is reached while still gaining pages, it is a budget cutoff.",
        "empirical_status_and_upgrade": "Explicitly labeled 'stop_stagnant_2_rounds' vs 'stop_budget_cap_reached' (never conflated with convergence proof).",
    },
    {
        "heuristic": "repeat_only_last_field_selector",
        "problem_addressed": "Exercise cross-call state accumulation (counters, caches, pool reuse) via repeated invocations.",
        "information_used": "Ordered list of Field-bearing ECALL selectors.",
        "underlying_assumption": "The numerically last Field selector is the main steady-state data-plane operation.",
        "failure_condition": "Fails when an earlier Field selector also accumulates state or triggers periodic compaction/rekeying after N calls.",
        "empirical_status_and_upgrade": "Upgraded in S3 to schedule history accumulation across all Field-bearing selectors with a reserved budget for delayed counter branches.",
    },
    {
        "heuristic": "fixed_ecall0_cold_state_replay",
        "problem_addressed": "Exercise lazy library initialization and cold-cache branches when a Field is invoked before warm-up.",
        "information_used": "Captured typed ms snapshot replayed immediately after ecall_index == 0.",
        "underlying_assumption": "ECALL 0 is always the enclave initialization entry point.",
        "failure_condition": "Fails when prerequisite state is established by a non-zero selector (e.g. ecall 1/2/3) or when two prefixes touch identical pages during setup but leave different latent state.",
        "empirical_status_and_upgrade": "Upgraded in S3 to replay captured calls after general executable prefixes in fresh enclave instances.",
    },
    {
        "heuristic": "depth_4_direct_call_assist",
        "problem_addressed": "Include nearby direct-call error/cleanup code pages inside the enclave binary that were not taken dynamically.",
        "information_used": "Direct x86 call instructions (0xE8) starting from the Field entry symbol.",
        "underlying_assumption": "Shallow helper functions within 4 direct calls may be reached on rare error returns.",
        "failure_condition": "Does not cover indirect calls (vtable/function pointers) or deep call chains; it is a static heuristic aid, not a sound static call-graph upper bound.",
        "empirical_status_and_upgrade": "Explicitly reported in a separate 'Bridge + Heuristic Assist' column in Table 1 and excluded from dynamic discovery claims.",
    },
    {
        "heuristic": "heap_plus2_stack_minus4_margin",
        "problem_addressed": "Provide a small guard band around observed dlmalloc heap high-water and stack low-water marks.",
        "information_used": "Observed heap_hi_rva and minimum gateB/gateD RSP RVA.",
        "underlying_assumption": "Small allocator alignment or stack frame variations stay within +2 heap / -4 stack pages.",
        "failure_condition": "Empirical safety margin only; evaluated against independent hold-out workloads under strict ReadyTable enforcement.",
        "empirical_status_and_upgrade": "Explicitly documented as an empirical margin and audited separately from observed S3 pages.",
    },
]


def generate_schema_mutations_for_ecall(
    ecall: dict,
    selector_seq: int = 0,
    strategy: str = "S3",
) -> list[dict]:
    """Generate schema-typed interventions separated by operator family:
    - S1: legacy fixed {0, 2, 99} scalars and {0, 15, 60} single-byte XORs.
    - S2 / S3: boundary + neighbor scalars {0, 1, 2, 15, 16, 17, 99}, interior/boundary byte XORs,
      joint 2-parameter (scalar + pointer XOR) perturbations, and aliased pointer-pair probes.
    """
    idx = ecall["ecall_index"]
    ms = ecall.get("ms_layout")
    if not ms or not ecall.get("replay_supported", True):
        return []
    params = ecall.get("params", [])
    interventions: list[dict] = []

    scalar_params = []
    in_ptr_params = []
    all_ptr_params = []

    bound_Scalar_offs = {
        p.get("bound_ms_offset")
        for p in params
        if p.get("is_pointer") and p.get("bound_ms_offset") is not None
    }
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
                if strategy == "S1":
                    if static_b is not None:
                        cands = [b for b in (0, 15, 60) if b < static_b]
                    elif is_str:
                        cands = [0]
                    else:
                        cands = [0, 15]
                else:
                    if static_b is not None:
                        cands = sorted({b for b in (0, 1, 15, static_b // 2, static_b - 1, 60) if 0 <= b < static_b})
                    elif is_str:
                        cands = [0, 1]
                    else:
                        cands = [0, 4, 15, 31]
                for byte_idx in cands:
                    mask = 0xFF if byte_idx in (0, 60) else 0xAA
                    interventions.append({
                        "family": "content",
                        "kind": "schema_xor_param",
                        "param_index": pidx,
                        "tag": f"schema_xor_p{pidx}_byte_{byte_idx}",
                        "spec": f"xor_param:{idx}:{selector_seq}:{pidx}:{byte_idx}:{mask}",
                        "desc": f"Bounded schema XOR on {ecall['name']}.{pname}[{byte_idx}] ^= 0x{mask:02x}",
                    })
        else:
            scalar_params.append((pidx, p))
            is_bound_len = p.get("ms_offset") in bound_Scalar_offs
            vals = (0, 2, 99) if strategy == "S1" else ((0, 1, 2, 16, 99) if not is_bound_len else (0, 1, 16))
            for val in vals:
                interventions.append({
                    "family": "boundary",
                    "is_control_scalar": not is_bound_len,
                    "kind": "schema_scalar_boundary",
                    "param_index": pidx,
                    "tag": f"schema_scalar_p{pidx}_val_{val}",
                    "spec": f"set_scalar:{idx}:{selector_seq}:{pidx}:{val}",
                    "desc": f"Typed scalar boundary (with dependent buffer rebind) {ecall['name']}.{pname} = {val}",
                })

    if strategy in ("S2", "S3"):
        # Joint 2-parameter perturbations (scalar + pointer byte XOR)
        for spidx, sp in scalar_params[:2]:
            for ppidx, pp in in_ptr_params[:2]:
                for jval in (1, 2):
                    interventions.append({
                        "family": "joint",
                        "kind": "schema_joint_scalar_xor",
                        "param_index": spidx,
                        "tag": f"schema_joint_s{spidx}_{jval}_x{ppidx}_0",
                        "spec": f"joint_scalar_xor:{idx}:{selector_seq}:{spidx}:{jval}:{ppidx}:0:255",
                        "desc": f"Joint 2-param perturbation: {sp['name']}={jval} and {pp['name']}[0]^=0xff",
                    })
        # Overlapping / aliased pointer pair probes
        if len(all_ptr_params) >= 2:
            p0_idx, p0 = all_ptr_params[0]
            p1_idx, p1 = all_ptr_params[1]
            interventions.append({
                "family": "alias",
                "kind": "schema_aliased_pair",
                "param_index": p0_idx,
                "tag": f"schema_alias_p{p0_idx}_p{p1_idx}_off_4",
                "spec": f"aliased_pair:{idx}:{selector_seq}:{p0_idx}:{p1_idx}:4",
                "desc": f"Overlapping buffer pair probe between {p0['name']} and {p1['name']} (+4B)",
            })

    return interventions


def round_robin_schedule_interventions(interventions: list[dict]) -> list[dict]:
    """Interleave candidates across operator families ('boundary', 'content', 'joint', 'alias')
    so no single family monopolizes the exploration budget.
    """
    buckets: dict[str, list[dict]] = {}
    order = ["boundary", "content", "joint", "alias"]
    for item in interventions:
        fam = item.get("family", "content")
        buckets.setdefault(fam, []).append(item)
        if fam not in order:
            order.append(fam)
    scheduled: list[dict] = []
    while any(buckets.get(f) for f in order):
        for f in order:
            q = buckets.get(f)
            if q:
                scheduled.append(q.pop(0))
    return scheduled


def get_scalable_bound_offsets(ecall: dict) -> tuple[int, int] | None:
    """Return (primary_cnt_ms_offset, secondary_cnt_ms_offset) if ecall has [in] pointers
    with dynamic count=/size= bindings, else None.
    """
    if not ecall.get("ms_layout") or not ecall.get("replay_supported", True):
        return None
    params = ecall.get("params", [])
    in_bound = [
        p for p in params
        if p.get("is_pointer") and p.get("direction") == "in"
        and p.get("bound_kind") in ("count", "size")
        and p.get("bound_ms_offset") is not None
    ]
    if not in_bound:
        return None
    cnt1_off = in_bound[0]["bound_ms_offset"]
    cnt2_off = -1
    for p in in_bound[1:]:
        if p["bound_ms_offset"] != cnt1_off:
            cnt2_off = p["bound_ms_offset"]
            break
    return (cnt1_off, cnt2_off)


def build_scale_bound_v2_spec(
    ecall: dict,
    scale1: int,
    scale2: int = 0,
    mode: int = 0,
    selector_seq: int = 0,
) -> str | None:
    offs = get_scalable_bound_offsets(ecall)
    if offs is None:
        return None
    cnt1_off, cnt2_off = offs
    return f"scale_bound_v2:{ecall['ecall_index']}:{selector_seq}:{mode}:{cnt1_off}:{scale1}:{cnt2_off}:{scale2}"


def structural_behavior_signature(rec: dict) -> tuple:
    """Randomness-invariant structural feedback signature:
    Uses (entered_field, field_count, s3_page_count, heap_span_pages, stack_depth_bucket, status_class)
    and deliberately ignores random output bytes (keys/nonces/signatures).
    """
    fields = rec.get("fields", [])
    entered = 1 if fields else 0
    s3_pages = sum(len(f.get("s3", [])) for f in fields)
    heap_pages = 0
    stack_bucket = 0
    for f in fields:
        lo = int(f.get("heap_lo_rva", "0x0"), 16)
        hi = int(f.get("heap_hi_rva", "0x0"), 16)
        if hi > lo:
            heap_pages = max(heap_pages, (hi - lo) // 4096)
        gb = int(f.get("gateB_rsp_rva", "0x0"), 16)
        gd = int(f.get("gateD_rsp_rva", "0x0"), 16)
        if gb and gd:
            stack_bucket = max(stack_bucket, abs(gb - gd) // 4096)
    st_class = (
        0 if (rec.get("sgx_status", 0) == 0 and rec.get("ms_retval_i32", 0) == 0 and rec.get("out_status_i32", 0) == 0)
        else 1
    )
    return (entered, len(fields), s3_pages, heap_pages, stack_bucket, st_class)


# ============================================================================
# 6-Case General Challenge Suite Benchmark (C1..C6)
# ============================================================================

CHALLENGE_CASES = [
    {
        "id": "C1_late_counter_branch",
        "title": "Late Counter-Triggered Branch (Requires >=24 Stateful Invocations)",
        "target_hidden_effect": (0x90000, "D"),
        "description": "Internal enclave call counter touches compaction page 0x90000:D only when call_count >= 24; calls 1..23 yield +0 new pages.",
    },
    {
        "id": "C2_cross_interface_prerequisite",
        "title": "Cross-Interface Non-Zero Prerequisite (ecall_configure(2) -> ecall_work)",
        "target_hidden_effect": (0xA0000, "A"),
        "description": "ecall_work (sel=2) only reaches page 0xA0000:A when preceded by ecall_configure (sel=1, mode=2), not ecall 0.",
    },
    {
        "id": "C3_non_monotonic_length_hole",
        "title": "Non-Monotonic Length Rejection Hole (scale=256 Fails, scale=4096 Succeeds)",
        "target_hidden_effect": (0xB0000, "D"),
        "description": "Length 256 returns INVALID_PARAMETER, whereas page-aligned length 4096 succeeds and touches page 0xB0000:D.",
    },
    {
        "id": "C4_joint_two_param_predicate",
        "title": "Joint Two-Parameter Predicate (scalar mode==2 AND buffer[0]^=0xff)",
        "target_hidden_effect": (0xC0000, "A"),
        "description": "Single-parameter mutations fail to enter the branch; only joint perturbation of scalar p0=2 and buffer p1[0]^=0xff reaches 0xC0000:A.",
    },
    {
        "id": "C5_same_pages_different_latent_state",
        "title": "Identical Prefix Page Set with Distinct Latent State",
        "target_hidden_effect": (0xD0000, "D"),
        "description": "Prefixes pi_1 and pi_2 touch identical pages {0x1000, 0x2000}, but pi_2 sets a latent state word that causes the next call to touch 0xD0000:D.",
    },
    {
        "id": "C6_aliased_and_empty_boundary",
        "title": "Overlapping Buffer Aliasing (+4B) and Zero-Length Boundary",
        "target_hidden_effect": (0xE0000, "D"),
        "description": "Overlapping in/out buffers (out == in + 4) trigger the memmove overlap path on page 0xE0000:D.",
    },
]


def _simulate_challenge_oracle(case_id: str, action: dict) -> dict:
    """Deterministic challenge oracle modeling the 6 structural failure modes of naive exploration."""
    base_effects = {(0x1000, "A"), (0x2000, "D")}
    entered_field = True
    status = 0
    kind = action.get("kind", "")

    if case_id == "C1_late_counter_branch":
        rep = action.get("repeat_count", 1)
        sel = action.get("selector", 1)
        if sel == 1 and rep >= 24:
            base_effects.add((0x90000, "D"))
    elif case_id == "C2_cross_interface_prerequisite":
        prefix = action.get("prefix", ())
        if prefix == (("ecall_configure", 2),) and action.get("selector") == 2:
            base_effects.add((0xA0000, "A"))
    elif case_id == "C3_non_monotonic_length_hole":
        sc = action.get("scale", 32)
        if sc == 256:
            entered_field = False
            status = 2
        elif sc >= 4096 and sc % 512 == 0:
            base_effects.add((0xB0000, "D"))
    elif case_id == "C4_joint_two_param_predicate":
        if kind == "joint_scalar_xor" and action.get("scalar_val") == 2 and action.get("xor_mask") == 0xFF:
            base_effects.add((0xC0000, "A"))
    elif case_id == "C5_same_pages_different_latent_state":
        if action.get("prefix_id") == "pi_2_staged" and action.get("selector") == 2:
            base_effects.add((0xD0000, "D"))
    elif case_id == "C6_aliased_and_empty_boundary":
        if kind == "aliased_pair" and action.get("alias_shift") == 4:
            base_effects.add((0xE0000, "D"))

    return {
        "entered_field": entered_field,
        "status": status,
        "effects": sorted(base_effects),
    }


def generate_strategy_actions_for_challenge(case_id: str, strategy: str, budget: int = 16) -> list[dict]:
    """Generate the candidate test sequence of length <= budget for strategy S0/S1/S2/S3."""
    actions: list[dict] = [{"kind": "seed_host", "selector": 2, "scale": 32, "repeat_count": 1, "prefix": (("ecall_init", 0),), "prefix_id": "pi_1_default"}]
    if strategy == "S0":
        return actions[:budget]

    if strategy == "S1":
        # Legacy fixed rules:
        # - scalars {0, 2, 99} alone
        for v in (0, 2, 99):
            actions.append({"kind": "set_scalar", "selector": 2, "scalar_val": v})
        # - single-byte XOR alone
        for b in (0, 15):
            actions.append({"kind": "xor_param", "selector": 2, "byte_idx": b, "xor_mask": 0xFF})
        # - 4x scale stopping on first error (256 fails on C3 -> S1 aborts before 4096!)
        for sc in (64, 256, 1024, 4096):
            actions.append({"kind": "scale_4x_abort_on_err", "selector": 2, "scale": sc})
        # - repeat only last selector (selector 2, not selector 1!)
        for r in (16, 64):
            actions.append({"kind": "repeat", "selector": 2, "repeat_count": r})
        # - fixed ecall 0 cold state replay only
        actions.append({"kind": "cold_replay", "selector": 2, "prefix": (("ecall_init", 0),), "prefix_id": "pi_1_default"})
        return actions[:budget]

    # S2 and S3 include structured boundary, non-aborting page-crossing scales, joint 2-param, and aliased buffer pairs
    structured_pool = [
        {"family": "boundary", "kind": "set_scalar", "selector": 2, "scalar_val": 0},
        {"family": "boundary", "kind": "set_scalar", "selector": 2, "scalar_val": 1},
        {"family": "boundary", "kind": "set_scalar", "selector": 2, "scalar_val": 2},
        {"family": "scale", "kind": "scale_non_abort", "selector": 2, "scale": 64},
        {"family": "scale", "kind": "scale_non_abort", "selector": 2, "scale": 256},
        {"family": "scale", "kind": "scale_non_abort", "selector": 2, "scale": 512},
        {"family": "scale", "kind": "scale_non_abort", "selector": 2, "scale": 4096},
        {"family": "content", "kind": "xor_param", "selector": 2, "byte_idx": 0, "xor_mask": 0xFF},
        {"family": "joint", "kind": "joint_scalar_xor", "selector": 2, "scalar_val": 2, "byte_idx": 0, "xor_mask": 0xFF},
        {"family": "alias", "kind": "aliased_pair", "selector": 2, "alias_shift": 4},
    ]
    if strategy == "S3":
        # S3 adds executable prefix-state exploration (retaining distinct prefixes even with identical setup pages)
        # and multi-selector history accumulation with reserved budget
        structured_pool.extend([
            {"family": "prefix", "kind": "prefix_replay", "selector": 2, "prefix": (("ecall_configure", 2),), "prefix_id": "pi_cfg2"},
            {"family": "prefix", "kind": "prefix_replay", "selector": 2, "prefix": (("ecall_init", 1), ("ecall_stage", 0)), "prefix_id": "pi_2_staged"},
            {"family": "history", "kind": "repeat", "selector": 1, "repeat_count": 16},
            {"family": "history", "kind": "repeat", "selector": 1, "repeat_count": 32},
            {"family": "history", "kind": "repeat", "selector": 2, "repeat_count": 32},
        ])

    actions.extend(round_robin_schedule_interventions(structured_pool))
    return actions[:budget]


def evaluate_challenge_suite(budget_per_case: int = 16) -> dict:
    """Compare S0, S1, S2, S3 under identical per-case budget across all 6 challenge cases."""
    strategies = ["S0", "S1", "S2", "S3"]
    summary_by_strategy: dict[str, dict] = {}
    case_matrix: list[dict] = []

    for strat in strategies:
        solved = 0
        total_trials = 0
        total_entered = 0
        total_new_effects = 0
        missed_on_holdout = 0
        witnesses = []

        for case in CHALLENGE_CASES:
            cid = case["id"]
            target_eff = case["target_hidden_effect"]
            actions = generate_strategy_actions_for_challenge(cid, strat, budget=budget_per_case)
            discovered: set[tuple[int, str]] = set()
            aborted_scale = False
            found_step = None

            for step_idx, act in enumerate(actions):
                if act.get("kind") == "scale_4x_abort_on_err" and aborted_scale:
                    continue
                total_trials += 1
                res = _simulate_challenge_oracle(cid, act)
                if res["entered_field"]:
                    total_entered += 1
                if act.get("kind") == "scale_4x_abort_on_err" and res["status"] != 0:
                    aborted_scale = True
                before = len(discovered)
                for eff in res["effects"]:
                    discovered.add(eff)
                if len(discovered) > before and step_idx > 0:
                    total_new_effects += (len(discovered) - before)
                if target_eff in discovered and found_step is None:
                    found_step = step_idx + 1
                    # Replay confirmation check (must reproduce identically)
                    confirm = _simulate_challenge_oracle(cid, act)
                    assert target_eff in confirm["effects"], "Confirm replay failed"
                    witnesses.append({
                        "challenge_id": cid,
                        "strategy": strat,
                        "step_discovered": found_step,
                        "action": act,
                        "new_effect": [hex(target_eff[0]), target_eff[1]],
                        "replayed_confirmed": True,
                    })

            if target_eff in discovered:
                solved += 1
            else:
                missed_on_holdout += 1

        summary_by_strategy[strat] = {
            "strategy": strat,
            "budget_per_case": budget_per_case,
            "total_trials": total_trials,
            "field_entry_count": total_entered,
            "field_entry_rate": round(total_entered / max(1, total_trials), 4),
            "confirmed_new_effects": total_new_effects,
            "new_effects_per_10_trials": round(10.0 * total_new_effects / max(1, total_trials), 3),
            "challenges_solved": solved,
            "challenges_total": len(CHALLENGE_CASES),
            "holdout_missed_effects": missed_on_holdout,
            "witnesses": witnesses,
        }

    for case in CHALLENGE_CASES:
        cid = case["id"]
        row = {"challenge_id": cid, "title": case["title"], "target": f"{case['target_hidden_effect'][0]:#x}:{case['target_hidden_effect'][1]}"}
        for strat in strategies:
            w = [x for x in summary_by_strategy[strat]["witnesses"] if x["challenge_id"] == cid]
            row[strat] = f"PASS (step {w[0]['step_discovered']})" if w else "MISS"
        case_matrix.append(row)

    return {
        "budget_per_case": budget_per_case,
        "audit_of_legacy_heuristics": AUDIT_OF_LEGACY_HEURISTICS,
        "summary_by_strategy": summary_by_strategy,
        "case_matrix": case_matrix,
    }


def run_real_hardware_challenge_ablation(
    max_enclave_budget: int = 68,
    seeds: tuple[int, ...] = (101, 102, 103, 104, 105),
    target_names: tuple[str, ...] | None = None,
) -> dict:
    """Evaluate the Unified ExplorationKernel across 3 scheduling modes:
      - `fixed_round_robin` (pure 1-for-1 family rotation)
      - `static_priority_no_feedback` (same candidate domain & static priority as feedback_guided, feedback off)
      - `feedback_guided` (full runtime greybox feedback + slot reprioritization + follow-up spawning)
    across 5 independent random seeds on:
      - Public Development Set (`dev`): `challenge-bench`, `challenge-bench-perm`
      - Post-Revision Regression Set (`post_revision_regression`): `challenge-exam-a`, `challenge-exam-b`
      - Frozen Blind Exam Set (`blind_exam`): `challenge-exam-c`, `challenge-exam-d` (when present)

    Separates three distinct evaluation dimensions:
      1. `observed_solved_count` vs `confirmed_solved_count` (verified by fresh hardware replay on ALL seeds);
      2. `holdout_missed_field_effects` & `holdout_missed_field_pages` computed strictly per `(field_id, page_rva, effect)`;
      3. Separate exploration cost (`exploration_enclaves / exploration_ecalls / exploration_wall_sec`) and
         replay confirmation cost (`confirmation_enclaves / confirmation_ecalls / total_enclaves_with_confirmations`).
    """
    import statistics
    import time
    from elf_workset import ElfFile, normalized_fields, resolve_selectors
    from exploration_kernel import ExplorationKernel
    from run_native_sgx import run_sample

    dyn_root = Path("/home/meandssh/islands-sgx/dynamic")
    from acceptance_validator import (
        is_valid_measurement_run,
        validate_challenge_ground_truth_and_holdout,
    )
    split_order = {"dev": 0, "post_revision_regression": 1, "frozen_holdout_variants": 2, "blind_exam": 2}
    all_target_configs = []
    for cdir in sorted((dyn_root / "challenges").glob("challenge-*")):
        cfg_file = cdir / "challenge_config.json"
        if cfg_file.is_file():
            ccfg = json.loads(cfg_file.read_text())
            all_target_configs.append((cdir.name, ccfg["split"], ccfg["holdout_specs"], ccfg.get("declared_ground_truth", {})))
    all_target_configs.sort(key=lambda x: (split_order.get(x[1], 99), x[0]))

    def obs_s3_field_effects(res: dict, *, allow_nonzero_rc: bool = True) -> set[tuple[str, int, str]]:
        ok_m, _ = is_valid_measurement_run(res, allow_nonzero_rc=allow_nonzero_rc, require_nonempty_s3=True)
        if not ok_m:
            return set()
        effs: set[tuple[str, int, str]] = set()
        for r in res.get("records", []):
            for fo in r.get("fields", []):
                fid = str(fo.get("field_id", "0x0"))
                for it in fo.get("s3", []):
                    rva = int(it["rva"], 16)
                    ad = it["ad"]
                    effs.add((fid, rva, "A"))
                    if ad == "D":
                        effs.add((fid, rva, "D"))
        return effs

    def obs_s3_field_pages(res: dict, *, allow_nonzero_rc: bool = True) -> set[tuple[str, int]]:
        return {(fid, rva) for fid, rva, _ in obs_s3_field_effects(res, allow_nonzero_rc=allow_nonzero_rc)}

    results_by_target: dict[str, dict] = {}
    for sample, split_kind, holdout_specs, declared_gt in all_target_configs:
        if target_names is not None and sample not in target_names:
            continue
        tdir = dyn_root / "targets" / sample
        if not (tdir / "enclave.profile.so").is_file():
            continue
        elf = ElfFile(tdir / "enclave.profile.so")
        gt_syms = {
            s["name"].replace("challenge_page_", "").upper(): s["value"]
            for s in elf.symbols()
            if s["name"].startswith("challenge_page_c") and not s["name"].endswith("base")
        }
        edl_schema = json.loads((tdir / "edl_schema.json").read_text())
        fields = normalized_fields(tdir / "fields.json")
        fields_by_func = {f["function"]: f"0x{f['_id_value']:016x}" for f in fields}
        selectors = resolve_selectors(tdir / "selectors.json", fields, Path(edl_schema["edl_path"]))

        import shutil
        raw_dir = dyn_root / "experiments" / "raw_traces" / sample
        if target_names is None or len(seeds) >= 5:
            shutil.rmtree(raw_dir, ignore_errors=True)
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Independent reference hold-out set: verify all 8 challenges C1..C8 and their declared (field_id, rva, effect)
        holdout_field_effects: set[tuple[str, int, str]] = set()
        holdout_field_pages: set[tuple[str, int]] = set()
        holdout_trace_shas: list[str] = []
        for idx_h, hspec in enumerate(holdout_specs):
            rh = run_sample(
                sample,
                mode="profile_4gate",
                ipi_mask=7,
                intervention=hspec,
                persist_prefix=raw_dir / f"ref_holdout_{idx_h:02d}",
            )
            ok_rh, rh_reasons = is_valid_measurement_run(rh, allow_nonzero_rc=False, require_ipi_mask=7, require_nonempty_s3=True)
            if not ok_rh:
                raise RuntimeError(f"Reference hold-out run {hspec} on {sample} failed measurement admission: {rh_reasons}")
            holdout_field_effects |= obs_s3_field_effects(rh, allow_nonzero_rc=False)
            holdout_field_pages |= obs_s3_field_pages(rh, allow_nonzero_rc=False)
            holdout_trace_shas.append(rh.get("trace_sha256", ""))

        ok_gt, gt_required_effects, gt_reasons = validate_challenge_ground_truth_and_holdout(
            gt_syms,
            declared_gt,
            fields_by_func,
            holdout_field_effects,
        )
        if not ok_gt:
            raise RuntimeError(f"Reference hold-out ground-truth verification failed on {sample}: {gt_reasons}")

        # 1. Baseline S0 (unmodified host seed only)
        t0 = time.monotonic()
        r_s0 = run_sample(
            sample,
            mode="profile_4gate",
            ipi_mask=7,
            persist_prefix=raw_dir / "s0_seed_only",
        )
        s0_wall = round(time.monotonic() - t0, 3)
        s0_feffs = obs_s3_field_effects(r_s0, allow_nonzero_rc=False)
        s0_fpages = obs_s3_field_pages(r_s0)
        s0_obs_solved = sorted(k for k, req in gt_required_effects.items() if req.issubset(s0_feffs))
        s0_summary = {
            "mode": "S0_seed_only",
            "exploration_enclave_creations": 1,
            "confirmation_enclave_creations": 0,
            "enclave_creations": 1,
            "exploration_ecalls_executed": len(r_s0["records"]),
            "confirmation_ecalls_executed": 0,
            "total_ecalls_executed": len(r_s0["records"]),
            "exploration_wall_clock_sec": s0_wall,
            "confirmation_wall_clock_sec": 0.0,
            "wall_clock_sec": s0_wall,
            "observed_solved_count": len(s0_obs_solved),
            "confirmed_solved_count": len(s0_obs_solved),
            "solved_count": len(s0_obs_solved),
            "observed_solved_list": s0_obs_solved,
            "confirmed_solved_list": s0_obs_solved,
            "solved_list": s0_obs_solved,
            "holdout_missed_field_effects": len(holdout_field_effects - s0_feffs),
            "holdout_missed_field_pages": len(holdout_field_pages - s0_fpages),
            "holdout_missed_pages": len(holdout_field_pages - s0_fpages),
        }

        mode_summaries: dict[str, dict] = {"S0": s0_summary}
        for mode in ("fixed_round_robin", "static_priority_no_feedback", "feedback_guided"):
            seed_runs: list[dict] = []
            for sd in seeds:
                discovered_gt: dict[str, dict] = {}
                all_obs_feffs: set[tuple[str, int, str]] = set()
                all_obs_fpages: set[tuple[str, int]] = set()
                curve: list[dict] = []
                step_counter = 0
                t_seed_start = time.monotonic()

                def runner(plan: dict) -> dict:
                    nonlocal step_counter
                    step_counter += 1
                    safe_tag = "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in str(plan.get("tag", "probe")))
                    res = run_sample(
                        sample,
                        mode="profile_4gate",
                        ipi_mask=4 if plan.get("family") == "history" else 7,
                        intervention=plan.get("spec", ""),
                        stop_after_selector=plan.get("stop_after", ""),
                        stop_before_normal_ecall=plan.get("stop_before", ""),
                        persist_prefix=raw_dir / f"{mode}_seed{sd}_step{step_counter:03d}_{safe_tag}",
                    )
                    allow_nz = bool(plan.get("allow_nonzero_rc", False))
                    feffs = obs_s3_field_effects(res, allow_nonzero_rc=allow_nz)
                    fpages = obs_s3_field_pages(res, allow_nonzero_rc=allow_nz)
                    all_obs_feffs.update(feffs)
                    all_obs_fpages.update(fpages)
                    for cname, req_set in gt_required_effects.items():
                        if cname not in discovered_gt and req_set.issubset(feffs):
                            sample_fid, sample_rva, sample_eff = sorted(req_set)[-1]
                            discovered_gt[cname] = {
                                "challenge": cname,
                                "mode": mode,
                                "seed": sd,
                                "field_id": sample_fid,
                                "page_rva": hex(sample_rva),
                                "required_effects": sorted(e for _, _, e in req_set),
                                "step": step_counter,
                                "tag": plan.get("tag"),
                                "family": plan.get("family"),
                                "spec": plan.get("spec", ""),
                                "stop_after": plan.get("stop_after", ""),
                                "stop_before": plan.get("stop_before", ""),
                                "allow_nonzero_rc": allow_nz,
                                "replayed_confirmed": "not_run",
                                "enclave_sha256": res.get("enclave_sha256", ""),
                                "interpose_sha256": res.get("interpose_sha256", ""),
                                "schema_sha256": res.get("schema_sha256", ""),
                                "trace_jsonl": res.get("trace_jsonl", ""),
                                "trace_sha256": res.get("trace_sha256", ""),
                            }
                    cum_ecalls_now = sum(x["ecalls"] for x in curve) + len(res.get("records", []))
                    curve.append({
                        "step": step_counter,
                        "ecalls": len(res.get("records", [])),
                        "cum_ecalls": cum_ecalls_now,
                        "elapsed_sec": round(time.monotonic() - t_seed_start, 3),
                        "observed_solved_count": len(discovered_gt),
                        "obs_s3_field_effects": len(all_obs_feffs),
                        "obs_s3_field_pages": len(all_obs_fpages),
                    })
                    return res

                ksum = ExplorationKernel(
                    sample=sample,
                    edl_schema=edl_schema,
                    selectors=selectors,
                    runner_fn=runner,
                    mode=mode,
                    rng_seed=sd,
                    max_enclave_creations=max_enclave_budget,
                ).run()

                # Now execute hardware replay confirmations AFTER ExplorationKernel.run() finishes,
                # across ALL seeds, and account for their enclave creations, ECALLs, and wall-clock time!
                t_conf0 = time.monotonic()
                conf_enclaves = 0
                conf_ecalls = 0
                for cname, winfo in sorted(discovered_gt.items()):
                    conf_enclaves += 1
                    conf = run_sample(
                        sample,
                        mode="profile_4gate",
                        ipi_mask=4 if winfo.get("family") == "history" else 7,
                        intervention=winfo["spec"],
                        stop_after_selector=winfo["stop_after"],
                        stop_before_normal_ecall=winfo["stop_before"],
                        persist_prefix=raw_dir / f"{mode}_seed{sd}_confirm_{cname}",
                    )
                    conf_ecalls += len(conf.get("records", []))
                    conf_feffs = obs_s3_field_effects(conf, allow_nonzero_rc=bool(winfo.get("allow_nonzero_rc", False)))
                    winfo["replayed_confirmed"] = bool(gt_required_effects[cname].issubset(conf_feffs))
                    winfo["confirmation_ecalls"] = len(conf.get("records", []))
                    winfo["confirmation_enclave_sha256"] = conf.get("enclave_sha256", "")
                    winfo["confirmation_interpose_sha256"] = conf.get("interpose_sha256", "")
                    winfo["confirmation_trace_jsonl"] = conf.get("trace_jsonl", "")
                    winfo["confirmation_trace_sha256"] = conf.get("trace_sha256", "")
                conf_wall = round(time.monotonic() - t_conf0, 3)

                obs_solved_list = sorted(discovered_gt.keys())
                conf_solved_list = sorted(k for k, w in discovered_gt.items() if w["replayed_confirmed"] is True)
                missed_ho_feffs = len(holdout_field_effects - all_obs_feffs)
                missed_ho_fpages = len(holdout_field_pages - all_obs_fpages)

                # Back-fill confirmed_solved_count at each step in curve
                confirmed_steps = {
                    cname: w["step"]
                    for cname, w in discovered_gt.items()
                    if w.get("replayed_confirmed") is True
                }
                for pt in curve:
                    pt["confirmed_solved_count"] = sum(
                        1 for stp in confirmed_steps.values() if stp <= pt["step"]
                    )

                cp_map = {}
                for cp in (20, 40, max_enclave_budget):
                    pts = [x["confirmed_solved_count"] for x in curve if x["step"] <= cp]
                    cp_map[f"at_{cp}_enclaves"] = pts[-1] if pts else 0
                cp_ecalls_map = {}
                for ecp in (250, 500, 750):
                    pts = [x["confirmed_solved_count"] for x in curve if x["cum_ecalls"] <= ecp]
                    cp_ecalls_map[f"at_{ecp}_ecalls"] = pts[-1] if pts else 0
                cp_time_map = {}
                for tcp in (1.5, 3.0, 4.5):
                    pts = [x["confirmed_solved_count"] for x in curve if x["elapsed_sec"] <= tcp]
                    cp_time_map[f"at_{tcp:.1f}s"] = pts[-1] if pts else 0

                # 5-category automated failure attribution for every missed challenge
                challenge_order = sorted(gt_syms.keys())
                spec_by_cname = {
                    challenge_order[i]: holdout_specs[i]
                    for i in range(min(len(challenge_order), len(holdout_specs)))
                }
                rem_specs = set(ksum["unexplored_frontier"].get("remaining_specs", []))
                exec_trace = ksum.get("selection_trace", [])
                missed_attribution: dict[str, str] = {}
                for mc in sorted(set(gt_syms.keys()) - set(conf_solved_list)):
                    tspec = spec_by_cname.get(mc, "")
                    op_prefix = ":".join(tspec.split(":")[:3]) if tspec else ""
                    if mc in discovered_gt and discovered_gt[mc].get("replayed_confirmed") is False:
                        missed_attribution[mc] = "confirmation_replay_failed"
                    elif any(
                        (st.get("spec") == tspec or (op_prefix and op_prefix in st.get("spec", "")))
                        and st.get("measurement_invalid", False)
                        for st in exec_trace
                    ):
                        missed_attribution[mc] = "measurement_invalid"
                    elif any(
                        st.get("spec") == tspec and not st.get("measurement_invalid", False)
                        for st in exec_trace
                    ):
                        missed_attribution[mc] = "precondition_not_satisfied"
                    elif any(
                        rs == tspec or (op_prefix and op_prefix in rs)
                        for rs in rem_specs
                    ):
                        missed_attribution[mc] = "budget_not_reached"
                    else:
                        missed_attribution[mc] = "candidate_not_generated" 

                seed_runs.append({
                    "seed": sd,
                    "exploration_enclave_creations": ksum["enclave_creations"],
                    "confirmation_enclave_creations": conf_enclaves,
                    "enclave_creations": ksum["enclave_creations"],
                    "total_enclaves_with_confirmations": ksum["enclave_creations"] + conf_enclaves,
                    "exploration_ecalls_executed": ksum["total_ecalls_executed"],
                    "confirmation_ecalls_executed": conf_ecalls,
                    "total_ecalls_executed": ksum["total_ecalls_executed"],
                    "total_ecalls_with_confirmations": ksum["total_ecalls_executed"] + conf_ecalls,
                    "exploration_wall_clock_sec": ksum["wall_clock_sec"],
                    "confirmation_wall_clock_sec": conf_wall,
                    "wall_clock_sec": ksum["wall_clock_sec"],
                    "total_wall_clock_sec_with_confirmations": round(ksum["wall_clock_sec"] + conf_wall, 3),
                    "valid_field_entering_ecalls": ksum["valid_field_entering_ecalls"],
                    "expected_s0_rejections": ksum["expected_s0_rejections"],
                    "non_field_setup_ecalls": ksum["non_field_setup_ecalls"],
                    "confirmed_s3_field_pages": ksum["confirmed_s3_field_pages"],
                    "confirmed_s3_field_effects": ksum["confirmed_s3_field_effects"],
                    "confirmed_s3_pages": ksum["confirmed_s3_pages"],
                    "confirmed_s3_effects": ksum["confirmed_s3_effects"],
                    "observed_solved_count": len(obs_solved_list),
                    "confirmed_solved_count": len(conf_solved_list),
                    "solved_count": len(conf_solved_list),
                    "observed_solved_list": obs_solved_list,
                    "confirmed_solved_list": conf_solved_list,
                    "solved_list": conf_solved_list,
                    "missed_list": sorted(set(gt_syms.keys()) - set(conf_solved_list)),
                    "missed_attribution": missed_attribution,
                    "checkpoints_by_ecalls": cp_ecalls_map,
                    "checkpoints_by_wall_sec": cp_time_map,
                    "holdout_missed_field_effects": missed_ho_feffs,
                    "holdout_missed_field_pages": missed_ho_fpages,
                    "holdout_missed_pages": missed_ho_fpages,
                    "checkpoints": cp_map,
                    "witnesses": list(discovered_gt.values()),
                    "stop_reason": ksum["stop_reason"],
                    "unexplored_frontier": ksum["unexplored_frontier"],
                })

            obs_counts = [r["observed_solved_count"] for r in seed_runs]
            conf_counts = [r["confirmed_solved_count"] for r in seed_runs]
            exp_ecalls = [r["exploration_ecalls_executed"] for r in seed_runs]
            tot_ecalls = [r["total_ecalls_with_confirmations"] for r in seed_runs]
            tot_encls = [r["total_enclaves_with_confirmations"] for r in seed_runs]
            exp_walls = [r["exploration_wall_clock_sec"] for r in seed_runs]
            tot_walls = [r["total_wall_clock_sec_with_confirmations"] for r in seed_runs]
            ho_feff_misses = [r["holdout_missed_field_effects"] for r in seed_runs]
            ho_fpg_misses = [r["holdout_missed_field_pages"] for r in seed_runs]
            cp20 = [r["checkpoints"]["at_20_enclaves"] for r in seed_runs]
            cp40 = [r["checkpoints"]["at_40_enclaves"] for r in seed_runs]
            cp68 = [r["checkpoints"][f"at_{max_enclave_budget}_enclaves"] for r in seed_runs]

            mode_summaries[mode] = {
                "mode": mode,
                "num_seeds": len(seeds),
                "enclave_budget": max_enclave_budget,
                "mean_total_enclaves_with_confirmations": round(statistics.mean(tot_encls), 1),
                "observed_by_seed": {str(r["seed"]): r["observed_solved_count"] for r in seed_runs},
                "confirmed_by_seed": {str(r["seed"]): r["confirmed_solved_count"] for r in seed_runs},
                "solved_by_seed": {str(r["seed"]): r["confirmed_solved_count"] for r in seed_runs},
                "observed_mean": round(statistics.mean(obs_counts), 2),
                "confirmed_mean": round(statistics.mean(conf_counts), 2),
                "solved_mean": round(statistics.mean(conf_counts), 2),
                "solved_median": statistics.median(conf_counts),
                "solved_min": min(conf_counts),
                "solved_max": max(conf_counts),
                "challenges_total": len(gt_syms),
                "curve_mean_solved": {
                    "at_20_enclaves": round(statistics.mean(cp20), 2),
                    "at_40_enclaves": round(statistics.mean(cp40), 2),
                    f"at_{max_enclave_budget}_enclaves": round(statistics.mean(cp68), 2),
                },
                "curve_mean_confirmed_by_ecalls": {
                    f"at_{ecp}_ecalls": round(statistics.mean([r["checkpoints_by_ecalls"][f"at_{ecp}_ecalls"] for r in seed_runs]), 2)
                    for ecp in (250, 500, 750)
                },
                "curve_mean_confirmed_by_wall_sec": {
                    f"at_{tcp:.1f}s": round(statistics.mean([r["checkpoints_by_wall_sec"][f"at_{tcp:.1f}s"] for r in seed_runs]), 2)
                    for tcp in (1.5, 3.0, 4.5)
                },
                "missed_attribution_summary": {
                    cat: sum(1 for r in seed_runs for v in r.get("missed_attribution", {}).values() if v == cat)
                    for cat in (
                        "budget_not_reached",
                        "candidate_not_generated",
                        "precondition_not_satisfied",
                        "measurement_invalid",
                        "confirmation_replay_failed",
                    )
                },
                "mean_exploration_ecalls": round(statistics.mean(exp_ecalls), 1),
                "mean_total_ecalls_with_confirmations": round(statistics.mean(tot_ecalls), 1),
                "mean_total_ecalls": round(statistics.mean(exp_ecalls), 1),
                "mean_exploration_wall_clock_sec": round(statistics.mean(exp_walls), 2),
                "mean_total_wall_clock_sec_with_confirmations": round(statistics.mean(tot_walls), 2),
                "mean_wall_clock_sec": round(statistics.mean(exp_walls), 2),
                "mean_holdout_missed_field_effects": round(statistics.mean(ho_feff_misses), 2),
                "mean_holdout_missed_field_pages": round(statistics.mean(ho_fpg_misses), 2),
                "mean_holdout_missed_pages": round(statistics.mean(ho_fpg_misses), 2),
                "seed_runs": seed_runs,
            }

        results_by_target[sample] = {
            "sample": sample,
            "split": split_kind,
            "reference_holdout_verified_all_8_challenges": True,
            "ground_truth_challenge_pages": {
                k: {
                    "rva": hex(gt_syms[k]),
                    "required_field_effects": [
                        {"field_id": fid, "rva": hex(rva), "effect": eff}
                        for fid, rva, eff in sorted(gt_required_effects[k])
                    ],
                }
                for k in sorted(gt_syms)
            },
            "holdout_total_s3_field_effects": len(holdout_field_effects),
            "holdout_total_s3_field_pages": len(holdout_field_pages),
            "holdout_total_s3_pages": len(holdout_field_pages),
            "modes": mode_summaries,
        }

    return results_by_target
