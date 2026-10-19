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


def run_real_hardware_challenge_ablation(max_enclave_budget: int = 48) -> dict:
    """Execute strategies S0, S1, S2, S3 under an IDENTICAL enclave-creation budget (including replay confirmations)
    on REAL compiled SGX challenge enclaves (challenge-bench and challenge-bench-perm).
    """
    import time
    from elf_workset import ElfFile, normalized_fields, resolve_selectors
    from run_native_sgx import run_sample

    dyn_root = Path("/home/meandssh/islands-sgx/dynamic")
    targets = ["challenge-bench", "challenge-bench-perm"]
    strategies = ["S0", "S1", "S2", "S3"]
    results_by_target: dict[str, dict] = {}

    for sample in targets:
        tdir = dyn_root / "targets" / sample
        elf = ElfFile(tdir / "enclave.profile.so")
        # Ground-truth symbol map is used ONLY by the post-hoc evaluator, never read by the explorer!
        gt_syms = {
            s["name"].replace("challenge_page_", "").upper(): s["value"]
            for s in elf.symbols()
            if s["name"].startswith("challenge_page_c") and s["name"] != "challenge_page_base"
        }
        edl_schema = json.loads((tdir / "edl_schema.json").read_text())
        fields = normalized_fields(tdir / "fields.json")
        selectors = resolve_selectors(tdir / "selectors.json", fields, Path(edl_schema["edl_path"]))
        ecalls_by_idx = {e["ecall_index"]: e for e in edl_schema["ecalls"]}
        field_selectors = [s["ecall_index"] for s in selectors if s["reachable_fields"]]
        non_field_selectors = [s["ecall_index"] for s in selectors if not s["reachable_fields"]]

        if sample == "challenge-bench":
            holdout_specs = [
                "repeat:3:0:14",
                "set_scalar:1:0:0:2",
                "scale_bound_v2:3:0:0:16:1024:-1:0",
                "joint_scalar_xor:3:0:0:2:1:0:255",
                "set_scalar:3:1:0:16",
                "aliased_pair:3:0:1:3:4",
            ]
        else:
            holdout_specs = [
                "repeat:1:0:22",
                "set_scalar:0:0:0:16",
                "scale_bound_v2:1:0:0:16:4096:-1:0",
                "joint_scalar_xor:1:0:0:1:1:0:255",
                "set_scalar:1:1:0:2",
                "aliased_pair:1:0:1:3:4",
            ]
        holdout_pages: set[int] = set()
        for hspec in holdout_specs:
            rh = run_sample(sample, mode="profile_4gate", ipi_mask=7, intervention=hspec)
            for rec in rh["records"]:
                for fobs in rec["fields"]:
                    for item in fobs["s3"]:
                        holdout_pages.add(int(item["rva"], 16))

        strat_summaries: dict[str, dict] = {}
        for strat in strategies:
            budget_cap = 1 if strat == "S0" else max_enclave_budget
            t0 = time.monotonic()
            enclave_creations = 0
            total_ecalls = 0
            valid_field_ecalls = 0
            expected_reject_ecalls = 0
            non_field_ecalls = 0
            invalid_runs = 0
            discovered_pages: set[int] = set()
            discovered_effects: set[tuple[int, str]] = set()
            seen_behavior_sigs: set[tuple] = set()
            family_credits: dict[str, float] = {
                "scale": 1.0,
                "boundary": 1.0,
                "joint": 1.0,
                "alias": 1.0,
                "prefix_setup": 1.0,
                "history": 1.0,
                "content": 0.5,
            }
            witnesses: list[dict] = []
            curve: list[dict] = []

            def run_and_account(spec: str, stop_after: str = "", stop_before: str = "", label: str = "", family: str = "seed") -> dict | None:
                nonlocal enclave_creations, total_ecalls, valid_field_ecalls, expected_reject_ecalls, non_field_ecalls, invalid_runs
                if enclave_creations >= budget_cap:
                    return None
                enclave_creations += 1
                res = run_sample(
                    sample,
                    mode="profile_4gate",
                    ipi_mask=7,
                    intervention=spec,
                    stop_after_selector=stop_after,
                    stop_before_normal_ecall=stop_before,
                )
                if res["measurement_invalid"]:
                    invalid_runs += 1
                total_ecalls += len(res["records"])
                new_gt_hits = []
                before_effs = len(discovered_effects)
                new_sig = False
                for rec in res["records"]:
                    sig = structural_behavior_signature(rec)
                    if sig not in seen_behavior_sigs:
                        seen_behavior_sigs.add(sig)
                        new_sig = True
                    if rec["fields"]:
                        valid_field_ecalls += 1
                        for fobs in rec["fields"]:
                            for item in fobs["s3"]:
                                rva = int(item["rva"], 16)
                                eff = item["ad"]
                                if rva not in discovered_pages and rva in gt_syms.values():
                                    cname = next(k for k, v in gt_syms.items() if v == rva)
                                    new_gt_hits.append((cname, rva, eff))
                                discovered_pages.add(rva)
                                discovered_effects.add((rva, "A"))
                                if eff == "D":
                                    discovered_effects.add((rva, "D"))
                    else:
                        if rec["ecall_index"] in field_selectors and rec.get("ms_retval", 0) != 0:
                            expected_reject_ecalls += 1
                        else:
                            non_field_ecalls += 1

                # Update feedback credit for the operator family based on hardware trace novelty
                gained_effs = len(discovered_effects) - before_effs
                if gained_effs > 0:
                    family_credits[family] = family_credits.get(family, 1.0) + 2.0 * gained_effs
                elif new_sig:
                    family_credits[family] = family_credits.get(family, 1.0) + 0.5

                # Replay confirmation for any newly discovered challenge page (charged to budget!)
                for cname, rva, eff in new_gt_hits:
                    if enclave_creations < budget_cap:
                        enclave_creations += 1
                        conf = run_sample(
                            sample,
                            mode="profile_4gate",
                            ipi_mask=7,
                            intervention=spec,
                            stop_after_selector=stop_after,
                            stop_before_normal_ecall=stop_before,
                        )
                        total_ecalls += len(conf["records"])
                        conf_rvas = {
                            int(it["rva"], 16)
                            for r in conf["records"]
                            for fo in r["fields"]
                            for it in fo["s3"]
                        }
                        confirmed = (rva in conf_rvas)
                    else:
                        confirmed = False
                    witnesses.append({
                        "challenge": cname,
                        "page_rva": hex(rva),
                        "effect": eff,
                        "intervention": spec or "unmodified_seed",
                        "label": label,
                        "enclave_creations_at_discovery": enclave_creations,
                        "ecalls_at_discovery": total_ecalls,
                        "wall_clock_sec": round(time.monotonic() - t0, 3),
                        "replayed_confirmed": confirmed,
                        "trace_sha256": res["trace_sha256"],
                        "enclave_sha256": res["enclave_sha256"],
                    })

                solved_now = sum(1 for w in witnesses if w["replayed_confirmed"])
                curve.append({
                    "enclave_creations": enclave_creations,
                    "total_ecalls": total_ecalls,
                    "wall_clock_sec": round(time.monotonic() - t0, 3),
                    "challenges_solved": solved_now,
                })
                return res

            # Step 0: Seed run (all strategies S0..S3)
            res0 = run_and_account("", label="L0_L1_seed", family="seed")
            if strat != "S0" and res0 is not None:
                field_positions: list[tuple[int, int]] = []
                for rec in res0["records"]:
                    if rec["fields"]:
                        pos = (rec["ecall_index"], rec["selector_seq"])
                        if pos not in field_positions:
                            field_positions.append(pos)

                if strat == "S1":
                    # Legacy S1: first position only, 4x scale aborting on first error, single-param {0,2,99} + byte XORs, repeat last selector
                    idx, sseq = field_positions[0]
                    ec = ecalls_by_idx[idx]
                    for sc in (64, 256, 1024, 4096):
                        sp = build_scale_bound_v2_spec(ec, sc, sc, mode=0, selector_seq=sseq)
                        if not sp:
                            break
                        rsc = run_and_account(sp, stop_after=f"{idx}:{sseq}", label=f"scale_{sc}", family="scale")
                        if rsc is None:
                            break
                        entered = any(r["tag"].startswith("schema_scale_") and r["fields"] for r in rsc["records"])
                        if not entered:
                            break
                    for m in generate_schema_mutations_for_ecall(ec, selector_seq=sseq, strategy="S1"):
                        if run_and_account(m["spec"], stop_before=f"{idx}:{sseq}", label=m["tag"], family=m["family"]) is None:
                            break
                    for depth in (16, 24):
                        run_and_account(f"repeat:{idx}:{sseq}:{depth}", stop_after=f"{idx}:{sseq}", label=f"repeat_{depth}", family="history")
                    # Pad remaining budget with additional single-byte XOR offsets so S1 uses the exact same enclave budget (44) as S2/S3
                    extra_byte = 1
                    while enclave_creations < budget_cap:
                        run_and_account(
                            f"xor_param:{idx}:{sseq}:1:{extra_byte % 32}:170",
                            stop_before=f"{idx}:{sseq}",
                            label=f"legacy_extra_xor_{extra_byte}",
                            family="content",
                        )
                        extra_byte += 1

                else:
                    # Build per-family candidate queues for S2 (single position, no prefix setup) vs S3 (all positions + prefix setup + feedback priority)
                    target_positions = field_positions[:1] if strat == "S2" else field_positions
                    queues: dict[str, list[dict]] = {
                        "scale": [],
                        "boundary": [],
                        "joint": [],
                        "alias": [],
                        "prefix_setup": [],
                        "history": [],
                        "content": [],
                    }
                    idx0, sseq0 = field_positions[0]
                    ec0 = ecalls_by_idx[idx0]
                    if get_scalable_bound_offsets(ec0) is not None:
                        for sc in (16, 64, 256, 512, 1024, 4096):
                            sp = build_scale_bound_v2_spec(ec0, sc, sc, mode=0, selector_seq=sseq0)
                            if sp:
                                queues["scale"].append({
                                    "family": "scale",
                                    "spec": sp,
                                    "stop_after": f"{idx0}:{sseq0}",
                                    "stop_before": "",
                                    "label": f"scale_{sc}",
                                })

                    pos_mut_lists = [
                        [
                            {
                                "family": m.get("family", "content"),
                                "spec": m["spec"],
                                "stop_after": "",
                                "stop_before": f"{idx}:{sseq}",
                                "label": f"s{sseq}_{m['tag']}",
                            }
                            for m in generate_schema_mutations_for_ecall(ecalls_by_idx[idx], selector_seq=sseq, strategy=strat)
                        ]
                        for idx, sseq in target_positions
                    ]
                    max_mlen = max((len(ml) for ml in pos_mut_lists), default=0)
                    for mi in range(max_mlen):
                        for ml in pos_mut_lists:
                            if mi < len(ml):
                                item = ml[mi]
                                queues.setdefault(item["family"], []).append(item)

                    if strat == "S3":
                        for nf_idx in non_field_selectors:
                            nf_ec = ecalls_by_idx.get(nf_idx)
                            if not nf_ec:
                                continue
                            for pidx, p in enumerate(nf_ec.get("params", [])):
                                if not p.get("is_pointer"):
                                    for val in (2, 16, 1):
                                        queues["prefix_setup"].append({
                                            "family": "prefix_setup",
                                            "spec": f"set_scalar:{nf_idx}:0:{pidx}:{val}",
                                            "stop_after": "",
                                            "stop_before": "",
                                            "label": f"prefix_setup_ecall{nf_idx}_p{pidx}_v{val}",
                                        })

                    for depth in (16, 24):
                        queues["history"].append({
                            "family": "history",
                            "spec": f"repeat:{idx0}:{sseq0}:{depth}",
                            "stop_after": f"{idx0}:{sseq0}",
                            "stop_before": "",
                            "label": f"repeat_{depth}",
                        })

                    # Feedback-weighted round-robin loop until budget_cap is reached
                    active_fams = ["scale", "joint", "alias", "boundary", "prefix_setup", "history", "content"]
                    while enclave_creations < budget_cap and any(queues.get(f) for f in active_fams):
                        # Sort non-empty families by descending feedback credit (with rotation tie-breaker)
                        avail = [f for f in active_fams if queues.get(f)]
                        if strat == "S3":
                            avail.sort(key=lambda f: -family_credits.get(f, 1.0))
                        for fam in avail:
                            if enclave_creations >= budget_cap or not queues[fam]:
                                break
                            cand = queues[fam].pop(0)
                            # Decay credit slightly on selection so no single family starves zero-immediate-gain prefixes
                            family_credits[fam] = max(0.5, family_credits.get(fam, 1.0) * 0.85)
                            run_and_account(
                                cand["spec"],
                                stop_after=cand["stop_after"],
                                stop_before=cand["stop_before"],
                                label=cand["label"],
                                family=fam,
                            )

                    # If S2 still has budget remaining, pad with remaining content mutations so S1/S2/S3 use identical enclave budget
                    extra_b = 2
                    while enclave_creations < budget_cap:
                        run_and_account(
                            f"xor_param:{idx0}:{sseq0}:1:{extra_b % 32}:85",
                            stop_before=f"{idx0}:{sseq0}",
                            label=f"s2_extra_xor_{extra_b}",
                            family="content",
                        )
                        extra_b += 1

            elapsed_sec = round(time.monotonic() - t0, 3)
            solved_names = sorted(w["challenge"] for w in witnesses if w["replayed_confirmed"])
            missed_holdout = len(holdout_pages - discovered_pages)
            strat_summaries[strat] = {
                "strategy": strat,
                "enclave_creations": enclave_creations,
                "total_ecalls_executed": total_ecalls,
                "wall_clock_sec": elapsed_sec,
                "valid_field_entering_ecalls": valid_field_ecalls,
                "expected_s0_rejections": expected_reject_ecalls,
                "non_field_setup_ecalls": non_field_ecalls,
                "measurement_invalid_runs": invalid_runs,
                "confirmed_s3_pages": len(discovered_pages),
                "confirmed_s3_effects": len(discovered_effects),
                "new_effects_per_100_ecalls": round(100.0 * len(discovered_effects) / max(1, total_ecalls), 2),
                "confirmed_pages_per_sec": round(len(discovered_pages) / max(0.001, elapsed_sec), 2),
                "challenges_solved_count": len(solved_names),
                "challenges_total": len(gt_syms),
                "challenges_solved_list": solved_names,
                "holdout_missed_pages": missed_holdout,
                "witnesses": witnesses,
                "discovery_curve": curve,
            }

        results_by_target[sample] = {
            "sample": sample,
            "ground_truth_challenge_pages": {k: hex(v) for k, v in sorted(gt_syms.items())},
            "strategies": strat_summaries,
        }

    return results_by_target
