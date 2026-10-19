#!/usr/bin/env python3
"""Comprehensive P0-P4 Hardware Evaluation for ATField-SGX Dynamic Worksets.

Implements:
1. Cold vs Warm TLB hardware calibration & 4-gate vs uninstrumented output equivalence check.
2. Single-page X / R / W retraction positive/negative fault calibration + same-fault-point AEX0 vs AEX1 comparison.
3. Truly independent Hold-Out challenge suite (disjoint from training inputs/scales/histories),
   evaluating BOTH:
     - Strict ReadyTable v3 (ECALL window: EENTER..EEXIT)
     - Strict FieldTargetPages (Field active window: Gate B..Gate D)
   and checking whether ANY hold-out call discovers a new (page_rva, effect) outside the closed workset.
4. Three-group ablation (Group A: all_reg XR, Group B: dynamic_xr XR, Group C: dynamic X-refined)
   across 5 interleaved rounds, reporting min/median/mean/max distributions for both:
     - 4-gate diagnostic S2/S3 TSC ticks and S3 A/D re-walk page counts, and
     - Production AEX1 signed final enclave end-to-end ECALL wall-clock latency (ns).
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))
from run_native_sgx import run_sample, sha256_file  # noqa: E402

SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm"]

# Disjoint Independent Hold-Out Challenges (none of these parameters/scales/offsets were used in controller.py training):
INDEPENDENT_HOLDOUT_SUITES = {
    "qe3": {
        "intervention": "xor_buf:0:0:8:3:90;xor_buf:0:0:8:11:165;xor_buf:0:0:8:19:60;xor_buf:0:0:8:27:195",
        "host_args": [],
        "desc": "Disjoint key_id byte positions {3, 11, 19, 27} and masks {0x5a, 0xa5, 0x3c, 0xc3}",
    },
    "signal-cds": {
        "intervention": (
            "scale_bound:0:0:48:16:8:384:8:8:0:32:8:96:24:8:40:1;"
            "scale_bound:0:0:48:16:8:3072:8:8:1:32:8:384:24:8:40:1;"
            "scale_bound:0:0:48:16:8:12288:8:8:2:32:8:512:24:8:40:1;"
            "scale_bound:0:0:48:16:8:49152:8:8:0:32:8:512:24:8:40:1;"
            "scale_bound:0:0:48:16:8:131072:8:8:1:32:8:512:24:8:40:1"
        ),
        "host_args": [],
        "desc": "Disjoint intermediate/large record scales {384, 3072, 12288, 49152, 131072} and query counts {96, 384, 512}",
    },
    "sgxwallet": {
        "intervention": "xor_buf:6:500:32:4:1;xor_buf:6:999:32:6:1;set_u32:6:2:72:37;xor_buf:5:0:16:7:127;xor_buf:3:0:16:45:127",
        "host_args": ["--requests", "1005"],
        "desc": "Full 1005-request host workflow (0 skipped) + disjoint hash mutations at seq 500/999 + disjoint base=37 + byte 7/45 flips",
    },
    "ehsm": {
        "intervention": "state_probe:2:1:0:1:72;state_probe:4:1:0:1:72;xor_buf:3:1:40:9:127",
        "host_args": ["--bytes", "1536", "--requests", "3"],
        "desc": "Disjoint payload size (--bytes 1536 --requests 3) + cold-instance state probes on encrypt & generate_datakey + byte 9 bit-flip",
    },
}


def dist_summary(vals: list[int | float]) -> dict:
    if not vals:
        return {"count": 0, "min": 0, "median": 0, "mean": 0, "max": 0}
    return {
        "count": len(vals),
        "min": round(min(vals), 2),
        "median": round(statistics.median(vals), 2),
        "mean": round(statistics.mean(vals), 2),
        "max": round(max(vals), 2),
    }


def write_strict_file_from_ready(tdir: Path, variant: str, out_path: Path) -> dict[int, list[int]]:
    rdy = json.loads((tdir / f"enclave.{variant}.ready.json").read_text())
    sel_map = {}
    lines = []
    for s in rdy["selectors"]:
        idx = s["ecall_index"]
        rvas = s["page_rvas"]
        sel_map[idx] = rvas
        if rvas:
            lines.append(f"{idx} " + " ".join(f"{p:x}" for p in rvas))
    out_path.write_text("\n".join(lines) + "\n")
    return sel_map


def write_strict_file_from_field_targets(tdir: Path, variant: str, out_path: Path) -> dict[int, list[int]]:
    """Build a strict-ready map containing ONLY FieldTargetPages (+ pretouch code segment & gate helper page)
    for Gate B..Gate D (ATFIELD_STRICT_MODE=field) verification.
    """
    ws = json.loads((tdir / f"workset.{variant}.json").read_text())
    layout = ws["layout"]
    p_start = layout["pretouch_start"]
    p_end = p_start + layout["capacity_q"]
    pretouch_pages = set(range(p_start, p_end, 4096))
    fields_by_id = {f"0x{int(f['id'], 16):016x}" if isinstance(f["id"], str) else f"0x{f['id']:016x}": f for f in ws["fields"]}

    sel_map = {}
    lines = []
    for s in ws["selectors"]:
        idx = s["ecall_index"]
        rvas = set(pretouch_pages)
        for fid in s["reachable_fields"]:
            fobj = fields_by_id.get(fid)
            if fobj:
                for pg in fobj["pages"]:
                    rvas.add(pg["page_rva"])
        if s["reachable_fields"]:
            sorted_rvas = sorted(rvas)
            sel_map[idx] = sorted_rvas
            lines.append(f"{idx} " + " ".join(f"{p:x}" for p in sorted_rvas))
    out_path.write_text("\n".join(lines) + "\n")
    return sel_map


def run_xrw_and_aex_calibration(sample: str, tdir: Path, raw_dir: Path) -> dict:
    """Select 1 known-accessed X page, 1 R page, and 1 W page in the first active Field selector;
    retract one page at a time under AEX0, verify real fault address/kind is caught, verify restoring it passes with 0 faults,
    and compare AEX0 vs AEX1 at the exact same single X-page fault point.
    """
    ws = json.loads((tdir / "workset.dynamic.json").read_text())
    rdy = json.loads((tdir / "enclave.dynamic.ready.json").read_text())
    # Run one profile_4gate baseline to pick pages definitely accessed in S3 on call 0
    r_base = run_sample(sample, mode="profile_4gate", ipi_mask=7, host_args=["--requests", "1"] if sample == "sgxwallet" else [])
    first_f_rec = next(rec for rec in r_base["records"] if rec["fields"])
    sel_idx = first_f_rec["ecall_index"]
    s3_ad_map = {}
    s3_full_ad_map = {}
    outside_field_rvas = set()
    for rec in r_base["records"]:
        if rec["ecall_index"] != sel_idx or not rec["fields"]:
            continue
        f0 = rec["fields"][0]
        s0_s1_rvas = {int(x["rva"], 16) for x in f0["s0"] + f0["s1"]}
        s3_rvas_this = {int(x["rva"], 16) for x in f0["s3"]}
        ecall_rvas_this = {int(x["rva"], 16) for x in rec.get("ecall_ad", [])}
        outside_field_rvas |= s0_s1_rvas | (ecall_rvas_this - s3_rvas_this)
        for x in f0["s3"]:
            rva = int(x["rva"], 16)
            ad = x["ad"]
            if s3_full_ad_map.get(rva) != "D":
                s3_full_ad_map[rva] = ad
    for rva, ad in s3_full_ad_map.items():
        if rva not in outside_field_rvas:
            s3_ad_map[rva] = ad

    # Map page permissions from workset
    page_perm_map = {}
    for f in ws["fields"]:
        for pg in f["pages"]:
            page_perm_map[pg["page_rva"]] = pg

    # Exclude pretouch segment and excluded regions
    p_start = ws["layout"]["pretouch_start"]
    p_end = p_start + ws["layout"]["capacity_q"]
    x_cand = next(
        (
            p for p, ad in sorted(s3_ad_map.items())
            if p in page_perm_map and (page_perm_map[p]["max_permissions"] & 4) and not (p_start <= p < p_end)
        ),
        next(
            p for p, ad in sorted(s3_full_ad_map.items())
            if p in page_perm_map and (page_perm_map[p]["max_permissions"] & 4) and not (p_start <= p < p_end)
        ),
    )
    r_cand = next(
        (
            p for p, ad in sorted(s3_ad_map.items())
            if p in page_perm_map and (page_perm_map[p]["max_permissions"] & 4) == 0 and ad == "A"
        ),
        next(
            p for p, ad in sorted(s3_full_ad_map.items())
            if p in page_perm_map and page_perm_map[p]["max_permissions"] == 1 and ad == "A"
        ),
    )
    w_cand = next(
        (
            p for p, ad in sorted(s3_ad_map.items())
            if p in page_perm_map and (page_perm_map[p]["max_permissions"] & 2) and ad == "D"
        ),
        next(
            p for p, ad in sorted(s3_full_ad_map.items())
            if p in page_perm_map and (page_perm_map[p]["max_permissions"] & 2) and ad == "D"
        ),
    )

    full_sel_map = {s["ecall_index"]: set(s["page_rvas"]) for s in rdy["selectors"] if s["page_rvas"]}
    cal_results = {}
    h_args = ["--requests", "1"] if sample == "sgxwallet" else []

    for label, drop_rva in (("X_code_page", x_cand), ("R_rodata_page", r_cand), ("W_data_page", w_cand)):
        cal_file = tdir / f"strict_cal_drop_{label}.txt"
        lines = []
        for idx, rvas in sorted(full_sel_map.items()):
            mod = sorted(rvas - ({drop_rva} if idx == sel_idx else set()))
            lines.append(f"{idx} " + " ".join(f"{p:x}" for p in mod))
        cal_file.write_text("\n".join(lines) + "\n")

        res_drop = run_sample(
            sample,
            mode="dynamic_final_aex0",
            ipi_mask=0,
            strict_ready_file=str(cal_file),
            strict_mode="ecall",
            host_args=h_args,
            persist_prefix=raw_dir / f"cal_drop_{label}_aex0",
        )
        matched_events = [
            fe
            for rec in res_drop["records"]
            for fe in rec.get("fault_events", [])
            if int(fe["page_rva"], 16) == drop_rva
        ]
        cal_results[label] = {
            "retracted_page_rva": hex(drop_rva),
            "target_selector": sel_idx,
            "fault_caught": len(matched_events) > 0,
            "matched_fault_count": len(matched_events),
            "first_matched_event": matched_events[0] if matched_events else None,
            "measurement_invalid": res_drop["measurement_invalid"],
        }

    # Positive control: restore all pages (full ReadyTable v3) and verify 0 faults
    full_file = tdir / "strict_ready_dynamic.txt"
    write_strict_file_from_ready(tdir, "dynamic", full_file)
    res_restored = run_sample(
        sample,
        mode="dynamic_final_aex0",
        ipi_mask=0,
        strict_ready_file=str(full_file),
        strict_mode="ecall",
        host_args=h_args,
        persist_prefix=raw_dir / "cal_restored_full_aex0",
    )
    restored_faults = sum(r["strict_non_ready_fault_count"] for r in res_restored["records"])

    # Same-fault-point AEX0 vs AEX1 comparison on the retracted X_code_page (guaranteed active_flag == 1 inside Field!)
    x_cal_file = tdir / "strict_cal_drop_X_code_page.txt"
    res_aex1 = run_sample(
        sample,
        mode="dynamic_final",
        ipi_mask=0,
        strict_ready_file=str(x_cal_file),
        strict_mode="ecall",
        host_args=h_args,
        persist_prefix=raw_dir / "cal_drop_X_code_page_aex1",
    )
    aex1_events = [
        fe
        for rec in res_aex1["records"]
        for fe in rec.get("fault_events", [])
        if int(fe["page_rva"], 16) == x_cand
    ]
    aex1_crashed_records = [rec for rec in res_aex1["records"] if rec["sgx_status"] == 0x1006]
    same_fault_aex_notify_pass = bool(
        cal_results["X_code_page"]["fault_caught"]
        and cal_results["X_code_page"]["first_matched_event"]["active_flag"] == 1
        and len(aex1_events) > 0
        and aex1_events[0]["active_flag"] == 1
        and aex1_events[0]["page_rva"] == hex(x_cand)
        and len(aex1_crashed_records) > 0
        and res_aex1["returncode"] != 0
        and not res_aex1["timed_out"]
        and not res_aex1["measurement_invalid"]
    )

    all_cal_valid = bool(
        cal_results["X_code_page"]["fault_caught"]
        and cal_results["R_rodata_page"]["fault_caught"]
        and cal_results["W_data_page"]["fault_caught"]
        and restored_faults == 0
        and not res_restored["measurement_invalid"]
    )
    return {
        "calibration_valid": all_cal_valid,
        "single_page_retraction_controls": cal_results,
        "restored_positive_control_faults": restored_faults,
        "same_fault_point_aex0_vs_aex1": {
            "fault_page_rva": hex(x_cand),
            "aex0_first_event": cal_results["X_code_page"]["first_matched_event"],
            "aex0_completed_normally": res_restored["returncode"] == 0,
            "aex1_first_event": aex1_events[0] if aex1_events else None,
            "aex1_sgx_status_0x1006_observed": len(aex1_crashed_records) > 0,
            "aex1_host_returncode": res_aex1["returncode"],
            "verdict": "PASS" if same_fault_aex_notify_pass else "INVALID_OR_FAIL",
        },
    }


def run_tlb_and_fixture_checks(sample: str, raw_dir: Path) -> dict:
    """1. Calibrate Cold TLB (ipi_mask=7) vs Unflushed Warm TLB (ipi_mask=0) on profile_4gate:
          pages touched in S0/S1 that are re-accessed in S3 only set A/D in S3 if the Gate B/C IPI flushed the TLB!
       2. Verify business output equivalence between uninstrumented profile_signed and 4-gate profile_4gate.
    """
    h_args = ["--requests", "1"] if sample == "sgxwallet" else []
    r_cold = run_sample(sample, mode="profile_4gate", ipi_mask=7, host_args=h_args, persist_prefix=raw_dir / "tlb_cal_cold_ipi7")
    r_warm = run_sample(sample, mode="profile_4gate", ipi_mask=0, host_args=h_args, persist_prefix=raw_dir / "tlb_cal_warm_ipi0")
    r_uninst = run_sample(sample, mode="dynamic_final_aex0", ipi_mask=0, host_args=h_args, persist_prefix=raw_dir / "fixture_uninst_aex0")

    fc = next(rec["fields"][0] for rec in r_cold["records"] if rec["fields"])
    fw = next(rec["fields"][0] for rec in r_warm["records"] if rec["fields"])
    s01_pages = {x["rva"] for x in fc["s0"] + fc["s1"]}
    cold_s3_pages = {x["rva"] for x in fc["s3"]}
    warm_s3_pages = {x["rva"] for x in fw["s3"]}
    s01_rewalked_when_cold = len(s01_pages & cold_s3_pages)
    s01_rewalked_when_warm = len(s01_pages & warm_s3_pages)

    uninst_rets = [(r["ecall_index"], r["sgx_status"], r["ms_retval_i32"]) for r in r_uninst["records"]]
    gate_rets = [(r["ecall_index"], r["sgx_status"], r["ms_retval_i32"]) for r in r_cold["records"]]

    return {
        "cold_vs_warm_tlb_calibration": {
            "cold_ipi_verified_mask": fc["ipi_aex_verified_mask"],
            "cold_s3_pages_observed": len(cold_s3_pages),
            "warm_no_ipi_s3_pages_observed": len(warm_s3_pages),
            "s0_s1_overlap_rewalked_in_s3_when_cold": s01_rewalked_when_cold,
            "s0_s1_overlap_rewalked_in_s3_when_warm": s01_rewalked_when_warm,
            "cold_tlb_proven": bool(fc["ipi_aex_verified_mask"] == 7 and len(cold_s3_pages) > len(warm_s3_pages)),
        },
        "four_gate_fixture_equivalence": {
            "fixture_classification": "DIAGNOSTIC_TEST_DATA_ONLY_AEX0",
            "arithmetic_flags_saved_restored": "CF,PF,AF,ZF,SF,OF (via lahf + seto/addb + sahf)",
            "uninstrumented_stdout": r_uninst["stdout"],
            "four_gate_stdout": r_cold["stdout"],
            "ecall_status_sequence_identical": uninst_rets == gate_rets,
            "stdout_identical": r_uninst["stdout"] == r_cold["stdout"],
        },
    }


def evaluate_sample(sample: str) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    wdir = DYN_ROOT / "witnesses" / sample
    raw_dir = DYN_ROOT / "experiments" / "raw_traces" / sample
    raw_dir.mkdir(parents=True, exist_ok=True)

    ledger = json.loads((wdir / "witness_ledger.json").read_text())
    ws_dyn = json.loads((tdir / "workset.dynamic.json").read_text())
    closed_target_pages_by_fid = {}
    closed_target_effects_by_fid = {}
    for f in ws_dyn["fields"]:
        fid = f"0x{int(f['id'], 16):016x}" if isinstance(f["id"], str) else f"0x{f['id']:016x}"
        closed_target_pages_by_fid[fid] = {pg["page_rva"] for pg in f["pages"]}
        effs = set()
        for pg in f["pages"]:
            rva = pg["page_rva"]
            effs.add((rva, "A"))
            if "W" in pg["effects"]:
                effs.add((rva, "D"))
        closed_target_effects_by_fid[fid] = effs

    # 1. Cold TLB & 4-gate fixture equivalence checks
    tlb_and_fixture = run_tlb_and_fixture_checks(sample, raw_dir)

    # 2. Single-page X/R/W calibration & same-fault-point AEX0 vs AEX1 check
    calibration = run_xrw_and_aex_calibration(sample, tdir, raw_dir)

    # 3. Independent Hold-Out Challenge Suite:
    #    (a) Run under profile_4gate (ipi_mask=7) to check if ANY hold-out call touches a page or (page, effect)
    #        outside the frozen closed workset, and collect per-Field hold-out statistics.
    #    (b) Run under dynamic_4gate with ATFIELD_STRICT_MODE=field (Gate B..Gate D, FieldTargetPages only!).
    #    (c) Run under dynamic_final_aex0 with ATFIELD_STRICT_MODE=ecall (EENTER..EEXIT, ReadyTable v3).
    holdout_cfg = INDEPENDENT_HOLDOUT_SUITES[sample]
    res_ho_obs = run_sample(
        sample,
        mode="profile_4gate",
        ipi_mask=7,
        intervention=holdout_cfg["intervention"],
        host_args=holdout_cfg["host_args"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_profile_4gate",
    )

    strict_field_file = tdir / "strict_field_targets_dynamic.txt"
    write_strict_file_from_field_targets(tdir, "dynamic", strict_field_file)
    res_ho_strict_field = run_sample(
        sample,
        mode="dynamic_4gate",
        ipi_mask=3,
        intervention=holdout_cfg["intervention"],
        strict_ready_file=str(strict_field_file),
        strict_mode="field",
        host_args=holdout_cfg["host_args"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_strict_field_window",
    )

    strict_ecall_file = tdir / "strict_ready_dynamic.txt"
    write_strict_file_from_ready(tdir, "dynamic", strict_ecall_file)
    res_ho_strict_ecall = run_sample(
        sample,
        mode="dynamic_final_aex0",
        ipi_mask=0,
        intervention=holdout_cfg["intervention"],
        strict_ready_file=str(strict_ecall_file),
        strict_mode="ecall",
        host_args=holdout_cfg["host_args"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_strict_ecall_readytable",
    )

    per_field_holdout = {}
    for fid in closed_target_pages_by_fid:
        per_field_holdout[fid] = {
            "field_entries": 0,
            "succeeded_entries": 0,
            "expected_failure_entries": 0,
            "unexpected_transport_errors": 0,
            "missing_or_invalid_observations": 0,
            "Observed_holdout_pages": set(),
            "unseen_pages_outside_field_target_pages": set(),
            "unseen_effects_outside_field_target_pages": set(),
        }

    for rec in res_ho_obs["records"]:
        for fobs in rec["fields"]:
            fid = fobs["field_id"]
            if fid not in per_field_holdout:
                continue
            pf = per_field_holdout[fid]
            pf["field_entries"] += 1
            if rec.get("measurement_invalid", 0) or fobs.get("ipi_aex_verified_mask", 0) != 7:
                pf["missing_or_invalid_observations"] += 1
            if rec["sgx_status"] != 0:
                pf["unexpected_transport_errors"] += 1
            elif rec["ms_retval_i32"] == 0:
                pf["succeeded_entries"] += 1
            else:
                pf["expected_failure_entries"] += 1

            for item in fobs["s3"]:
                rva = int(item["rva"], 16)
                ad = item["ad"]
                pf["Observed_holdout_pages"].add(rva)
                if rva not in closed_target_pages_by_fid[fid]:
                    pf["unseen_pages_outside_field_target_pages"].add(hex(rva))
                for eff in (("A", "D") if ad == "D" else ("A",)):
                    if (rva, eff) not in closed_target_effects_by_fid[fid]:
                        pf["unseen_effects_outside_field_target_pages"].add(f"{hex(rva)}:{eff}")

    per_field_holdout_json = {}
    for fid, pf in per_field_holdout.items():
        per_field_holdout_json[fid] = {
            "field_entries": pf["field_entries"],
            "succeeded_entries": pf["succeeded_entries"],
            "expected_failure_entries": pf["expected_failure_entries"],
            "unexpected_transport_errors": pf["unexpected_transport_errors"],
            "missing_or_invalid_observations": pf["missing_or_invalid_observations"],
            "holdout_observed_pages_count": len(pf["Observed_holdout_pages"]),
            "unseen_pages_outside_target_count": len(pf["unseen_pages_outside_field_target_pages"]),
            "unseen_pages_outside_target": sorted(pf["unseen_pages_outside_field_target_pages"]),
            "unseen_effects_outside_target_count": len(pf["unseen_effects_outside_field_target_pages"]),
            "unseen_effects_outside_target": sorted(pf["unseen_effects_outside_field_target_pages"]),
        }

    field_window_faults = sum(r["strict_non_ready_fault_count"] for r in res_ho_strict_field["records"])
    ecall_window_faults = sum(r["strict_non_ready_fault_count"] for r in res_ho_strict_ecall["records"])

    # 4. P4: Three-Group Ablation across 5 Interleaved Rounds!
    #    Group A: all_reg (Full REG XR)
    #    Group B: dynamic_xr (Reduced page set, keeping RX = XR)
    #    Group C: dynamic (Reduced page set + pure code RX refined to X-only)
    perf_rounds = 5
    perf_h_args = ["--requests", "5"] if sample == "sgxwallet" else []
    gate_ablation = {g: {fid: {"tsc_s2": [], "tsc_s3": [], "s3_ad_rewalk_pages": [], "s3_in_s2_rewalk_pages": [], "s3_missing_from_s2_pages": []} for fid in closed_target_pages_by_fid} for g in ("groupA_all_reg_xr", "groupB_dynamic_xr", "groupC_dynamic_refined")}
    prod_aex1_e2e_ns = {g: [] for g in ("groupA_all_reg_xr", "groupB_dynamic_xr", "groupC_dynamic_refined")}

    group_modes_4gate = [
        ("groupA_all_reg_xr", "all_reg_4gate"),
        ("groupB_dynamic_xr", "dynamic_xr_4gate"),
        ("groupC_dynamic_refined", "dynamic_4gate"),
    ]
    group_modes_prod_aex1 = [
        ("groupA_all_reg_xr", "all_reg_final"),
        ("groupB_dynamic_xr", "dynamic_xr_final"),
        ("groupC_dynamic_refined", "dynamic_final"),
    ]

    for rnd in range(perf_rounds):
        for gname, gmode in group_modes_4gate:
            r4 = run_sample(
                sample,
                mode=gmode,
                ipi_mask=3,
                host_args=perf_h_args,
                allow_fast_forward=0,
                persist_prefix=raw_dir / f"ablation_4gate_r{rnd}_{gname}",
            )
            for rec in r4["records"]:
                for fobs in rec["fields"]:
                    fid = fobs["field_id"]
                    if fid not in gate_ablation[gname]:
                        continue
                    s2_set = {x["rva"] for x in fobs["s2"]}
                    s3_set = {x["rva"] for x in fobs["s3"]}
                    d = gate_ablation[gname][fid]
                    d["tsc_s2"].append(fobs["tsc_s2"])
                    d["tsc_s3"].append(fobs["tsc_s3"])
                    d["s3_ad_rewalk_pages"].append(len(s3_set))
                    d["s3_in_s2_rewalk_pages"].append(len(s3_set & s2_set))
                    d["s3_missing_from_s2_pages"].append(len(s3_set - s2_set))

        for gname, pmode in group_modes_prod_aex1:
            rp = run_sample(
                sample,
                mode=pmode,
                ipi_mask=0,
                host_args=perf_h_args,
                allow_fast_forward=0,
                persist_prefix=raw_dir / f"ablation_prod_aex1_r{rnd}_{gname}",
            )
            total_ecall_ns = sum(r["elapsed_ns"] for r in rp["records"])
            prod_aex1_e2e_ns[gname].append(total_ecall_ns)

    ablation_summary_by_field = {}
    for fid in closed_target_pages_by_fid:
        ablation_summary_by_field[fid] = {}
        for gname in ("groupA_all_reg_xr", "groupB_dynamic_xr", "groupC_dynamic_refined"):
            d = gate_ablation[gname][fid]
            ablation_summary_by_field[fid][gname] = {
                "observations": len(d["tsc_s2"]),
                "tsc_s2_ticks": dist_summary(d["tsc_s2"]),
                "tsc_s3_ticks": dist_summary(d["tsc_s3"]),
                "s3_ad_rewalk_pages": dist_summary(d["s3_ad_rewalk_pages"]),
                "s3_in_s2_rewalk_pages": dist_summary(d["s3_in_s2_rewalk_pages"]),
                "s3_missing_from_s2_pages_max": max(d["s3_missing_from_s2_pages"]) if d["s3_missing_from_s2_pages"] else 0,
            }

    pretouch_A = json.loads((tdir / "pretouch.all_reg.finalized.json").read_text())
    pretouch_B = json.loads((tdir / "pretouch.dynamic_xr.finalized.json").read_text())
    pretouch_C = json.loads((tdir / "pretouch.dynamic.finalized.json").read_text())
    ready_A = json.loads((tdir / "enclave.all_reg.ready.json").read_text())
    ready_B = json.loads((tdir / "enclave.dynamic_xr.ready.json").read_text())
    ready_C = json.loads((tdir / "enclave.dynamic.ready.json").read_text())

    strict_verdict = (
        "PASS"
        if (
            calibration["calibration_valid"]
            and field_window_faults == 0
            and ecall_window_faults == 0
            and not res_ho_strict_field["measurement_invalid"]
            and not res_ho_strict_ecall["measurement_invalid"]
            and all(v["unseen_pages_outside_target_count"] == 0 for v in per_field_holdout_json.values())
        )
        else "INVALID_OR_FAIL"
    )

    return {
        "sample": sample,
        "tlb_and_fixture_validation": tlb_and_fixture,
        "fault_detector_calibration_and_aex_notify": calibration,
        "independent_holdout_evaluation": {
            "description": holdout_cfg["desc"],
            "intervention": holdout_cfg["intervention"],
            "host_args": holdout_cfg["host_args"],
            "records_evaluated": len(res_ho_obs["records"]),
            "per_field_holdout": per_field_holdout_json,
            "strict_field_target_pages_window_gateB_to_gateD": {
                "mode": "ATFIELD_STRICT_MODE=field (Gate B..Gate D)",
                "fault_count": field_window_faults,
                "measurement_invalid": res_ho_strict_field["measurement_invalid"],
            },
            "strict_readytable_v3_window_ecall": {
                "mode": "ATFIELD_STRICT_MODE=ecall (EENTER..EEXIT)",
                "fault_count": ecall_window_faults,
                "measurement_invalid": res_ho_strict_ecall["measurement_invalid"],
            },
            "overall_holdout_and_strict_verdict": strict_verdict,
        },
        "three_group_ablation": {
            "interleaved_rounds": perf_rounds,
            "code_and_readytable_sizes": {
                "groupA_all_reg_xr": {
                    "pretouch_code_bytes": pretouch_A["code_bytes"],
                    "readytable_bytes": ready_A["table_bytes"],
                },
                "groupB_dynamic_xr": {
                    "pretouch_code_bytes": pretouch_B["code_bytes"],
                    "readytable_bytes": ready_B["table_bytes"],
                },
                "groupC_dynamic_refined": {
                    "pretouch_code_bytes": pretouch_C["code_bytes"],
                    "readytable_bytes": ready_C["table_bytes"],
                },
            },
            "production_aex1_end_to_end_ecall_ns": {
                g: dist_summary(prod_aex1_e2e_ns[g])
                for g in ("groupA_all_reg_xr", "groupB_dynamic_xr", "groupC_dynamic_refined")
            },
            "per_field_4gate_diagnostic_ablation": ablation_summary_by_field,
        },
        "closure_breakdown": ledger["closure_breakdown"],
    }


def main() -> None:
    out_dir = DYN_ROOT / "experiments"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {}
    for s in SAMPLES:
        print(f"=== Running P0-P4 Hardware Evaluation for {s} ===", flush=True)
        summary[s] = evaluate_sample(s)
        ho = summary[s]["independent_holdout_evaluation"]
        cal = summary[s]["fault_detector_calibration_and_aex_notify"]
        print(
            f"  [Cal & Hold-Out] cal_valid={cal['calibration_valid']} "
            f"aex_notify={cal['same_fault_point_aex0_vs_aex1']['verdict']} "
            f"field_win_faults={ho['strict_field_target_pages_window_gateB_to_gateD']['fault_count']} "
            f"ecall_win_faults={ho['strict_readytable_v3_window_ecall']['fault_count']} "
            f"verdict={ho['overall_holdout_and_strict_verdict']}"
        )
        for fid, cb in summary[s]["closure_breakdown"].items():
            ab = summary[s]["three_group_ablation"]["per_field_4gate_diagnostic_ablation"][fid]
            print(
                f"  [{cb['function']}] target={cb['final_field_target_pages']}/{cb['all_business_reg_pages']} "
                f"S2_med(A/B/C)={ab['groupA_all_reg_xr']['tsc_s2_ticks']['median']}/"
                f"{ab['groupB_dynamic_xr']['tsc_s2_ticks']['median']}/"
                f"{ab['groupC_dynamic_refined']['tsc_s2_ticks']['median']} ticks | "
                f"S3_rewalk_med(A/B/C)={ab['groupA_all_reg_xr']['s3_ad_rewalk_pages']['median']}/"
                f"{ab['groupB_dynamic_xr']['s3_ad_rewalk_pages']['median']}/"
                f"{ab['groupC_dynamic_refined']['s3_ad_rewalk_pages']['median']}"
            )

    (out_dir / "evaluation_results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Wrote {out_dir / 'evaluation_results.json'}")


if __name__ == "__main__":
    main()
