#!/usr/bin/env python3
"""Strict Hardware Evaluation for ATField-SGX Dynamic Worksets (Steps 4 & 5)."""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from acceptance_validator import (
    evaluate_regression_workflow_case,
    extract_valid_s3_effects,
    is_valid_measurement_run,  # noqa: E402
    sha256_path,
    validate_diagnostic_4gate_run,
    validate_production_run_result,
    validate_provenance_consistency,
    validate_run_result,
)
from run_native_sgx import run_sample  # noqa: E402
from target_manifest import discover_real_target_manifests, load_target_manifest  # noqa: E402

SAMPLES = [m["name"] for m in discover_real_target_manifests()]


def get_holdout_suite(sample: str) -> dict:
    m = load_target_manifest(sample)
    ho = dict(m.get("scenarios", {}).get("holdout_suite", {}))
    ho["expected_tags"] = set(ho["expected_tags"]) if ho.get("expected_tags") else None
    aux_list = []
    for ax in ho.get("aux_runs", []):
        ax_copy = dict(ax)
        ax_copy["expected_tags"] = set(ax_copy["expected_tags"]) if ax_copy.get("expected_tags") else None
        aux_list.append(ax_copy)
    ho["aux_runs"] = aux_list
    return ho


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
    """Calibrate single-page X, R, W retraction on Group B (dynamic_xr) and verify:
    1. pte_healed_observed == True on the retracted page,
    2. confirmed_access_kind matches the expected 'X', 'R', 'W' (via RIP / instruction / post-ERESUME D bit),
    3. Restoring the page yields 0 faults,
    4. Same-fault-point AEX0 vs AEX1:
       - AEX0 retracted X-page run ITSELF completes normally (returncode == 0 and 'PASS' in stdout),
       - AEX1 retracted X-page run faults at the exact same page_rva with active_flag == 1, confirmed_access_kind == 'X',
         and terminates on that exact record with sgx_status == 0x1006.
    """
    ws = json.loads((tdir / "workset.dynamic_xr.json").read_text())
    rdy = json.loads((tdir / "enclave.dynamic_xr.ready.json").read_text())
    h_args = load_target_manifest(sample).get("scenarios", {}).get("calibration_host_args", [])
    r_base = run_sample(sample, mode="profile_4gate", ipi_mask=7, host_args=h_args)
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

    page_perm_map = {}
    for f in ws["fields"]:
        for pg in f["pages"]:
            page_perm_map[pg["page_rva"]] = pg

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
            if p > 0 and p in page_perm_map and page_perm_map[p]["effects"] == ["R"] and ad == "A"
        ),
        next(
            p for p, ad in sorted(s3_full_ad_map.items())
            if p > 0 and p in page_perm_map and page_perm_map[p]["effects"] == ["R"]
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
    drop_runs = {}

    for label, exp_kind, drop_rva in (
        ("X_code_page", "X", x_cand),
        ("R_rodata_page", "R", r_cand),
        ("W_data_page", "W", w_cand),
    ):
        cal_file = tdir / f"strict_cal_drop_{label}.txt"
        lines = []
        for idx, rvas in sorted(full_sel_map.items()):
            mod = sorted(rvas - ({drop_rva} if idx == sel_idx else set()))
            lines.append(f"{idx} " + " ".join(f"{p:x}" for p in mod))
        cal_file.write_text("\n".join(lines) + "\n")

        use_field_win = (drop_rva in outside_field_rvas)
        res_drop = run_sample(
            sample,
            mode="dynamic_xr_4gate" if use_field_win else "dynamic_xr_final_aex0",
            ipi_mask=2 if use_field_win else 0,
            strict_ready_file=str(cal_file),
            strict_mode="field" if use_field_win else "ecall",
            host_args=h_args,
            persist_prefix=raw_dir / f"cal_drop_{label}_aex0",
        )
        drop_runs[label] = res_drop
        matched_events = [
            fe
            for rec in res_drop["records"]
            for fe in rec.get("fault_events", [])
            if int(fe["page_rva"], 16) == drop_rva
        ]
        first_ev = matched_events[0] if matched_events else None
        cal_results[label] = {
            "retracted_page_rva": hex(drop_rva),
            "expected_access_kind": exp_kind,
            "target_selector": sel_idx,
            "pte_healed_observed": bool(first_ev and first_ev.get("pte_healed_observed")),
            "ea_verified": bool(first_ev and first_ev.get("ea_verified")),
            "effective_addr_rva": first_ev.get("effective_addr_rva", "0x0") if first_ev else "0x0",
            "confirmed_access_kind": first_ev.get("confirmed_access_kind", "none") if first_ev else "none",
            "inferred_post_window_kind": first_ev.get("inferred_post_window_kind", "none") if first_ev else "none",
            "access_kind_confirmed_match": bool(first_ev and first_ev.get("ea_verified") and first_ev.get("confirmed_access_kind") == exp_kind),
            "matched_fault_count": len(matched_events),
            "first_matched_event": first_ev,
            "aex0_run_completed_cleanly": bool(res_drop["returncode"] == 0 and "PASS" in res_drop["stdout"]),
            "measurement_invalid": res_drop["measurement_invalid"],
            "interpose_sha256": res_drop["interpose_sha256"],
        }

    # Positive control: restore all pages (full ReadyTable v3 of Group B dynamic_xr) and verify 0 faults
    full_file = tdir / "strict_ready_dynamic_xr.txt"
    write_strict_file_from_ready(tdir, "dynamic_xr", full_file)
    res_restored = run_sample(
        sample,
        mode="dynamic_xr_final_aex0",
        ipi_mask=0,
        strict_ready_file=str(full_file),
        strict_mode="ecall",
        host_args=h_args,
        persist_prefix=raw_dir / "cal_restored_full_aex0",
    )
    restored_faults = sum(r["strict_non_ready_fault_count"] for r in res_restored["records"])

    # Same-fault-point AEX0 vs AEX1 comparison on the retracted X_code_page
    x_cal_file = tdir / "strict_cal_drop_X_code_page.txt"
    res_aex0_x = drop_runs["X_code_page"]
    res_aex1_x = run_sample(
        sample,
        mode="dynamic_xr_final",
        ipi_mask=0,
        strict_ready_file=str(x_cal_file),
        strict_mode="ecall",
        host_args=h_args,
        persist_prefix=raw_dir / "cal_drop_X_code_page_aex1",
    )
    aex1_last_rec = res_aex1_x["records"][-1] if res_aex1_x["records"] else None
    aex1_matched_on_last = [
        fe for fe in (aex1_last_rec.get("fault_events", []) if aex1_last_rec else [])
        if int(fe["page_rva"], 16) == x_cand
    ]
    same_fault_aex_notify_pass = bool(
        cal_results["X_code_page"]["pte_healed_observed"]
        and cal_results["X_code_page"]["access_kind_confirmed_match"]
        and cal_results["X_code_page"]["first_matched_event"]["active_flag"] == 1
        and cal_results["X_code_page"]["aex0_run_completed_cleanly"]
        and aex1_last_rec is not None
        and aex1_last_rec["sgx_status"] == 0x1006
        and len(aex1_matched_on_last) > 0
        and aex1_matched_on_last[0]["active_flag"] == 1
        and aex1_matched_on_last[0]["page_rva"] == hex(x_cand)
        and res_aex1_x["returncode"] != 0
        and not res_aex1_x["timed_out"]
        and not res_aex1_x["measurement_invalid"]
    )

    all_cal_valid = bool(
        all(
            cal_results[k]["pte_healed_observed"]
            and cal_results[k]["access_kind_confirmed_match"]
            and cal_results[k]["aex0_run_completed_cleanly"]
            and not cal_results[k]["measurement_invalid"]
            for k in ("X_code_page", "R_rodata_page", "W_data_page")
        )
        and restored_faults == 0
        and res_restored["returncode"] == 0
        and "PASS" in res_restored["stdout"]
        and not res_restored["measurement_invalid"]
    )
    return {
        "calibration_valid": all_cal_valid,
        "single_page_retraction_controls": cal_results,
        "restored_positive_control_faults": restored_faults,
        "restored_interpose_sha256": res_restored["interpose_sha256"],
        "same_fault_point_aex0_vs_aex1": {
            "fault_page_rva": hex(x_cand),
            "aex0_first_event": cal_results["X_code_page"]["first_matched_event"],
            "aex0_retracted_run_returncode": res_aex0_x["returncode"],
            "aex0_retracted_run_stdout": res_aex0_x["stdout"],
            "aex0_retracted_run_completed_normally": cal_results["X_code_page"]["aex0_run_completed_cleanly"],
            "aex1_terminating_record_seq": aex1_last_rec["call_seq"] if aex1_last_rec else -1,
            "aex1_terminating_sgx_status": hex(aex1_last_rec["sgx_status"]) if aex1_last_rec else "none",
            "aex1_fault_event_on_terminating_record": aex1_matched_on_last[0] if aex1_matched_on_last else None,
            "aex1_host_returncode": res_aex1_x["returncode"],
            "verdict": "PASS" if same_fault_aex_notify_pass else "FAIL",
        },
    }


def run_tlb_and_fixture_checks(sample: str, raw_dir: Path) -> dict:
    h_args = load_target_manifest(sample).get("scenarios", {}).get("calibration_host_args", [])
    r_cold = run_sample(sample, mode="profile_4gate", ipi_mask=7, host_args=h_args, persist_prefix=raw_dir / "tlb_cal_cold_ipi7")
    r_warm = run_sample(sample, mode="profile_4gate", ipi_mask=0, host_args=h_args, persist_prefix=raw_dir / "tlb_cal_warm_ipi0")
    r_uninst = run_sample(sample, mode="dynamic_xr_final_aex0", ipi_mask=0, host_args=h_args, persist_prefix=raw_dir / "fixture_uninst_aex0")

    fc = next(rec["fields"][0] for rec in r_cold["records"] if rec["fields"])
    fw = next(rec["fields"][0] for rec in r_warm["records"] if rec["fields"])
    s01_pages = {x["rva"] for x in fc["s0"] + fc["s1"]}
    cold_s3_pages = {x["rva"] for x in fc["s3"]}
    warm_s3_pages = {x["rva"] for x in fw["s3"]}

    uninst_rets = [(r["ecall_index"], r["sgx_status"], r["ms_retval"]) for r in r_uninst["records"]]
    gate_rets = [(r["ecall_index"], r["sgx_status"], r["ms_retval"]) for r in r_cold["records"]]

    return {
        "cold_vs_warm_tlb_calibration": {
            "cold_ipi_verified_mask": fc["ipi_aex_verified_mask"],
            "cold_s3_pages_observed": len(cold_s3_pages),
            "warm_no_ipi_s3_pages_observed": len(warm_s3_pages),
            "s0_s1_overlap_rewalked_in_s3_when_cold": len(s01_pages & cold_s3_pages),
            "s0_s1_overlap_rewalked_in_s3_when_warm": len(s01_pages & warm_s3_pages),
            "cold_tlb_proven": bool(fc["ipi_aex_verified_mask"] == 7 and len(cold_s3_pages) > len(warm_s3_pages)),
            "interpose_sha256": r_cold["interpose_sha256"],
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


def run_known_answer_measurement_calibration() -> dict:
    """Execute the Known-Answer 7-Case Hardware Measurement Calibration Fixture (`calibration-fixture`):
    1. Pages accessed first in S0/S1 (before Gate B), then in S3 across 2 repeated Field entries in one ECALL:
       - X_code_page (`cal_code_target_fn`, expected `['A']`)
       - RX_data_read_page (`cal_rx_data_table_fn`, RX page read as data without calling it in S3, expected `['A']`)
       - R_rodata_page (`cal_rodata_page`, expected `['A']`)
       - W_writable_page (`cal_writable_page`, expected `['A', 'D']`)
       - Cross_page_0 & Cross_page_1 (`cal_cross_page_buf` spanning 2 pages, expected `['A', 'D']` on both)
       - Temporary 4-page deep stack frame (`cal_deep_stack_helper`) that returns before Gate D
         so `gateB_rsp_rva == gateD_rsp_rva`, verifying S3 still captures >= 4 dirty (`D`) stack pages!
    2. Full pre-touch positive control (`dynamic_xr_4gate`, `ipi_mask=3`): verifies `0` clean S3 rewalk pages.
    3. Deliberate 1-page omission negative control (`omit_one_4gate`, omitting `W_writable_page` from pre-touch
       and workset): verifies both `validate_run_result` (`UNCOVERED_PAGE_...`) and 4-Gate `S3` rewalk catch the
       exact omitted page.
    4. Active permission retraction negative control (`ATFIELD_STRICT_READY_FILE` dropping `W_writable_page`):
       verifies `AEX0` heals and logs exact EA (`confirmed_access_kind == 'W'`), `AEX1` aborts with `0x1006`,
       and restoring full `ReadyTable` yields `0` faults and `rc=0, PASS`.
    """
    import subprocess
    import sys
    sys.path.insert(0, str(DYN_ROOT))
    from controller import PRETOUCH_TOOL
    from elf_workset import ElfFile, normalized_fields

    sample = "calibration-fixture"
    tdir = DYN_ROOT / "targets" / sample
    cdir = DYN_ROOT / "challenges" / sample
    raw_dir = DYN_ROOT / "experiments" / "raw_traces" / sample
    raw_dir.mkdir(parents=True, exist_ok=True)
    for old_f in raw_dir.glob("cal_fix_*"):
        old_f.unlink(missing_ok=True)

    cfg = json.loads((cdir / "calibration_config.json").read_text())
    elf = ElfFile(tdir / "enclave.profile.so")
    syms = {s["name"]: s["value"] for s in elf.symbols()}
    fields = normalized_fields(tdir / "fields.json")
    fid = f"0x{fields[0]['_id_value']:016x}"

    # 1. S0/S1 pre-access -> S3 measurement across 2 repeated Field entries in one ECALL
    r_prof = run_sample(
        sample,
        mode="profile_4gate",
        ipi_mask=7,
        allow_fast_forward=0,
        persist_prefix=raw_dir / "cal_fix_01_profile_s0_then_s3",
    )
    val_prof = validate_run_result(
        r_prof,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=1,
        expected_field_ids={fid},
        require_ipi_mask=7,
    )
    rec = r_prof["records"][0]
    repeated_entries = len(rec["fields"])
    declared_cases_report = {}
    total_expected_effects = 0
    total_observed_effects = 0

    for entry_idx, fobs in enumerate(rec["fields"]):
        s0_rvas = {int(x["rva"], 16) for x in fobs["s0"]}
        s3_raw = {(int(x["rva"], 16), x["ad"]) for x in fobs["s3"]}
        s3_exp = set()
        for rva, ad in s3_raw:
            s3_exp.add((rva, "A"))
            if ad == "D":
                s3_exp.add((rva, "D"))
        gb = int(fobs["gateB_rsp_rva"], 16)
        gd = int(fobs["gateD_rsp_rva"], 16)
        stack_dirty_rvas = sorted(hex(rva) for rva, ad in s3_raw if ad == "D" and abs(rva - gb) <= 8 * 4096)

        for cname, cspec in cfg["declared_symbols"].items():
            page_rva = (syms[cspec["symbol"]] + cspec["page_offset"]) & ~0xFFF
            exp_effs = cspec["effects"]
            total_expected_effects += len(exp_effs)
            obs_cnt = sum(1 for e in exp_effs if (page_rva, e) in s3_exp)
            total_observed_effects += obs_cnt
            if entry_idx == 0:
                declared_cases_report[cname] = {
                    "page_rva": hex(page_rva),
                    "expected_effects": exp_effs,
                    "pre_accessed_in_s0": page_rva in s0_rvas,
                    "observed_in_s3_entry0": obs_cnt == len(exp_effs),
                    "observed_in_s3_entry1": False,
                }
            else:
                declared_cases_report[cname]["observed_in_s3_entry1"] = (obs_cnt == len(exp_effs))

        req_stack_pages = cfg["min_temp_deep_stack_dirty_pages"]
        total_expected_effects += req_stack_pages * 2
        total_observed_effects += min(len(stack_dirty_rvas), req_stack_pages) * 2
        if entry_idx == 0:
            declared_cases_report["Temp_deep_stack_4pages"] = {
                "gateB_rsp_rva": hex(gb),
                "gateD_rsp_rva": hex(gd),
                "rsp_endpoint_delta_bytes": abs(gb - gd),
                "dirty_stack_pages_entry0": stack_dirty_rvas,
                "dirty_stack_pages_entry1": [],
            }
        else:
            declared_cases_report["Temp_deep_stack_4pages"]["dirty_stack_pages_entry1"] = stack_dirty_rvas

    missed_effects = total_expected_effects - total_observed_effects
    omission_rate = missed_effects / total_expected_effects if total_expected_effects > 0 else 0.0

    # 2. Full pre-touch positive control (dynamic_xr_4gate, ipi_mask=3) -> 0 clean S3 rewalks
    r_full_4g = run_sample(
        sample,
        mode="dynamic_xr_4gate",
        ipi_mask=3,
        allow_fast_forward=0,
        persist_prefix=raw_dir / "cal_fix_02_full_pretouch_4gate",
    )
    val_full_4g = validate_diagnostic_4gate_run(
        r_full_4g,
        expected_field_ids={fid},
        expected_ecall_seq=[0],
        expected_field_call_seqs={0},
        require_ipi_mask=3,
        require_clean_observation_per_field=True,
    )
    full_pretouch_rewalks = [
        len(fo["s3"])
        for r in r_full_4g["records"]
        for fo in r["fields"]
        if fo.get("s3_active_aex_count") == 0
    ]

    # 3. Deliberate 1-page omission negative control (omit W_writable_page from workset & pre-touch)
    w_rva = (syms[cfg["declared_symbols"]["W_writable_page"]["symbol"]]) & ~0xFFF
    ws_full = json.loads((tdir / "workset.dynamic_xr.json").read_text())
    ws_omit = json.loads((tdir / "workset.dynamic_xr.json").read_text())
    ws_omit["fields"][0]["pages"] = [
        pg for pg in ws_omit["fields"][0]["pages"] if pg["page_rva"] != w_rva
    ]
    ws_omit_path = tdir / "workset.omit_one.json"
    ws_omit_path.write_text(json.dumps(ws_omit, indent=2) + "\n")

    omit_effects_by_fid = {
        fid: {
            (pg["page_rva"], "A") for pg in ws_omit["fields"][0]["pages"]
        } | {
            (pg["page_rva"], "D") for pg in ws_omit["fields"][0]["pages"] if "W" in pg["effects"]
        }
    }
    val_omit_workset = validate_run_result(
        r_prof,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=1,
        expected_field_ids={fid},
        require_ipi_mask=7,
        closed_workset_effects=omit_effects_by_fid,
    )

    cap_q = ws_full["layout"]["capacity_q"]
    omit_final_elf = tdir / "enclave.omit_one.final.so"
    omit_final_json = tdir / "pretouch.omit_one.finalized.json"
    subprocess.run([
        str(PRETOUCH_TOOL), "finalize",
        "--profile-elf", str(tdir / "enclave.profile.so"),
        "--signed-profile-elf", str(tdir / "enclave.profile.signed.so"),
        "--workset", str(ws_omit_path),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--out-elf", str(omit_final_elf),
        "--out-json", str(omit_final_json),
    ], check=True, capture_output=True)
    subprocess.run([
        sys.executable, str(DYN_ROOT / "tools" / "patch_4gate.py"),
        "--input-elf", str(omit_final_elf),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--config-xml", str(tdir / "Enclave.aex0.config.xml"),
        "--out-elf", str(tdir / "enclave.omit_one.4gate.so"),
        "--out-signed-elf", str(tdir / "enclave.omit_one.4gate.aex0.signed.so"),
        "--out-json", str(tdir / "enclave.omit_one.4gate.json"),
    ], check=True, capture_output=True)

    r_omit_4g = run_sample(
        sample,
        mode="omit_one_4gate",
        ipi_mask=3,
        allow_fast_forward=0,
        persist_prefix=raw_dir / "cal_fix_03_omit_one_4gate",
    )
    omit_s3_detected = any(
        int(it["rva"], 16) == w_rva and it["ad"] == "D"
        for r in r_omit_4g["records"]
        for fo in r["fields"]
        for it in fo["s3"]
    )

    # 4. Active permission retraction negative control (drop w_rva in strict_ready_file) + restored control
    rdy = json.loads((tdir / "enclave.dynamic_xr.ready.json").read_text())
    sel_rvas = set(rdy["selectors"][0]["page_rvas"])
    drop_file = tdir / "strict_cal_drop_w.txt"
    drop_file.write_text("0 " + " ".join(f"{p:x}" for p in sorted(sel_rvas - {w_rva})) + "\n")
    full_file = tdir / "strict_cal_full.txt"
    full_file.write_text("0 " + " ".join(f"{p:x}" for p in sorted(sel_rvas)) + "\n")

    r_retract_aex0 = run_sample(
        sample,
        mode="dynamic_xr_final_aex0",
        ipi_mask=0,
        strict_ready_file=str(drop_file),
        strict_mode="ecall",
        host_args=["1"],
        persist_prefix=raw_dir / "cal_fix_04_retract_w_aex0",
    )
    matched_faults = [
        fe
        for r in r_retract_aex0["records"]
        for fe in r.get("fault_events", [])
        if int(fe["page_rva"], 16) == w_rva
    ]
    r_retract_aex1 = run_sample(
        sample,
        mode="dynamic_xr_final",
        ipi_mask=0,
        strict_ready_file=str(drop_file),
        strict_mode="ecall",
        host_args=["1"],
        persist_prefix=raw_dir / "cal_fix_05_retract_w_aex1",
    )
    r_restored = run_sample(
        sample,
        mode="dynamic_xr_final_aex0",
        ipi_mask=0,
        strict_ready_file=str(full_file),
        strict_mode="ecall",
        host_args=["1"],
        persist_prefix=raw_dir / "cal_fix_06_restored_full_aex0",
    )
    restored_faults = sum(r["strict_non_ready_fault_count"] for r in r_restored["records"])

    all_pass = bool(
        val_prof["status"] == "PASS"
        and repeated_entries == cfg["expected_repeated_field_entries_per_ecall"]
        and missed_effects == 0
        and val_full_4g["status"] == "PASS"
        and len(full_pretouch_rewalks) == 2 and all(x == 0 for x in full_pretouch_rewalks)
        and val_omit_workset["status"] == "FAIL"
        and any(f"UNCOVERED_PAGE_{hex(w_rva)}" in x for x in val_omit_workset["reasons"])
        and omit_s3_detected
        and len(matched_faults) > 0 and matched_faults[0].get("pte_healed_observed") and matched_faults[0].get("confirmed_access_kind") == "W"
        and r_retract_aex1["records"][-1]["sgx_status"] == 0x1006
        and restored_faults == 0 and r_restored["returncode"] == 0
    )
    if not all_pass:
        raise RuntimeError(f"Known-answer measurement calibration fixture failed! missed={missed_effects} rewalks={full_pretouch_rewalks} omit_det={omit_s3_detected}")

    return {
        "fixture": sample,
        "repeated_field_entries_per_ecall": repeated_entries,
        "total_declared_effects_across_entries": total_expected_effects,
        "observed_declared_effects": total_observed_effects,
        "missed_declared_effects": missed_effects,
        "measurement_omission_rate": omission_rate,
        "declared_cases": declared_cases_report,
        "full_pretouch_clean_rewalk_pages": full_pretouch_rewalks,
        "deliberate_omission_control": {
            "omitted_page_rva": hex(w_rva),
            "validator_status": val_omit_workset["status"],
            "validator_reasons": val_omit_workset["reasons"],
            "caught_by_4gate_s3_rewalk": omit_s3_detected,
        },
        "active_retraction_and_restore_control": {
            "retracted_page_rva": hex(w_rva),
            "aex0_pte_healed_and_ea_verified": bool(matched_faults and matched_faults[0].get("ea_verified")),
            "aex0_confirmed_kind": matched_faults[0].get("confirmed_access_kind", "") if matched_faults else "",
            "aex1_fail_stop_status": hex(r_retract_aex1["records"][-1]["sgx_status"]),
            "restored_control_faults": restored_faults,
        },
        "verdict": "PASS" if all_pass else "FAIL",
    }


def run_frozen_workset_generalization_suite(
    sample: str,
    tdir: Path,
    raw_dir: Path,
    expected_fids: set[str],
    closed_target_effects_by_fid: dict[str, set[tuple[int, str]]],
    ready_sel_set: set[int],
) -> dict:
    """Evaluate the FROZEN Group B workset (`workset.dynamic_xr.json` & `enclave.dynamic_xr.final.signed.so`)
    across 10 predetermined end-to-end regression cases per configuration (60 cases total across the
    4 applications / 6 configurations).
    Each case is evaluated on BOTH `profile_4gate` (coverage) and `dynamic_xr_final` (frozen protected
    production enclave with `AEX-Notify=1` and `ReadyTable v3`) and reports FOUR separate verdicts:
      1. `measurement_valid_count`
      2. `business_workflow_completed_count` (enforcing `min_rec`, `expected_fids`, `expected_tags`, `rc==0`, `PASS`)
      3. `workset_coverage_zero_omission_count`
      4. `frozen_protected_enclave_completed_count` (plus `protected_aex1_0x1006_retries`)
    Note: Because these 60 cases are a predetermined regression matrix rather than random draws from a
    formally specified input distribution, no binomial probability upper bound is claimed.
    """
    manifest = load_target_manifest(sample)
    raw_cases = manifest.get("scenarios", {}).get("predetermined_regression_cases", [])
    unseen_specs = []
    for rc in raw_cases:
        c = dict(rc)
        c["expected_tags"] = set(c.get("expected_tags", []))
        unseen_specs.append(c)

    meas_valid_cnt = 0
    biz_completed_cnt = 0
    cov_zero_omission_cnt = 0
    prod_completed_cnt = 0
    prod_aex_retries = 0
    max_omitted_pages = 0
    max_omitted_effects = 0
    total_ecalls_evaluated = 0
    total_field_entries = 0
    workflow_details = []

    for idx_w, wsp in enumerate(unseen_specs):
        rw_cov = run_sample(
            sample,
            mode="profile_4gate",
            ipi_mask=7,
            intervention=wsp["intervention"],
            host_args=wsp["host_args"],
            allow_fast_forward=0,
            persist_prefix=raw_dir / f"holdout_unseen_wf_{idx_w:02d}_{wsp['id']}",
        )
        rw_prod = {}
        for att in range(4):
            sfx = "" if att == 0 else f"_retry{att}"
            rw_prod = run_sample(
                sample,
                mode="dynamic_xr_final",
                ipi_mask=0,
                intervention=wsp["intervention"],
                host_args=wsp["host_args"],
                allow_fast_forward=0,
                persist_prefix=raw_dir / f"holdout_unseen_wf_{idx_w:02d}_{wsp['id']}_prod_aex1{sfx}",
            )
            if not any(r.get("sgx_status") == 0x1006 for r in rw_prod.get("records", [])):
                break
            prod_aex_retries += 1

        case_res = evaluate_regression_workflow_case(
            wsp,
            rw_cov,
            rw_prod,
            expected_fids=expected_fids,
            closed_target_effects_by_fid=closed_target_effects_by_fid,
            ready_sel_set=ready_sel_set,
        )
        if not (
            case_res["measurement_valid"]
            and case_res["business_workflow_completed"]
            and case_res["workset_coverage_zero_omission"]
            and case_res["frozen_protected_enclave_completed"]
        ):
            raise RuntimeError(f"Predetermined regression workflow {wsp['id']} on {sample} failed 4-verdict check: {case_res}")

        meas_valid_cnt += int(case_res["measurement_valid"])
        biz_completed_cnt += int(case_res["business_workflow_completed"])
        cov_zero_omission_cnt += int(case_res["workset_coverage_zero_omission"])
        prod_completed_cnt += int(case_res["frozen_protected_enclave_completed"])
        total_ecalls_evaluated += case_res["ecalls"]
        total_field_entries += case_res["field_entries"]
        max_omitted_pages = max(max_omitted_pages, case_res["omitted_pages_count"] or 0)
        max_omitted_effects = max(max_omitted_effects, case_res["omitted_effects_count"] or 0)
        workflow_details.append(case_res)

    n_wf = len(unseen_specs)
    return {
        "predetermined_cases_count": n_wf,
        "measurement_valid_count": meas_valid_cnt,
        "business_workflow_completed_count": biz_completed_cnt,
        "workset_coverage_zero_omission_count": cov_zero_omission_cnt,
        "frozen_protected_enclave_completed_count": prod_completed_cnt,
        "protected_aex1_0x1006_retries": prod_aex_retries,
        "total_ecalls_evaluated": total_ecalls_evaluated,
        "total_field_entries_evaluated": total_field_entries,
        "workflows_with_any_omission": n_wf - cov_zero_omission_cnt,
        "worst_case_omitted_pages_per_workflow": max_omitted_pages,
        "worst_case_omitted_effects_per_workflow": max_omitted_effects,
        "workflows": workflow_details,
    }


def evaluate_sm4_two_tier(
    sample: str,
    tdir: Path,
    raw_dir: Path,
    ledger: dict,
    expected_fids: set[str],
    closed_target_effects_by_fid: dict[str, set[tuple[int, str]]],
) -> dict:
    """Non-circular Two-Tier SM4 Producer-Consumer Evaluation:
    - Tier 1 loads the independently built and frozen `workset.sm4_seeded_xr.json`,
      `enclave.sm4_seeded_xr.4gate.aex0.signed.so`, `enclave.sm4_seeded_xr.final.signed.so`,
      and `enclave.sm4_seeded_xr.ready.bin` (whose hashes differ from the AES-only `dynamic_xr` artifacts),
      then executes THREE fresh independent `--sm4-check` runs:
        1. `profile_4gate` coverage check (`validate_run_result` with `expected_field_ids` & `require_ipi_mask=7`);
        2. `sm4_seeded_xr_4gate` pre-touch diagnostic check (`validate_diagnostic_4gate_run` + 0 clean S3 rewalks);
        3. `sm4_seeded_xr_final` protected production execution under `AEX-Notify=1` and kernel `ReadyTable`
           enforcement (`validate_production_run_result` with `require_readiness=True`).
    - Tier 2 validates the fresh `--sm4-check` coverage run against the AES-only `dynamic_xr` workset
      (with `expected_field_ids` & `require_ipi_mask=7`), honestly reporting `FAIL` and the exact uncovered SM4 pages.
    """
    ws_sm4_path = tdir / "workset.sm4_seeded_xr.json"
    rdy_sm4_path = tdir / "enclave.sm4_seeded_xr.ready.json"
    if not ws_sm4_path.is_file() or not rdy_sm4_path.is_file():
        raise FileNotFoundError(f"Missing frozen Tier-1 SM4-seeded artifacts in {tdir}")

    ws_sm4 = json.loads(ws_sm4_path.read_text())
    rdy_sm4 = json.loads(rdy_sm4_path.read_text())
    sm4_ready_sel_set = {s["ecall_index"] for s in rdy_sm4["selectors"] if s["page_rvas"]}
    sm4_effects_by_fid: dict[str, set[tuple[int, str]]] = {}
    for f in ws_sm4["fields"]:
        fid = f"0x{int(f['id'], 16):016x}" if isinstance(f["id"], str) else f"0x{f['id']:016x}"
        effs: set[tuple[int, str]] = set()
        for pg in f["pages"]:
            rva = pg["page_rva"]
            effs.add((rva, "A"))
            if "W" in pg["effects"]:
                effs.add((rva, "D"))
        sm4_effects_by_fid[fid] = effs

    # Fresh independent `--sm4-check` coverage run on profile_4gate
    r_sm4_cov = run_sample(
        sample,
        mode="profile_4gate",
        ipi_mask=7,
        host_args=["--sm4-check"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_sm4_independent_coverage_4gate",
    )
    val_t1_cov = validate_run_result(
        r_sm4_cov,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=21,
        expected_field_ids=expected_fids,
        require_ipi_mask=7,
        closed_workset_effects=sm4_effects_by_fid,
    )

    sm4_ecall_seq = [r["ecall_index"] for r in r_sm4_cov["records"]]
    sm4_field_call_seqs = {r["call_seq"] for r in r_sm4_cov["records"] if r["fields"]}

    # Fresh independent 4-Gate pre-touch diagnostic run on sm4_seeded_xr_4gate
    r_sm4_4gate = run_sample(
        sample,
        mode="sm4_seeded_xr_4gate",
        ipi_mask=3,
        host_args=["--sm4-check"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_tier1_sm4_4gate_pretouch",
    )
    val_t1_4gate = validate_diagnostic_4gate_run(
        r_sm4_4gate,
        expected_field_ids=expected_fids,
        expected_ecall_seq=sm4_ecall_seq,
        expected_field_call_seqs=sm4_field_call_seqs,
        require_ipi_mask=3,
    )
    clean_rewalks = [
        len(fobs["s3"])
        for rec in r_sm4_4gate["records"]
        for fobs in rec["fields"]
        if fobs.get("s3_active_aex_count", 0) == 0
    ]

    # Fresh independent production protected execution on sm4_seeded_xr_final (AEX-Notify=1 + ReadyTable)
    val_t1_prod = {"status": "FAIL", "reasons": ["NOT_RUN"]}
    r_sm4_prod = {}
    for att in range(4):
        sfx = "" if att == 0 else f"_retry{att}"
        r_sm4_prod = run_sample(
            sample,
            mode="sm4_seeded_xr_final",
            ipi_mask=0,
            host_args=["--sm4-check"],
            allow_fast_forward=0,
            persist_prefix=raw_dir / f"holdout_tier1_sm4_prod_aex1{sfx}",
        )
        val_t1_prod = validate_production_run_result(
            r_sm4_prod,
            expected_stdout_substr="PASS",
            expected_ecall_seq=sm4_ecall_seq,
            ready_sel_set=sm4_ready_sel_set,
            require_readiness=True,
        )
        if val_t1_prod["status"] == "PASS":
            break
        if not any(r.get("sgx_status") == 0x1006 for r in r_sm4_prod.get("records", [])):
            break

    # Tier 2: Validate the exact same independent `--sm4-check` run against the AES-only `dynamic_xr` workset
    val_t2_cov = validate_run_result(
        r_sm4_cov,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=21,
        expected_field_ids=expected_fids,
        require_ipi_mask=7,
        closed_workset_effects=closed_target_effects_by_fid,
    )

    sm4_art = ledger.get("artifacts", {}).get("sm4_seeded_xr", {})
    aes_art = ledger.get("artifacts", {}).get("dynamic_xr", {})
    prov_sm4 = validate_provenance_consistency(
        ledger,
        [r_sm4_cov, r_sm4_4gate, r_sm4_prod],
        target_dir=tdir,
        variant="sm4_seeded_xr",
    )
    disk_ws_sha = sha256_path(ws_sm4_path)
    disk_aex1_sha = sha256_path(tdir / "enclave.sm4_seeded_xr.final.signed.so")
    disk_4gate_sha = sha256_path(tdir / "enclave.sm4_seeded_xr.4gate.aex0.signed.so")
    disk_rdy_sha = sha256_path(tdir / "enclave.sm4_seeded_xr.ready.bin")
    exact_file_and_run_binding_ok = bool(
        prov_sm4["status"] == "PASS"
        and disk_ws_sha == sm4_art.get("workset_sha256")
        and disk_aex1_sha == sm4_art.get("signed_aex1_sha256")
        and disk_4gate_sha == sm4_art.get("gate_aex0_sha256")
        and disk_rdy_sha == sm4_art.get("ready_bin_sha256")
        and r_sm4_4gate.get("enclave_sha256") == disk_4gate_sha
        and r_sm4_prod.get("enclave_sha256") == disk_aex1_sha
        and r_sm4_prod.get("ready_table_sha256") == disk_rdy_sha
        and sha256_path(Path(r_sm4_cov.get("trace_jsonl", ""))) == r_sm4_cov.get("trace_sha256")
        and sha256_path(Path(r_sm4_4gate.get("trace_jsonl", ""))) == r_sm4_4gate.get("trace_sha256")
        and sha256_path(Path(r_sm4_prod.get("trace_jsonl", ""))) == r_sm4_prod.get("trace_sha256")
        and disk_ws_sha != aes_art.get("workset_sha256")
        and disk_aex1_sha != aes_art.get("signed_aex1_sha256")
        and disk_rdy_sha != aes_art.get("ready_bin_sha256")
        and sm4_art.get("seed_collection_trace_sha256", "") != r_sm4_cov["trace_sha256"]
    )
    tier1_overall_pass = bool(
        val_t1_cov["status"] == "PASS"
        and val_t1_4gate["status"] == "PASS"
        and val_t1_prod["status"] == "PASS"
        and len(clean_rewalks) > 0 and all(x == 0 for x in clean_rewalks)
        and exact_file_and_run_binding_ok
    )
    if not tier1_overall_pass:
        raise RuntimeError(
            f"Tier-1 SM4 independent protected verification failed on {sample}: "
            f"cov={val_t1_cov['status']} 4gate={val_t1_4gate['status']} prod={val_t1_prod['status']} rewalks={clean_rewalks}"
        )

    return {
        "tier1_sm4_seeded_coverage": {
            "description": "Tier 1 (Seed Coverage): Independent sm4_seeded_xr workset, ReadyTable, and signed 4gate/protect enclaves built from seed run and verified by fresh hold-out coverage, 4-gate 0-rewalk, and AEX1 production runs.",
            "seed_added_effects_count": sum(len(sm4_effects_by_fid[fid] - closed_target_effects_by_fid[fid]) for fid in sm4_effects_by_fid),
            "independent_artifacts": {
                "workset_sha256": sha256_path(ws_sm4_path),
                "signed_aex1_sha256": sha256_path(tdir / "enclave.sm4_seeded_xr.final.signed.so"),
                "gate_aex0_sha256": sha256_path(tdir / "enclave.sm4_seeded_xr.4gate.aex0.signed.so"),
                "ready_bin_sha256": sha256_path(tdir / "enclave.sm4_seeded_xr.ready.bin"),
                "distinct_from_aes_only_workset": sm4_art.get("workset_sha256") != aes_art.get("workset_sha256"),
                "seed_trace_sha256": sm4_art.get("seed_collection_trace_sha256", ""),
                "holdout_coverage_trace_sha256": r_sm4_cov["trace_sha256"],
                "holdout_prod_trace_sha256": r_sm4_prod.get("trace_sha256", ""),
            },
            "validator_result": val_t1_cov,
            "diagnostic_4gate_validator_result": val_t1_4gate,
            "clean_zero_rewalk_observations": f"{sum(1 for x in clean_rewalks if x == 0)}/{len(clean_rewalks)}",
            "protected_production_validator_result": val_t1_prod,
            "overall_tier1_status": "PASS" if tier1_overall_pass else "FAIL",
        },
        "tier2_aes_only_seed_discovery": {
            "description": "Tier 2 (Un-Seeded Discovery from AES-Only Workflow): Validates fresh --sm4-check run against AES-only dynamic_xr workset (with expected_field_ids and require_ipi_mask=7).",
            "structural_limitation": "ehsm_create_sm4_key requires coupled 3-field struct changes inside ehsm_keyblob_t (metadata.keyspec=20, keybloblen=64, cmk_size=80) before domain-key AES-GCM sealing.",
            "validator_result": val_t2_cov,
        },
    }


def evaluate_sample(sample: str) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    wdir = DYN_ROOT / "witnesses" / sample
    raw_dir = DYN_ROOT / "experiments" / "raw_traces" / sample
    raw_dir.mkdir(parents=True, exist_ok=True)
    for old_f in raw_dir.glob("*"):
        if old_f.name.startswith(("holdout_", "cal_", "ablation_", "tlb_", "uninstrumented_", "four_gate_")):
            old_f.unlink(missing_ok=True)

    ledger = json.loads((wdir / "witness_ledger.json").read_text())
    # Default candidate is Group B (workset.dynamic_xr.json, keeping RX = XR conservatively!)
    ws_xr = json.loads((tdir / "workset.dynamic_xr.json").read_text())
    closed_target_pages_by_fid = {}
    closed_target_effects_by_fid = {}
    for f in ws_xr["fields"]:
        fid = f"0x{int(f['id'], 16):016x}" if isinstance(f["id"], str) else f"0x{f['id']:016x}"
        closed_target_pages_by_fid[fid] = {pg["page_rva"] for pg in f["pages"]}
        effs = set()
        for pg in f["pages"]:
            rva = pg["page_rva"]
            effs.add((rva, "A"))
            if "W" in pg["effects"]:
                effs.add((rva, "D"))
        closed_target_effects_by_fid[fid] = effs

    expected_fids = set(closed_target_pages_by_fid.keys())
    tlb_and_fixture = run_tlb_and_fixture_checks(sample, raw_dir)
    calibration = run_xrw_and_aex_calibration(sample, tdir, raw_dir)

    # Hold-out evaluation on default Group B (dynamic_xr)
    holdout_cfg = get_holdout_suite(sample)
    res_ho_obs = run_sample(
        sample,
        mode="profile_4gate",
        ipi_mask=7,
        intervention=holdout_cfg["intervention"],
        host_args=holdout_cfg["host_args"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_profile_4gate",
    )
    val_ho_obs = validate_run_result(
        res_ho_obs,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=holdout_cfg["min_records"],
        expected_field_ids=expected_fids,
        expected_tags=holdout_cfg["expected_tags"],
        require_ipi_mask=7,
        closed_workset_effects=closed_target_effects_by_fid,
    )

    aux_obs_records = []
    aux_validations = []
    for aux in holdout_cfg.get("aux_runs", []):
        res_aux = run_sample(
            sample,
            mode="profile_4gate",
            ipi_mask=7,
            intervention=aux["intervention"],
            stop_before_normal_ecall=aux.get("stop_before_normal_ecall", ""),
            host_args=aux.get("host_args", []),
            allow_fast_forward=0,
            persist_prefix=raw_dir / f"holdout_aux_{aux['name']}",
        )
        v_aux = validate_run_result(
            res_aux,
            expected_returncode=0,
            expected_stdout_substr=aux.get("expected_stdout_substr", ""),
            expected_min_records=aux["min_records"],
            expected_field_ids=expected_fids if aux.get("expected_stdout_substr") == "PASS" else None,
            expected_tags=aux.get("expected_tags"),
            require_ipi_mask=7,
            closed_workset_effects=closed_target_effects_by_fid,
        )
        aux_validations.append({"name": aux["name"], "validation": v_aux, "interpose_sha256": res_aux["interpose_sha256"]})
        aux_obs_records.extend(res_aux["records"])

    strict_field_file = tdir / "strict_field_targets_dynamic_xr.txt"
    write_strict_file_from_field_targets(tdir, "dynamic_xr", strict_field_file)
    res_ho_strict_field = run_sample(
        sample,
        mode="dynamic_xr_4gate",
        ipi_mask=3,
        intervention=holdout_cfg["intervention"],
        strict_ready_file=str(strict_field_file),
        strict_mode="field",
        host_args=holdout_cfg["host_args"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_strict_field_window",
    )
    val_ho_strict_field = validate_run_result(
        res_ho_strict_field,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=holdout_cfg["min_records"],
        expected_field_ids=expected_fids,
        expected_tags=holdout_cfg["expected_tags"],
        require_strict_mode=2,
        require_zero_strict_faults=True,
    )

    strict_ecall_file = tdir / "strict_ready_dynamic_xr.txt"
    write_strict_file_from_ready(tdir, "dynamic_xr", strict_ecall_file)
    res_ho_strict_ecall = run_sample(
        sample,
        mode="dynamic_xr_final_aex0",
        ipi_mask=0,
        intervention=holdout_cfg["intervention"],
        strict_ready_file=str(strict_ecall_file),
        strict_mode="ecall",
        host_args=holdout_cfg["host_args"],
        allow_fast_forward=0,
        persist_prefix=raw_dir / "holdout_strict_ecall_readytable",
    )
    val_ho_strict_ecall = validate_run_result(
        res_ho_strict_ecall,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=holdout_cfg["min_records"],
        expected_tags=holdout_cfg["expected_tags"],
        require_strict_mode=1,
        require_zero_strict_faults=True,
    )

    prov_check = validate_provenance_consistency(
        ledger,
        [
            res_ho_obs,
            res_ho_strict_field,
            res_ho_strict_ecall,
            {"interpose_sha256": calibration["restored_interpose_sha256"]},
            {"interpose_sha256": tlb_and_fixture["cold_vs_warm_tlb_calibration"]["interpose_sha256"]},
        ],
        target_dir=tdir,
        variant="dynamic_xr",
    )

    per_field_holdout = {
        fid: {
            "field_entries": 0,
            "transport_ok_entries": 0,
            "abi_zero_or_void_ok_entries": 0,
            "abi_nonzero_or_out_err_entries": 0,
            "unexpected_transport_errors": 0,
            "missing_or_invalid_observations": 0,
            "observed_holdout_pages": set(),
            "unseen_pages_outside_field_target_pages": set(),
            "unseen_effects_outside_field_target_pages": set(),
        }
        for fid in closed_target_pages_by_fid
    }

    for rec in res_ho_obs["records"] + aux_obs_records:
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
            else:
                pf["transport_ok_entries"] += 1
                if rec.get("abi_return_type") == "void":
                    if rec.get("has_out_status_i32") and rec.get("out_status_i32") != 0:
                        pf["abi_nonzero_or_out_err_entries"] += 1
                    else:
                        pf["abi_zero_or_void_ok_entries"] += 1
                elif rec.get("ms_retval") == 0:
                    pf["abi_zero_or_void_ok_entries"] += 1
                else:
                    pf["abi_nonzero_or_out_err_entries"] += 1

            for item in fobs["s3"]:
                rva = int(item["rva"], 16)
                ad = item["ad"]
                pf["observed_holdout_pages"].add(rva)
                if rva not in closed_target_pages_by_fid[fid]:
                    pf["unseen_pages_outside_field_target_pages"].add(hex(rva))
                for eff in (("A", "D") if ad == "D" else ("A",)):
                    if (rva, eff) not in closed_target_effects_by_fid[fid]:
                        pf["unseen_effects_outside_field_target_pages"].add(f"{hex(rva)}:{eff}")

    per_field_holdout_json = {}
    for fid, pf in per_field_holdout.items():
        per_field_holdout_json[fid] = {
            "field_entries": pf["field_entries"],
            "transport_ok_entries": pf["transport_ok_entries"],
            "abi_zero_or_void_ok_entries": pf["abi_zero_or_void_ok_entries"],
            "abi_nonzero_or_out_err_entries": pf["abi_nonzero_or_out_err_entries"],
            "unexpected_transport_errors": pf["unexpected_transport_errors"],
            "missing_or_invalid_observations": pf["missing_or_invalid_observations"],
            "holdout_observed_pages_count": len(pf["observed_holdout_pages"]),
            "unseen_pages_outside_target_count": len(pf["unseen_pages_outside_field_target_pages"]),
            "unseen_pages_outside_target": sorted(pf["unseen_pages_outside_field_target_pages"]),
            "unseen_effects_outside_target_count": len(pf["unseen_effects_outside_field_target_pages"]),
            "unseen_effects_outside_target": sorted(pf["unseen_effects_outside_field_target_pages"]),
        }

    field_window_faults = sum(r["strict_non_ready_fault_count"] for r in res_ho_strict_field["records"])
    ecall_window_faults = sum(r["strict_non_ready_fault_count"] for r in res_ho_strict_ecall["records"])

    # Step 5: Three-Group Ablation across 5 Interleaved Rounds with explicit clean vs interrupt-contaminated separation
    perf_rounds = 5
    perf_h_args = load_target_manifest(sample).get("scenarios", {}).get("benchmark_host_args", [])
    groups = ("groupA_all_reg_xr", "groupB_dynamic_xr", "groupC_dynamic_refined")
    gate_ablation = {
        g: {
            fid: {
                "tsc_s2": [],
                "tsc_s3": [],
                "all_s3_rewalk": [],
                "clean_s3_rewalk": [],
                "contaminated_s3_rewalk": [],
                "clean_nonzero_details": [],
                "s3_missing_from_s2": [],
            }
            for fid in closed_target_pages_by_fid
        }
        for g in groups
    }
    prod_keys = ("raw_unprotected", "profile_no_pretouch") + groups
    prod_aex1_ecall_sum_ns = {g: [] for g in prod_keys}
    prod_aex1_seg = {
        g: {
            "cat3_total_ns": [],
            "cat3_acquire_ns": [],
            "cat3_body_ns": [],
            "cat3_release_ns": [],
            "cat2_early_ret_ns": [],
            "cat2_acquire_ns": [],
            "cat2_body_ns": [],
            "cat2_release_ns": [],
            "cat1_init_ns": [],
            "cat1_acquire_ns": [],
            "cat1_body_ns": [],
            "cat1_release_ns": [],
        }
        for g in prod_keys
    }
    prod_aex1_attempt_stats = {}
    ready_B_early = json.loads((tdir / "enclave.dynamic_xr.ready.json").read_text())
    full_sel_map = {s["ecall_index"]: set(s["page_rvas"]) for s in ready_B_early["selectors"] if s["page_rvas"]}
    field_entering_call_seqs: set[int] = set()
    first_4gate_records: list[dict] = []

    group_modes_4gate = [
        ("groupA_all_reg_xr", "all_reg_4gate"),
        ("groupB_dynamic_xr", "dynamic_xr_4gate"),
        ("groupC_dynamic_refined", "dynamic_4gate"),
    ]
    group_modes_prod_aex1 = [
        ("raw_unprotected", "raw_unprotected"),
        ("profile_no_pretouch", "profile_signed"),
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
            if not first_4gate_records:
                for rec in r4["records"]:
                    first_4gate_records.append(rec)
                    if rec["fields"]:
                        field_entering_call_seqs.add(rec["call_seq"])
            val_d4 = validate_diagnostic_4gate_run(
                r4,
                expected_field_ids=expected_fids,
                expected_ecall_seq=[r["ecall_index"] for r in first_4gate_records],
                expected_field_call_seqs=field_entering_call_seqs,
                require_ipi_mask=3,
            )
            if val_d4["status"] != "PASS":
                raise RuntimeError(f"4-Gate diagnostic validation failed on {sample} {gname} r{rnd}: {val_d4}")
            for rec in r4["records"]:
                for fobs in rec["fields"]:
                    fid = fobs["field_id"]
                    if fid not in gate_ablation[gname]:
                        continue
                    s2_set = {x["rva"] for x in fobs["s2"]}
                    s3_set = {x["rva"] for x in fobs["s3"]}
                    s3_aex = fobs.get("s3_active_aex_count", 0)
                    d = gate_ablation[gname][fid]
                    d["tsc_s2"].append(fobs["tsc_s2"])
                    d["tsc_s3"].append(fobs["tsc_s3"])
                    d["all_s3_rewalk"].append(len(s3_set))
                    d["s3_missing_from_s2"].append(len(s3_set - s2_set))
                    if s3_aex == 0:
                        d["clean_s3_rewalk"].append(len(s3_set))
                        if len(s3_set) > 0:
                            d["clean_nonzero_details"].append({
                                "round": rnd,
                                "call_seq": rec["call_seq"],
                                "s3_pages": sorted(s3_set),
                                "in_s2": len(s3_set & s2_set),
                                "missing_from_s2": len(s3_set - s2_set),
                            })
                    else:
                        d["contaminated_s3_rewalk"].append(len(s3_set))

    # Separate 4-gate diagnostic runs from production AEX1 performance benchmark, with 1 warmup round
    for _, pmode in group_modes_prod_aex1:
        run_sample(sample, mode=pmode, ipi_mask=0, host_args=perf_h_args, allow_fast_forward=0)

    expected_ecall_seq = [r["ecall_index"] for r in first_4gate_records]
    ready_sel_set = set(full_sel_map.keys())
    protected_groups = {"groupA_all_reg_xr", "groupB_dynamic_xr", "groupC_dynamic_refined"}

    for rnd in range(perf_rounds):
        for gname, pmode in group_modes_prod_aex1:
            for att in range(4):
                suffix = f"r{rnd}_{gname}" if att == 0 else f"r{rnd}_{gname}_retry{att}"
                rp = run_sample(
                    sample,
                    mode=pmode,
                    ipi_mask=0,
                    host_args=perf_h_args,
                    allow_fast_forward=0,
                    persist_prefix=raw_dir / f"ablation_prod_aex1_{suffix}",
                )
                prod_aex1_attempt_stats.setdefault(gname, {"total_attempts": 0, "clean_completed": 0, "interrupt_aborted_0x1006": 0, "other_failures": 0})
                prod_aex1_attempt_stats[gname]["total_attempts"] += 1
                val_prod = validate_production_run_result(
                    rp,
                    expected_stdout_substr="PASS",
                    expected_ecall_seq=expected_ecall_seq,
                    ready_sel_set=ready_sel_set,
                    require_readiness=(gname in protected_groups),
                )
                if val_prod["status"] == "PASS":
                    prod_aex1_attempt_stats[gname]["clean_completed"] += 1
                    prod_aex1_ecall_sum_ns[gname].append(sum(r["elapsed_ns"] for r in rp["records"]))
                    c3_tot = c3_acq = c3_bod = c3_rel = 0
                    c2_tot = c2_acq = c2_bod = c2_rel = 0
                    c1_tot = c1_acq = c1_bod = c1_rel = 0
                    for r in rp["records"]:
                        cseq = r["call_seq"]
                        eidx = r["ecall_index"]
                        has_rdy = eidx in full_sel_map
                        el = r.get("elapsed_ns", 0)
                        ac = r.get("acquire_ns", 0)
                        bd = r.get("encl_body_ns", el)
                        rl = r.get("release_ns", 0)
                        if cseq in field_entering_call_seqs:
                            c3_tot += el; c3_acq += ac; c3_bod += bd; c3_rel += rl
                        elif has_rdy:
                            c2_tot += el; c2_acq += ac; c2_bod += bd; c2_rel += rl
                        else:
                            c1_tot += el; c1_acq += ac; c1_bod += bd; c1_rel += rl
                    prod_aex1_seg[gname]["cat3_total_ns"].append(c3_tot)
                    prod_aex1_seg[gname]["cat3_acquire_ns"].append(c3_acq)
                    prod_aex1_seg[gname]["cat3_body_ns"].append(c3_bod)
                    prod_aex1_seg[gname]["cat3_release_ns"].append(c3_rel)
                    prod_aex1_seg[gname]["cat2_early_ret_ns"].append(c2_tot)
                    prod_aex1_seg[gname]["cat2_acquire_ns"].append(c2_acq)
                    prod_aex1_seg[gname]["cat2_body_ns"].append(c2_bod)
                    prod_aex1_seg[gname]["cat2_release_ns"].append(c2_rel)
                    prod_aex1_seg[gname]["cat1_init_ns"].append(c1_tot)
                    prod_aex1_seg[gname]["cat1_acquire_ns"].append(c1_acq)
                    prod_aex1_seg[gname]["cat1_body_ns"].append(c1_bod)
                    prod_aex1_seg[gname]["cat1_release_ns"].append(c1_rel)
                    break
                elif any(r.get("sgx_status") == 0x1006 for r in rp["records"]) and not rp.get("measurement_invalid", False):
                    prod_aex1_attempt_stats[gname]["interrupt_aborted_0x1006"] += 1
                else:
                    prod_aex1_attempt_stats[gname]["other_failures"] += 1
                    raise RuntimeError(f"Production validation failed on {sample} {gname} r{rnd}: {val_prod}")

    ablation_summary_by_field = {}
    for fid in closed_target_pages_by_fid:
        ablation_summary_by_field[fid] = {}
        for gname in groups:
            d = gate_ablation[gname][fid]
            total_att = len(d["all_s3_rewalk"])
            clean_cnt = len(d["clean_s3_rewalk"])
            contam_cnt = len(d["contaminated_s3_rewalk"])
            clean_zero_cnt = sum(1 for x in d["clean_s3_rewalk"] if x == 0)
            all_zero_cnt = sum(1 for x in d["all_s3_rewalk"] if x == 0)
            ablation_summary_by_field[fid][gname] = {
                "total_attempts": total_att,
                "clean_no_aex_count": clean_cnt,
                "interrupt_aex_contaminated_count": contam_cnt,
                "clean_zero_rewalk_count": clean_zero_cnt,
                "all_zero_rewalk_count": all_zero_cnt,
                "tsc_s2_ticks": dist_summary(d["tsc_s2"]),
                "tsc_s3_ticks": dist_summary(d["tsc_s3"]),
                "all_s3_ad_rewalk_pages": dist_summary(d["all_s3_rewalk"]),
                "clean_s3_ad_rewalk_pages": dist_summary(d["clean_s3_rewalk"]),
                "contaminated_s3_ad_rewalk_pages": dist_summary(d["contaminated_s3_rewalk"]),
                "clean_nonzero_rewalk_events": d["clean_nonzero_details"],
                "s3_missing_from_s2_pages_max": max(d["s3_missing_from_s2"]) if d["s3_missing_from_s2"] else 0,
            }

    pretouch_A = json.loads((tdir / "pretouch.all_reg.finalized.json").read_text())
    pretouch_B = json.loads((tdir / "pretouch.dynamic_xr.finalized.json").read_text())
    pretouch_C = json.loads((tdir / "pretouch.dynamic.finalized.json").read_text())
    ready_A = json.loads((tdir / "enclave.all_reg.ready.json").read_text())
    ready_B = json.loads((tdir / "enclave.dynamic_xr.ready.json").read_text())
    ready_C = json.loads((tdir / "enclave.dynamic.ready.json").read_text())

    all_validators_pass = bool(
        tlb_and_fixture["cold_vs_warm_tlb_calibration"]["cold_tlb_proven"]
        and tlb_and_fixture["four_gate_fixture_equivalence"]["ecall_status_sequence_identical"]
        and tlb_and_fixture["four_gate_fixture_equivalence"]["stdout_identical"]
        and calibration["calibration_valid"]
        and calibration["same_fault_point_aex0_vs_aex1"]["verdict"] == "PASS"
        and val_ho_obs["status"] == "PASS"
        and all(av["validation"]["status"] == "PASS" for av in aux_validations)
        and val_ho_strict_field["status"] == "PASS"
        and val_ho_strict_ecall["status"] == "PASS"
        and prov_check["status"] == "PASS"
        and all(
            prod_aex1_attempt_stats[g]["clean_completed"] == perf_rounds
            and prod_aex1_attempt_stats[g]["other_failures"] == 0
            for g in prod_keys
        )
        and all(
            ablation_summary_by_field[fid][gname]["clean_no_aex_count"] > 0
            for fid in closed_target_pages_by_fid
            for gname in groups
        )
    )
    overall_verdict = "PASS" if all_validators_pass else "FAIL_OR_INVALID"

    return {
        "sample": sample,
        "default_candidate_group": "groupB_dynamic_xr (RX pages kept as XR conservatively)",
        "provenance_consistency": prov_check,
        "tlb_and_fixture_validation": tlb_and_fixture,
        "fault_detector_calibration_and_aex_notify": calibration,
        "independent_holdout_evaluation": {
            "description": holdout_cfg["desc"],
            "intervention": holdout_cfg["intervention"],
            "host_args": holdout_cfg["host_args"],
            "main_holdout_returncode": res_ho_obs["returncode"],
            "main_holdout_stdout": res_ho_obs["stdout"],
            "records_evaluated": len(res_ho_obs["records"]) + len(aux_obs_records),
            "validator_main_holdout": val_ho_obs,
            "validator_aux_holdouts": aux_validations,
            "validator_strict_field_window": val_ho_strict_field,
            "validator_strict_ecall_window": val_ho_strict_ecall,
            "per_field_holdout": per_field_holdout_json,
            "strict_field_target_pages_window_gateB_to_gateD": {
                "mode": "ATFIELD_STRICT_MODE=field (Gate B..Gate D, Group B dynamic_xr)",
                "returncode": res_ho_strict_field["returncode"],
                "stdout": res_ho_strict_field["stdout"],
                "fault_count": field_window_faults,
                "measurement_invalid": res_ho_strict_field["measurement_invalid"],
            },
            "strict_readytable_v3_window_ecall": {
                "mode": "ATFIELD_STRICT_MODE=ecall (EENTER..EEXIT, Group B dynamic_xr)",
                "returncode": res_ho_strict_ecall["returncode"],
                "stdout": res_ho_strict_ecall["stdout"],
                "fault_count": ecall_window_faults,
                "measurement_invalid": res_ho_strict_ecall["measurement_invalid"],
            },
            "overall_holdout_and_strict_verdict": overall_verdict,
            "unseen_input_history_generalization": run_frozen_workset_generalization_suite(
                sample,
                tdir,
                raw_dir,
                expected_fids,
                closed_target_effects_by_fid,
                ready_sel_set,
            ),
            "sm4_two_tier_accounting": (
                evaluate_sm4_two_tier(
                    sample,
                    tdir,
                    raw_dir,
                    ledger,
                    expected_fids,
                    closed_target_effects_by_fid,
                )
                if load_target_manifest(sample).get("scenarios", {}).get("seeded_variants")
                else None
            ),
        },
        "three_group_ablation": {
            "interleaved_rounds": perf_rounds,
            "performance_host_args": perf_h_args,
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
            "production_aex1_attempt_accounting": prod_aex1_attempt_stats,
            "workflow_call_category_counts": {
                "cat3_field_entering_calls": len(field_entering_call_seqs),
                "cat2_early_return_ready_calls": sum(1 for r in first_4gate_records if r["call_seq"] not in field_entering_call_seqs and r["ecall_index"] in full_sel_map),
                "cat1_init_no_ready_calls": sum(1 for r in first_4gate_records if r["call_seq"] not in field_entering_call_seqs and r["ecall_index"] not in full_sel_map),
            },
            "production_aex1_segmented_breakdown_ns": {
                g: {k: dist_summary(v) for k, v in prod_aex1_seg[g].items()}
                for g in prod_keys
            },
            "production_aex1_per_round_ecall_sum_ns": {
                g: dist_summary(prod_aex1_ecall_sum_ns[g])
                for g in prod_keys
            },
            "binary_and_memory_size_comparison": {
                "raw_unprotected": {
                    "elf_file_bytes": (Path("/home/meandssh/islands-sgx/sample/build/real") / sample / "raw" / "enclave.signed.so").stat().st_size,
                    "pt_load_memsz_bytes": sum(int(l.split()[5], 16) for l in __import__("subprocess").check_output(["readelf", "-lW", str(Path("/home/meandssh/islands-sgx/sample/build/real") / sample / "raw" / "enclave.signed.so")], text=True).splitlines() if l.split() and l.split()[0] == "LOAD"),
                    "pretouch_code_bytes": 0,
                    "readytable_bytes": 0,
                },
                "groupA_all_reg_xr": {
                    "elf_file_bytes": (tdir / "enclave.all_reg.final.signed.so").stat().st_size,
                    "pt_load_memsz_bytes": sum(int(l.split()[5], 16) for l in __import__("subprocess").check_output(["readelf", "-lW", str(tdir / "enclave.all_reg.final.signed.so")], text=True).splitlines() if l.split() and l.split()[0] == "LOAD"),
                    "pretouch_code_bytes": pretouch_A["code_bytes"],
                    "readytable_bytes": ready_A["table_bytes"],
                },
                "groupB_dynamic_xr": {
                    "elf_file_bytes": (tdir / "enclave.dynamic_xr.final.signed.so").stat().st_size,
                    "pt_load_memsz_bytes": sum(int(l.split()[5], 16) for l in __import__("subprocess").check_output(["readelf", "-lW", str(tdir / "enclave.dynamic_xr.final.signed.so")], text=True).splitlines() if l.split() and l.split()[0] == "LOAD"),
                    "pretouch_code_bytes": pretouch_B["code_bytes"],
                    "readytable_bytes": ready_B["table_bytes"],
                },
                "groupC_dynamic_refined": {
                    "elf_file_bytes": (tdir / "enclave.dynamic.final.signed.so").stat().st_size,
                    "pt_load_memsz_bytes": sum(int(l.split()[5], 16) for l in __import__("subprocess").check_output(["readelf", "-lW", str(tdir / "enclave.dynamic.final.signed.so")], text=True).splitlines() if l.split() and l.split()[0] == "LOAD"),
                    "pretouch_code_bytes": pretouch_C["code_bytes"],
                    "readytable_bytes": ready_C["table_bytes"],
                },
            },
            "per_field_4gate_diagnostic_ablation": ablation_summary_by_field,
        },
        "closure_breakdown": ledger["closure_breakdown"],
    }


def main() -> None:
    import glob, subprocess
    no_turbo_p = Path("/sys/devices/system/cpu/intel_pstate/no_turbo")
    orig_no_turbo = no_turbo_p.read_text().strip() if no_turbo_p.exists() else None
    gov_paths = [Path(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")]
    orig_govs = {}
    for gp in gov_paths:
        try:
            orig_govs[gp] = gp.read_text().strip()
        except OSError:
            pass
    try:
        if no_turbo_p.exists():
            subprocess.run(["sudo", "sh", "-c", "echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo"], check=False)
        subprocess.run(["sudo", "sh", "-c", "for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > \"$f\" 2>/dev/null || true; done"], check=False)
        _run_main_body()
    finally:
        if orig_no_turbo is not None:
            subprocess.run(["sudo", "sh", "-c", f"echo {orig_no_turbo} > /sys/devices/system/cpu/intel_pstate/no_turbo"], check=False)
        for gp, val in orig_govs.items():
            subprocess.run(["sudo", "sh", "-c", f"echo {val} > {gp} 2>/dev/null || true"], check=False)


def _run_main_body() -> None:
    out_dir = DYN_ROOT / "experiments"
    out_dir.mkdir(parents=True, exist_ok=True)
    print("=== Running Known-Answer 7-Case Hardware Measurement Calibration Fixture ===", flush=True)
    cal_fixture_res = run_known_answer_measurement_calibration()
    print(f"  [Calibration Fixture] omission_rate={cal_fixture_res['measurement_omission_rate']} verdict={cal_fixture_res['verdict']}", flush=True)
    summary = {"_calibration_fixture": cal_fixture_res}
    for s in SAMPLES:
        print(f"=== Running Strict Hardware Evaluation for {s} ===", flush=True)
        summary[s] = evaluate_sample(s)
        ho = summary[s]["independent_holdout_evaluation"]
        cal = summary[s]["fault_detector_calibration_and_aex_notify"]
        prov = summary[s]["provenance_consistency"]
        print(
            f"  [Verdicts] prov={prov['status']} cal_valid={cal['calibration_valid']} "
            f"aex_notify={cal['same_fault_point_aex0_vs_aex1']['verdict']} "
            f"ho_obs={ho['validator_main_holdout']['status']} "
            f"ho_field={ho['validator_strict_field_window']['status']} "
            f"ho_ecall={ho['validator_strict_ecall_window']['status']} "
            f"overall={ho['overall_holdout_and_strict_verdict']}"
        )
    (out_dir / "evaluation_results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Wrote {out_dir / 'evaluation_results.json'}")

    manifest_entries = []
    raw_root = out_dir / "raw_traces"
    active_trace_dirs = ["calibration-fixture"] + list(SAMPLES) + [
        cdir.name for cdir in sorted((DYN_ROOT / "challenges").glob("challenge-*"))
    ]
    if raw_root.is_dir():
        for jf in sorted(p for s_name in active_trace_dirs if (raw_root / s_name).is_dir() for p in (raw_root / s_name).glob("*.jsonl")):
            manifest_entries.append({
                "rel_path": str(jf.relative_to(DYN_ROOT)),
                "sha256": sha256_path(jf),
                "bytes": jf.stat().st_size,
                "lines": sum(1 for _ in jf.open("rb")),
            })
        archive_path = out_dir / "latest_traces_archive.tar.gz"
        __import__("subprocess").run(
            ["tar", "-czf", str(archive_path), "-C", str(out_dir), "raw_traces"],
            check=True,
        )
        manifest_payload = {
            "archive_path": "experiments/latest_traces_archive.tar.gz",
            "archive_sha256": sha256_path(archive_path),
            "archive_bytes": archive_path.stat().st_size,
            "total_trace_files": len(manifest_entries),
            "traces": manifest_entries,
        }
        (out_dir / "traces_manifest.json").write_text(json.dumps(manifest_payload, indent=2) + "\n")


if __name__ == "__main__":
    main()
