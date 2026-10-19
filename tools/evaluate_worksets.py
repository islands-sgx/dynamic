#!/usr/bin/env python3
"""Strict Hardware Evaluation for ATField-SGX Dynamic Worksets (Steps 4 & 5)."""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from acceptance_validator import (  # noqa: E402
    sha256_path,
    validate_diagnostic_4gate_run,
    validate_production_run_result,
    validate_provenance_consistency,
    validate_run_result,
)
from run_native_sgx import run_sample  # noqa: E402

SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm", "ehsm-opt-1", "ehsm-opt-2"]

# Hold-out suites:
# - Uses schema-typed primitives (xor_param, set_scalar, scale_bound_v2, typed_state_probe).
# - For sgxwallet, ecall 3 (trustedSetSEK) is a CALL_ONCE function; its negative bit-flip test is run in a
#   dedicated auxiliary hold-out invocation with stop_before_normal_ecall="3:0" so the main 1005-request
#   hold-out workflow completes all 1005 signatures + SEK reload cleanly with returncode=0 and stdout="PASS".
HOLDOUT_SUITES = {
    "qe3": {
        "expected_tags": {"schema_xor_p0_byte_3", "schema_xor_p0_byte_11", "schema_xor_p0_byte_19", "schema_xor_p0_byte_27"},
        "intervention": "xor_param:0:0:0:3:90;xor_param:0:0:0:11:165;xor_param:0:0:0:19:60;xor_param:0:0:0:27:195",
        "host_args": [],
        "min_records": 7,
        "aux_runs": [],
        "desc": "Disjoint key_id byte positions {3, 11, 19, 27} and masks {0x5a, 0xa5, 0x3c, 0xc3}",
    },
    "signal-cds": {
        "expected_tags": {"schema_scale_cnt_384_q_96_m_0", "schema_scale_cnt_3072_q_384_m_1", "schema_scale_cnt_12288_q_512_m_2", "schema_scale_cnt_49152_q_512_m_0", "schema_scale_cnt_131072_q_512_m_1"},
        "intervention": (
            "scale_bound_v2:0:0:0:16:384:32:96;"
            "scale_bound_v2:0:0:1:16:3072:32:384;"
            "scale_bound_v2:0:0:2:16:12288:32:512;"
            "scale_bound_v2:0:0:0:16:49152:32:512;"
            "scale_bound_v2:0:0:1:16:131072:32:512"
        ),
        "host_args": [],
        "min_records": 11,
        "aux_runs": [],
        "desc": "Disjoint record scales {384, 3072, 12288, 49152, 131072} and query counts {96, 384, 512}",
    },
    "sgxwallet": {
        "expected_tags": {"schema_xor_p4_byte_0", "schema_scalar_p8_val_37", "schema_xor_p2_byte_7"},
        "intervention": "xor_param:6:500:4:0:1;xor_param:6:999:4:0:1;set_scalar:6:2:8:37;xor_param:5:0:2:7:127",
        "host_args": ["--requests", "1005"],
        "min_records": 1020,
        "aux_runs": [
            {
                "name": "call_once_set_sek_bitflip",
                "expected_tags": {"schema_xor_p2_byte_45"},
                "intervention": "xor_param:3:0:2:45:127",
                "stop_before_normal_ecall": "3:0",
                "host_args": ["--requests", "1"],
                "min_records": 10,
                "expected_stdout_substr": "",
            }
        ],
        "desc": "Full 1005-request host workflow (0 skipped, rc=0, PASS) + disjoint hash/base=37/byte-7 mutations + isolated CALL_ONCE SetSEK byte-45 probe",
    },
    "ehsm": {
        "expected_tags": {"cold_state_replay_ecall_2_after_0_1", "cold_state_replay_ecall_4_after_0_1", "schema_xor_p4_byte_9"},
        "intervention": "typed_state_probe:2:1:0:1;typed_state_probe:4:1:0:1;xor_param:3:1:4:9:127",
        "host_args": ["--bytes", "1536", "--requests", "3"],
        "min_records": 39,
        "aux_runs": [],
        "desc": "Original 2-step eHSM (--bytes 1536 --requests 3) + cold-enclave state replay on encrypt & generate_datakey + ciphertext byte-9 bit-flip",
    },
    "ehsm-opt-1": {
        "expected_tags": {"cold_state_replay_ecall_2_after_0_1", "cold_state_replay_ecall_4_after_0_1", "schema_xor_p4_byte_9"},
        "intervention": "typed_state_probe:2:0:0:1;typed_state_probe:4:0:0:1;xor_param:3:0:4:9:127",
        "host_args": ["--bytes", "1536", "--requests", "3"],
        "min_records": 20,
        "aux_runs": [
            {
                "name": "compat_query_and_capacity_matrix",
                "expected_tags": None,
                "intervention": "",
                "stop_before_normal_ecall": "",
                "host_args": ["--compat-check"],
                "min_records": 23,
                "expected_stdout_substr": "PASS",
            }
        ],
        "desc": "Direct-sizing eHSM-opt-1 (--bytes 1536 --requests 3 + --compat-check query/capacity/canary/SM4 matrix) + cold-enclave state replay + byte-9 bit-flip",
    },
    "ehsm-opt-2": {
        "expected_tags": {"cold_state_replay_ecall_2_after_0_1", "cold_state_replay_ecall_4_after_0_1", "schema_xor_p4_byte_9"},
        "intervention": "typed_state_probe:2:0:0:1;typed_state_probe:4:0:0:1;xor_param:3:0:4:9:127",
        "host_args": ["--bytes", "1536", "--requests", "3"],
        "min_records": 20,
        "aux_runs": [
            {
                "name": "compat_query_and_capacity_matrix",
                "expected_tags": None,
                "intervention": "",
                "stop_before_normal_ecall": "",
                "host_args": ["--compat-check"],
                "min_records": 23,
                "expected_stdout_substr": "PASS",
            }
        ],
        "desc": "Eager-OpenSSL-init eHSM-opt-2 (--bytes 1536 --requests 3 + --compat-check query/capacity/canary/SM4 matrix) + cold-enclave state replay + byte-9 bit-flip",
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
    h_args = ["--requests", "1"] if sample == "sgxwallet" else []
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
    h_args = ["--requests", "1"] if sample == "sgxwallet" else []
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


def evaluate_sample(sample: str) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    wdir = DYN_ROOT / "witnesses" / sample
    raw_dir = DYN_ROOT / "experiments" / "raw_traces" / sample
    raw_dir.mkdir(parents=True, exist_ok=True)

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
    holdout_cfg = HOLDOUT_SUITES[sample]
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
    perf_h_args = ["--requests", "5"] if sample == "sgxwallet" else []
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
        calibration["calibration_valid"]
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
            "sm4_two_tier_accounting": (
                (lambda r_sm4: (
                    (lambda tier1_effects: {
                        "tier1_sm4_seeded_coverage": {
                            "description": "Tier 1 (Seed Coverage): Legal --sm4-check workflow included as seed; verifies full producer-consumer capture & closure.",
                            "seed_added_effects_count": sum(len(tier1_effects[fid] - closed_target_effects_by_fid[fid]) for fid in tier1_effects),
                            "validator_result": validate_run_result(
                                r_sm4,
                                expected_returncode=0,
                                expected_stdout_substr="PASS",
                                expected_min_records=21,
                                closed_workset_effects=tier1_effects,
                            ),
                        },
                        "tier2_aes_only_seed_discovery": {
                            "description": "Tier 2 (Un-Seeded Discovery from AES-Only Workflow): Tests whether generic explorer reaches SM4 without an SM4 seed.",
                            "structural_limitation": "ehsm_create_sm4_key requires coupled 3-field struct changes inside ehsm_keyblob_t (metadata.keyspec=20, keybloblen=64, cmk_size=80) before domain-key AES-GCM sealing.",
                            "validator_result": validate_run_result(
                                r_sm4,
                                expected_returncode=0,
                                expected_stdout_substr="PASS",
                                expected_min_records=21,
                                closed_workset_effects=closed_target_effects_by_fid,
                            ),
                        },
                    })({
                        fid: set(closed_target_effects_by_fid[fid]) | {
                            (int(it["rva"], 16), "A")
                            for rec in r_sm4["records"]
                            for fobs in rec["fields"]
                            if fobs["field_id"] == fid
                            for it in fobs["s3"]
                        } | {
                            (int(it["rva"], 16), "D")
                            for rec in r_sm4["records"]
                            for fobs in rec["fields"]
                            if fobs["field_id"] == fid
                            for it in fobs["s3"]
                            if it["ad"] == "D"
                        }
                        for fid in closed_target_effects_by_fid
                    })
                ))(
                    run_sample(
                        sample,
                        mode="profile_4gate",
                        ipi_mask=7,
                        host_args=["--sm4-check"],
                        allow_fast_forward=0,
                        persist_prefix=raw_dir / "holdout_out_of_seed_sm4_audit",
                    )
                )
                if sample in ("ehsm-opt-1", "ehsm-opt-2")
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
    summary = {}
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
    if raw_root.is_dir():
        for jf in sorted(raw_root.rglob("*.jsonl")):
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
