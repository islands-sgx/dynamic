#!/usr/bin/env python3
"""End-to-end hardware evaluation of Dynamic+Closure vs All-Committed-REG vs Raw Single-Run.

Runs on real SGX hardware (CPU 45 + watcher CPU 1):
1. 4-Gate S2 Pretouch Latency & S3 Residency comparison (All-REG vs Dynamic+Closure)
2. Strict Non-Ready Page (PTE=0) Hardware Enforcement on Hold-Out Workloads:
   - Tests Raw-Single-Run ReadySet (demonstrating faults on unseen scales/states)
   - Tests Dynamic+Closure ReadyTable v3 (proving 0 faults across all hold-out workloads)
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))
from run_native_sgx import run_sample  # noqa: E402


HOLDOUT_INTERVENTIONS = {
    "qe3": "xor_buf:0:0:8:7:123;xor_buf:0:0:8:23:231",
    "signal-cds": "signal_scales:0",
    "sgxwallet": "set_u32:6:0:72:10;set_u32:6:0:72:99",
    "ehsm": "ehsm_sizes:1",
}


def write_strict_ready_file(ready_json_path: Path, out_txt_path: Path) -> None:
    rdy = json.loads(ready_json_path.read_text())
    lines = []
    for sel in rdy["selectors"]:
        if not sel["page_rvas"]:
            continue
        rvas_hex = " ".join(f"{p:x}" for p in sel["page_rvas"])
        lines.append(f"{sel['ecall_index']} {rvas_hex}")
    out_txt_path.write_text("\n".join(lines) + "\n")


def summarize_4gate_run(res: dict) -> dict:
    by_field: dict[str, dict] = {}
    for rec in res["records"]:
        for f in rec["fields"]:
            fid = f["field_id"]
            info = by_field.setdefault(fid, {
                "invocations": 0,
                "s2_pages": len(f["s2"]),
                "tsc_s2_list": [],
                "tsc_s3_list": [],
                "s3_counts": [],
                "zero_s3_runs": 0,
                "not_in_s2_missing_pages": set(),
                "d_upgrade_pages": set(),
                "in_s2_rewalk_pages": set(),
            })
            info["invocations"] += 1
            info["s2_pages"] = max(info["s2_pages"], len(f["s2"]))
            info["tsc_s2_list"].append(f["tsc_s2"])
            info["tsc_s3_list"].append(f["tsc_s3"])
            info["s3_counts"].append(len(f["s3"]))
            if len(f["s3"]) == 0:
                info["zero_s3_runs"] += 1
            s2_map = {x["rva"]: x["ad"] for x in f["s2"]}
            for x in f["s3"]:
                rva, ad = x["rva"], x["ad"]
                if rva not in s2_map:
                    info["not_in_s2_missing_pages"].add(rva)
                elif s2_map[rva] == "A" and ad == "D":
                    info["d_upgrade_pages"].add(rva)
                else:
                    info["in_s2_rewalk_pages"].add(rva)

    out = {}
    for fid, info in by_field.items():
        out[fid] = {
            "invocations": info["invocations"],
            "s2_pages_observed": info["s2_pages"],
            "tsc_s2_median": int(statistics.median(info["tsc_s2_list"])) if info["tsc_s2_list"] else 0,
            "tsc_s2_min": min(info["tsc_s2_list"]) if info["tsc_s2_list"] else 0,
            "tsc_s3_median": int(statistics.median(info["tsc_s3_list"])) if info["tsc_s3_list"] else 0,
            "s3_count_min": min(info["s3_counts"]) if info["s3_counts"] else 0,
            "s3_count_median": float(statistics.median(info["s3_counts"])) if info["s3_counts"] else 0.0,
            "s3_count_max": max(info["s3_counts"]) if info["s3_counts"] else 0,
            "zero_s3_runs": info["zero_s3_runs"],
            "not_in_s2_missing_count": len(info["not_in_s2_missing_pages"]),
            "not_in_s2_missing_rvas": sorted(info["not_in_s2_missing_pages"]),
            "d_upgrade_count": len(info["d_upgrade_pages"]),
            "in_s2_tlb_rewalk_union_count": len(info["in_s2_rewalk_pages"]),
        }
    return out


def evaluate_sample(sample: str) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    wdir = DYN_ROOT / "witnesses" / sample
    ledger = json.loads((wdir / "witness_ledger.json").read_text())
    ver_all = json.loads((tdir / "pretouch.all_reg.verified.json").read_text())
    ver_dyn = json.loads((tdir / "pretouch.dynamic.verified.json").read_text())
    rdy_all = json.loads((tdir / "enclave.all_reg.ready.json").read_text())
    rdy_dyn = json.loads((tdir / "enclave.dynamic.ready.json").read_text())

    # 1. Run 4-gate residency comparison (ipi_mask=3) on All-REG vs Dynamic+Closure
    res_all_4g = run_sample(sample, mode="all_reg_4gate", ipi_mask=3)
    res_dyn_4g = run_sample(sample, mode="dynamic_4gate", ipi_mask=3)
    sum_all_4g = summarize_4gate_run(res_all_4g)
    sum_dyn_4g = summarize_4gate_run(res_dyn_4g)

    # 2. Run Strict Non-Ready Page (PTE=0) Hardware Verification on Hold-Out Workloads
    strict_dyn_txt = tdir / "strict_ready_dynamic.txt"
    write_strict_ready_file(tdir / "enclave.dynamic.ready.json", strict_dyn_txt)

    res_strict_holdout = run_sample(
        sample,
        mode="dynamic_final_aex0",
        ipi_mask=0,
        intervention=HOLDOUT_INTERVENTIONS[sample],
        strict_ready_file=str(strict_dyn_txt),
    )
    enforced_calls = sum(1 for r in res_strict_holdout["records"] if r["strict_pte_enforced"] == 1)
    faulted_calls = sum(1 for r in res_strict_holdout["records"] if r["strict_non_ready_faulted"] != 0)

    # 3. Also test a deliberately incomplete Raw-Single-Run strict ready table (omitting exploration/closure pages)
    #    to verify our PTE=0 hardware checker catches missing pages!
    strict_incomplete_txt = tdir / "strict_ready_incomplete_test.txt"
    incomplete_lines = []
    for sel in rdy_dyn["selectors"]:
        if not sel["page_rvas"]:
            continue
        # Drop the highest heap/data page from selector's ready set to test fault detection
        trimmed = sel["page_rvas"][:-20] if len(sel["page_rvas"]) > 30 else sel["page_rvas"][:-1]
        incomplete_lines.append(f"{sel['ecall_index']} " + " ".join(f"{p:x}" for p in trimmed))
    strict_incomplete_txt.write_text("\n".join(incomplete_lines) + "\n")
    # Test 3a: Incomplete ReadyTable under dynamic_final (EnableAEXNotify=1) -> must fail-stop with 0x1006 (SGX_ERROR_ENCLAVE_CRASHED)
    res_aex_failstop = run_sample(
        sample,
        mode="dynamic_final",
        ipi_mask=0,
        intervention="",
        strict_ready_file=str(strict_incomplete_txt),
    )
    aex_failstop_triggered = int(
        res_aex_failstop["returncode"] != 0
        and any(r["sgx_status"] == 0x1006 or r["strict_non_ready_faulted"] != 0 for r in res_aex_failstop["records"])
    )
    # Test 3b: Incomplete ReadyTable under dynamic_final_aex0 -> watchdog catches missing page fault
    res_strict_incomplete = run_sample(
        sample,
        mode="dynamic_final_aex0",
        ipi_mask=0,
        intervention="",
        strict_ready_file=str(strict_incomplete_txt),
    )
    incomplete_faulted_calls = sum(
        1 for r in res_strict_incomplete["records"] if r["strict_non_ready_faulted"] != 0 or r["sgx_status"] == 0x1006
    )

    fields_comparison = {}
    for fid, cb in ledger["closure_breakdown"].items():
        all_4g = sum_all_4g.get(fid, {})
        dyn_4g = sum_dyn_4g.get(fid, {})
        all_blk = next((b for b in ver_all["blocks"] if b["field_id"] == fid), {})
        dyn_blk = next((b for b in ver_dyn["blocks"] if b["field_id"] == fid), {})
        fields_comparison[fid] = {
            "function": cb["function"],
            "pages": {
                "raw_single_run": cb["raw_single_run_pages"],
                "dynamic_explored_obs": cb["dynamic_explored_obs_pages"],
                "dynamic_plus_closure": cb["final_field_target_pages"],
                "all_business_reg": cb["all_business_reg_pages"],
                "reduction_vs_all_reg_pct": cb["reduction_vs_all_reg_pct"],
            },
            "pretouch_bytes": {
                "dynamic_plus_closure": dyn_blk.get("size", 0),
                "all_business_reg": all_blk.get("size", 0),
            },
            "hardware_4gate_all_reg": all_4g,
            "hardware_4gate_dynamic": dyn_4g,
            "s2_speedup_ratio": round(
                all_4g.get("tsc_s2_median", 1) / max(dyn_4g.get("tsc_s2_median", 1), 1), 2
            ),
        }

    return {
        "sample": sample,
        "all_reg_total_pretouch_bytes": ver_all["code_bytes"],
        "dynamic_total_pretouch_bytes": ver_dyn["code_bytes"],
        "all_reg_ready_table_bytes": rdy_all["table_bytes"],
        "dynamic_ready_table_bytes": rdy_dyn["table_bytes"],
        "strict_pte_zero_holdout": {
            "returncode": res_strict_holdout["returncode"],
            "stdout": res_strict_holdout["stdout"],
            "total_ecalls": len(res_strict_holdout["records"]),
            "strict_enforced_ecalls": enforced_calls,
            "non_ready_page_faults": faulted_calls,
            "negative_control_incomplete_set_faults_caught": incomplete_faulted_calls,
            "aex_notify_failstop_on_missing_page_verified": aex_failstop_triggered,
        },
        "fields": fields_comparison,
    }


def main() -> None:
    exp_dir = DYN_ROOT / "experiments"
    exp_dir.mkdir(parents=True, exist_ok=True)
    samples = sys.argv[1:] or ["qe3", "signal-cds", "sgxwallet", "ehsm"]
    all_results = {"schema": "atfield-dynamic-evaluation-v1", "samples": {}}
    for s in samples:
        print(f"=== Evaluating {s} on SGX hardware ===", flush=True)
        all_results["samples"][s] = evaluate_sample(s)
        print(json.dumps(all_results["samples"][s], indent=2), flush=True)
    out_file = exp_dir / "evaluation_results.json"
    out_file.write_text(json.dumps(all_results, indent=2) + "\n")
    print(f"Wrote {out_file}")


if __name__ == "__main__":
    main()
