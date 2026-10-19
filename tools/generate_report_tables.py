#!/usr/bin/env python3
"""Auto-generate markdown summary tables directly from evaluation_results.json and witness_ledger.json."""
from __future__ import annotations

import json
from pathlib import Path

DYN_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm"]


def short_fn(fn: str) -> str:
    for k in (
        "get_att_key_based_from_seal_key",
        "sabd_lookup_hash",
        "generate_sek_field",
        "set_sek_field",
        "generate_ecdsa_key_field",
        "get_public_ecdsa_key_field",
        "ecdsa_sign_field",
        "ehsm_generate_datakey",
        "ehsm_aes_gcm_encrypt",
        "ehsm_aes_gcm_decrypt",
        "ehsm_create_aes_key",
    ):
        if k in fn:
            return k
    return fn


def main() -> None:
    ev = json.loads((DYN_ROOT / "experiments" / "evaluation_results.json").read_text())
    manifest = json.loads((DYN_ROOT / "vendor" / "IMPLEMENT_UPSTREAM.json").read_text())
    provenance = ev.get("_provenance")
    if not isinstance(provenance, dict):
        raise SystemExit("Refusing to regenerate tables: evaluation_results.json has no source/artifact provenance.")
    if provenance.get("implementation_source_commit") != manifest["commit"]:
        raise SystemExit("Refusing to regenerate tables: evaluation results use a different implementation source commit.")
    saved_preflight = provenance.get("artifact_preflight")
    preflight_path = DYN_ROOT / "experiments" / "evaluation_preflight.json"
    if not isinstance(saved_preflight, dict) or not preflight_path.exists():
        raise SystemExit("Refusing to regenerate tables: current artifact preflight is missing.")
    current_preflight = json.loads(preflight_path.read_text())
    if current_preflight != saved_preflight or not all(v.get("valid") for v in current_preflight.values()):
        raise SystemExit("Refusing to regenerate tables: current artifacts do not match the successful evaluation preflight.")

    lines = []
    lines.append("# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)\n\n")
    lines.append("All tables in this document are **automatically generated** from `experiments/evaluation_results.json` and `witnesses/<sample>/witness_ledger.json` by `tools/generate_report_tables.py`.\n\n")
    lines.append("- Evaluation implementation source commit: " + provenance["implementation_source_commit"] + "; artifacts matched the recorded preflight.\n\n")
    lines.append("- Frozen initial prototype tag: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)\n\n")

    # Table 1: 4-Layer Discovery Attribution + Heuristic Assist Breakdown
    lines.append("## 1. Four-Layer Discovery Attribution & Heuristic Assist Breakdown (11 Fields)\n\n")
    lines.append("| Sample | Field | L0 First Call (`p / eff`) | L1 Full Host (`p / +p`) | L2 Generic Schema+`L*` on Seed (`p`) | L2 Added Beyond Full Host (`+p / +eff`) | L3 Domain Assist (`+p`) | Bridge + Heuristic Assist (`+p`) | Final `FieldTargetPages` | All-REG Baseline | Reduction |\n")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")

    for s in SAMPLES:
        cb_map = ev[s]["closure_breakdown"]
        for fid, cb in cb_map.items():
            fn = short_fn(cb["function"])
            fl = cb["four_layer_attribution"]
            l0 = fl["layer0_first_field_call"]
            l1 = fl["layer1_full_existing_host"]
            l2 = fl["layer2_generic_schema_explorer"]
            l3 = fl["layer3_domain_assisted"]
            assist_added = cb["final_field_target_pages"] - cb["dynamic_explored_obs_pages"]
            lines.append(
                f"| `{s}` | `{fn}` | {l0['pages']}p / {l0['page_effects']}e | "
                f"{l1['pages']}p (`+{l1['added_pages_over_layer0']}`) | "
                f"**{l2['independent_pages_from_minimal_seed']}p** | "
                f"**+{l2['added_pages_beyond_full_host_layer1']}p / +{l2['added_effects_beyond_full_host_layer1']}e** | "
                f"+{l3['added_pages_beyond_layer2']}p | +{assist_added}p | "
                f"**{cb['final_field_target_pages']}p** | {cb['all_business_reg_pages']}p | "
                f"**{cb['reduction_vs_all_reg_pct']}%** |\n"
            )

    # Table 2: P0 & P3 Calibration, Independent Hold-Out, and Strict Window Verification
    lines.append("\n## 2. Fault Detector Calibration, Same-Fault `AEX0/AEX1`, & Independent Hold-Out Verification\n\n")
    lines.append("| Sample | Cold TLB Cal (`ipi_mask=7` vs `0` S3 pages) | 4-Gate vs Uninstrumented Output Eq | Single-Page Retraction Caught (`X` / `R` / `W`) | Restored Pos-Ctrl Faults | Same-Fault `AEX0` vs `AEX1` (`active_flag=1`) | Hold-Out Unseen `(page, effect)` | Strict `FieldTargetPages` (`Gate B..D`) Faults | Strict `ReadyTable v3` (`ECALL`) Faults | Overall Verdict |\n")
    lines.append("|---|---|---|---|---:|---|---|---:|---:|---|\n")

    for s in SAMPLES:
        tf = ev[s]["tlb_and_fixture_validation"]
        tc = tf["cold_vs_warm_tlb_calibration"]
        fq = tf["four_gate_fixture_equivalence"]
        cal = ev[s]["fault_detector_calibration_and_aex_notify"]
        sp = cal["single_page_retraction_controls"]
        aex_cmp = cal["same_fault_point_aex0_vs_aex1"]
        ho = ev[s]["independent_holdout_evaluation"]
        unseen_p = sum(v["unseen_pages_outside_target_count"] for v in ho["per_field_holdout"].values())
        unseen_e = sum(v["unseen_effects_outside_target_count"] for v in ho["per_field_holdout"].values())
        lines.append(
            f"| `{s}` | {tc['cold_s3_pages_observed']}p vs {tc['warm_no_ipi_s3_pages_observed']}p (`proven={tc['cold_tlb_proven']}`) | "
            f"`{fq['ecall_status_sequence_identical'] and fq['stdout_identical']}` | "
            f"`{sp['X_code_page']['retracted_page_rva']}`:`{sp['X_code_page']['fault_caught']}`, "
            f"`{sp['R_rodata_page']['retracted_page_rva']}`:`{sp['R_rodata_page']['fault_caught']}`, "
            f"`{sp['W_data_page']['retracted_page_rva']}`:`{sp['W_data_page']['fault_caught']}` | "
            f"{cal['restored_positive_control_faults']} | "
            f"`{aex_cmp['fault_page_rva']}` -> **{aex_cmp['verdict']}** | "
            f"**{unseen_p}p / {unseen_e}e** | "
            f"**{ho['strict_field_target_pages_window_gateB_to_gateD']['fault_count']}** | "
            f"**{ho['strict_readytable_v3_window_ecall']['fault_count']}** | "
            f"**{ho['overall_holdout_and_strict_verdict']}** |\n"
        )

    # Table 3: P4 Three-Group Ablation (5 Interleaved Rounds)
    lines.append("\n## 3. Three-Group Ablation Across 5 Interleaved Rounds (4-Gate Diagnostic `AEX0` TSC Ticks & `S3` A/D Re-Walk Pages)\n\n")
    lines.append("- **Group A (`all_reg_xr`)**: All committed business REG pages, all RX pages kept as `XR` (`call C3` + `movb`).\n")
    lines.append("- **Group B (`dynamic_xr`)**: Reduced dynamic + heuristic-assist page set, keeping all RX pages conservatively as `XR`.\n")
    lines.append("- **Group C (`dynamic_refined`)**: Same page set as Group B, refining RX pages without `STT_OBJECT`/RIP-data references to `X`-only.\n\n")
    lines.append("| Sample | Field | Obs (`5` rounds) | `.atfield_pretouch` Bytes (`A / B / C`) | `S2` Pretouch Median TSC Ticks (`Group A` / `Group B` / `Group C`) | `S3` Residual A/D Re-Walk Pages Median (`Group A` / `Group B` / `Group C`) | `S3` Missing-from-`S2` Pages Max (`B / C`) |\n")
    lines.append("|---|---|---:|---|---:|---:|---:|\n")

    non_enclu_obs_total = 0
    non_enclu_zero_rewalk_B = 0
    non_enclu_zero_rewalk_C = 0
    ENCLU_FIELDS = {"get_att_key_based_from_seal_key", "generate_sek_field", "set_sek_field"}

    for s in SAMPLES:
        tga = ev[s]["three_group_ablation"]
        sz = tga["code_and_readytable_sizes"]
        sz_str = f"{sz['groupA_all_reg_xr']['pretouch_code_bytes']} / {sz['groupB_dynamic_xr']['pretouch_code_bytes']} / {sz['groupC_dynamic_refined']['pretouch_code_bytes']}"
        for fid, cb in ev[s]["closure_breakdown"].items():
            fn = short_fn(cb["function"])
            ab = tga["per_field_4gate_diagnostic_ablation"][fid]
            ga = ab["groupA_all_reg_xr"]
            gb = ab["groupB_dynamic_xr"]
            gc = ab["groupC_dynamic_refined"]
            obs_n = gc["observations"]
            if fn not in ENCLU_FIELDS:
                non_enclu_obs_total += obs_n
                if gb["s3_ad_rewalk_pages"]["max"] == 0:
                    non_enclu_zero_rewalk_B += obs_n
                if gc["s3_ad_rewalk_pages"]["max"] == 0:
                    non_enclu_zero_rewalk_C += obs_n
            lines.append(
                f"| `{s}` | `{fn}` | {obs_n} | {sz_str} | "
                f"{int(ga['tsc_s2_ticks']['median']):,} / **{int(gb['tsc_s2_ticks']['median']):,}** / **{int(gc['tsc_s2_ticks']['median']):,}** | "
                f"{ga['s3_ad_rewalk_pages']['median']} (max {int(ga['s3_ad_rewalk_pages']['max'])}) / "
                f"**{gb['s3_ad_rewalk_pages']['median']}** (max {int(gb['s3_ad_rewalk_pages']['max'])}) / "
                f"**{gc['s3_ad_rewalk_pages']['median']}** (max {int(gc['s3_ad_rewalk_pages']['max'])}) | "
                f"{gb['s3_missing_from_s2_pages_max']} / {gc['s3_missing_from_s2_pages_max']} |\n"
            )

    lines.append(f"\n- **Auto-summed non-`ENCLU` Field observations across 5 interleaved rounds**: **{non_enclu_obs_total}** total observations (Group B `S3=[]` in **{non_enclu_zero_rewalk_B}/{non_enclu_obs_total}**, Group C `S3=[]` in **{non_enclu_zero_rewalk_C}/{non_enclu_obs_total}**).\n")

    # Table 4: Production AEX1 Final Signed Enclave End-to-End Host Latency
    lines.append("\n## 4. Production `AEX1` Signed Final Enclave End-to-End ECALL Wall-Clock Latency (5 Interleaved Rounds, No 4-Gate Fixture)\n\n")
    lines.append("| Sample | Group A (`all_reg_xr`) Median / Min..Max (ms) | Group B (`dynamic_xr`) Median / Min..Max (ms) | Group C (`dynamic_refined`) Median / Min..Max (ms) | End-to-End Speedup (`Group B` vs `A` / `Group C` vs `A`) |\n")
    lines.append("|---|---:|---:|---:|---:|\n")
    for s in SAMPLES:
        pe = ev[s]["three_group_ablation"]["production_aex1_end_to_end_ecall_ns"]
        ga, gb, gc = pe["groupA_all_reg_xr"], pe["groupB_dynamic_xr"], pe["groupC_dynamic_refined"]
        sp_b = round(ga["median"] / gb["median"], 2) if gb["median"] else 1.0
        sp_c = round(ga["median"] / gc["median"], 2) if gc["median"] else 1.0
        lines.append(
            f"| `{s}` | {ga['median']/1e6:.2f} ms ({ga['min']/1e6:.2f}..{ga['max']/1e6:.2f}) | "
            f"**{gb['median']/1e6:.2f} ms** ({gb['min']/1e6:.2f}..{gb['max']/1e6:.2f}) | "
            f"**{gc['median']/1e6:.2f} ms** ({gc['min']/1e6:.2f}..{gc['max']/1e6:.2f}) | "
            f"**{sp_b}x** / **{sp_c}x** |\n"
        )

    lines.append("""
## 5. Clean-Checkout Reproducible Workflow

```bash
# 0. Verify that vendored implementation files match the pinned upstream commit
python3 tools/check_vendor_sync.py /path/to/implement

# 1. Build ProfileELFs, All-REG baselines, and signed AEX0/AEX1 artifacts
python3 tools/build_real_targets.py

# 2. Extract compiler-exact EDL marshaling layouts and parameter bindings
python3 tools/edl_harness.py

# 3. Compile native SGX page-table/AEP interposition library
gcc -shared -fPIC -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 \\
  -Ivendor/sgxstep src/native_sgx_interpose.c \\
  vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c vendor/sgxstep/libsgxstep/debug.c \\
  -ldl -lpthread -o build/libatfield_native_sgx.so

# 4. Run 4-layer dynamic exploration, archive witness ledgers + raw JSONL traces, and build Group B/C enclaves
python3 controller.py qe3 signal-cds sgxwallet ehsm

# 5. Run P0-P4 calibration, independent hold-out verification, and 5-round 3-group ablation
python3 tools/evaluate_worksets.py

# 6. Auto-generate summary tables from JSON evidence
python3 tools/generate_report_tables.py
```
""")

    md_text = "".join(lines)
    (DYN_ROOT / "README.md").write_text(md_text)
    (DYN_ROOT / "experiments" / "SUMMARY_TABLES.md").write_text(md_text)
    print(md_text)


if __name__ == "__main__":
    main()
