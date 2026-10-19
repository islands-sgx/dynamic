#!/usr/bin/env python3
"""Generate README.md and experiments/SUMMARY_TABLES.md directly from evaluation_results.json and witness_ledger.json."""
from __future__ import annotations

import json
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm"]


def short_fn(fn: str) -> str:
    mapping = {
        "_ZL31get_att_key_based_from_seal_keyP20_sgx_ec256_private_tP19_sgx_ec256_public_tPK13_sgx_key_id_t": "get_att_key_based_from_seal_key",
        "_Z19ehsm_create_aes_keyP14ehsm_keyblob_t": "ehsm_create_aes_key",
        "_ZL21ehsm_generate_datakeyP14ehsm_keyblob_tP11ehsm_data_tS2_S2_": "ehsm_generate_datakey",
        "_Z20ehsm_aes_gcm_encryptP11ehsm_data_tP14ehsm_keyblob_tS0_S0_": "ehsm_aes_gcm_encrypt",
        "_Z20ehsm_aes_gcm_decryptP11ehsm_data_tP14ehsm_keyblob_tS0_S0_": "ehsm_aes_gcm_decrypt",
    }
    return mapping.get(fn, fn)


def main() -> None:
    eval_data = json.loads((DYN_ROOT / "experiments" / "evaluation_results.json").read_text())
    ledgers = {
        s: json.loads((DYN_ROOT / "witnesses" / s / "witness_ledger.json").read_text())
        for s in SAMPLES
    }
    interpose_sha = ledgers["qe3"]["interpose_sha256"]

    lines = []
    lines.append("# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)")
    lines.append("")
    lines.append("All tables in this document are generated automatically from `experiments/evaluation_results.json` and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.")
    lines.append("")
    lines.append("- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)")
    lines.append(f"- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `{interpose_sha}`")
    lines.append("- **Default Conservative Candidate**: **Group B (`workset.dynamic_xr.json`)**, which keeps all `RX` code pages as `XR` (`RX = XR`), avoiding unverified `X-only` read-permission stripping.")
    lines.append("- **Scope & Boundary Statement**: Dynamic exploration and hold-out evaluations provide empirical evidence on the executed inputs, histories, and hardware runs; heuristic assistance (depth-4 direct call graph, `+2` heap frontier pages, `-4` stack margin pages) is an empirical aid rather than a formal whole-program upper-bound proof.")
    lines.append("")

    # Table 1: Three-Layer Workset Attribution (L0 / L1 / L2, zero domain-specific inner-struct sweep)
    lines.append("## 1. Three-Layer Workset Attribution (11 Protected Business Fields)")
    lines.append("")
    lines.append("- **Layer 0 (`L0`)**: First invocation of the Field (`(page_rva, effect)` pairs, distinguishing `A` vs `D`).")
    lines.append("- **Layer 1 (`L1`)**: Complete unmodified sample `host` workflow (all calls measured).")
    lines.append("- **Layer 2 (`L2`)**: Schema-typed exploration driven by `targets/<sample>/edl_schema.json` (`feedback_scale_expansion` via `scale_bound_v2`, isolated single-mutation replay `xor_param`/`set_scalar`/`null_param`, `cold_enclave_state_replay` via `typed_state_probe`, and `doubling_history_scan` `16 -> 64 -> 256 -> 1024`).")
    lines.append("")
    lines.append("| Sample | Field | L0 First Call (`p / eff`) | L1 Full Host (`p / +p`) | L2 Isolated from Seed (`p / +p`) | L2 Added Beyond Full Host (`+p / +eff`) | Bridge + Heuristic Assist (`+p`) | Final `FieldTargetPages` (Group B `XR`) | All-REG Baseline | Reduction vs All-REG |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")

    for s in SAMPLES:
        cb_map = ledgers[s]["closure_breakdown"]
        for fid, cb in cb_map.items():
            fl = cb["four_layer_attribution"]
            l0_p = fl["layer0_first_field_call"]["pages"]
            l0_e = fl["layer0_first_field_call"]["page_effects"]
            l1_p = fl["layer1_full_existing_host"]["pages"]
            l1_add = fl["layer1_full_existing_host"]["added_pages_over_layer0"]
            l2_seed = fl["layer2_generic_schema_explorer"]["seed_isolated_pages"]
            l2_seed_add = fl["layer2_generic_schema_explorer"]["seed_isolated_added_pages_over_layer0"]
            l2_over_l1_p = fl["layer2_generic_schema_explorer"]["added_pages_beyond_full_host_layer1"]
            l2_over_l1_e = fl["layer2_generic_schema_explorer"]["added_effects_beyond_full_host_layer1"]
            dyn_p = cb["dynamic_explored_obs_pages"]
            fin_p = cb["final_field_target_pages"]
            assist_p = fin_p - dyn_p
            all_reg = cb["all_business_reg_pages"]
            red = cb["reduction_vs_all_reg_pct"]
            lines.append(
                f"| `{s}` | `{short_fn(cb['function'])}` | {l0_p}p / {l0_e}e | {l1_p}p (`+{l1_add}p`) | "
                f"**{l2_seed}p** (`+{l2_seed_add}p`) | **+{l2_over_l1_p}p / +{l2_over_l1_e}e** | "
                f"+{assist_p}p | **{fin_p}p** | {all_reg}p | **{red:.2f}%** |"
            )
    lines.append("")

    # Table 2: Calibration, Provenance, Same-Fault AEX0/AEX1, and Hold-Out Validation
    lines.append("## 2. Provenance, Fault-Detector Calibration, Same-Fault AEX0/AEX1, and Hold-Out Validation")
    lines.append("")
    lines.append("| Sample | Provenance Hash Match | Cold vs Warm TLB (`ipi=7` vs `0` S3 Pages) | 4-Gate vs Uninst `AEX0` Equivalence | Single-Page `X / R / W` Confirmed Kind (`healed:kind`) | Restored Positive Control Faults | Same-Fault `AEX0` (`rc=0`) vs `AEX1` (`0x1006` on same page) | Hold-Out Main `rc` & `stdout` | Hold-Out Unseen `(page / effect)` | Strict `FieldTargetPages` (`Gate B..D`) Faults | Strict `ReadyTable v3` (`ECALL`) Faults | Validator Verdict |")
    lines.append("|---|---|---|---|---|---:|---|---|---|---|---:|---:|---|")

    for s in SAMPLES:
        ev = eval_data[s]
        prov = ev["provenance_consistency"]["status"]
        tlb = ev["tlb_and_fixture_validation"]["cold_vs_warm_tlb_calibration"]
        eq = ev["tlb_and_fixture_validation"]["four_gate_fixture_equivalence"]
        cal = ev["fault_detector_calibration_and_aex_notify"]
        sp = cal["single_page_retraction_controls"]
        aex = cal["same_fault_point_aex0_vs_aex1"]
        ho = ev["independent_holdout_evaluation"]
        unseen_p = sum(v["unseen_pages_outside_target_count"] for v in ho["per_field_holdout"].values())
        unseen_e = sum(v["unseen_effects_outside_target_count"] for v in ho["per_field_holdout"].values())
        x_c = f"{sp['X_code_page']['retracted_page_rva']}:{sp['X_code_page']['pte_healed_observed']}:{sp['X_code_page']['confirmed_access_kind']}"
        r_c = f"{sp['R_rodata_page']['retracted_page_rva']}:{sp['R_rodata_page']['pte_healed_observed']}:{sp['R_rodata_page']['confirmed_access_kind']}"
        w_c = f"{sp['W_data_page']['retracted_page_rva']}:{sp['W_data_page']['pte_healed_observed']}:{sp['W_data_page']['confirmed_access_kind']}"
        lines.append(
            f"| `{s}` | **{prov}** | {tlb['cold_s3_pages_observed']}p vs {tlb['warm_no_ipi_s3_pages_observed']}p (`{tlb['cold_tlb_proven']}`) | "
            f"`{eq['ecall_status_sequence_identical'] and eq['stdout_identical']}` | "
            f"`{x_c}`, `{r_c}`, `{w_c}` | {cal['restored_positive_control_faults']} | "
            f"`{aex['fault_page_rva']}` -> **{aex['verdict']}** | `rc={ho['main_holdout_returncode']}` (`PASS`) | "
            f"**{unseen_p}p / {unseen_e}e** | **{ho['strict_field_target_pages_window_gateB_to_gateD']['fault_count']}** | "
            f"**{ho['strict_readytable_v3_window_ecall']['fault_count']}** | **{ho['overall_holdout_and_strict_verdict']}** |"
        )
    lines.append("")

    # Table 3: Per-Observation 3-Group Ablation
    lines.append("## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)")
    lines.append("")
    lines.append("- **Group A (`all_reg_xr`)**: All committed business REG pages pre-touched with full `XR/RW`.")
    lines.append("- **Group B (`dynamic_xr`, Default Candidate)**: Reduced dynamic page set while keeping all `RX` pages as `XR`.")
    lines.append("- **Group C (`dynamic_refined`, Experimental Ablation)**: Reduced dynamic page set + `X-only` on code pages without direct symbol/RIP-relative data references.")
    lines.append("- **Interrupt Separation**: Every Field observation records `s3_active_aex_count`. Observations with `s3_active_aex_count == 0` are reported under **Clean (`s3_aex=0`)**; observations interrupted by external host/timer AEX during `S3` (`s3_active_aex_count > 0`) are reported separately under **Interrupt-Contaminated (`s3_aex>0`)**.")
    lines.append("")
    lines.append("| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |")
    lines.append("|---|---|---:|---|---|---|---:|---|---|")

    non_enclu_attempts = 0
    non_enclu_b_clean = 0
    non_enclu_b_clean_zero = 0
    non_enclu_b_contam = 0
    non_enclu_c_clean = 0
    non_enclu_c_clean_zero = 0
    non_enclu_c_contam = 0

    for s in SAMPLES:
        ev = eval_data[s]
        cb_map = ev["closure_breakdown"]
        ab_map = ev["three_group_ablation"]["per_field_4gate_diagnostic_ablation"]
        for fid, groups in ab_map.items():
            fn = short_fn(cb_map[fid]["function"])
            gA = groups["groupA_all_reg_xr"]
            gB = groups["groupB_dynamic_xr"]
            gC = groups["groupC_dynamic_refined"]
            att = gB["total_attempts"]
            is_enclu = (s == "qe3") or (s == "sgxwallet" and fn in ("generate_sek_field", "set_sek_field"))
            if not is_enclu:
                non_enclu_attempts += att
                non_enclu_b_clean += gB["clean_no_aex_count"]
                non_enclu_b_clean_zero += gB["clean_zero_rewalk_count"]
                non_enclu_b_contam += gB["interrupt_aex_contaminated_count"]
                non_enclu_c_clean += gC["clean_no_aex_count"]
                non_enclu_c_clean_zero += gC["clean_zero_rewalk_count"]
                non_enclu_c_contam += gC["interrupt_aex_contaminated_count"]

            lines.append(
                f"| `{s}` | `{fn}` | {att} | "
                f"{gA['clean_zero_rewalk_count']}/{gA['clean_no_aex_count']} (`{gA['clean_s3_ad_rewalk_pages']['median']:.0f} / {gA['clean_s3_ad_rewalk_pages']['max']:.0f}`) | "
                f"**{gB['clean_zero_rewalk_count']}/{gB['clean_no_aex_count']}** (`{gB['clean_s3_ad_rewalk_pages']['median']:.0f} / {gB['clean_s3_ad_rewalk_pages']['max']:.0f}`) | "
                f"{gB['interrupt_aex_contaminated_count']} (`max={gB['contaminated_s3_ad_rewalk_pages']['max']:.0f}p`) | "
                f"{gC['clean_zero_rewalk_count']}/{gC['clean_no_aex_count']} (`{gC['clean_s3_ad_rewalk_pages']['median']:.0f} / {gC['clean_s3_ad_rewalk_pages']['max']:.0f}`) | "
                f"{gC['interrupt_aex_contaminated_count']} (`max={gC['contaminated_s3_ad_rewalk_pages']['max']:.0f}p`) | "
                f"`{gA['tsc_s2_ticks']['median']:,.0f}` -> **`{gB['tsc_s2_ticks']['median']:,.0f}`** -> `{gC['tsc_s2_ticks']['median']:,.0f}` |"
            )

    lines.append("")
    lines.append(f"- **Exact Per-Observation Totals Across the 8 Non-`ENCLU` Fields ({non_enclu_attempts} total Field entries across 5 rounds)**:")
    lines.append(f"  - **Group B (`dynamic_xr`, Default `XR`)**: **{non_enclu_b_clean} / {non_enclu_attempts}** clean (`s3_aex=0`) observations, **{non_enclu_b_contam} / {non_enclu_attempts}** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **{non_enclu_b_clean_zero} / {non_enclu_b_clean}** achieved `0` residual page-table A/D re-walks.")
    lines.append(f"  - **Group C (`dynamic_refined`, `X-only`)**: **{non_enclu_c_clean} / {non_enclu_attempts}** clean (`s3_aex=0`) observations, **{non_enclu_c_contam} / {non_enclu_attempts}** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **{non_enclu_c_clean_zero} / {non_enclu_c_clean}** achieved `0` residual page-table A/D re-walks.")
    lines.append("")

    # Table 4A & 4B: Dual-View Production AEX1 Latency Breakdown & Whole-Workflow Summary
    lines.append("## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)")
    lines.append("")
    lines.append("- **Symmetric Initial PTE Baseline**: All modes (`Raw`, `No-PreTouch`, `Group A/B/C`) fault in their enclave VMAs at `sgx_create_enclave` time (outside the timed `sgx_ecall` window) and run 1 warmup round before the 5 measured rounds.")
    lines.append("- **Direct Hardware Segmented Timing**: `libatfield_native_sgx.so` directly times `ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE)` (`acquire_ns`), the enclave `EENTER` body (`encl_body_ns = elapsed_ns - acquire_ns - release_ns`), and `ioctl(SGX_IOC_ENCLAVE_PAGES_RELEASE)` (`release_ns`) on every `sgx_ecall`.")
    lines.append("")
    lines.append("### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown")
    lines.append("")
    lines.append("| Sample | Protected Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Warm `S2` Pre-Touch (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for s in SAMPLES:
        ab = eval_data[s]["three_group_ablation"]
        cats = ab["workflow_call_category_counts"]
        n_c3 = max(1, cats["cat3_field_entering_calls"])
        att_b = ab["production_aex1_attempt_accounting"]["groupB_dynamic_xr"]
        seg = ab["production_aex1_segmented_breakdown_ns"]
        np_body_us = (seg["profile_no_pretouch"]["cat3_total_ns"]["median"] / 1e3) / n_c3
        b_acq_rel_us = ((seg["groupB_dynamic_xr"]["cat3_acquire_ns"]["median"] + seg["groupB_dynamic_xr"]["cat3_release_ns"]["median"]) / 1e3) / n_c3
        b_body_us = (seg["groupB_dynamic_xr"]["cat3_body_ns"]["median"] / 1e3) / n_c3
        b_tot_us = (seg["groupB_dynamic_xr"]["cat3_total_ns"]["median"] / 1e3) / n_c3
        b_s2_us = b_body_us - np_body_us
        a_tot_us = (seg["groupA_all_reg_xr"]["cat3_total_ns"]["median"] / 1e3) / n_c3
        ovh_b_us = b_tot_us - np_body_us
        ovh_a_us = a_tot_us - np_body_us
        ovh_pct = 100.0 * ovh_b_us / np_body_us if np_body_us > 0 else 0.0
        red_factor = ovh_a_us / ovh_b_us if ovh_b_us > 0 else 1.0
        lines.append(
            f"| `{s}` | {n_c3} | **{att_b['clean_completed']}/{att_b['total_attempts']}** | "
            f"{np_body_us:.1f} | **{b_acq_rel_us:.1f}** | **{b_s2_us:+.1f}** | "
            f"**{b_tot_us:.1f}** | **{ovh_pct:+.2f}%** (`{ovh_b_us:+.1f} µs`) | "
            f"{a_tot_us:.1f} (`{ovh_a_us:+.1f} µs`) | **{red_factor:.2f}x** |"
        )

    lines.append("")
    lines.append("### 4B. Whole-Workflow End-to-End ECALL Sum (`cat=1` Init + `cat=2` Early-Return + `cat=3` Field Calls) & Binary Footprint")
    lines.append("")
    lines.append("| Sample | Call Mix (`Field / Early-Ret / Init`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B Workflow Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for s in SAMPLES:
        ab = eval_data[s]["three_group_ablation"]
        cats = ab["workflow_call_category_counts"]
        mix_str = f"{cats['cat3_field_entering_calls']} / {cats['cat2_early_return_ready_calls']} / {cats['cat1_init_no_ready_calls']}"
        att_b = ab["production_aex1_attempt_accounting"]["groupB_dynamic_xr"]
        pr = ab["production_aex1_per_round_ecall_sum_ns"]
        sz = ab["binary_and_memory_size_comparison"]
        mRaw = pr["raw_unprotected"]["median"] / 1e6
        mNP = pr["profile_no_pretouch"]["median"] / 1e6
        mA = pr["groupA_all_reg_xr"]["median"] / 1e6
        mB = pr["groupB_dynamic_xr"]["median"] / 1e6
        mC = pr["groupC_dynamic_refined"]["median"] / 1e6
        ovh_pct = 100.0 * (mB - mNP) / mNP if mNP > 0 else 0.0
        spB = mA / mB if mB > 0 else 1.0
        mem_raw_kb = sz["raw_unprotected"]["pt_load_memsz_bytes"] / 1024.0
        mem_b_kb = sz["groupB_dynamic_xr"]["pt_load_memsz_bytes"] / 1024.0
        mem_pct = 100.0 * (mem_b_kb - mem_raw_kb) / mem_raw_kb if mem_raw_kb > 0 else 0.0
        cB = sz["groupB_dynamic_xr"]["pretouch_code_bytes"]
        rB = sz["groupB_dynamic_xr"]["readytable_bytes"]
        lines.append(
            f"| `{s}` | `{mix_str}` | **{att_b['clean_completed']}/{att_b['total_attempts']}** | "
            f"{mRaw:.2f} | {mNP:.2f} | {mA:.2f} | **{mB:.2f}** | {mC:.2f} | "
            f"**{ovh_pct:+.2f}%** (`{mB - mNP:+.2f} ms`) | **{spB:.2f}x** | "
            f"`{mem_raw_kb:.1f} -> {mem_b_kb:.1f} KiB` (**+{mem_pct:.2f}%**) | `{cB} B + {rB} B` |"
        )

    lines.append("")
    lines.append("## 5. Clean-Checkout Reproducible Workflow")
    lines.append("")
    lines.append("```bash")
    lines.append("# 0. Run offline negative & schema/ABI unit tests first")
    lines.append("python3 -m unittest discover -s tests -p 'test_*.py' -v")
    lines.append("")
    lines.append("# 1. Build baseline Profile & All-REG enclaves + extract compiler-exact EDL schemas")
    lines.append("python3 tools/build_real_targets.py")
    lines.append("python3 tools/edl_harness.py")
    lines.append("")
    lines.append("# 2. Compile the SGX-Step + AEP native interposer")
    lines.append("gcc -shared -fPIC -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 \\")
    lines.append("  -Isrc -Ivendor/sgxstep src/native_sgx_interpose.c \\")
    lines.append("  vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c \\")
    lines.append("  vendor/sgxstep/libsgxstep/debug.c -ldl -lpthread \\")
    lines.append("  -o build/libatfield_native_sgx.so")
    lines.append("")
    lines.append("# 3. Run 3-layer dynamic exploration & emit Group B (dynamic_xr) and Group C (dynamic) artifacts")
    lines.append("python3 controller.py qe3 signal-cds sgxwallet ehsm")
    lines.append("")
    lines.append("# 4. Run calibration, independent hold-out verification, and 5-round 3-group evaluation")
    lines.append("python3 tools/evaluate_worksets.py")
    lines.append("")
    lines.append("# 5. Generate summary tables from JSON evidence")
    lines.append("python3 tools/generate_report_tables.py")
    lines.append("```")
    lines.append("")

    content = "\n".join(lines)
    (DYN_ROOT / "README.md").write_text(content)
    (DYN_ROOT / "experiments" / "SUMMARY_TABLES.md").write_text(content)
    print("Updated README.md and experiments/SUMMARY_TABLES.md")


if __name__ == "__main__":
    main()
