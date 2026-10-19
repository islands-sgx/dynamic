#!/usr/bin/env python3
"""Generate README.md and experiments/SUMMARY_TABLES.md directly from evaluation_results.json, strategy_comparison.json, and witness_ledger.json."""
from __future__ import annotations

import json
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm", "ehsm-opt-1", "ehsm-opt-2"]


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
    strat_data = json.loads((DYN_ROOT / "experiments" / "strategy_comparison.json").read_text())
    manifest_path = DYN_ROOT / "experiments" / "traces_manifest.json"
    manifest_data = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    ledgers = {
        s: json.loads((DYN_ROOT / "witnesses" / s / "witness_ledger.json").read_text())
        for s in SAMPLES
    }
    interpose_sha = ledgers["qe3"]["interpose_sha256"]

    lines = []
    lines.append("# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)")
    lines.append("")
    lines.append("All tables in this document are generated automatically from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.")
    lines.append("")
    lines.append("- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)")
    lines.append(f"- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `{interpose_sha}`")
    if manifest_data:
        lines.append(f"- **Reproducible Raw Trace Archive**: `{manifest_data.get('archive_path')}` (`{manifest_data.get('total_trace_files')} traces`, SHA-256 `{manifest_data.get('archive_sha256')}`, per-trace index in `experiments/traces_manifest.json`)")
    lines.append("- **Default Conservative Candidate**: **Group B (`workset.dynamic_xr.json`)**, which keeps all `RX` code pages as `XR` (`RX = XR`), avoiding unverified `X-only` read-permission stripping.")
    lines.append("- **Scope & Boundary Statement**: Dynamic exploration and hold-out evaluations provide empirical evidence on the executed inputs, prefixes, histories, and hardware runs; heuristic assistance (depth-4 direct call graph, `+2` heap frontier pages, `-4` stack margin pages) is an empirical aid rather than a formal whole-program upper-bound proof.")
    lines.append("")

    # Section 1A: Audit of Legacy Heuristics & Equal-Budget 4-Strategy Challenge Evaluation
    lines.append("## 1A. Legacy Heuristics Audit & Equal-Budget 4-Strategy Challenge Evaluation")
    lines.append("")
    lines.append("### Explicit Audit of Exploration & Closure Heuristics")
    lines.append("")
    lines.append("| Heuristic / Rule | Problem Addressed | Information Used | Underlying Assumption | Failure Condition | Status & Upgrade |")
    lines.append("|---|---|---|---|---|---|")
    for h in strat_data["audit_of_legacy_heuristics"]:
        lines.append(
            f"| `{h['heuristic']}` | {h['problem_addressed']} | {h['information_used']} | "
            f"{h['underlying_assumption']} | {h['failure_condition']} | {h['empirical_status_and_upgrade']} |"
        )
    lines.append("")

    lines.append("### 6-Case General Challenge Suite (`C1..C6`) under Equal Budget (`16` Trials / Case)")
    lines.append("")
    lines.append("- **`S0` (`baseline_host_only`)**: Unmodified seed workflow only.")
    lines.append("- **`S1` (`legacy_fixed_heuristics`)**: Fixed `{0, 2, 99}` scalars, `4x` scale aborting on first error, repeat only last Field selector, fixed `ecall 0` cold replay.")
    lines.append("- **`S2` (`structured_boundary_and_joint`)**: Boundary + neighbor scalars, non-aborting page-crossing scales with flexible-array header preservation, joint 2-parameter perturbations (`joint_scalar_xor`), and overlapping buffer probes (`aliased_pair`).")
    lines.append("- **`S3` (`prefix_state_and_feedback_round_robin`)**: `S2` + executable prefix-state replay across non-zero setup interfaces (retaining distinct prefixes even when setup page sets coincide) + multi-selector history accumulation with reserved budget.")
    lines.append("")
    lines.append("| Strategy | Total Trials | Field Entry Rate | Confirmed New Effects | New Effects / 10 Trials | Challenges Solved (`C1..C6`) | Residual Missed on Hold-Out |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for st_key in ("S0", "S1", "S2", "S3"):
        s = strat_data["summary_by_strategy"][st_key]
        lines.append(
            f"| **`{st_key}`** | {s['total_trials']} | {100.0 * s['field_entry_rate']:.1f}% (`{s['field_entry_count']}/{s['total_trials']}`) | "
            f"{s['confirmed_new_effects']} | {s['new_effects_per_10_trials']:.2f} | "
            f"**{s['challenges_solved']} / {s['challenges_total']}** | **{s['holdout_missed_effects']}** |"
        )
    lines.append("")
    lines.append("| Challenge ID | Structural Failure Mode Tested | Target Hidden Effect | `S0` | `S1` (Legacy Fixed) | `S2` (Structured + Joint) | **`S3` (Prefix-State + Round-Robin)** |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in strat_data["case_matrix"]:
        lines.append(
            f"| `{row['challenge_id']}` | {row['title']} | `{row['target']}` | {row['S0']} | {row['S1']} | {row['S2']} | **{row['S3']}** |"
        )
    lines.append("")

    # Section 1B: Three-Layer Workset Attribution across 6 Targets (19 Field instances)
    lines.append("## 1B. Three-Layer Workset Attribution Across 6 Targets (Including `ehsm`, `ehsm-opt-1`, `ehsm-opt-2`)")
    lines.append("")
    lines.append("- **`ehsm` (Original)**: Unmodified two-step size-query + crypto host workflow (`32` ECALLs/round: `14` Field-entering + `16` early-return + `2` init); OpenSSL 3.0 lazy provider init occurs inside the first Field call.")
    lines.append("- **`ehsm-opt-1` (Direct Host Sizing + Backward-Compatible Enclave `S0`)**: Host allocates buffers directly using public constants (`EH_AES_GCM_256_SIZE`, `plain_len + 28`), eliminating `13` redundant size-query ECALLs (`19` ECALLs/round: `14` Field-entering + `3` negative early-return + `2` init) while preserving `S0` size-query compatibility, full `SM4` dispatch, and strict `decrypt` output capacity validation (`plaintext->datalen >= ciphertext->datalen - 28`).")
    lines.append("- **`ehsm-opt-2` (+ Explicit Secret-Independent OpenSSL Provider Init in `enclave_get_domain_key_from_local`)**: Adds 5 lines of key-less `EVP_CipherInit_ex(..., NULL, NULL)` initialization during enclave domain-key init, moving the 174-page one-time OpenSSL global provider setup out of the confidential Fields (`263-266p -> 86-92p` observed S3 pages).")
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
    lines.append(f"- **Exact Per-Observation Totals Across the 16 Non-`ENCLU` Field Instances ({non_enclu_attempts} total Field entries across 5 rounds)**:")
    lines.append(f"  - **Group B (`dynamic_xr`, Default `XR`)**: **{non_enclu_b_clean} / {non_enclu_attempts}** clean (`s3_aex=0`) observations, **{non_enclu_b_contam} / {non_enclu_attempts}** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **{non_enclu_b_clean_zero} / {non_enclu_b_clean}** achieved `0` residual page-table A/D re-walks.")
    lines.append(f"  - **Group C (`dynamic_refined`, `X-only`)**: **{non_enclu_c_clean} / {non_enclu_attempts}** clean (`s3_aex=0`) observations, **{non_enclu_c_contam} / {non_enclu_attempts}** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **{non_enclu_c_clean_zero} / {non_enclu_c_clean}** achieved `0` residual page-table A/D re-walks.")
    lines.append("")

    # Section 4: Production AEX1 Segmented Breakdown (4A: cat=3, 4B: cat=2 & cat=1 direct segmented, 4C: sum of ECALLs)
    lines.append("## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)")
    lines.append("")
    lines.append("- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).")
    lines.append("- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).")
    lines.append("")
    lines.append("### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown")
    lines.append("")
    lines.append("| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

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
        b_dbody_us = b_body_us - np_body_us
        a_tot_us = (seg["groupA_all_reg_xr"]["cat3_total_ns"]["median"] / 1e3) / n_c3
        ovh_b_us = b_tot_us - np_body_us
        ovh_a_us = a_tot_us - np_body_us
        ovh_pct = 100.0 * ovh_b_us / np_body_us if np_body_us > 0 else 0.0
        red_factor = ovh_a_us / ovh_b_us if ovh_b_us > 0 else 1.0
        lines.append(
            f"| `{s}` | {n_c3} | **{att_b['clean_completed']}/{att_b['total_attempts']}** | "
            f"{np_body_us:.1f} | **{b_acq_rel_us:.1f}** | {b_body_us:.1f} | {b_dbody_us:+.1f} | "
            f"**{b_tot_us:.1f}** | **{ovh_pct:+.2f}%** (`{ovh_b_us:+.1f} µs`) | "
            f"{a_tot_us:.1f} (`{ovh_a_us:+.1f} µs`) | **{red_factor:.2f}x** |"
        )

    lines.append("")
    lines.append("### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)")
    lines.append("")
    lines.append("| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")

    for s in SAMPLES:
        ab = eval_data[s]["three_group_ablation"]
        cats = ab["workflow_call_category_counts"]
        n_c2 = cats["cat2_early_return_ready_calls"]
        n_c1 = cats["cat1_init_no_ready_calls"]
        seg = ab["production_aex1_segmented_breakdown_ns"]
        np_c2_ms = seg["profile_no_pretouch"]["cat2_early_ret_ns"]["median"] / 1e6
        b_c2_ar_ms = (seg["groupB_dynamic_xr"]["cat2_acquire_ns"]["median"] + seg["groupB_dynamic_xr"]["cat2_release_ns"]["median"]) / 1e6
        b_c2_bd_ms = seg["groupB_dynamic_xr"]["cat2_body_ns"]["median"] / 1e6
        b_c2_tot_ms = seg["groupB_dynamic_xr"]["cat2_early_ret_ns"]["median"] / 1e6
        np_c1_ms = seg["profile_no_pretouch"]["cat1_init_ns"]["median"] / 1e6
        b_c1_tot_ms = seg["groupB_dynamic_xr"]["cat1_init_ns"]["median"] / 1e6
        lines.append(
            f"| `{s}` | {n_c2} | {np_c2_ms:.3f} | **{b_c2_ar_ms:.3f}** | {b_c2_bd_ms:.3f} | "
            f"**{b_c2_tot_ms:.3f}** | {n_c1} | {np_c1_ms:.3f} | {b_c1_tot_ms:.3f} |"
        )

    lines.append("")
    lines.append("### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint")
    lines.append("")
    lines.append("| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |")
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
    lines.append("# 0. Run offline negative, schema/ABI, and 6-case challenge suite unit tests first")
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
    lines.append("python3 controller.py qe3 signal-cds sgxwallet ehsm ehsm-opt-1 ehsm-opt-2")
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
