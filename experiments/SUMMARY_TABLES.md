# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)

All tables in this document are generated automatically from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.

- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)
- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `b0dd52b0d0f74d1e16b85748e8ec70a80fd07b4266a9e0a717105e69d52e9905`
- **Reproducible Raw Trace Archive**: `experiments/latest_traces_archive.tar.gz` (`860 traces`, SHA-256 `cf39929d439bfa760afa2db36aa22bf8d0abed05c8d63e878f71548473fd76d1`, per-trace index in `experiments/traces_manifest.json`)
- **Default Conservative Candidate**: **Group B (`workset.dynamic_xr.json`)**, which keeps all `RX` code pages as `XR` (`RX = XR`), avoiding unverified `X-only` read-permission stripping.
- **Scope & Boundary Statement**: Dynamic exploration and hold-out evaluations provide empirical evidence on the executed inputs, prefixes, histories, and hardware runs; heuristic assistance (depth-4 direct call graph, `+2` heap frontier pages, `-4` stack margin pages) is an empirical aid rather than a formal whole-program upper-bound proof.

## 1A. Legacy Heuristics Audit & Equal-Budget 4-Strategy Challenge Evaluation

### Explicit Audit of Exploration & Closure Heuristics

| Heuristic / Rule | Problem Addressed | Information Used | Underlying Assumption | Failure Condition | Status & Upgrade |
|---|---|---|---|---|---|
| `scalar_values_0_2_99` | Probe zero/empty, small valid enum/mode, and out-of-range scalar branches at S0/S3. | EDL non-pointer scalar parameter offset and byte width. | Branch predicates compare scalar parameters against 0, small enum constants, or upper bounds < 99. | Misses off-by-one boundary checks (e.g., 1, 15, 16, 17, 255) or predicates coupling a scalar with a buffer byte. | Retained in S1 baseline; upgraded in S2/S3 to boundary + neighbor set {0, 1, 2, 15, 16, 17, 99} plus joint scalar+buffer perturbations. |
| `quadrupling_scale_64_to_262144` | Trigger multi-page heap allocations, dlmalloc bin transitions, and multi-block loops. | EDL [in]/[inout] pointer count=/size= binding offsets and runtime heap chunk spans. | Heap and buffer footprint grows monotonically with power-of-four sizes. | Fails when a specific intermediate size is rejected while a larger size succeeds (non-monotonic hole), or when page-crossing off-by-one lengths (4095/4096/4097) take distinct remainder paths. | Renamed from 'doubling' to 'quadrupling' in S1; upgraded in S2/S3 to include page-crossing sizes and continue past single-length rejections instead of aborting. |
| `two_round_stagnation_stop` | Bound exploration cost when larger scales or mutations stop yielding new (page, effect) pairs or heap/stack growth. | New (page_rva, effect) count, heap_hi_rva delta, and stack low-water delta. | Two consecutive zero-gain steps indicate local saturation of the current operator family. | Indicates local operator stagnation, NOT formal whole-program convergence; if the budget cap (e.g. 262144) is reached while still gaining pages, it is a budget cutoff. | Explicitly labeled 'stop_stagnant_2_rounds' vs 'stop_budget_cap_reached' (never conflated with convergence proof). |
| `repeat_only_last_field_selector` | Exercise cross-call state accumulation (counters, caches, pool reuse) via repeated invocations. | Ordered list of Field-bearing ECALL selectors. | The numerically last Field selector is the main steady-state data-plane operation. | Fails when an earlier Field selector also accumulates state or triggers periodic compaction/rekeying after N calls. | Upgraded in S3 to schedule history accumulation across all Field-bearing selectors with a reserved budget for delayed counter branches. |
| `fixed_ecall0_cold_state_replay` | Exercise lazy library initialization and cold-cache branches when a Field is invoked before warm-up. | Captured typed ms snapshot replayed immediately after ecall_index == 0. | ECALL 0 is always the enclave initialization entry point. | Fails when prerequisite state is established by a non-zero selector (e.g. ecall 1/2/3) or when two prefixes touch identical pages during setup but leave different latent state. | Upgraded in S3 to replay captured calls after general executable prefixes in fresh enclave instances. |
| `depth_4_direct_call_assist` | Include nearby direct-call error/cleanup code pages inside the enclave binary that were not taken dynamically. | Direct x86 call instructions (0xE8) starting from the Field entry symbol. | Shallow helper functions within 4 direct calls may be reached on rare error returns. | Does not cover indirect calls (vtable/function pointers) or deep call chains; it is a static heuristic aid, not a sound static call-graph upper bound. | Explicitly reported in a separate 'Bridge + Heuristic Assist' column in Table 1 and excluded from dynamic discovery claims. |
| `heap_plus2_stack_minus4_margin` | Provide a small guard band around observed dlmalloc heap high-water and stack low-water marks. | Observed heap_hi_rva and minimum gateB/gateD RSP RVA. | Small allocator alignment or stack frame variations stay within +2 heap / -4 stack pages. | Empirical safety margin only; evaluated against independent hold-out workloads under strict ReadyTable enforcement. | Explicitly documented as an empirical margin and audited separately from observed S3 pages. |

### 6-Case General Challenge Suite (`C1..C6`) under Equal Budget (`16` Trials / Case)

- **`S0` (`baseline_host_only`)**: Unmodified seed workflow only.
- **`S1` (`legacy_fixed_heuristics`)**: Fixed `{0, 2, 99}` scalars, `4x` scale aborting on first error, repeat only last Field selector, fixed `ecall 0` cold replay.
- **`S2` (`structured_boundary_and_joint`)**: Boundary + neighbor scalars, non-aborting page-crossing scales with flexible-array header preservation, joint 2-parameter perturbations (`joint_scalar_xor`), and overlapping buffer probes (`aliased_pair`).
- **`S3` (`prefix_state_and_feedback_round_robin`)**: `S2` + executable prefix-state replay across non-zero setup interfaces (retaining distinct prefixes even when setup page sets coincide) + multi-selector history accumulation with reserved budget.

| Strategy | Total Trials | Field Entry Rate | Confirmed New Effects | New Effects / 10 Trials | Challenges Solved (`C1..C6`) | Residual Missed on Hold-Out |
|---|---:|---:|---:|---:|---:|---:|
| **`S0`** | 6 | 100.0% (`6/6`) | 0 | 0.00 | **0 / 6** | **6** |
| **`S1`** | 76 | 98.7% (`75/76`) | 0 | 0.00 | **0 / 6** | **6** |
| **`S2`** | 66 | 98.5% (`65/66`) | 3 | 0.46 | **3 / 6** | **3** |
| **`S3`** | 96 | 99.0% (`95/96`) | 6 | 0.62 | **6 / 6** | **0** |

| Challenge ID | Structural Failure Mode Tested | Target Hidden Effect | `S0` | `S1` (Legacy Fixed) | `S2` (Structured + Joint) | **`S3` (Prefix-State + Round-Robin)** |
|---|---|---|---|---|---|---|
| `C1_late_counter_branch` | Late Counter-Triggered Branch (Requires >=24 Stateful Invocations) | `0x90000:D` | MISS | MISS | MISS | **PASS (step 12)** |
| `C2_cross_interface_prerequisite` | Cross-Interface Non-Zero Prerequisite (ecall_configure(2) -> ecall_work) | `0xa0000:A` | MISS | MISS | MISS | **PASS (step 7)** |
| `C3_non_monotonic_length_hole` | Non-Monotonic Length Rejection Hole (scale=256 Fails, scale=4096 Succeeds) | `0xb0000:D` | MISS | MISS | PASS (step 11) | **PASS (step 16)** |
| `C4_joint_two_param_predicate` | Joint Two-Parameter Predicate (scalar mode==2 AND buffer[0]^=0xff) | `0xc0000:A` | MISS | MISS | PASS (step 4) | **PASS (step 4)** |
| `C5_same_pages_different_latent_state` | Identical Prefix Page Set with Distinct Latent State | `0xd0000:D` | MISS | MISS | MISS | **PASS (step 11)** |
| `C6_aliased_and_empty_boundary` | Overlapping Buffer Aliasing (+4B) and Zero-Length Boundary | `0xe0000:D` | MISS | MISS | PASS (step 5) | **PASS (step 5)** |

## 1B. Three-Layer Workset Attribution Across 6 Targets (Including `ehsm`, `ehsm-opt-1`, `ehsm-opt-2`)

- **`ehsm` (Original)**: Unmodified two-step size-query + crypto host workflow (`32` ECALLs/round: `14` Field-entering + `16` early-return + `2` init); OpenSSL 3.0 lazy provider init occurs inside the first Field call.
- **`ehsm-opt-1` (Direct Host Sizing + Backward-Compatible Enclave `S0`)**: Host allocates buffers directly using public constants (`EH_AES_GCM_256_SIZE`, `plain_len + 28`), eliminating `13` redundant size-query ECALLs (`19` ECALLs/round: `14` Field-entering + `3` negative early-return + `2` init) while preserving `S0` size-query compatibility, full `SM4` dispatch, and strict `decrypt` output capacity validation (`plaintext->datalen >= ciphertext->datalen - 28`).
- **`ehsm-opt-2` (+ Explicit Secret-Independent OpenSSL Provider Init in `enclave_get_domain_key_from_local`)**: Adds 5 lines of key-less `EVP_CipherInit_ex(..., NULL, NULL)` initialization during enclave domain-key init, moving the 174-page one-time OpenSSL global provider setup out of the confidential Fields (`263-266p -> 86-92p` observed S3 pages).

| Sample | Field | L0 First Call (`p / eff`) | L1 Full Host (`p / +p`) | L2 Isolated from Seed (`p / +p`) | L2 Added Beyond Full Host (`+p / +eff`) | Bridge + Heuristic Assist (`+p`) | Final `FieldTargetPages` (Group B `XR`) | All-REG Baseline | Reduction vs All-REG |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `get_att_key_based_from_seal_key` | 69p / 77e | 69p (`+0p`) | **69p** (`+0p`) | **+0p / +0e** | +57p | **126p** | 850p | **85.18%** |
| `signal-cds` | `sabd_lookup_hash` | 16p / 20e | 230p (`+214p`) | **554p** (`+538p`) | **+324p / +364e** | +12p | **566p** | 1127p | **49.78%** |
| `sgxwallet` | `ecdsa_sign_field` | 69p / 77e | 75p (`+6p`) | **75p** (`+6p`) | **+0p / +0e** | +33p | **108p** | 1774p | **93.91%** |
| `sgxwallet` | `get_public_ecdsa_key_field` | 67p / 73e | 67p (`+0p`) | **71p** (`+4p`) | **+4p / +4e** | +29p | **100p** | 1774p | **94.36%** |
| `sgxwallet` | `set_sek_field` | 45p / 52e | 45p (`+0p`) | **52p** (`+7p`) | **+7p / +7e** | +22p | **74p** | 1774p | **95.83%** |
| `sgxwallet` | `generate_ecdsa_key_field` | 75p / 81e | 75p (`+0p`) | **75p** (`+0p`) | **+0p / +0e** | +31p | **106p** | 1774p | **94.02%** |
| `sgxwallet` | `generate_sek_field` | 49p / 57e | 49p (`+0p`) | **49p** (`+0p`) | **+0p / +0e** | +25p | **74p** | 1774p | **95.83%** |
| `ehsm` | `ehsm_create_aes_key` | 263p / 332e | 263p (`+0p`) | **263p** (`+0p`) | **+0p / +0e** | +35p | **298p** | 2349p | **87.31%** |
| `ehsm` | `ehsm_generate_datakey` | 90p / 98e | 90p (`+0p`) | **264p** (`+174p`) | **+174p / +236e** | +35p | **299p** | 2349p | **87.27%** |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 90p / 97e | 93p (`+3p`) | **266p** (`+176p`) | **+173p / +234e** | +35p | **301p** | 2349p | **87.19%** |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 90p / 98e | 266p (`+176p`) | **266p** (`+176p`) | **+0p / +0e** | +37p | **303p** | 2349p | **87.10%** |
| `ehsm-opt-1` | `ehsm_generate_datakey` | 90p / 98e | 90p (`+0p`) | **266p** (`+176p`) | **+176p / +238e** | +34p | **300p** | 2349p | **87.23%** |
| `ehsm-opt-1` | `ehsm_aes_gcm_encrypt` | 90p / 97e | 93p (`+3p`) | **268p** (`+178p`) | **+175p / +236e** | +34p | **302p** | 2349p | **87.14%** |
| `ehsm-opt-1` | `ehsm_aes_gcm_decrypt` | 90p / 98e | 268p (`+178p`) | **268p** (`+178p`) | **+0p / +0e** | +36p | **304p** | 2349p | **87.06%** |
| `ehsm-opt-1` | `ehsm_create_aes_key` | 265p / 334e | 265p (`+0p`) | **265p** (`+0p`) | **+0p / +0e** | +34p | **299p** | 2349p | **87.27%** |
| `ehsm-opt-2` | `ehsm_aes_gcm_encrypt` | 89p / 95e | 92p (`+3p`) | **92p** (`+3p`) | **+0p / +0e** | +89p | **181p** | 2349p | **92.29%** |
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 89p / 95e | 92p (`+3p`) | **92p** (`+3p`) | **+0p / +1e** | +92p | **184p** | 2349p | **92.17%** |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 89p / 95e | 89p (`+0p`) | **89p** (`+0p`) | **+0p / +1e** | +89p | **178p** | 2349p | **92.42%** |
| `ehsm-opt-2` | `ehsm_create_aes_key` | 86p / 93e | 86p (`+0p`) | **86p** (`+0p`) | **+0p / +0e** | +90p | **176p** | 2349p | **92.51%** |

## 2. Provenance, Fault-Detector Calibration, Same-Fault AEX0/AEX1, and Hold-Out Validation

| Sample | Provenance Hash Match | Cold vs Warm TLB (`ipi=7` vs `0` S3 Pages) | 4-Gate vs Uninst `AEX0` Equivalence | Single-Page `X / R / W` Confirmed Kind (`healed:kind`) | Restored Positive Control Faults | Same-Fault `AEX0` (`rc=0`) vs `AEX1` (`0x1006` on same page) | Hold-Out Main `rc` & `stdout` | Hold-Out Unseen `(page / effect)` | Strict `FieldTargetPages` (`Gate B..D`) Faults | Strict `ReadyTable v3` (`ECALL`) Faults | Validator Verdict |
|---|---|---|---|---|---:|---|---|---|---|---:|---:|---|
| `qe3` | **PASS** | 69p vs 52p (`True`) | `True` | `0xd5000:True:X`, `0x2000:True:R`, `0x1f4000:True:W` | 0 | `0xd5000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `signal-cds` | **PASS** | 16p vs 1p (`True`) | `True` | `0xc000:True:X`, `0x10000:True:R`, `0x3d000:True:W` | 0 | `0xc000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `sgxwallet` | **PASS** | 49p vs 31p (`True`) | `True` | `0x16000:True:X`, `0x5000:True:R`, `0x28c000:True:W` | 0 | `0x16000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `ehsm` | **PASS** | 263p vs 245p (`True`) | `True` | `0xdb000:True:X`, `0x57000:True:R`, `0x4c9000:True:W` | 0 | `0xdb000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `ehsm-opt-1` | **PASS** | 265p vs 245p (`True`) | `True` | `0xdb000:True:X`, `0x57000:True:R`, `0x4c9000:True:W` | 0 | `0xdb000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `ehsm-opt-2` | **PASS** | 86p vs 68p (`True`) | `True` | `0xdb000:True:X`, `0x5c000:True:R`, `0x52e000:True:W` | 0 | `0xdb000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |

## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)

| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |
|---|---|---:|---|---|---|---:|---|---|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 0/15 (`3 / 4`) | **0/15** (`3 / 3`) | 0 (`max=0p`) | 0/15 (`3 / 3`) | 0 (`max=0p`) | `1,684,046` -> **`188,562`** -> `151,740` |
| `signal-cds` | `sabd_lookup_hash` | 25 | 15/25 (`0 / 25`) | **25/25** (`0 / 0`) | 0 (`max=0p`) | 25/25 (`0 / 0`) | 0 (`max=0p`) | `1,267,082` -> **`632,956`** -> `647,012` |
| `sgxwallet` | `generate_sek_field` | 5 | 0/5 (`11 / 13`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,039,944` -> **`229,844`** -> `223,316` |
| `sgxwallet` | `set_sek_field` | 5 | 0/5 (`14 / 15`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,002,574` -> **`223,384`** -> `209,754` |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 0/5 (`17 / 28`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `3,089,244` -> **`202,172`** -> `192,364` |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 0/5 (`13 / 18`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,046,464` -> **`125,496`** -> `125,872` |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 0/50 (`16 / 23`) | **50/50** (`0 / 0`) | 0 (`max=0p`) | 50/50 (`0 / 0`) | 0 (`max=0p`) | `2,020,617` -> **`140,731`** -> `140,792` |
| `ehsm` | `ehsm_generate_datakey` | 5 | 0/5 (`34 / 43`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,889,156` -> **`443,282`** -> `435,442` |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 45`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,876,257` -> **`453,233`** -> `433,984` |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 129`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,894,045` -> **`451,545`** -> `440,736` |
| `ehsm` | `ehsm_create_aes_key` | 5 | 0/5 (`124 / 138`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,006,262` -> **`940,634`** -> `909,638` |
| `ehsm-opt-1` | `ehsm_generate_datakey` | 5 | 0/5 (`37 / 39`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,893,770` -> **`444,204`** -> `439,434` |
| `ehsm-opt-1` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 44`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,894,037` -> **`450,395`** -> `430,224` |
| `ehsm-opt-1` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`38 / 131`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,904,609` -> **`443,112`** -> `445,014` |
| `ehsm-opt-1` | `ehsm_create_aes_key` | 5 | 0/5 (`125 / 140`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,099,276` -> **`951,376`** -> `921,632` |
| `ehsm-opt-2` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 44`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,865,916` -> **`292,887`** -> `291,293` |
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`35 / 45`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,872,739` -> **`293,769`** -> `293,878` |
| `ehsm-opt-2` | `ehsm_create_aes_key` | 5 | 0/5 (`30 / 34`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `7,654,926` -> **`375,918`** -> `365,614` |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 5 | 0/5 (`37 / 40`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,890,654` -> **`292,764`** -> `289,964` |

- **Exact Per-Observation Totals Across the 16 Non-`ENCLU` Field Instances (295 total Field entries across 5 rounds)**:
  - **Group B (`dynamic_xr`, Default `XR`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.
  - **Group C (`dynamic_refined`, `X-only`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.

## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)

- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).
- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).

### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown

| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 3 | **5/5** | 249.7 | **40.2** | 258.9 | +9.2 | **298.6** | **+19.56%** (`+48.8 µs`) | 472.4 (`+222.7 µs`) | **4.56x** |
| `signal-cds` | 5 | **5/5** | 87441.7 | **128.5** | 87463.4 | +21.7 | **87594.6** | **+0.17%** (`+152.9 µs`) | 87709.1 (`+267.4 µs`) | **1.75x** |
| `sgxwallet` | 14 | **5/5** | 1347.8 | **34.8** | 1357.5 | +9.7 | **1392.2** | **+3.30%** (`+44.4 µs`) | 1798.5 (`+450.7 µs`) | **10.15x** |
| `ehsm` | 14 | **5/5** | 141.9 | **70.3** | 144.9 | +3.0 | **215.0** | **+51.58%** (`+73.2 µs`) | 703.9 (`+562.1 µs`) | **7.68x** |
| `ehsm-opt-1` | 14 | **5/5** | 140.5 | **72.4** | 145.6 | +5.1 | **218.3** | **+55.37%** (`+77.8 µs`) | 711.7 (`+571.2 µs`) | **7.34x** |
| `ehsm-opt-2` | 14 | **5/5** | 11.5 | **49.9** | 14.9 | +3.3 | **64.7** | **+460.12%** (`+53.1 µs`) | 588.6 (`+577.0 µs`) | **10.86x** |

### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)

| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 0 | 0.000 | 0.000 |
| `signal-cds` | 1 | 0.005 | **0.123** | 0.006 | **0.129** | 0 | 0.000 | 0.000 |
| `sgxwallet` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 4 | 17.100 | 17.110 |
| `ehsm` | 16 | 0.091 | **1.147** | 0.096 | **1.243** | 2 | 0.163 | 0.156 |
| `ehsm-opt-1` | 3 | 0.017 | **0.210** | 0.017 | **0.227** | 2 | 0.168 | 0.159 |
| `ehsm-opt-2` | 3 | 0.017 | **0.142** | 0.017 | **0.159** | 2 | 2.002 | 1.955 |

### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint

| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `3 / 0 / 0` | **5/5** | 0.75 | 0.75 | 1.42 | **0.90** | 0.90 | **+19.56%** (`+0.15 ms`) | **1.58x** | `2104.7 -> 2116.7 KiB` (**+0.57%**) | `1303 B + 1544 B` |
| `signal-cds` | `5 / 1 / 0` | **5/5** | 437.19 | 437.21 | 438.78 | **438.10** | 438.17 | **+0.20%** (`+0.89 ms`) | **1.00x** | `140.3 -> 155.8 KiB` (**+11.06%**) | `4568 B + 5072 B` |
| `sgxwallet` | `14 / 0 / 4` | **5/5** | 42.66 | 35.99 | 42.36 | **36.57** | 36.63 | **+1.61%** (`+0.58 ms`) | **1.16x** | `2722.2 -> 2818.2 KiB` (**+3.52%**) | `4458 B + 6280 B` |
| `ehsm` | `14 / 16 / 2` | **5/5** | 2.22 | 2.24 | 17.36 | **4.41** | 4.44 | **+97.00%** (`+2.17 ms`) | **3.94x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10206 B + 11696 B` |
| `ehsm-opt-1` | `14 / 3 / 2` | **5/5** | 2.16 | 2.15 | 11.47 | **3.44** | 3.45 | **+59.92%** (`+1.29 ms`) | **3.33x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10250 B + 11728 B` |
| `ehsm-opt-2` | `14 / 3 / 2` | **5/5** | 2.17 | 2.18 | 11.56 | **3.02** | 3.04 | **+38.51%** (`+0.84 ms`) | **3.83x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `6117 B + 7832 B` |

## 5. Clean-Checkout Reproducible Workflow

```bash
# 0. Run offline negative, schema/ABI, and 6-case challenge suite unit tests first
python3 -m unittest discover -s tests -p 'test_*.py' -v

# 1. Build baseline Profile & All-REG enclaves + extract compiler-exact EDL schemas
python3 tools/build_real_targets.py
python3 tools/edl_harness.py

# 2. Compile the SGX-Step + AEP native interposer
gcc -shared -fPIC -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 \
  -Isrc -Ivendor/sgxstep src/native_sgx_interpose.c \
  vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c \
  vendor/sgxstep/libsgxstep/debug.c -ldl -lpthread \
  -o build/libatfield_native_sgx.so

# 3. Run 3-layer dynamic exploration & emit Group B (dynamic_xr) and Group C (dynamic) artifacts
python3 controller.py qe3 signal-cds sgxwallet ehsm ehsm-opt-1 ehsm-opt-2

# 4. Run calibration, independent hold-out verification, and 5-round 3-group evaluation
python3 tools/evaluate_worksets.py

# 5. Generate summary tables from JSON evidence
python3 tools/generate_report_tables.py
```
