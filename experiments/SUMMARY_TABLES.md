# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)

All tables in this document are generated automatically from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.

- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)
- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `02116a65cb8e46e267a828bf3c08f9756844342db558dadd34a9e8bf04e63e6c`
- **Reproducible Raw Trace Archive**: `experiments/latest_traces_archive.tar.gz` (`898 traces`, SHA-256 `a63942fe43120f79584cdc9989ed92de46c54b52b198871b3faf7237a4dbdad5`, per-trace index in `experiments/traces_manifest.json`)
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

### Real SGX Hardware Challenge Enclaves (`challenge-bench` & `challenge-bench-perm`) under Equal Enclave-Creation Budget (`48` Enclaves, Including Replay Confirmations)

- **Real Compiled SGX Enclaves**: Both `challenges/challenge-bench` (standard ECALL order & thresholds) and `challenges/challenge-bench-perm` (shuffled ECALL indices, renamed functions, mutated thresholds) are compiled with `atfield-enclave-clang`, signed with `sgx_sign`, patched with `patch_4gate.py`, and executed on real SGX hardware under `build/libatfield_native_sgx.so` using the exact same candidate generator, scheduler, and collector as the real benchmarks.
- **Full Cost Accounting**: Every enclave creation, prefix execution, rejected S0 call, and replay-confirmation run is charged to the `48`-enclave budget.

| Target Enclave | Strategy | Enclaves Created | Total ECALLs Executed | Wall-Clock (s) | Call Breakdown (`Field / S0-Reject / Setup`) | Confirmed `S3` Pages / Effects (`Eff / 100 ECALLs`) | **Challenges Solved (`C1..C6`)** | **Independent Hold-Out Missed Pages** |
|---|---|---:|---:|---:|---|---:|---|---:|
| `challenge-bench` | **`S0`** | 1 | 5 | 0.06s | `2 / 0 / 3` | 5p / 9e (`180.0`) | **0 / 6** (`none`) | **6** |
| `challenge-bench` | **`S1`** | 48 | 203 | 2.81s | `83 / 6 / 95` | 6p / 11e (`5.4`) | **1 / 6** (`C1`) | **5** |
| `challenge-bench` | **`S2`** | 48 | 209 | 2.80s | `85 / 6 / 89` | 11p / 19e (`9.1`) | **4 / 6** (`C1,C3,C4,C6`) | **2** |
| `challenge-bench` | **`S3`** | 48 | 262 | 2.83s | `107 / 2 / 113` | 13p / 22e (`8.4`) | **6 / 6** (`C1,C2,C3,C4,C5,C6`) | **0** |
| `challenge-bench-perm` | **`S0`** | 1 | 5 | 0.06s | `2 / 0 / 3` | 5p / 9e (`180.0`) | **0 / 6** (`none`) | **7** |
| `challenge-bench-perm` | **`S1`** | 48 | 212 | 2.81s | `85 / 5 / 95` | 6p / 11e (`5.2`) | **1 / 6** (`C1`) | **6** |
| `challenge-bench-perm` | **`S2`** | 48 | 217 | 2.82s | `86 / 5 / 89` | 11p / 19e (`8.8`) | **4 / 6** (`C1,C3,C4,C6`) | **2** |
| `challenge-bench-perm` | **`S3`** | 48 | 270 | 2.85s | `108 / 1 / 113` | 13p / 22e (`8.2`) | **6 / 6** (`C1,C2,C3,C4,C5,C6`) | **0** |

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

### Out-of-Seed Producer-Consumer Boundary Audit & Onboarding Cost Accounting

- **Un-Seeded Producer-Consumer Dependency (`create_key(EH_SM4_CTR) -> generate_datakey(sm4_cmk)`)**: When the seed host only exercises `EH_AES_GCM_256`, single-call `L2` mutations on `enclave_generate_datakey` cannot forge a valid `EH_SM4_CTR` `cmk` because `cmk->keyblob` is authenticated by the enclave domain key via AES-GCM (`ehsm_parse_keyblob_to_gcm_data`). Running `--sm4-check` against the AES-seeded workset demonstrates that `validate_run_result()` automatically catches the exact uncovered `SM4-CTR` pages:
  - `ehsm-opt-1` (`--sm4-check` against AES-only workset): validator status = **`FAIL`**, automatically catching **4 uncovered page effects** (`UNCOVERED_PAGE_0x1d3000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x21e000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x285000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x286000_IN_0x2c6ee760c60f6016`).
  - `ehsm-opt-2` (`--sm4-check` against AES-only workset): validator status = **`FAIL`**, automatically catching **14 uncovered page effects** (`UNCOVERED_PAGE_0x5b000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x89000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x93000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x184000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x1d3000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x1e4000_IN_0x61a6007dac8ab670...`).
- **Target Onboarding Cost Summary (Zero Sample-Name Branches in Explorer)**:
  - `qe3`: `1` Field annotation (`ATFIELD`), `1` selector in `selectors.json`, `0` explorer lines changed;
  - `signal-cds`: `1` Field annotation, `1` selector in `selectors.json`, `0` explorer lines changed;
  - `sgxwallet`: `5` Field annotations, `7` selectors in `selectors.json`, `0` explorer lines changed (`CALL_ONCE` abort on `ecall 2/3` detected automatically at runtime);
  - `ehsm / ehsm-opt-1 / ehsm-opt-2` (single application, 3-variant ablation): `4` Field annotations, `5` selectors in `selectors.json`, `0` explorer lines changed;
  - `challenge-bench / challenge-bench-perm` (2 synthetic challenge enclaves): `1` Field annotation, `4` selectors in `selectors.json`, `0` explorer lines changed.

## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)

| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |
|---|---|---:|---|---|---|---:|---|---|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 0/15 (`3 / 5`) | **0/15** (`3 / 3`) | 0 (`max=0p`) | 0/15 (`3 / 3`) | 0 (`max=0p`) | `1,619,396` -> **`181,058`** -> `156,262` |
| `signal-cds` | `sabd_lookup_hash` | 25 | 16/25 (`0 / 11`) | **25/25** (`0 / 0`) | 0 (`max=0p`) | 25/25 (`0 / 0`) | 0 (`max=0p`) | `1,279,124` -> **`658,316`** -> `647,058` |
| `sgxwallet` | `generate_sek_field` | 5 | 0/5 (`15 / 16`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,275,754` -> **`233,186`** -> `213,668` |
| `sgxwallet` | `set_sek_field` | 5 | 0/5 (`15 / 16`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,275,048` -> **`226,718`** -> `210,842` |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 0/5 (`20 / 22`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `3,059,328` -> **`196,968`** -> `199,074` |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 0/5 (`19 / 21`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,045,614` -> **`128,712`** -> `121,510` |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 0/50 (`16 / 24`) | **50/50** (`0 / 0`) | 0 (`max=0p`) | 50/50 (`0 / 0`) | 0 (`max=0p`) | `2,027,587` -> **`142,754`** -> `140,768` |
| `ehsm` | `ehsm_generate_datakey` | 5 | 0/5 (`30 / 35`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,895,710` -> **`440,754`** -> `452,492` |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`34 / 44`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,930,528` -> **`463,868`** -> `437,952` |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 145`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,904,272` -> **`452,259`** -> `445,379` |
| `ehsm` | `ehsm_create_aes_key` | 5 | 0/5 (`129 / 145`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,219,628` -> **`958,516`** -> `912,618` |
| `ehsm-opt-1` | `ehsm_generate_datakey` | 5 | 0/5 (`36 / 41`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,876,488` -> **`445,420`** -> `455,224` |
| `ehsm-opt-1` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`37 / 42`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,887,834` -> **`458,566`** -> `437,511` |
| `ehsm-opt-1` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 136`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,889,180` -> **`449,687`** -> `448,304` |
| `ehsm-opt-1` | `ehsm_create_aes_key` | 5 | 0/5 (`137 / 140`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,445,990` -> **`971,916`** -> `907,306` |
| `ehsm-opt-2` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`38 / 43`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,854,786` -> **`293,977`** -> `295,030` |
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 48`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,884,497` -> **`294,211`** -> `297,206` |
| `ehsm-opt-2` | `ehsm_create_aes_key` | 5 | 0/5 (`36 / 41`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,096,684` -> **`376,168`** -> `359,814` |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 5 | 0/5 (`37 / 42`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,876,258` -> **`292,868`** -> `293,506` |

- **Exact Per-Observation Totals Across the 16 Non-`ENCLU` Field Instances (295 total Field entries across 5 rounds)**:
  - **Group B (`dynamic_xr`, Default `XR`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.
  - **Group C (`dynamic_refined`, `X-only`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.

## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)

- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).
- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).

### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown

| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 3 | **5/5** | 251.8 | **39.2** | 260.0 | +8.2 | **299.4** | **+18.90%** (`+47.6 µs`) | 478.0 (`+226.2 µs`) | **4.75x** |
| `signal-cds` | 5 | **5/5** | 87441.3 | **128.9** | 87454.9 | +13.6 | **87583.8** | **+0.16%** (`+142.6 µs`) | 87704.6 (`+263.3 µs`) | **1.85x** |
| `sgxwallet` | 14 | **5/5** | 1355.4 | **35.0** | 1357.3 | +1.9 | **1392.0** | **+2.70%** (`+36.6 µs`) | 1792.7 (`+437.2 µs`) | **11.95x** |
| `ehsm` | 14 | **5/5** | 141.5 | **70.3** | 146.1 | +4.6 | **216.5** | **+52.99%** (`+75.0 µs`) | 709.7 (`+568.1 µs`) | **7.58x** |
| `ehsm-opt-1` | 14 | **5/5** | 141.4 | **72.6** | 145.9 | +4.5 | **219.1** | **+54.93%** (`+77.7 µs`) | 723.0 (`+581.6 µs`) | **7.49x** |
| `ehsm-opt-2` | 14 | **5/5** | 11.5 | **49.8** | 14.9 | +3.4 | **64.7** | **+460.89%** (`+53.2 µs`) | 599.7 (`+588.2 µs`) | **11.06x** |

### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)

| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 0 | 0.000 | 0.000 |
| `signal-cds` | 1 | 0.005 | **0.123** | 0.006 | **0.129** | 0 | 0.000 | 0.000 |
| `sgxwallet` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 4 | 17.103 | 17.111 |
| `ehsm` | 16 | 0.091 | **1.146** | 0.097 | **1.249** | 2 | 0.158 | 0.158 |
| `ehsm-opt-1` | 3 | 0.017 | **0.210** | 0.018 | **0.231** | 2 | 0.161 | 0.155 |
| `ehsm-opt-2` | 3 | 0.017 | **0.143** | 0.017 | **0.161** | 2 | 1.986 | 1.989 |

### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint

| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `3 / 0 / 0` | **5/5** | 0.75 | 0.76 | 1.43 | **0.90** | 0.90 | **+18.90%** (`+0.14 ms`) | **1.60x** | `2104.7 -> 2116.7 KiB` (**+0.57%**) | `1303 B + 1544 B` |
| `signal-cds` | `5 / 1 / 0` | **5/5** | 439.48 | 437.21 | 438.75 | **438.05** | 438.14 | **+0.19%** (`+0.84 ms`) | **1.00x** | `140.3 -> 155.8 KiB` (**+11.06%**) | `4568 B + 5072 B` |
| `sgxwallet` | `14 / 0 / 4` | **5/5** | 42.05 | 36.05 | 42.17 | **36.60** | 36.70 | **+1.54%** (`+0.55 ms`) | **1.15x** | `2722.2 -> 2818.2 KiB` (**+3.52%**) | `4458 B + 6280 B` |
| `ehsm` | `14 / 16 / 2` | **5/5** | 2.24 | 2.23 | 17.48 | **4.44** | 4.43 | **+98.89%** (`+2.21 ms`) | **3.94x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10206 B + 11696 B` |
| `ehsm-opt-1` | `14 / 3 / 2` | **5/5** | 2.18 | 2.16 | 11.62 | **3.45** | 3.45 | **+60.06%** (`+1.30 ms`) | **3.37x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10250 B + 11728 B` |
| `ehsm-opt-2` | `14 / 3 / 2` | **5/5** | 2.18 | 2.16 | 11.75 | **3.06** | 3.06 | **+41.14%** (`+0.89 ms`) | **3.85x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `6117 B + 7832 B` |

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
