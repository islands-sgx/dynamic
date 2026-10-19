# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)

All tables in this document are generated automatically from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.

- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)
- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `02c08eb5256d7bb8cbd92fd6afadd06f170486854f748a3c95171577ebb97576`
- **Reproducible Raw Trace Archive**: `experiments/latest_traces_archive.tar.gz` (`1205 traces`, SHA-256 `5ee76ae7946b96e816bde56fe5116457268f5717a5ab3bc315c88e72bf5e8765`, per-trace index in `experiments/traces_manifest.json`)
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

### 8-Challenge 2-Field SGX Enclaves (`C1..C8`): Public Dev Set (`dev`) & Frozen Blind Exam Set (`blind_exam`) across 5 Random Seeds (`101..105`, Budget = `68` Enclaves)

- **Unified Exploration Kernel (`tools/exploration_kernel.py`)**: All 4 challenge enclaves and all 6 real targets execute the exact same `ExplorationKernel` implementation.
- **8 Structural Challenges across 2 Fields (`C1..C8`)**:
  - `C1`: Non-last Field selector delayed stateful counter (`> 16` calls: `>= 18..22`);
  - `C2`: Overwriting configuration setter (`set_scalar` insert-before-normal is overwritten by the host's normal call and fails; requires in-place `replace_scalar`);
  - `C3`: Non-monotonic S0 length rejection hole (`64..256` / `64..512` rejected; `>= 1024` / `>= 4096` succeeds);
  - `C4`: Joint 2-parameter predicate (control scalar + buffer byte perturbation);
  - `C5`: Identical seed page set with latent state active only at the **3rd (`sseq=2`) or 4th (`sseq=3`)** call position;
  - `C6`: Cross-buffer content slice relation (`aux_buf[0..11] == in_buf[off..off+11]`) + in-enclave sliding-window overlap;
  - `C7`: Authenticated opaque object producer-consumer chain (64-bit keyed MAC under per-boot `sgx_read_rand` secret; consumer rejects forged tokens; requires in-place `replace_scalar` on producer with ABI writeback to host buffer);
  - `C8`: Multi-Field + `> 4`-page (`6..8` pages) heap object where seed calls only touch page 0 (head) and delayed operations touch the tail page (`offset 5..7 * 4096`).
- **Strict Dev vs Blind Exam Split**: `challenge-bench` and `challenge-bench-perm` form the development set (`dev`). After freezing `ExplorationKernel` (`COMMIT_2_SHA = a7c9216`), `challenge-exam-a` and `challenge-exam-b` (`blind_exam`, with swapped Field order, non-zero init index, reversed data layout, and `sseq=2/3` latent positions) were evaluated across 5 seeds (`101..105`) without re-tuning.

| Enclave (`Split`) | Mode | Enclave Budget | Mean ECALLs (`5` Seeds) | Mean Wall-Clock (s) | Discovery Curve (`@20 -> @40 -> @68` Enclaves) | Per-Seed Solved (`101..105`, out of `8`) | **Mean Solved (`min..max`)** | **Mean Hold-Out Missed Pages** |
|---|---|---:|---:|---:|---|---|---|---:|
| `challenge-bench` (`dev`) | **`S0` (Seed Only)** | 1 | 9 | 0.06s | `0.0 -> 0.0 -> 0.0` | `all: 0/8` | **0.00 / 8** | **5.00** |
| `challenge-bench` (`dev`) | **`fixed_round_robin`** | 68 | 1852.4 | 5.84s | `3.6 -> 5.4 -> 6.0` | `101:5, 102:5, 103:7, 104:6, 105:7` | **6.00 / 8** (`5..7`) | **0.40** |
| `challenge-bench` (`dev`) | **`feedback_guided`** | 68 | 640.2 | 4.26s | `3.0 -> 4.8 -> 8.0` | `101:8, 102:8, 103:8, 104:8, 105:8` | **8.00 / 8** (`8..8`) | **0.00** |
| `challenge-bench-perm` (`dev`) | **`S0` (Seed Only)** | 1 | 9 | 0.06s | `0.0 -> 0.0 -> 0.0` | `all: 0/8` | **0.00 / 8** | **10.00** |
| `challenge-bench-perm` (`dev`) | **`fixed_round_robin`** | 68 | 1936.0 | 4.64s | `4.4 -> 5.6 -> 6.8` | `101:8, 102:6, 103:5, 104:8, 105:7` | **6.80 / 8** (`5..8`) | **1.20** |
| `challenge-bench-perm` (`dev`) | **`feedback_guided`** | 68 | 635.0 | 4.30s | `3.2 -> 5.4 -> 8.0` | `101:8, 102:8, 103:8, 104:8, 105:8` | **8.00 / 8** (`8..8`) | **0.00** |
| `challenge-exam-a` (`blind_exam`) | **`S0` (Seed Only)** | 1 | 9 | 0.06s | `0.0 -> 0.0 -> 0.0` | `all: 0/8` | **0.00 / 8** | **10.00** |
| `challenge-exam-a` (`blind_exam`) | **`fixed_round_robin`** | 68 | 1885.0 | 4.56s | `2.6 -> 2.6 -> 5.2` | `101:4, 102:5, 103:6, 104:6, 105:5` | **5.20 / 8** (`4..6`) | **3.60** |
| `challenge-exam-a` (`blind_exam`) | **`feedback_guided`** | 68 | 634.6 | 4.27s | `2.8 -> 4.0 -> 7.6` | `101:6, 102:8, 103:8, 104:8, 105:8` | **7.60 / 8** (`6..8`) | **0.60** |
| `challenge-exam-b` (`blind_exam`) | **`S0` (Seed Only)** | 1 | 11 | 0.06s | `0.0 -> 0.0 -> 0.0` | `all: 0/8` | **0.00 / 8** | **9.00** |
| `challenge-exam-b` (`blind_exam`) | **`fixed_round_robin`** | 68 | 1929.0 | 4.60s | `1.6 -> 3.6 -> 5.8` | `101:5, 102:5, 103:6, 104:6, 105:7` | **5.80 / 8** (`5..7`) | **2.80** |
| `challenge-exam-b` (`blind_exam`) | **`feedback_guided`** | 68 | 695.2 | 4.34s | `2.2 -> 3.0 -> 7.6` | `101:6, 102:8, 103:8, 104:8, 105:8` | **7.60 / 8** (`6..8`) | **0.40** |

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
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 89p / 95e | 92p (`+3p`) | **92p** (`+3p`) | **+0p / +0e** | +92p | **184p** | 2349p | **92.17%** |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 89p / 95e | 89p (`+0p`) | **89p** (`+0p`) | **+0p / +0e** | +89p | **178p** | 2349p | **92.42%** |
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

### Two-Tier SM4 Producer-Consumer Accounting & Onboarding Cost Summary

| Target | Accounting Tier | Seed Workflow Provided | Hold-Out Tested (`--sm4-check`) | Validator Verdict | Uncovered Pages / Structural Explanation |
|---|---|---|---|---|---|
| `ehsm-opt-1` | **Tier 1 (Seed Coverage)** | Default AES-256 + legal `--sm4-check` seed (`+4` effects) | `create_key(EH_SM4_CTR) -> generate_datakey(sm4_cmk)` | **`PASS`** | **0 uncovered pages** (verifies full capture, merge, and protection when seeded) |
| `ehsm-opt-1` | **Tier 2 (AES-Only Seed Discovery)** | Default AES-256 host seed only | `create_key(EH_SM4_CTR) -> generate_datakey(sm4_cmk)` | **`FAIL`** | **4 uncovered effects** (`UNCOVERED_PAGE_0x1d3000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x21e000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x285000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x286000_IN_0x2c6ee760c60f6016...`): requires 3-field coupled struct change (`keyspec=20, keybloblen=64, cmk_size=80`) inside `ehsm_keyblob_t` |
| `ehsm-opt-2` | **Tier 1 (Seed Coverage)** | Default AES-256 + legal `--sm4-check` seed (`+14` effects) | `create_key(EH_SM4_CTR) -> generate_datakey(sm4_cmk)` | **`PASS`** | **0 uncovered pages** (verifies full capture, merge, and protection when seeded) |
| `ehsm-opt-2` | **Tier 2 (AES-Only Seed Discovery)** | Default AES-256 host seed only | `create_key(EH_SM4_CTR) -> generate_datakey(sm4_cmk)` | **`FAIL`** | **14 uncovered effects** (`UNCOVERED_PAGE_0x5b000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x89000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x93000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x184000_IN_0x61a6007dac8ab670...`): requires 3-field coupled struct change (`keyspec=20, keybloblen=64, cmk_size=80`) inside `ehsm_keyblob_t` |

- **Target Onboarding Cost Summary (Zero Sample-Name Branches in Explorer)**:
  - `qe3`: `1` Field annotation (`ATFIELD`), `1` selector in `selectors.json`, `0` explorer lines changed;
  - `signal-cds`: `1` Field annotation, `1` selector in `selectors.json`, `0` explorer lines changed;
  - `sgxwallet`: `5` Field annotations, `7` selectors in `selectors.json`, `0` explorer lines changed (`CALL_ONCE` abort on `ecall 2/3` detected automatically at runtime);
  - `ehsm / ehsm-opt-1 / ehsm-opt-2` (single application, 3-variant ablation): `4` Field annotations, `5` selectors in `selectors.json`, `0` explorer lines changed;
  - `challenge-bench / challenge-bench-perm` (2 synthetic challenge enclaves): `1` Field annotation, `4` selectors in `selectors.json`, `0` explorer lines changed.

## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)

| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |
|---|---|---:|---|---|---|---:|---|---|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 0/15 (`3 / 5`) | **0/15** (`3 / 3`) | 0 (`max=0p`) | 0/15 (`3 / 3`) | 0 (`max=0p`) | `1,380,152` -> **`168,580`** -> `156,156` |
| `signal-cds` | `sabd_lookup_hash` | 25 | 16/25 (`0 / 11`) | **25/25** (`0 / 0`) | 0 (`max=0p`) | 25/25 (`0 / 0`) | 0 (`max=0p`) | `1,271,488` -> **`649,538`** -> `644,562` |
| `sgxwallet` | `generate_sek_field` | 5 | 0/5 (`13 / 15`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,324,578` -> **`223,220`** -> `221,270` |
| `sgxwallet` | `set_sek_field` | 5 | 0/5 (`13 / 16`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,223,534` -> **`231,800`** -> `214,514` |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 0/5 (`22 / 26`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,715,086` -> **`203,708`** -> `194,738` |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 0/5 (`17 / 22`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,068,012` -> **`119,932`** -> `122,650` |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 0/50 (`16 / 23`) | **50/50** (`0 / 0`) | 0 (`max=0p`) | 50/50 (`0 / 0`) | 0 (`max=0p`) | `2,025,133` -> **`141,141`** -> `140,366` |
| `ehsm` | `ehsm_generate_datakey` | 5 | 0/5 (`32 / 40`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,797,446` -> **`450,204`** -> `449,382` |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 46`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,870,316` -> **`460,613`** -> `442,615` |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 136`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,889,895` -> **`456,751`** -> `447,536` |
| `ehsm` | `ehsm_create_aes_key` | 5 | 0/5 (`127 / 142`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,427,500` -> **`957,514`** -> `905,546` |
| `ehsm-opt-1` | `ehsm_generate_datakey` | 5 | 0/5 (`38 / 45`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,877,296` -> **`440,166`** -> `448,868` |
| `ehsm-opt-1` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`34 / 44`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,883,664` -> **`449,090`** -> `435,783` |
| `ehsm-opt-1` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 152`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,881,115` -> **`447,381`** -> `443,546` |
| `ehsm-opt-1` | `ehsm_create_aes_key` | 5 | 0/5 (`143 / 147`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,460,124` -> **`969,942`** -> `917,828` |
| `ehsm-opt-2` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`34 / 42`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,821,024` -> **`297,674`** -> `289,550` |
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`35 / 45`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,863,780` -> **`295,972`** -> `294,054` |
| `ehsm-opt-2` | `ehsm_create_aes_key` | 5 | 0/5 (`37 / 44`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,079,854` -> **`376,966`** -> `357,442` |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 5 | 0/5 (`35 / 39`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,888,252` -> **`294,812`** -> `290,562` |

- **Exact Per-Observation Totals Across the 16 Non-`ENCLU` Field Instances (295 total Field entries across 5 rounds)**:
  - **Group B (`dynamic_xr`, Default `XR`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.
  - **Group C (`dynamic_refined`, `X-only`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.

## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)

- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).
- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).

### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown

| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 3 | **5/5** | 251.7 | **39.0** | 259.6 | +8.0 | **298.9** | **+18.79%** (`+47.3 µs`) | 476.7 (`+225.0 µs`) | **4.76x** |
| `signal-cds` | 5 | **5/5** | 88361.7 | **128.7** | 87462.9 | -898.8 | **87591.7** | **-0.87%** (`-770.0 µs`) | 87793.8 (`-567.9 µs`) | **1.00x** |
| `sgxwallet` | 14 | **5/5** | 1348.2 | **34.9** | 1363.9 | +15.7 | **1398.8** | **+3.75%** (`+50.6 µs`) | 1797.5 (`+449.3 µs`) | **8.89x** |
| `ehsm` | 14 | **5/5** | 141.3 | **70.7** | 145.4 | +4.1 | **216.6** | **+53.25%** (`+75.3 µs`) | 706.8 (`+565.5 µs`) | **7.51x** |
| `ehsm-opt-1` | 14 | **5/5** | 141.7 | **72.6** | 146.1 | +4.4 | **218.9** | **+54.47%** (`+77.2 µs`) | 717.2 (`+575.6 µs`) | **7.46x** |
| `ehsm-opt-2` | 14 | **5/5** | 11.6 | **50.0** | 14.9 | +3.3 | **65.1** | **+461.41%** (`+53.5 µs`) | 592.2 (`+580.6 µs`) | **10.85x** |

### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)

| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 0 | 0.000 | 0.000 |
| `signal-cds` | 1 | 0.005 | **0.122** | 0.005 | **0.128** | 0 | 0.000 | 0.000 |
| `sgxwallet` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 4 | 17.071 | 17.083 |
| `ehsm` | 16 | 0.092 | **1.152** | 0.097 | **1.249** | 2 | 0.157 | 0.157 |
| `ehsm-opt-1` | 3 | 0.017 | **0.209** | 0.017 | **0.228** | 2 | 0.173 | 0.156 |
| `ehsm-opt-2` | 3 | 0.017 | **0.143** | 0.017 | **0.160** | 2 | 1.998 | 1.990 |

### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint

| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `3 / 0 / 0` | **5/5** | 0.75 | 0.75 | 1.43 | **0.90** | 0.90 | **+18.79%** (`+0.14 ms`) | **1.59x** | `2104.7 -> 2116.7 KiB` (**+0.57%**) | `1303 B + 1544 B` |
| `signal-cds` | `5 / 1 / 0` | **5/5** | 437.19 | 441.81 | 439.19 | **438.09** | 438.13 | **-0.84%** (`-3.73 ms`) | **1.00x** | `140.3 -> 155.8 KiB` (**+11.06%**) | `4568 B + 5072 B` |
| `sgxwallet` | `14 / 0 / 4` | **5/5** | 42.65 | 35.93 | 42.25 | **36.70** | 36.62 | **+2.14%** (`+0.77 ms`) | **1.15x** | `2722.2 -> 2818.2 KiB` (**+3.52%**) | `4458 B + 6280 B` |
| `ehsm` | `14 / 16 / 2` | **5/5** | 2.25 | 2.23 | 17.41 | **4.44** | 4.43 | **+99.29%** (`+2.21 ms`) | **3.93x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10206 B + 11696 B` |
| `ehsm-opt-1` | `14 / 3 / 2` | **5/5** | 2.20 | 2.19 | 11.54 | **3.45** | 3.46 | **+57.67%** (`+1.26 ms`) | **3.35x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10250 B + 11728 B` |
| `ehsm-opt-2` | `14 / 3 / 2` | **5/5** | 2.19 | 2.18 | 11.62 | **3.06** | 3.07 | **+40.77%** (`+0.89 ms`) | **3.79x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `6117 B + 7832 B` |

## 6. One-Page Methodology & Boundary Specification: Why It Works, When It Can Miss, and What Each Experiment Verifies

### 6.1 Why the Prototype Works (Three Grounded Pillars)
1. **ABI-Typed & Capacity-Safe In-Place / Isolated Interventions (`edl_harness.py` + `interpose_interventions.h`)**: Compiler-exact EDL marshaling schemas (`ms_*` offsets, sizes, pointer directions, and `count=/size=` bindings) ensure that every mutation (`replace_scalar`, `replace_xor`, `scale_bound_v2`, `joint_scalar_xor`, `aliased_pair`) respects C ABI memory bounds and refuses in-place output replacements when `[out]/[inout]` capacity would be exceeded.
2. **Executable Host Prefixes & True In-Place Call Replacement (`replace_scalar` / `replace_xor`)**: Instead of fabricating opaque handles, keys, or MAC-authenticated blobs offline, each trial executes a fresh enclave from the beginning of the host workflow, replaces parameters in-place at the target call position (executing once and writing ABI return values and `[out]/[inout]` buffers back to the host), and lets the host's own logic carry valid handles/tokens into downstream Fields.
3. **Greybox Concrete Page-Set Feedback + Anti-Starvation Base Scheduling (`ExplorationKernel`)**: Feedback tracks concrete `frozenset((page_rva, effect))` sets (ignoring random output bytes and never collapsing distinct call positions that happen to touch the same setup pages). Once a parameter slot satisfies its target branch or a selector fails `S0` integrity/repeatability checks, remaining redundant candidates on that slot are demoted to `low_priority_queue`, reallocating budget to unexplored call positions (`sseq=0, 1, 2, 3`) and multi-selector history depths.

### 6.2 Under What Conditions It Can Miss (Explicit Soundness Boundaries)
- **Measurement Soundness vs Whole-Program Input Coverage**: Hardware 4-Gate AEP page-table `A/D` tracking with single-page `X/R/W` fault calibration and `AEX-Notify` fail-stop guarantees that *every page touched during an executed run is measured*, and *any un-readied page touched at runtime triggers deterministic fail-stop (`0x1006`)*. However, finite dynamic exploration does **not** prove coverage over all future inputs, secrets, or un-seeded protocol states.
- **Specific Structural Conditions Where Dynamic Exploration Can Miss**:
  1. **Multi-Field Coupled Struct Invariants in Producer Calls (Demonstrated by `eHSM` SM4 Tier 2)**: When a producer ECALL (`enclave_create_key`) takes a nested C struct (`ehsm_keyblob_t`) requiring simultaneous coordinated updates to multiple internal struct fields (`metadata.keyspec = 20`, `keybloblen = 64`) and an outer EDL size scalar (`cmk_size = 80`) before sealing an authenticated blob, single-scalar replacement does not synthesize the valid struct tuple without a legal seed or struct-binding spec (resulting in the `4` / `14` uncovered pages caught by Tier 2).
  2. **Narrow Constants Outside the Declared Enum/Boundary Domain**: Predicates checking arbitrary 32/64-bit magic numbers outside the declared domain `{0, 1, 2, 3, 4, 8, 16, 99}` and page-crossing length progression `[16..262144]` cannot be guessed by black-box/grey-box enumeration without symbolic or taint guidance.
  3. **Deep History or Call Positions Beyond the Declared Budget Ceiling**: When the enclave creation budget (`68` on challenge enclaves) expires before all `replace_prefix` / `boundary` slots are exhausted (as seen on `seed=101` of `challenge-exam-a` and `challenge-exam-b`, which solved `6/8` before budget cutoff), unvisited candidates remain in `unexplored_frontier`.

### 6.3 What Each Experiment Verifies
| Experiment / Artifact | Specific Claim Verified | Where Recorded |
|---|---|---|
| `test_exploration_kernel_and_replace.py` | Single-round feedback deterministically alters subsequent scheduling; `replace_scalar` executes once and preserves overwriting-setter (`C2`) and keyed-MAC token (`C7`) state where `set_scalar` fails. | Section 1A & `tests/` |
| `challenge-bench` & `challenge-bench-perm` (`dev`, 5 seeds) | `ExplorationKernel` (`feedback_guided`) solves `8.0/8` across all 5 seeds in `~635-640` ECALLs vs `fixed_round_robin`'s `6.0-6.8/8` in `1936` ECALLs. | Section 1A & `strategy_comparison.json` |
| `challenge-exam-a` & `challenge-exam-b` (`blind_exam`, 5 seeds, frozen kernel) | Without re-tuning `ExplorationKernel` (`COMMIT_2_SHA = a7c9216`), `feedback_guided` achieves `7.6/8` mean (`8/8` on 4/5 seeds) in `~635-695` ECALLs vs `fixed_round_robin`'s `5.2-5.8/8` in `~1885-1929` ECALLs. | Section 1A & `strategy_comparison.json` |
| `qe3`, `signal-cds`, `sgxwallet`, `ehsm` (`opt-1/2`) Migration | The exact same frozen `ExplorationKernel` closes all 6 real targets (`5/5` production acceptance, `295/295` clean `0`-rewalk observations in Group B). | Sections 1B, 2, 3, 4 |
| `ehsm-opt-1/2` Two-Tier SM4 Accounting | Tier 1 verifies `PASS` (`0` misses) when SM4 is seeded; Tier 2 verifies that `validate_run_result()` catches the exact `4` / `14` uncovered SM4 pages when only AES-256 is seeded. | Section 2 (`sm4_two_tier_accounting`) |

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
