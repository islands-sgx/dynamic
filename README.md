# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)

All tables in this document are generated automatically from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.

- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)
- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `0770a77da1a9b9211c3980aaa2aff9105b6c9c5a44e8ef7a314f62d99827cfb7`
- **Reproducible Raw Trace Archive**: `experiments/latest_traces_archive.tar.gz` (`1272 traces`, SHA-256 `6dd2c8726792286467554f64f6a403aaddc123683ac4428205cdded98962d968`, per-trace index in `experiments/traces_manifest.json`)
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

### 8-Challenge 2-Field SGX Enclaves (`C1..C8`): Dev (`dev`), Post-Revision Regression (`post_revision_regression`), & Frozen Blind Exam (`blind_exam`) across 5 Random Seeds (`101..105`)

- **Unified Exploration Kernel (`tools/exploration_kernel.py`)**: All challenge enclaves and all 6 real targets execute the exact same `ExplorationKernel` implementation.
- **Three-Mode Attribution on Shared Candidate Domain**: `fixed_round_robin` (1-for-1 family rotation), `static_priority_no_feedback` (same candidate pool & static structural priority order as `feedback_guided`, but with runtime feedback disabled), and `feedback_guided` (runtime greybox feedback + active-slot reprioritization to `secondary_branch_queue` + state/effect follow-up spawning).
- **8 Structural Challenges across 2 Fields (`C1..C8`)**:
  - `C1`: Non-last Field selector delayed stateful counter (`> 16` calls: `>= 18..22`);
  - `C2`: Overwriting configuration setter (`set_scalar` insert-before-normal is overwritten by the host's normal call and fails; requires in-place `replace_scalar`);
  - `C3`: Non-monotonic S0 length rejection hole (`64..256` / `64..512` rejected; `>= 1024` / `>= 4096` succeeds);
  - `C4`: Joint 2-parameter predicate (control scalar + buffer byte perturbation);
  - `C5`: Identical seed page set with latent state active only at the **3rd (`sseq=2`) or 4th (`sseq=3`)** call position;
  - `C6`: Cross-buffer content slice relation (`aux_buf[0..11] == in_buf[off..off+11]`) + in-enclave sliding-window overlap;
  - `C7`: Authenticated opaque object producer-consumer chain using Intel SGX SDK `sgx_rijndael128_cmac_msg` (128-bit AES-CMAC under per-boot `sgx_read_rand` key);
  - `C8`: Multi-Field + `> 4`-page (`6..8` pages) heap object where seed calls only touch page 0 (head) and delayed operations touch the tail page (`offset 5..7 * 4096`).
- **Strict Dataset Split & Freeze Provenance**: `challenge-bench` and `challenge-bench-perm` form the development set (`dev`); `challenge-exam-a` and `challenge-exam-b` (inspected before the final kernel revision) are classified as `post_revision_regression`. After freezing the kernel, candidate generator, adapter, and budget at commit `fc153e66ec45217ec77422da9078bab3e9592d46`, brand-new unseen exam enclaves (`challenge-exam-c`, `challenge-exam-d`, including a multi-branch parameter slot where two distinct values on the same parameter unlock two different challenge pages) were created and evaluated as `blind_exam`.

| Enclave (`Split`) | Mode | Expl. Enclaves (`+Conf = Total`) | Mean Expl. ECALLs (`+Conf = Total`) | Mean Wall-Clock (`Expl / Total`) | Discovery Curve (`@20 -> @40 -> @68`) | Per-Seed `Obs/Conf` (`101..105`) | **Mean `Obs / Conf` (`min..max`)** | **Mean Ref Hold-Out Missed (`Field-Eff / Field-Page`)** |
|---|---|---:|---:|---:|---|---|---|---:|
| `challenge-bench` (`dev`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.06s / 0.06s` | `0.0 -> 0.0 -> 0.0` | `all: 0/0` | **0.00 / 0.00** | **16.0e / 9.0p** |
| `challenge-bench` (`dev`) | **`fixed_round_robin`** | `68 (+6.0 = 74.0)` | `3204.0 (+78.8 = 3282.8)` | `5.24s / 5.66s` | `3.6 -> 4.4 -> 6.0` | `101:5/5, 102:5/5, 103:7/7, 104:6/6, 105:7/7` | **6.00 / 6.00** (`5..7`) | **3.20e / 2.00p** |
| `challenge-bench` (`dev`) | **`static_priority_no_feedback`** | `68 (+7.0 = 75.0)` | `912.0 (+83.8 = 995.8)` | `4.72s / 5.21s` | `3.0 -> 4.2 -> 7.0` | `101:7/7, 102:6/6, 103:8/8, 104:7/7, 105:7/7` | **7.00 / 7.00** (`6..8`) | **1.40e / 1.00p** |
| `challenge-bench` (`dev`) | **`feedback_guided`** | `68 (+7.4 = 75.4)` | `634.2 (+87.0 = 721.2)` | `4.59s / 5.10s` | `3.0 -> 4.2 -> 7.4` | `101:8/8, 102:7/7, 103:8/8, 104:6/6, 105:8/8` | **7.40 / 7.40** (`6..8`) | **0.80e / 0.60p** |
| `challenge-bench-perm` (`dev`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.07s / 0.07s` | `0.0 -> 0.0 -> 0.0` | `all: 0/0` | **0.00 / 0.00** | **18.0e / 10.0p** |
| `challenge-bench-perm` (`dev`) | **`fixed_round_robin`** | `68 (+6.8 = 74.8)` | `3204.0 (+86.4 = 3290.4)` | `5.24s / 5.71s` | `4.4 -> 4.6 -> 6.8` | `101:8/8, 102:6/6, 103:5/5, 104:8/8, 105:7/7` | **6.80 / 6.80** (`5..8`) | **2.00e / 1.20p** |
| `challenge-bench-perm` (`dev`) | **`static_priority_no_feedback`** | `68 (+7.2 = 75.2)` | `912.0 (+91.6 = 1003.6)` | `4.67s / 5.17s` | `3.2 -> 5.4 -> 7.2` | `101:8/8, 102:7/7, 103:7/7, 104:8/8, 105:6/6` | **7.20 / 7.20** (`6..8`) | **1.00e / 0.80p** |
| `challenge-bench-perm` (`dev`) | **`feedback_guided`** | `68 (+7.6 = 75.6)` | `636.2 (+94.8 = 731.0)` | `4.57s / 5.09s` | `3.2 -> 5.4 -> 7.6` | `101:8/8, 102:8/8, 103:7/7, 104:8/8, 105:7/7` | **7.60 / 7.60** (`7..8`) | **0.40e / 0.40p** |
| `challenge-exam-a` (`post_revision_regression`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.07s / 0.07s` | `0.0 -> 0.0 -> 0.0` | `all: 0/0` | **0.00 / 0.00** | **18.0e / 10.0p** |
| `challenge-exam-a` (`post_revision_regression`) | **`fixed_round_robin`** | `68 (+5.0 = 73.0)` | `3159.0 (+53.8 = 3212.8)` | `5.22s / 5.56s` | `2.6 -> 2.6 -> 5.0` | `101:4/4, 102:5/5, 103:5/5, 104:6/6, 105:5/5` | **5.00 / 5.00** (`4..6`) | **6.80e / 3.80p** |
| `challenge-exam-a` (`post_revision_regression`) | **`static_priority_no_feedback`** | `68 (+5.6 = 73.6)` | `881.0 (+60.4 = 941.4)` | `4.54s / 4.91s` | `2.6 -> 3.4 -> 5.6` | `101:4/4, 102:7/7, 103:6/6, 104:6/6, 105:5/5` | **5.60 / 5.60** (`4..7`) | **4.20e / 2.80p** |
| `challenge-exam-a` (`post_revision_regression`) | **`feedback_guided`** | `68 (+7.2 = 75.2)` | `636.6 (+70.6 = 707.2)` | `4.59s / 5.07s` | `2.4 -> 3.6 -> 7.2` | `101:5/5, 102:8/8, 103:8/8, 104:8/8, 105:7/7` | **7.20 / 7.20** (`5..8`) | **1.80e / 1.00p** |
| `challenge-exam-b` (`post_revision_regression`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `11 (+0 = 11)` | `0.07s / 0.07s` | `0.0 -> 0.0 -> 0.0` | `all: 0/0` | **0.00 / 0.00** | **16.0e / 9.0p** |
| `challenge-exam-b` (`post_revision_regression`) | **`fixed_round_robin`** | `68 (+5.6 = 73.6)` | `3201.0 (+61.0 = 3262.0)` | `5.33s / 5.73s` | `1.6 -> 3.6 -> 5.6` | `101:4/4, 102:5/5, 103:6/6, 104:6/6, 105:7/7` | **5.60 / 5.60** (`4..7`) | **5.40e / 3.00p** |
| `challenge-exam-b` (`post_revision_regression`) | **`static_priority_no_feedback`** | `68 (+6.8 = 74.8)` | `935.0 (+71.4 = 1006.4)` | `4.77s / 5.25s` | `2.0 -> 3.0 -> 6.8` | `101:5/5, 102:7/7, 103:7/7, 104:8/8, 105:7/7` | **6.80 / 6.80** (`5..8`) | **2.20e / 1.40p** |
| `challenge-exam-b` (`post_revision_regression`) | **`feedback_guided`** | `68 (+7.2 = 75.2)` | `688.8 (+74.4 = 763.2)` | `4.71s / 5.21s` | `2.2 -> 3.0 -> 7.2` | `101:6/6, 102:7/7, 103:7/7, 104:8/8, 105:8/8` | **7.20 / 7.20** (`6..8`) | **1.00e / 0.80p** |
| `challenge-exam-c` (`blind_exam`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.07s / 0.07s` | `0.0 -> 0.0 -> 0.0` | `all: 0/0` | **0.00 / 0.00** | **18.0e / 10.0p** |
| `challenge-exam-c` (`blind_exam`) | **`fixed_round_robin`** | `68 (+6.2 = 74.2)` | `3159.0 (+62.8 = 3221.8)` | `5.29s / 5.73s` | `2.2 -> 4.4 -> 6.2` | `101:6/6, 102:5/5, 103:6/6, 104:7/7, 105:7/7` | **6.20 / 6.20** (`5..7`) | **4.40e / 2.40p** |
| `challenge-exam-c` (`blind_exam`) | **`static_priority_no_feedback`** | `68 (+7.4 = 75.4)` | `881.0 (+72.2 = 953.2)` | `4.69s / 5.19s` | `2.8 -> 3.8 -> 7.4` | `101:8/8, 102:8/8, 103:6/6, 104:8/8, 105:7/7` | **7.40 / 7.40** (`6..8`) | **0.80e / 0.60p** |
| `challenge-exam-c` (`blind_exam`) | **`feedback_guided`** | `68 (+8.0 = 76.0)` | `633.8 (+76.0 = 709.8)` | `4.45s / 4.99s` | `3.2 -> 4.4 -> 8.0` | `101:8/8, 102:8/8, 103:8/8, 104:8/8, 105:8/8` | **8.00 / 8.00** (`8..8`) | **0.00e / 0.00p** |
| `challenge-exam-d` (`blind_exam`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `11 (+0 = 11)` | `0.07s / 0.07s` | `0.0 -> 0.0 -> 0.0` | `all: 0/0` | **0.00 / 0.00** | **16.0e / 9.0p** |
| `challenge-exam-d` (`blind_exam`) | **`fixed_round_robin`** | `68 (+5.6 = 73.6)` | `3199.0 (+59.8 = 3258.8)` | `5.33s / 5.72s` | `2.2 -> 3.2 -> 5.6` | `101:6/6, 102:5/5, 103:5/5, 104:6/6, 105:6/6` | **5.60 / 5.60** (`5..6`) | **5.60e / 3.00p** |
| `challenge-exam-d` (`blind_exam`) | **`static_priority_no_feedback`** | `68 (+6.0 = 74.0)` | `935.0 (+65.2 = 1000.2)` | `4.69s / 5.11s` | `2.6 -> 3.6 -> 6.0` | `101:5/5, 102:6/6, 103:7/7, 104:5/5, 105:7/7` | **6.00 / 6.00** (`5..7`) | **4.20e / 2.40p** |
| `challenge-exam-d` (`blind_exam`) | **`feedback_guided`** | `68 (+6.8 = 74.8)` | `696.2 (+72.6 = 768.8)` | `4.68s / 5.14s` | `2.4 -> 3.6 -> 6.8` | `101:7/7, 102:6/6, 103:8/8, 104:6/6, 105:7/7` | **6.80 / 6.80** (`6..8`) | **2.40e / 1.40p** |

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

### Two-Tier SM4 Producer-Consumer Accounting (Independent Artifact Generation & Protected Verification) & Onboarding Cost

| Target | Accounting Tier | Frozen Artifact Hashes (`workset / signed_aex1 / ready_bin`) | Fresh Hold-Out Coverage (`ipi=7`) | Fresh 4-Gate Diagnostic (`clean 0-rewalk`) | Fresh Protected `AEX1` Execution (`ReadyTable`) | Overall Verdict & Explanation |
|---|---|---|---|---|---|---|
| `ehsm-opt-1` | **Tier 1 (`sm4_seeded_xr`)** | `34d69ee4 / 6b3ba134 / 60e70591` (`+4e` over AES) | **`PASS`** (`0` unseen) | **`PASS`** (`15/15 0-rewalk`) | **`PASS`** (`rc=0, PASS`) | **`PASS`**: Independent signed enclave & ReadyTable built from seed trace and verified on fresh runs |
| `ehsm-opt-1` | **Tier 2 (`dynamic_xr` AES-only)** | `9be55c1f / 6db6f5fd / 0549004e` (AES-256 seed only) | **`FAIL`** (`4` uncovered) | N/A (coverage failed) | N/A (coverage failed) | **`FAIL`**: Catches **4 uncovered SM4 effects** (`UNCOVERED_PAGE_0x1d3000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x21e000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x285000_IN_0x2c6ee760c60f6016...`); requires coupled 3-field struct change (`keyspec=20, keybloblen=64, cmk_size=80`) |
| `ehsm-opt-2` | **Tier 1 (`sm4_seeded_xr`)** | `984d1f6e / 494ea552 / 51b0175a` (`+21e` over AES) | **`PASS`** (`0` unseen) | **`PASS`** (`15/15 0-rewalk`) | **`PASS`** (`rc=0, PASS`) | **`PASS`**: Independent signed enclave & ReadyTable built from seed trace and verified on fresh runs |
| `ehsm-opt-2` | **Tier 2 (`dynamic_xr` AES-only)** | `97f0de0a / b11491f1 / b542c015` (AES-256 seed only) | **`FAIL`** (`14` uncovered) | N/A (coverage failed) | N/A (coverage failed) | **`FAIL`**: Catches **14 uncovered SM4 effects** (`UNCOVERED_PAGE_0x5b000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x89000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x93000_IN_0x61a6007dac8ab670...`); requires coupled 3-field struct change (`keyspec=20, keybloblen=64, cmk_size=80`) |

- **Target Onboarding Cost Summary (Zero Sample-Name Branches in Explorer)**:
  - `qe3`: `1` Field annotation (`ATFIELD`), `1` selector in `selectors.json`, `0` explorer lines changed;
  - `signal-cds`: `1` Field annotation, `1` selector in `selectors.json`, `0` explorer lines changed;
  - `sgxwallet`: `5` Field annotations, `7` selectors in `selectors.json`, `0` explorer lines changed (`CALL_ONCE` abort on `ecall 2/3` detected automatically at runtime);
  - `ehsm / ehsm-opt-1 / ehsm-opt-2` (single application, 3-variant ablation): `4` Field annotations, `5` selectors in `selectors.json`, `0` explorer lines changed;
  - `challenge-bench / challenge-bench-perm` (2 synthetic challenge enclaves): `1` Field annotation, `4` selectors in `selectors.json`, `0` explorer lines changed.

## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)

| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |
|---|---|---:|---|---|---|---:|---|---|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 0/15 (`3 / 6`) | **0/15** (`3 / 3`) | 0 (`max=0p`) | 0/15 (`3 / 3`) | 0 (`max=0p`) | `1,587,088` -> **`189,972`** -> `157,392` |
| `signal-cds` | `sabd_lookup_hash` | 25 | 15/25 (`0 / 13`) | **25/25** (`0 / 0`) | 0 (`max=0p`) | 25/25 (`0 / 0`) | 0 (`max=0p`) | `1,259,514` -> **`636,172`** -> `634,614` |
| `sgxwallet` | `generate_sek_field` | 5 | 0/5 (`11 / 14`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,501,516` -> **`231,976`** -> `212,156` |
| `sgxwallet` | `set_sek_field` | 5 | 0/5 (`11 / 15`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,164,290` -> **`220,260`** -> `221,558` |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 0/5 (`17 / 23`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,930,664` -> **`202,596`** -> `192,468` |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 0/5 (`13 / 17`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,048,450` -> **`128,662`** -> `125,214` |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 0/50 (`15 / 22`) | **50/50** (`0 / 0`) | 0 (`max=0p`) | 50/50 (`0 / 0`) | 0 (`max=0p`) | `2,025,585` -> **`137,613`** -> `139,260` |
| `ehsm` | `ehsm_generate_datakey` | 5 | 0/5 (`37 / 41`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,898,406` -> **`454,510`** -> `451,798` |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 46`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,900,441` -> **`455,266`** -> `437,503` |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`37 / 144`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,894,584` -> **`455,179`** -> `449,312` |
| `ehsm` | `ehsm_create_aes_key` | 5 | 0/5 (`140 / 153`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,363,288` -> **`957,118`** -> `910,526` |
| `ehsm-opt-1` | `ehsm_generate_datakey` | 5 | 0/5 (`36 / 37`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,893,160` -> **`450,400`** -> `444,368` |
| `ehsm-opt-1` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`35 / 46`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,889,388` -> **`457,084`** -> `441,765` |
| `ehsm-opt-1` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`37 / 131`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,883,739` -> **`449,610`** -> `442,982` |
| `ehsm-opt-1` | `ehsm_create_aes_key` | 5 | 0/5 (`142 / 145`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,488,628` -> **`965,648`** -> `922,808` |
| `ehsm-opt-2` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 50`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,842,961` -> **`293,891`** -> `293,033` |
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`34 / 47`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,861,069` -> **`297,994`** -> `296,504` |
| `ehsm-opt-2` | `ehsm_create_aes_key` | 5 | 0/5 (`38 / 40`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,150,450` -> **`379,172`** -> `364,604` |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 5 | 0/5 (`38 / 40`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,855,100` -> **`290,550`** -> `290,670` |

- **Exact Per-Observation Totals Across the 16 Non-`ENCLU` Field Instances (295 total Field entries across 5 rounds)**:
  - **Group B (`dynamic_xr`, Default `XR`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.
  - **Group C (`dynamic_refined`, `X-only`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.

## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)

- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).
- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).

### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown

| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 3 | **5/5** | 250.0 | **39.0** | 260.5 | +10.5 | **299.3** | **+19.76%** (`+49.4 µs`) | 473.1 (`+223.1 µs`) | **4.52x** |
| `signal-cds` | 5 | **5/5** | 87450.5 | **129.3** | 87517.0 | +66.6 | **87646.9** | **+0.22%** (`+196.5 µs`) | 87712.0 (`+261.6 µs`) | **1.33x** |
| `sgxwallet` | 14 | **5/5** | 1351.9 | **35.0** | 1349.6 | -2.4 | **1385.2** | **+2.46%** (`+33.2 µs`) | 1796.8 (`+444.8 µs`) | **13.38x** |
| `ehsm` | 14 | **5/5** | 140.7 | **70.4** | 145.4 | +4.6 | **215.9** | **+53.42%** (`+75.2 µs`) | 708.9 (`+568.2 µs`) | **7.56x** |
| `ehsm-opt-1` | 14 | **5/5** | 142.5 | **72.8** | 145.8 | +3.3 | **218.6** | **+53.44%** (`+76.1 µs`) | 717.9 (`+575.4 µs`) | **7.56x** |
| `ehsm-opt-2` | 14 | **5/5** | 11.6 | **50.2** | 14.9 | +3.3 | **65.1** | **+458.53%** (`+53.4 µs`) | 597.4 (`+585.8 µs`) | **10.97x** |

### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)

| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 0 | 0.000 | 0.000 |
| `signal-cds` | 1 | 0.005 | **0.125** | 0.006 | **0.130** | 0 | 0.000 | 0.000 |
| `sgxwallet` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 4 | 17.091 | 17.070 |
| `ehsm` | 16 | 0.092 | **1.151** | 0.098 | **1.249** | 2 | 0.157 | 0.150 |
| `ehsm-opt-1` | 3 | 0.017 | **0.210** | 0.017 | **0.227** | 2 | 0.154 | 0.150 |
| `ehsm-opt-2` | 3 | 0.017 | **0.144** | 0.017 | **0.162** | 2 | 2.014 | 1.978 |

### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint

| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `3 / 0 / 0` | **5/5** | 0.75 | 0.75 | 1.42 | **0.90** | 0.90 | **+19.76%** (`+0.15 ms`) | **1.58x** | `2104.7 -> 2116.7 KiB` (**+0.57%**) | `1303 B + 1544 B` |
| `signal-cds` | `5 / 1 / 0` | **5/5** | 439.47 | 437.26 | 438.78 | **438.36** | 438.10 | **+0.25%** (`+1.11 ms`) | **1.00x** | `140.3 -> 155.8 KiB` (**+11.06%**) | `4568 B + 5072 B` |
| `sgxwallet` | `14 / 0 / 4` | **5/5** | 42.71 | 36.01 | 42.30 | **36.44** | 36.63 | **+1.18%** (`+0.43 ms`) | **1.16x** | `2722.2 -> 2818.2 KiB` (**+3.52%**) | `4458 B + 6280 B` |
| `ehsm` | `14 / 16 / 2` | **5/5** | 2.23 | 2.23 | 17.46 | **4.43** | 4.42 | **+98.54%** (`+2.20 ms`) | **3.94x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10206 B + 11696 B` |
| `ehsm-opt-1` | `14 / 3 / 2` | **5/5** | 2.17 | 2.17 | 11.55 | **3.44** | 3.45 | **+58.78%** (`+1.28 ms`) | **3.35x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10250 B + 11728 B` |
| `ehsm-opt-2` | `14 / 3 / 2` | **5/5** | 2.18 | 2.19 | 11.71 | **3.05** | 3.06 | **+39.19%** (`+0.86 ms`) | **3.84x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `6117 B + 7832 B` |

## 6. One-Page Methodology & Boundary Specification: Why It Works, When It Can Miss, and What Each Experiment Verifies

### 6.1 Why the Prototype Works (Three Grounded Pillars)
1. **ABI-Typed & Capacity-Safe In-Place / Isolated Interventions (`edl_harness.py` + `interpose_interventions.h`)**: Compiler-exact EDL marshaling schemas (`ms_*` offsets, sizes, pointer directions, and `count=/size=` bindings) ensure that every mutation (`replace_scalar`, `replace_xor`, `scale_bound_v2`, `joint_scalar_xor`, `aliased_pair`) respects C ABI memory bounds and refuses in-place output replacements when `[out]/[inout]` capacity would be exceeded.
2. **Executable Host Prefixes & True In-Place Call Replacement (`replace_scalar` / `replace_xor`)**: Instead of fabricating opaque handles, keys, or MAC-authenticated blobs offline, each trial executes a fresh enclave from the beginning of the host workflow, replaces parameters in-place at the target call position (executing once and writing ABI return values and `[out]/[inout]` buffers back to the host), and lets the host's own logic carry valid handles/tokens into downstream Fields.
3. **Greybox Concrete Page-Set Feedback + Anti-Starvation Base Scheduling (`ExplorationKernel`)**: Feedback tracks concrete `frozenset((page_rva, effect))` sets (ignoring random output bytes and never collapsing distinct call positions that happen to touch the same setup pages). Once a parameter slot satisfies its target branch or a selector fails `S0` integrity/repeatability checks, remaining redundant candidates on that slot are demoted to `low_priority_queue`, reallocating budget to unexplored call positions (`sseq=0, 1, 2, 3`) and multi-selector history depths.

### 6.2 Under What Conditions It Can Miss (Explicit Soundness & Hardware Enforcement Boundaries)
- **Pre-Touch Omission vs `ReadyTable` Permission Enforcement & `AEX-Notify` Fail-Stop**:
  - If a page is omitted from pre-touch and has no cached TLB translation, touching it while its OS page-table entry remains valid (present and accessible) simply triggers a normal hardware page-table walk (setting `A/D` bits) **without causing an AEX or `0x1006` abort**. Therefore, `AEX-Notify` fail-stop cannot by itself serve as an automatic detector for omitted pre-touch pages in unprotected page tables; omitted pre-touch pages are measured by the 4-Gate `S3` `A/D` rewalk diagnostic.
  - Deterministic runtime fail-stop (`0x1006`) occurs only when an actual page fault (e.g., when non-`ReadyTable` pages have their permissions retracted by the kernel readiness module during a protected ECALL, or under explicit single-page retraction fault calibration) or an external interrupt triggers an AEX while `__atfield_active == 1`.
- **Single-Run Measurement Soundness vs Whole-Program Input Coverage**: Hardware 4-Gate AEP page-table `A/D` tracking with single-page `X/R/W` fault calibration guarantees that *every page touched during an executed run is measured*, but finite dynamic exploration does **not** prove coverage over all future inputs, secrets, or un-seeded protocol states.
- **Specific Structural Conditions Where Dynamic Exploration Can Miss**:
  1. **Multi-Field Coupled Struct Invariants in Producer Calls (Demonstrated by `eHSM` SM4 Tier 2)**: When a producer ECALL (`enclave_create_key`) takes a nested C struct (`ehsm_keyblob_t`) requiring simultaneous coordinated updates to multiple internal struct fields (`metadata.keyspec = 20`, `keybloblen = 64`) and an outer EDL size scalar (`cmk_size = 80`) before sealing an authenticated blob, single-scalar replacement does not synthesize the valid struct tuple without a legal seed or struct-binding spec (resulting in the `4` / `14` uncovered pages caught by Tier 2).
  2. **Narrow Constants Outside the Declared Enum/Boundary Domain**: Predicates checking arbitrary 32/64-bit magic numbers outside the declared domain `{0, 1, 2, 3, 4, 8, 16, 99}` and page-crossing length progression `[16..262144]` cannot be guessed by black-box/grey-box enumeration without symbolic or taint guidance.
  3. **Deep History or Call Positions Beyond the Declared Budget Ceiling**: When the enclave creation budget (`68` on challenge enclaves) expires before all `replace_prefix` / `boundary` slots are exhausted (as seen on `seed=101` of `challenge-exam-a` and `challenge-exam-b`, which solved `6/8` before budget cutoff), unvisited candidates remain in `unexplored_frontier`.

### 6.3 What Each Experiment Verifies
| Experiment / Artifact | Specific Claim Verified | Where Recorded |
|---|---|---|
| `test_exploration_kernel_and_replace.py` | Single-round feedback on real `ehsm` target alters subsequent scheduling; state novelty without new pages spawns `feedback_joint_...`; multi-branch parameter slot discovers both branches via `secondary_branch_queue`; `replace_scalar` solves overwriting setter (`C2`) and SGX SDK AES-128-CMAC token chain (`C7`). | Section 1A & `tests/` |
| `challenge-bench` & `challenge-bench-perm` (`dev`, 5 seeds, 3 modes) | `feedback_guided` achieves `7.4-7.6/8` confirmed in `~634-636` exploration ECALLs (`0.4-0.8` missed hold-out Field-effects), outperforming `static_priority_no_feedback` (`7.0-7.2/8` in `912` ECALLs) and `fixed_round_robin` (`6.0-6.8/8` in `3204` ECALLs). | Section 1A & `strategy_comparison.json` |
| `challenge-exam-a` & `challenge-exam-b` (`post_revision_regression`, 5 seeds, 3 modes) | Re-evaluated honestly as post-revision regression: `feedback_guided` achieves `7.2/8` confirmed vs `5.6-6.8/8` for `static_priority_no_feedback` and `5.0-5.6/8` for `fixed_round_robin`. | Section 1A & `strategy_comparison.json` |
| `challenge-exam-c` & `challenge-exam-d` (`blind_exam`, 5 seeds, 3 modes, frozen kernel `fc153e6`) | Created and evaluated AFTER freezing `src/`, `ExplorationKernel`, `generic_explorer.py`, and `controller.py` at `fc153e66ec45217ec77422da9078bab3e9592d46`: `feedback_guided` achieves `8.0/8` (`0.0` missed Field-effects) on `exam-c` and `6.8/8` on `exam-d`, outperforming `static_priority_no_feedback` (`7.4/8`, `6.0/8`) and `fixed_round_robin` (`6.2/8`, `5.6/8`). | Section 1A & `strategy_comparison.json` |
| `qe3`, `signal-cds`, `sgxwallet`, `ehsm` (`opt-1/2`) Migration | The exact same frozen `ExplorationKernel` closes all 6 real targets (`5/5` production acceptance, `295/295` clean `0`-rewalk observations in Group B). | Sections 1B, 2, 3, 4 |
| `ehsm-opt-1/2` Two-Tier SM4 Accounting | Tier 1 builds independent `sm4_seeded_xr` workset, `ReadyTable`, and signed `4gate`/`AEX1` enclaves and verifies fresh hold-out coverage (`PASS`), `0-rewalk` (`PASS`), and `AEX1` production execution (`PASS`); Tier 2 catches the exact `4` / `14` uncovered SM4 effects when only AES-256 is seeded (`FAIL`). | Section 2 (`sm4_two_tier_accounting`) |

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
