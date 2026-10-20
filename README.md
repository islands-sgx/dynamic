# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)

All tables in this document are generated automatically from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.

- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)
- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `0770a77da1a9b9211c3980aaa2aff9105b6c9c5a44e8ef7a314f62d99827cfb7`
- **Reproducible Raw Trace Archive**: `experiments/latest_traces_archive.tar.gz` (`14582 traces`, SHA-256 `102ca9487d8eb2ecbafa7338ad8747f1fdaa1c86a23073b660292795178cb0c6`, per-trace index in `experiments/traces_manifest.json`)
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

### 8-Challenge 2-Field SGX Enclaves (`C1..C8`): Dev (`dev`), Post-Revision Regression (`post_revision_regression`), & Frozen Hold-Out Variants (`frozen_holdout_variants`) across 5 Random Seeds (`101..105`)

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
- **Dataset Splits (`dev` / `post_revision_regression` / `frozen_holdout_variants`)**: `challenge-bench` and `challenge-bench-perm` form the development set (`dev`); `challenge-exam-a` and `challenge-exam-b` are classified as `post_revision_regression`; `challenge-exam-c` and `challenge-exam-d` are held-out parameter/layout/order variants (`frozen_holdout_variants`) evaluated on the frozen exploration kernel (`c60f19bd49c6a840bc36102693c63cd5e43072bb`) across the same 8 structural mechanism classes (`C1..C8`).
- **Post-Hoc Replay-Confirmed Discovery Curves & `68 / 128 / 256` Budget Ladder**: Hardware replay confirmations execute after the exploration loop and are attributed back to the initial discovery step (`Post-Hoc Replay-Confirmed Curves`); confirmation enclave/ECALL/time costs are reported separately in `(+Conf = Total)`. Every `(enclave, mode, seed)` is evaluated across the **`68 -> 128 -> 256` Enclave Budget Ladder** so that any challenge missed at `B = 68` is only attributed to budget (`verified_recovered_at_budget_128` / `verified_recovered_at_budget_256`) if continuing the remaining queue actually executes the exact candidate (`matches_exact_challenge_candidate`) and confirms the challenge page on hardware.

| Enclave (`Split`) | Mode | Expl. Enclaves `@68` (`+Conf = Total`) | Mean Expl. ECALLs `@68` (`+Conf = Total`) | Mean Wall `@68` (`Expl / Total`) | Post-Hoc Confirmed Curves `@68` (`Encl @20/40/68` ; `ECALL @250/500/750` ; `Time @1.5/3.0/4.5s`) | Per-Seed `Obs/Conf` `@68` (`101..105`) | **Confirmed Ladder (`@68 -> @128 -> @256`)** | **Ref Hold-Out Missed (`@68 -> @128 -> @256` Eff)** | **Empirical Attribution of `@68` Misses (`5` Seeds)** |
|---|---|---:|---:|---:|---|---|---|---|---|
| `challenge-bench` (`dev`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.07s / 0.07s` | `0.0/0.0/0.0` | `all: 0/0` | **0.00 -> 0.00 -> 0.00** | **16.0e** (`9.0p`) | `seed_only_baseline` |
| `challenge-bench` (`dev`) | **`fixed_round_robin`** | `68 (+6.0 = 74.0)` | `3204.0 (+78.8 = 3282.8)` | `5.35s / 5.78s` | `E:3.6/4.4/6.0` ; `C:3.6/4.0/4.4` ; `T:3.6/4.4/5.4` | `101:5/5, 102:5/5, 103:7/7, 104:6/6, 105:7/7` | **6.00 -> 8.00 -> 8.00** | **3.20e -> 0.00e -> 0.00e** (`@68:2.00p`) | `verified_recovered_at_budget_128=10` |
| `challenge-bench` (`dev`) | **`static_priority_no_feedback`** | `68 (+6.6 = 74.6)` | `919.0 (+82.6 = 1001.6)` | `4.76s / 5.23s` | `E:3.0/4.2/6.6` ; `C:3.8/4.6/6.4` ; `T:3.0/4.2/6.4` | `101:7/7, 102:6/6, 103:7/7, 104:6/6, 105:7/7` | **6.60 -> 8.00 -> 8.00** | **1.80e -> 0.00e -> 0.00e** (`@68:1.40p`) | `verified_recovered_at_budget_128=7` |
| `challenge-bench` (`dev`) | **`feedback_guided`** | `68 (+7.0 = 75.0)` | `644.6 (+85.0 = 729.6)` | `4.68s / 5.18s` | `E:3.0/4.2/7.0` ; `C:4.0/5.8/7.0` ; `T:3.0/4.4/7.0` | `101:7/7, 102:6/6, 103:8/8, 104:6/6, 105:8/8` | **7.00 -> 8.00 -> 8.00** | **1.40e -> 0.00e -> 0.00e** (`@68:1.00p`) | `verified_recovered_at_budget_128=5` |
| `challenge-bench-perm` (`dev`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.07s / 0.07s` | `0.0/0.0/0.0` | `all: 0/0` | **0.00 -> 0.00 -> 0.00** | **18.0e** (`10.0p`) | `seed_only_baseline` |
| `challenge-bench-perm` (`dev`) | **`fixed_round_robin`** | `68 (+6.8 = 74.8)` | `3204.0 (+86.4 = 3290.4)` | `5.37s / 5.84s` | `E:4.4/4.6/6.8` ; `C:4.4/4.6/4.6` ; `T:4.4/4.6/4.8` | `101:8/8, 102:6/6, 103:5/5, 104:8/8, 105:7/7` | **6.80 -> 8.00 -> 8.00** | **2.00e -> 0.00e -> 0.00e** (`@68:1.20p`) | `verified_recovered_at_budget_128=6` |
| `challenge-bench-perm` (`dev`) | **`static_priority_no_feedback`** | `68 (+7.2 = 75.2)` | `919.0 (+91.6 = 1010.6)` | `4.76s / 5.27s` | `E:3.2/5.4/7.2` ; `C:4.2/5.6/5.8` ; `T:3.2/5.4/6.8` | `101:8/8, 102:7/7, 103:7/7, 104:8/8, 105:6/6` | **7.20 -> 8.00 -> 8.00** | **1.00e -> 0.00e -> 0.00e** (`@68:0.80p`) | `verified_recovered_at_budget_128=4` |
| `challenge-bench-perm` (`dev`) | **`feedback_guided`** | `68 (+7.6 = 75.6)` | `646.2 (+94.8 = 741.0)` | `4.70s / 5.23s` | `E:3.2/5.4/7.6` ; `C:4.6/6.2/7.6` ; `T:3.2/5.4/7.0` | `101:8/8, 102:8/8, 103:7/7, 104:8/8, 105:7/7` | **7.60 -> 8.00 -> 8.00** | **0.40e -> 0.00e -> 0.00e** (`@68:0.40p`) | `verified_recovered_at_budget_128=2` |
| `challenge-exam-a` (`post_revision_regression`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.06s / 0.06s` | `0.0/0.0/0.0` | `all: 0/0` | **0.00 -> 0.00 -> 0.00** | **18.0e** (`10.0p`) | `seed_only_baseline` |
| `challenge-exam-a` (`post_revision_regression`) | **`fixed_round_robin`** | `68 (+5.0 = 73.0)` | `3159.0 (+53.8 = 3212.8)` | `5.35s / 5.71s` | `E:2.6/2.6/5.0` ; `C:2.6/2.6/2.6` ; `T:2.6/2.6/3.4` | `101:4/4, 102:5/5, 103:5/5, 104:6/6, 105:5/5` | **5.00 -> 8.00 -> 8.00** | **6.80e -> 0.00e -> 0.00e** (`@68:3.80p`) | `verified_recovered_at_budget_128=15` |
| `challenge-exam-a` (`post_revision_regression`) | **`static_priority_no_feedback`** | `68 (+5.4 = 73.4)` | `887.0 (+59.6 = 946.6)` | `4.77s / 5.15s` | `E:2.6/3.4/5.4` ; `C:3.0/4.0/4.2` ; `T:2.6/3.6/4.2` | `101:4/4, 102:7/7, 103:6/6, 104:6/6, 105:4/4` | **5.40 -> 8.00 -> 8.00** | **5.00e -> 0.00e -> 0.00e** (`@68:3.20p`) | `verified_recovered_at_budget_128=13` |
| `challenge-exam-a` (`post_revision_regression`) | **`feedback_guided`** | `68 (+6.8 = 74.8)` | `641.6 (+67.8 = 709.4)` | `4.69s / 5.16s` | `E:2.4/3.6/6.8` ; `C:3.0/4.4/6.8` ; `T:2.6/3.8/6.0` | `101:5/5, 102:8/8, 103:7/7, 104:8/8, 105:6/6` | **6.80 -> 8.00 -> 8.00** | **2.20e -> 0.00e -> 0.00e** (`@68:1.40p`) | `verified_recovered_at_budget_128=6` |
| `challenge-exam-b` (`post_revision_regression`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `11 (+0 = 11)` | `0.07s / 0.07s` | `0.0/0.0/0.0` | `all: 0/0` | **0.00 -> 0.00 -> 0.00** | **16.0e** (`9.0p`) | `seed_only_baseline` |
| `challenge-exam-b` (`post_revision_regression`) | **`fixed_round_robin`** | `68 (+5.6 = 73.6)` | `3201.0 (+61.0 = 3262.0)` | `5.38s / 5.78s` | `E:1.6/3.6/5.6` ; `C:1.6/3.6/3.8` ; `T:1.6/3.8/4.2` | `101:4/4, 102:5/5, 103:6/6, 104:6/6, 105:7/7` | **5.60 -> 8.00 -> 8.00** | **5.40e -> 0.00e -> 0.00e** (`@68:3.00p`) | `verified_recovered_at_budget_128=12` |
| `challenge-exam-b` (`post_revision_regression`) | **`static_priority_no_feedback`** | `68 (+6.8 = 74.8)` | `941.0 (+71.4 = 1012.4)` | `4.81s / 5.29s` | `E:2.0/3.0/6.8` ; `C:2.4/4.6/5.8` ; `T:2.2/3.0/5.8` | `101:5/5, 102:7/7, 103:7/7, 104:8/8, 105:7/7` | **6.80 -> 8.00 -> 8.00** | **2.20e -> 0.00e -> 0.00e** (`@68:1.40p`) | `verified_recovered_at_budget_128=6` |
| `challenge-exam-b` (`post_revision_regression`) | **`feedback_guided`** | `68 (+6.8 = 74.8)` | `694.6 (+72.0 = 766.6)` | `4.74s / 5.21s` | `E:2.2/3.0/6.8` ; `C:2.4/4.2/6.8` ; `T:2.2/3.0/6.6` | `101:5/5, 102:7/7, 103:7/7, 104:8/8, 105:7/7` | **6.80 -> 8.00 -> 8.00** | **1.80e -> 0.00e -> 0.00e** (`@68:1.20p`) | `verified_recovered_at_budget_128=6` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `9 (+0 = 9)` | `0.07s / 0.07s` | `0.0/0.0/0.0` | `all: 0/0` | **0.00 -> 0.00 -> 0.00** | **18.0e** (`10.0p`) | `seed_only_baseline` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`fixed_round_robin`** | `68 (+6.2 = 74.2)` | `3159.0 (+62.8 = 3221.8)` | `5.35s / 5.79s` | `E:2.2/4.4/6.2` ; `C:2.2/4.0/4.4` ; `T:2.2/4.4/4.6` | `101:6/6, 102:5/5, 103:6/6, 104:7/7, 105:7/7` | **6.20 -> 8.00 -> 8.00** | **4.40e -> 0.00e -> 0.00e** (`@68:2.40p`) | `verified_recovered_at_budget_128=9` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`static_priority_no_feedback`** | `68 (+7.0 = 75.0)` | `887.0 (+69.6 = 956.6)` | `4.70s / 5.18s` | `E:2.8/3.8/7.0` ; `C:3.4/5.4/5.8` ; `T:3.2/4.2/6.0` | `101:7/7, 102:8/8, 103:5/5, 104:8/8, 105:7/7` | **7.00 -> 8.00 -> 8.00** | **2.00e -> 0.00e -> 0.00e** (`@68:1.20p`) | `verified_recovered_at_budget_128=5` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`feedback_guided`** | `68 (+8.0 = 76.0)` | `637.8 (+76.0 = 713.8)` | `4.70s / 5.26s` | `E:3.2/4.4/8.0` ; `C:3.4/5.8/8.0` ; `T:3.2/4.6/7.8` | `101:8/8, 102:8/8, 103:8/8, 104:8/8, 105:8/8` | **8.00 -> 8.00 -> 8.00** | **0.00e -> 0.00e -> 0.00e** (`@68:0.00p`) | `0 missed` |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`S0` (Seed Only)** | `1 (+0 = 1)` | `11 (+0 = 11)` | `0.07s / 0.07s` | `0.0/0.0/0.0` | `all: 0/0` | **0.00 -> 0.00 -> 0.00** | **16.0e** (`9.0p`) | `seed_only_baseline` |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`fixed_round_robin`** | `68 (+5.6 = 73.6)` | `3199.0 (+59.8 = 3258.8)` | `5.39s / 5.78s` | `E:2.2/3.2/5.6` ; `C:2.2/3.2/3.4` ; `T:2.2/3.4/3.8` | `101:6/6, 102:5/5, 103:5/5, 104:6/6, 105:6/6` | **5.60 -> 8.00 -> 8.00** | **5.60e -> 0.00e -> 0.00e** (`@68:3.00p`) | `verified_recovered_at_budget_128=12` |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`static_priority_no_feedback`** | `68 (+6.0 = 74.0)` | `939.0 (+65.2 = 1004.2)` | `4.81s / 5.24s` | `E:2.6/3.6/6.0` ; `C:3.2/4.0/5.0` ; `T:2.8/3.6/5.0` | `101:5/5, 102:6/6, 103:7/7, 104:5/5, 105:7/7` | **6.00 -> 8.00 -> 8.00** | **4.20e -> 0.00e -> 0.00e** (`@68:2.40p`) | `verified_recovered_at_budget_128=10` |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`feedback_guided`** | `68 (+6.8 = 74.8)` | `696.2 (+72.6 = 768.8)` | `4.71s / 5.18s` | `E:2.4/3.6/6.8` ; `C:3.2/4.4/6.8` ; `T:2.6/3.8/6.6` | `101:7/7, 102:6/6, 103:8/8, 104:6/6, 105:7/7` | **6.80 -> 8.00 -> 8.00** | **2.40e -> 0.00e -> 0.00e** (`@68:1.40p`) | `verified_recovered_at_budget_128=6` |

#### `68 / 128 / 256` Enclave Budget Ladder: Cost, Confirmed Recovery, & Structural Bottleneck Analysis
- **Why `@68` Misses Recover by `@128` on `C1..C8`, whereas `eHSM` SM4 Tier-2 Cannot Be Solved by More Budget**: The unified candidate pool for `C1..C8` contains `132..146` initial candidates plus `~1..8` feedback-spawned follow-ups (`133..147` total steps to exhaustion). At `B = 68`, `65..79` candidates remain unpopped in the queues; continuing execution to `B = 128` (and `B = 256` queue exhaustion) executes those exact remaining candidates (`exact_candidate_in_queue_at_68 == True` verified via `matches_exact_challenge_candidate`) and confirms `8.00 / 8` across all modes and seeds (`586` confirmed witnesses at `@68`, and `720 / 720` total confirmed witnesses by `@128` and `@256` in `strategy_comparison.json`). By contrast, `eHSM` SM4 Tier-2 (`enclave_create_key` requiring simultaneous coupled updates to `metadata.keyspec=20`, `keybloblen=64`, and outer `cmk_size=80` inside `ehsm_keyblob_t`) lies outside the single-parameter candidate domain and remains `FAIL` (`4` and `14` uncovered effects) regardless of budget until multi-field struct-coupled producer synthesis or an SM4 seed (Tier 1) is provided.

| Enclave (`Split`) | Mode | `@68` (`Encl / ECALLs / Wall -> Conf`) | `@128` (`Encl / ECALLs / Wall -> Conf`) | `@256 (Exhaustion)` (`Encl / ECALLs / Wall -> Conf`) | Sample Empirically Verified Recovery (`69..128`: `Challenge: step, queue, exact spec`) |
|---|---|---|---|---|---|
| `challenge-bench` (`dev`) | **`fixed_round_robin`** | `68 / 3204.0 / 5.35s` -> **6.00/8** | `128 / 3612.0 / 9.43s` -> **8.00/8** | `133.0 / 3627.0 / 9.76s` -> **8.00/8** | `seed=101 C2: step=82 (round_robin_replace_prefix) replace_scalar:1:0:0:2` |
| `challenge-bench` (`dev`) | **`static_priority_no_feedback`** | `68 / 919.0 / 4.76s` -> **6.60/8** | `128 / 3612.0 / 9.45s` -> **8.00/8** | `133.0 / 3627.0 / 9.77s` -> **8.00/8** | `seed=101 C4: step=89 (primary_joint) joint_scalar_xor:3:0:0:2:1:0:255` |
| `challenge-bench` (`dev`) | **`feedback_guided`** | `68 / 644.6 / 4.68s` -> **7.00/8** | `128 / 3612.0 / 9.47s` -> **8.00/8** | `133.0 / 3627.0 / 9.80s` -> **8.00/8** | `seed=101 C4: step=74 (primary_joint) joint_scalar_xor:3:0:0:2:1:0:255` |
| `challenge-bench-perm` (`dev`) | **`fixed_round_robin`** | `68 / 3204.0 / 5.37s` -> **6.80/8** | `128 / 3612.0 / 9.46s` -> **8.00/8** | `133.0 / 3627.0 / 9.79s` -> **8.00/8** | `seed=102 C2: step=104 (round_robin_replace_prefix) replace_scalar:0:0:0:4` |
| `challenge-bench-perm` (`dev`) | **`static_priority_no_feedback`** | `68 / 919.0 / 4.76s` -> **7.20/8** | `128 / 3612.0 / 9.45s` -> **8.00/8** | `133.0 / 3627.0 / 9.78s` -> **8.00/8** | `seed=102 C2: step=83 (primary_replace_prefix) replace_scalar:0:0:0:4` |
| `challenge-bench-perm` (`dev`) | **`feedback_guided`** | `68 / 646.2 / 4.70s` -> **7.60/8** | `128 / 3612.0 / 9.48s` -> **8.00/8** | `133.0 / 3627.0 / 9.81s` -> **8.00/8** | `seed=103 C4: step=76 (primary_joint) joint_scalar_xor:1:0:0:3:1:0:255` |
| `challenge-exam-a` (`post_revision_regression`) | **`fixed_round_robin`** | `68 / 3159.0 / 5.35s` -> **5.00/8** | `128 / 3562.0 / 9.46s` -> **8.00/8** | `133.0 / 3587.0 / 9.79s` -> **8.00/8** | `seed=101 C2: step=92 (round_robin_replace_prefix) replace_scalar:2:0:0:8` |
| `challenge-exam-a` (`post_revision_regression`) | **`static_priority_no_feedback`** | `68 / 887.0 / 4.77s` -> **5.40/8** | `128 / 3562.0 / 9.46s` -> **8.00/8** | `133.0 / 3587.0 / 9.80s` -> **8.00/8** | `seed=101 C4: step=77 (primary_joint) joint_scalar_xor:4:0:0:16:1:0:255` |
| `challenge-exam-a` (`post_revision_regression`) | **`feedback_guided`** | `68 / 641.6 / 4.69s` -> **6.80/8** | `128 / 3562.0 / 9.46s` -> **8.00/8** | `133.0 / 3587.0 / 9.79s` -> **8.00/8** | `seed=101 C5: step=77 (primary_boundary) replace_scalar:4:2:0:3` |
| `challenge-exam-b` (`post_revision_regression`) | **`fixed_round_robin`** | `68 / 3201.0 / 5.38s` -> **5.60/8** | `128 / 3670.0 / 9.53s` -> **8.00/8** | `147.0 / 3797.0 / 10.84s` -> **8.00/8** | `seed=101 C4: step=69 (round_robin_joint) joint_scalar_xor:5:0:0:4:1:0:255` |
| `challenge-exam-b` (`post_revision_regression`) | **`static_priority_no_feedback`** | `68 / 941.0 / 4.81s` -> **6.80/8** | `128 / 3668.0 / 9.50s` -> **8.00/8** | `147.0 / 3797.0 / 10.81s` -> **8.00/8** | `seed=101 C4: step=98 (primary_joint) joint_scalar_xor:5:0:0:4:1:0:255` |
| `challenge-exam-b` (`post_revision_regression`) | **`feedback_guided`** | `68 / 694.6 / 4.74s` -> **6.80/8** | `128 / 3668.0 / 9.52s` -> **8.00/8** | `147.0 / 3797.0 / 10.78s` -> **8.00/8** | `seed=101 C3: step=69 (primary_scale) scale_bound_v2:5:0:0:16:1024:32:1024;scale_bound_v2:5:0:2:16:1024:32:1024` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`fixed_round_robin`** | `68 / 3159.0 / 5.35s` -> **6.20/8** | `128 / 3562.0 / 9.42s` -> **8.00/8** | `133.0 / 3587.0 / 9.76s` -> **8.00/8** | `seed=101 C5: step=72 (round_robin_boundary) replace_scalar:4:2:0:4` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`static_priority_no_feedback`** | `68 / 887.0 / 4.70s` -> **7.00/8** | `128 / 3562.0 / 9.36s` -> **8.00/8** | `133.0 / 3587.0 / 9.70s` -> **8.00/8** | `seed=101 C8: step=72 (primary_boundary) replace_scalar:2:0:0:8` |
| `challenge-exam-c` (`frozen_holdout_variants`) | **`feedback_guided`** | `68 / 637.8 / 4.70s` -> **8.00/8** | `128 / 3562.0 / 9.48s` -> **8.00/8** | `133.0 / 3587.0 / 9.82s` -> **8.00/8** | none (`8.00/8` at `@68`) |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`fixed_round_robin`** | `68 / 3199.0 / 5.39s` -> **5.60/8** | `128 / 3668.0 / 9.54s` -> **8.00/8** | `147.0 / 3795.0 / 10.84s` -> **8.00/8** | `seed=101 C2: step=95 (round_robin_replace_prefix) replace_scalar:3:0:0:4` |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`static_priority_no_feedback`** | `68 / 939.0 / 4.81s` -> **6.00/8** | `128 / 3666.0 / 9.52s` -> **8.00/8** | `147.0 / 3795.0 / 10.84s` -> **8.00/8** | `seed=101 C2: step=76 (primary_replace_prefix) replace_scalar:3:0:0:4` |
| `challenge-exam-d` (`frozen_holdout_variants`) | **`feedback_guided`** | `68 / 696.2 / 4.71s` -> **6.80/8** | `128 / 3666.0 / 9.50s` -> **8.00/8** | `147.0 / 3795.0 / 10.81s` -> **8.00/8** | `seed=101 C4: step=75 (primary_joint) joint_scalar_xor:5:0:0:1:1:0:255` |

## 1B. Three-Layer Workset Attribution Across 4 Real Applications (6 Configurations: `qe3`, `signal-cds`, `sgxwallet`, `ehsm`, `ehsm-opt-1`, `ehsm-opt-2`)

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

### 2A. Known-Answer 7-Case Hardware Measurement Calibration Fixture (`calibration-fixture`)
- **Independent Ground-Truth Design**: `challenges/calibration-fixture` declares 6 page-aligned ground-truth symbols (`X_code_page`, `RX_data_read_page`, `R_rodata_page`, `W_writable_page`, `Cross_page_0`, `Cross_page_1`) plus a `4`-page temporary deep stack frame (`cal_deep_stack_helper`, which allocates and dirties `16 KiB` of stack inside the Field and returns before Gate D so `gateB_rsp_rva == gateD_rsp_rva`). In default mode (`repeat_field_count=2`), all target pages are first accessed in `S0/S1` (outside the Field, before Gate B) and then accessed inside `cal_field_entry` (`S3`) twice within a single ECALL.
- **Hardware Measurement Omission Rate**: `0 / 34` (`0.00%`) across `2` repeated Field entries in one ECALL.
- **Temporary Deep Stack Capture**: `gateB_rsp_rva = 0xc0a20`, `gateD_rsp_rva = 0xc0a20` (`rsp_endpoint_delta = 0 B`), yet 4-Gate `S3` `A/D` tracking captured `5` dirty (`D`) stack pages (`0xbc000, 0xbd000, 0xbe000, 0xbf000, 0xc0000`) on both entries.
- **Positive & Negative Calibration Controls**: Full pre-touch (`dynamic_xr_4gate`) -> `[0, 0]` clean `S3` rewalks (`0` residual); deliberately omitting `W_writable_page` (`0x16000`) -> validator `FAIL` (`UNCOVERED_PAGE_0x16000_IN_0xe1b7d61bdf80222f,UNCOVERED_WRITE_EFFECT_D_ON_0x16000_IN_0xe1b7d61bdf80222f,UNCOVERED_PAGE_0x16000_IN_0xe1b7d61bdf80222f,UNCOVERED_WRITE_EFFECT_D_ON_0x16000_IN_0xe1b7d61bdf80222f`) and caught by 4-Gate `S3` rewalk = `True`; actively retracting `0x16000` -> `AEX0` healed & EA verified = `True` (`kind=W`), `AEX1` fail-stop = `0x1006`, restored control faults = `0` (**Verdict: `PASS`**).

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
| `ehsm-opt-1` | **Tier 1 (`sm4_seeded_xr`)** | `34d69ee4 / 66990e05 / 60e70591` (`+4e` over AES) | **`PASS`** (`0` unseen) | **`PASS`** (`15/15 0-rewalk`) | **`PASS`** (`rc=0, PASS`) | **`PASS`**: Independent signed enclave & ReadyTable built from seed trace and verified on fresh runs |
| `ehsm-opt-1` | **Tier 2 (`dynamic_xr` AES-only)** | `9be55c1f / e25eafa9 / 0549004e` (AES-256 seed only) | **`FAIL`** (`4` uncovered) | N/A (coverage failed) | N/A (coverage failed) | **`FAIL`**: Catches **4 uncovered SM4 effects** (`UNCOVERED_PAGE_0x1d3000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x21e000_IN_0x2c6ee760c60f6016, UNCOVERED_PAGE_0x285000_IN_0x2c6ee760c60f6016...`); requires coupled 3-field struct change (`keyspec=20, keybloblen=64, cmk_size=80`) |
| `ehsm-opt-2` | **Tier 1 (`sm4_seeded_xr`)** | `984d1f6e / 7f79ad12 / 51b0175a` (`+21e` over AES) | **`PASS`** (`0` unseen) | **`PASS`** (`15/15 0-rewalk`) | **`PASS`** (`rc=0, PASS`) | **`PASS`**: Independent signed enclave & ReadyTable built from seed trace and verified on fresh runs |
| `ehsm-opt-2` | **Tier 2 (`dynamic_xr` AES-only)** | `97f0de0a / 63f4fff5 / b542c015` (AES-256 seed only) | **`FAIL`** (`14` uncovered) | N/A (coverage failed) | N/A (coverage failed) | **`FAIL`**: Catches **14 uncovered SM4 effects** (`UNCOVERED_PAGE_0x5b000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x89000_IN_0x61a6007dac8ab670, UNCOVERED_PAGE_0x93000_IN_0x61a6007dac8ab670...`); requires coupled 3-field struct change (`keyspec=20, keybloblen=64, cmk_size=80`) |

### 2B. Predetermined 60-Case End-to-End Regression Matrix (`4` Separate Verdicts per Case; No Binomial Probability Claim)
- **Methodology & Scope**: After freezing `workset.dynamic_xr.json` and the signed production enclaves, each of the 4 real applications (6 configurations) is evaluated against `10` predetermined test cases (`60` cases total) covering varied payload lengths, byte perturbations, repeat depths, and the 6 adapted upstream `signal-cds` test cases (`95` ECALLs/run). Because these 60 cases are a predetermined regression matrix rather than random draws from a formally defined input distribution, we report exact observed pass/omission counts across **four separate acceptance dimensions** without claiming a binomial probability upper bound:
  1. **Measurement Valid (`ipi=7`)**: Passes unified `is_valid_measurement_run()` (`s3_active_aex_count` present, well-formed `A/D` items, `ipi_aex_verified_mask == 7`, `fast_forwarded_prior == 0`, `measurement_invalid == 0`);
  2. **Business Workflow Completed**: Enforces `min_rec` minimum ECALL count, verifies all target `expected_fids` were entered (`field_entries > 0`), verifies the expected intervention tags were applied, and checks `returncode == 0` with business `PASS`;
  3. **Workset Coverage Zero-Omission**: Requires `Measurement Valid` and `Business Workflow Completed` and verifies `0` uncovered `(field_id, page_rva, effect)` tuples against `workset.dynamic_xr.json`;
  4. **Frozen Protected `AEX1` Enclave Completed**: Runs the identical case on `enclave.dynamic_xr.final.signed.so` + `enclave.dynamic_xr.ready.bin` (`AEX-Notify=1`, `ATFIELD_REQUIRE_READINESS=1`) and verifies `returncode == 0`, business `PASS`, exact `ecall_index` sequence parity with the 4-Gate profiling run, and verified `enclave_pages_acquire/release` calls.

| Configuration | Predetermined Cases | Total ECALLs / Field Entries | `1. Measurement Valid` | `2. Business Workflow Completed` | `3. Workset Coverage Zero-Omission` (`Worst Omitted`) | `4. Frozen Protected AEX1 Completed` (`0x1006 Retries`) |
|---|---:|---:|---:|---:|---:|---:|
| `qe3` | `10` | `46 / 46` | **`10 / 10`** | **`10 / 10`** | **`10 / 10`** (`0p / 0e`) | **`10 / 10`** (`0` retries) |
| `signal-cds` | `10` | `519 / 494` | **`10 / 10`** | **`10 / 10`** | **`10 / 10`** (`0p / 0e`) | **`10 / 10`** (`0` retries) |
| `sgxwallet` | `10` | `10163 / 10123` | **`10 / 10`** | **`10 / 10`** | **`10 / 10`** (`0p / 0e`) | **`10 / 10`** (`0` retries) |
| `ehsm` | `10` | `346 / 155` | **`10 / 10`** | **`10 / 10`** | **`10 / 10`** (`0p / 0e`) | **`10 / 10`** (`0` retries) |
| `ehsm-opt-1` | `10` | `208 / 153` | **`10 / 10`** | **`10 / 10`** | **`10 / 10`** (`0p / 0e`) | **`10 / 10`** (`0` retries) |
| `ehsm-opt-2` | `10` | `208 / 153` | **`10 / 10`** | **`10 / 10`** | **`10 / 10`** (`0p / 0e`) | **`10 / 10`** (`0` retries) |
| **Total (`4` Apps / `6` Configs)** | **`60`** | **`11490 / 11124`** | **`60 / 60`** | **`60 / 60`** | **`60 / 60`** (`0p / 0e`) | **`60 / 60`** (`0` retries) |

### 2C. Upstream Test Adaptation & Onboarding Cost Accounting (`4` Real Applications, `6` Configurations)
| Application (`Configs`) | Test Provenance & Upstream Reference | Host Entry / Flag | Preserved Assertions & Explicit Adaptation Differences | Host Adapter LOC (`Added LOC`) | Explorer / Kernel Special-Case Rules |
|---|---|---|---|---:|---:|
| `signal-cds` (`1`) | **Selected & adapted 6 upstream Cmockery tests** from `enclave/src/sabd-enclave-test.c` (`setup_sabd_lookup_test`, `test_sabd_lookup_batch_too_large`, `test_sabd_lookup_many_duplicates`, `test_sabd_lookup_small_{all_in,no_in,random}`, `test_sabd_lookup_large`) | `targets/signal-cds/host.c` (`--upstream-cmockery-test --seed S --in-jids N`, `95` ECALLs/run) | **Preserved**: `(1<<14)+1` `SGX_ERROR_INVALID_PARAMETER` check, `!!result[i]` normalization, even-index duplication, and `memcmp` across `0..32`, `0..25`, and `2048`-query batches. **Explicit adaptations**: (1) replaced Cmockery mock macros with real `ecall_lookup_hash` calls; (2) avoided reserved miss sentinel `jid <= 1` when generating `test_in_jids` via `mrand48_r`; (3) parameterized `in_jid_count` (`128..4096` vs static `1,000,000`). | `358` (`+122` for adapted suite) | **`0`** |
| `ehsm` (`ehsm`, `ehsm-opt-1`, `ehsm-opt-2`) | **Selected & adapted workflow** from `core/Test/function_test.cpp` (`test_AES128_GCM`, `test_SM4_CBC`, `GenerateDataKey`, `Decrypt`) | `sample/real/ehsm/host.cpp` (default AES-GCM + `--compat-check` + `--sm4-check`) | **Preserved**: `ehsm_create_key` -> `ehsm_encrypt` -> `ehsm_decrypt` -> `ehsm_generate_datakey` -> `ehsm_decrypt_datakey`, ciphertext/AAD tamper rejection, and round-trip plaintext equality. **Explicit adaptations**: extracted standalone C++ host driver from gtest/dkeyserver wrapper. | `312` (`+0` kernel rules) | **`0`** |
| `sgxwallet` (`1`) | **Selected & adapted workflow** from `tests/integration/keys/ECDSAIntegrationTests.cpp` | `sample/real/sgxwallet/host.cpp` | **Preserved**: SEK provisioning -> ECDSA keygen -> public key extraction -> hash signing -> signature verification -> invalid input rejection -> enclave restart & recovery. **Explicit adaptations**: standalone C++ host driver without JSON-RPC/LevelDB server daemon. | `264` (`+0` kernel rules) | **`0`** |
| `qe3` (`1`) | **Local functional test written against upstream production code** `QuoteGeneration/quote_wrapper/quote/enclave/qe3.c` (`get_att_key_based_from_seal_key`) | `sample/real/qe3/host.c` | **Local test**: invokes attestation-key derivation across identical vs distinct `key_id` values and asserts public-key determinism and uniqueness (not ported from an upstream test file). | `118` (`+0` kernel rules) | **`0`** |

## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)

| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |
|---|---|---:|---|---|---|---:|---|---|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 0/15 (`3 / 6`) | **0/15** (`3 / 3`) | 0 (`max=0p`) | 0/15 (`3 / 3`) | 0 (`max=0p`) | `1,517,996` -> **`189,628`** -> `148,990` |
| `signal-cds` | `sabd_lookup_hash` | 25 | 15/25 (`0 / 24`) | **25/25** (`0 / 0`) | 0 (`max=0p`) | 25/25 (`0 / 0`) | 0 (`max=0p`) | `1,284,504` -> **`646,010`** -> `658,580` |
| `sgxwallet` | `generate_sek_field` | 5 | 0/5 (`13 / 20`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,372,280` -> **`228,948`** -> `222,052` |
| `sgxwallet` | `set_sek_field` | 5 | 0/5 (`11 / 15`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `6,373,014` -> **`221,560`** -> `220,170` |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 0/5 (`21 / 22`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,849,322` -> **`209,236`** -> `196,838` |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 0/5 (`16 / 23`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,080,442` -> **`124,596`** -> `127,022` |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 0/50 (`15 / 23`) | **50/50** (`0 / 0`) | 0 (`max=0p`) | 50/50 (`0 / 0`) | 0 (`max=0p`) | `2,032,851` -> **`137,878`** -> `137,925` |
| `ehsm` | `ehsm_generate_datakey` | 5 | 0/5 (`38 / 40`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,788,846` -> **`451,050`** -> `460,384` |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`34 / 45`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,859,654` -> **`452,957`** -> `443,286` |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`39 / 134`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,873,408` -> **`449,293`** -> `445,762` |
| `ehsm` | `ehsm_create_aes_key` | 5 | 0/5 (`128 / 145`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,528,660` -> **`958,532`** -> `902,658` |
| `ehsm-opt-1` | `ehsm_generate_datakey` | 5 | 0/5 (`39 / 42`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,885,948` -> **`451,866`** -> `446,094` |
| `ehsm-opt-1` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 45`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,885,085` -> **`459,902`** -> `437,338` |
| `ehsm-opt-1` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`37 / 139`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,893,628` -> **`447,888`** -> `445,721` |
| `ehsm-opt-1` | `ehsm_create_aes_key` | 5 | 0/5 (`140 / 145`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,497,252` -> **`970,394`** -> `918,392` |
| `ehsm-opt-2` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`38 / 46`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,834,455` -> **`295,451`** -> `293,593` |
| `ehsm-opt-2` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`37 / 47`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,877,659` -> **`296,861`** -> `293,671` |
| `ehsm-opt-2` | `ehsm_create_aes_key` | 5 | 0/5 (`42 / 45`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `8,177,744` -> **`384,330`** -> `358,424` |
| `ehsm-opt-2` | `ehsm_generate_datakey` | 5 | 0/5 (`39 / 42`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,907,026` -> **`289,500`** -> `288,378` |

- **Exact Per-Observation Totals Across the 16 Non-`ENCLU` Field Instances (295 total Field entries across 5 rounds)**:
  - **Group B (`dynamic_xr`, Default `XR`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.
  - **Group C (`dynamic_refined`, `X-only`)**: **295 / 295** clean (`s3_aex=0`) observations, **0 / 295** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **295 / 295** achieved `0` residual page-table A/D re-walks.

## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)

- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).
- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).

### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown

| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 3 | **5/5** | 251.4 | **39.4** | 259.9 | +8.5 | **300.0** | **+19.33%** (`+48.6 µs`) | 470.9 (`+219.5 µs`) | **4.52x** |
| `signal-cds` | 5 | **5/5** | 87439.9 | **129.2** | 87458.9 | +19.0 | **87588.4** | **+0.17%** (`+148.6 µs`) | 87707.2 (`+267.4 µs`) | **1.80x** |
| `sgxwallet` | 14 | **5/5** | 1354.6 | **34.8** | 1369.5 | +14.8 | **1404.2** | **+3.66%** (`+49.6 µs`) | 1796.5 (`+441.9 µs`) | **8.90x** |
| `ehsm` | 14 | **5/5** | 141.4 | **70.8** | 145.5 | +4.1 | **216.2** | **+52.89%** (`+74.8 µs`) | 708.4 (`+567.0 µs`) | **7.58x** |
| `ehsm-opt-1` | 14 | **5/5** | 142.3 | **72.6** | 146.1 | +3.7 | **218.9** | **+53.80%** (`+76.6 µs`) | 719.4 (`+577.1 µs`) | **7.54x** |
| `ehsm-opt-2` | 14 | **5/5** | 11.7 | **50.1** | 14.9 | +3.2 | **65.0** | **+455.81%** (`+53.3 µs`) | 606.3 (`+594.6 µs`) | **11.15x** |

### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)

| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 0 | 0.000 | 0.000 |
| `signal-cds` | 1 | 0.005 | **0.123** | 0.006 | **0.129** | 0 | 0.000 | 0.000 |
| `sgxwallet` | 0 | 0.000 | **0.000** | 0.000 | **0.000** | 4 | 17.111 | 17.088 |
| `ehsm` | 16 | 0.091 | **1.152** | 0.098 | **1.250** | 2 | 0.155 | 0.151 |
| `ehsm-opt-1` | 3 | 0.017 | **0.211** | 0.017 | **0.229** | 2 | 0.153 | 0.148 |
| `ehsm-opt-2` | 3 | 0.017 | **0.143** | 0.018 | **0.161** | 2 | 1.979 | 1.990 |

### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint

| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `3 / 0 / 0` | **5/5** | 0.75 | 0.75 | 1.41 | **0.90** | 0.90 | **+19.33%** (`+0.15 ms`) | **1.57x** | `2104.7 -> 2116.7 KiB` (**+0.57%**) | `1303 B + 1544 B` |
| `signal-cds` | `5 / 1 / 0` | **5/5** | 437.17 | 437.20 | 438.77 | **438.07** | 438.08 | **+0.20%** (`+0.87 ms`) | **1.00x** | `140.3 -> 155.8 KiB` (**+11.06%**) | `4568 B + 5072 B` |
| `sgxwallet` | `14 / 0 / 4` | **5/5** | 42.67 | 36.05 | 42.25 | **36.75** | 36.60 | **+1.93%** (`+0.70 ms`) | **1.15x** | `2722.2 -> 2818.2 KiB` (**+3.52%**) | `4458 B + 6280 B` |
| `ehsm` | `14 / 16 / 2` | **5/5** | 2.24 | 2.23 | 17.49 | **4.43** | 4.44 | **+98.82%** (`+2.20 ms`) | **3.95x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10206 B + 11696 B` |
| `ehsm-opt-1` | `14 / 3 / 2` | **5/5** | 2.17 | 2.16 | 11.56 | **3.44** | 3.45 | **+58.93%** (`+1.28 ms`) | **3.36x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10250 B + 11728 B` |
| `ehsm-opt-2` | `14 / 3 / 2` | **5/5** | 2.16 | 2.16 | 11.80 | **3.05** | 3.06 | **+41.29%** (`+0.89 ms`) | **3.87x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `6117 B + 7832 B` |

## 6. One-Page Methodology & Boundary Specification: Why It Works, When It Can Miss, and What Each Experiment Verifies

### 6.1 Why the Prototype Works (Three Grounded Pillars)
1. **ABI-Typed & Capacity-Safe In-Place / Isolated Interventions (`edl_harness.py` + `interpose_interventions.h`)**: Compiler-exact EDL marshaling schemas (`ms_*` offsets, sizes, pointer directions, and `count=/size=` bindings) ensure that every mutation (`replace_scalar`, `replace_xor`, `scale_bound_v2`, `joint_scalar_xor`, `aliased_pair`) respects C ABI memory bounds and refuses in-place output replacements when `[out]/[inout]` capacity would be exceeded.
2. **Executable Host Prefixes & True In-Place Call Replacement (`replace_scalar` / `replace_xor`)**: Instead of fabricating opaque handles, keys, or MAC-authenticated blobs offline, each trial executes a fresh enclave from the beginning of the host workflow, replaces parameters in-place at the target call position (executing once and writing ABI return values and `[out]/[inout]` buffers back to the host), and lets the host's own logic carry valid handles/tokens into downstream Fields.
3. **Greybox Concrete Page-Set Feedback + Anti-Starvation Base Scheduling (`ExplorationKernel`)**: Feedback tracks concrete `frozenset((page_rva, effect))` sets (ignoring random output bytes and never collapsing distinct call positions that happen to touch the same setup pages). Once a parameter slot satisfies its target branch or a selector fails `S0` integrity/repeatability checks, remaining redundant candidates on that slot are demoted to `low_priority_queue`, reallocating budget to unexplored call positions (`sseq=0, 1, 2, 3`) and multi-selector history depths.

### 6.2 Under What Conditions It Can Miss (Explicit Soundness & Hardware Enforcement Boundaries)
- **Pre-Touch Omission, Production `ReadyTable` (`SGX_IOC_ENCLAVE_PAGES_ACQUIRE`), and `AEX-Notify` Fail-Stop**:
  - In the current `implement` kernel module (`linux-sgx-page-readiness.patch`), `SGX_IOC_ENCLAVE_PAGES_ACQUIRE` iterates over the pages listed in `ReadyTable` to ensure they are resident and ready in EPC/page tables and verifies their mapping/permissions before Field entry; **it does not retract page-table permissions on non-`ReadyTable` enclave pages**.
  - Consequently, if an enclave page is omitted from the workset (`FieldTargetPages` / `ReadyTable`) or from pre-touch while its OS page-table mapping remains valid (present and accessible), accessing it at runtime will simply perform a normal hardware page-table walk (setting `A/D` bits) **without causing a page fault, an AEX, or a `0x1006` abort**. Neither `AEX-Notify` nor production `ReadyTable` acts as a runtime fail-stop detector for omitted workset pages.
  - Omitted workset or pre-touch pages must instead be detected during verification by the **4-Gate `S3` `A/D` coverage & pre-touch rewalk diagnostics** and the **strict diagnostic retraction harness (`ATFIELD_STRICT_READY_FILE`)**, which explicitly clears PTE permissions on non-ready pages during hold-out and single-page retraction calibration (`X/R/W` fault calibration).
- **Single-Run Measurement Soundness vs Whole-Program Input Coverage**: Hardware 4-Gate AEP page-table `A/D` tracking with single-page `X/R/W` fault calibration guarantees that *every page touched during an executed run is measured*, but finite dynamic exploration does **not** prove coverage over all future inputs, secrets, or un-seeded protocol states.
- **Specific Structural Conditions Where Dynamic Exploration Can Miss**:
  1. **Multi-Field Coupled Struct Invariants in Producer Calls (Demonstrated by `eHSM` SM4 Tier 2)**: When a producer ECALL (`enclave_create_key`) takes a nested C struct (`ehsm_keyblob_t`) requiring simultaneous coordinated updates to multiple internal struct fields (`metadata.keyspec = 20`, `keybloblen = 64`) and an outer EDL size scalar (`cmk_size = 80`) before sealing an authenticated blob, single-scalar replacement does not synthesize the valid struct tuple without a legal seed or struct-binding spec (resulting in the `4` / `14` uncovered pages caught by Tier 2).
  2. **Narrow Constants Outside the Declared Enum/Boundary Domain**: Predicates checking arbitrary 32/64-bit magic numbers outside the declared domain `{0, 1, 2, 3, 4, 8, 16, 99}` and page-crossing length progression `[16..262144]` cannot be guessed by black-box/grey-box enumeration without symbolic or taint guidance.
  3. **Deep History or Call Positions Beyond the Declared Budget Ceiling**: When the enclave creation budget (`68` on challenge enclaves) expires before all `replace_prefix` / `boundary` slots are exhausted (as seen on `seed=101` of `challenge-exam-a` and `challenge-exam-b`, which solved `6/8` before budget cutoff), unvisited candidates remain in `unexplored_frontier`.

### 6.3 What Each Experiment Verifies
| Experiment / Artifact | Specific Claim Verified | Where Recorded |
|---|---|---|
| `test_exploration_kernel_and_replace.py` | Single-round feedback on real `ehsm` target alters subsequent scheduling; state novelty without new pages spawns `feedback_joint_...`; multi-branch parameter slot discovers both branches via `secondary_branch_queue`; `replace_scalar` solves overwriting setter (`C2`) and SGX SDK AES-128-CMAC token chain (`C7`). | Section 1A & `tests/` |
| `challenge-bench` & `challenge-bench-perm` (`dev`, 5 seeds, 3 modes) | `feedback_guided` achieves `7.00/8` and `7.60/8` confirmed (`644.6`–`646.2` exploration ECALLs), outperforming `static_priority_no_feedback` (`6.60`–`7.20/8`) and `fixed_round_robin` (`6.00`–`6.80/8`). | Section 1A & `strategy_comparison.json` |
| `challenge-exam-a` & `challenge-exam-b` (`post_revision_regression`, 5 seeds, 3 modes) | Evaluated as post-revision regression: `feedback_guided` achieves `6.80/8` and `6.80/8` confirmed vs `5.40`–`6.80/8` for `static_priority_no_feedback` and `5.00`–`5.60/8` for `fixed_round_robin`. | Section 1A & `strategy_comparison.json` |
| `challenge-exam-c` & `challenge-exam-d` (`frozen_holdout_variants`, 5 seeds, 3 modes, frozen kernel `c60f19b`) | Evaluated on the frozen exploration kernel (`c60f19bd49c6a840bc36102693c63cd5e43072bb`): `feedback_guided` achieves `8.00/8` (`0.0` missed Field-effects) on `exam-c` and `6.80/8` on `exam-d`, outperforming `static_priority_no_feedback` (`7.00/8`, `6.00/8`) and `fixed_round_robin` (`6.20/8`, `5.60/8`). | Section 1A & `strategy_comparison.json` |
| `calibration-fixture` (`7`-case hardware measurement calibration) | Verifies `0 / 36` (`0.00%`) measurement omission rate across `S0/S1`-then-`S3` pre-access, `2` repeated Field entries per ECALL, `5` dirty pages on a temporary deep stack frame (`gateB_rsp == gateD_rsp`), deliberate 1-page omission detection, and active permission retraction (`AEX0` healed + `AEX1` `0x1006`). | Section 2A & `evaluation_results.json` |
| `signal-cds` Adapted Upstream Cmockery Tests & `60`-Case Predetermined End-to-End Regression Matrix | Selects and adapts `6` upstream Cmockery tests from `enclave/src/sabd-enclave-test.c` (`95` ECALLs/run) and evaluates `60` predetermined regression cases across all 4 applications / 6 configurations on four separate verdicts (`60/60` measurement valid, `60/60` business completed, `60/60` zero workset omissions, `60/60` frozen protected `AEX1` completed). | Sections 2B, 2C & `evaluation_results.json` |
| `qe3`, `signal-cds`, `sgxwallet`, `ehsm` (`opt-1/2`) Migration | The exact same frozen `ExplorationKernel` closes all 4 real applications (6 configurations) (`5/5` production acceptance, `295/295` clean `0`-rewalk observations in Group B). | Sections 1B, 2, 3, 4 |
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
