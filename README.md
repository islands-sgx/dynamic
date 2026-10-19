# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)

All tables in this document are generated automatically from `experiments/evaluation_results.json` and `witnesses/<sample>/witness_ledger.json` via `python3 tools/generate_report_tables.py`.

- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)
- **Unified Collector (`build/libatfield_native_sgx.so`) SHA-256 across Discovery & Evaluation**: `47c38d9747d34471783416657f33d2204a2eeee4d0e0f2b4aad811a98c1bb124`
- **Default Conservative Candidate**: **Group B (`workset.dynamic_xr.json`)**, which keeps all `RX` code pages as `XR` (`RX = XR`), avoiding unverified `X-only` read-permission stripping.
- **Scope & Boundary Statement**: Dynamic exploration and hold-out evaluations provide empirical evidence on the executed inputs, histories, and hardware runs; heuristic assistance (depth-4 direct call graph, `+2` heap frontier pages, `-4` stack margin pages) is an empirical aid rather than a formal whole-program upper-bound proof.

## 1. Three-Layer Workset Attribution (11 Protected Business Fields)

- **Layer 0 (`L0`)**: First invocation of the Field (`(page_rva, effect)` pairs, distinguishing `A` vs `D`).
- **Layer 1 (`L1`)**: Complete unmodified sample `host` workflow (all calls measured).
- **Layer 2 (`L2`)**: Schema-typed exploration driven by `targets/<sample>/edl_schema.json` (`feedback_scale_expansion` via `scale_bound_v2`, isolated single-mutation replay `xor_param`/`set_scalar`/`null_param`, `cold_enclave_state_replay` via `typed_state_probe`, and `doubling_history_scan` `16 -> 64 -> 256 -> 1024`).

| Sample | Field | L0 First Call (`p / eff`) | L1 Full Host (`p / +p`) | L2 Isolated from Seed (`p / +p`) | L2 Added Beyond Full Host (`+p / +eff`) | Bridge + Heuristic Assist (`+p`) | Final `FieldTargetPages` (Group B `XR`) | All-REG Baseline | Reduction vs All-REG |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `get_att_key_based_from_seal_key` | 69p / 77e | 69p (`+0p`) | **69p** (`+0p`) | **+0p / +0e** | +57p | **126p** | 850p | **85.18%** |
| `signal-cds` | `sabd_lookup_hash` | 16p / 20e | 230p (`+214p`) | **554p** (`+538p`) | **+324p / +364e** | +12p | **566p** | 1127p | **49.78%** |
| `sgxwallet` | `ecdsa_sign_field` | 70p / 78e | 76p (`+6p`) | **76p** (`+6p`) | **+0p / +0e** | +33p | **109p** | 1774p | **93.86%** |
| `sgxwallet` | `get_public_ecdsa_key_field` | 68p / 74e | 68p (`+0p`) | **72p** (`+4p`) | **+4p / +4e** | +29p | **101p** | 1774p | **94.31%** |
| `sgxwallet` | `set_sek_field` | 45p / 52e | 45p (`+0p`) | **52p** (`+7p`) | **+7p / +7e** | +22p | **74p** | 1774p | **95.83%** |
| `sgxwallet` | `generate_ecdsa_key_field` | 76p / 82e | 76p (`+0p`) | **76p** (`+0p`) | **+0p / +0e** | +31p | **107p** | 1774p | **93.97%** |
| `sgxwallet` | `generate_sek_field` | 48p / 56e | 48p (`+0p`) | **48p** (`+0p`) | **+0p / +0e** | +24p | **72p** | 1774p | **95.94%** |
| `ehsm` | `ehsm_create_aes_key` | 263p / 332e | 263p (`+0p`) | **263p** (`+0p`) | **+0p / +0e** | +36p | **299p** | 2349p | **87.27%** |
| `ehsm` | `ehsm_generate_datakey` | 90p / 98e | 90p (`+0p`) | **264p** (`+174p`) | **+174p / +236e** | +35p | **299p** | 2349p | **87.27%** |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 90p / 97e | 93p (`+3p`) | **266p** (`+176p`) | **+173p / +234e** | +36p | **302p** | 2349p | **87.14%** |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 90p / 98e | 266p (`+176p`) | **266p** (`+176p`) | **+0p / +0e** | +38p | **304p** | 2349p | **87.06%** |

## 2. Provenance, Fault-Detector Calibration, Same-Fault AEX0/AEX1, and Hold-Out Validation

| Sample | Provenance Hash Match | Cold vs Warm TLB (`ipi=7` vs `0` S3 Pages) | 4-Gate vs Uninst `AEX0` Equivalence | Single-Page `X / R / W` Confirmed Kind (`healed:kind`) | Restored Positive Control Faults | Same-Fault `AEX0` (`rc=0`) vs `AEX1` (`0x1006` on same page) | Hold-Out Main `rc` & `stdout` | Hold-Out Unseen `(page / effect)` | Strict `FieldTargetPages` (`Gate B..D`) Faults | Strict `ReadyTable v3` (`ECALL`) Faults | Validator Verdict |
|---|---|---|---|---|---:|---|---|---|---|---:|---:|---|
| `qe3` | **PASS** | 69p vs 52p (`True`) | `True` | `0xd5000:True:X`, `0x2000:True:R`, `0x1f4000:True:W` | 0 | `0xd5000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `signal-cds` | **PASS** | 16p vs 1p (`True`) | `True` | `0xc000:True:X`, `0x10000:True:R`, `0x3d000:True:W` | 0 | `0xc000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `sgxwallet` | **PASS** | 48p vs 29p (`True`) | `True` | `0x16000:True:X`, `0x5000:True:R`, `0x28c000:True:W` | 0 | `0x16000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |
| `ehsm` | **PASS** | 263p vs 245p (`True`) | `True` | `0xdb000:True:X`, `0x57000:True:R`, `0x4c9000:True:W` | 0 | `0xdb000` -> **PASS** | `rc=0` (`PASS`) | **0p / 0e** | **0** | **0** | **PASS** |

## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)

- **Group A (`all_reg_xr`)**: All committed business REG pages pre-touched with full `XR/RW`.
- **Group B (`dynamic_xr`, Default Candidate)**: Reduced dynamic page set while keeping all `RX` pages as `XR`.
- **Group C (`dynamic_refined`, Experimental Ablation)**: Reduced dynamic page set + `X-only` on code pages without direct symbol/RIP-relative data references.
- **Interrupt Separation**: Every Field observation records `s3_active_aex_count`. Observations with `s3_active_aex_count == 0` are reported under **Clean (`s3_aex=0`)**; observations interrupted by external host/timer AEX during `S3` (`s3_active_aex_count > 0`) are reported separately under **Interrupt-Contaminated (`s3_aex>0`)**.

| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |
|---|---|---:|---|---|---|---:|---|---|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 0/15 (`3 / 5`) | **0/15** (`3 / 3`) | 0 (`max=0p`) | 0/15 (`3 / 3`) | 0 (`max=0p`) | `1,343,094` -> **`164,620`** -> `155,348` |
| `signal-cds` | `sabd_lookup_hash` | 25 | 16/25 (`0 / 20`) | **25/25** (`0 / 0`) | 0 (`max=0p`) | 25/25 (`0 / 0`) | 0 (`max=0p`) | `1,275,788` -> **`642,572`** -> `640,726` |
| `sgxwallet` | `generate_sek_field` | 5 | 0/5 (`12 / 15`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `5,871,450` -> **`228,084`** -> `204,960` |
| `sgxwallet` | `set_sek_field` | 5 | 0/5 (`10 / 11`) | **0/5** (`1 / 1`) | 0 (`max=0p`) | 0/5 (`1 / 1`) | 0 (`max=0p`) | `5,746,390` -> **`229,292`** -> `211,932` |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 0/5 (`23 / 25`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `3,003,770` -> **`206,286`** -> `195,682` |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 0/5 (`14 / 23`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,068,158` -> **`130,180`** -> `127,890` |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 0/50 (`15 / 23`) | **50/50** (`0 / 0`) | 0 (`max=0p`) | 50/50 (`0 / 0`) | 0 (`max=0p`) | `2,032,920` -> **`144,740`** -> `144,655` |
| `ehsm` | `ehsm_generate_datakey` | 5 | 0/5 (`42 / 45`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `2,817,912` -> **`437,696`** -> `443,212` |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 0/20 (`36 / 47`) | **20/20** (`0 / 0`) | 0 (`max=0p`) | 20/20 (`0 / 0`) | 0 (`max=0p`) | `2,883,352` -> **`448,603`** -> `434,922` |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 0/40 (`36 / 130`) | **40/40** (`0 / 0`) | 0 (`max=0p`) | 40/40 (`0 / 0`) | 0 (`max=0p`) | `2,850,213` -> **`444,100`** -> `437,250` |
| `ehsm` | `ehsm_create_aes_key` | 5 | 0/5 (`130 / 149`) | **5/5** (`0 / 0`) | 0 (`max=0p`) | 5/5 (`0 / 0`) | 0 (`max=0p`) | `7,839,046` -> **`936,988`** -> `897,494` |

- **Exact Per-Observation Totals Across the 8 Non-`ENCLU` Fields (155 total Field entries across 5 rounds)**:
  - **Group B (`dynamic_xr`, Default `XR`)**: **155 / 155** clean (`s3_aex=0`) observations, **0 / 155** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **155 / 155** achieved `0` residual page-table A/D re-walks.
  - **Group C (`dynamic_refined`, `X-only`)**: **155 / 155** clean (`s3_aex=0`) observations, **0 / 155** interrupt-contaminated (`s3_aex>0`) observations; among clean observations, **155 / 155** achieved `0` residual page-table A/D re-walks.

## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)

- **Symmetric Initial PTE Baseline**: All modes (`Raw`, `No-PreTouch`, `Group A/B/C`) fault in their enclave VMAs at `sgx_create_enclave` time (outside the timed `sgx_ecall` window) and run 1 warmup round before the 5 measured rounds.
- **Direct Hardware Segmented Timing**: `libatfield_native_sgx.so` directly times `ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE)` (`acquire_ns`), the enclave `EENTER` body (`encl_body_ns = elapsed_ns - acquire_ns - release_ns`), and `ioctl(SGX_IOC_ENCLAVE_PAGES_RELEASE)` (`release_ns`) on every `sgx_ecall`.

### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown

| Sample | Protected Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Warm `S2` Pre-Touch (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | 3 | **5/5** | 250.1 | **38.8** | **+9.7** | **298.6** | **+19.39%** (`+48.5 µs`) | 466.7 (`+216.6 µs`) | **4.47x** |
| `signal-cds` | 5 | **5/5** | 87452.4 | **128.9** | **+5.2** | **87585.4** | **+0.15%** (`+133.0 µs`) | 87716.6 (`+264.1 µs`) | **1.99x** |
| `sgxwallet` | 14 | **5/5** | 1353.1 | **34.9** | **-3.3** | **1384.8** | **+2.35%** (`+31.7 µs`) | 1801.2 (`+448.1 µs`) | **14.12x** |
| `ehsm` | 14 | **5/5** | 141.3 | **70.8** | **+3.5** | **216.3** | **+53.09%** (`+75.0 µs`) | 708.0 (`+566.8 µs`) | **7.56x** |

### 4B. Whole-Workflow End-to-End ECALL Sum (`cat=1` Init + `cat=2` Early-Return + `cat=3` Field Calls) & Binary Footprint

| Sample | Call Mix (`Field / Early-Ret / Init`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B Workflow Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `3 / 0 / 0` | **5/5** | 0.74 | 0.75 | 1.40 | **0.90** | 0.90 | **+19.39%** (`+0.15 ms`) | **1.56x** | `2104.7 -> 2116.7 KiB` (**+0.57%**) | `1303 B + 1544 B` |
| `signal-cds` | `5 / 1 / 0` | **5/5** | 437.16 | 437.27 | 438.81 | **438.05** | 438.06 | **+0.18%** (`+0.79 ms`) | **1.00x** | `140.3 -> 155.8 KiB` (**+11.06%**) | `4568 B + 5072 B` |
| `sgxwallet` | `14 / 0 / 4` | **5/5** | 42.10 | 36.03 | 42.38 | **36.44** | 36.65 | **+1.15%** (`+0.41 ms`) | **1.16x** | `2722.2 -> 2818.2 KiB` (**+3.52%**) | `4460 B + 6288 B` |
| `ehsm` | `14 / 16 / 2` | **5/5** | 2.21 | 2.25 | 17.47 | **4.44** | 4.44 | **+97.75%** (`+2.20 ms`) | **3.93x** | `5023.2 -> 5123.3 KiB` (**+1.99%**) | `10230 B + 11720 B` |

## 5. Clean-Checkout Reproducible Workflow

```bash
# 0. Run offline negative & schema/ABI unit tests first
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
python3 controller.py qe3 signal-cds sgxwallet ehsm

# 4. Run calibration, independent hold-out verification, and 5-round 3-group evaluation
python3 tools/evaluate_worksets.py

# 5. Generate summary tables from JSON evidence
python3 tools/generate_report_tables.py
```
