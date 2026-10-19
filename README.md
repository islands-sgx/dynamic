# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)
Historical snapshot: the figures and PASS verdicts below come from stored evidence captured before the vendor source was synchronized to implement commit a3cf16bce12267c4323cabe2b571fdae9a203b01. That evidence does not record its implement source revision. The current evaluator preflight rejects the stale dynamic and dynamic_xr artifacts; rebuild their fields, profiles, signed closures, readiness tables and 4-gate binaries, then rerun the hardware suite before treating these results as current.

All tables in this document are **automatically generated** from `experiments/evaluation_results.json` and `witnesses/<sample>/witness_ledger.json` by `tools/generate_report_tables.py`.

- Frozen initial prototype tag: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)

## 1. Four-Layer Discovery Attribution & Heuristic Assist Breakdown (11 Fields)

| Sample | Field | L0 First Call (`p / eff`) | L1 Full Host (`p / +p`) | L2 Generic Schema+`L*` on Seed (`p`) | L2 Added Beyond Full Host (`+p / +eff`) | L3 Domain Assist (`+p`) | Bridge + Heuristic Assist (`+p`) | Final `FieldTargetPages` | All-REG Baseline | Reduction |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `get_att_key_based_from_seal_key` | 69p / 77e | 69p (`+0`) | **69p** | **+0p / +0e** | +0p | +57p | **126p** | 850p | **85.18%** |
| `signal-cds` | `sabd_lookup_hash` | 16p / 20e | 230p (`+214`) | **554p** | **+324p / +364e** | +0p | +12p | **566p** | 1127p | **49.78%** |
| `sgxwallet` | `ecdsa_sign_field` | 70p / 78e | 76p (`+6`) | **76p** | **+0p / +0e** | +0p | +32p | **108p** | 1774p | **93.91%** |
| `sgxwallet` | `get_public_ecdsa_key_field` | 68p / 74e | 68p (`+0`) | **72p** | **+4p / +4e** | +0p | +28p | **100p** | 1774p | **94.36%** |
| `sgxwallet` | `set_sek_field` | 45p / 52e | 45p (`+0`) | **52p** | **+7p / +7e** | +0p | +22p | **74p** | 1774p | **95.83%** |
| `sgxwallet` | `generate_ecdsa_key_field` | 76p / 82e | 76p (`+0`) | **76p** | **+0p / +0e** | +0p | +30p | **106p** | 1774p | **94.02%** |
| `sgxwallet` | `generate_sek_field` | 48p / 56e | 48p (`+0`) | **48p** | **+0p / +0e** | +0p | +24p | **72p** | 1774p | **95.94%** |
| `ehsm` | `ehsm_create_aes_key` | 263p / 332e | 263p (`+0`) | **263p** | **+0p / +0e** | +0p | +35p | **298p** | 2349p | **87.31%** |
| `ehsm` | `ehsm_generate_datakey` | 90p / 98e | 90p (`+0`) | **264p** | **+174p / +236e** | +0p | +35p | **299p** | 2349p | **87.27%** |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 90p / 97e | 93p (`+3`) | **263p** | **+173p / +234e** | +0p | +35p | **301p** | 2349p | **87.19%** |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 90p / 98e | 266p (`+176`) | **263p** | **+0p / +0e** | +0p | +37p | **303p** | 2349p | **87.1%** |

## 2. Fault Detector Calibration, Same-Fault `AEX0/AEX1`, & Independent Hold-Out Verification

| Sample | Cold TLB Cal (`ipi_mask=7` vs `0` S3 pages) | 4-Gate vs Uninstrumented Output Eq | Single-Page Retraction Caught (`X` / `R` / `W`) | Restored Pos-Ctrl Faults | Same-Fault `AEX0` vs `AEX1` (`active_flag=1`) | Hold-Out Unseen `(page, effect)` | Strict `FieldTargetPages` (`Gate B..D`) Faults | Strict `ReadyTable v3` (`ECALL`) Faults | Overall Verdict |
|---|---|---|---|---:|---|---|---:|---:|---|
| `qe3` | 69p vs 53p (`proven=True`) | `True` | `0xd5000`:`True`, `0x2000`:`True`, `0x1f4000`:`True` | 0 | `0xd5000` -> **PASS** | **0p / 0e** | **0** | **0** | **PASS** |
| `signal-cds` | 16p vs 1p (`proven=True`) | `True` | `0xc000`:`True`, `0x0`:`True`, `0x3d000`:`True` | 0 | `0xc000` -> **PASS** | **0p / 0e** | **0** | **0** | **PASS** |
| `sgxwallet` | 48p vs 29p (`proven=True`) | `True` | `0x16000`:`True`, `0x5000`:`True`, `0x28c000`:`True` | 0 | `0x16000` -> **PASS** | **0p / 0e** | **0** | **0** | **PASS** |
| `ehsm` | 263p vs 246p (`proven=True`) | `True` | `0xdb000`:`True`, `0x57000`:`True`, `0x4c9000`:`True` | 0 | `0xdb000` -> **PASS** | **0p / 0e** | **0** | **0** | **PASS** |

## 3. Three-Group Ablation Across 5 Interleaved Rounds (4-Gate Diagnostic `AEX0` TSC Ticks & `S3` A/D Re-Walk Pages)

- **Group A (`all_reg_xr`)**: All committed business REG pages, all RX pages kept as `XR` (`call C3` + `movb`).
- **Group B (`dynamic_xr`)**: Reduced dynamic + heuristic-assist page set, keeping all RX pages conservatively as `XR`.
- **Group C (`dynamic_refined`)**: Same page set as Group B, refining RX pages without `STT_OBJECT`/RIP-data references to `X`-only.

| Sample | Field | Obs (`5` rounds) | `.atfield_pretouch` Bytes (`A / B / C`) | `S2` Pretouch Median TSC Ticks (`Group A` / `Group B` / `Group C`) | `S3` Residual A/D Re-Walk Pages Median (`Group A` / `Group B` / `Group C`) | `S3` Missing-from-`S2` Pages Max (`B / C`) |
|---|---|---:|---|---:|---:|---:|
| `qe3` | `get_att_key_based_from_seal_key` | 15 | 7376 / 1303 / 859 | 1,416,228 / **155,934** / **134,670** | 3 (max 4) / **3** (max 3) / **3** (max 3) | 0 / 0 |
| `signal-cds` | `sabd_lookup_hash` | 25 | 9060 / 4568 / 4520 | 1,029,044 / **546,064** / **545,038** | 0 (max 15) / **0** (max 1) / **0** (max 223) | 0 / 0 |
| `sgxwallet` | `ecdsa_sign_field` | 50 | 80115 / 4436 / 3326 | 1,619,045 / **105,000** / **108,718** | 14.0 (max 25) / **0.0** (max 0) / **0.0** (max 0) | 0 / 0 |
| `sgxwallet` | `get_public_ecdsa_key_field` | 5 | 80115 / 4436 / 3326 | 1,636,014 / **99,470** / **95,866** | 18 (max 19) / **0** (max 0) / **0** (max 0) | 0 / 0 |
| `sgxwallet` | `set_sek_field` | 5 | 80115 / 4436 / 3326 | 5,140,132 / **193,794** / **184,998** | 11 (max 12) / **1** (max 1) / **1** (max 1) | 0 / 0 |
| `sgxwallet` | `generate_ecdsa_key_field` | 5 | 80115 / 4436 / 3326 | 3,336,602 / **186,462** / **168,262** | 18 (max 22) / **0** (max 0) / **0** (max 0) | 0 / 0 |
| `sgxwallet` | `generate_sek_field` | 5 | 80115 / 4436 / 3326 | 5,263,112 / **193,396** / **175,734** | 12 (max 14) / **1** (max 1) / **1** (max 1) | 0 / 0 |
| `ehsm` | `ehsm_create_aes_key` | 5 | 84112 / 10206 / 8742 | 7,066,002 / **856,804** / **807,446** | 111 (max 127) / **0** (max 0) / **0** (max 0) | 0 / 0 |
| `ehsm` | `ehsm_generate_datakey` | 5 | 84112 / 10206 / 8742 | 2,345,232 / **371,286** / **362,486** | 33 (max 38) / **0** (max 0) / **0** (max 0) | 0 / 0 |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 20 | 84112 / 10206 / 8742 | 2,369,271 / **377,573** / **352,173** | 33.5 (max 44) / **0.0** (max 0) / **0.0** (max 0) | 0 / 0 |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 40 | 84112 / 10206 / 8742 | 2,377,076 / **366,030** / **362,842** | 34.5 (max 137) / **0.0** (max 0) / **0.0** (max 0) | 0 / 0 |

- **Auto-summed non-`ENCLU` Field observations across 5 interleaved rounds**: **155** total observations (Group B `S3=[]` in **130/155**, Group C `S3=[]` in **130/155**).

## 4. Production `AEX1` Signed Final Enclave End-to-End ECALL Wall-Clock Latency (5 Interleaved Rounds, No 4-Gate Fixture)

| Sample | Group A (`all_reg_xr`) Median / Min..Max (ms) | Group B (`dynamic_xr`) Median / Min..Max (ms) | Group C (`dynamic_refined`) Median / Min..Max (ms) | End-to-End Speedup (`Group B` vs `A` / `Group C` vs `A`) |
|---|---:|---:|---:|---:|
| `qe3` | 2.13 ms (2.05..2.20) | **0.84 ms** (0.83..0.86) | **0.84 ms** (0.83..0.85) | **2.52x** / **2.54x** |
| `signal-cds` | 320.14 ms (320.07..321.88) | **318.72 ms** (318.54..318.84) | **318.73 ms** (318.64..319.21) | **1.0x** / **1.0x** |
| `sgxwallet` | 36.41 ms (35.36..36.63) | **26.61 ms** (26.52..26.71) | **26.58 ms** (26.48..26.70) | **1.37x** / **1.37x** |
| `ehsm` | 15.48 ms (13.95..15.91) | **3.90 ms** (3.68..3.92) | **3.74 ms** (3.64..3.85) | **3.97x** / **4.14x** |

## 5. Clean-Checkout Reproducible Workflow

```bash
# 0. Verify that vendored implementation files match the pinned upstream commit
python3 tools/check_vendor_sync.py /path/to/implement
# 1. Build ProfileELFs, All-REG baselines, and signed AEX0/AEX1 artifacts
python3 tools/build_real_targets.py

# 2. Extract compiler-exact EDL marshaling layouts and parameter bindings
python3 tools/edl_harness.py

# 3. Compile native SGX page-table/AEP interposition library
gcc -shared -fPIC -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 \
  -Ivendor/sgxstep src/native_sgx_interpose.c \
  vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c vendor/sgxstep/libsgxstep/debug.c \
  -ldl -lpthread -o build/libatfield_native_sgx.so

# 4. Run 4-layer dynamic exploration, archive witness ledgers + raw JSONL traces, and build Group B/C enclaves
python3 controller.py qe3 signal-cds sgxwallet ehsm

# 5. Run P0-P4 calibration, independent hold-out verification, and 5-round 3-group ablation
python3 tools/evaluate_worksets.py

# 6. Auto-generate summary tables from JSON evidence
python3 tools/generate_report_tables.py
```
