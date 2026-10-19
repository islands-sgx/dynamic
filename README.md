# ATField-SGX Dynamic Workset Explorer (`islands-sgx/dynamic`)

End-to-end, zero-intrusion dynamic workset acquisition, conservative closure, `.atfield_pretouch` generation, `ReadyTable v3` synthesis, and real-SGX 4-Gate / `PTE=0` / `AEX-Notify` hardware verification across all 4 `real` samples (`qe3`, `signal-cds`, `sgxwallet`, `ehsm`, 11 protected Fields).

## 1. Architecture Overview

1. **Zero-Intrusion EDL Schema & Marshaling Introspection (`tools/edl_harness.py`)**
   - Parses `.edl` and `edger8r`-generated `*_u.c` bridges, compiling an introspection probe to emit compiler-exact `offsetof`/`sizeof` marshaling schemas (`targets/<sample>/edl_schema.json`) for every `ms_<ecall>_t` struct without modifying upstream `host` source code.
2. **Layout-Identical 4-Gate ELF Patcher (`tools/patch_4gate.py`)**
   - Places per-Field `Gate A` (pre-`field_enter`), `Gate B` (post-`field_enter` / pre-`.atfield_pretouch`), `Gate C` (post-`.atfield_pretouch` `lfence` / pre-`__atfield_body`), and `Gate D` (post-`field_exit` closing CAS) trampolines into the reserved trailing helper page (`post_start + Q - 0x1000`) of `.atfield_pretouch` without altering any `PT_LOAD` header, section size, or business symbol RVA.
3. **Real-SGX Hardware Footprint & Intervention Interposer (`src/native_sgx_interpose.c` -> `build/libatfield_native_sgx.so`)**
   - `LD_PRELOAD` library that wraps unmodified `host` binaries (`/home/meandssh/islands-sgx/sample/build/real/<sample>/anchor/host`), pins the enclave thread to `CPU 45` and an event-driven 4-Gate Watcher thread to `CPU 1` under `/tmp/atfield_sgxstep.lock`, maps leaf PTEs via `/dev/sgx-step`, and executes:
     - Cross-core IPI TLB shootdowns (`ipi_mask=7` for cold-`S3` profiling; `ipi_mask=3` for warm `S2 -> S3` residency verification) **before** active windows so observer IPIs never interrupt active execution;
     - Live `dlmalloc` (`_gm_`) chunk walks at `Gate D` via `/proc/self/mem`;
     - EDL-typed interventions (`repeat`, `null_ptr`, `set_u32`, `xor_buf`, `ehsm_sizes`, `signal_scales`);
     - Strict non-ready page hardware enforcement (`*pte_slot = 0` on all business REG pages outside `ReadyTable v3`).
4. **Exploration Controller & §4.2 Conservative Closure (`controller.py`)**
   - Orchestrates multi-stage exploration, archives reproducible witnesses (`witnesses/<sample>/witness_ledger.json`), applies `workset-acquisition.md` §4.2 closures (`STT_OBJECT` full span, `dlmalloc` `_gm_` + chunk span + frontier, stack interval + `TD`, direct call-graph + RIP-relative constant reachability, and pure-code `X` vs embedded-data `XR` effect refinement), and invokes `pretouch.py` (`lock orb $0 + lfence`) and `readiness.py` (`ReadyTable v3`).

## 2. Key Real-SGX Hardware Results (`experiments/evaluation_results.json`)

| Sample | Field | Raw 1-Run Pages | Dynamic Explored Pages | Dynamic + Closure Pages (`FieldTargetPages`) | All-Business-REG Baseline Pages | Page Reduction vs All-REG | Pretouch Bytes (Dynamic vs All-REG) | Median `S2` Cycles (Dynamic vs All-REG, Speedup) | Median `S3` Walk Count (Dynamic vs All-REG) | Hold-Out Strict `PTE=0` Faults | `AEX-Notify` Missing-Page Fail-Stop (`0x1006`) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qe3` | `get_att_key_based_from_seal_key` | 69 | 69 | **126** | 850 | **85.18%** | **859 B** vs 7,376 B | **127k** vs 1,515k (**11.89x**) | **3.0** (`ENCLU` op) vs 4.0 | **0 / 5** | PASS (`1`) |
| `signal-cds` | `sabd_lookup_hash` | 16 | 230 | **242** | 1,127 | **78.53%** | **1,928 B** vs 9,060 B | **214k** vs 970k (**4.53x**) | **0.0 (5/5 `S3=[]`)** vs 1.0 (max 13) | **0 / 12** | PASS (`1`) |
| `sgxwallet` | `generate_sek_field` | 48 | 48 | **74** | 1,774 | **95.83%** | **557 B** vs 16,023 B | **202k** vs 5,812k (**28.70x**) | **1.0** (`ENCLU` op) vs 10.0 | **0 / 49** | PASS (`1`) |
| `sgxwallet` | `set_sek_field` | 45 | 52 | **74** | 1,774 | **95.83%** | **557 B** vs 16,023 B | **224k** vs 5,550k (**24.75x**) | **1.0** (`ENCLU` op) vs 12.0 | **0 / 49** | PASS (`1`) |
| `sgxwallet` | `generate_ecdsa_key_field` | 76 | 76 | **105** | 1,774 | **94.08%** | **743 B** vs 16,023 B | **169k** vs 3,614k (**21.42x**) | **0.0 (1/1 `S3=[]`)** vs 13.0 | **0 / 49** | PASS (`1`) |
| `sgxwallet` | `get_public_ecdsa_key_field` | 68 | 72 | **98** | 1,774 | **94.48%** | **702 B** vs 16,023 B | **98k** vs 1,669k (**17.08x**) | **0.0 (1/1 `S3=[]`)** vs 12.0 | **0 / 49** | PASS (`1`) |
| `sgxwallet` | `ecdsa_sign_field` | 70 | 76 | **107** | 1,774 | **93.97%** | **759 B** vs 16,023 B | **110k** vs 1,605k (**14.59x**) | **0.0 (43/43 `S3=[]`)** vs 15.0 (max 24) | **0 / 49** | PASS (`1`) |
| `ehsm` | `ehsm_create_aes_key` | 263 | 263 | **298** | 2,349 | **87.31%** | **2,166 B** vs 21,028 B | **883k** vs 7,113k (**8.05x**) | **0.0 (1/1 `S3=[]`)** vs 133.0 | **0 / 50** | PASS (`1`) |
| `ehsm` | `ehsm_generate_datakey` | 90 | 90 | **193** | 2,349 | **91.78%** | **1,458 B** vs 21,028 B | **288k** vs 2,053k (**7.13x**) | **0.0 (1/1 `S3=[]`)** vs 32.0 | **0 / 50** | PASS (`1`) |
| `ehsm` | `ehsm_aes_gcm_encrypt` | 90 | 93 | **196** | 2,349 | **91.66%** | **1,482 B** vs 21,028 B | **279k** vs 2,075k (**7.44x**) | **0.0 (4/4 `S3=[]`)** vs 35.5 | **0 / 50** | PASS (`1`) |
| `ehsm` | `ehsm_aes_gcm_decrypt` | 90 | 266 | **303** | 2,349 | **87.10%** | **2,212 B** vs 21,028 B | **373k** vs 2,003k (**5.37x**) | **0.0 (8/8 `S3=[]`)** vs 30.5 (max 136) | **0 / 50** | PASS (`1`) |

## 3. Reproducing All Artifacts & Hardware Experiments

```bash
# 1. Build Profile & All-REG Baseline ELFs for all 4 real targets
python3 tools/build_real_targets.py

# 2. Extract compiler-exact EDL / ms_*_t marshaling schemas
python3 tools/edl_harness.py

# 3. Run multi-stage dynamic exploration, §4.2 conservative closure, pretouch finalize, and ReadyTable v3 synthesis
python3 controller.py qe3 signal-cds sgxwallet ehsm

# 4. Run 4-Gate residency, S2 latency, Hold-Out strict PTE=0, and AEX-Notify fail-stop evaluation
python3 tools/evaluate_worksets.py
```
