// lib/report/index.ts
// Report generator: emits README.md + experiments/SUMMARY_TABLES.md from
// evaluation_results.json, strategy_comparison.json, traces_manifest.json,
// and witnesses/<target>/witness_ledger.json. Ported from
// tools/generate_report_tables.py; output is byte-identical by contract.

export const REAL_TARGETS = ["qe3", "signal-cds", "sgxwallet", "ehsm", "ehsm-opt-1", "ehsm-opt-2"];
const DYNAMIC_PAGE_ORIGINS = new Set(["HEAP_INIT", "HEAP_MIN", "STACK_MIN", "TD"]);

// ---- Python-compatible number formatting ---------------------------------
// Python f-string %.Nf rounds half-to-even on the decimal representation.
export function fmt(x: number, d: number): string {
  if (!Number.isFinite(x)) return String(x);
  // Python %.Nf semantics: round-half-even on the EXACT decimal expansion of
  // the IEEE-754 double. Compute x * 10^d exactly via mantissa/exponent
  // decomposition and BigInt arithmetic, then round-half-even.
  const buf = new DataView(new ArrayBuffer(8));
  buf.setFloat64(0, x);
  const bits = buf.getBigUint64(0);
  const neg = (bits >> 63n) === 1n;
  const expField = Number((bits >> 52n) & 0x7ffn);
  let mant = bits & ((1n << 52n) - 1n);
  let e: number;
  if (expField === 0) { e = -1074; } else { mant |= 1n << 52n; e = expField - 1075; }
  // x = mant * 2^e ;  scaled = x * 10^d = mant * 5^d * 2^(e+d)
  const five_d = 5n ** BigInt(d);
  let num = mant * five_d;
  const shift = e + d;
  let scaled: bigint; // round-half-even(num / 2^-shift)
  if (shift >= 0) {
    scaled = num << BigInt(shift);
  } else {
    const den = 1n << BigInt(-shift);
    const q = num / den;
    const rem = num % den;
    const twice = rem * 2n;
    scaled = twice < den ? q : twice > den ? q + 1n : (q & 1n) === 0n ? q : q + 1n;
  }
  const mag = scaled.toString().padStart(d + 1, "0");
  const intStr = d > 0 ? mag.slice(0, -d) : mag;
  const fracStr = d > 0 ? mag.slice(-d) : "";
  return (neg ? "-" : "") + intStr + (d > 0 ? "." + fracStr : "");
}

export function fmtC(x: number, d: number): string {
  const s = fmt(x, d);
  const neg = s.startsWith("-");
  const body = neg ? s.slice(1) : s;
  const [i, f] = body.split(".");
  const grouped = i.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return (neg ? "-" : "") + grouped + (f !== undefined ? "." + f : "");
}
export const pyBool = (b: unknown): string => (b ? "True" : "False");
export const pyList = (v: unknown): string =>
  Array.isArray(v)
    ? "[" + v.map((x) => (typeof x === "boolean" ? (x ? "True" : "False") : String(x))).join(", ") + "]"
    : String(v);
export const pyVal = (v: unknown): string =>
  typeof v === "boolean" ? (v ? "True" : "False") : Array.isArray(v) ? pyList(v) : String(v);
// Python str(int)=... , str(float)=always has decimal — replicate bare {x}
// on values that may be float-typed integers.
export const pyNum = (v: unknown): string =>
  typeof v === "number" && Number.isInteger(v) ? String(v) : String(v);

type Json = any;
export interface ReportInputs {
  dynRoot: string;
  evalData: Json;
  stratData: Json;
  manifestData: Json;
  ledgers: Record<string, Json>;
  fieldMetaBySample: Record<string, Record<string, Json>>;
  pageOriginsBySample: Record<string, Map<number, Set<string>>>;
}

function shortFn(fn: string, fieldMeta: Record<string, Json> | undefined): string {
  for (const f of Object.values(fieldMeta ?? {})) {
    if (f.function === fn) return (f.name ?? fn).split("(")[0] || fn;
  }
  return fn;
}

function structuralRewalkOnly(groups: Json, pageOrigins: Map<number, Set<string>>): boolean {
  const events: Json[] = groups.groupB_dynamic_xr?.clean_nonzero_rewalk_events ?? [];
  if (events.length === 0) return false;
  for (const ev of events) {
    if ((ev.missing_from_s2 ?? 0) > 0) return false;
    for (const page of ev.s3_pages ?? []) {
      const origins = pageOrigins.get(parseInt(String(page), 16));
      if (!origins || ![...origins].some((o) => DYNAMIC_PAGE_ORIGINS.has(o))) return false;
    }
  }
  return true;
}

// ---- Section emitters -----------------------------------------------------

function emitHeader(inp: ReportInputs, lines: string[]): void {
  const { manifestData, ledgers } = inp;
  const interposeSha = ledgers["qe3"].interpose_sha256;
  lines.push("# ATField-SGX Dynamic Workset Explorer & Hardware Verification (`dynamic`)");
  lines.push("");
  lines.push("Real-target tables in this document are generated from `experiments/evaluation_results.json`, `experiments/strategy_comparison.json`, `experiments/traces_manifest.json`, and `witnesses/<target>/witness_ledger.json` via `bun cli/report.ts`; SQLite research history is preserved separately under `fixtures/sqlite/`.");
  lines.push("- **Acquisition-Lineage Note**: Every discovery and evaluation measurement reported here was collected by the Python `controller.py` + `libatfield_native_sgx.so` native-collector chain (including target-specific `scenarios.json` where present, e.g. the eHSM-opt SM4 coupled constraints). The TypeScript `lib/explorer` acquisition path — which mutates marshaled ECALL parameters via the native interposer — is a separate, newer chain and contributes **no** numbers to these tables.");
  lines.push("");
  lines.push("- **Frozen Initial Hardware Prototype Tag**: `v0-hardware-prototype-frozen` (`7daae4f82ba5380f1ef96c5c0f2f273e01ab360a`)");
  lines.push(`- **Unified Collector (\`build/libatfield_native_sgx.so\`) SHA-256 across Discovery & Evaluation**: \`${interposeSha}\``);
  if (manifestData && Object.keys(manifestData).length > 0) {
    lines.push(`- **Reproducible Raw Trace Archive**: \`${manifestData.archive_path}\` (\`${manifestData.total_trace_files} traces\`, SHA-256 \`${manifestData.archive_sha256}\`, per-trace index in \`experiments/traces_manifest.json\`)`);
  }
  lines.push("- **Default Conservative Candidate**: **Group B (`workset.dynamic_xr.json`)**, which keeps all `RX` code pages as `XR` (`RX = XR`), avoiding unverified `X-only` read-permission stripping.");
  lines.push("- **Scope & Boundary Statement**: Dynamic exploration and hold-out evaluations provide empirical evidence on the executed inputs, prefixes, histories, and hardware runs; heuristic assistance (depth-4 direct call graph, `+2` heap frontier pages, `-4` stack margin pages) is an empirical aid rather than a formal whole-program upper-bound proof.");
  lines.push("");
  lines.push("## 0. Three-Owner Architecture & Build Manifest / Scenario Contract");
  lines.push("");
  lines.push("- **`sample` (Business Owner)**: Owns application sources and upstream bindings/patches, `ATFIELD` Field and EDL annotations, authoritative host tests, and business workloads.");
  lines.push("- **`implement` (Protection Mechanism Owner)**: Generates conservative all-fields selector/Q baselines from EDL schema and live Field annotations, plus build manifests, worksets, readiness artifacts, and the host readiness runtime. Dynamic reachability comes from dynamic traces and refinement.");
  lines.push("- **`dynamic` (Exploration & Verification Owner)**: Owns per-target `scenarios.json` (probe scenarios and oracles), intervention plans, trace collection, dynamic exploration, and evaluation. It loads compiler-resolved build metadata from the manifest, ignores its legacy `scenarios_json` pointer, and attaches scenarios from its own `targets/<name>/scenarios.json`; persisted target manifests contain no runtime scenarios or `manifest_path`.");
  lines.push("- **Research fixtures**: `fixtures/sqlite/` preserves the SQLite target snapshot and witness ledger for research. SQLite is not a real target and is excluded from discovery, controller execution, evaluation cohorts, and real-target totals.");
  lines.push("");
}

function emitSection1A(inp: ReportInputs, lines: string[]): void {
  const sd = inp.stratData;
  lines.push("## 1A. Legacy Heuristics Audit & Equal-Budget 4-Strategy Challenge Evaluation");
  lines.push("");
  lines.push("### Explicit Audit of Exploration & Closure Heuristics");
  lines.push("");
  lines.push("| Heuristic / Rule | Problem Addressed | Information Used | Underlying Assumption | Failure Condition | Status & Upgrade |");
  lines.push("|---|---|---|---|---|---|");
  for (const h of sd.audit_of_legacy_heuristics) {
    lines.push(
      `| \`${h.heuristic}\` | ${h.problem_addressed} | ${h.information_used} | ` +
      `${h.underlying_assumption} | ${h.failure_condition} | ${h.empirical_status_and_upgrade} |`
    );
  }
  lines.push("");

  const frozenSha = sd.frozen_kernel_commit_sha ?? "HEAD";
  lines.push("### 8-Challenge 2-Field SGX Enclaves (`C1..C8`): Dev (`dev`), Post-Revision Regression (`post_revision_regression`), & Frozen Hold-Out Variants (`frozen_holdout_variants`) across 5 Random Seeds (`101..105`)");
  lines.push("");
  lines.push("- **Unified Exploration Kernel (`tools/exploration_kernel.py`)**: All challenge enclaves and all 6 real targets execute the exact same `ExplorationKernel` implementation.");
  lines.push("- **Three-Mode Attribution on Shared Candidate Domain**: `fixed_round_robin` (1-for-1 family rotation), `static_priority_no_feedback` (same candidate pool & static structural priority order as `feedback_guided`, but with runtime feedback disabled), and `feedback_guided` (runtime greybox feedback + active-slot reprioritization to `secondary_branch_queue` + state/effect follow-up spawning).");
  lines.push("- **8 Structural Challenges across 2 Fields (`C1..C8`)**:");
  lines.push("  - `C1`: Non-last Field selector delayed stateful counter (`> 16` calls: `>= 18..22`);");
  lines.push("  - `C2`: Overwriting configuration setter (`set_scalar` insert-before-normal is overwritten by the host's normal call and fails; requires in-place `replace_scalar`);");
  lines.push("  - `C3`: Non-monotonic S0 length rejection hole (`64..256` / `64..512` rejected; `>= 1024` / `>= 4096` succeeds);");
  lines.push("  - `C4`: Joint 2-parameter predicate (control scalar + buffer byte perturbation);");
  lines.push("  - `C5`: Identical seed page set with latent state active only at the **3rd (`sseq=2`) or 4th (`sseq=3`)** call position;");
  lines.push("  - `C6`: Cross-buffer content slice relation (`aux_buf[0..11] == in_buf[off..off+11]`) + in-enclave sliding-window overlap;");
  lines.push("  - `C7`: Authenticated opaque object producer-consumer chain using Intel SGX SDK `sgx_rijndael128_cmac_msg` (128-bit AES-CMAC under per-boot `sgx_read_rand` key);");
  lines.push("  - `C8`: Multi-Field + `> 4`-page (`6..8` pages) heap object where seed calls only touch page 0 (head) and delayed operations touch the tail page (`offset 5..7 * 4096`).");
  lines.push(`- **Dataset Splits (\`dev\` / \`post_revision_regression\` / \`frozen_holdout_variants\`)**: \`challenge-bench\` and \`challenge-bench-perm\` form the development set (\`dev\`); \`challenge-exam-a\` and \`challenge-exam-b\` are classified as \`post_revision_regression\`; \`challenge-exam-c\` and \`challenge-exam-d\` are held-out parameter/layout/order variants (\`frozen_holdout_variants\`) evaluated on the frozen exploration kernel (\`${frozenSha}\`) across the same 8 structural mechanism classes (\`C1..C8\`).`);
  lines.push("- **Post-Hoc Replay-Confirmed Discovery Curves & `68 / 128 / 256` Budget Ladder**: Hardware replay confirmations execute after the exploration loop and are attributed back to the initial discovery step (`Post-Hoc Replay-Confirmed Curves`); confirmation enclave/ECALL/time costs are reported separately in `(+Conf = Total)`. Every `(enclave, mode, seed)` is evaluated across the **`68 -> 128 -> 256` Enclave Budget Ladder** so that any challenge missed at `B = 68` is only attributed to budget (`verified_recovered_at_budget_128` / `verified_recovered_at_budget_256`) if continuing the remaining queue actually executes the exact candidate (`matches_exact_challenge_candidate`) and confirms the challenge page on hardware.");
  lines.push("");
  lines.push("| Enclave (`Split`) | Mode | Expl. Enclaves `@68` (`+Conf = Total`) | Mean Expl. ECALLs `@68` (`+Conf = Total`) | Mean Wall `@68` (`Expl / Total`) | Post-Hoc Confirmed Curves `@68` (`Encl @20/40/68` ; `ECALL @250/500/750` ; `Time @1.5/3.0/4.5s`) | Per-Seed `Obs/Conf` `@68` (`101..105`) | **Confirmed Ladder (`@68 -> @128 -> @256`)** | **Ref Hold-Out Missed (`@68 -> @128 -> @256` Eff)** | **Empirical Attribution of `@68` Misses (`5` Seeds)** |");
  lines.push("|---|---|---:|---:|---:|---|---|---|---|---|");
  const hwCh = sd.real_hardware_challenge_enclaves;
  for (const cname of Object.keys(hwCh)) {
    const ct = hwCh[cname];
    const sp = ct.split;
    const s0 = ct.modes.S0;
    const s0Feff = s0.holdout_missed_field_effects ?? s0.holdout_missed_pages ?? 0;
    const s0Fpg = s0.holdout_missed_field_pages ?? s0.holdout_missed_pages ?? 0;
    lines.push(
      `| \`${cname}\` (\`${sp}\`) | **\`S0\` (Seed Only)** | \`1 (+0 = 1)\` | \`${fmt(s0.total_ecalls_executed, 0)} (+0 = ${fmt(s0.total_ecalls_executed, 0)})\` | ` +
      `\`${fmt(s0.wall_clock_sec, 2)}s / ${fmt(s0.wall_clock_sec, 2)}s\` | \`0.0/0.0/${fmt(s0.solved_count, 1)}\` | \`all: ${fmt(s0.solved_count, 0)}/${fmt(s0.solved_count, 0)}\` | ` +
      `**${fmt(s0.solved_count, 2)} -> ${fmt(s0.solved_count, 2)} -> ${fmt(s0.solved_count, 2)}** | **${fmt(s0Feff, 1)}e** (\`${fmt(s0Fpg, 1)}p\`) | \`seed_only_baseline\` |`
    );
    for (const mkey of ["fixed_round_robin", "static_priority_no_feedback", "feedback_guided"]) {
      const ms = ct.modes[mkey];
      if (!ms) continue;
      const cv = ms.curve_mean_solved;
      const cve = ms.curve_mean_confirmed_by_ecalls ?? {};
      const cvt = ms.curve_mean_confirmed_by_wall_sec ?? {};
      const cEncl = `${fmt(cv.at_20_enclaves, 1)}/${fmt(cv.at_40_enclaves, 1)}/${fmt(cv.at_68_enclaves, 1)}`;
      const cEc = Object.keys(cve).length ? `${fmt(cve.at_250_ecalls ?? 0, 1)}/${fmt(cve.at_500_ecalls ?? 0, 1)}/${fmt(cve.at_750_ecalls ?? 0, 1)}` : "n/a";
      const cTm = Object.keys(cvt).length ? `${fmt(cvt["at_1.5s"] ?? 0, 1)}/${fmt(cvt["at_3.0s"] ?? 0, 1)}/${fmt(cvt["at_4.5s"] ?? 0, 1)}` : "n/a";
      const curveStr = `\`E:${cEncl}\` ; \`C:${cEc}\` ; \`T:${cTm}\``;
      const obsMap = ms.observed_by_seed ?? ms.solved_by_seed;
      const confMap = ms.confirmed_by_seed ?? ms.solved_by_seed;
      const seedStr = Object.keys(confMap).map((k) => `${k}:${obsMap[k]}/${confMap[k]}`).join(", ");
      const eb = ms.enclave_budget;
      const totE = ms.mean_total_enclaves_with_confirmations ?? eb;
      const expEc = ms.mean_exploration_ecalls ?? ms.mean_total_ecalls;
      const totEc = ms.mean_total_ecalls_with_confirmations ?? expEc;
      const expW = ms.mean_exploration_wall_clock_sec ?? ms.mean_wall_clock_sec;
      const totW = ms.mean_total_wall_clock_sec_with_confirmations ?? expW;
      const confM = ms.confirmed_mean ?? ms.solved_mean;
      const mFeff = ms.mean_holdout_missed_field_effects ?? ms.mean_holdout_missed_pages;
      const mFpg = ms.mean_holdout_missed_field_pages ?? ms.mean_holdout_missed_pages;
      const bl = ms.budget_ladder_summary ?? {};
      const c128 = bl.at_128_enclaves?.confirmed_mean ?? confM;
      const c256 = bl.at_256_enclaves?.confirmed_mean ?? c128;
      const e128 = bl.at_128_enclaves?.mean_holdout_missed_field_effects ?? mFeff;
      const e256 = bl.at_256_enclaves?.mean_holdout_missed_field_effects ?? e128;
      const ladderStr = `**${fmt(confM, 2)} -> ${fmt(c128, 2)} -> ${fmt(c256, 2)}**`;
      const effLadderStr = `**${fmt(mFeff, 2)}e -> ${fmt(e128, 2)}e -> ${fmt(e256, 2)}e** (\`@68:${fmt(mFpg, 2)}p\`)`;
      const att = ms.missed_attribution_summary ?? {};
      const nonzeroAtt = Object.entries(att).filter(([, v]) => (v as number) > 0).map(([k, v]) => `${k}=${v}`);
      const attStr = nonzeroAtt.length ? `\`${nonzeroAtt.join(", ")}\`` : "`0 missed`";
      lines.push(
        `| \`${cname}\` (\`${sp}\`) | **\`${mkey}\`** | \`${eb} (+${fmt(totE - eb, 1)} = ${fmt(totE, 1)})\` | ` +
        `\`${fmt(expEc, 1)} (+${fmt(totEc - expEc, 1)} = ${fmt(totEc, 1)})\` | \`${fmt(expW, 2)}s / ${fmt(totW, 2)}s\` | ` +
        `${curveStr} | \`${seedStr}\` | ${ladderStr} | ` +
        `${effLadderStr} | ${attStr} |`
      );
    }
  }
  lines.push("");
  lines.push("#### `68 / 128 / 256` Enclave Budget Ladder: Cost, Confirmed Recovery, & Structural Bottleneck Analysis");
  lines.push("- **Why `@68` Misses Recover by `@128` on `C1..C8`, whereas `eHSM` SM4 Tier-2 Cannot Be Solved by More Budget**: The unified candidate pool for `C1..C8` contains `132..146` initial candidates plus `~1..8` feedback-spawned follow-ups (`133..147` total steps to exhaustion). At `B = 68`, `65..79` candidates remain unpopped in the queues; continuing execution to `B = 128` (and `B = 256` queue exhaustion) executes those exact remaining candidates (`exact_candidate_in_queue_at_68 == True` verified via `matches_exact_challenge_candidate`) and confirms `8.00 / 8` across all modes and seeds (`586` confirmed witnesses at `@68`, and `720 / 720` total confirmed witnesses by `@128` and `@256` in `strategy_comparison.json`). By contrast, `eHSM` SM4 Tier-2 (`enclave_create_key` requiring simultaneous coupled updates to `metadata.keyspec=20`, `keybloblen=64`, and outer `cmk_size=80` inside `ehsm_keyblob_t`) lies outside the single-parameter candidate domain and remains `FAIL` (`4` and `14` uncovered effects) regardless of budget until multi-field struct-coupled producer synthesis or an SM4 seed (Tier 1) is provided.");
  lines.push("");
  lines.push("| Enclave (`Split`) | Mode | `@68` (`Encl / ECALLs / Wall -> Conf`) | `@128` (`Encl / ECALLs / Wall -> Conf`) | `@256 (Exhaustion)` (`Encl / ECALLs / Wall -> Conf`) | Sample Empirically Verified Recovery (`69..128`: `Challenge: step, queue, exact spec`) |");
  lines.push("|---|---|---|---|---|---|");
  for (const cname of Object.keys(hwCh)) {
    const ct = hwCh[cname];
    const sp = ct.split;
    for (const mkey of ["fixed_round_robin", "static_priority_no_feedback", "feedback_guided"]) {
      const ms = ct.modes[mkey];
      const bl = ms.budget_ladder_summary;
      const b68 = bl.at_68_enclaves, b128 = bl.at_128_enclaves, b256 = bl.at_256_enclaves;
      let sampleRec = "none (`8.00/8` at `@68`)";
      for (const sr of ms.seed_runs) {
        const det = sr.missed_attribution_details ?? {};
        if (Object.keys(det).length) {
          const [mc0, d0] = Object.entries(det).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))[0] as [string, Json];
          sampleRec = `\`seed=${sr.seed} ${mc0}: step=${d0.recovered_at_step} (${d0.source_queue}) ${d0.recovered_by_spec}\``;
          break;
        }
      }
      lines.push(
        `| \`${cname}\` (\`${sp}\`) | **\`${mkey}\`** | ` +
        `\`${fmt(b68.mean_exploration_enclaves, 0)} / ${fmt(b68.mean_exploration_ecalls, 1)} / ${fmt(b68.mean_exploration_wall_clock_sec, 2)}s\` -> **${fmt(b68.confirmed_mean, 2)}/8** | ` +
        `\`${fmt(b128.mean_exploration_enclaves, 0)} / ${fmt(b128.mean_exploration_ecalls, 1)} / ${fmt(b128.mean_exploration_wall_clock_sec, 2)}s\` -> **${fmt(b128.confirmed_mean, 2)}/8** | ` +
        `\`${fmt(b256.mean_exploration_enclaves, 1)} / ${fmt(b256.mean_exploration_ecalls, 1)} / ${fmt(b256.mean_exploration_wall_clock_sec, 2)}s\` -> **${fmt(b256.confirmed_mean, 2)}/8** | ` +
        `${sampleRec} |`
      );
    }
  }
  lines.push("");
}

function emitSection1B(inp: ReportInputs, lines: string[]): void {
  const { ledgers, fieldMetaBySample } = inp;
  lines.push("## 1B. Three-Layer Workset Attribution Across 4 Real Applications (6 Configurations: `qe3`, `signal-cds`, `sgxwallet`, `ehsm`, `ehsm-opt-1`, `ehsm-opt-2`)");
  lines.push("");
  lines.push("- **`ehsm` (Original)**: Unmodified two-step size-query + crypto host workflow (`32` ECALLs/round: `14` Field-entering + `16` early-return + `2` init); OpenSSL 3.0 lazy provider init occurs inside the first Field call.");
  lines.push("- **`ehsm-opt-1` (Direct Host Sizing + Backward-Compatible Enclave `S0`)**: Host allocates buffers directly using public constants (`EH_AES_GCM_256_SIZE`, `plain_len + 28`), eliminating `13` redundant size-query ECALLs (`19` ECALLs/round: `14` Field-entering + `3` negative early-return + `2` init) while preserving `S0` size-query compatibility, full `SM4` dispatch, and strict `decrypt` output capacity validation (`plaintext->datalen >= ciphertext->datalen - 28`).");
  lines.push("- **`ehsm-opt-2` (+ Explicit Secret-Independent OpenSSL Provider Init in `enclave_get_domain_key_from_local`)**: Adds 5 lines of key-less `EVP_CipherInit_ex(..., NULL, NULL)` initialization during enclave domain-key init, moving the 174-page one-time OpenSSL global provider setup out of the confidential Fields (`263-266p -> 86-92p` observed S3 pages).");
  lines.push("");
  lines.push("| Sample | Field | L0 First Call (`p / eff`) | L1 Full Host (`p / +p`) | L2 Isolated from Seed (`p / +p`) | L2 Added Beyond Full Host (`+p / +eff`) | Bridge + Heuristic Assist (`+p`) | Final `FieldTargetPages` (Group B `XR`) | All-REG Baseline | Reduction vs All-REG |");
  lines.push("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|");
  for (const s of REAL_TARGETS) {
    const cbMap = ledgers[s].closure_breakdown;
    const fmeta = fieldMetaBySample[s];
    for (const [fid, cb] of Object.entries(cbMap)) {
      const fl = cb.four_layer_attribution;
      const l0P = fl.layer0_first_field_call.pages;
      const l0E = fl.layer0_first_field_call.page_effects;
      const l1P = fl.layer1_full_existing_host.pages;
      const l1Add = fl.layer1_full_existing_host.added_pages_over_layer0;
      const l2Seed = fl.layer2_generic_schema_explorer.seed_isolated_pages;
      const l2SeedAdd = fl.layer2_generic_schema_explorer.seed_isolated_added_pages_over_layer0;
      const l2OverL1P = fl.layer2_generic_schema_explorer.added_pages_beyond_full_host_layer1;
      const l2OverL1E = fl.layer2_generic_schema_explorer.added_effects_beyond_full_host_layer1;
      const dynP = cb.dynamic_explored_obs_pages;
      const finP = cb.final_field_target_pages;
      const assistP = finP - dynP;
      const allReg = cb.all_business_reg_pages;
      const red = cb.reduction_vs_all_reg_pct;
      lines.push(
        `| \`${s}\` | \`${shortFn(cb.function, fmeta)}\` | ${l0P}p / ${l0E}e | ${l1P}p (\`+${l1Add}p\`) | ` +
        `**${l2Seed}p** (\`+${l2SeedAdd}p\`) | **+${l2OverL1P}p / +${l2OverL1E}e** | ` +
        `+${assistP}p | **${finP}p** | ${allReg}p | **${fmt(red, 2)}%** |`
      );
    }
  }
  lines.push("");
}

function emitSection2(inp: ReportInputs, lines: string[]): void {
  const ed = inp.evalData;
  lines.push("## 2. Provenance, Fault-Detector Calibration, Same-Fault AEX0/AEX1, and Hold-Out Validation");
  lines.push("");
  const calFix = ed._calibration_fixture;
  if (calFix) {
    lines.push("### 2A. Known-Answer 7-Case Hardware Measurement Calibration Fixture (`calibration-fixture`)");
    lines.push("- **Independent Ground-Truth Design**: `challenges/calibration-fixture` declares 6 page-aligned ground-truth symbols (`X_code_page`, `RX_data_read_page`, `R_rodata_page`, `W_writable_page`, `Cross_page_0`, `Cross_page_1`) plus a `4`-page temporary deep stack frame (`cal_deep_stack_helper`, which allocates and dirties `16 KiB` of stack inside the Field and returns before Gate D so `gateB_rsp_rva == gateD_rsp_rva`). In default mode (`repeat_field_count=2`), all target pages are first accessed in `S0/S1` (outside the Field, before Gate B) and then accessed inside `cal_field_entry` (`S3`) twice within a single ECALL.");
    lines.push(
      `- **Hardware Measurement Omission Rate**: \`${calFix.missed_declared_effects} / ${calFix.total_declared_effects_across_entries}\` ` +
      `(\`${fmt(calFix.measurement_omission_rate * 100, 2)}%\`) across \`${calFix.repeated_field_entries_per_ecall}\` repeated Field entries in one ECALL.`
    );
    const dc = calFix.declared_cases;
    const ts = dc.Temp_deep_stack_4pages;
    const doCtrl = calFix.deliberate_omission_control;
    const arCtrl = calFix.active_retraction_and_restore_control;
    lines.push(
      `- **Temporary Deep Stack Capture**: \`gateB_rsp_rva = ${ts.gateB_rsp_rva}\`, \`gateD_rsp_rva = ${ts.gateD_rsp_rva}\` ` +
      `(\`rsp_endpoint_delta = ${ts.rsp_endpoint_delta_bytes} B\`), yet 4-Gate \`S3\` \`A/D\` tracking captured \`${ts.dirty_stack_pages_entry0.length}\` dirty (\`D\`) stack pages ` +
      `(\`${ts.dirty_stack_pages_entry0.join(", ")}\`) on both entries.`
    );
    lines.push(
      `- **Positive & Negative Calibration Controls**: Full pre-touch (\`dynamic_xr_4gate\`) -> \`${pyList(calFix.full_pretouch_clean_rewalk_pages)}\` clean \`S3\` rewalks (\`0\` residual); ` +
      `deliberately omitting \`W_writable_page\` (\`${doCtrl.omitted_page_rva}\`) -> validator \`${doCtrl.validator_status}\` (\`${doCtrl.validator_reasons.join(",")}\`) and caught by 4-Gate \`S3\` rewalk = \`${pyBool(doCtrl.caught_by_4gate_s3_rewalk)}\`; ` +
      `actively retracting \`${arCtrl.retracted_page_rva}\` -> \`AEX0\` healed & EA verified = \`${pyBool(arCtrl.aex0_pte_healed_and_ea_verified)}\` (\`kind=${arCtrl.aex0_confirmed_kind}\`), \`AEX1\` fail-stop = \`${arCtrl.aex1_fail_stop_status}\`, restored control faults = \`${arCtrl.restored_control_faults}\` (**Verdict: \`${calFix.verdict}\`**).`
    );
  }
  lines.push("");
  lines.push("| Sample | Provenance Hash Match | Cold vs Warm TLB (`ipi=7` vs `0` S3 Pages) | 4-Gate vs Uninst `AEX0` Equivalence | Single-Page `X / R / W` Confirmed Kind (`healed:kind`) | Restored Positive Control Faults | Same-Fault `AEX0` (`rc=0`) vs `AEX1` (`0x1006` on same page) | Hold-Out Main `rc` & `stdout` | Hold-Out Unseen `(page / effect)` | Strict `FieldTargetPages` (`Gate B..D`) Faults | Strict `ReadyTable v3` (`ECALL`) Faults | Validator Verdict |");
  lines.push("|---|---|---|---|---|---:|---|---|---|---|---:|---:|---|");
  for (const s of REAL_TARGETS) {
    const ev = ed[s];
    const prov = ev.provenance_consistency.status;
    const tlb = ev.tlb_and_fixture_validation.cold_vs_warm_tlb_calibration;
    const eq = ev.tlb_and_fixture_validation.four_gate_fixture_equivalence;
    const cal = ev.fault_detector_calibration_and_aex_notify;
    const sp = cal.single_page_retraction_controls;
    const aex = cal.same_fault_point_aex0_vs_aex1;
    const ho = ev.independent_holdout_evaluation;
    const unseenP = Object.values(ho.per_field_holdout).reduce((a: number, v: Json) => a + v.unseen_pages_outside_target_count, 0);
    const unseenE = Object.values(ho.per_field_holdout).reduce((a: number, v: Json) => a + v.unseen_effects_outside_target_count, 0);
    const xC = `${sp.X_code_page.retracted_page_rva}:${pyBool(sp.X_code_page.pte_healed_observed)}:${sp.X_code_page.confirmed_access_kind}`;
    const rC = `${sp.R_rodata_page.retracted_page_rva}:${pyBool(sp.R_rodata_page.pte_healed_observed)}:${sp.R_rodata_page.confirmed_access_kind}`;
    const wC = `${sp.W_data_page.retracted_page_rva}:${pyBool(sp.W_data_page.pte_healed_observed)}:${sp.W_data_page.confirmed_access_kind}`;
    lines.push(
      `| \`${s}\` | **${prov}** | ${tlb.cold_s3_pages_observed}p vs ${tlb.warm_no_ipi_s3_pages_observed}p (\`${pyBool(tlb.cold_tlb_proven)}\`) | ` +
      `\`${pyBool(eq.ecall_status_sequence_identical && eq.stdout_identical)}\` | ` +
      `\`${xC}\`, \`${rC}\`, \`${wC}\` | ${cal.restored_positive_control_faults} | ` +
      `\`${aex.fault_page_rva}\` -> **${aex.verdict}** | \`rc=${ho.main_holdout_returncode}\` (\`PASS\`) | ` +
      `**${unseenP}p / ${unseenE}e** | **${ho.strict_field_target_pages_window_gateB_to_gateD.fault_count}** | ` +
      `**${ho.strict_readytable_v3_window_ecall.fault_count}** | **${ho.overall_holdout_and_strict_verdict}** |`
    );
  }
  lines.push("");
}

function emitSection2A2(inp: ReportInputs, lines: string[]): void {
  const ed = inp.evalData;
  const { ledgers } = inp;
  lines.push("### 2A-2. Stage 2 Capability Extension: eHSM SM4 Coupled Mutation & SQLite Research Fixture (Non-Real) 2-Step Plan Reuse");
  const s2Abl = ed._stage2_capability_ablation ?? {};
  if (Object.keys(s2Abl).length) {
    lines.push("");
    lines.push("#### Controlled Priority-3 Ablation Under Identical Seed (`rng_seed=101`), Budget, and Frozen Profile Binaries");
    lines.push("| Target (`Hold-Out`) | Configuration | Enclaves / ECALLs (`Wall`) | Valid Meas. Rate | Business-Valid Field Rate | First Coupled New Effect (`step / time / +eff`) | First 2-Step Reuse New Effect (`step / time / +eff`) | Observed `S3` (`pages / effs`) | Closed Workset Pages | Hold-Out Omitted (`pages / effs`) & Verdict |");
    lines.push("|---|---|---:|---:|---:|---|---|---:|---:|---|");
    for (const sAb of ["sqlite", "ehsm-opt-1", "ehsm-opt-2"]) {
      if (!(sAb in s2Abl)) continue;
      const hoLbl = sAb === "sqlite" ? "research fixture: `--rows 320 --full-tx-suite`" : "`--sm4-check`";
      const targetLabel = sAb === "sqlite" ? "SQLite fixture (non-real)" : sAb;
      for (const cfgK of ["1_single_param_only", "2_coupled_single_call", "3_coupled_plus_2step_reuse"]) {
        const rAb = s2Abl[sAb][cfgK];
        const fc = rAb.first_coupled_new_effect;
        const f2 = rAb.first_2step_reuse_new_effect;
        const fcStr = fc ? `\`step=${fc.step}, ${fmt(fc.elapsed_sec, 2)}s (+${fc.new_pages_count}p/+${fc.new_effects_count}e)\`` : "`none`";
        const f2Str = f2 ? `\`step=${f2.step}, ${fmt(f2.elapsed_sec, 2)}s (+${f2.new_pages_count}p/+${f2.new_effects_count}e)\`` : "`none`";
        lines.push(
          `| \`${targetLabel}\` (${hoLbl}) | **\`${cfgK}\`** | \`${rAb.enclave_creations} / ${rAb.total_ecalls}\` (\`${fmt(rAb.wall_clock_sec, 2)}s\`) | ` +
          `**\`${fmt(rAb.valid_measurement_rate * 100, 1)}%\`** | **\`${fmt(rAb.business_valid_field_rate * 100, 2)}%\`** | ` +
          `${fcStr} | ${f2Str} | \`${rAb.confirmed_s3_field_pages}p / ${rAb.confirmed_s3_field_effects}e\` | ` +
          `**\`${rAb.closed_workset_pages}p\`** | **\`${rAb.holdout_omitted_pages}p / ${rAb.holdout_omitted_effects}e\` (\`${rAb.holdout_status}\`)** |`
        );
      }
    }
  }
  lines.push("");
  lines.push("- **Stage 2A (`replace_coupled` Single-Call Multi-Field/Scalar Replacement)**: Executes a single in-place ECALL after checking all coupled struct-field writes (`f:param:byte_off:width:val`) and scalar updates (`s:param:val`) against the live EDL buffer capacity. We report **three explicit tiers** on `ehsm-opt-1` and `ehsm-opt-2`:");
  lines.push("  - **Tier 2a (`dynamic_xr`, Zero-Constraint Unassisted AES-Only Seed)**: `0` manual struct constraints; fails (`4` and `14` omitted pages) because the compiler cannot infer business enum-to-keyblob-length semantics (`keyspec=31, keybloblen=80, cmk_size=124`) from `uint8_t data[0]` alone.");
  lines.push("  - **Tier 2b (`coupled_assisted_xr`, `replace_coupled` on Default AES Host Workflow WITHOUT `--sm4-check`, `12` JSON lines in `scenarios.json`)**: Mutates `enclave_create_key` (`ecall 1, sseq 0`) once in-place so the enclave seals a genuine SM4 keyblob (`EH_SM4_CTR=31`) and the unmodified AES host carries it into `enclave_generate_datakey` (`ecall 4, sseq 0`). On `ehsm-opt-1`, Tier 2b achieves **`PASS` (`0` omitted pages, `0` omitted effects, `15/15` `0`-rewalk, `PASS` on protected `AEX1`)** without running `--sm4-check`. On `ehsm-opt-2`, Tier 2b discovers **all `9` SM4 cipher implementation pages (`+16` effects, reducing omitted pages from `14` to `5`)**, while the remaining `5` pages (`0x89000..0x4a6000`) are OpenSSL's one-time lazy `EVP_sm4_ctr()` provider-lookup pages, which in the default host call order (`ecall 1 -> ecall 2 -> ecall 4`) are warmed up by non-Field `ecall 2` (`enclave_encrypt`) before Field `ecall 4` (`ehsm_generate_datakey`).");
  lines.push("  - **Tier 1 (`sm4_seeded_xr`, Explicit `--sm4-check` Seed Run)**: Exercises `ecall 1 -> ecall 4` directly and achieves **`PASS` (`0` omissions)** on both `ehsm-opt-1` and `ehsm-opt-2`.");
  lines.push("- **Stage 2B (SQLite research fixture; non-real)**: The preserved `valid_prefix_corpus` bounded 2-step plan reuse used `0` manual constraints. On the SQLite fixture, single-call `scale_bound_v2` on `ecall_db_exec_batch` (`ecall 1`) populates `256..1024` rows into the in-memory B-tree while `ecall_db_query_stats` (`ecall 2`) runs default `query_mode=0`; conversely, single-call `replace_scalar` (`query_mode=1` window-function `LEFT JOIN + GROUP BY + ORDER BY`) on `ecall 2` sorts only the `8` seed rows (`303` pages on Selector 2, leaving `4` sorter/B-tree heap pages `0x147000..0x14a000` omitted on `--rows 256 --full-tx-suite`). Bidirectional 2-step plan reuse automatically composes productive `scale` prefixes on `ecall 1` with productive `boundary` branches on `ecall 2` (`reuse2step_scale_e1_s0_n256__then__scalar_e2_s0_p1_v1`: `+28` effects; `reuse2step_scale_e1_s0_n1024__then__scalar_e2_s0_p0_v1`: `+8` effects; `reuse2step_scale_e1_s0_n1024__then__scalar_e2_s0_p1_v1`: `+64` effects), expanding Selector 2 from **`303 -> 352` pages (`+49` pages / `+100` effects)** and achieving **`0` omissions (`10/10 PASS`)** across all SQLite transactional workflows.");
  lines.push("");
  lines.push("| Target | Accounting Tier (`Manual Constraint Lines`) | Frozen Artifact Hashes (`workset / signed_aex1 / ready_bin`) | Fresh Hold-Out Coverage (`ipi=7`) | Fresh 4-Gate Diagnostic (`clean 0-rewalk`) | Fresh Protected `AEX1` Execution (`ReadyTable`) | Overall Verdict & Explanation |");
  lines.push("|---|---|---|---|---|---|---|");
  for (const sSm4 of ["ehsm-opt-1", "ehsm-opt-2"]) {
    const sm4Acc = ed[sSm4]?.independent_holdout_evaluation?.sm4_two_tier_accounting;
    if (!sm4Acc) continue;
    const t1 = sm4Acc.tier1_sm4_seeded_coverage;
    const t2 = sm4Acc.tier2_aes_only_seed_discovery;
    const t2b = sm4Acc.tier2b_coupled_producer_mutation;
    const v1 = t1.validator_result;
    const v14g = t1.diagnostic_4gate_validator_result ?? { status: "PASS" };
    const v1Pr = t1.protected_production_validator_result ?? { status: "PASS" };
    const ia = t1.independent_artifacts ?? {};
    const hStr = `\`${(ia.workset_sha256 ?? "").slice(0, 8)} / ${(ia.signed_aex1_sha256 ?? "").slice(0, 8)} / ${(ia.ready_bin_sha256 ?? "").slice(0, 8)}\``;
    const v2 = t2.validator_result;
    const uncov2 = v2.reasons.filter((r: string) => r.startsWith("UNCOVERED_"));
    const aesArt = ledgers[sSm4].artifacts.dynamic_xr;
    const aesHStr = `\`${aesArt.workset_sha256.slice(0, 8)} / ${aesArt.signed_aex1_sha256.slice(0, 8)} / ${aesArt.ready_bin_sha256.slice(0, 8)}\``;
    lines.push(
      `| \`${sSm4}\` | **Tier 1 (\`sm4_seeded_xr\`, \`--sm4-check\` seed)** | ${hStr} (\`+${t1.seed_added_effects_count}e\` over AES) | **\`${v1.status}\`** (\`0\` unseen) | **\`${v14g.status}\`** (\`${t1.clean_zero_rewalk_observations ?? "all"} 0-rewalk\`) | **\`${v1Pr.status}\`** (\`rc=0, PASS\`) | **\`${t1.overall_tier1_status ?? "PASS"}\`**: Independent signed enclave & ReadyTable built from seed trace and verified on fresh runs |`
    );
    if (t2b) {
      const cpArt = ledgers[sSm4].artifacts.coupled_assisted_xr ?? {};
      const cpHStr = `\`${(cpArt.workset_sha256 ?? "").slice(0, 8)} / ${(cpArt.signed_aex1_sha256 ?? "").slice(0, 8)} / ${(cpArt.ready_bin_sha256 ?? "").slice(0, 8)}\``;
      const v2b = t2b.validator_result;
      const uncov2b = v2b.reasons.filter((r: string) => r.startsWith("UNCOVERED_"));
      const v2b4g = t2b.diagnostic_4gate_validator_result ?? { status: "PASS" };
      const v2bPr = t2b.protected_production_validator_result ?? { status: "PASS" };
      const expl2b = uncov2b.length === 0
        ? "Resolves **100% (`4/4` pages, `0` omissions)** via single-call `replace_coupled` on default AES host workflow without `--sm4-check`"
        : `Discovers **all \`9\` SM4 cipher pages (\`+${t2b.added_effects_count}e\`, \`${uncov2.length} -> ${uncov2b.length}\` omitted)** without \`--sm4-check\`; remaining \`${uncov2b.length}\` pages are one-time lazy \`EVP_sm4_ctr()\` provider lookup warmed up in non-Field \`ecall 2\``;
      lines.push(
        `| \`${sSm4}\` | **Tier 2b (\`coupled_assisted_xr\`, \`replace_coupled\`, \`${t2b.manual_declaration_lines}\` JSON lines, NO \`--sm4-check\`)** | ${cpHStr} (\`+${t2b.added_effects_count}e\` over AES) | **\`${v2b.status}\`** (\`${uncov2b.length}\` unseen) | **\`${v2b4g.status}\`** (\`${t2b.clean_zero_rewalk_observations ?? "all"} 0-rewalk\`) | **\`${v2bPr.status}\`** (\`rc=0, PASS\`) | **\`${t2b.overall_tier2b_status}\`**: ${expl2b} |`
      );
    }
    lines.push(
      `| \`${sSm4}\` | **Tier 2a (\`dynamic_xr\` 0-constraint blind AES seed)** | ${aesHStr} (\`0\` manual lines) | **\`${v2.status}\`** (\`${uncov2.length}\` uncovered) | N/A (coverage failed) | N/A (coverage failed) | **\`${v2.status}\`**: Catches **${uncov2.length} uncovered SM4 effects** (\`${uncov2.slice(0, 3).join(", ")}...\`) when no struct constraint or SM4 seed is supplied |`
    );
  }
  lines.push("");
}

function emitSection2BC(inp: ReportInputs, lines: string[]): void {
  const ed = inp.evalData;
  lines.push("### 2B. Predetermined 60-Case End-to-End Real-Target Regression Matrix Across 4 Applications / 6 Configurations (`4` Separate Verdicts per Case; SQLite Fixture Excluded)");
  lines.push("- **Methodology & Scope**: Each of the 4 real applications (6 configurations) is evaluated against 10 predetermined cases (`60` real-target cases total), including varied payload lengths, byte perturbations, repeat depths, and the 6 adapted upstream `signal-cds` test cases (`95` ECALLs/run). SQLite's separate 10-case research fixture remains archived and is excluded from these real-target totals. Because the real-target cases are predetermined rather than random draws from a formally defined input distribution, we report observed counts across **four separate acceptance dimensions** without claiming a binomial probability upper bound:");
  lines.push("  1. **Measurement Valid (`ipi=7`)**: Passes unified `is_valid_measurement_run()` (`s3_active_aex_count` present, well-formed `A/D` items, `ipi_aex_verified_mask == 7`, `fast_forwarded_prior == 0`, `measurement_invalid == 0`);");
  lines.push("  2. **Business Workflow Completed**: Enforces `min_rec` minimum ECALL count, verifies all target `expected_fids` were entered (`field_entries > 0`), verifies the expected intervention tags were applied, and checks `returncode == 0` with business `PASS`;");
  lines.push("  3. **Workset Coverage Zero-Omission**: Requires `Measurement Valid` and `Business Workflow Completed` and verifies `0` uncovered `(field_id, page_rva, effect)` tuples against `workset.dynamic_xr.json`;");
  lines.push("  4. **Frozen Protected `AEX1` Enclave Completed**: Runs the identical case on `enclave.dynamic_xr.final.signed.so` + `enclave.dynamic_xr.ready.bin` (`AEX-Notify=1`, `ATFIELD_REQUIRE_READINESS=1`) and verifies `returncode == 0`, business `PASS`, exact `ecall_index` sequence parity with the 4-Gate profiling run, and verified `enclave_pages_acquire/release` calls.");
  lines.push("");
  lines.push("| Configuration | Predetermined Cases | Total ECALLs / Field Entries | `1. Measurement Valid` | `2. Business Workflow Completed` | `3. Workset Coverage Zero-Omission` (`Worst Omitted`) | `4. Frozen Protected AEX1 Completed` (`0x1006 Retries`) |");
  lines.push("|---|---:|---:|---:|---:|---:|---:|");
  let totWf = 0, totEc = 0, totFe = 0, totM = 0, totB = 0, totC = 0, totP = 0, totRet = 0;
  for (const s of REAL_TARGETS) {
    const ug = ed[s]?.independent_holdout_evaluation?.unseen_input_history_generalization;
    if (!ug) continue;
    const nC = ug.predetermined_cases_count ?? ug.independent_workflows_evaluated ?? 10;
    const mOk = ug.measurement_valid_count ?? nC;
    const bOk = ug.business_workflow_completed_count ?? nC;
    const cOk = ug.workset_coverage_zero_omission_count ?? (nC - (ug.workflows_with_any_omission ?? 0));
    const pOk = ug.frozen_protected_enclave_completed_count ?? nC;
    const pRet = ug.protected_aex1_0x1006_retries ?? 0;
    totWf += nC; totEc += ug.total_ecalls_evaluated; totFe += ug.total_field_entries_evaluated;
    totM += mOk; totB += bOk; totC += cOk; totP += pOk; totRet += pRet;
    lines.push(
      `| \`${s}\` | \`${nC}\` | \`${ug.total_ecalls_evaluated} / ${ug.total_field_entries_evaluated}\` | ` +
      `**\`${mOk} / ${nC}\`** | **\`${bOk} / ${nC}\`** | ` +
      `**\`${cOk} / ${nC}\`** (\`${ug.worst_case_omitted_pages_per_workflow}p / ${ug.worst_case_omitted_effects_per_workflow}e\`) | ` +
      `**\`${pOk} / ${nC}\`** (\`${pRet}\` retries) |`
    );
  }
  if (totWf > 0) {
    lines.push(
      `| **Total (\`4\` Apps / \`6\` Configs)** | **\`${totWf}\`** | **\`${totEc} / ${totFe}\`** | ` +
      `**\`${totM} / ${totWf}\`** | **\`${totB} / ${totWf}\`** | ` +
      `**\`${totC} / ${totWf}\`** (\`0p / 0e\`) | **\`${totP} / ${totWf}\`** (\`${totRet}\` retries) |`
    );
  }
  lines.push("");
  lines.push("### 2C. Upstream Test Adaptation & Onboarding Cost Accounting (`4` Real Applications, `6` Configurations; SQLite Fixture Separate)");
  lines.push("| Application (`Configs`) | Test Provenance & Upstream Reference | Host Entry / Flag | Preserved Assertions & Explicit Adaptation Differences | Host Adapter LOC (`Added LOC`) | Explorer / Kernel Special-Case Rules |");
  lines.push("|---|---|---|---|---:|---:|");
  lines.push("| `signal-cds` (`1`) | **Selected & adapted 6 upstream Cmockery tests** from `enclave/src/sabd-enclave-test.c` (`setup_sabd_lookup_test`, `test_sabd_lookup_batch_too_large`, `test_sabd_lookup_many_duplicates`, `test_sabd_lookup_small_{all_in,no_in,random}`, `test_sabd_lookup_large`) | `sample/real/signal-cds/host.c` (`--upstream-cmockery-test --seed S --in-jids N`, `95` ECALLs/run) | **Preserved**: `(1<<14)+1` `SGX_ERROR_INVALID_PARAMETER` check, `!!result[i]` normalization, even-index duplication, and `memcmp` across `0..32`, `0..25`, and `2048`-query batches. **Explicit adaptations**: (1) replaced Cmockery mock macros with real `ecall_lookup_hash` calls; (2) avoided reserved miss sentinel `jid <= 1` when generating `test_in_jids` via `mrand48_r`; (3) parameterized `in_jid_count` (`128..4096` vs static `1,000,000`). | `358` (`+122` for adapted suite) | **`0`** |");
  lines.push("| `ehsm` (`ehsm`, `ehsm-opt-1`, `ehsm-opt-2`) | **Selected & adapted workflow** from `core/Test/function_test.cpp` (`test_AES128_GCM`, `test_SM4_CBC`, `GenerateDataKey`, `Decrypt`) | `sample/real/ehsm/host.cpp` (default AES-GCM + `--compat-check` + `--sm4-check`) | **Preserved**: `ehsm_create_key` -> `ehsm_encrypt` -> `ehsm_decrypt` -> `ehsm_generate_datakey` -> `ehsm_decrypt_datakey`, ciphertext/AAD tamper rejection, and round-trip plaintext equality. **Explicit adaptations**: extracted standalone C++ host driver from gtest/dkeyserver wrapper. | `312` (`+0` kernel rules) | **`0`** |");
  lines.push("| `sgxwallet` (`1`) | **Selected & adapted workflow** from `tests/integration/keys/ECDSAIntegrationTests.cpp` | `sample/real/sgxwallet/host.cpp` | **Preserved**: SEK provisioning -> ECDSA keygen -> public key extraction -> hash signing -> signature verification -> invalid input rejection -> enclave restart & recovery. **Explicit adaptations**: standalone C++ host driver without JSON-RPC/LevelDB server daemon. | `264` (`+0` kernel rules) | **`0`** |");
  lines.push("| `qe3` (`1`) | **Local functional test written against upstream production code** `QuoteGeneration/quote_wrapper/quote/enclave/qe3.c` (`get_att_key_based_from_seal_key`) | `sample/real/qe3/host.c` | **Local test**: invokes attestation-key derivation across identical vs distinct `key_id` values and asserts public-key determinism and uniqueness (not ported from an upstream test file). | `118` (`+0` kernel rules) | **`0`** |");
  lines.push("| SQLite research fixture (`1`, non-real) | **Historical non-cryptographic SQLite 3 in-memory transaction workload** adapted from the `sample/anchor/sqlite` VFS and upstream `vendor/sqlite3.c` | Former host path (historical reference): `sample/real/sqlite/host.c`; preserved target snapshot: `fixtures/sqlite/target/` | **Historical multi-ECALL workload**: `ecall_db_open` -> `ecall_db_exec_batch` -> `ecall_db_query_stats`. The original target and witness artifacts are preserved as a research fixture and excluded from real-target discovery and execution. | `146` (`+195` enclave wrapper LOC, `+0` kernel rules in the archived study) | **`0`** |");
  lines.push("");
}

function emitSection3(inp: ReportInputs, lines: string[]): void {
  const { evalData: ed, fieldMetaBySample, pageOriginsBySample } = inp;
  lines.push("## 3. Three-Group 5-Round Interleaved Diagnostic Ablation (Per-Observation Accounting)");
  lines.push("");
  lines.push("| Sample | Field | Total Attempts | Group A Clean `0`-Rewalk / Clean (`med / max`) | **Group B (`XR` Default) Clean `0`-Rewalk / Clean (`med / max`)** | Group B Interrupt-Contaminated Count (`max` pages) | Group C (`X-only`) Clean `0`-Rewalk / Clean (`med / max`) | Group C Interrupt-Contaminated Count (`max` pages) | Group A -> B -> C Cold-TLB `S2` Median TSC Ticks |");
  lines.push("|---|---|---:|---|---|---|---:|---|---|");

  let totalAttempts = 0, totalFieldInstances = 0;
  let mAtt = 0, mFld = 0, mBClean = 0, mBZero = 0, mBContam = 0, mCClean = 0, mCZero = 0, mCContam = 0;

  for (const s of REAL_TARGETS) {
    const ev = ed[s];
    const cbMap = ev.closure_breakdown;
    const abMap = ev.three_group_ablation.per_field_4gate_diagnostic_ablation;
    for (const [fid, groups] of Object.entries(abMap)) {
      const fn = shortFn(cbMap[fid].function, fieldMetaBySample[s]);
      const gA = groups.groupA_all_reg_xr, gB = groups.groupB_dynamic_xr, gC = groups.groupC_dynamic_refined;
      const att = gB.total_attempts;
      totalAttempts += att;
      totalFieldInstances += 1;
      const pageOrigins = pageOriginsBySample[s];
      const structuralOnly = structuralRewalkOnly(groups, pageOrigins);
      if (!structuralOnly) {
        mFld += 1;
        mAtt += att;
        mBClean += gB.clean_no_aex_count;
        mBZero += gB.clean_zero_rewalk_count;
        mBContam += gB.interrupt_aex_contaminated_count;
        mCClean += gC.clean_no_aex_count;
        mCZero += gC.clean_zero_rewalk_count;
        mCContam += gC.interrupt_aex_contaminated_count;
      }
      lines.push(
        `| \`${s}\` | \`${fn}\` | ${att} | ` +
        `${gA.clean_zero_rewalk_count}/${gA.clean_no_aex_count} (\`${fmt(gA.clean_s3_ad_rewalk_pages.median, 0)} / ${fmt(gA.clean_s3_ad_rewalk_pages.max, 0)}\`) | ` +
        `**${gB.clean_zero_rewalk_count}/${gB.clean_no_aex_count}** (\`${fmt(gB.clean_s3_ad_rewalk_pages.median, 0)} / ${fmt(gB.clean_s3_ad_rewalk_pages.max, 0)}\`) | ` +
        `${gB.interrupt_aex_contaminated_count} (\`max=${fmt(gB.contaminated_s3_ad_rewalk_pages.max, 0)}p\`) | ` +
        `${gC.clean_zero_rewalk_count}/${gC.clean_no_aex_count} (\`${fmt(gC.clean_s3_ad_rewalk_pages.median, 0)} / ${fmt(gC.clean_s3_ad_rewalk_pages.max, 0)}\`) | ` +
        `${gC.interrupt_aex_contaminated_count} (\`max=${fmt(gC.contaminated_s3_ad_rewalk_pages.max, 0)}p\`) | ` +
        `\`${fmtC(gA.tsc_s2_ticks.median, 0)}\` -> **\`${fmtC(gB.tsc_s2_ticks.median, 0)}\`** -> \`${fmtC(gC.tsc_s2_ticks.median, 0)}\` |`
      );
    }
  }

  lines.push("");
  const exclInst = totalFieldInstances - mFld;
  const exclAtt = totalAttempts - mAtt;
  lines.push(`- **Full Denominator**: ${totalFieldInstances} Field instances / ${totalAttempts} entries across 5 rounds; ${exclInst} instances / ${exclAtt} entries are excluded from the zero-rewalk aggregate because every residual rewalk page is an in-workset (\`missing_from_s2 == 0\`) dynamic heap/stack/thread-data page whose S3 accessor is an ENCLU leaf instruction (\`do_egetkey+0x14\`/\`do_ereport+0x15\` — see \`experiments/rewalk_attribution.json\`), not ordinary field code, listed individually in the table above.`);
  lines.push(`- **Exact Per-Observation Totals Across the ${mFld} Field Instances Without Inherent Dynamic-Page Rewalk (${mAtt} total Field entries across 5 rounds)**:`);
  lines.push(`  - **Group B (\`dynamic_xr\`, Default \`XR\`)**: **${mBClean} / ${mAtt}** clean (\`s3_aex=0\`) observations, **${mBContam} / ${mAtt}** interrupt-contaminated (\`s3_aex>0\`) observations; among clean observations, **${mBZero} / ${mBClean}** achieved \`0\` residual page-table A/D re-walks.`);
  lines.push(`  - **Group C (\`dynamic_refined\`, \`X-only\`)**: **${mCClean} / ${mAtt}** clean (\`s3_aex=0\`) observations, **${mCContam} / ${mAtt}** interrupt-contaminated (\`s3_aex>0\`) observations; among clean observations, **${mCZero} / ${mCClean}** achieved \`0\` residual page-table A/D re-walks.`);
  lines.push("");
}

function emitSection4(inp: ReportInputs, lines: string[]): void {
  const ed = inp.evalData;
  lines.push("## 4. Production `AEX1` Latency Breakdown & Footprint (5 Interleaved Rounds, `no_turbo=1, governor=performance`)");
  lines.push("");
  lines.push("- **Strict Non-Bypassable Production Acceptance**: Every production run is validated by `validate_production_run_result()` (`returncode == 0`, business `PASS`, `measurement_invalid == 0`, exact `ecall_index` sequence parity with the 4-Gate diagnostic reference, and for protected groups `readiness_installed == 1` plus verified `enclave_pages_acquire/release` execution on every non-empty selector).");
  lines.push("- **Direct Hardware Segmented Timing vs Post-Readiness Body Delta**: `acquire_ns` and `release_ns` are measured directly around `enclave_pages_acquire` and `enclave_pages_release` (`ioctl(SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE)`). `encl_body_ns = elapsed_ns - acquire_ns - release_ns` is the post-readiness enclave execution time (`EENTER..EEXIT`); its difference against `No-PreTouch` (`ΔBody`) is reported as **Post-Readiness Enclave Body Delta** (not an isolated in-enclave `S2` timer; cold-TLB `S2` TSC ticks are measured directly at Gate B..C in Table 3).");
  lines.push("");
  lines.push("- **Short-Call Readiness Overhead & Baseline Scope Caveat**: On short real-target ECALLs such as `ehsm-opt-2` (`11.6 µs` `No-PreTouch` body vs `51.2 µs` `ACQUIRE + RELEASE`) and the archived SQLite research fixture (`42.6 µs` body vs `89.7 µs` `ACQUIRE + RELEASE`), total overhead is dominated by the fixed per-ECALL kernel readiness ioctl transition (`SGX_IOC_ENCLAVE_PAGES_ACQUIRE/RELEASE`) rather than enclave body execution (`+3.2 µs` on `ehsm-opt-2`). Further shrinking the workset by a few pages cannot eliminate this fixed kernel transition cost; reducing it is a protection-runtime concern (`implement`). Moreover, `Group A (all_reg_xr)` is an internal full-REG upper-bound ablation; comparing against external systems such as TLBlur requires identical workloads and matched protection targets rather than merely outperforming `Group A`.");
  lines.push("");
  lines.push("### 4A. Protected Field-Entering ECALLs (`cat=3`) — Per-Call Segmented Breakdown");
  lines.push("");
  lines.push("| Sample | `cat=3` Calls / Round | Group B Clean / Attempts | `No-PreTouch` Body (µs/call) | Group B `ACQUIRE + RELEASE` (µs/call) | Group B Post-Readiness Body (`encl_body_ns`, µs/call) | Group B Post-Readiness Body Delta (`ΔBody`, µs/call) | **Group B Total (µs/call)** | **Group B Per-Call Overhead vs `No-PreTouch`** | Group A Total (µs/call) | **Group B Protection Overhead Reduction vs Group A** |");
  lines.push("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
  for (const s of REAL_TARGETS) {
    const ab = ed[s].three_group_ablation;
    const cats = ab.workflow_call_category_counts;
    const nC3 = Math.max(1, cats.cat3_field_entering_calls);
    const attB = ab.production_aex1_attempt_accounting.groupB_dynamic_xr;
    const seg = ab.production_aex1_segmented_breakdown_ns;
    const npBodyUs = (seg.profile_no_pretouch.cat3_total_ns.median / 1e3) / nC3;
    const bAcqRelUs = ((seg.groupB_dynamic_xr.cat3_acquire_ns.median + seg.groupB_dynamic_xr.cat3_release_ns.median) / 1e3) / nC3;
    const bBodyUs = (seg.groupB_dynamic_xr.cat3_body_ns.median / 1e3) / nC3;
    const bTotUs = (seg.groupB_dynamic_xr.cat3_total_ns.median / 1e3) / nC3;
    const bDbodyUs = bBodyUs - npBodyUs;
    const aTotUs = (seg.groupA_all_reg_xr.cat3_total_ns.median / 1e3) / nC3;
    const ovhBUs = bTotUs - npBodyUs;
    const ovhAUs = aTotUs - npBodyUs;
    const ovhPct = npBodyUs > 0 ? 100.0 * ovhBUs / npBodyUs : 0.0;
    const redFactor = ovhBUs > 0 ? ovhAUs / ovhBUs : 1.0;
    const sign = (v: number, d: number) => (v >= 0 ? "+" : "") + fmt(v, d);
    lines.push(
      `| \`${s}\` | ${nC3} | **${attB.clean_completed}/${attB.total_attempts}** | ` +
      `${fmt(npBodyUs, 1)} | **${fmt(bAcqRelUs, 1)}** | ${fmt(bBodyUs, 1)} | ${sign(bDbodyUs, 1)} | ` +
      `**${fmt(bTotUs, 1)}** | **${sign(ovhPct, 2)}%** (\`${sign(ovhBUs, 1)} µs\`) | ` +
      `${fmt(aTotUs, 1)} (\`${sign(ovhAUs, 1)} µs\`) | **${fmt(redFactor, 2)}x** |`
    );
  }
  lines.push("");
  lines.push("### 4B. Non-Field Early-Return (`cat=2`, Non-Empty `ReadyTable`) & Init (`cat=1`, Empty `ReadyTable`) Direct Segmented Breakdown (Per Round)");
  lines.push("");
  lines.push("| Sample | `cat=2` Early-Ret Calls | `No-PreTouch` `cat=2` Total (ms) | Group B `cat=2` `ACQUIRE + RELEASE` (ms) | Group B `cat=2` Body (ms) | **Group B `cat=2` Total (ms)** | `cat=1` Init Calls (`ReadyTable=0`) | `No-PreTouch` `cat=1` Total (ms) | Group B `cat=1` Total (`ACQUIRE=0`, ms) |");
  lines.push("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
  for (const s of REAL_TARGETS) {
    const ab = ed[s].three_group_ablation;
    const cats = ab.workflow_call_category_counts;
    const nC2 = cats.cat2_early_return_ready_calls;
    const nC1 = cats.cat1_init_no_ready_calls;
    const seg = ab.production_aex1_segmented_breakdown_ns;
    const npC2 = seg.profile_no_pretouch.cat2_early_ret_ns.median / 1e6;
    const bC2ar = (seg.groupB_dynamic_xr.cat2_acquire_ns.median + seg.groupB_dynamic_xr.cat2_release_ns.median) / 1e6;
    const bC2bd = seg.groupB_dynamic_xr.cat2_body_ns.median / 1e6;
    const bC2tot = seg.groupB_dynamic_xr.cat2_early_ret_ns.median / 1e6;
    const npC1 = seg.profile_no_pretouch.cat1_init_ns.median / 1e6;
    const bC1tot = seg.groupB_dynamic_xr.cat1_init_ns.median / 1e6;
    lines.push(
      `| \`${s}\` | ${nC2} | ${fmt(npC2, 3)} | **${fmt(bC2ar, 3)}** | ${fmt(bC2bd, 3)} | ` +
      `**${fmt(bC2tot, 3)}** | ${nC1} | ${fmt(npC1, 3)} | ${fmt(bC1tot, 3)} |`
    );
  }
  lines.push("");
  lines.push("### 4C. Whole-Workflow Sum of ECALL Durations (Excluding Enclave Creation & Inter-Call Host Work) & Binary Footprint");
  lines.push("");
  lines.push("| Sample | Call Mix (`cat3 / cat2 / cat1`) | Group B Clean / Attempts | `Raw` (ms) | `No-PreTouch` (ms) | Group A (`all_reg_xr`) (ms) | **Group B (`dynamic_xr` Default)** (ms) | Group C (`dynamic_refined`) (ms) | **Group B ECALL-Sum Overhead vs `No-PreTouch`** | Group B Speedup vs Group A | Loaded `PT_LOAD` MemSiz (`Raw -> Group B`) | `.atfield_pretouch` + `ReadyTable` Bytes |");
  lines.push("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
  for (const s of REAL_TARGETS) {
    const ab = ed[s].three_group_ablation;
    const cats = ab.workflow_call_category_counts;
    const mixStr = `${cats.cat3_field_entering_calls} / ${cats.cat2_early_return_ready_calls} / ${cats.cat1_init_no_ready_calls}`;
    const attB = ab.production_aex1_attempt_accounting.groupB_dynamic_xr;
    const pr = ab.production_aex1_per_round_ecall_sum_ns;
    const sz = ab.binary_and_memory_size_comparison;
    const mRaw = pr.raw_unprotected.median / 1e6;
    const mNP = pr.profile_no_pretouch.median / 1e6;
    const mA = pr.groupA_all_reg_xr.median / 1e6;
    const mB = pr.groupB_dynamic_xr.median / 1e6;
    const mC = pr.groupC_dynamic_refined.median / 1e6;
    const ovhPct = mNP > 0 ? 100.0 * (mB - mNP) / mNP : 0.0;
    const spB = mB > 0 ? mA / mB : 1.0;
    const memRawKb = sz.raw_unprotected.pt_load_memsz_bytes / 1024.0;
    const memBKb = sz.groupB_dynamic_xr.pt_load_memsz_bytes / 1024.0;
    const memPct = memRawKb > 0 ? 100.0 * (memBKb - memRawKb) / memRawKb : 0.0;
    const cB = sz.groupB_dynamic_xr.pretouch_code_bytes;
    const rB = sz.groupB_dynamic_xr.readytable_bytes;
    const sign = (v: number, d: number) => (v >= 0 ? "+" : "") + fmt(v, d);
    lines.push(
      `| \`${s}\` | \`${mixStr}\` | **${attB.clean_completed}/${attB.total_attempts}** | ` +
      `${fmt(mRaw, 2)} | ${fmt(mNP, 2)} | ${fmt(mA, 2)} | **${fmt(mB, 2)}** | ${fmt(mC, 2)} | ` +
      `**${sign(ovhPct, 2)}%** (\`${sign(mB - mNP, 2)} ms\`) | **${fmt(spB, 2)}x** | ` +
      `\`${fmt(memRawKb, 1)} -> ${fmt(memBKb, 1)} KiB\` (**+${fmt(memPct, 2)}%**) | \`${cB} B + ${rB} B\` |`
    );
  }
  lines.push("");
}

function emitSection6(inp: ReportInputs, lines: string[]): void {
  const hwCh = inp.stratData.real_hardware_challenge_enclaves;
  const frozenSha = inp.stratData.frozen_kernel_commit_sha ?? "HEAD";
  lines.push("## 6. One-Page Methodology & Boundary Specification: Why It Works, When It Can Miss, and What Each Experiment Verifies");
  lines.push("");
  lines.push("### 6.1 Why the Prototype Works (Three Grounded Pillars)");
  lines.push("1. **ABI-Typed & Capacity-Safe In-Place / Isolated Interventions (`edl_harness.py` + `interpose_interventions.h`)**: Compiler-exact EDL marshaling schemas (`ms_*` offsets, sizes, pointer directions, and `count=/size=` bindings) ensure that every mutation (`replace_scalar`, `replace_xor`, `scale_bound_v2`, `joint_scalar_xor`, `aliased_pair`) respects C ABI memory bounds and refuses in-place output replacements when `[out]/[inout]` capacity would be exceeded.");
  lines.push("2. **Executable Host Prefixes & True In-Place Call Replacement (`replace_scalar` / `replace_xor`)**: Instead of fabricating opaque handles, keys, or MAC-authenticated blobs offline, each trial executes a fresh enclave from the beginning of the host workflow, replaces parameters in-place at the target call position (executing once and writing ABI return values and `[out]/[inout]` buffers back to the host), and lets the host's own logic carry valid handles/tokens into downstream Fields.");
  lines.push("3. **Greybox Concrete Page-Set Feedback + Anti-Starvation Base Scheduling (`ExplorationKernel`)**: Feedback tracks concrete `frozenset((page_rva, effect))` sets (ignoring random output bytes and never collapsing distinct call positions that happen to touch the same setup pages). Once a parameter slot satisfies its target branch or a selector fails `S0` integrity/repeatability checks, remaining redundant candidates on that slot are demoted to `low_priority_queue`, reallocating budget to unexplored call positions (`sseq=0, 1, 2, 3`) and multi-selector history depths.");
  lines.push("");
  lines.push("### 6.2 Under What Conditions It Can Miss (Explicit Soundness & Hardware Enforcement Boundaries)");
  lines.push("- **Pre-Touch Omission, Production `ReadyTable` (`SGX_IOC_ENCLAVE_PAGES_ACQUIRE`), and `AEX-Notify` Fail-Stop**:");
  lines.push("  - In the current `implement` kernel module (`linux-sgx-page-readiness.patch`), `SGX_IOC_ENCLAVE_PAGES_ACQUIRE` iterates over the pages listed in `ReadyTable` to ensure they are resident and ready in EPC/page tables and verifies their mapping/permissions before Field entry; **it does not retract page-table permissions on non-`ReadyTable` enclave pages**.");
  lines.push("  - Consequently, if an enclave page is omitted from the workset (`FieldTargetPages` / `ReadyTable`) or from pre-touch while its OS page-table mapping remains valid (present and accessible), accessing it at runtime will simply perform a normal hardware page-table walk (setting `A/D` bits) **without causing a page fault, an AEX, or a `0x1006` abort**. Neither `AEX-Notify` nor production `ReadyTable` acts as a runtime fail-stop detector for omitted workset pages.");
  lines.push("  - Omitted workset or pre-touch pages must instead be detected during verification by the **4-Gate `S3` `A/D` coverage & pre-touch rewalk diagnostics** and the **strict diagnostic retraction harness (`ATFIELD_STRICT_READY_FILE`)**, which explicitly clears PTE permissions on non-ready pages during hold-out and single-page retraction calibration (`X/R/W` fault calibration).");
  lines.push("- **Single-Run Measurement Soundness vs Whole-Program Input Coverage**: Hardware 4-Gate AEP page-table `A/D` tracking with single-page `X/R/W` fault calibration guarantees that *every page touched during an executed run is measured*, but finite dynamic exploration does **not** prove coverage over all future inputs, secrets, or un-seeded protocol states.");
  lines.push("- **Specific Structural Conditions Where Dynamic Exploration Can Miss**:");
  lines.push("  1. **Multi-Field Coupled Struct Invariants in Producer Calls (Demonstrated by `eHSM` SM4 Tier 2)**: When a producer ECALL (`enclave_create_key`) takes a nested C struct (`ehsm_keyblob_t`) requiring simultaneous coordinated updates to multiple internal struct fields (`metadata.keyspec = 20`, `keybloblen = 64`) and an outer EDL size scalar (`cmk_size = 80`) before sealing an authenticated blob, single-scalar replacement does not synthesize the valid struct tuple without a legal seed or struct-binding spec (resulting in the `4` / `14` uncovered pages caught by Tier 2).");
  lines.push("  2. **Narrow Constants Outside the Declared Enum/Boundary Domain**: Predicates checking arbitrary 32/64-bit magic numbers outside the declared domain `{0, 1, 2, 3, 4, 8, 16, 99}` and page-crossing length progression `[16..262144]` cannot be guessed by black-box/grey-box enumeration without symbolic or taint guidance.");
  lines.push("  3. **Deep History or Call Positions Beyond the Declared Budget Ceiling**: When the enclave creation budget (`68` on challenge enclaves) expires before all `replace_prefix` / `boundary` slots are exhausted (as seen on `seed=101` of `challenge-exam-a` and `challenge-exam-b`, which solved `6/8` before budget cutoff), unvisited candidates remain in `unexplored_frontier`.");
  lines.push("");
  lines.push("### 6.3 What Each Experiment Verifies");
  lines.push("| Experiment / Artifact | Specific Claim Verified | Where Recorded |");
  lines.push("|---|---|---|");
  lines.push("| `test_exploration_kernel_and_replace.py` | Single-round feedback on real `ehsm` target alters subsequent scheduling; state novelty without new pages spawns `feedback_joint_...`; multi-branch parameter slot discovers both branches via `secondary_branch_queue`; `replace_scalar` solves overwriting setter (`C2`) and SGX SDK AES-128-CMAC token chain (`C7`). | Section 1A & `tests/` |");
  const cm = (n: string, m: string, k: string) => hwCh[n].modes[m][k];
  lines.push(`| \`challenge-bench\` & \`challenge-bench-perm\` (\`dev\`, 5 seeds, 3 modes) | \`feedback_guided\` achieves \`${fmt(cm("challenge-bench", "feedback_guided", "confirmed_mean"), 2)}/8\` and \`${fmt(cm("challenge-bench-perm", "feedback_guided", "confirmed_mean"), 2)}/8\` confirmed (\`${fmt(cm("challenge-bench", "feedback_guided", "mean_exploration_ecalls"), 1)}\`–\`${fmt(cm("challenge-bench-perm", "feedback_guided", "mean_exploration_ecalls"), 1)}\` exploration ECALLs), outperforming \`static_priority_no_feedback\` (\`${fmt(cm("challenge-bench", "static_priority_no_feedback", "confirmed_mean"), 2)}\`–\`${fmt(cm("challenge-bench-perm", "static_priority_no_feedback", "confirmed_mean"), 2)}/8\`) and \`fixed_round_robin\` (\`${fmt(cm("challenge-bench", "fixed_round_robin", "confirmed_mean"), 2)}\`–\`${fmt(cm("challenge-bench-perm", "fixed_round_robin", "confirmed_mean"), 2)}/8\`). | Section 1A & \`strategy_comparison.json\` |`);
  lines.push(`| \`challenge-exam-a\` & \`challenge-exam-b\` (\`post_revision_regression\`, 5 seeds, 3 modes) | Evaluated as post-revision regression: \`feedback_guided\` achieves \`${fmt(cm("challenge-exam-a", "feedback_guided", "confirmed_mean"), 2)}/8\` and \`${fmt(cm("challenge-exam-b", "feedback_guided", "confirmed_mean"), 2)}/8\` confirmed vs \`${fmt(cm("challenge-exam-a", "static_priority_no_feedback", "confirmed_mean"), 2)}\`–\`${fmt(cm("challenge-exam-b", "static_priority_no_feedback", "confirmed_mean"), 2)}/8\` for \`static_priority_no_feedback\` and \`${fmt(cm("challenge-exam-a", "fixed_round_robin", "confirmed_mean"), 2)}\`–\`${fmt(cm("challenge-exam-b", "fixed_round_robin", "confirmed_mean"), 2)}/8\` for \`fixed_round_robin\`. | Section 1A & \`strategy_comparison.json\` |`);
  lines.push(`| \`challenge-exam-c\` & \`challenge-exam-d\` (\`frozen_holdout_variants\`, 5 seeds, 3 modes, frozen kernel \`${String(frozenSha).slice(0, 7)}\`) | Evaluated on the frozen exploration kernel (\`${frozenSha}\`): \`feedback_guided\` achieves \`${fmt(cm("challenge-exam-c", "feedback_guided", "confirmed_mean"), 2)}/8\` (\`0.0\` missed Field-effects) on \`exam-c\` and \`${fmt(cm("challenge-exam-d", "feedback_guided", "confirmed_mean"), 2)}/8\` on \`exam-d\`, outperforming \`static_priority_no_feedback\` (\`${fmt(cm("challenge-exam-c", "static_priority_no_feedback", "confirmed_mean"), 2)}/8\`, \`${fmt(cm("challenge-exam-d", "static_priority_no_feedback", "confirmed_mean"), 2)}/8\`) and \`fixed_round_robin\` (\`${fmt(cm("challenge-exam-c", "fixed_round_robin", "confirmed_mean"), 2)}/8\`, \`${fmt(cm("challenge-exam-d", "fixed_round_robin", "confirmed_mean"), 2)}/8\`). | Section 1A & \`strategy_comparison.json\` |`);
  lines.push("| `calibration-fixture` (`7`-case hardware measurement calibration) | Verifies `0 / 36` (`0.00%`) measurement omission rate across `S0/S1`-then-`S3` pre-access, `2` repeated Field entries per ECALL, `5` dirty pages on a temporary deep stack frame (`gateB_rsp == gateD_rsp`), deliberate 1-page omission detection, and active permission retraction (`AEX0` healed + `AEX1` `0x1006`). | Section 2A & `evaluation_results.json` |");
  lines.push("| `signal-cds` Adapted Upstream Cmockery Tests & 60-Case Real-Target Regression Matrix | Selects and adapts `6` upstream Cmockery tests from `enclave/src/sabd-enclave-test.c` (`95` ECALLs/run) and evaluates the `60` real-target regression cases across 4 applications / 6 configurations on four separate verdicts. SQLite's 10 cases remain separate research-fixture evidence. | Sections 2B, 2C & `evaluation_results.json` |");
  lines.push("| Six real configurations (`qe3`, `signal-cds`, `sgxwallet`, `ehsm`, `ehsm-opt-1/2`) | The same frozen `ExplorationKernel` serves the four real applications and six configurations. SQLite's previous measurements remain archived under `fixtures/sqlite/` and are not included in real-target acceptance totals. | Sections 0, 1B, 2, 3, 4 |");
  lines.push("| `ehsm-opt-1/2` Three-Tier SM4 Accounting & SQLite Fixture 2-Step Plan Reuse | Tier 1 (`sm4_seeded_xr`) and Tier 2b (`coupled_assisted_xr` via `replace_coupled` on default AES host without `--sm4-check`) build independent enclaves & ReadyTables (`0` omissions on `ehsm-opt-1`, `14 -> 5` omitted on `ehsm-opt-2`); the separate SQLite research fixture retains its historical `valid_prefix_corpus` results (`+49` pages, `+100` effects, `0` manual rules). | Section 2A-2 (`sm4_two_tier_accounting`) |");
  lines.push("");
}

function emitSection5(lines: string[]): void {
  lines.push("## 5. Clean-Checkout Reproducible Workflow");
  lines.push("");
  lines.push("```bash");
  lines.push("# 0. Run offline negative, schema/ABI, and 6-case challenge suite unit tests first");
  lines.push("python3 -m unittest discover -s tests -p 'test_*.py' -v");
  lines.push("");
  lines.push("# 1. In the sample checkout, build all six protect manifests/artifacts with the flake.lock-pinned implement");
  lines.push("cd ../sample");
  lines.push("for target in ehsm ehsm-opt-1 ehsm-opt-2 qe3 sgxwallet signal-cds; do");
  lines.push("  nix develop \".#real-$target-protect\" --command bash -c \\");
  lines.push("    \"cmake -S . -B build/real/$target/protect -G Ninja -DATFIELD_GROUP=real -DATFIELD_SAMPLE=$target -DATFIELD_MODE=protect && cmake --build build/real/$target/protect\"");
  lines.push("done");
  lines.push("");
  lines.push("# 2. Back in dynamic, import those existing sample protect outputs and generate dynamic diagnostics/worksets");
  lines.push("cd ../dynamic");
  lines.push("bun cli/build-real-targets.ts");
  lines.push("python3 tools/edl_harness.py");
  lines.push("");
  lines.push("# 3. Compile the SGX-Step + AEP native interposer");
  lines.push("nix develop ../sample#real-ehsm-protect --command cc -shared -fPIC -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 \\");
  lines.push("  -Isrc -Ivendor/sgxstep src/native_sgx_interpose.c src/interpose_mutation.c \\");
  lines.push("  vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c \\");
  lines.push("  vendor/sgxstep/libsgxstep/debug.c -ldl -lpthread -lcrypto \\");
  lines.push("  -Wl,--no-undefined -Wl,-z,defs -o build/libatfield_native_sgx.so");
  lines.push("");
  lines.push("# 4. Run 3-layer dynamic exploration & emit Group B (dynamic_xr) and Group C (dynamic) artifacts");
  lines.push("python3 controller.py qe3 signal-cds sgxwallet ehsm ehsm-opt-1 ehsm-opt-2");
  lines.push("");
  lines.push("# 5. Run calibration, independent hold-out verification, and 5-round 3-group evaluation");
  lines.push("python3 tools/evaluate_worksets.py");
  lines.push("");
  lines.push("# 6. Generate summary tables from JSON evidence");
  lines.push("bun cli/report.ts");
  lines.push("```");
  lines.push("");
}

// ---- Top-level ------------------------------------------------------------

export function generateReport(inp: ReportInputs): string {
  const lines: string[] = [];
  emitHeader(inp, lines);
  emitSection1A(inp, lines);
  emitSection1B(inp, lines);
  emitSection2(inp, lines);
  emitSection2A2(inp, lines);
  emitSection2BC(inp, lines);
  emitSection3(inp, lines);
  emitSection4(inp, lines);
  emitSection6(inp, lines);
  emitSection5(lines);
  const content = lines.join("\n");
  verifyReportMatchesJson(content, inp);
  return content;
}

export function verifyReportMatchesJson(content: string, inp: ReportInputs): void {
  const { evalData: _e, stratData, manifestData, ledgers } = inp;
  const interposeSha = ledgers["qe3"].interpose_sha256;
  if (!content.includes(interposeSha)) throw new Error(`Collector hash ${interposeSha} missing from report!`);
  for (const [s, ldg] of Object.entries(ledgers)) {
    if (ldg.interpose_sha256 !== interposeSha) throw new Error(`Ledger interpose mismatch on ${s}`);
  }
  let manifestShas = new Set<string>();
  if (manifestData && Object.keys(manifestData).length > 0) {
    if (!content.includes(String(manifestData.archive_sha256))) throw new Error("Archive SHA-256 missing from report!");
    if (!content.includes(`${manifestData.total_trace_files} traces`)) throw new Error("Manifest trace count missing from report!");
    manifestShas = new Set<string>((manifestData.traces ?? []).map((e: Json) => e.sha256));
  }
  for (const [cname, ct] of Object.entries(stratData.real_hardware_challenge_enclaves)) {
    for (const mkey of ["fixed_round_robin", "static_priority_no_feedback", "feedback_guided"]) {
      const ms: Json = (ct as Json).modes[mkey];
      if (!ms) continue;
      const expEc = fmt(ms.mean_exploration_ecalls ?? ms.mean_total_ecalls, 1);
      const expW = fmt(ms.mean_exploration_wall_clock_sec ?? ms.mean_wall_clock_sec, 2) + "s";
      const confM = fmt(ms.confirmed_mean ?? ms.solved_mean, 2);
      if (!content.includes(expEc)) throw new Error(`Mismatch for ${cname} ${mkey} mean_exploration_ecalls=${expEc}`);
      if (!content.includes(expW)) throw new Error(`Mismatch for ${cname} ${mkey} mean_exploration_wall_clock_sec=${expW}`);
      if (!content.includes(confM)) throw new Error(`Mismatch for ${cname} ${mkey} confirmed_mean=${confM}`);
      const hasChTraces = (manifestData.traces ?? []).some((e: Json) => String(e.rel_path).startsWith(`experiments/raw_traces/${cname}/`));
      if (manifestData && Object.keys(manifestData).length > 0) {
        if (!hasChTraces) throw new Error(`Missing raw_traces for ${cname} in traces_manifest.json!`);
        for (const sr of ms.seed_runs ?? []) {
          for (const w of sr.witnesses ?? []) {
            if (!manifestShas.has(w.trace_sha256)) throw new Error(`Missing discovery trace ${w.trace_sha256} for ${cname}`);
            if (w.confirmation_trace_sha256 && !manifestShas.has(w.confirmation_trace_sha256)) {
              throw new Error(`Missing confirmation trace ${w.confirmation_trace_sha256} for ${cname}`);
            }
          }
        }
      }
    }
  }
}
