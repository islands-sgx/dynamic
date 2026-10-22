import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalJson } from "../bundle/profile-bundle.ts";
import { resolveRunnerCpuConfig, runSeedCommands } from "./canonical-runner.ts";

const temporaryRoots: string[] = [];
const digest = (value: string): string => createHash("sha256").update(value).digest("hex");

function makeBundle(): { root: string; manifest: string; observations: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), "canonical-runner-test-"));
  temporaryRoots.push(root);
  const artifactsDir = path.join(root, "bundle");
  mkdirSync(artifactsDir, { recursive: true });
  const bundleFields = [{ id: "field-1", name: "fixture field" }];
  const edlAbiObj = {
    schema: "atfield-edl-abi-v1",
    tool: { name: "sgx_edger8r", version: "fixture" },
    input: { root: "enclave.edl", imports: [] },
    ecalls: [
      {
        ordinal: 0,
        name: "fixture_ecall",
        visibility: "public",
        switchless: false,
        parameters: [],
        return_type: { kind: "builtin", name: "void" },
      },
    ],
    ocalls: [],
    types: [],
  };
  const fieldsObj = {
    schema: "atfield-fields-v1",
    fields: bundleFields,
  };
  const edlAbiText = JSON.stringify(edlAbiObj) + "\n";
  const fieldsText = JSON.stringify(fieldsObj) + "\n";
  const profileContent = "profile ELF fixture";
  const signedProfileContent = "signed profile ELF fixture";
  const marshalLayoutObj = {
    schema: "atfield-marshal-layout-v1",
    input: {
      edl_abi_sha256: digest(edlAbiText),
      untrusted_bridge_c_sha256: "11".repeat(32),
      untrusted_bridge_h_sha256: "22".repeat(32),
    },
    tool: { name: "atfield-marshal-layout", version: "1", compiler: "gcc" },
    ecalls: [
      {
        ordinal: 0,
        name: "fixture_ecall",
        visibility: "public",
        switchless: false,
        replay_supported: true,
        ms_size: 0,
        retval: null,
        params: [],
      },
    ],
  };
  const compileVariant = { target_triple: "x86_64-unknown-linux-gnu", optimization_level: "2", relocation_model: "pic", backend_flags: ["-O2"] };
  const irFact = {
    schema: "atfield-ir-facts-v2",
    translation_unit: "src/enclave.c",
    module_id: "irtu_00000000000000000000000000000001",
    backend_ir_sha256: "33".repeat(32),
    object_sha256: "44".repeat(32),
    compile_variant: compileVariant,
    source: { input_file: "src/enclave.c", ir_filename: "obj/enclave.after-boundary.ll" },
    callgraph_complete: true,
    guidance_complete: true,
    diagnostics: [],
    definitions: [
      { symbol: "fixture_ecall", linkage: "external", source_file: "src/enclave.c", address_use: { address_taken: false, complete: true, reasons: [] } },
    ],
    direct_calls: [],
    unknown_indirect: [],
    guidance_sites: [],
  };
  const irFactsObj = { schema: "atfield-ir-facts-aggregate-v2", facts: [irFact] };
  const reachInput = {
    profile_elf_sha256: digest(profileContent),
    edl_abi_sha256: digest(edlAbiText),
    live_fields_sha256: digest(fieldsText),
    expected_objects: [{ translation_unit: irFact.translation_unit, object_sha256: irFact.object_sha256 }],
    ir_facts_tus: [{
      translation_unit: irFact.translation_unit,
      module_id: irFact.module_id,
      backend_ir_sha256: irFact.backend_ir_sha256,
      object_sha256: irFact.object_sha256,
      variant_sha256: digest(canonicalJson(compileVariant)),
      facts_sha256: digest(canonicalJson(irFact)),
    }],
  };
  const reachEcall = {
    ordinal: 0,
    name: "fixture_ecall",
    visibility: "public",
    switchless: false,
    status: "verified",
    entry_symbol: "fixture_ecall",
    private: false,
    callgraph_complete: true,
    guidance_complete: true,
    field_reachability_complete: true,
    reachable_function_instances: [],
    reachability: "static-may-reach",
    evidence: {},
    reachable_fields: ["field-1"],
    reachable_functions: ["fixture_ecall"],
    unknown_indirect: false,
    unknown_external: false,
    function_closure_complete: true,
  };
  const reachabilityObj = {
    schema: "atfield-reachability-v1",
    version: 1,
    algorithm: "fixture-v1",
    tool: { name: "atfield-reachability", version: "1" },
    analysis: { kind: "fixture", profile_elf_sha256: digest(profileContent) },
    input: reachInput,
    live_field_ids: ["field-1"],
    ecalls: [reachEcall],
  };
  const layout = {
    epoch: "",
    page_size: 4096,
    capacity_q: 4096,
    ordinary_load_end: "0x1000",
    pretouch_start: "0x1000",
    enclave_size: 12288,
    ssa_frame_pages: 1,
    regions: [],
    excluded_regions: [],
  };
  const measurementManifestObj = {
    schema: "atfield-measurement-profile-v1",
    identity: {
      profile_elf_sha256: digest(profileContent),
      signed_profile_elf_sha256: digest(signedProfileContent),
      fields_sha256: digest(fieldsText),
    },
    layout: {
      metadata_version: 1,
      ssa_frame_pages: layout.ssa_frame_pages,
      page_size: layout.page_size,
      enclave_size: layout.enclave_size,
      ordinary_load_end: layout.ordinary_load_end,
      pretouch_start: layout.pretouch_start,
      capacity_q: layout.capacity_q,
      pretouch_segment: null,
      regions: layout.regions,
      excluded_regions: layout.excluded_regions,
      relro_ranges: [],
      relro_pages: [],
    },
    artifacts: {
      profile_elf: { path: "profile_elf", sha256: digest(profileContent) },
      signed_profile_elf: { path: "signed_profile_elf", sha256: digest(signedProfileContent) },
    },
    collector: {
      abi: "atfield-4gate-native-v1",
      page_size: 4096,
      tcs_ranges: [{ start_rva: "0x1000", end_rva: "0x1100" }],
      ssa_ranges: [{ start_rva: "0x1000", end_rva: "0x2000" }],
      gate_helper_range: { start_rva: "0x1000", end_rva: "0x2000" },
      guard_manager_rva: "0x1000",
      layout_spec: "tcs=0x1000;ssa=0x1000;gm=0x1000;pretouch=0x1000:0x2000;gate=0x1000:0x2000",
      active_field_rva: null,
      pretouch: { start_rva: "0x1000", end_rva: "0x2000", capacity_q: 4096 },
      stack_ranges: [],
      excluded_regions: [],
    },
  };
  const artifacts: Record<string, string> = {
    profile_elf: profileContent,
    signed_profile_elf: signedProfileContent,
    edl_abi: edlAbiText,
    fields: fieldsText,
    measurement_manifest: JSON.stringify(measurementManifestObj) + "\n",
    marshal_layout: JSON.stringify(marshalLayoutObj) + "\n",
    ir_facts: JSON.stringify(irFactsObj) + "\n",
    reachability: JSON.stringify(reachabilityObj) + "\n",
  };
  for (const [name, content] of Object.entries(artifacts)) {
    writeFileSync(path.join(artifactsDir, name), content);
  }
  const hostPath = path.join(artifactsDir, "fake-host.cjs");
  const hostSource = [
    "#!" + (Bun.which("node") ?? "/usr/bin/env node"),
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const mode = process.argv[2] || 'ok';",
    "if (mode === 'collector-error') { process.stdout.write('fixture child stdout\\n'); process.stderr.write('ATFIELD_TRACE_ERROR: injected collector fault\\n'); }",
    "const observation = {",
    "  seed_id: process.env.ATFIELD_SEED_ID,",
    "  pid: process.pid,",
    "  state_dir: process.env.ATFIELD_STATE_DIR,",
    "  state_arg: process.argv[3],",
    "  bundle_root: process.env.ATFIELD_BUNDLE_ROOT,",
    "  bundle_arg: process.argv[4],",
    "  cwd: process.cwd(),",
    "  bundle_link: fs.lstatSync(path.join(process.env.ATFIELD_BUNDLE_ROOT, 'fake-host.cjs')).isSymbolicLink() || fs.statSync(path.join(process.env.ATFIELD_BUNDLE_ROOT, 'fake-host.cjs')).isFile(),",
    "  home: process.env.HOME,",
    "  data: process.env.XDG_DATA_HOME,",
    "  cache: process.env.XDG_CACHE_HOME,",
    "  tmp: process.env.TMPDIR,",
    "  fresh: !fs.existsSync(path.join(process.env.ATFIELD_STATE_DIR, 'already-used')),",
    "  use_4gate: process.env.ATFIELD_USE_4GATE,",
    "  ipi_mask: process.env.ATFIELD_IPI_MASK,",
    "  gate_mode: process.env.ATFIELD_GATE_MODE,",
    "  mode: process.env.ATFIELD_MODE,",
    "  leaked_custom_atfield: process.env.ATFIELD_EXTERNAL_LEAK || null,",
    "};",
    "fs.writeFileSync(path.join(process.env.ATFIELD_STATE_DIR, 'already-used'), 'yes');",
    "if (process.env.ATFIELD_TEST_OBSERVATIONS) {",
    "  fs.appendFileSync(process.env.ATFIELD_TEST_OBSERVATIONS, JSON.stringify(observation) + '\\n');",
    "}",
    "if (mode === 'bad-json') {",
    "  fs.writeFileSync(process.env.ATFIELD_TRACE_PATH, '{broken-json\\n');",
    "} else {",
    "  const start = {",
    "    schema: 'atfield-canonical-trace-v1',",
    "    record_type: 'run_start',",
    "    run_id: process.env.ATFIELD_RUN_ID,",
    "    layout_epoch: process.env.ATFIELD_LAYOUT_EPOCH,",
    "    instance_generation: null,",
    "    sample: process.env.ATFIELD_SAMPLE,",
    "    mode: process.env.ATFIELD_MODE,",
    "    start_time: new Date().toISOString(),",
    "    selected_enclave_sha256: process.env.ATFIELD_ENCLAVE_SHA256,",
    "    bundle_manifest_sha256: process.env.ATFIELD_BUNDLE_MANIFEST_SHA256,",
    "  };",
    "  const records = [start];",
    "  if (mode !== 'bad-json') {",
    "    const emptyPhase = { page_size: 4096, complete: true, page_effects: [] };",
    "    const touchedPhase = { page_size: 4096, complete: true, page_effects: [{ rva: '0x1000', a: true, d: false }] };",
    "    const s2Phase = process.env.ATFIELD_MODE === 'verify-pretouch' ? touchedPhase : emptyPhase;",
    "    const s3Phase = process.env.ATFIELD_MODE === 'verify-pretouch' ? emptyPhase : touchedPhase;",
    "    records.push({",
    "      schema: start.schema,",
    "      record_type: 'ecall',",
    "      run_id: start.run_id,",
    "      layout_epoch: start.layout_epoch,",
    "      bundle_manifest_sha256: start.bundle_manifest_sha256,",
    "      instance_generation: 1,",
    "      call_seq: 0,",
    "      selector_ordinal: 0,",
    "      selector_seq: 0,",
    "      tag: 'fixture',",
    "      elapsed_ns: 1,",
    "      sgx_status: 0,",
    "      abi_return_type: 'void',",
    "      abi_return_value: 0,",
    "      out_status_i32: 0,",
    "      measurement_valid: true,",
    "      measurement_invalid_reasons: [],",
    "      aex: { count: mode === 'aex' ? 1 : 0 },",
    "      fields: [{",
    "        field_id: 'field-1',",
    "        phases: { S0_BRIDGE: emptyPhase, S1_ENTER: emptyPhase, S2_PRETOUCH: s2Phase, S3_BODY: s3Phase },",
    "      }],",
    "    });",
    "  }",
    "  if (mode === 'bad-sequence') {",
    "    records.push({ ...records[1], call_seq: 2, selector_seq: 1 });",
    "  }",
    "  if (mode === 'collector-end') {",
    "    records.push({",
    "      schema: start.schema,",
    "      record_type: 'run_end',",
    "      run_id: start.run_id,",
    "      layout_epoch: start.layout_epoch,",
    "      bundle_manifest_sha256: start.bundle_manifest_sha256,",
    "      instance_generation: 1,",
    "      process_return_code: 0,",
    "      timeout: false,",
    "      record_count: 1,",
    "      completion: 'complete',",
    "      incomplete_reasons: [],",
    "    });",
    "  }",
    "  fs.writeFileSync(process.env.ATFIELD_TRACE_PATH, records.map((record) => JSON.stringify(record)).join('\\n') + '\\n');",
    "  if (mode === 'hang') setInterval(() => {}, 1000);",
    "  if (mode === 'orphan-pipe') {",
    "    const child = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'inherit' });",
    "    child.unref();",
    "  }",
    "}",
  ].join("\n") + "\n";
  writeFileSync(hostPath, hostSource);
  chmodSync(hostPath, 0o755);

  const artifactPaths: Record<string, { path: string; sha256: string }> = {};
  for (const [name, content] of Object.entries(artifacts)) {
    artifactPaths[name] = { path: name, sha256: digest(content) };
  }
  const hostBytes = readFileSync(hostPath);
  artifactPaths.host = { path: "fake-host.cjs", sha256: createHash("sha256").update(hostBytes).digest("hex") };
  layout.epoch = digest(canonicalJson({
    profile_elf_sha256: artifactPaths.profile_elf.sha256,
    signed_profile_elf_sha256: artifactPaths.signed_profile_elf.sha256,
    page_size: layout.page_size,
    capacity_q: layout.capacity_q,
    ordinary_load_end: layout.ordinary_load_end,
    pretouch_start: layout.pretouch_start,
    enclave_size: layout.enclave_size,
    ssa_frame_pages: layout.ssa_frame_pages,
    regions: layout.regions,
    excluded_regions: layout.excluded_regions,
  }));
  const manifest = {
    schema: "atfield-profile-bundle-v1",
    identity: {
      profile_elf_sha256: artifactPaths.profile_elf.sha256,
      signed_profile_elf_sha256: artifactPaths.signed_profile_elf.sha256,
      edl_abi_sha256: artifactPaths.edl_abi.sha256,
      fields_sha256: artifactPaths.fields.sha256,
    },
    layout,
    artifacts: artifactPaths,
    fields: bundleFields,
    selectors: [{
      ordinal: 0,
      name: "fixture_ecall",
      visibility: "public",
      switchless: false,
      entry_rva: "0x1000",
      reachable_fields: ["field-1"],
      reachability: "fixture",
    }],
    page_universe: [{ rva: "0x1000", max_permissions: "R-X", region_kind: "text" }],
  };
  const manifestPath = path.join(artifactsDir, "bundle.json");
  writeFileSync(manifestPath, JSON.stringify(manifest));
  return { root, manifest: manifestPath, observations: path.join(root, "observations.jsonl") };
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("canonical Bun runner", () => {
  test("starts a fresh process and state directory for every seed", async () => {
    const fixture = makeBundle();
    const runs = await runSeedCommands({
      bundlePath: fixture.manifest,
      commands: [
        { seed_id: "seed-a", argv: ["ok", "{state_dir}", "{bundle_root}"] },
        { seed_id: "seed-b", argv: ["ok", "{state_dir}", "{bundle_root}"] },
      ],
      env: { ATFIELD_TEST_OBSERVATIONS: fixture.observations },
    });
    expect(runs.map((run) => run.completion)).toEqual(["complete", "complete"]);
    const observations = readFileSync(fixture.observations, "utf8")
      .trim()
      .split(String.fromCharCode(10))
      .map((line) => JSON.parse(line) as { pid: number; state_dir: string; state_arg: string; bundle_root: string; bundle_arg: string; cwd: string; bundle_link: boolean; home: string; data: string; cache: string; tmp: string; fresh: boolean });
    expect(observations).toHaveLength(2);
    expect(observations.every((row) => row.fresh)).toBe(true);
    expect(new Set(observations.map((row) => row.pid)).size).toBe(2);
    expect(new Set(observations.map((row) => row.state_dir)).size).toBe(2);
    expect(observations.every((row) => row.state_arg === row.state_dir)).toBe(true);
    expect(observations.every((row) => row.cwd === row.state_dir)).toBe(true);
    expect(observations.every((row) => row.bundle_arg === row.bundle_root)).toBe(true);
    expect(observations.every((row) => row.bundle_link)).toBe(true);
    expect(new Set(observations.map((row) => row.bundle_root)).size).toBe(2);
    for (const key of ["home", "data", "cache", "tmp"] as const) {
      expect(new Set(observations.map((row) => row[key])).size).toBe(2);
    }
  });

  test("appends runner end, and preserves malformed or collector-ended prefixes", async () => {
    const fixture = makeBundle();
    const runs = await runSeedCommands({
      bundlePath: fixture.manifest,
      artifactDir: path.join(fixture.root, "traces"),
      commands: [
        { seed_id: "bad-json", argv: ["bad-json"] },
        { seed_id: "collector-end", argv: ["collector-end"] },
        { seed_id: "bad-sequence", argv: ["bad-sequence"] },
        { seed_id: "valid", argv: ["ok"] },
      ],
    });
    expect(runs[0]!.completion).toBe("incomplete");
    expect(runs[0]!.artifactPaths?.partial).toBeDefined();
    expect(runs[1]!.completion).toBe("incomplete");
    expect(runs[1]!.incompleteReasons.some((reason) => reason.includes("run_end"))).toBe(true);
    expect(runs[1]!.artifactPaths?.partial).toBeDefined();
    expect(runs[2]!.completion).toBe("incomplete");
    expect(runs[2]!.incompleteReasons.some((reason) => reason.includes("call_seq"))).toBe(true);
    expect(runs[3]!.completion).toBe("complete");
    const validRecords = runs[3]!.traceText.trim().split("\n").map((line) => JSON.parse(line));
    expect(validRecords.map((record) => record.record_type)).toEqual(["run_start", "ecall", "run_end"]);
    expect(validRecords[2]!.record_count).toBe(1);
    expect(validRecords[2]!.instance_generation).toBe(1);
    expect(validRecords[2]!.process_return_code).toBe(0);
  });

  test("persists exact child stdout and stderr for incomplete runs", async () => {
    const fixture = makeBundle();
    const artifactDir = path.join(fixture.root, "child-output");
    const runs = await runSeedCommands({
      bundlePath: fixture.manifest,
      artifactDir,
      commands: [{ seed_id: "collector-error", argv: ["collector-error"] }],
    });
    expect(runs[0]!.completion).toBe("incomplete");
    expect(runs[0]!.artifactPaths?.stdout).toBeDefined();
    expect(runs[0]!.artifactPaths?.stderr).toBeDefined();
    expect(readFileSync(runs[0]!.artifactPaths!.stdout!, "utf8")).toBe("fixture child stdout\n");
    expect(readFileSync(runs[0]!.artifactPaths!.stderr!, "utf8")).toBe("ATFIELD_TRACE_ERROR: injected collector fault\n");
    const meta = JSON.parse(readFileSync(runs[0]!.artifactPaths!.meta!, "utf8"));
    expect(meta.stdout_path).toBe(runs[0]!.artifactPaths!.stdout);
    expect(meta.stderr_path).toBe(runs[0]!.artifactPaths!.stderr);
    expect(meta.stderr_bytes).toBe(new TextEncoder().encode("ATFIELD_TRACE_ERROR: injected collector fault\n").length);
  });
  test("marks AEX and timeout incomplete and terminates a hung host", async () => {
    const fixture = makeBundle();
    const aex = await runSeedCommands({
      bundlePath: fixture.manifest,
      commands: [{ seed_id: "aex", argv: ["aex"] }],
    });
    expect(aex[0]!.completion).toBe("incomplete");
    expect(aex[0]!.incompleteReasons.some((reason) => /AEX|measurement/i.test(reason))).toBe(true);

    const start = Date.now();
    const timeout = await runSeedCommands({
      bundlePath: fixture.manifest,
      commands: [{ seed_id: "hang", argv: ["hang"] }],
      timeoutMs: 40,
      killGraceMs: 50,
    });
    expect(timeout[0]!.timedOut).toBe(true);
    expect(timeout[0]!.completion).toBe("incomplete");
    expect(timeout[0]!.incompleteReasons.some((reason) => reason.includes("timed out"))).toBe(true);
    const timeoutEnd = JSON.parse(timeout[0]!.traceText.trim().split("\n").at(-1)!);
    expect(timeoutEnd.record_type).toBe("run_end");
    expect(timeoutEnd.completion).toBe("incomplete");
    expect(timeoutEnd.timeout).toBe(true);
    expect(Date.now() - start).toBeLessThan(3000);

    const pipeStart = Date.now();
    const inheritedPipe = await runSeedCommands({
      bundlePath: fixture.manifest,
      commands: [{ seed_id: "orphan-pipe", argv: ["orphan-pipe"] }],
      timeoutMs: 2000,
      killGraceMs: 50,
    });
    expect(inheritedPipe[0]!.timedOut).toBe(true);
    expect(inheritedPipe[0]!.completion).toBe("incomplete");
    expect(inheritedPipe[0]!.incompleteReasons.some((reason) => reason.includes("pipes"))).toBe(true);
    const pipeEnd = JSON.parse(inheritedPipe[0]!.traceText.trim().split("\n").at(-1)!);
    expect(pipeEnd.record_type).toBe("run_end");
    expect(pipeEnd.completion).toBe("incomplete");
    expect(pipeEnd.timeout).toBe(true);
    expect(Date.now() - pipeStart).toBeLessThan(3000);
  });

  test("marks the collector trace-error prefix incomplete", async () => {
    const fixture = makeBundle();
    const runs = await runSeedCommands({
      bundlePath: fixture.manifest,
      commands: [{ seed_id: "collector-error", argv: ["collector-error"] }],
    });
    expect(runs[0]!.completion).toBe("incomplete");
    expect(runs[0]!.incompleteReasons).toContain("collector reported ATFIELD_TRACE_ERROR");
  });

  test("loads the collector once in the detached host process", async () => {
    const compiler = Bun.which("cc");
    const node = Bun.which("node");
    if (!compiler || !node) return;
    const fixture = makeBundle();
    const collectorSource = path.join(fixture.root, "collector.c");
    const collectorPath = path.join(fixture.root, "collector.so");
    const constructorCount = path.join(fixture.root, "collector-count.txt");
    writeFileSync(collectorSource, `#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void count_load(void) {
  const char *path = getenv("ATFIELD_TEST_COLLECTOR_COUNT_FILE");
  if (!path) return;
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd >= 0) { (void)write(fd, "loaded\\n", 7); close(fd); }
}
`);
    const compile = Bun.spawnSync([compiler, "-shared", "-fPIC", "-o", collectorPath, collectorSource], {
      stdout: "pipe",
      stderr: "pipe",
    });
    if (compile.exitCode !== 0) throw new Error(new TextDecoder().decode(compile.stderr));
    const runs = await runSeedCommands({
      bundlePath: fixture.manifest,
      collectorPath,
      commands: [{ seed_id: "collector-once", argv: ["ok"] }],
      env: { ATFIELD_TEST_COLLECTOR_COUNT_FILE: constructorCount },
    });
    expect(runs[0]!.completion).toBe("complete");
    const count = readFileSync(constructorCount, "utf8").trim().split("\n");
    expect(count).toEqual(["loaded"]);
  });

  test("rejects a bundle whose host artifact digest no longer matches", async () => {
    const fixture = makeBundle();
    const hostPath = path.join(path.dirname(fixture.manifest), "fake-host.cjs");
    writeFileSync(hostPath, "changed after bundle creation");
    await expect(runSeedCommands({
      bundlePath: fixture.manifest,
      commands: [{ seed_id: "seed", argv: [] }],
    })).rejects.toThrow("artifact digest mismatch for host");
  });

  test("explicitly configures 4-gate C-flush in acquisition mode and C-preserve-TLB in verify-pretouch mode while stripping external ATFIELD env leaks", async () => {
    const fixture = makeBundle();
    process.env.ATFIELD_EXTERNAL_LEAK = "should-not-leak";
    process.env.ATFIELD_USE_4GATE = "0";
    process.env.ATFIELD_IPI_MASK = "0";
    try {
      const acqRuns = await runSeedCommands({
        bundlePath: fixture.manifest,
        mode: "profile",
        gateMode: "c-flush",
        commands: [{ seed_id: "acq", argv: ["ok", "{state_dir}", "{bundle_root}"] }],
        env: { ATFIELD_TEST_OBSERVATIONS: fixture.observations },
      });
      expect(acqRuns[0]!.completion).toBe("complete");
      expect(acqRuns[0]!.mode).toBe("profile");
      expect(acqRuns[0]!.gateMode).toBe("c-flush");

      const verRuns = await runSeedCommands({
        bundlePath: fixture.manifest,
        mode: "verify-pretouch",
        gateMode: "c-preserve-tlb",
        commands: [{ seed_id: "ver", argv: ["ok", "{state_dir}", "{bundle_root}"] }],
        env: { ATFIELD_TEST_OBSERVATIONS: fixture.observations },
      });
      expect(verRuns[0]!.completion).toBe("complete");
      expect(verRuns[0]!.mode).toBe("verify-pretouch");
      expect(verRuns[0]!.gateMode).toBe("c-preserve-tlb");

      const obs = readFileSync(fixture.observations, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(obs[0]).toMatchObject({
        use_4gate: "1",
        ipi_mask: "7",
        gate_mode: "c-flush",
        mode: "profile",
        leaked_custom_atfield: null,
      });
      expect(obs[1]).toMatchObject({
        use_4gate: "1",
        ipi_mask: "3",
        gate_mode: "c-preserve-tlb",
        mode: "verify-pretouch",
        leaked_custom_atfield: null,
      });

      await expect(runSeedCommands({
        bundlePath: fixture.manifest,
        mode: "profile",
        gateMode: "c-preserve-tlb",
        commands: [{ seed_id: "bad-combo", argv: ["ok"] }],
      })).rejects.toThrow(/gateMode c-preserve-tlb requires mode verify-pretouch/);
    } finally {
      delete process.env.ATFIELD_EXTERNAL_LEAK;
      delete process.env.ATFIELD_USE_4GATE;
      delete process.env.ATFIELD_IPI_MASK;
    }
  });

  test("validates and records run-level CPU selection and rejects offline, disallowed, or conflicting CPUs with actionable errors", async () => {
    const autoCfg = resolveRunnerCpuConfig({
      cpuTopology: {
        online: "0-47",
        isolated: "46-47",
        processInitialAffinity: "0-45",
        effectiveCpuset: "0-47",
      },
    });
    expect(autoCfg).toEqual({
      enclCpu: 46,
      watchCpu: 1,
      enclCpuSource: "auto-isolated",
      watchCpuSource: "auto-housekeeping",
      enclCpuIsolated: true,
      onlineCpus: "0-47",
      isolatedCpus: "46-47",
      processInitialAffinityCpus: "0-45",
      effectiveCpusetCpus: "0-47",
      allowedCpus: "0-47",
    });

    expect(() => resolveRunnerCpuConfig({
      enclCpu: 48,
      watchCpu: 1,
      cpuTopology: { online: "0-47", isolated: "46-47", allowed: "0-47" },
    })).toThrow(/configured enclave CPU 48 is not online/);

    expect(() => resolveRunnerCpuConfig({
      enclCpu: 46,
      watchCpu: 1,
      cpuTopology: { online: "0-47", isolated: "46-47", allowed: "0-3" },
    })).toThrow(/configured enclave CPU 46 is outside allowed CPU affinity/);

    expect(() => resolveRunnerCpuConfig({
      enclCpu: 1,
      watchCpu: 1,
      cpuTopology: { online: "0-47", isolated: "46-47", allowed: "0-47" },
    })).toThrow(/enclave CPU \(1\) and watcher CPU \(1\) must not conflict/);

    expect(() => resolveRunnerCpuConfig({
      cpuTopology: { online: "0", isolated: "", allowed: "0" },
    })).toThrow(/at least 2 distinct online allowed CPUs are required/);

    const fixture = makeBundle();
    const artifactDir = path.join(fixture.root, "cpu-artifacts");
    const runs = await runSeedCommands({
      bundlePath: fixture.manifest,
      enclCpu: 46,
      watchCpu: 1,
      cpuTopology: { online: "0-47", isolated: "46-47", allowed: "0-47" },
      artifactDir,
      commands: [{ seed_id: "cpu-explicit", argv: ["ok", "{state_dir}", "{bundle_root}"] }],
      env: { ATFIELD_TEST_OBSERVATIONS: fixture.observations },
    });
    expect(runs[0]!.completion).toBe("complete");
    expect(runs[0]!.cpuConfig.enclCpu).toBe(46);
    expect(runs[0]!.cpuConfig.watchCpu).toBe(1);
    expect(runs[0]!.cpuConfig.enclCpuSource).toBe("explicit");
    expect(runs[0]!.cpuConfig.watchCpuSource).toBe("explicit");
    const meta = JSON.parse(readFileSync(runs[0]!.artifactPaths!.meta!, "utf8"));
    expect(meta.cpu_config).toEqual({
      encl_cpu: 46,
      watch_cpu: 1,
      encl_cpu_source: "explicit",
      watch_cpu_source: "explicit",
      encl_cpu_isolated: true,
      online_cpus: "0-47",
      isolated_cpus: "46-47",
      process_initial_affinity_cpus: "0-45",
      effective_cpuset_cpus: "0-47",
      allowed_cpus: "0-47",
      final_affinity_verified: true,
    });
  });
});
