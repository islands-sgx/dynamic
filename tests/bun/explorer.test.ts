import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalJson } from "../../lib/bundle/profile-bundle.ts";
import {
  encodeMutationSpec,
  parseCallCapture,
  type ScalarMutationRule,
} from "../../lib/explorer/contract.ts";
import { exploreSeeds } from "../../lib/explorer/explorer.ts";
import { readFinalizableCorpus } from "../../lib/explorer/corpus.ts";
import { parseArgs } from "../../cli/explore.ts";

const temporaryRoots: string[] = [];
const digest = (value: string): string => createHash("sha256").update(value).digest("hex");

function makeFakeHostSource(): string {
  const nodePath = Bun.which("node");
  if (!nodePath) throw new Error("node is required for the subprocess fixture");
  const lines = [
    "#!" + nodePath,
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const env = process.env;",
    "const stateDir = env.ATFIELD_STATE_DIR;",
    "const marker = path.join(stateDir, 'already-used');",
    "const fresh = !fs.existsSync(marker);",
    "fs.writeFileSync(marker, 'used');",
    "const mutationPath = env.ATFIELD_MUTATION_SPEC_PATH;",
    "let mutation = null;",
    "let inputBits = '0x00000005';",
    "if (mutationPath) {",
    "  const bytes = fs.readFileSync(mutationPath);",
    "  if (bytes.length !== 144 || bytes.readUInt32LE(16) !== 1 || bytes.readUInt32LE(88) !== 56 || bytes.readUInt16LE(108) !== 1 || bytes.toString('ascii', 0, 6) !== 'ATFMUT') process.exit(21);",
    "  const ordinal = bytes.readUInt32LE(96);",
    "  const selectorSeq = Number(bytes.readBigUInt64LE(100));",
    "  const paramIndex = bytes.readUInt32LE(120);",
    "  const widthBytes = bytes[125];",
    "  const signedness = bytes[124] === 0 ? 'unsigned' : 'signed';",
    "  const expectedBits = '0x' + bytes.readBigUInt64LE(128).toString(16).padStart(widthBytes * 2, '0');",
    "  inputBits = '0x' + bytes.readBigUInt64LE(136).toString(16).padStart(widthBytes * 2, '0');",
    "  if (ordinal !== 0 || selectorSeq !== 0 || paramIndex !== 0 || expectedBits !== '0x00000005') process.exit(22);",
    "  mutation = {",
    "    param_index: paramIndex, width_bytes: widthBytes, signedness,",
    "    expected_bits: expectedBits, observed_bits: expectedBits, replacement_bits: inputBits,",
    "    applied: true, reason: 'applied',",
    "  };",
    "}",
    "const seen = {",
    "  pid: process.pid, stateDir, cwd: process.cwd(), home: env.HOME,",
    "  state: env.XDG_STATE_HOME, data: env.XDG_DATA_HOME, cache: env.XDG_CACHE_HOME, tmp: env.TMPDIR, fresh,",
    "  mutationPath: mutationPath || null, inputBits, use4Gate: env.ATFIELD_USE_4GATE, ipiMask: env.ATFIELD_IPI_MASK, gateMode: env.ATFIELD_GATE_MODE, mode: env.ATFIELD_MODE,",
    "};",
    "if (env.TEST_OBSERVATIONS) fs.appendFileSync(env.TEST_OBSERVATIONS, JSON.stringify(seen) + '\\n');",
    "const numeric = Number(BigInt(inputBits));",
    "const selectedPage = mutation && numeric === 7 ? '0x2000' : '0x1000';",
    "const phase = (rva) => ({ page_size: 4096, complete: true, page_effects: [{ rva, a: true, d: false }] });",
    "const traceStart = {",
    "  schema: 'atfield-canonical-trace-v1', record_type: 'run_start',",
    "  run_id: env.ATFIELD_RUN_ID, layout_epoch: env.ATFIELD_LAYOUT_EPOCH,",
    "  instance_generation: null, sample: env.ATFIELD_SAMPLE, mode: env.ATFIELD_MODE,",
    "  start_time: new Date().toISOString(), selected_enclave_sha256: env.ATFIELD_ENCLAVE_SHA256,",
    "  bundle_manifest_sha256: env.ATFIELD_BUNDLE_MANIFEST_SHA256,",
    "};",
    "const traceEcall = {",
    "  schema: traceStart.schema, record_type: 'ecall', run_id: traceStart.run_id,",
    "  layout_epoch: traceStart.layout_epoch, bundle_manifest_sha256: traceStart.bundle_manifest_sha256,",
    "  instance_generation: 1, call_seq: 0, selector_ordinal: 0, selector_seq: 0,",
    "  tag: 'synthetic', elapsed_ns: 1, sgx_status: 0, abi_return_type: 'void',",
    "  abi_return_value: 0, out_status_i32: 0, measurement_valid: true,",
    "  measurement_invalid_reasons: [], aex: { count: mutation && inputBits === '0x00000006' ? 1 : 0 },",
    "  fields: (!mutation && process.argv.includes('--early-return')) ? [] : [{ field_id: 'field-1', phases: {",
    "    S0_BRIDGE: phase('0x1000'), S1_ENTER: phase('0x1000'),",
    "    S2_PRETOUCH: phase('0x1000'), S3_BODY: phase(selectedPage),",
    "  } }],",
    "};",
    "fs.writeFileSync(env.ATFIELD_TRACE_PATH, [traceStart, traceEcall].map(JSON.stringify).join('\\n') + '\\n');",
    "const captureStart = {",
    "  type: 'capture_start', schema: 'atfield-call-capture-v1', run_id: env.ATFIELD_RUN_ID,",
    "  bundle_manifest_sha256: env.ATFIELD_BUNDLE_MANIFEST_SHA256,",
    "  marshal_layout_sha256: env.ATFIELD_MARSHAL_LAYOUT_SHA256,",
    "  marshal_spec_sha256: env.ATFIELD_MARSHAL_SPEC_SHA256 || \"33\".repeat(32),",
    "};",
    "const captureEcall = {",
    "  type: 'ecall', generation: 1, call_seq: 0, selector_ordinal: 0, selector_seq: 0,",
    "  transport_status: 0, scalar_inputs: [{ param_index: 0, width_bytes: 4, signedness: 'signed', bits: inputBits }],",
    "  retval: { width_bytes: 4, signedness: 'signed', bits: '0x00000000' },",
    "  scalar_outputs: [], mutation,",
    "};",
    "fs.writeFileSync(env.ATFIELD_CALL_CAPTURE_PATH, [captureStart, captureEcall].map(JSON.stringify).join('\\n') + '\\n');",
    "if (mutation && inputBits === '0x00000006') {",
    "  const aexTrace = JSON.parse(fs.readFileSync(env.ATFIELD_TRACE_PATH, 'utf8').split('\\n')[1]);",
    "  aexTrace.aex.count = 1;",
    "  fs.writeFileSync(env.ATFIELD_TRACE_PATH, [traceStart, aexTrace].map(JSON.stringify).join('\\n') + '\\n');",
    "}",
  ];
  return lines.join("\n") + "\n";
}

function makeBundle(opts: { recordEcall?: boolean } = {}): { root: string; manifestPath: string; hostPath: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), "dynamic-explorer-test-"));
  temporaryRoots.push(root);
  const artifactsDir = path.join(root, "bundle");
  mkdirSync(artifactsDir, { recursive: true });
  const hostPath = path.join(artifactsDir, "host-fixture.cjs");
  const hostSource = makeFakeHostSource();
  writeFileSync(hostPath, hostSource, { mode: 0o700 });
  chmodSync(hostPath, 0o700);

  const fields = [{ id: "field-1", name: "synthetic field" }];
  const abi = {
    schema: "atfield-edl-abi-v1",
    tool: { name: "sgx_edger8r", version: "fixture" },
    input: {},
    types: [],
    ecalls: [{
      ordinal: 0,
      name: "fixture_call",
      visibility: "public",
      switchless: false,
      return_type: { kind: "builtin", name: "void" },
      parameters: [{
        name: "value",
        type: { kind: "builtin", name: "int", signedness: "signed" },
        parameter_form: "value",
        pointer_depth: 0,
        array_dimensions: [],
        direction: "value",
        attributes: null,
      }],
    }],
    ocalls: [],
  };
  if (opts.recordEcall) {
    abi.ecalls.push({
      ordinal: 1,
      name: "record_call",
      visibility: "public",
      switchless: false,
      return_type: { kind: "builtin", name: "void" },
      parameters: [
        {
          name: "data",
          type: { kind: "pointer", to: { kind: "named", name: "Rec" } },
          parameter_form: "pointer",
          pointer_depth: 1,
          array_dimensions: [],
          direction: "in",
          attributes: {
            size: { kind: "identifier", name: "data_len" },
            count: null, string: false, wstring: false,
            user_check: false, isptr: false, isary: false, readonly: false,
          },
        },
        {
          name: "data_len",
          type: { kind: "builtin", name: "size_t" },
          parameter_form: "value",
          pointer_depth: 0,
          array_dimensions: [],
          direction: "value",
          attributes: null,
        },
      ],
    });
  }
  const abiBytes = JSON.stringify(abi);
  const fieldsArtifact = { schema: "atfield-fields-v1", fields };
  const marshalLayout = {
    schema: "atfield-marshal-layout-v1",
    input: { edl_abi_sha256: digest(abiBytes) },
    tool: {},
    ecalls: [{
      ordinal: 0,
      name: "fixture_call",
      visibility: "public",
      switchless: false,
      ms_size: 16,
      replay_supported: true,
      params: [{
        name: "value",
        abi_type: { kind: "builtin", name: "int" },
        form: "value",
        pointer_depth: 0,
        array_dimensions: [],
        array_decay: false,
        abi_array_parameter_decays_to_pointer: null,
        marshaled_form: "value",
        is_pointer: false,
        direction: "value",
        string: false,
        wstring: false,
        user_check: false,
        ms_offset: 12,
        ms_size: 4,
        ms_type_category: "integer",
        ms_signed: true,
        element_size: null,
        element_type_category: null,
        element_signed: null,
        bound: null,
        replay_supported: true,
        reasons: [],
      }],
    }],
  };
  const irFacts = {
    schema: "atfield-ir-facts-aggregate-v1",
    facts: [{
      schema: "atfield-ir-facts-v1",
      translation_unit: "fixture.o",
      module_id: "irtu_00000000000000000000000000000001",
      backend_ir_sha256: "11".repeat(32),
      object_sha256: "22".repeat(32),
      compile_variant: { compiler: "fixture", flags: [] },
      source: { input_file: "fixture.c", ir_filename: "fixture.ll" },
      callgraph_complete: true,
      guidance_complete: true,
      diagnostics: [],
      definitions: [{ symbol: "fixture_function", linkage: "external", source_file: "fixture.c", line: 1 }],
      direct_calls: [],
      unknown_indirect: [],
      guidance_sites: [{
        site_id: "irsite_00000000000000000000000000000001",
        function: "fixture_function",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 0,
        source: { file: "fixture.c", line: 1 },
        kind: "icmp",
        predicate: "eq",
        width_bits: 32,
        signedness: "signless",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%value" },
          { operand: 1, status: "constant", value: "7" },
        ],
      }],
    }],
  };
  const irFact = irFacts.facts[0]!
  const reachability = {
    schema: "atfield-reachability-v1",
    input: {
      edl_abi_sha256: digest(abiBytes),
      live_fields_sha256: digest(JSON.stringify(fieldsArtifact)),
      ir_facts_tus: [{
        translation_unit: irFact.translation_unit,
        module_id: irFact.module_id,
        backend_ir_sha256: irFact.backend_ir_sha256,
        object_sha256: irFact.object_sha256,
        variant_sha256: digest(canonicalJson(irFact.compile_variant)),
        facts_sha256: digest(canonicalJson(irFact)),
      }],
    },
    live_field_ids: ["field-1"],
    ecalls: [{
      ordinal: 0,
      name: "fixture_call",
      visibility: "public",
      switchless: false,
      status: "verified",
      reachable_functions: ["fixture_function"],
      reachable_fields: ["field-1"],
      unknown_indirect: false,
      unknown_external: false,
      function_closure_complete: true,
    }],
  };  if (opts.recordEcall) {
    marshalLayout.ecalls.push({
      ordinal: 1,
      name: "record_call",
      visibility: "public",
      switchless: false,
      ms_size: 24,
      replay_supported: true,
      params: [
        {
          name: "data",
          abi_type: { kind: "pointer", to: { kind: "named", name: "Rec" } },
          form: "pointer",
          pointer_depth: 1,
          array_dimensions: [],
          array_decay: false,
          abi_array_parameter_decays_to_pointer: null,
          marshaled_form: "pointer",
          is_pointer: true,
          direction: "in",
          string: false,
          wstring: false,
          user_check: false,
          ms_offset: 0,
          ms_size: 8,
          ms_type_category: "pointer",
          ms_signed: null,
          element_size: 44,
          element_type_category: "record",
          element_signed: null,
          bound: { kind: "size_bytes", source: { kind: "parameter", name: "data_len" } },
          replay_supported: true,
          reasons: [],
        },
        {
          name: "data_len",
          abi_type: { kind: "builtin", name: "size_t" },
          form: "value",
          pointer_depth: 0,
          array_dimensions: [],
          array_decay: false,
          abi_array_parameter_decays_to_pointer: null,
          marshaled_form: "value",
          is_pointer: false,
          direction: "value",
          string: false,
          wstring: false,
          user_check: false,
          ms_offset: 8,
          ms_size: 8,
          ms_type_category: "integer",
          ms_signed: false,
          element_size: null,
          element_type_category: null,
          element_signed: null,
          bound: null,
          replay_supported: true,
          reasons: [],
        },
      ],
    });
    irFact.definitions.push({
      symbol: "record_function", linkage: "external", source_file: "fixture.c", line: 2,
    });
    irFact.guidance_sites.push({
      site_id: "irsite_00000000000000000000000000000002",
      function: "record_function",
      function_linkage: "external",
      block_ordinal: 0,
      instruction_ordinal: 1,
      source: { file: "fixture.c", line: 2 },
      kind: "switch",
      width_bits: 32,
      selector: { operand: 0, status: "dynamic", value_ref: "%keyspec" },
      default_target: "default",
      cases: [
        { value: "1", status: "constant", target: "case1" },
        { value: "30", status: "constant", target: "case30" },
        { value: "31", status: "constant", target: "case31" },
        { value: "32", status: "constant", target: "case32" },
      ],
    });
    reachability.ecalls.push({
      ordinal: 1,
      name: "record_call",
      visibility: "public",
      switchless: false,
      status: "verified",
      reachable_functions: ["record_function"],
      reachable_fields: ["field-1"],
      unknown_indirect: false,
      unknown_external: false,
      function_closure_complete: true,
    });
    reachability.input.ir_facts_tus[0]!.facts_sha256 = digest(canonicalJson(irFact));
  }
  const artifactBytes: Record<string, string> = {
    profile_elf: "synthetic profile ELF",
    signed_profile_elf: "synthetic signed profile ELF",
    edl_abi: abiBytes,
    fields: JSON.stringify(fieldsArtifact),
    host: hostSource,
    marshal_layout: JSON.stringify(marshalLayout),
    ir_facts: JSON.stringify(irFacts),
    reachability: JSON.stringify(reachability),
  };
  for (const [name, content] of Object.entries(artifactBytes)) {
    if (name !== "host") writeFileSync(path.join(artifactsDir, name), content);
  }
  const artifactRecords: Record<string, { path: string; sha256: string }> = {};
  for (const [name, content] of Object.entries(artifactBytes)) {
    artifactRecords[name] = { path: name === "host" ? path.basename(hostPath) : name, sha256: digest(content) };
  }
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
  layout.epoch = digest(canonicalJson({
    profile_elf_sha256: artifactRecords.profile_elf.sha256,
    signed_profile_elf_sha256: artifactRecords.signed_profile_elf.sha256,
    page_size: layout.page_size,
    capacity_q: layout.capacity_q,
    ordinary_load_end: layout.ordinary_load_end,
    pretouch_start: layout.pretouch_start,
    enclave_size: layout.enclave_size,
    ssa_frame_pages: layout.ssa_frame_pages,
    regions: layout.regions,
    excluded_regions: layout.excluded_regions,
  }));
  const measurementManifest = {
    schema: "atfield-measurement-profile-v1",
    identity: {
      profile_elf_sha256: artifactRecords.profile_elf.sha256,
      signed_profile_elf_sha256: artifactRecords.signed_profile_elf.sha256,
      fields_sha256: artifactRecords.fields.sha256,
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
      profile_elf: { path: artifactRecords.profile_elf.path, sha256: artifactRecords.profile_elf.sha256 },
      signed_profile_elf: { path: artifactRecords.signed_profile_elf.path, sha256: artifactRecords.signed_profile_elf.sha256 },
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
  artifactBytes.measurement_manifest = JSON.stringify(measurementManifest);
  writeFileSync(path.join(artifactsDir, "measurement_manifest"), artifactBytes.measurement_manifest);
  artifactRecords.measurement_manifest = { path: "measurement_manifest", sha256: digest(artifactBytes.measurement_manifest) };

  const manifest = {
    schema: "atfield-profile-bundle-v1",
    identity: {
      profile_elf_sha256: artifactRecords.profile_elf.sha256,
      signed_profile_elf_sha256: artifactRecords.signed_profile_elf.sha256,
      edl_abi_sha256: artifactRecords.edl_abi.sha256,
      fields_sha256: artifactRecords.fields.sha256,
    },
    layout,
    artifacts: artifactRecords,
    fields,
    selectors: [{
      ordinal: 0,
      name: "fixture_call",
      visibility: "public",
      switchless: false,
      entry_rva: "0x1000",
      reachable_fields: ["field-1"],
      reachability: "fixture",
    }].concat(opts.recordEcall ? [{
      ordinal: 1,
      name: "record_call",
      visibility: "public",
      switchless: false,
      entry_rva: "0x2000",
      reachable_fields: ["field-1"],
      reachability: "fixture",
    }] : []),
    page_universe: [
      { rva: "0x1000", max_permissions: "R-X", region_kind: "text" },
      { rva: "0x2000", max_permissions: "R-X", region_kind: "text" },
    ],
  };
  const manifestPath = path.join(artifactsDir, "bundle.json");
  writeFileSync(manifestPath, JSON.stringify(manifest));
  return { root, manifestPath, hostPath };
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("Bun dynamic explorer", () => {
  test("encodes one versioned little-endian scalar mutation rule", () => {
    const rule: ScalarMutationRule = {
      selectorOrdinal: 3,
      selectorSeq: 2,
      paramIndex: 1,
      widthBytes: 4,
      signedness: "signed",
      expectedBits: "0x00000005",
      replacementBits: "0x00000007",
    };
    const bytes = encodeMutationSpec({
      bundleManifestSha256: "11".repeat(32),
      marshalLayoutSha256: "22".repeat(32),
    }, rule);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    expect(bytes.length).toBe(144);
    expect(new TextDecoder().decode(bytes.subarray(0, 6))).toBe("ATFMUT");
    expect(view.getUint16(8, true)).toBe(1);
    expect(view.getUint16(10, true)).toBe(88);
    expect(view.getUint32(12, true)).toBe(144);
    expect(view.getUint32(16, true)).toBe(1);
    expect(view.getUint32(88, true)).toBe(56);
    expect(view.getUint16(92, true)).toBe(1);
    expect(view.getUint32(96, true)).toBe(3);
    expect(view.getBigUint64(100, true)).toBe(2n);
    expect(view.getUint32(120, true)).toBe(1);
    expect(bytes[124]).toBe(1);
    expect(bytes[125]).toBe(4);
    expect(view.getBigUint64(128, true)).toBe(5n);
    expect(view.getBigUint64(136, true)).toBe(7n);
    expect(() => encodeMutationSpec({
      bundleManifestSha256: "11".repeat(32),
      marshalLayoutSha256: "22".repeat(32),
    }, { ...rule, replacementBits: "0x7" })).toThrow();
  });

  test("splits explorer options from direct host arguments", () => {
    const options = parseArgs(["--bundle", "/tmp/profile/bundle.json", "--corpus", "/tmp/profile/corpus", "--role", "main", "--budget", "4", "--timeout-ms", "1234", "--encl-cpu", "46", "--watch-cpu", "1", "--", "--self-test", "fixture.data"]);
    expect(options.bundlePath).toBe(path.resolve("/tmp/profile/bundle.json"));
    expect(options.corpusPath).toBe(path.resolve("/tmp/profile/corpus"));
    expect(options.role).toBe("main");
    expect(options.hostArgs).toEqual(["--self-test", "fixture.data"]);
    expect(options.candidateBudget).toBe(4);
    expect(options.timeoutMs).toBe(1234);
    expect(options.enclCpu).toBe(46);
    expect(options.watchCpu).toBe(1);
    expect(() => parseArgs(["--bundle", "/tmp/profile/bundle.json", "--self-test"])).toThrow(/must follow --/);
  });

  test("replays fresh subprocesses, applies one replacement, and excludes an AEX trace", async () => {
    const fixture = makeBundle();
    const observationsPath = path.join(fixture.root, "observations.jsonl");
    const seeds = [{
      id: "synthetic-direct-host-case",
      args: ["--business-flow"],
      env: { TEST_OBSERVATIONS: observationsPath },
    }];
    const result = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath: path.join(fixture.root, "corpus"),
      role: "main",
      seeds,
      candidateBudget: 3,
      timeoutMs: 2000,
      killGraceMs: 100,
    });

    expect(result.baselineRuns).toBe(1);
    expect(result.candidateRuns).toBe(3);
    expect(result.acceptedCandidates).toBe(2);
    expect(result.seedResults[0]!.baselineAccepted).toBe(true);
    expect(result.seedResults[0]!.candidates.map((candidate) => candidate.value)).toEqual(["7", "6", "8"]);
    expect(result.seedResults[0]!.candidates.map((candidate) => candidate.accepted)).toEqual([true, false, true]);
    expect(result.seedResults[0]!.feedback).toHaveLength(1);
    expect(result.seedResults[0]!.feedback[0]!.value).toBe("7");
    expect(readFinalizableCorpus(path.join(fixture.root, "corpus"), fixture.manifestPath)).toHaveLength(2);
    expect(result.seedResults[0]!.feedback[0]!.pageDelta).toEqual([{
      fieldId: "field-1",
      pageRva: "0x2000",
      effects: ["R", "X"],
    }]);
    expect(result.seedResults[0]!.candidates[1]!.reason).toMatch(/AEX|measurement|incomplete/i);

    const runs = readFileSync(observationsPath, "utf8").trim().split("\n")
      .map((line) => JSON.parse(line) as {
        pid: number; stateDir: string; cwd: string; home: string; state: string;
        data: string; cache: string; tmp: string; fresh: boolean; mutationPath: string | null;
      });
    expect(runs).toHaveLength(4);
    expect(runs.every((run) => run.fresh)).toBe(true);
    expect(new Set(runs.map((run) => run.pid)).size).toBe(4);
    for (const key of ["stateDir", "cwd", "home", "state", "data", "cache", "tmp"] as const) {
      expect(new Set(runs.map((run) => run[key])).size).toBe(4);
    }
    expect(runs[0]!.cwd).toBe(runs[0]!.stateDir);
    expect(runs[0]!.mutationPath).toBeNull();
    expect(runs.every((run: any) => run.use4Gate === "1" && run.ipiMask === "7" && run.gateMode === "c-flush" && run.mode === "explore")).toBe(true);
    expect(runs.slice(1).every((run) => run.mutationPath !== null)).toBe(true);
  });

  test("supplemental self-test traces cannot finalize without a main business-flow trace", async () => {
    const fixture = makeBundle();
    const corpusPath = path.join(fixture.root, "corpus");
    const seed = (id: string, arg: string) => [{ id, args: [arg], env: {} }];
    await exploreSeeds({
      bundlePath: fixture.manifestPath, corpusPath, role: "supplemental",
      seeds: seed("self-test", "--self-test"), candidateBudget: 0, timeoutMs: 2000,
    });
    expect(() => readFinalizableCorpus(corpusPath, fixture.manifestPath)).toThrow(/complete main/);
    await exploreSeeds({
      bundlePath: fixture.manifestPath, corpusPath, role: "main",
      seeds: seed("main-flow", "--business-flow"), candidateBudget: 0, timeoutMs: 2000,
    });
    expect(readFinalizableCorpus(corpusPath, fixture.manifestPath).map((entry) => entry.role).sort())
      .toEqual(["main", "supplemental"]);
  });
  test("rejects a capture whose bundle binding differs", () => {
    const text = [
      JSON.stringify({
        type: "capture_start",
        schema: "atfield-call-capture-v1",
        run_id: "run-1",
        bundle_manifest_sha256: "00".repeat(32),
        marshal_layout_sha256: "22".repeat(32),
        marshal_spec_sha256: "33".repeat(32),
      }),
      JSON.stringify({
        type: "capture_end",
        schema: "atfield-call-capture-v1",
        process_return_code: 0,
        timed_out: false,
        complete: false,
        ecall_count: 0,
        target_match_count: 0,
        mutation_applied_count: 0,
        incomplete_reasons: ["fixture"],
      }),
      "",
    ].join("\n");
    expect(() => parseCallCapture(text, {
      runId: "run-1",
      bundleManifestSha256: "11".repeat(32),
      marshalLayoutSha256: "22".repeat(32),
    })).toThrow(/bound to different/);
  });

  test("accepts a legal early-return seed trace without Field entry, mutates from it, and refuses corpus finalization when target Fields remain uncovered across the round", async () => {
    const fixture = makeBundle();
    const uncoveredCorpus = path.join(fixture.root, "corpus-uncovered");
    const earlyRes = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath: uncoveredCorpus,
      role: "main",
      seeds: [{ id: "early-return-only", args: ["--early-return"], env: {} }],
      candidateBudget: 0,
      timeoutMs: 2000,
    });
    expect(earlyRes.seedResults[0]?.baselineAccepted).toBe(true);
    expect(earlyRes.seedResults[0]?.baselinePageEffects).toBe(0);
    expect(() => readFinalizableCorpus(uncoveredCorpus, fixture.manifestPath))
      .toThrow(/finalizing the trace corpus requires complete valid S3 observations for live Field field-1/);

    const coveredCorpus = path.join(fixture.root, "corpus-covered");
    const mutatedRes = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath: coveredCorpus,
      role: "main",
      seeds: [{ id: "early-return-then-mutate", args: ["--early-return"], env: {} }],
      candidateBudget: 4,
      timeoutMs: 2000,
    });
    expect(mutatedRes.seedResults[0]?.baselineAccepted).toBe(true);
    expect(mutatedRes.acceptedCandidates).toBeGreaterThan(0);
    const finalized = readFinalizableCorpus(coveredCorpus, fixture.manifestPath);
    expect(finalized.length).toBeGreaterThanOrEqual(2);
  });

  test("atfield-workset CLI consumes --corpus with main and supplemental traces", async () => {
    const fixture = makeBundle();
    const corpusPath = path.join(fixture.root, "corpus-workset-cli");
    await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath,
      role: "main",
      seeds: [{ id: "main-flow", args: ["--business-flow"], env: {} }],
      candidateBudget: 0,
      timeoutMs: 2000,
    });
    await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath,
      role: "supplemental",
      seeds: [{ id: "self-test", args: ["--self-test"], env: {} }],
      candidateBudget: 0,
      timeoutMs: 2000,
    });
    const { main: worksetCliMain } = await import("../../cli/atfield-workset.ts");
    const outWorkset = path.join(fixture.root, "from-corpus.workset.v2.json");
    const rc = worksetCliMain(["--bundle", fixture.manifestPath, "--corpus", corpusPath, "--out", outWorkset]);
    expect(rc).toBe(0);
    const doc = JSON.parse(readFileSync(outWorkset, "utf8"));
    expect(doc.schema).toBe("atfield-workset-v2");
    expect(doc.source_traces).toHaveLength(2);
  });

  test("derives child scalar, buffer, and call-history candidates from discovered cases and preserves distinct histories with same page set", async () => {
    const fixture = makeBundle();
    const { loadExplorerProfile } = await import("../../lib/explorer/profile.ts");
    const { deriveCandidatesFromCase, deriveChildCandidatesFromFeedback } = await import("../../lib/explorer/planner.ts");
    const profile = loadExplorerProfile(fixture.manifestPath);

    const baseCapture = {
      bundleManifestSha256: profile.binding.bundleManifestSha256,
      marshalLayoutSha256: profile.binding.marshalLayoutSha256,
      runId: "11111111-1111-4111-8111-111111111111",
      events: [{
        generation: 1,
        callSeq: 0,
        selectorOrdinal: 0,
        selectorSeq: 0,
        transportStatus: 0,
        scalarInputs: [{ paramIndex: 0, widthBytes: 4 as const, signedness: "signed" as const, bits: "0x00000005" }],
        bufferInputs: [{
          paramIndex: 0,
          direction: "in" as const,
          isString: false,
          elementSize: 1,
          byteLength: 8,
          fnv1a64: "0x0102030405060708",
          prefixHex: "1122334455667788",
        }],
        retval: { widthBytes: 4 as const, signedness: "signed" as const, bits: "0x00000000" },
        scalarOutputs: [],
        mutation: null,
      }],
      end: {
        processReturnCode: 0,
        timedOut: false,
        complete: true,
        ecallCount: 1,
        targetMatchCount: 0,
        mutationAppliedCount: 0,
        incompleteReasons: [],
      },
    };

    const rootPlans = deriveCandidatesFromCase(profile, baseCapture, { budget: 64, depth: 0 });
    expect(rootPlans.some((p) => (p.rule.opKind ?? "replace_scalar") === "replace_scalar")).toBe(true);
    expect(rootPlans.some((p) => p.rule.opKind === "mutate_buffer")).toBe(true);
    expect(rootPlans.some((p) => p.rule.opKind === "extend_history")).toBe(true);

    const historyParent = rootPlans.find((p) => p.rule.opKind === "extend_history" && p.rule.repeatCount === 1)!;
    expect(historyParent).toBeDefined();

    // Simulate a discovered extend_history run whose page set is identical to baseline, but has a 2-ECALL history
    const discoveredHistoryCapture = {
      ...baseCapture,
      runId: "22222222-2222-4222-8222-222222222222",
      events: [
        {
          ...baseCapture.events[0]!,
          mutation: {
            paramIndex: 0,
            widthBytes: 1 as const,
            signedness: "unsigned" as const,
            expectedBits: "0x00",
            observedBits: "0x00",
            replacementBits: "0x00",
            applied: true,
            reason: "applied",
          },
        },
        {
          ...baseCapture.events[0]!,
          callSeq: 1,
          selectorSeq: 1,
          mutation: null,
        },
      ],
      end: {
        ...baseCapture.end,
        ecallCount: 2,
        targetMatchCount: 1,
        mutationAppliedCount: 1,
      },
    };

    const historyChildren = deriveChildCandidatesFromFeedback(
      profile,
      baseCapture,
      discoveredHistoryCapture,
      historyParent,
      1,
      32,
    );
    expect(historyChildren.length).toBeGreaterThan(0);
    expect(historyChildren.some((c) => c.rule.opKind === "extend_history" && c.rule.repeatCount === 2)).toBe(true);
    expect(historyChildren.some((c) => c.rule.opKind === "mutate_buffer" && c.rule.execMode === 1)).toBe(true);
    expect(historyChildren.some((c) => (c.rule.opKind ?? "replace_scalar") === "replace_scalar" && c.rule.execMode === 1)).toBe(true);

    // End-to-end subprocess check: candidate "7" at depth 0 spawns depth-1 child candidates that execute when budget > 3
    const result = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath: path.join(fixture.root, "corpus-derivation"),
      role: "main",
      seeds: [{ id: "derive-case", args: ["--business-flow"], env: {} }],
      candidateBudget: 5,
      timeoutMs: 2000,
    });
    expect(result.seedResults[0]!.candidates[0]!.value).toBe("7");
    expect(result.seedResults[0]!.candidates[0]!.spawnedChildrenCount).toBeGreaterThan(0);
  });

  test("record-element buffers get IR switch-constant word writes in seed and child derivation", async () => {
    const fixture = makeBundle({ recordEcall: true });
    const { loadExplorerProfile } = await import("../../lib/explorer/profile.ts");
    const { deriveCandidatesFromCase, deriveChildCandidatesFromFeedback } = await import("../../lib/explorer/planner.ts");
    const profile = loadExplorerProfile(fixture.manifestPath);

    // A record-typed [in,size=data_len] buffer: first 4-byte word holds value 10 (not a switch case)
    const prefixBytes = Buffer.alloc(128);
    prefixBytes.writeUInt32LE(10, 0);
    const recordCapture = {
      bundleManifestSha256: profile.binding.bundleManifestSha256,
      marshalLayoutSha256: profile.binding.marshalLayoutSha256,
      runId: "33333333-3333-4333-8333-333333333333",
      events: [{
        generation: 1,
        callSeq: 0,
        selectorOrdinal: 1,
        selectorSeq: 0,
        transportStatus: 0,
        scalarInputs: [{ paramIndex: 1, widthBytes: 8 as const, signedness: "unsigned" as const, bits: "0x0000000000000058" }],
        bufferInputs: [{
          paramIndex: 0,
          direction: "in" as const,
          isString: false,
          elementSize: 44,
          byteLength: 88,
          fnv1a64: "0x0123456789abcdef",
          prefixHex: prefixBytes.toString("hex"),
        }],
        retval: { widthBytes: 4 as const, signedness: "signed" as const, bits: "0x00000000" },
        scalarOutputs: [],
        mutation: null,
      }],
      end: {
        processReturnCode: 0,
        timedOut: false,
        complete: true,
        ecallCount: 1,
        targetMatchCount: 0,
        mutationAppliedCount: 0,
        incompleteReasons: [],
      },
    };

    const roots = deriveCandidatesFromCase(profile, recordCapture, { budget: 512, depth: 0 });
    const constWrites = roots.filter((p) =>
      p.rule.opKind === "mutate_buffer" && p.rule.bufferSubOp === "write_le" &&
      p.rule.paramIndex === 0 && p.rule.byteOffset === 0 && p.value.startsWith("buf_word_const"));
    const constRepls = new Set(constWrites.map((p) => p.rule.replacementBits));
    // switch cases 1/30/31/32 all differ from the observed 10, so all four are candidates
    for (const hex of ["0x00000001", "0x0000001e", "0x0000001f", "0x00000020"]) {
      expect(constRepls.has(hex)).toBe(true);
    }

    // Child derivation on a record buffer previously hit a deleted producer hook; it must
    // now emit decoupled switch-constant writes without throwing.
    const parent = roots.find((p) => p.rule.opKind === "mutate_buffer")!;
    const discovered = {
      ...recordCapture,
      runId: "44444444-4444-4444-8444-444444444444",
      events: [{
        ...recordCapture.events[0]!,
        mutation: {
          paramIndex: 0,
          widthBytes: 1 as const,
          signedness: "unsigned" as const,
          expectedBits: "0x0a",
          observedBits: "0x0a",
          replacementBits: "0x0b",
          applied: true,
          reason: "applied",
        },
      }],
      end: { ...recordCapture.end, targetMatchCount: 1, mutationAppliedCount: 1 },
    };
    const children = deriveChildCandidatesFromFeedback(profile, recordCapture, discovered, parent, 1, 128);
    expect(children.length).toBeGreaterThan(0);
    expect(children.some((c) => c.value.startsWith("derived_buf_word_const"))).toBe(true);

    // A non-record buffer on the scalar ecall must NOT get switch-constant record writes.
    const scalarCapture = {
      ...recordCapture,
      events: [{
        ...recordCapture.events[0]!,
        selectorOrdinal: 0,
        bufferInputs: [{
          paramIndex: 0,
          direction: "in" as const,
          isString: false,
          elementSize: 4,
          byteLength: 16,
          fnv1a64: "0x0123456789abcdef",
          prefixHex: prefixBytes.toString("hex", 0, 16),
        }],
      }],
    };
    const scalarRoots = deriveCandidatesFromCase(profile, scalarCapture, { budget: 256, depth: 0 });
    expect(scalarRoots.some((p) => p.value.startsWith("buf_word_const"))).toBe(false);
  });
});
