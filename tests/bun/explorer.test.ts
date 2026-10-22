import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalJson, validateIrFactsAggregateV2 } from "../../lib/bundle/profile-bundle.ts";
import {
  encodeMutationSpec,
  parseCallCapture,
  parseNativeCallCapture,
  appendCallCaptureEnd,
  captureHasExactlyOneMutation,
  type CallCaptureDocument,
  type CallCaptureEvent,
  type ScalarMutationRule,
} from "../../lib/explorer/contract.ts";
import { exploreSeeds } from "../../lib/explorer/explorer.ts";
import { deriveOnlineScalarCandidates } from "../../lib/explorer/planner.ts";
import { readFinalizableCorpus } from "../../lib/explorer/corpus.ts";
import { parseArgs } from "../../cli/explore.ts";
import { loadExplorerProfile } from "../../lib/explorer/profile.ts";
import { runCanonicalHost } from "../../lib/runner/canonical-runner.ts";
import { parseCanonicalTrace } from "../../lib/workset/trace.ts";
import { appendValidatedCorpusTrace } from "../../lib/explorer/corpus.ts";

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
    "  if (bytes.length < 144 || bytes.readUInt32LE(16) !== 1 || bytes.readUInt32LE(88) !== bytes.length - 88 || bytes.readUInt16LE(108) < 1 || bytes.toString('ascii', 0, 6) !== 'ATFMUT') process.exit(21);",
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
    "  capturePath: env.ATFIELD_CALL_CAPTURE_PATH, lifecyclePath: env.ATFIELD_LIFECYCLE_PATH, marshalSpecPath: env.ATFIELD_MARSHAL_SPEC_PATH,",
    "  mutationPath: mutationPath || null, inputBits, use4Gate: env.ATFIELD_USE_4GATE, ipiMask: env.ATFIELD_IPI_MASK, gateMode: env.ATFIELD_GATE_MODE, mode: env.ATFIELD_MODE,",
    "};",
    "if (env.TEST_OBSERVATIONS) fs.appendFileSync(env.TEST_OBSERVATIONS, JSON.stringify(seen) + '\\n');",
    "if (env.TEST_WRITE_LIFECYCLE) fs.writeFileSync(env.ATFIELD_LIFECYCLE_PATH, [{ event: 'enclave_created', generation: 1, callSeq: 0, selectorOrdinal: 0, selectorSeq: 0 }, { event: 'ecall_enter', generation: 1, callSeq: 0, selectorOrdinal: 0, selectorSeq: 0 }, { event: 'ecall_return', generation: 1, callSeq: 0, selectorOrdinal: 0, selectorSeq: 0 }].map(JSON.stringify).join('\\n') + '\\n');",
    "const numeric = Number(BigInt(inputBits));",
    "const isBizReject = Boolean(mutation && process.argv.includes('--call-once') && numeric === 8);",
    "const selectedPage = mutation && numeric === 7 ? '0x2000' : (mutation && numeric === 10 ? '0x4000' : (isBizReject ? '0x3000' : '0x1000'));",
    "const phase = (rva) => ({ page_size: 4096, complete: true, page_effects: [{ rva, a: true, d: false }] });",
    "const traceStart = {",
    "  schema: 'atfield-canonical-trace-v1', record_type: 'run_start',",
    "  run_id: env.ATFIELD_RUN_ID, layout_epoch: env.ATFIELD_LAYOUT_EPOCH,",
    "  instance_generation: null, seed_id: env.ATFIELD_SEED_ID, argv: JSON.parse(env.ATFIELD_SEED_ARGV_JSON),",
    "  sample: env.ATFIELD_SAMPLE, mode: env.ATFIELD_MODE,",
    "  start_time: new Date().toISOString(), selected_enclave_sha256: env.ATFIELD_ENCLAVE_SHA256,",
    "  bundle_manifest_sha256: env.ATFIELD_BUNDLE_MANIFEST_SHA256,",
    "};",
    "const traceEcall = {",
    "  schema: traceStart.schema, record_type: 'ecall', run_id: traceStart.run_id,",
    "  layout_epoch: traceStart.layout_epoch, bundle_manifest_sha256: traceStart.bundle_manifest_sha256,",
    "  instance_generation: 1, call_seq: 0, selector_ordinal: 0, selector_seq: 0,",
    "  tag: 'synthetic', elapsed_ns: 1, sgx_status: 0, abi_return_type: 'void',",
    "  abi_return_value: isBizReject ? -1 : 0, out_status_i32: isBizReject ? 12289 : 0, measurement_valid: true,",
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
    "if (isBizReject) process.exit(1);",
    "if (mutation && numeric === 8 && process.argv.includes('--signal-after-field')) process.kill(process.pid, 'SIGSEGV');",
  ];
  return lines.join("\n") + "\n";
}

function makeBundle(opts: { recordEcall?: boolean; includePage3000?: boolean; includePage4000?: boolean } = {}): { root: string; manifestPath: string; hostPath: string } {
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
    schema: "atfield-ir-facts-aggregate-v2",
    facts: [{
      schema: "atfield-ir-facts-v2",
      translation_unit: "fixture.o",
      module_id: "irtu_00000000000000000000000000000001",
      backend_ir_sha256: "11".repeat(32),
      object_sha256: "22".repeat(32),
      compile_variant: { target_triple: "x86_64-unknown-linux-gnu", optimization_level: "0", relocation_model: "pic", backend_flags: [] },
      source: { input_file: "fixture.c", ir_filename: "fixture.ll" },
      callgraph_complete: true,
      guidance_complete: true,
      diagnostics: [],
      definitions: [{ symbol: "fixture_function", linkage: "external", source_file: "fixture.c", address_use: { address_taken: false, complete: true, reasons: [] }, line: 1 }],
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
    version: 1,
    algorithm: "fixture-v1",
    tool: { name: "atfield-reachability", version: "1" },
    analysis: { kind: "fixture", profile_elf_sha256: digest("synthetic profile ELF") },
    input: {
      profile_elf_sha256: digest("synthetic profile ELF"),
      edl_abi_sha256: digest(abiBytes),
      live_fields_sha256: digest(JSON.stringify(fieldsArtifact)),
      expected_objects: [{ translation_unit: irFact.translation_unit, object_sha256: irFact.object_sha256 }],
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
      entry_symbol: "fixture_function",
      private: false,
      callgraph_complete: true,
      guidance_complete: true,
      field_reachability_complete: true,
      reachable_function_instances: [],
      reachability: "static-may-reach",
      evidence: {},
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
      symbol: "record_function", linkage: "external", source_file: "fixture.c",
      address_use: { address_taken: false, complete: true, reasons: [] }, line: 2,
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
      entry_symbol: "record_function",
      private: false,
      callgraph_complete: true,
      guidance_complete: true,
      field_reachability_complete: true,
      reachable_function_instances: [],
      reachability: "static-may-reach",
      evidence: {},
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
      ...(opts.includePage3000 ? [{ rva: "0x3000", max_permissions: "R-X", region_kind: "text" }] : []),
      ...(opts.includePage4000 ? [{ rva: "0x4000", max_permissions: "R-X", region_kind: "text" }] : []),
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
  test("validates the captured WolfSSL v2 IR aggregate including address-use provenance", () => {
    const fixture = path.join(import.meta.dir, "../../fixtures/profile-bundle-v2-wolfssl-ir-facts.json");
    const aggregate = JSON.parse(readFileSync(fixture, "utf8"));
    const facts = validateIrFactsAggregateV2(aggregate);
    expect(facts.length).toBe(3);
    const definition = (facts[0]!.definitions as Array<Record<string, unknown>>)
      .find((item) => item.symbol === "sgx_fixture")!;
    expect(definition.address_use).toMatchObject({
      address_taken: true,
      complete: true,
      non_direct_uses: ["global:g_ecall_table"],
    });
    const malformed = structuredClone(aggregate);
    malformed.facts[0].definitions[0].address_use.complete = "yes";
    expect(() => validateIrFactsAggregateV2(malformed)).toThrow("address_use flags must be boolean");
  });

  test("canonical runtime files use a tmpfs scratch and are copied to durable run artifacts", async () => {
    const fixture = makeBundle();
    const scratchRoot = mkdtempSync(path.join("/dev/shm", "explorer-tmpfs-test-"));
    temporaryRoots.push(scratchRoot);
    const corpusPath = path.join(fixture.root, "tmpfs-corpus");
    const observationsPath = path.join(fixture.root, "runtime-paths.jsonl");
    const result = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath,
      role: "main",
      seeds: [{ id: "tmpfs-runtime", args: [], env: {
        TEST_OBSERVATIONS: observationsPath,
        TEST_WRITE_LIFECYCLE: "1",
      } }],
      candidateBudget: 1,
      tempRoot: scratchRoot,
    });
    const observations = readFileSync(observationsPath, "utf8").trim().split("\n")
      .map((line) => JSON.parse(line) as { capturePath: string; lifecyclePath: string; marshalSpecPath: string; mutationPath: string | null });
    expect(observations.length).toBeGreaterThan(1);
    for (const observation of observations) {
      expect(observation.capturePath.startsWith(scratchRoot + path.sep)).toBe(true);
      expect(observation.lifecyclePath.startsWith(scratchRoot + path.sep)).toBe(true);
      expect(observation.marshalSpecPath.startsWith(scratchRoot + path.sep)).toBe(true);
      if (observation.mutationPath) expect(observation.mutationPath.startsWith(scratchRoot + path.sep)).toBe(true);
      expect(existsSync(path.dirname(observation.capturePath))).toBe(false);
    }
    const baselineDir = result.seedResults[0]!.baselineArtifactPath!;
    expect(existsSync(path.join(baselineDir, "calls.jsonl"))).toBe(true);
    expect(existsSync(path.join(baselineDir, "lifecycle.jsonl"))).toBe(true);
    expect(existsSync(path.join(baselineDir, "marshal.spec"))).toBe(true);
    const candidate = result.seedResults[0]!.candidates[0]!;
    expect(existsSync(path.join(candidate.artifactPath!, "calls.jsonl"))).toBe(true);
    expect(existsSync(path.join(candidate.artifactPath!, "lifecycle.jsonl"))).toBe(true);
    expect(existsSync(path.join(candidate.artifactPath!, "marshal.spec"))).toBe(true);
    expect(existsSync(path.join(candidate.artifactPath!, "mutation.spec"))).toBe(true);
    expect(existsSync(observations[0]!.capturePath)).toBe(false);
  });

  test("an explicit non-tmpfs scratch root fails closed", async () => {
    const fixture = makeBundle();
    const { statfsSync } = await import("node:fs");
    if (statfsSync(process.cwd(), { bigint: true }).type === 0x01021994n) return;
    await expect(exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath: path.join(fixture.root, "rejected-scratch-corpus"),
      role: "main",
      seeds: [{ id: "non-tmpfs", args: [], env: {} }],
      candidateBudget: 0,
      tempRoot: process.cwd(),
    })).rejects.toThrow(/not tmpfs/);
  });

  test("a real signal after Field completion is rejected with durable failure evidence", async () => {
    const fixture = makeBundle({ includePage3000: true });
    const corpusPath = path.join(fixture.root, "signal-corpus");
    const result = await exploreSeeds({ bundlePath: fixture.manifestPath, corpusPath, role: "main",
      seeds: [{ id: "signal-exit", args: ["--signal-after-field"], env: {} }], candidateBudget: 6 });
    const attempt = result.seedResults[0]?.candidates.find((item) => item.value === "8");
    expect(attempt?.accepted).toBe(false);
    expect(attempt?.runTerminalState).toBe("incomplete");
    if (!attempt?.artifactPath || !attempt.runId) throw new Error("missing signal failure artifacts");
    const artifactDir = attempt.artifactPath;
    expect(existsSync(path.join(artifactDir, "calls.jsonl"))).toBe(true);
    expect(existsSync(path.join(artifactDir, "mutation.spec"))).toBe(true);
    expect(existsSync(path.join(artifactDir, "stdout.log"))).toBe(true);
    expect(existsSync(path.join(artifactDir, "stderr.log"))).toBe(true);
    const metadata = readFileSync(path.join(artifactDir, "signal-exit-" + attempt.runId + ".meta.json"), "utf8");
    expect(metadata).toContain('"termination": "signaled"');
    expect(readFinalizableCorpus(corpusPath, fixture.manifestPath).some((trace) => trace.runId === attempt.runId)).toBe(false);
  });

  test("native prefix writer passes the real capture contract and corpus gate", async () => {
    const fixture = makeBundle();
    const profile = loadExplorerProfile(fixture.manifestPath);
    const run = await runCanonicalHost({
      bundlePath: fixture.manifestPath, args: [],
      env: { ATFIELD_CALL_CAPTURE_PATH: path.join(fixture.root, "baseline.calls"),
        ATFIELD_MARSHAL_LAYOUT_SHA256: profile.binding.marshalLayoutSha256 },
    });
    expect(run.completion).toBe("complete");
    const rule: ScalarMutationRule = { selectorOrdinal: 0, selectorSeq: 1, paramIndex: 0,
      widthBytes: 4, signedness: "unsigned", expectedBits: "0x0000002a", replacementBits: "0x00000007",
      prefixMutations: [{ selectorOrdinal: 0, selectorSeq: 0, paramIndex: 3, byteOffset: 0,
        widthBytes: 4, expectedBits: "0x11223344", replacementBits: "0xaabbccdd" }] };
    const specPath = path.join(fixture.root, "native.spec");
    const capturePath = path.join(fixture.root, "native.calls.jsonl");
    writeFileSync(specPath, encodeMutationSpec(profile.binding, rule));
    const probe = Bun.spawnSync([path.resolve("build/mutation_contract_probe"), specPath, capturePath,
      profile.binding.bundleManifestSha256, profile.binding.marshalLayoutSha256, run.runId]);
    expect(new TextDecoder().decode(probe.stderr)).toBe("");
    expect(probe.exitCode).toBe(0);
    const lines = run.traceText.trimEnd().split("\n");
    const ecall = lines[1];
    if (!ecall) throw new Error("fixture has no ECALL");
    lines.splice(2, 0, ecall.replace(/"call_seq"\s*:\s*0\b/, '"call_seq":1').replace(/"selector_seq"\s*:\s*0\b/, '"selector_seq":1'));
    const traceText = lines.join("\n").replace(/"(?:ecall_count|record_count)"\s*:\s*1\b/, '"ecall_count":2') + "\n";
    const candidate = { ...run, traceText, parsedTrace: parseCanonicalTrace(traceText, "native prefix fixture", profile.bundle) };
    const nativeText = readFileSync(capturePath, "utf8");
    const completed = appendCallCaptureEnd(nativeText, candidate, { ...profile.binding, runId: run.runId, mutation: rule });
    expect(completed.capture.end.complete).toBe(true);
    expect(captureHasExactlyOneMutation(completed.capture, rule)).toBe(true);
    const buffer = completed.capture.events[0]?.bufferInputs?.find((b) => b.paramIndex === 3);
    expect(buffer?.prefixHex).toBe("ddccbbaa88776655");
    expect(buffer?.storageAddress).toMatch(/^0x[0-9a-f]{16}$/);
    const corpusPath = path.join(fixture.root, "native-corpus");
    appendValidatedCorpusTrace(corpusPath, "main", candidate, profile.bundle);
    expect(readFinalizableCorpus(corpusPath, fixture.manifestPath)[0]?.parsedTrace.ecallCount).toBe(2);
  });

  test("one encoded expansion budget controls native allocation and rejection", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "native-expansion-contract-"));
    temporaryRoots.push(root);
    const binding = { bundleManifestSha256: "aa".repeat(32), marshalLayoutSha256: "bb".repeat(32) };
    const rule: ScalarMutationRule = { selectorOrdinal: 0, selectorSeq: 0, paramIndex: 2, execMode: 1,
      widthBytes: 4, signedness: "unsigned", expectedBits: "0x00000008", replacementBits: "0x00013880" };
    for (const [name, budget, allowed] of [
      ["small", { perBufferBytes: 65536, totalBytes: 262144 }, false],
      ["large", { perBufferBytes: 262144, totalBytes: 1048576 }, true],
    ] as const) {
      const specPath = path.join(root, name + ".spec");
      const capturePath = path.join(root, name + ".jsonl");
      const runId = "00000000-0000-4000-8000-000000000001";
      writeFileSync(specPath, encodeMutationSpec(binding, { ...rule, expansionBudget: budget }));
      const probe = Bun.spawnSync([path.resolve("build/mutation_contract_probe"), specPath, capturePath,
        binding.bundleManifestSha256, binding.marshalLayoutSha256, runId]);
      expect(probe.exitCode).toBe(0);
      const capture = parseNativeCallCapture(readFileSync(capturePath, "utf8"), { ...binding, runId, mutation: rule });
      expect(capture.events[0]?.mutation?.applied).toBe(allowed);
      expect(capture.events[0]?.mutation?.reason).toBe(allowed ? "applied" : "expansion_budget_exceeded");
      if (allowed) expect(capture.events[0]?.bufferInputs?.[0]?.byteLength).toBe(80000);
      expect(new TextDecoder().decode(probe.stdout)).toContain('"zeroExpansion":true');
    }
  });

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
    const binding = { bundleManifestSha256: "11".repeat(32), marshalLayoutSha256: "22".repeat(32) };
    expect(() => encodeMutationSpec(binding, { ...rule, replacementBits: rule.expectedBits }))
      .toThrow(/no-op/);
    const historyBytes = encodeMutationSpec(binding, {
      ...rule, opKind: "extend_history", repeatCount: 1, replacementBits: rule.expectedBits,
    });
    expect(new DataView(historyBytes.buffer, historyBytes.byteOffset, historyBytes.byteLength)
      .getUint16(112, true)).toBe(3);
    expect(() => encodeMutationSpec({
      bundleManifestSha256: "11".repeat(32),
      marshalLayoutSha256: "22".repeat(32),
    }, { ...rule, replacementBits: "0x7" })).toThrow();
  });

  test("online feedback skips a scalar candidate that returns to baseline bits", () => {
    const fixture = makeBundle();
    const profile = loadExplorerProfile(fixture.manifestPath);
    const baselineEvent: CallCaptureEvent = {
      generation: 1, callSeq: 0, selectorOrdinal: 0, selectorSeq: 0, transportStatus: 0,
      scalarInputs: [{ paramIndex: 0, widthBytes: 4, signedness: "signed", bits: "0x00000005" }],
      retval: null, scalarOutputs: [], mutation: null,
    };
    const observedEvent: CallCaptureEvent = {
      ...baselineEvent,
      scalarInputs: [{ paramIndex: 0, widthBytes: 4, signedness: "signed", bits: "0x00000006" }],
      mutation: { paramIndex: 0, widthBytes: 4, signedness: "signed",
        expectedBits: "0x00000005", observedBits: "0x00000005", replacementBits: "0x00000006",
        applied: true, reason: "applied" },
    };
    const capture = (event: CallCaptureEvent, runId: string): CallCaptureDocument => ({
      ...profile.binding, runId, events: [event], end: { processReturnCode: 0, termination: "exited",
        timedOut: false, complete: true, ecallCount: 1, targetMatchCount: 1,
        mutationAppliedCount: event.mutation?.applied ? 1 : 0, incompleteReasons: [] },
    });
    const baseline = capture(baselineEvent, "11111111-1111-4111-8111-111111111111");
    const observed = capture(observedEvent, "22222222-2222-4222-8222-222222222222");
    const plans = deriveOnlineScalarCandidates(profile, baseline, observed, {
      rule: { selectorOrdinal: 0, selectorSeq: 0, paramIndex: 0, widthBytes: 4,
        signedness: "signed", expectedBits: "0x00000005", replacementBits: "0x00000006", execMode: 1 },
      value: "6", priority: 500, evidenceSiteIds: ["fixture"],
    }, { measurementComplete: true, accepted: true, businessOutcome: "ok",
      pageDeltaCount: 1, newFieldEntry: true });
    expect(plans.map((plan) => plan.value)).not.toContain("5");
    expect(plans.every((plan) => plan.rule.replacementBits !== "0x00000005")).toBe(true);
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
    const baselineDir = result.seedResults[0]!.baselineArtifactPath!;
    const evidenceDirs = [baselineDir, ...result.seedResults[0]!.candidates.map((candidate) => candidate.artifactPath!)];
    expect(evidenceDirs).toHaveLength(4);
    for (const directory of evidenceDirs) {
      const manifest = JSON.parse(readFileSync(path.join(directory, "attempt.json"), "utf8"));
      const runMeta = JSON.parse(readFileSync(manifest.artifactPaths.meta, "utf8"));
      const runStart = JSON.parse(readFileSync(manifest.artifactPaths.trace, "utf8").split("\n")[0]!);
      expect(manifest.seed).toEqual(seeds[0]);
      expect(runMeta.seed_id).toBe(seeds[0]!.id);
      expect(runMeta.argv).toEqual(seeds[0]!.args);
      expect(runStart.seed_id).toBe(seeds[0]!.id);
      expect(runStart.argv).toEqual(seeds[0]!.args);
    }
    expect(result.seedResults[0]!.candidates.map((candidate) => candidate.value)).toEqual(["7", "6", "8"]);
    expect(result.seedResults[0]!.candidates.map((candidate) => candidate.accepted)).toEqual([true, false, true]);
    expect(result.seedResults[0]!.feedback.map((item) => item.value)).toEqual(["7", "8"]);
    expect(result.seedResults[0]!.candidates[2]!.novel).toBe(true);
    expect(result.seedResults[0]!.candidates[2]!.targetEnteredField).toBe(true);
    expect(result.seedResults[0]!.candidates[2]!.newFieldEntry).toBe(false);
    expect(result.seedResults[0]!.candidates[2]!.pageDelta).toEqual([]);
    expect(result.seedResults[0]!.candidates[2]!.committedCorpusRole).toBe("main");
    expect(readFinalizableCorpus(path.join(fixture.root, "corpus"), fixture.manifestPath)).toHaveLength(3);
    expect(result.seedResults[0]!.feedback[0]!.pageDelta).toEqual([{
      fieldId: "field-1",
      pageRva: "0x2000",
      effects: ["R", "X"],
    }]);
    expect(result.seedResults[0]!.candidates[1]!.reason).toMatch(/AEX|measurement|incomplete/i);
    expect(result.seedResults[0]!.candidates[1]!.committedCorpusRole).toBeNull();
    expect(new Set(result.seedResults[0]!.candidates.map((candidate) => candidate.candidateKey)).size)
      .toBe(result.seedResults[0]!.candidates.length);
    const finalizedRunIds = new Set(readFinalizableCorpus(path.join(fixture.root, "corpus"), fixture.manifestPath)
      .map((trace) => trace.runId));
    expect(finalizedRunIds.has(result.seedResults[0]!.candidates[1]!.runId!)).toBe(false);

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
  test("accepts optional full-buffer SHA-256 and rejects malformed digests", () => {
    const binding = { bundleManifestSha256: "11".repeat(32), marshalLayoutSha256: "22".repeat(32) };
    const runId = "run-hash";
    const captureText = (sha256?: string) => [
      JSON.stringify({ type: "capture_start", schema: "atfield-call-capture-v1", run_id: runId,
        bundle_manifest_sha256: binding.bundleManifestSha256, marshal_layout_sha256: binding.marshalLayoutSha256 }),
      JSON.stringify({ type: "ecall", generation: 1, call_seq: 0, selector_ordinal: 0, selector_seq: 0,
        transport_status: 0, scalar_inputs: [], retval: null, scalar_outputs: [], mutation: null,
        buffer_inputs: [{ param_index: 3, direction: "in", is_string: false, element_size: 1,
          byte_length: 192, fnv1a64: "0x0000000000000000", prefix_hex: "00".repeat(128),
          ...(sha256 !== undefined ? { sha256 } : {}) }] }),
    ].join("\n");
    const expectation = { ...binding, runId };
    expect(parseNativeCallCapture(captureText(), expectation).events[0]?.bufferInputs?.[0]?.sha256).toBeUndefined();
    expect(parseNativeCallCapture(captureText("ab".repeat(32)), expectation).events[0]?.bufferInputs?.[0]?.sha256)
      .toBe("ab".repeat(32));
    expect(() => parseNativeCallCapture(captureText("AB".repeat(32)), expectation))
      .toThrow(/sha256 must be lowercase SHA-256 hex/);
    expect(() => parseNativeCallCapture(captureText("ab".repeat(31)), expectation))
      .toThrow(/sha256 must be lowercase SHA-256 hex/);
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
    expect(mutatedRes.seedResults[0]?.candidates.some((candidate) => candidate.newFieldEntry)).toBe(true);
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

  test("collector shared library links with zero undefined symbols", () => {
    const soPath = path.join(import.meta.dir, "..", "..", "build", "libatfield_native_sgx.so");
    expect(existsSync(soPath)).toBe(true);
    const ldd = Bun.spawnSync({ cmd: ["ldd", "-r", soPath], stdout: "pipe", stderr: "pipe" });
    const out = new TextDecoder().decode(ldd.stdout) + "\n" + new TextDecoder().decode(ldd.stderr);
    expect(ldd.exitCode).toBe(0);
    expect(out).not.toContain("undefined symbol");
  });

  test("online scalar feedback schedules a post-measurement value that reaches a new Field page effect", async () => {
    const fixture = makeBundle({ includePage4000: true });
    const corpusPath = path.join(fixture.root, "corpus-online-feedback");
    const result = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath,
      role: "main",
      seeds: [{ id: "online-feedback-seed", args: ["--early-return"], env: {} }],
      candidateBudget: 2,
      timeoutMs: 2000,
    });
    const attempts = result.seedResults[0]!.candidates;
    expect(attempts.map((item) => item.value)).toEqual(["7", "10"]);
    expect(attempts[0]!.accepted).toBe(true);
    expect(attempts[0]!.newFieldEntry).toBe(true);
    expect(attempts[0]!.spawnedChildrenCount).toBeGreaterThan(0);
    expect(attempts[1]!.accepted).toBe(true);
    expect(attempts[1]!.pageDelta.some((item) => item.pageRva === "0x4000")).toBe(true);
    const committedRunIds = new Set(readFinalizableCorpus(corpusPath, fixture.manifestPath).map((trace) => trace.runId));
    expect(committedRunIds.has(attempts[1]!.runId!)).toBe(true);
  });

  test("Stage 1: CALL_ONCE probes in fresh instances distinguish normal completion from business-rejection exit while committing valid 4-gate observations", async () => {
    const fixture = makeBundle({ includePage3000: true });
    const corpusPath = path.join(fixture.root, "corpus-call-once");
    const result = await exploreSeeds({
      bundlePath: fixture.manifestPath,
      corpusPath,
      role: "main",
      seeds: [{ id: "call-once-seed", args: ["--call-once"], env: {} }],
      candidateBudget: 6,
      timeoutMs: 2000,
    });
    const attempts = result.seedResults[0]!.candidates;
    const normalProbe = attempts.find((c) => c.value === "7")!;
    const rejectProbe = attempts.find((c) => c.value === "8")!;
    const aexProbe = attempts.find((c) => c.value === "6")!;
    expect(normalProbe).toBeDefined();
    expect(normalProbe.accepted).toBe(true);
    expect(normalProbe.measurementComplete).toBe(true);
    expect(normalProbe.businessOutcome).toBe("ok");
    expect(normalProbe.runTerminalState).toBe("complete");
    expect(normalProbe.processReturnCode).toBe(0);
    expect(normalProbe.pageDelta.some((p) => p.pageRva === "0x2000")).toBe(true);

    expect(rejectProbe).toBeDefined();
    expect(rejectProbe.accepted).toBe(true);
    expect(rejectProbe.measurementComplete).toBe(true);
    expect(rejectProbe.businessOutcome).toBe("rejected");
    expect(rejectProbe.runTerminalState).toBe("business_rejection_exit");
    expect(rejectProbe.processReturnCode).toBe(1);
    expect(rejectProbe.pageDelta).toEqual([]);

    if (aexProbe) {
      expect(aexProbe.accepted).toBe(false);
      expect(aexProbe.measurementComplete).toBe(false);
      expect(aexProbe.runTerminalState).toBe("incomplete");
    }

    const finalized = readFinalizableCorpus(corpusPath, fixture.manifestPath);
    const mainTraces = finalized.filter((tr) => tr.role === "main");
    const suppTraces = finalized.filter((tr) => tr.role === "supplemental");
    expect(mainTraces.length).toBeGreaterThanOrEqual(2);
    expect(suppTraces).toHaveLength(0);
    expect(rejectProbe.pageDelta).toEqual([]);
    expect(rejectProbe.committedCorpusRole).toBeNull();
    expect(finalized.some((trace) => trace.parsedTrace.observations.some((o) => o.pageRva === 0x3000n))).toBe(false);
    const { main: worksetCliMain } = await import("../../cli/atfield-workset.ts");
    expect(worksetCliMain(["--bundle", fixture.manifestPath, "--corpus", corpusPath,
      "--out", path.join(fixture.root, "with-business-rejection.workset.json")])).toBe(0);
  });

  test("Stage 2: evaluateLinkedBufferExpansion computes synchronized input/output capacities and reports expansion_budget_exceeded on over-budget candidates", async () => {
    const fixture = makeBundle({ recordEcall: true });
    const { loadExplorerProfile } = await import("../../lib/explorer/profile.ts");
    const { evaluateLinkedBufferExpansion } = await import("../../lib/explorer/planner.ts");
    const profile = loadExplorerProfile(fixture.manifestPath);
    const event = {
      generation: 1,
      callSeq: 0,
      selectorOrdinal: 1,
      selectorSeq: 0,
      transportStatus: 0,
      scalarInputs: [{ paramIndex: 1, widthBytes: 8 as const, signedness: "unsigned" as const, bits: "0x000000000000002c" }],
      retval: null,
      scalarOutputs: [],
      mutation: null,
    };
    const shrink = evaluateLinkedBufferExpansion(profile, 1, 1, 44n, event);
    expect(shrink.status).toBe("in_place_ok");
    const expand = evaluateLinkedBufferExpansion(profile, 1, 1, 88n, event);
    expect(expand.status).toBe("expanded_ok");
    expect(expand.affectedBuffers).toEqual([{ paramIndex: 0, oldBytes: 44n, newBytes: 88n }]);
    const overBudget = evaluateLinkedBufferExpansion(profile, 1, 1, 131072n, event);
    expect(overBudget.status).toBe("expansion_budget_exceeded");
    expect(overBudget.reason).toBe("expansion_budget_exceeded");
  });

  test("Stage 3: Producer-consumer dataflow links runtime buffer outputs to consumers and distinguishes fresh objects from stale, wrong-generation, and length-mismatched objects", async () => {
    const {
      inferCaptureProducerConsumerFlow,
      validateProducerConsumerBinding,
    } = await import("../../lib/explorer/planner.ts");
    const capture = {
      bundleManifestSha256: "00".repeat(32),
      marshalLayoutSha256: "11".repeat(32),
      runId: "run-current",
      events: [
        {
          generation: 1,
          callSeq: 0,
          selectorOrdinal: 2,
          selectorSeq: 0,
          transportStatus: 0,
          scalarInputs: [],
          bufferOutputs: [{
            paramIndex: 1,
            direction: "out" as const,
            isString: false,
            elementSize: 1,
            byteLength: 64,
            fnv1a64: "0xdeadbeefcafebabe",
            prefixHex: "aa55",
            storageAddress: "0x0000000000001000",
          }],
          retval: null,
          scalarOutputs: [],
          mutation: null,
        },
        {
          generation: 1,
          callSeq: 1,
          selectorOrdinal: 6,
          selectorSeq: 0,
          transportStatus: 0,
          scalarInputs: [],
          bufferInputs: [{
            paramIndex: 2,
            direction: "in" as const,
            isString: false,
            elementSize: 1,
            byteLength: 64,
            fnv1a64: "0xdeadbeefcafebabe",
            prefixHex: "aa55",
            storageAddress: "0x0000000000001000",
          }],
          retval: null,
          scalarOutputs: [],
          mutation: null,
        },
      ],
      end: {
        processReturnCode: 0,
        timedOut: false,
        complete: true,
        ecallCount: 2,
        targetMatchCount: 0,
        mutationAppliedCount: 0,
        incompleteReasons: [],
      },
    };
    const edges = inferCaptureProducerConsumerFlow(capture);
    expect(edges).toHaveLength(1);
    const edge = edges[0]!;
    expect(edge.producer.selectorOrdinal).toBe(2);
    expect(edge.consumer.selectorOrdinal).toBe(6);

    const freshOk = validateProducerConsumerBinding(edge, {
      runId: "run-current",
      currentRunId: "run-current",
      instanceGeneration: 1,
      objectVersion: 1,
      latestObjectVersion: 1,
      byteLength: 64,
      verifiedIdentity: true,
      storageAddress: "0x0000000000001000", producerCallSeq: 0, producerParamIndex: 1, elementSize: 1,
    });
    expect(freshOk).toEqual({ valid: true, reason: null });

    const stale = validateProducerConsumerBinding(edge, {
      runId: "run-previous",
      currentRunId: "run-current",
      instanceGeneration: 1,
      objectVersion: 1,
      latestObjectVersion: 1,
      byteLength: 64,
      verifiedIdentity: true,
      storageAddress: "0x0000000000001000", producerCallSeq: 0, producerParamIndex: 1, elementSize: 1,
    });
    expect(stale).toEqual({ valid: false, reason: "stale_producer_object" });

    const wrongGen = validateProducerConsumerBinding(edge, {
      runId: "run-current",
      currentRunId: "run-current",
      instanceGeneration: 2,
      objectVersion: 1,
      latestObjectVersion: 1,
      byteLength: 64,
      verifiedIdentity: true,
      storageAddress: "0x0000000000001000", producerCallSeq: 0, producerParamIndex: 1, elementSize: 1,
    });
    expect(wrongGen).toEqual({ valid: false, reason: "producer_generation_mismatch" });

    const wrongLen = validateProducerConsumerBinding(edge, {
      runId: "run-current",
      currentRunId: "run-current",
      instanceGeneration: 1,
      objectVersion: 1,
      latestObjectVersion: 1,
      byteLength: 48,
      verifiedIdentity: true,
      storageAddress: "0x0000000000001000", producerCallSeq: 0, producerParamIndex: 1, elementSize: 1,
    });
    expect(wrongLen).toEqual({ valid: false, reason: "producer_length_mismatch" });
  });

  test("Stage 4: Cold-instance first-call reorder preserves no-Field initializer prefix, accepts portable serialized objects, and rejects instance-bound handles", async () => {
    const { evaluateColdInstanceFirstCallReorder } = await import("../../lib/explorer/planner.ts");
    const capture = {
      bundleManifestSha256: "00".repeat(32),
      marshalLayoutSha256: "11".repeat(32),
      runId: "run-cold",
      events: [
        {
          generation: 2,
          callSeq: 5,
          selectorOrdinal: 0, // no-Field initializer call (trustedEnclaveInit)
          selectorSeq: 0,
          transportStatus: 0,
          scalarInputs: [],
          retval: null,
          scalarOutputs: [],
          mutation: null,
        },
        {
          generation: 2,
          callSeq: 6,
          selectorOrdinal: 3, // restoration call (trustedSetSEK)
          selectorSeq: 0,
          transportStatus: 0,
          scalarInputs: [],
          retval: null,
          scalarOutputs: [],
          mutation: null,
        },
        {
          generation: 2,
          callSeq: 7,
          selectorOrdinal: 6, // consumer call (trustedEcdsaSign)
          selectorSeq: 0,
          transportStatus: 0,
          scalarInputs: [],
          retval: null,
          scalarOutputs: [],
          mutation: null,
        },
      ],
      end: {
        processReturnCode: 0,
        timedOut: false,
        complete: true,
        ecallCount: 3,
        targetMatchCount: 0,
        mutationAppliedCount: 0,
        incompleteReasons: [],
      },
    };

    const portableOk = evaluateColdInstanceFirstCallReorder(capture, {
      targetGeneration: 2,
      targetConsumerCallSeq: 7,
      preserveInitializerCalls: true,
      inputPortability: "verified_portable_serialized",
    });
    expect(portableOk).toEqual({
      allowed: true,
      reason: null,
      requiredPrefixCallSeqs: [5, 6],
    });

    const handleRejected = evaluateColdInstanceFirstCallReorder(capture, {
      targetGeneration: 2,
      targetConsumerCallSeq: 7,
      preserveInitializerCalls: true,
      inputPortability: "instance_bound_handle",
    });
    expect(handleRejected).toEqual({
      allowed: false,
      reason: "instance_bound_handle_not_transferable",
      requiredPrefixCallSeqs: [5, 6],
    });

    const droppedInitRejected = evaluateColdInstanceFirstCallReorder(capture, {
      targetGeneration: 2,
      targetConsumerCallSeq: 7,
      preserveInitializerCalls: false,
      inputPortability: "verified_portable_serialized",
    });
    expect(droppedInitRejected.allowed).toBe(false);
    expect(droppedInitRejected.reason).toBe("missing_initializer_or_restoration_prefix");
  });

  test("Stage 5: Anti-specialization test verifies planner and dataflow operators remain invariant under renamed symbols, permuted selector ordinals, altered struct sizes, and shifted enum constants", async () => {
    const fixture = makeBundle({ recordEcall: true });
    const { loadExplorerProfile } = await import("../../lib/explorer/profile.ts");
    const { deriveCandidatesFromCase, evaluateLinkedBufferExpansion } = await import("../../lib/explorer/planner.ts");

    const bundleDir = path.dirname(fixture.manifestPath);
    const abi = JSON.parse(readFileSync(path.join(bundleDir, "edl_abi"), "utf8"));
    abi.ecalls[0].name = "renamed_boot_entry_alpha";
    abi.ecalls[1].name = "renamed_crypto_op_omega";
    abi.ecalls[1].parameters[0].name = "renamed_blob_ptr";
    abi.ecalls[1].parameters[1].name = "renamed_blob_bytes";
    abi.ecalls[1].parameters[0].attributes.size.name = "renamed_blob_bytes";
    abi.ecalls = [
      { ...abi.ecalls[1], ordinal: 0 },
      { ...abi.ecalls[0], ordinal: 1 },
    ];
    const abiStr = JSON.stringify(abi);
    writeFileSync(path.join(bundleDir, "edl_abi"), abiStr);

    const marshal = JSON.parse(readFileSync(path.join(bundleDir, "marshal_layout"), "utf8"));
    marshal.input.edl_abi_sha256 = digest(abiStr);
    marshal.ecalls[0].name = "renamed_boot_entry_alpha";
    marshal.ecalls[1].name = "renamed_crypto_op_omega";
    marshal.ecalls[1].params[0].name = "renamed_blob_ptr";
    marshal.ecalls[1].params[0].element_size = 60;
    marshal.ecalls[1].params[0].bound.source.name = "renamed_blob_bytes";
    marshal.ecalls[1].params[1].name = "renamed_blob_bytes";
    marshal.ecalls = [
      { ...marshal.ecalls[1], ordinal: 0 },
      { ...marshal.ecalls[0], ordinal: 1 },
    ];
    const marshalStr = JSON.stringify(marshal);
    writeFileSync(path.join(bundleDir, "marshal_layout"), marshalStr);

    const irFacts = JSON.parse(readFileSync(path.join(bundleDir, "ir_facts"), "utf8"));
    irFacts.facts[0].definitions[1].symbol = "renamed_internal_worker";
    irFacts.facts[0].guidance_sites[1].function = "renamed_internal_worker";
    irFacts.facts[0].guidance_sites[1].cases = [
      { value: "77", status: "constant", target: "c77" },
      { value: "88", status: "constant", target: "c88" },
      { value: "99", status: "constant", target: "c99" },
    ];
    const irFact0 = irFacts.facts[0];
    const irStr = JSON.stringify(irFacts);
    writeFileSync(path.join(bundleDir, "ir_facts"), irStr);

    const reach = JSON.parse(readFileSync(path.join(bundleDir, "reachability"), "utf8"));
    reach.input.edl_abi_sha256 = digest(abiStr);
    reach.input.ir_facts_tus[0].facts_sha256 = digest(canonicalJson(irFact0));
    reach.ecalls[0].name = "renamed_boot_entry_alpha";
    reach.ecalls[1].name = "renamed_crypto_op_omega";
    reach.ecalls[1].reachable_functions = ["renamed_internal_worker"];
    reach.ecalls = [
      { ...reach.ecalls[1], ordinal: 0 },
      { ...reach.ecalls[0], ordinal: 1 },
    ];
    const reachStr = JSON.stringify(reach);
    writeFileSync(path.join(bundleDir, "reachability"), reachStr);

    const manifest = JSON.parse(readFileSync(fixture.manifestPath, "utf8"));
    manifest.identity.edl_abi_sha256 = digest(abiStr);
    manifest.artifacts.edl_abi.sha256 = digest(abiStr);
    manifest.artifacts.marshal_layout.sha256 = digest(marshalStr);
    manifest.artifacts.ir_facts.sha256 = digest(irStr);
    manifest.artifacts.reachability.sha256 = digest(reachStr);
    manifest.selectors = [
      { ...manifest.selectors[1], ordinal: 0, name: "renamed_crypto_op_omega" },
      { ...manifest.selectors[0], ordinal: 1, name: "renamed_boot_entry_alpha" },
    ];
    writeFileSync(fixture.manifestPath, JSON.stringify(manifest));

    const profile = loadExplorerProfile(fixture.manifestPath);
    const capture = {
      bundleManifestSha256: profile.binding.bundleManifestSha256,
      marshalLayoutSha256: profile.binding.marshalLayoutSha256,
      runId: "99999999-9999-4999-8999-999999999999",
      events: [{
        generation: 1,
        callSeq: 0,
        selectorOrdinal: 0,
        selectorSeq: 0,
        transportStatus: 0,
        scalarInputs: [{ paramIndex: 1, widthBytes: 8 as const, signedness: "unsigned" as const, bits: "0x000000000000003c" }],
        bufferInputs: [{
          paramIndex: 0,
          direction: "in" as const,
          isString: false,
          elementSize: 60,
          byteLength: 60,
          fnv1a64: "0x0102030405060708",
          prefixHex: "00".repeat(60),
        }],
        retval: null,
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
    const plans = deriveCandidatesFromCase(profile, capture, { budget: 128, depth: 0 });
    expect(plans.some((p) => p.rule.selectorOrdinal === 0 && p.value.includes("0x0000004d"))).toBe(true);
    expect(plans.some((p) => p.rule.selectorOrdinal === 0 && p.value.includes("0x00000058"))).toBe(true);
    expect(plans.some((p) => p.rule.selectorOrdinal === 0 && p.value.includes("0x00000063"))).toBe(true);
    const expCheck = evaluateLinkedBufferExpansion(profile, 0, 1, 120n, capture.events[0]!);
    expect(expCheck.status).toBe("expanded_ok");
  });

  test("explicit prefix mutations encode a v2 spec and require a recorded application on the designated call", async () => {
    const fixture = makeBundle({ recordEcall: true });
    const { loadExplorerProfile } = await import("../../lib/explorer/profile.ts");
    const {
      captureHasExactlyOneMutation,
      encodeMutationSpec,
      MUTATION_SPEC_VERSION,
      MUTATION_SPEC_PREFIX_OP_BYTES,
    } = await import("../../lib/explorer/contract.ts");
    const profile = loadExplorerProfile(fixture.manifestPath);

    const rule = {
      selectorOrdinal: 1,
      selectorSeq: 0,
      paramIndex: 1,
      widthBytes: 8 as const,
      signedness: "unsigned" as const,
      expectedBits: "0x000000000000003c",
      replacementBits: "0x000000000000003d",
      execMode: 0,
      prefixMutations: [{
        selectorOrdinal: 0,
        selectorSeq: 0,
        paramIndex: 2,
        byteOffset: 4,
        widthBytes: 4 as const,
        expectedBits: "0x00000003",
        replacementBits: "0x00000001",
        source: { producerCallSeq: 0, outputParamIndex: 0 },
      }],
    };

    const spec = encodeMutationSpec(profile.binding, rule);
    const view = new DataView(spec.buffer, spec.byteOffset, spec.byteLength);
    expect(view.getUint16(8, true)).toBe(MUTATION_SPEC_VERSION);
    expect(view.getUint32(88, true)).toBe(24 + 32 + MUTATION_SPEC_PREFIX_OP_BYTES);
    expect(view.getUint16(88 + 20, true)).toBe(2); // op_count = target + prefix
    const pre = 88 + 24 + 32;
    expect(view.getUint16(pre, true)).toBe(4);      // ATFIELD_MUTATION_OP_PREFIX_MUTATE
    expect(view.getUint32(pre + 4, true)).toBe(MUTATION_SPEC_PREFIX_OP_BYTES);
    expect(view.getUint32(pre + 8, true)).toBe(0);  // prefix call selector ordinal
    expect(Number(view.getBigUint64(pre + 12, true))).toBe(0); // occurrence
    expect(view.getUint32(pre + 20, true)).toBe(2); // param index
    expect(view.getUint32(pre + 28, true)).toBe(4); // byte offset
    expect(view.getBigUint64(pre + 32, true)).toBe(3n); // expected bits
    expect(view.getBigUint64(pre + 40, true)).toBe(1n); // replacement bits
    expect(spec.length).toBe(88 + 24 + 32 + MUTATION_SPEC_PREFIX_OP_BYTES);

    const mkEvent = (callSeq: number, selectorOrdinal: number, mutation: object | null, scalarBits?: string) => ({
      generation: 1,
      callSeq,
      selectorOrdinal,
      selectorSeq: 0,
      transportStatus: 0,
      scalarInputs: scalarBits === undefined ? [] : [{ paramIndex: 1, widthBytes: 8 as const, signedness: "unsigned" as const, bits: scalarBits }],
      retval: null,
      scalarOutputs: [],
      mutation,
    });
    const prefixRecord = {
      paramIndex: 2, widthBytes: 4, byteOffset: 4, signedness: "unsigned",
      expectedBits: "0x00000003", observedBits: "0x00000003",
      replacementBits: "0x00000001", applied: true, reason: "applied",
    };
    const targetRecord = {
      paramIndex: 1, widthBytes: 8, signedness: "unsigned",
      expectedBits: "0x000000000000003c", observedBits: "0x000000000000003c",
      replacementBits: "0x000000000000003d", applied: true, reason: "applied",
    };
    const capture = {
      bundleManifestSha256: profile.binding.bundleManifestSha256,
      marshalLayoutSha256: profile.binding.marshalLayoutSha256,
      runId: "99999999-9999-4999-8999-999999999999",
      events: [
        mkEvent(0, 0, prefixRecord),
        mkEvent(1, 1, targetRecord, "0x000000000000003d"),
      ],
      end: {
        processReturnCode: 0,
        termination: "exited" as const,
        timedOut: false,
        complete: true,
        ecallCount: 2,
        targetMatchCount: 1,
        mutationAppliedCount: 2,
        incompleteReasons: [],
      },
    };
    expect(captureHasExactlyOneMutation(capture, rule)).toBe(true);

    // A planned prefix op that was never applied fails the plan
    const unapplied = {
      ...capture,
      events: [mkEvent(0, 0, null), capture.events[1]!],
      end: { ...capture.end, mutationAppliedCount: 1 },
    };
    expect(captureHasExactlyOneMutation(unapplied, rule)).toBe(false);

    // An extra unplanned mutation record fails the plan
    const extra = {
      ...capture,
      events: [capture.events[0]!, capture.events[1]!,
        mkEvent(2, 1, { ...targetRecord, expectedBits: "0x000000000000003d", observedBits: "0x000000000000003d", replacementBits: "0x000000000000003e" }, "0x000000000000003e")],
      end: { ...capture.end, ecallCount: 3, mutationAppliedCount: 3 },
    };
    expect(captureHasExactlyOneMutation(extra, rule)).toBe(false);

    // Crash-terminated runs are never clean business rejections
    const crashed = {
      ...capture,
      end: {
        ...capture.end,
        complete: false,
        termination: "signaled" as const,
        processReturnCode: -6,
        incompleteReasons: ["host process terminated by signal SIGABRT"],
      },
    };
    expect(captureHasExactlyOneMutation(crashed, rule, { allowBusinessRejectionExit: true })).toBe(false);

    // Clean nonzero exits retain business-rejection eligibility
    const rejected = {
      ...capture,
      end: {
        ...capture.end,
        complete: false,
        termination: "exited" as const,
        processReturnCode: 1,
        incompleteReasons: ["host process exit code was 1"],
      },
    };
    expect(captureHasExactlyOneMutation(rejected, rule, { allowBusinessRejectionExit: true })).toBe(true);
  });

  test("budget-blocked linked-expansion candidates land in the unexplored frontier", async () => {
    const fixture = makeBundle({ recordEcall: true });
    const { loadExplorerProfile } = await import("../../lib/explorer/profile.ts");
    const { deriveCandidatesFromCase } = await import("../../lib/explorer/planner.ts");
    const profile = loadExplorerProfile(fixture.manifestPath);
    const capture = {
      bundleManifestSha256: profile.binding.bundleManifestSha256,
      marshalLayoutSha256: profile.binding.marshalLayoutSha256,
      runId: "99999999-9999-4999-8999-999999999999",
      events: [{
        generation: 1,
        callSeq: 0,
        selectorOrdinal: 0,
        selectorSeq: 0,
        transportStatus: 0,
        scalarInputs: [{ paramIndex: 1, widthBytes: 8 as const, signedness: "unsigned" as const, bits: "0x000000000000003c" }],
        bufferInputs: [{
          paramIndex: 0,
          direction: "in" as const,
          isString: false,
          elementSize: 60,
          byteLength: 60,
          fnv1a64: "0x0102030405060708",
          prefixHex: "00".repeat(60),
        }],
        retval: null,
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
    // re-point event at the record ecall (ordinal 1)
    capture.events[0]!.selectorOrdinal = 1;

    const frontier: unknown[] = [];
    deriveCandidatesFromCase(profile, capture, {
      budget: 256,
      depth: 0,
      frontier,
      expansionBufferBudgetBytes: 30n,
    });
    expect(frontier.length).toBeGreaterThan(0);
    for (const entry of frontier) {
      const e = entry as { reason: string; selectorOrdinal: number; candidateValue: string; affectedBuffers: { newBytes: string }[] };
      expect(e.reason).toBe("expansion_budget_exceeded");
      expect(e.selectorOrdinal).toBe(1);
      expect(e.affectedBuffers.every((b) => BigInt(b.newBytes) > 30n)).toBe(true);
      expect(e.affectedBuffers.length).toBeGreaterThan(0);
    }

    const open: unknown[] = [];
    deriveCandidatesFromCase(profile, capture, { budget: 256, depth: 0, frontier: open });
    expect(open.length).toBe(0);
  });
});
