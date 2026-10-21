import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  canonicalJson,
  loadProfileBundle,
  sha256,
} from "../../lib/bundle/profile-bundle.ts";
import {
  CANONICAL_TRACE_SCHEMA,
  parseCanonicalTrace,
  readCanonicalTrace,
} from "../../lib/workset/trace.ts";
import { buildWorkset } from "../../lib/workset/build.ts";
import { main as worksetMain, makeWorksetFromFiles } from "../../cli/atfield-workset.ts";

const tempRoots: string[] = [];
const PAGE = 4096;
const EFFECTS_A = [{ rva: "0x4000", a: true, d: false }];
const EFFECTS_B = [{ rva: "0x4000", a: true, d: true }];

function digest(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function writeFixture(fields?: unknown[], selectors?: unknown[]) {
  const root = mkdtempSync(path.join(tmpdir(), "atfield-workset-bun-"));
  tempRoots.push(root);
  const artifactDir = path.join(root, "artifacts");
  mkdirSync(artifactDir);
  const chosenFields = fields ?? [
    {
      id: "field-a",
      name: "first",
      static_pages: ["0x5000"],
      resource_pages: [{ rva: "0x6000", effects: ["R", "W"] }],
      layout_extents: [
        { kind: "function", start_rva: "0x1000", end_rva: "0x1800", exact: true },
        { kind: "object", start_rva: "0x4000", end_rva: "0x4100", exact: false },
      ],
    },
    {
      id: "field-b",
      name: "second",
      static_pages: [{ rva: "0x1000", effects: ["X"] }],
    },
  ];
  const fieldIds = (chosenFields as Array<{ id: string }>).map((f) => f.id);
  const edlAbiObj = {
    schema: "atfield-edl-abi-v1",
    tool: { name: "sgx_edger8r", version: "fixture" },
    input: { root: "enclave.edl", imports: [] },
    ecalls: [
      {
        ordinal: 0,
        name: "lookup",
        visibility: "public",
        switchless: false,
        parameters: [],
        return_type: { kind: "builtin", name: "int" },
      },
      {
        ordinal: 1,
        name: "initialize",
        visibility: "public",
        switchless: false,
        parameters: [],
        return_type: { kind: "builtin", name: "void" },
      },
    ],
    ocalls: [],
    types: [],
  };
  const fieldsArtifactObj = {
    schema: "atfield-fields-v1",
    fields: chosenFields,
  };
  const edlAbiText = JSON.stringify(edlAbiObj) + "\n";
  const fieldsText = JSON.stringify(fieldsArtifactObj) + "\n";
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
        name: "lookup",
        visibility: "public",
        switchless: false,
        replay_supported: true,
        ms_size: 4,
        retval: {
          name: "retval",
          c_type: "int",
          ms_offset: 0,
          ms_size: 4,
          type_kind: "builtin",
          type_category: "integer",
          signedness: "signed",
          pointer_depth: 0,
        },
        params: [],
      },
      {
        ordinal: 1,
        name: "initialize",
        visibility: "public",
        switchless: false,
        replay_supported: true,
        ms_size: 0,
        retval: null,
        params: [],
      },
    ],
  };
  const compileVariant = { compiler: "clang", flags: ["-O2"] };
  const irFact = {
    schema: "atfield-ir-facts-v1",
    translation_unit: "src/enclave.c",
    module_id: "src/enclave.c",
    backend_ir_sha256: "33".repeat(32),
    object_sha256: "44".repeat(32),
    compile_variant: compileVariant,
    source: { input_file: "src/enclave.c", ir_filename: "obj/enclave.after-boundary.ll" },
    callgraph_complete: true,
    guidance_complete: true,
    diagnostics: [],
    definitions: [
      { name: "lookup", linkage: "external", defined: true, address_taken: false },
      { name: "initialize", linkage: "external", defined: true, address_taken: false },
    ],
    direct_calls: [],
    unknown_indirect_calls: [],
    unknown_external_calls: [],
    guidance_sites: [],
  };
  const irFactsObj = { schema: "atfield-ir-facts-aggregate-v1", facts: [irFact] };
  const reachInput = {
    edl_abi_sha256: digest(edlAbiText),
    live_fields_sha256: digest(fieldsText),
    ir_facts_tus: [{
      translation_unit: irFact.translation_unit,
      module_id: irFact.module_id,
      backend_ir_sha256: irFact.backend_ir_sha256,
      object_sha256: irFact.object_sha256,
      variant_sha256: digest(canonicalJson(compileVariant)),
      facts_sha256: digest(canonicalJson(irFact)),
    }],
  };
  const reachEcalls = [
    {
      ordinal: 0,
      name: "lookup",
      visibility: "public",
      switchless: false,
      status: "verified",
      reachable_fields: fieldIds,
      reachable_functions: ["lookup"],
      unknown_indirect: false,
      unknown_external: false,
      function_closure_complete: true,
    },
    {
      ordinal: 1,
      name: "initialize",
      visibility: "public",
      switchless: false,
      status: "verified",
      reachable_fields: [],
      reachable_functions: ["initialize"],
      unknown_indirect: false,
      unknown_external: false,
      function_closure_complete: true,
    },
  ];
  const reachabilityObj = {
    schema: "atfield-reachability-v1",
    input: reachInput,
    live_field_ids: fieldIds,
    ecalls: reachEcalls,
  };
  const chosenSelectors = selectors ?? [
    {
      ordinal: 0,
      name: "lookup",
      visibility: "public",
      switchless: false,
      entry_rva: "0x100",
      reachable_fields: fieldIds,
      reachability: { kind: "callgraph", complete: true },
    },
    {
      ordinal: 1,
      name: "initialize",
      visibility: "public",
      switchless: false,
      entry_rva: "0x200",
      reachable_fields: [],
      reachability: { kind: "callgraph", complete: true },
    },
  ];
  const layout = {
    page_size: PAGE,
    capacity_q: 8192,
    ordinary_load_end: "0x1800",
    pretouch_start: "0x2000",
    enclave_size: 65536,
    ssa_frame_pages: 1,
    regions: [
      { kind: "PT_LOAD", start_rva: "0x0", end_rva: "0x2000", permissions: ["R", "X"] },
      { kind: "REG", start_rva: "0x4000", end_rva: "0x7000", permissions: ["R", "W"] },
    ],
    excluded_regions: [
      { kind: "TCS", start_rva: "0x3000", end_rva: "0x4000" },
    ],
  };
  const profileData = "unsigned-profile-bytes";
  const signedProfileData = "signed-profile-bytes";
  const hostData = "host-runner-bytes";
  const measurementManifestObj = {
    schema: "atfield-measurement-profile-v1",
    identity: {
      profile_elf_sha256: digest(profileData),
      signed_profile_elf_sha256: digest(signedProfileData),
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
      profile_elf: { path: "artifacts/profile_elf.bin", sha256: digest(profileData) },
      signed_profile_elf: { path: "artifacts/signed_profile_elf.bin", sha256: digest(signedProfileData) },
    },
    collector: {
      abi: "atfield-4gate-native-v1",
      page_size: PAGE,
      tcs_ranges: [{ start_rva: "0x3000", end_rva: "0x4000" }],
      ssa_ranges: [{ start_rva: "0x3000", end_rva: "0x4000" }],
      gate_helper_range: { start_rva: "0x2000", end_rva: "0x3000" },
      guard_manager_rva: "0x4000",
      layout_spec: "tcs=0x3000;ssa=0x3000;gm=0x4000;pretouch=0x2000:0x4000;gate=0x2000:0x3000",
      active_field_rva: null,
      pretouch: { start_rva: "0x2000", end_rva: "0x4000", capacity_q: 8192 },
      stack_ranges: [],
      excluded_regions: [],
    },
  };
  const bytes: Record<string, string> = {
    profile_elf: profileData,
    signed_profile_elf: signedProfileData,
    host: hostData,
    edl_abi: edlAbiText,
    fields: fieldsText,
    measurement_manifest: JSON.stringify(measurementManifestObj) + "\n",
    marshal_layout: JSON.stringify(marshalLayoutObj) + "\n",
    ir_facts: JSON.stringify(irFactsObj) + "\n",
    reachability: JSON.stringify(reachabilityObj) + "\n",
  };
  const jsonKeys = new Set(["edl_abi", "fields", "measurement_manifest", "marshal_layout", "ir_facts", "reachability"]);
  const artifactEntries: Record<string, { path: string; sha256: string }> = {};
  for (const [name, data] of Object.entries(bytes)) {
    const relative = "artifacts/" + name + (jsonKeys.has(name) ? ".json" : ".bin");
    writeFileSync(path.join(root, relative), data);
    artifactEntries[name] = { path: relative, sha256: digest(data) };
  }
  const identity = {
    profile_elf_sha256: artifactEntries.profile_elf!.sha256,
    signed_profile_elf_sha256: artifactEntries.signed_profile_elf!.sha256,
    edl_abi_sha256: artifactEntries.edl_abi!.sha256,
    fields_sha256: artifactEntries.fields!.sha256,
  };
  const epochPayload = {
    profile_elf_sha256: identity.profile_elf_sha256,
    signed_profile_elf_sha256: identity.signed_profile_elf_sha256,
    page_size: layout.page_size,
    capacity_q: layout.capacity_q,
    ordinary_load_end: layout.ordinary_load_end,
    pretouch_start: layout.pretouch_start,
    enclave_size: layout.enclave_size,
    ssa_frame_pages: layout.ssa_frame_pages,
    regions: layout.regions,
    excluded_regions: layout.excluded_regions,
  };
  const manifest = {
    schema: "atfield-profile-bundle-v1",
    identity,
    layout: {
      ...layout,
      epoch: sha256(new TextEncoder().encode(canonicalJson(epochPayload))),
    },
    artifacts: artifactEntries,
    fields: chosenFields,
    selectors: chosenSelectors,
    page_universe: [
      { rva: "0x1000", max_permissions: ["R", "X"], region_kind: "code" },
      { rva: "0x4000", max_permissions: ["R", "W"], region_kind: "heap" },
      { rva: "0x5000", max_permissions: ["R"], region_kind: "rodata" },
      { rva: "0x6000", max_permissions: ["R", "W"], region_kind: "stack" },
    ],
  };
  const manifestPath = path.join(root, "profile-bundle.json");
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  return { root, manifestPath, bundle: loadProfileBundle(manifestPath), manifest };
}

function fieldRecord(fieldId: string, pages: Array<{ rva: string; a: boolean; d: boolean }>) {
  const empty = () => ({ complete: true, page_size: PAGE, page_effects: [] });
  return {
    field_id: fieldId,
    phases: {
      S0_BRIDGE: empty(),
      S1_ENTER: empty(),
      S2_PRETOUCH: empty(),
      S3_BODY: { complete: true, page_size: PAGE, page_effects: pages },
    },
  };
}

function traceText(
  bundle: ReturnType<typeof loadProfileBundle>,
  fieldRuns: Array<{ callSeq: number; selectorSeq: number; fields: Array<{ id: string; pages: Array<{ rva: string; a: boolean; d: boolean }> }> }>,
  endOverrides: Record<string, unknown> = {},
): string {
  const runId = "run-1";
  const start = {
    schema: CANONICAL_TRACE_SCHEMA,
    record_type: "run_start",
    run_id: runId,
    layout_epoch: bundle.layoutEpoch,
    instance_generation: null,
    sample: "generic-sample",
    mode: "profile",
    start_time: "2026-10-20T12:00:00Z",
    selected_enclave_sha256: bundle.identity.signedProfileElfSha256,
    bundle_manifest_sha256: bundle.manifestSha256,
    seed_id: "seed-1",
    argv: ["--input", "value"],
  };
  const ecalls = fieldRuns.map((run) => ({
    schema: CANONICAL_TRACE_SCHEMA,
    record_type: "ecall",
    run_id: runId,
    bundle_manifest_sha256: bundle.manifestSha256,
    layout_epoch: bundle.layoutEpoch,
    instance_generation: 1,
    call_seq: run.callSeq,
    selector_ordinal: 0,
    selector_seq: run.selectorSeq,
    tag: "seed",
    elapsed_ns: 10,
    sgx_status: 0,
    abi_return_type: "i32",
    abi_return_value: 0,
    out_status_i32: 0,
    measurement_valid: true,
    measurement_invalid_reasons: [],
    fields: run.fields.map((field) => fieldRecord(field.id, field.pages)),
  }));
  const end = {
    schema: CANONICAL_TRACE_SCHEMA,
    record_type: "run_end",
    run_id: runId,
    bundle_manifest_sha256: bundle.manifestSha256,
    layout_epoch: bundle.layoutEpoch,
    instance_generation: 1,
    process_return_code: 0,
    timeout: false,
    record_count: ecalls.length,
    completion: "complete",
    incomplete_reasons: [],
    ...endOverrides,
  };
  return [start, ...ecalls, end].map((record) => JSON.stringify(record)).join("\n") + "\n";
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test("rejects a Profile bundle whose artifact bytes do not match their digest", () => {
  const fixture = writeFixture();
  writeFileSync(path.join(fixture.root, "artifacts", "host.bin"), "different host bytes");
  expect(() => loadProfileBundle(fixture.manifestPath)).toThrow(/artifact digest mismatch for host/);
});

test("rejects an unsupported bundle schema and a mismatched canonical layout epoch", () => {
  const fixture = writeFixture();
  const wrongSchema = { ...fixture.manifest, schema: "atfield-profile-bundle-v0" };
  writeFileSync(fixture.manifestPath, JSON.stringify(wrongSchema));
  expect(() => loadProfileBundle(fixture.manifestPath)).toThrow(/expected atfield-profile-bundle-v1/);

  const wrongEpoch = { ...fixture.manifest, layout: { ...fixture.manifest.layout, epoch: "0".repeat(64) } };
  writeFileSync(fixture.manifestPath, JSON.stringify(wrongEpoch));
  expect(() => loadProfileBundle(fixture.manifestPath)).toThrow(/canonical effective-layout digest/);

  const extraLayoutKey = {
    ...fixture.manifest,
    layout: { ...fixture.manifest.layout, unbound_hint: "not covered by the epoch" },
  };
  writeFileSync(fixture.manifestPath, JSON.stringify(extraLayoutKey));
  expect(() => loadProfileBundle(fixture.manifestPath)).toThrow(/layout has unsupported key unbound_hint/);
});

test("rejects bundle identity digests that differ from the hashed artifacts", () => {
  const fixture = writeFixture();
  const identity = { ...fixture.manifest.identity, profile_elf_sha256: "0".repeat(64) };
  const layout = fixture.manifest.layout;
  const epochPayload = {
    profile_elf_sha256: identity.profile_elf_sha256,
    signed_profile_elf_sha256: identity.signed_profile_elf_sha256,
    page_size: layout.page_size,
    capacity_q: layout.capacity_q,
    ordinary_load_end: layout.ordinary_load_end,
    pretouch_start: layout.pretouch_start,
    enclave_size: layout.enclave_size,
    ssa_frame_pages: layout.ssa_frame_pages,
    regions: layout.regions,
    excluded_regions: layout.excluded_regions,
  };
  const wrongIdentity = {
    ...fixture.manifest,
    identity,
    layout: { ...layout, epoch: sha256(new TextEncoder().encode(canonicalJson(epochPayload))) },
  };
  writeFileSync(fixture.manifestPath, JSON.stringify(wrongIdentity));
  expect(() => loadProfileBundle(fixture.manifestPath))
    .toThrow(/identity digest does not match artifacts.profile_elf/);
});

test("rejects missing run_end, incomplete gates, invalid measurements, and sequence gaps", () => {
  const { bundle } = writeFixture();
  const valid = traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [{ id: "field-a", pages: EFFECTS_A }],
  }]);
  expect(() => parseCanonicalTrace(valid.split("\n").slice(0, -2).join("\n"), "missing-end", bundle))
    .toThrow(/last record must be run_end/);

  const aliasLines = valid.trimEnd().split("\n");
  const aliasEcall = JSON.parse(aliasLines[1]!);
  aliasEcall.ecall_index = 0;
  aliasLines[1] = JSON.stringify(aliasEcall);
  expect(() => parseCanonicalTrace(aliasLines.join("\n") + "\n", "legacy-alias", bundle))
    .toThrow(/unsupported key ecall_index/);

  const incomplete = JSON.parse(valid.split("\n")[1]!);
  incomplete.fields[0].phases.S2_PRETOUCH.complete = false;
  const lines = valid.trimEnd().split("\n");
  lines[1] = JSON.stringify(incomplete);
  expect(() => parseCanonicalTrace(lines.join("\n") + "\n", "incomplete-gate", bundle))
    .toThrow(/page set is not complete/);

  const invalidMeasurement = JSON.parse(valid.split("\n")[1]!);
  invalidMeasurement.measurement_valid = false;
  lines[1] = JSON.stringify(invalidMeasurement);
  expect(() => parseCanonicalTrace(lines.join("\n") + "\n", "invalid", bundle))
    .toThrow(/measurement is invalid/);

  const incompleteRun = JSON.parse(valid.split("\n").at(-2)!);
  incompleteRun.completion = "incomplete";
  incompleteRun.incomplete_reasons = ["required gate missing"];
  const incompleteLines = valid.trimEnd().split("\n");
  incompleteLines[incompleteLines.length - 1] = JSON.stringify(incompleteRun);
  expect(() => parseCanonicalTrace(incompleteLines.join("\n") + "\n", "incomplete-run", bundle))
    .toThrow(/completion is not complete/);

  const nonzeroEnd = JSON.parse(valid.trimEnd().split("\n").at(-1)!);
  nonzeroEnd.process_return_code = 1;
  const nonzeroLines = valid.trimEnd().split("\n");
  nonzeroLines[nonzeroLines.length - 1] = JSON.stringify(nonzeroEnd);
  expect(() => parseCanonicalTrace(nonzeroLines.join("\n") + "\n", "nonzero-exit", bundle))
    .toThrow(/process_return_code is nonzero/);

  const aexLines = valid.trimEnd().split("\n");
  const aexEcall = JSON.parse(aexLines[1]!);
  aexEcall.aex = { count: 1 };
  aexLines[1] = JSON.stringify(aexEcall);
  expect(() => parseCanonicalTrace(aexLines.join("\n") + "\n", "aex-incomplete", bundle))
    .toThrow(/nonzero AEX count/);

  const nonzeroStart = traceText(bundle, [{
    callSeq: 1,
    selectorSeq: 0,
    fields: [{ id: "field-a", pages: EFFECTS_A }],
  }]);
  expect(() => parseCanonicalTrace(nonzeroStart, "nonzero-call-seq-start", bundle))
    .toThrow(/call_seq must start at zero/);

  const gap = traceText(bundle, [
    { callSeq: 0, selectorSeq: 0, fields: [] },
    { callSeq: 2, selectorSeq: 1, fields: [] },
  ]);
  expect(() => parseCanonicalTrace(gap, "sequence-gap", bundle)).toThrow(/call_seq has a gap/);

  const repeatedSelector = traceText(bundle, [
    { callSeq: 0, selectorSeq: 0, fields: [] },
    { callSeq: 1, selectorSeq: 0, fields: [] },
  ]);
  expect(() => parseCanonicalTrace(repeatedSelector, "selector-sequence-repeat", bundle))
    .toThrow(/selector_seq must increment by one/);

  const skippedSelector = traceText(bundle, [
    { callSeq: 0, selectorSeq: 0, fields: [] },
    { callSeq: 1, selectorSeq: 2, fields: [] },
  ]);
  expect(() => parseCanonicalTrace(skippedSelector, "selector-sequence-gap", bundle))
    .toThrow(/selector_seq must increment by one/);

  const generationResetLines = traceText(bundle, [
    { callSeq: 0, selectorSeq: 0, fields: [] },
    { callSeq: 1, selectorSeq: 0, fields: [] },
  ]).trimEnd().split("\n");
  const secondGenerationEcall = JSON.parse(generationResetLines[2]!);
  secondGenerationEcall.instance_generation = 2;
  generationResetLines[2] = JSON.stringify(secondGenerationEcall);
  const finalGenerationEnd = JSON.parse(generationResetLines.at(-1)!);
  finalGenerationEnd.instance_generation = 2;
  generationResetLines[generationResetLines.length - 1] = JSON.stringify(finalGenerationEnd);
  expect(() => parseCanonicalTrace(generationResetLines.join("\n") + "\n", "selector-generation-reset", bundle))
    .not.toThrow();
});

test("joins a native-shaped collector prefix to the runner-appended run_end", () => {
  const { bundle } = writeFixture();
  const complete = traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }], { instance_generation: 1 });
  const lines = complete.trimEnd().split("\n");
  const nativeStart = JSON.parse(lines[0]!);
  const nativeEcall = JSON.parse(lines[1]!);
  nativeEcall.sgx_status = 7;
  nativeEcall.abi_return_value = -12;
  nativeEcall.out_status_i32 = 3;
  nativeEcall.business_result = { status: "error", value: -12, source: "fixture-adapter" };
  lines[1] = JSON.stringify(nativeEcall);
  const nativePrefix = lines.slice(0, -1).join("\n") + "\n";
  const runnerEnd = JSON.parse(lines.at(-1)!);
  expect(runnerEnd).toMatchObject({
    record_type: "run_end",
    run_id: nativeStart.run_id,
    instance_generation: 1,
    process_return_code: 0,
    timeout: false,
    record_count: 1,
    completion: "complete",
  });
  expect(() => parseCanonicalTrace(nativePrefix, "collector-prefix", bundle))
    .toThrow(/last record must be run_end/);

  const trace = parseCanonicalTrace(
    nativePrefix + JSON.stringify(runnerEnd) + "\n",
    "runner-finalized-native-trace",
    bundle,
  );
  expect(trace.observedFieldIds).toEqual(["field-a", "field-b"]);
  const workset = buildWorkset(bundle, [trace]);
  expect(workset.selectors[0]!.pages.find((page) => page.page_rva === "0x4000")?.effects)
    .toEqual(["R", "W"]);

  const absentBusinessResult = JSON.parse(lines[1]!);
  delete absentBusinessResult.business_result;
  lines[1] = JSON.stringify(absentBusinessResult);
  expect(() => parseCanonicalTrace(
    lines.slice(0, -1).join("\n") + "\n" + JSON.stringify(runnerEnd) + "\n",
    "optional-business-result",
    bundle,
  )).not.toThrow();
});

test("rejects canonical trace files with a UTF-8 BOM", () => {
  const fixture = writeFixture();
  const tracePath = path.join(fixture.root, "bom.jsonl");
  writeFileSync(tracePath, Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d, 0x0a]));
  expect(() => readCanonicalTrace(tracePath, fixture.bundle)).toThrow(/must not start with a UTF-8 BOM/);
});

test("rejects a bundle Field with no complete valid S3 observation", () => {
  const { bundle } = writeFixture();
  const trace = parseCanonicalTrace(traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [{ id: "field-a", pages: EFFECTS_A }],
  }]), "missing-field-observation", bundle);
  expect(() => buildWorkset(bundle, [trace]))
    .toThrow(/live Field field-b has no complete valid S3 observation/);
});

test("keeps observed, layout-closure, static-may-reach, and resource-bound evidence separate", () => {
  const { bundle } = writeFixture();
  const lines = traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]).trimEnd().split("\n");
  const ecall = JSON.parse(lines[1]!);
  ecall.fields[0].phases.S0_BRIDGE.page_effects = [{ rva: "0x5000", a: true, d: false }];
  ecall.fields[0].phases.S1_ENTER.page_effects = [{ rva: "0x6000", a: true, d: true }];
  ecall.fields[0].phases.S2_PRETOUCH.page_effects = [{ rva: "0x1000", a: true, d: false }];
  lines[1] = JSON.stringify(ecall);
  const trace = parseCanonicalTrace(lines.join("\n") + "\n", "evidence", bundle);
  const result = buildWorkset(bundle, [trace]);
  expect(result.schema).toBe("atfield-workset-v2");
  expect(result.bundle_manifest_sha256).toBe(bundle.manifestSha256);
  expect(result.layout_epoch).toBe(bundle.layoutEpoch);
  expect(result.source_traces).toEqual([{ run_id: trace.runId, sha256: trace.traceSha256 }]);

  const first = result.fields.find((field) => field.id === "field-a")!;
  const byRva = new Map(first.pages.map((page) => [page.page_rva, page]));
  expect(byRva.get("0x1000")?.evidence["layout-closure"]).toEqual(["X", "R"]);
  expect(byRva.get("0x5000")?.evidence["static-may-reach"]).toEqual(["R"]);
  expect(byRva.get("0x6000")?.evidence["resource-bound"]).toEqual(["R", "W"]);
  expect(byRva.get("0x4000")?.evidence.observed).toEqual(["R", "W"]);
  const obs4000A = trace.observations.find((o) => o.fieldId === "field-a" && o.pageRva === 0x4000n);
  expect(obs4000A?.accessed).toBe(true);
  expect(obs4000A?.dirty).toBe(false);
  expect(obs4000A?.effects).toEqual(["R", "W"]);
  expect(byRva.get("0x4000")?.evidence["layout-closure"]).toEqual([]);
});

test("preserves per-Field ownership and computes selector page unions", () => {
  const { bundle } = writeFixture();
  const trace = parseCanonicalTrace(traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]), "selector-union", bundle);
  const result = buildWorkset(bundle, [trace]);
  const selector = result.selectors.find((entry) => entry.name === "lookup")!;
  const shared = selector.pages.find((page) => page.page_rva === "0x4000")!;
  expect(shared.fields).toEqual(["field-a", "field-b"]);
  expect(shared.effects).toEqual(["R", "W"]);
  expect(shared.evidence.observed).toEqual(["R", "W"]);
  expect(result.selectors.find((entry) => entry.name === "initialize")?.pages).toEqual([]);

  const fieldPages = result.fields.map((field) => new Map(field.pages.map((page) => [page.page_rva, page])));
  expect(fieldPages[0]!.has("0x4000")).toBe(true);
  expect(fieldPages[1]!.has("0x4000")).toBe(true);
});

test("rejects a mixed trace batch without writing a partial workset", () => {
  const fixture = writeFixture();
  const validPath = path.join(fixture.root, "valid.jsonl");
  const invalidPath = path.join(fixture.root, "incomplete.jsonl");
  const outputPath = path.join(fixture.root, "batch-workset.json");
  const valid = traceText(fixture.bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]);
  const invalidLines = valid.trimEnd().split("\n");
  const invalidEcall = JSON.parse(invalidLines[1]!);
  invalidEcall.fields[0].phases.S2_PRETOUCH.complete = false;
  invalidLines[1] = JSON.stringify(invalidEcall);
  writeFileSync(validPath, valid);
  writeFileSync(invalidPath, invalidLines.join("\n") + "\n");

  const originalError = console.error;
  console.error = () => {};
  try {
    expect(worksetMain([
      "--bundle", fixture.manifestPath,
      "--trace", validPath,
      "--trace", invalidPath,
      "--out", outputPath,
    ])).toBe(2);
  } finally {
    console.error = originalError;
  }
  expect(existsSync(outputPath)).toBe(false);
});

test("refuses output paths that would replace the Profile bundle or a source trace", () => {
  const fixture = writeFixture();
  const tracePath = path.join(fixture.root, "seed.jsonl");
  const hostPath = path.join(fixture.root, fixture.manifest.artifacts.host.path);
  writeFileSync(tracePath, traceText(fixture.bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]));
  expect(() => makeWorksetFromFiles(fixture.manifestPath, [tracePath], fixture.manifestPath))
    .toThrow(/must not replace the Profile bundle manifest/);
  expect(() => makeWorksetFromFiles(fixture.manifestPath, [tracePath], hostPath))
    .toThrow(/must not replace the Profile bundle manifest/);
  expect(() => makeWorksetFromFiles(fixture.manifestPath, [tracePath], tracePath))
    .toThrow(/must not replace the Profile bundle manifest/);
});

test("CLI consumes canonical JSONL and writes an atfield-workset-v2 file", () => {
  const fixture = writeFixture();
  const tracePath = path.join(fixture.root, "seed.jsonl");
  const outputPath = path.join(fixture.root, "workset.json");
  writeFileSync(tracePath, traceText(fixture.bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]));
  expect(worksetMain([
    "--bundle", fixture.manifestPath,
    "--trace", tracePath,
    "--out", outputPath,
  ])).toBe(0);
  const output = JSON.parse(readFileSync(outputPath, "utf8"));
  expect(output.schema).toBe("atfield-workset-v2");
  expect(output.source_traces).toHaveLength(1);
  expect(output).not.toHaveProperty("seed_id");
  expect(output).not.toHaveProperty("argv");
  expect(output.fields.find((field: { id: string }) => field.id === "field-a").pages)
    .toContainEqual(expect.objectContaining({ page_rva: "0x4000" }));
});

test("classifies protocol gate-spin AEXs within verified boundaries and rejects body or unexpected AEXs", () => {
  const { bundle } = writeFixture();
  const baseLines = traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: EFFECTS_A },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]).trimEnd().split("\n");

  const validClassified = JSON.parse(baseLines[1]!);
  validClassified.aex = {
    count: 6,
    protocol_gate_count: 6,
    unexpected_count: 0,
    by_gate: { GATE_A: 2, GATE_B: 2, GATE_C: 2 },
    by_stage: {
      S0_BRIDGE: { protocol_gate: 2, unexpected: 0 },
      S1_ENTER: { protocol_gate: 2, unexpected: 0 },
      S2_PRETOUCH: { protocol_gate: 2, unexpected: 0 },
      S3_BODY: { protocol_gate: 0, unexpected: 0 },
      POST_FIELD: { protocol_gate: 0, unexpected: 0 },
    },
    fault_events: [],
  };
  const validLines = [...baseLines];
  validLines[1] = JSON.stringify(validClassified);
  const parsed = parseCanonicalTrace(validLines.join("\n") + "\n", "classified-aex-ok", bundle);
  expect(parsed.observedFieldIds).toEqual(["field-a", "field-b"]);

  const bodyAex = JSON.parse(validLines[1]!);
  bodyAex.aex.count = 7;
  bodyAex.aex.unexpected_count = 1;
  bodyAex.aex.by_stage.S3_BODY.unexpected = 1;
  const bodyLines = [...baseLines];
  bodyLines[1] = JSON.stringify(bodyAex);
  expect(() => parseCanonicalTrace(bodyLines.join("\n") + "\n", "body-aex", bundle))
    .toThrow(/nonzero AEX count/);

  const missingGateC = JSON.parse(validLines[1]!);
  missingGateC.aex.count = 4;
  missingGateC.aex.protocol_gate_count = 4;
  missingGateC.aex.by_gate.GATE_C = 0;
  missingGateC.aex.by_stage.S2_PRETOUCH.protocol_gate = 0;
  const missingGateCLines = [...baseLines];
  missingGateCLines[1] = JSON.stringify(missingGateC);
  expect(() => parseCanonicalTrace(missingGateCLines.join("\n") + "\n", "missing-gate-c", bundle))
    .toThrow(/missing required GATE_A\/GATE_B\/GATE_C shootdowns/);
});

test("merges repeated Field invocations and never masks an incomplete repeated invocation", () => {
  const { bundle } = writeFixture();
  const baseLines = traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: [{ rva: "0x4000", a: true, d: false }] },
      { id: "field-a", pages: [{ rva: "0x6000", a: true, d: true }] },
      { id: "field-b", pages: EFFECTS_B },
    ],
  }]).trimEnd().split("\n");

  const merged = parseCanonicalTrace(baseLines.join("\n") + "\n", "repeated-complete", bundle);
  const fieldAObs = merged.observations.filter((o) => o.fieldId === "field-a");
  expect(fieldAObs.map((o) => [o.pageRva, o.accessed, o.dirty, o.effects])).toEqual([
    [0x4000n, true, false, ["R", "W"]],
    [0x6000n, true, true, ["R", "W"]],
  ]);

  const secondCallIncomplete = JSON.parse(baseLines[1]!);
  secondCallIncomplete.fields[1].phases.S3_BODY.complete = false;
  const badLines = [...baseLines];
  badLines[1] = JSON.stringify(secondCallIncomplete);
  expect(() => parseCanonicalTrace(badLines.join("\n") + "\n", "repeated-incomplete", bundle))
    .toThrow(/page set is not complete/);

  const emptyS3 = JSON.parse(baseLines[1]!);
  emptyS3.fields[2].phases.S3_BODY.page_effects = [];
  const emptyLines = [...baseLines];
  emptyLines[1] = JSON.stringify(emptyS3);
  expect(() => parseCanonicalTrace(emptyLines.join("\n") + "\n", "empty-s3", bundle))
    .toThrow(/S3_BODY has no observed page effects/);
});

test("distinguishes verify-pretouch C-preserve-TLB mode and rejects building workset from verification traces", () => {
  const { bundle } = writeFixture();
  const baseLines = traceText(bundle, [{
    callSeq: 0,
    selectorSeq: 0,
    fields: [
      { id: "field-a", pages: [] },
      { id: "field-b", pages: [] },
    ],
  }]).trimEnd().split("\n");
  const start = JSON.parse(baseLines[0]!);
  start.mode = "verify-pretouch";
  baseLines[0] = JSON.stringify(start);
  const ecall = JSON.parse(baseLines[1]!);
  ecall.aex = {
    count: 4,
    protocol_gate_count: 4,
    unexpected_count: 0,
    by_gate: { GATE_A: 2, GATE_B: 2, GATE_C: 0 },
    by_stage: {
      S0_BRIDGE: { protocol_gate: 2, unexpected: 0 },
      S1_ENTER: { protocol_gate: 2, unexpected: 0 },
      S2_PRETOUCH: { protocol_gate: 0, unexpected: 0 },
      S3_BODY: { protocol_gate: 0, unexpected: 0 },
      POST_FIELD: { protocol_gate: 0, unexpected: 0 },
    },
    fault_events: [],
  };
  baseLines[1] = JSON.stringify(ecall);

  const verifyTrace = parseCanonicalTrace(baseLines.join("\n") + "\n", "verify-pretouch-ok", bundle);
  expect(verifyTrace.mode).toBe("verify-pretouch");
  expect(() => buildWorkset(bundle, [verifyTrace]))
    .toThrow(/cannot build workset from verification-mode trace/);

  ecall.aex.count = 6;
  ecall.aex.protocol_gate_count = 6;
  ecall.aex.by_gate.GATE_C = 2;
  ecall.aex.by_stage.S2_PRETOUCH.protocol_gate = 2;
  baseLines[1] = JSON.stringify(ecall);
  expect(() => parseCanonicalTrace(baseLines.join("\n") + "\n", "verify-pretouch-with-c-flush", bundle))
    .toThrow(/verify-pretouch mode must preserve TLB at GATE_C/);
});

test("accepts a field-free initialization ECALL followed by a same-instance Field-consuming ECALL, and accepts a legal early-return ECALL while rejecting Final workset when target Fields remain uncovered", () => {
  const { bundle } = writeFixture();
  const baseLines = traceText(bundle, [
    { callSeq: 0, selectorSeq: 0, fields: [] },
    {
      callSeq: 1,
      selectorSeq: 0,
      fields: [
        { id: "field-a", pages: [{ rva: "0x1000", a: true, d: false }] },
        { id: "field-b", pages: [{ rva: "0x4000", a: true, d: true }] },
      ],
    },
  ]).trimEnd().split("\n");
  const initEcall = JSON.parse(baseLines[1]!);
  initEcall.selector_ordinal = 1;
  initEcall.aex = {
    count: 0,
    protocol_gate_count: 0,
    unexpected_count: 0,
    by_gate: { GATE_A: 0, GATE_B: 0, GATE_C: 0 },
    by_stage: {
      S0_BRIDGE: { protocol_gate: 0, unexpected: 0 },
      S1_ENTER: { protocol_gate: 0, unexpected: 0 },
      S2_PRETOUCH: { protocol_gate: 0, unexpected: 0 },
      S3_BODY: { protocol_gate: 0, unexpected: 0 },
      POST_FIELD: { protocol_gate: 0, unexpected: 0 },
    },
    fault_events: [],
  };
  baseLines[1] = JSON.stringify(initEcall);

  const consumeEcall = JSON.parse(baseLines[2]!);
  consumeEcall.selector_ordinal = 0;
  consumeEcall.aex = {
    count: 6,
    protocol_gate_count: 6,
    unexpected_count: 0,
    by_gate: { GATE_A: 2, GATE_B: 2, GATE_C: 2 },
    by_stage: {
      S0_BRIDGE: { protocol_gate: 2, unexpected: 0 },
      S1_ENTER: { protocol_gate: 2, unexpected: 0 },
      S2_PRETOUCH: { protocol_gate: 2, unexpected: 0 },
      S3_BODY: { protocol_gate: 0, unexpected: 0 },
      POST_FIELD: { protocol_gate: 0, unexpected: 0 },
    },
    fault_events: [],
  };
  baseLines[2] = JSON.stringify(consumeEcall);

  const parsedSameInst = parseCanonicalTrace(baseLines.join("\n") + "\n", "same-instance-init-then-field", bundle);
  expect(parsedSameInst.ecallCount).toBe(2);
  expect(parsedSameInst.observedFieldIds).toEqual(["field-a", "field-b"]);
  const workset = buildWorkset(bundle, [parsedSameInst]);
  const initSelector = workset.selectors.find((s) => s.name === "initialize");
  const lookupSelector = workset.selectors.find((s) => s.name === "lookup");
  expect(initSelector?.pages).toEqual([]);
  expect(lookupSelector?.pages.length).toBeGreaterThan(0);

  // Legal early return on lookup (selector with non-empty reachable_fields returning before entering any Field)
  const earlyReturnLines = traceText(bundle, [
    { callSeq: 0, selectorSeq: 0, fields: [] },
  ]).trimEnd().split("\n");
  const startEr = JSON.parse(earlyReturnLines[0]!);
  startEr.run_id = "run-early-return";
  earlyReturnLines[0] = JSON.stringify(startEr);
  const ecallEr = JSON.parse(earlyReturnLines[1]!);
  ecallEr.run_id = "run-early-return";
  earlyReturnLines[1] = JSON.stringify(ecallEr);
  const endEr = JSON.parse(earlyReturnLines[2]!);
  endEr.run_id = "run-early-return";
  earlyReturnLines[2] = JSON.stringify(endEr);

  const parsedEarlyReturn = parseCanonicalTrace(earlyReturnLines.join("\n") + "\n", "legal-early-return", bundle);
  expect(parsedEarlyReturn.ecallCount).toBe(1);
  expect(parsedEarlyReturn.observedFieldIds).toEqual([]);
  expect(parsedEarlyReturn.observations).toEqual([]);
  // Whole round with only early-return trace cannot produce Final workset
  expect(() => buildWorkset(bundle, [parsedEarlyReturn]))
    .toThrow(/live Field field-a has no complete valid S3 observation/);
  // Combining legal early-return trace with complete Field-covering trace succeeds
  expect(buildWorkset(bundle, [parsedEarlyReturn, parsedSameInst]).fields.map((f) => f.id))
    .toEqual(["field-a", "field-b"]);

  // Truly missing Gate D (S3_BODY.complete === false while S0..S2 are complete) must be rejected
  const missingGateDLines = traceText(bundle, [
    {
      callSeq: 0,
      selectorSeq: 0,
      fields: [{ id: "field-a", pages: [{ rva: "0x1000", a: true, d: false }] }],
    },
  ]).trimEnd().split("\n");
  const ecallMissingD = JSON.parse(missingGateDLines[1]!);
  ecallMissingD.fields[0].phases.S3_BODY = { complete: false, page_size: 4096, page_effects: [] };
  missingGateDLines[1] = JSON.stringify(ecallMissingD);
  expect(() => parseCanonicalTrace(missingGateDLines.join("\n") + "\n", "missing-gate-d", bundle))
    .toThrow(/S3_BODY page set is not complete/);
});
