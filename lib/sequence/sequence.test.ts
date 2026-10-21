import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  ABI_SCHEMA_NAME, appendSequence, buildActionSequence, createReplayPlan,
  type AbiEcall, type AbiParameter, type AbiTypeDefinition, type AbiTypeNode,
  type CapturedObjectSnapshot, type CapturedRecord, type Edger8rAbiSchema, type ReplayContracts,
} from "./index.ts";

const builtin = (name: string): AbiTypeNode => ({ kind: "builtin", name });
const pointer = (to: AbiTypeNode): AbiTypeNode => ({ kind: "pointer", to });
const uint8 = builtin("uint8_t");
const sizeT = builtin("size_t");
const int32 = builtin("int32_t");

function attributes(size: unknown = null, count: unknown = null, extra: Partial<Record<"string" | "wstring" | "user_check" | "isptr" | "isary" | "readonly", boolean>> = {}) {
  return { size, count, string: false, wstring: false, user_check: false, isptr: false, isary: false, readonly: false, ...extra };
}
function parameter(
  name: string, direction: AbiParameter["direction"], type: AbiTypeNode,
  opts: { attributes?: AbiParameter["attributes"]; array_dimensions?: number[] } = {},
): AbiParameter {
  const pointer_depth = pointerDepth(type);
  const array_dimensions = opts.array_dimensions ?? [];
  return {
    name, direction, type, pointer_depth, array_dimensions,
    form: pointer_depth > 0 || array_dimensions.length > 0 ? "pointer" : "value",
    attributes: opts.attributes === undefined ? (pointer_depth ? attributes() : null) : opts.attributes,
  };
}
function pointerDepth(type: AbiTypeNode): number { return type.kind === "pointer" ? 1 + pointerDepth(type.to!) : 0; }
function ecall(ordinal: number, parameters: AbiParameter[]): AbiEcall {
  return { ordinal, name: `call_${ordinal}`, visibility: "public", switchless: false, return_type: int32, parameters };
}
function abi(ecalls: AbiEcall[], types: AbiTypeDefinition[] = []): Edger8rAbiSchema {
  return { schema: ABI_SCHEMA_NAME, tool: { name: "sgx_edger8r", version: "fixture" }, input: { root: "fixture.edl", imports: [] }, types, ecalls, ocalls: [] };
}
function capture(instance_generation: number, call_seq: number, ordinal: number, args: CapturedRecord["arguments"], objects: CapturedRecord["objects"] = {}, outputs: CapturedRecord["outputs"] = {}): CapturedRecord {
  return { instance_generation, call_seq, ordinal, arguments: args, outputs, objects };
}
function buffer(generation: number, capacity: number, bytes: number[]): CapturedObjectSnapshot {
  return { kind: "buffer", generation, capacity, actual_length: bytes.length, bytes };
}
function opaque(generation: number, bytes: number[]): CapturedObjectSnapshot {
  return { kind: "opaque", generation, capacity: bytes.length, actual_length: bytes.length, bytes };
}
function ref(object_id: string, generation: number, offset?: number, length?: number) {
  return { kind: "object_ref" as const, object_id, generation, offset, length };
}
function boundedBuffer(name: string, direction: AbiParameter["direction"], bound: unknown = { kind: "identifier", name: "size" }) {
  return parameter(name, direction, pointer(uint8), { attributes: attributes(bound) });
}
function sizeQueryAbi(): Edger8rAbiSchema {
  return abi([ecall(7, [
    parameter("buffer", "inout", pointer(uint8), { attributes: attributes({ kind: "identifier", name: "capacity" }) }),
    parameter("capacity", "value", sizeT),
    parameter("required", "out", pointer(sizeT), { attributes: attributes() }),
  ])]);
}
function sizeQueryRecord(instance: number, callSeq: number, capacity: number, objectId: string, required: number): CapturedRecord {
  const bytes = Array.from({ length: capacity }, (_, i) => (i * 31 + 7) & 255);
  return capture(instance, callSeq, 7,
    { buffer: ref(objectId, 0), capacity, required: 0 },
    { [objectId]: buffer(0, capacity, bytes) },
    { buffer: ref(objectId, 0), required });
}
const stableQueryContract: ReplayContracts = {
  7: {
    pure: true, idempotent: true,
    sizeQuery: { bufferParameter: "buffer", lengthParameter: "required", stability: { kind: "external-contract", evidenceId: "stable-length-contract-v1" } },
  },
};

describe("strict edger8r ABI parsing", () => {
  test("parses the SDK root.expected golden with fields, builtin, attributes, and pointer metadata", () => {
    const source = readFileSync(new URL("./fixtures/root.expected.json", import.meta.url), "utf8");
    const golden = JSON.parse(source) as Edger8rAbiSchema;
    const sequence = buildActionSequence(golden, []);
    expect(golden.schema).toBe("atfield-edl-abi-v1");
    expect(golden.types.find((type) => type.name === "Pair")).toHaveProperty("fields");
    expect(sequence.schema).toBe(ABI_SCHEMA_NAME);
    expect(sequence.blockers).toEqual([]);
  });

  test("rejects compatibility fields instead of consulting synthetic bounds or members", () => {
    const param = { ...boundedBuffer("blob", "in"), bounds: { kind: "integer", value: 4 } } as AbiParameter;
    expect(() => buildActionSequence(abi([ecall(1, [param])]), [])).toThrow(/legacy ABI field shape/);
    const oldDefinition = { kind: "struct", name: "Old", members: [] } as unknown as AbiTypeDefinition;
    expect(() => buildActionSequence(abi([], [oldDefinition]), [])).toThrow(/missing fields/);
  });
});

describe("typed sequence construction", () => {
  test("keeps scalar, record, capacity, actual length, and generation", () => {
    const header: AbiTypeDefinition = {
      kind: "struct", name: "Header",
      fields: [parameter("count", "value", int32)],
    };
    const dataParam = parameter("data", "in", pointer(uint8), { attributes: attributes({ kind: "identifier", name: "count" }) });
    const schema = abi([ecall(1, [
      parameter("count", "value", sizeT), dataParam, parameter("header", "in", { kind: "struct", name: "Header" }),
    ])], [header]);
    const recordValue = capture(4, 0, 1, { count: 3, data: ref("bytes", 2), header: ref("header", 1) }, {
      bytes: buffer(2, 8, [9, 8, 7]),
      header: { kind: "record", generation: 1, fields: { count: 3 } },
    });
    const sequence = buildActionSequence(schema, [recordValue]);
    expect(sequence.blockers).toEqual([]);
    const stream = sequence.streams[0];
    expect(stream.actions[0].arguments.count.input).toEqual({ kind: "scalar", value: 3 });
    expect(stream.objects.find((object) => object.objectId === "bytes")).toMatchObject({ kind: "buffer", capacity: 8, actualLength: 3, generation: 2, bytes: [9, 8, 7] });
    expect(stream.objects.find((object) => object.objectId === "header")).toMatchObject({ kind: "record", generation: 1, fields: { count: { kind: "scalar", value: 3 } } });
    expect(stream.actions[0].reads.find((access) => access.parameterPath === "data")).toMatchObject({ start: 0, end: 3 });
  });

  test("does not link distinct empty buffers with identical contents", () => {
    const schema = abi([
      ecall(1, [boundedBuffer("buffer", "out", { kind: "integer", value: 0 })]),
      ecall(2, [boundedBuffer("buffer", "in", { kind: "integer", value: 0 })]),
    ]);
    const seq = buildActionSequence(schema, [
      capture(1, 0, 1, { buffer: ref("empty-a", 0) }, { "empty-a": buffer(0, 0, []) }, { buffer: ref("empty-a", 0) }),
      capture(1, 1, 2, { buffer: ref("empty-b", 0) }, { "empty-b": buffer(0, 0, []) }),
    ]);
    expect(seq.streams[0].dataflowCandidates).toEqual([]);
  });

  test("preserves random opaque blobs and links only by identity", () => {
    const ext: AbiTypeDefinition = { kind: "named", name: "ExternalBlob", resolved: false };
    const opaquePtr = pointer({ kind: "named", name: "ExternalBlob" });
    const schema = abi([
      ecall(1, [parameter("blob", "out", opaquePtr, { attributes: attributes({ kind: "identifier", name: "size" }) }), parameter("size", "value", sizeT)]),
      ecall(2, [parameter("blob", "in", opaquePtr, { attributes: attributes({ kind: "identifier", name: "size" }) }), parameter("size", "value", sizeT)]),
    ], [ext]);
    const random = Array.from({ length: 96 }, (_, i) => (i * 73 + 19) & 255);
    const seq = buildActionSequence(schema, [
      capture(2, 0, 1, { blob: ref("opaque-a", 0), size: 96 }, { "opaque-a": opaque(0, random) }, { blob: ref("opaque-a", 0) }),
      capture(2, 1, 2, { blob: ref("opaque-b", 0), size: 96 }, { "opaque-b": opaque(0, random) }),
    ]);
    expect(seq.streams[0].objects.filter((o) => o.kind === "opaque").map((o) => o.bytes)).toEqual([random, random]);
    expect(seq.streams[0].dataflowCandidates).toEqual([]);
  });

  test("links overlapping aliases with slice evidence", () => {
    const schema = abi([
      ecall(1, [boundedBuffer("slice", "out", { kind: "integer", value: 6 })]),
      ecall(2, [boundedBuffer("slice", "in", { kind: "integer", value: 4 })]),
    ]);
    const shared = buffer(5, 8, [1, 2, 3, 4, 5, 6, 7, 8]);
    const seq = buildActionSequence(schema, [
      capture(3, 0, 1, { slice: ref("shared", 5, 0, 6) }, { shared }, { slice: ref("shared", 5, 0, 6) }),
      capture(3, 1, 2, { slice: ref("shared", 5, 4, 4) }, { shared }),
    ]);
    expect(seq.streams[0].dataflowCandidates).toHaveLength(1);
    expect(seq.streams[0].dataflowCandidates[0]).toMatchObject({
      overlap: { start: 4, end: 6 }, confidence: "medium",
      evidence: ["same-object-identity", "overlapping-slices", "producer-before-consumer", "same-generation"],
    });
  });

  test("rejects unknown user_check, multi-level pointers, and missing actual bounds", () => {
    const unknown = abi([ecall(1, [parameter("blob", "in", pointer(builtin("void")), { attributes: null })])]);
    const unknownSeq = buildActionSequence(unknown, [capture(1, 0, 1, { blob: ref("raw", 0) }, { raw: opaque(0, [1, 2]) })]);
    expect(unknownSeq.blockers.some((item) => item.code === "unknown_user_check")).toBe(true);
    expect(createReplayPlan(unknownSeq).eligible).toBe(false);

    const multiType = pointer(pointer(uint8));
    const multi = abi([ecall(2, [parameter("blob", "in", multiType, { attributes: attributes({ kind: "identifier", name: "size" }) })])]);
    const multiSeq = buildActionSequence(multi, [capture(1, 0, 2, { blob: ref("raw", 0) }, { raw: buffer(0, 2, [1, 2]) })]);
    expect(multiSeq.blockers.some((item) => item.code === "multi_level_pointer")).toBe(true);
    expect(createReplayPlan(multiSeq).eligible).toBe(false);

    const noBound = parameter("blob", "in", pointer(uint8), { attributes: attributes(null, null, { isary: true }) });
    const boundsSeq = buildActionSequence(abi([ecall(3, [noBound])]), [capture(1, 0, 3, { blob: ref("raw", 0) }, { raw: buffer(0, 2, [1, 2]) })]);
    expect(boundsSeq.blockers.some((item) => item.code === "unknown_buffer_bounds")).toBe(true);
    expect(createReplayPlan(boundsSeq).eligible).toBe(false);
  });
});

describe("replay contracts and instance isolation", () => {
  test("uses an explicit stable contract for a two-step size query", () => {
    const schema = sizeQueryAbi();
    const sequence = buildActionSequence(schema, [sizeQueryRecord(10, 0, 0, "query-buffer", 6), sizeQueryRecord(10, 1, 6, "fill-buffer", 6)], stableQueryContract);
    const plan = createReplayPlan(sequence, { repetitions: 2 });
    expect(plan.eligible).toBe(true);
    expect(plan.instancePolicy).toBe("fresh-per-run");
    expect(plan.sizeQueries[0]).toMatchObject({ strategy: "query-then-replay", stabilityEvidence: "external-contract:stable-length-contract-v1" });
    expect(plan.runs.map((run) => run.instanceId)).toEqual(["fresh-0", "fresh-1"]);
    expect(plan.runs[0].actions).toHaveLength(2);
  });

  test("proves query length only from explicit fresh-instance differential evidence", () => {
    const contract: ReplayContracts = { 7: { pure: true, idempotent: true, sizeQuery: {
      bufferParameter: "buffer", lengthParameter: "required", stability: { kind: "fresh-instance-differential", minimumInstances: 2 },
    } } };
    const sequence = buildActionSequence(sizeQueryAbi(), [
      sizeQueryRecord(20, 0, 0, "query-a", 6), sizeQueryRecord(20, 1, 6, "fill-a", 6), sizeQueryRecord(21, 0, 0, "query-b", 6),
    ], contract);
    const plan = createReplayPlan(sequence);
    expect(plan.eligible).toBe(true);
    expect(plan.sizeQueries[0]).toMatchObject({ strategy: "query-then-replay", stabilityEvidence: "fresh-instance-differential:2" });
    expect(plan.runs[0].sourceInstanceGeneration).toBe(20);
    expect(plan.runs[0].actions).toHaveLength(2);
  });

  test("never reuses a captured query result across instance generations", () => {
    const sequence = buildActionSequence(sizeQueryAbi(), [
      sizeQueryRecord(25, 0, 0, "query-buffer", 6), sizeQueryRecord(26, 0, 6, "fill-buffer", 6),
    ], stableQueryContract);
    const plan = createReplayPlan(sequence, { maximumCapacityByOrdinal: { 7: 12 } });
    expect(plan.eligible).toBe(true);
    expect(plan.runs[0].sourceInstanceGeneration).toBe(26);
    expect(plan.runs[0].actions.map((action) => action.callSeq)).toEqual([0]);
    expect(plan.sizeQueries[0]).toMatchObject({
      strategy: "capacity-ladder", initialCapacity: 6, skippedQueryCallSeqs: [],
      queryResultReusable: false, freshInstancePerAttempt: true,
    });
  });

  test("uses a fresh-instance capacity ladder for an effectful query", () => {
    const effectful: ReplayContracts = { 7: { pure: false, idempotent: false, sizeQuery: {
      bufferParameter: "buffer", lengthParameter: "required", stability: { kind: "external-contract", evidenceId: "stable-length-contract-v1" },
    } } };
    const sequence = buildActionSequence(sizeQueryAbi(), [sizeQueryRecord(30, 0, 0, "query-buffer", 6), sizeQueryRecord(30, 1, 6, "fill-buffer", 6)], effectful);
    const unbounded = createReplayPlan(sequence);
    expect(unbounded.eligible).toBe(false);
    expect(unbounded.sizeQueries[0]).toMatchObject({ strategy: "capacity-ladder", queryResultReusable: false, reason: "query-not-pure-idempotent" });
    const bounded = createReplayPlan(sequence, { maximumCapacityByOrdinal: { 7: 16 } });
    expect(bounded.eligible).toBe(true);
    expect(bounded.sizeQueries[0]).toMatchObject({ strategy: "capacity-ladder", initialCapacity: 6, maximumCapacity: 16, skippedQueryCallSeqs: [0] });
    expect(bounded.runs[0].actions.map((action) => action.callSeq)).toEqual([1]);
    expect(bounded.runs[0].objects.map((object) => object.objectId)).toEqual(["fill-buffer"]);
  });

  test("requires query stability evidence and skips the zero-capacity call without a contract", () => {
    const sequence = buildActionSequence(sizeQueryAbi(), [
      sizeQueryRecord(31, 0, 0, "query-buffer", 6), sizeQueryRecord(31, 1, 6, "fill-buffer", 6),
    ]);
    expect(sequence.sizeQueries[0]).toMatchObject({ fallbackReason: "stability-unproven", stabilityEvidence: undefined });
    const plan = createReplayPlan(sequence, { maximumCapacityByOrdinal: { 7: 16 } });
    expect(plan.eligible).toBe(true);
    expect(plan.sizeQueries[0]).toMatchObject({ strategy: "capacity-ladder", skippedQueryCallSeqs: [0], queryResultReusable: false });
    expect(plan.runs[0].actions.map((action) => action.callSeq)).toEqual([1]);
  });

  test("requires pure and idempotent declarations before appending the same EID", () => {
    const schema = abi([ecall(9, [parameter("value", "value", int32)])]);
    const first = buildActionSequence(schema, [capture(40, 0, 9, { value: 1 })]);
    const second = buildActionSequence(schema, [capture(40, 0, 9, { value: 2 })]);
    expect(appendSequence(first, second)).toEqual({ ok: false, code: "same_eid_requires_pure_idempotent", ordinals: [9] });
    const appended = appendSequence(first, second, { 9: { pure: true, idempotent: true } });
    expect(appended.ok).toBe(true);
    if (appended.ok) expect(appended.sequence.streams[0].actions.map((action) => action.ordinal)).toEqual([9, 9]);
  });

  test("keeps object generations within one instance and isolates fresh replay runs", () => {
    const schema = abi([ecall(12, [boundedBuffer("state", "inout", { kind: "integer", value: 2 })])]);
    const sequence = buildActionSequence(schema, [
      capture(60, 0, 12, { state: ref("state-object", 0) }, { "state-object": buffer(0, 2, [0, 0]) }, { state: ref("state-object", 0) }),
      capture(60, 1, 12, { state: ref("state-object", 0) }, { "state-object": buffer(1, 2, [1, 0]) }, { state: ref("state-object", 1) }),
    ]);
    expect(sequence.streams[0].dataflowCandidates).toHaveLength(1);
    expect(sequence.streams[0].dataflowCandidates[0]).toMatchObject({ generationFrom: 0, generationTo: 0 });
    const plan = createReplayPlan(sequence, { repetitions: 2 });
    expect(plan.eligible).toBe(true);
    const first = plan.runs[0].objects.find((object) => object.generation === 0 && object.objectId === "state-object");
    const second = plan.runs[1].objects.find((object) => object.generation === 0 && object.objectId === "state-object");
    if (first?.bytes) first.bytes[0] = 99;
    expect(second?.bytes).toEqual([0, 0]);
    expect(plan.runs.map((run) => run.actions.map((action) => action.callSeq))).toEqual([[0, 1], [0, 1]]);
  });

  test("replays repeated same-EID calls from a fresh instance per run", () => {
    const schema = abi([ecall(11, [parameter("state", "value", int32)])]);
    const sequence = buildActionSequence(schema, [capture(50, 0, 11, { state: 1 }), capture(50, 1, 11, { state: 2 })]);
    const plan = createReplayPlan(sequence, { repetitions: 2 });
    expect(plan.eligible).toBe(true);
    expect(plan.runs.map((run) => run.actions.map((action) => (action.arguments.state.input as { value: number }).value))).toEqual([[1, 2], [1, 2]]);
    const value = plan.runs[0].actions[0].arguments.state.input;
    if (value?.kind === "scalar") value.value = 99;
    expect((plan.runs[1].actions[0].arguments.state.input as { value: number }).value).toBe(1);
    expect(plan.runs[0].instanceId).not.toBe(plan.runs[1].instanceId);
  });
});

