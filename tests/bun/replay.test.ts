import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  buildReplayPlan,
  ReplayPlanningError,
  type ReplayBaselineCall,
  type ReplayBundleInputs,
  type ReplayMarshalParameterV1,
} from "../../lib/replay";
import type { AbiEcall, AbiParameter, AbiTypeNode } from "../../lib/sequence/types";

const attrs = (extra: Partial<NonNullable<AbiParameter["attributes"]>> = {}) => ({
  size: null,
  count: null,
  string: false,
  wstring: false,
  user_check: false,
  isptr: false,
  isary: false,
  readonly: false,
  ...extra,
});

const scalar = (name: string, index: number, direction: AbiParameter["direction"] = "value"): AbiParameter => ({
  name,
  type: { kind: "builtin", name: "size_t" },
  form: "value",
  pointer_depth: 0,
  direction,
  array_dimensions: [],
  attributes: null,
});

const pointer = (
  name: string,
  pointee: AbiTypeNode,
  direction: AbiParameter["direction"] = "in",
  extra: Partial<NonNullable<AbiParameter["attributes"]>> = {},
): AbiParameter => ({
  name,
  type: { kind: "pointer", to: pointee },
  form: "pointer",
  pointer_depth: 1,
  direction,
  array_dimensions: [],
  attributes: attrs(extra),
});

const layoutParameter = (
  parameter: AbiParameter,
  parameter_index: number,
  element_width_bytes?: number,
): ReplayMarshalParameterV1 => ({
  parameter_index,
  name: parameter.name,
  ms_offset: 8 + parameter_index * 8,
  ms_size: parameter.pointer_depth > 0 ? 8 : 8,
  source_type: parameter.type.name ?? (parameter.type.kind === "pointer" ? parameter.type.to?.name ?? "pointer" : "uint8_t"),
  is_pointer: parameter.pointer_depth > 0 || parameter.form === "pointer" || parameter.type.kind === "pointer",
  width_bytes: parameter.pointer_depth > 0 || parameter.type.kind === "pointer" ? 8 : 8,
  signedness: parameter.type.name?.startsWith("int") ? "signed" : "unsigned",
  direction: parameter.direction === "value" ? "val" : parameter.direction,
  ...(element_width_bytes === undefined ? {} : { element_width_bytes }),
});

function ecall(parameters: AbiParameter[], ordinal = 0): AbiEcall {
  return {
    ordinal,
    name: "consume",
    visibility: "public",
    switchless: false,
    return_type: { kind: "builtin", name: "int32_t" },
    parameters,
  };
}

function bundle(parameters: AbiParameter[], options: {
  ordinal?: number;
  types?: ReplayBundleInputs["abi"]["types"];
  contracts?: ReplayBundleInputs["contracts"];
  widths?: Record<number, number>;
} = {}): ReplayBundleInputs {
  const ordinal = options.ordinal ?? 0;
  return {
    manifest_sha256: "a".repeat(64),
    marshal_layout_sha256: "b".repeat(64),
    abi: {
      schema: "atfield-edl-abi-v1",
      tool: {},
      input: {},
      types: options.types ?? [],
      ecalls: [ecall(parameters, ordinal)],
      ocalls: [],
    },
    marshal_layout: {
      schema: "atfield-marshal-layout-v1",
      compiler_probed: true,
      selector_ordinal: ordinal,
      marshal_size: 8 + parameters.length * 8,
      parameters: parameters.map((item, index) => layoutParameter(item, index, options.widths?.[index])),
    },
    contracts: options.contracts,
  };
}

function capture(args: ReplayBaselineCall["arguments"], objects: ReplayBaselineCall["objects"] = {}, extra: Partial<ReplayBaselineCall> = {}): ReplayBaselineCall {
  return {
    instance_generation: 3,
    call_seq: 12,
    ordinal: 0,
    selector_seq: 2,
    arguments: args,
    outputs: {},
    objects,
    ...extra,
  };
}

function objectRef(object_id: string, generation: number, offset = 0, length?: number) {
  return { kind: "object_ref" as const, object_id, generation, offset, ...(length === undefined ? {} : { length }) };
}

function sha(bytes: readonly number[]): string {
  return createHash("sha256").update(new Uint8Array(bytes)).digest("hex");
}

function expectReplayError(code: string, fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(ReplayPlanningError);
    expect((error as ReplayPlanningError).code).toBe(code);
    return;
  }
  throw new Error("expected replay error " + code);
}

describe("replay parameter reconstruction", () => {
  test("reuses a producer object snapshot as a consumer input with its generation", () => {
    const p = pointer("input", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "integer", value: 4 },
    });
    const inputs = bundle([p]);
    const baseline = capture(
      { input: objectRef("key-material", 7, 0, 4) },
      { "key-material": { kind: "buffer", generation: 7, capacity: 4, actual_length: 4, bytes: [1, 2, 3, 4] } },
      { outputs: { produced: objectRef("key-material", 7, 0, 4) } },
    );

    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.action).toBe("reconstruct_captured_call_once");
    expect(plan.target.selector_seq).toBe(2);
    expect(plan.target.call_seq).toBe(12);
    expect(plan.memory).toHaveLength(1);
    expect(plan.memory[0]?.object_id).toBe("key-material");
    expect(plan.memory[0]?.generation).toBe(7);
    expect(plan.parameters[0]).toMatchObject({ kind: "buffer", direction: "in", byte_length: 4, copy_back: false });
  });

  test("rejects a size query that requires a fresh-instance differential", () => {
    const p = pointer("buffer", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "identifier", name: "length" },
    });
    const len = scalar("length", 1);
    const inputs = bundle([p, len], {
      contracts: {
        0: {
          sizeQuery: {
            bufferParameter: "buffer",
            lengthParameter: "length",
            stability: { kind: "fresh-instance-differential", minimumInstances: 2 },
          },
        },
      },
    });
    const baseline = capture(
      { buffer: objectRef("buffer", 1, 0, 4), length: { kind: "scalar", value: 4 } },
      { buffer: { kind: "buffer", generation: 1, capacity: 4, bytes: [1, 2, 3, 4] } },
    );
    expectReplayError("fresh_instance_required", () => buildReplayPlan(inputs, baseline, []));
  });

  test("preserves overlapping slices and alias identity while mutating one slice", () => {
    const left = pointer("left", { kind: "builtin", name: "uint8_t" }, "in", { size: { kind: "integer", value: 4 } });
    const right = pointer("right", { kind: "builtin", name: "uint8_t" }, "in", { size: { kind: "integer", value: 4 } });
    const inputs = bundle([left, right]);
    const baseline = capture(
      { left: objectRef("shared", 5, 0, 4), right: objectRef("shared", 5, 2, 4) },
      { shared: { kind: "buffer", generation: 5, capacity: 6, bytes: [1, 2, 3, 4, 5, 6] } },
      { buffer_evidence: { 0: { object_id: "shared", generation: 5, base_slice: { offset: 0, length: 4 }, capacity: 6, sha256: sha([1, 2, 3, 4]) } } },
    );
    const plan = buildReplayPlan(inputs, baseline, [{
      kind: "bytes",
      param_index: 0,
      expected_length: 4,
      expected_sha256: sha([1, 2, 3, 4]),
      replacement_bytes: [9, 9, 9, 9],
    }]);
    expect(plan.parameters[0]).toMatchObject({ object_id: "shared", object_generation: 5, offset: 0 });
    expect(plan.parameters[1]).toMatchObject({ object_id: "shared", object_generation: 5, offset: 2 });
    expect(plan.memory[0]?.initial_bytes_hex).toBe("090909090506");
    expect(plan.buffer_ops[0]?.expected_shape.slice_sha256).toBe(sha([1, 2, 3, 4]));
    expect(plan.buffer_ops[0]?.replacement_sha256).toBe(sha([9, 9, 9, 9]));
  });

  test("binds count identifiers to scalar parameters and checks replacements before sizing", () => {
    const p = pointer("items", { kind: "builtin", name: "uint8_t" }, "in", {
      count: { kind: "identifier", name: "count" },
    });
    const n = scalar("count", 1);
    const inputs = bundle([p, n]);
    const baseline = capture(
      { items: objectRef("items", 1, 0, 4), count: { kind: "scalar", value: 4 } },
      { items: { kind: "buffer", generation: 1, capacity: 8, bytes: [1, 2, 3, 4, 5, 6, 7, 8] } },
    );
    const plan = buildReplayPlan(inputs, baseline, [{
      kind: "scalar", param_index: 1, expected_value: 4, replacement_value: 6,
    }]);
    expect(plan.parameters[0]).toMatchObject({ byte_length: 6, element_count: 6, rebuild_owned_buffer: true, owned_storage: "single_pointer_copy" });
    expect(plan.buffer_ops).toHaveLength(0);
    expect(plan.scalar_ops[0]?.param_index).toBe(1);
    expect(plan.scalar_ops[0]?.expected_bits).toBe("0x0000000000000004");
    expect(plan.scalar_ops[0]?.replacement_bits).toBe("0x0000000000000006");
  });

  test("rejects hostile overlarge lengths before allocation or serialization", () => {
    const p = pointer("items", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "identifier", name: "length" },
    });
    const n = scalar("length", 1);
    const inputs = bundle([p, n]);
    const baseline = capture(
      { items: objectRef("items", 1, 0, 4), length: { kind: "scalar", value: 4 } },
      { items: { kind: "buffer", generation: 1, capacity: 4, bytes: [1, 2, 3, 4] } },
    );
    expectReplayError("invalid_bound", () => buildReplayPlan(inputs, baseline, [{
      kind: "scalar", param_index: 1, expected_value: 4, replacement_value: "18446744073709551615",
    }]));
  });

  test("rejects cyclic captured object graphs", () => {
    const p = pointer("node", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "integer", value: 1 },
    });
    const inputs = bundle([p]);
    const baseline = capture(
      { node: objectRef("cycle", 1, 0, 1) },
      { cycle: { kind: "record", generation: 1, capacity: 1, bytes: [0], fields: { self: objectRef("cycle", 1) } } },
    );
    expectReplayError("object_cycle", () => buildReplayPlan(inputs, baseline, []));
  });

  test("uses compiler-probed wchar width and requires the wide terminator", () => {
    const p = pointer("wide", { kind: "builtin", name: "wchar_t" }, "in", { wstring: true });
    const inputs = bundle([p], { widths: { 0: 4 } });
    const baseline = capture(
      { wide: objectRef("wide", 2, 0, 8) },
      { wide: { kind: "buffer", generation: 2, capacity: 8, bytes: [65, 0, 0, 0, 0, 0, 0, 0] } },
      { buffer_evidence: { 0: { object_id: "wide", generation: 2, base_slice: { offset: 0, length: 8 }, capacity: 8, sha256: sha([65, 0, 0, 0, 0, 0, 0, 0]) } } },
    );
    const plan = buildReplayPlan(inputs, baseline, [{
      kind: "bytes",
      param_index: 0,
      expected_length: 8,
      expected_sha256: sha([65, 0, 0, 0, 0, 0, 0, 0]),
      replacement_bytes: [66, 0, 0, 0, 0, 0, 0, 0],
    }]);
    expect(plan.parameters[0]).toMatchObject({ element_width_bytes: 4, byte_length: 8, element_count: 2 });
    expect(plan.buffer_ops[0]?.replacement_bytes_hex).toBe("4200000000000000");
  });

  test("rejects opaque, user_check and nested pointer parameters explicitly", () => {
    const opaque = pointer("opaque", { kind: "named", name: "Opaque" }, "in", {
      size: { kind: "integer", value: 1 },
    });
    const opaqueInputs = bundle([opaque], { types: [{ kind: "named", name: "Opaque", resolved: false }] });
    const base = capture({ opaque: objectRef("o", 1, 0, 1) }, { o: { kind: "buffer", generation: 1, capacity: 1, bytes: [0] } });
    expectReplayError("opaque_type", () => buildReplayPlan(opaqueInputs, base, []));

    const userChecked = pointer("user", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "integer", value: 1 }, user_check: true,
    });
    const userBundle = bundle([userChecked]);
    const userBase = capture({ user: objectRef("u", 1, 0, 1) }, { u: { kind: "buffer", generation: 1, capacity: 1, bytes: [0] } });
    expectReplayError("user_check", () => buildReplayPlan(userBundle, userBase, []));

    const nested = pointer("next", { kind: "pointer", to: { kind: "builtin", name: "uint8_t" } }, "in", {
      size: { kind: "integer", value: 8 },
    });
    const nestedBundle = bundle([nested]);
    const nestedBase = capture({ next: objectRef("n", 1, 0, 8) }, { n: { kind: "buffer", generation: 1, capacity: 8, bytes: Array(8).fill(0) } });
    expectReplayError("nested_pointer", () => buildReplayPlan(nestedBundle, nestedBase, []));
  });

  test("rejects scalar width overflow and stale baseline expectations", () => {
    const signed = scalar("signed", 0);
    signed.type = { kind: "builtin", name: "int32_t" };
    const inputs = bundle([signed]);
    inputs.marshal_layout.parameters[0]!.width_bytes = 4;
    inputs.marshal_layout.parameters[0]!.ms_size = 4;
    const baseline = capture({ signed: { kind: "scalar", value: -1 } });
    expectReplayError("integer_overflow", () => buildReplayPlan(inputs, baseline, [{
      kind: "scalar", param_index: 0, expected_value: -1, replacement_value: "2147483648",
    }]));
    expectReplayError("baseline_mismatch", () => buildReplayPlan(inputs, baseline, [{
      kind: "scalar", param_index: 0, expected_value: -2, replacement_value: 0,
    }]));
  });

  test("emits copy-back metadata for out and inout owned buffers", () => {
    const out = pointer("out", { kind: "builtin", name: "uint8_t" }, "out", { size: { kind: "integer", value: 4 } });
    const inout = pointer("inout", { kind: "builtin", name: "uint8_t" }, "inout", { size: { kind: "integer", value: 4 } });
    const inputs = bundle([out, inout]);
    const baseline = capture(
      { out: objectRef("out-obj", 1, 0, 4), inout: objectRef("inout-obj", 1, 0, 4) },
      {
        "out-obj": { kind: "buffer", generation: 1, capacity: 4, bytes: [1, 1, 1, 1] },
        "inout-obj": { kind: "buffer", generation: 1, capacity: 4, bytes: [2, 2, 2, 2] },
      },
    );
    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.parameters[0]).toMatchObject({ direction: "out", copy_back: true });
    expect(plan.memory.find((item) => item.object_id === "out-obj")?.initial_bytes_hex).toBe("00000000");
    expect(plan.parameters[1]).toMatchObject({ direction: "inout", copy_back: true });
    expect(plan.memory.find((item) => item.object_id === "inout-obj")?.initial_bytes_hex).toBe("02020202");
  });
});

describe("replay strings, nulls and decayed arrays", () => {
  test("preserves byte string terminators and character width", () => {
    const text = pointer("text", { kind: "builtin", name: "char" }, "in", { string: true });
    const inputs = bundle([text]);
    const baseline = capture(
      { text: objectRef("text", 1, 0, 3) },
      { text: { kind: "buffer", generation: 1, capacity: 3, bytes: [104, 105, 0] } },
      { buffer_evidence: { 0: { object_id: "text", generation: 1, base_slice: { offset: 0, length: 3 }, capacity: 3, sha256: sha([104, 105, 0]) } } },
    );
    const plan = buildReplayPlan(inputs, baseline, [{
      kind: "bytes",
      param_index: 0,
      expected_length: 3,
      expected_sha256: sha([104, 105, 0]),
      replacement_bytes: [98, 121, 0],
    }]);
    expect(plan.parameters[0]).toMatchObject({ element_width_bytes: 1, byte_length: 3 });
    expect(plan.buffer_ops[0]?.replacement_bytes_hex).toBe("627900");
  });

  test("keeps a captured NULL pointer null and rejects bytes for it", () => {
    const p = pointer("maybe", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "integer", value: 4 },
    });
    const inputs = bundle([p]);
    const baseline = capture({ maybe: null });
    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.parameters[0]).toMatchObject({ is_null: true, byte_length: 0, object_id: null });
    expect(plan.memory).toHaveLength(0);
    expectReplayError("invalid_candidate", () => buildReplayPlan(inputs, baseline, [{
      kind: "bytes", param_index: 0, expected_length: 0, expected_sha256: sha([]), replacement_bytes: [],
    }]));
  });

  test("handles fixed C arrays after ABI array decay", () => {
    const fixed: AbiParameter = {
      name: "fixed",
      type: { kind: "builtin", name: "uint32_t" },
      form: "pointer",
      pointer_depth: 0,
      direction: "in",
      array_dimensions: [3],
      attributes: attrs({ isary: true }),
    };
    const inputs = bundle([fixed], { widths: { 0: 4 } });
    const baseline = capture(
      { fixed: objectRef("fixed", 1, 0, 12) },
      { fixed: { kind: "buffer", generation: 1, capacity: 12, bytes: Array.from({ length: 12 }, (_, i) => i) } },
    );
    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.parameters[0]).toMatchObject({ kind: "buffer", element_width_bytes: 4, element_count: 3, byte_length: 12 });
  });
});

describe("combined bounds and capture-bound mutations", () => {
  test("combines size bytes and count elements with checked element rounding", () => {
    const p = pointer("records", { kind: "builtin", name: "uint32_t" }, "in", {
      size: { kind: "integer", value: 4 },
      count: { kind: "integer", value: 2 },
    });
    const inputs = bundle([p], { widths: { 0: 4 } });
    const baseline = capture(
      { records: objectRef("records", 1, 0, 8) },
      { records: { kind: "buffer", generation: 1, capacity: 8, bytes: [1, 2, 3, 4, 5, 6, 7, 8] } },
    );
    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.parameters[0]).toMatchObject({ byte_length: 8, element_count: 2, array_dimensions: [] });
  });

  test("requires capture supplied digest and shape evidence before making buffer ops", () => {
    const p = pointer("data", { kind: "builtin", name: "uint8_t" }, "in", {
      size: { kind: "integer", value: 2 },
    });
    const inputs = bundle([p]);
    const baseline = capture(
      { data: objectRef("data", 1, 0, 2) },
      { data: { kind: "buffer", generation: 1, capacity: 2, bytes: [1, 2] } },
    );
    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.buffer_ops).toHaveLength(0);
    expectReplayError("missing_buffer_evidence", () => buildReplayPlan(inputs, baseline, [{
      kind: "bytes", param_index: 0, expected_length: 2, expected_sha256: sha([1, 2]), replacement_bytes: [3, 4],
    }]));
  });

  test("encodes signed scalar bits at exactly compiler-probed width", () => {
    const signed = scalar("signed", 0);
    signed.type = { kind: "builtin", name: "int32_t" };
    const inputs = bundle([signed]);
    inputs.marshal_layout.parameters[0]!.width_bytes = 4;
    inputs.marshal_layout.parameters[0]!.ms_size = 4;
    const baseline = capture({ signed: { kind: "scalar", value: -1 } });
    const plan = buildReplayPlan(inputs, baseline, []);
    expect(plan.parameters[0]).toMatchObject({ width_bytes: 4, signedness: "signed", expected_bits: "0xffffffff" });
  });
});

describe("replay extension and byte-pointer semantics", () => {
  test("extends owned input storage only with explicit capture shape and digest", () => {
    const p = pointer("items", { kind: "builtin", name: "uint8_t" }, "in", {
      count: { kind: "identifier", name: "count" },
    });
    const n = scalar("count", 1);
    const inputs = bundle([p, n]);
    const baseline = capture(
      { items: objectRef("items", 1, 0, 4), count: { kind: "scalar", value: 4 } },
      { items: { kind: "buffer", generation: 1, capacity: 8, bytes: [1, 2, 3, 4, 5, 6, 7, 8] } },
      { buffer_evidence: { 0: { object_id: "items", generation: 1, base_slice: { offset: 0, length: 4 }, capacity: 8, sha256: sha([1, 2, 3, 4]) } } },
    );
    const plan = buildReplayPlan(inputs, baseline, [
      { kind: "scalar", param_index: 1, expected_value: 4, replacement_value: 6 },
      { kind: "bytes", param_index: 0, expected_length: 4, expected_sha256: sha([1, 2, 3, 4]), replacement_bytes: [9, 9, 9, 9, 9, 9] },
    ]);
    expect(plan.buffer_ops[0]?.expected_shape.byte_length).toBe(4);
    expect(plan.buffer_ops[0]?.replacement_shape.byte_length).toBe(6);
    expect(plan.buffer_ops[0]?.replacement_shape.object_capacity).toBe(8);
    expect(plan.memory[0]?.initial_bytes_hex).toBe("0909090909090708");
  });

  test("rejects misaligned combined typed size/count and treats sized void pointers as bytes", () => {
    const misaligned = pointer("records", { kind: "builtin", name: "uint32_t" }, "in", {
      size: { kind: "integer", value: 3 }, count: { kind: "integer", value: 2 },
    });
    const badBundle = bundle([misaligned], { widths: { 0: 4 } });
    const badCapture = capture(
      { records: objectRef("records", 1, 0, 8) },
      { records: { kind: "buffer", generation: 1, capacity: 8, bytes: Array(8).fill(0) } },
    );
    expectReplayError("invalid_bound", () => buildReplayPlan(badBundle, badCapture, []));

    const raw = pointer("raw", { kind: "builtin", name: "void" }, "in", {
      size: { kind: "integer", value: 3 },
    });
    const rawBundle = bundle([raw]);
    const rawCapture = capture(
      { raw: objectRef("raw", 1, 0, 3) },
      { raw: { kind: "buffer", generation: 1, capacity: 3, bytes: [1, 2, 3] } },
    );
    const rawPlan = buildReplayPlan(rawBundle, rawCapture, []);
    expect(rawPlan.parameters[0]).toMatchObject({ element_width_bytes: 1, byte_length: 3 });
  });
});
