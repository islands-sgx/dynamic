import { expect, test } from "bun:test";
import type {
  CallCaptureDocument,
  CallCaptureEvent,
  CapturedBufferInput,
  CapturedBufferOutput,
} from "../../lib/explorer/contract.ts";
import {
  encodeMutationSpec,
  MUTATION_SPEC_HEADER_BYTES,
  MUTATION_SPEC_RULE_BYTES,
  MUTATION_SPEC_SCALAR_OP_BYTES,
} from "../../lib/explorer/contract.ts";
import {
  deriveCandidatesFromCase,
  inferCaptureProducerConsumerFlow,
  linkedConsumerCallKey,
  mutationRuleKey,
  reserveLinkedConsumerCallKeys,
  validateProducerConsumerBinding,
} from "../../lib/explorer/planner.ts";
import type { ExplorerProfile, MarshalEcall, MarshalParameter } from "../../lib/explorer/profile.ts";
import type {
  PageUniverseEntry,
  ProfileBundle,
  ProfileField,
  ProfileSelector,
} from "../../lib/bundle/profile-bundle.ts";
import type { ScalarParameter } from "../../lib/guidance/index.ts";

const SELECTOR = { producer: 7, consumer: 2 } as const;
const RUN_ID = "12345678-1234-4234-8234-123456789abc";
const MANIFEST_HASH = "ab".repeat(32);
const LAYOUT_HASH = "cd".repeat(32);
const ADDRESS_A = "0x0000000000001000";
const ADDRESS_B = "0x0000000000002000";
const ADDRESS_C = "0x0000000000003000";
const RECORD_BYTES = 12;

function recordBytes(word: number): Uint8Array {
  const bytes = new Uint8Array(RECORD_BYTES);
  new DataView(bytes.buffer).setUint32(0, word, true);
  return bytes;
}

function hexBytes(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fnv1a64(bytes: Uint8Array): string {
  let hash = 0xcbf29ce484222325n;
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return "0x" + hash.toString(16).padStart(16, "0");
}

function inputBuffer(input: {
  readonly address?: string;
  readonly direction: "in" | "inout";
  readonly paramIndex: number;
  readonly word: number;
}): CapturedBufferInput {
  const bytes = recordBytes(input.word);
  return {
    paramIndex: input.paramIndex,
    direction: input.direction,
    isString: false,
    elementSize: RECORD_BYTES,
    byteLength: bytes.byteLength,
    fnv1a64: fnv1a64(bytes),
    prefixHex: hexBytes(bytes),
    ...(input.address === undefined ? {} : { storageAddress: input.address }),
  };
}

function outputBuffer(output: {
  readonly address?: string;
  readonly paramIndex: number;
  readonly word: number;
}): CapturedBufferOutput {
  const bytes = recordBytes(output.word);
  return {
    paramIndex: output.paramIndex,
    direction: "inout",
    isString: false,
    elementSize: RECORD_BYTES,
    byteLength: bytes.byteLength,
    fnv1a64: fnv1a64(bytes),
    prefixHex: hexBytes(bytes),
    ...(output.address === undefined ? {} : { storageAddress: output.address }),
  };
}

function event(input: {
  readonly generation: number;
  readonly callSeq: number;
  readonly selectorOrdinal: number;
  readonly selectorSeq: number;
  readonly bufferInputs?: CapturedBufferInput[];
  readonly bufferOutputs?: CapturedBufferOutput[];
}): CallCaptureEvent {
  return {
    generation: input.generation,
    callSeq: input.callSeq,
    selectorOrdinal: input.selectorOrdinal,
    selectorSeq: input.selectorSeq,
    transportStatus: 0,
    scalarInputs: [],
    ...(input.bufferInputs === undefined ? {} : { bufferInputs: input.bufferInputs }),
    ...(input.bufferOutputs === undefined ? {} : { bufferOutputs: input.bufferOutputs }),
    retval: null,
    scalarOutputs: [],
    mutation: null,
  };
}

function capture(events: CallCaptureEvent[]): CallCaptureDocument {
  return {
    bundleManifestSha256: MANIFEST_HASH,
    marshalLayoutSha256: LAYOUT_HASH,
    runId: RUN_ID,
    events,
    end: {
      processReturnCode: 0,
      termination: "exited",
      timedOut: false,
      complete: true,
      ecallCount: events.length,
      targetMatchCount: 0,
      mutationAppliedCount: 0,
      incompleteReasons: [],
    },
  };
}

function marshalParameter(input: {
  readonly ordinal: number;
  readonly paramIndex: number;
  readonly record: boolean;
}): MarshalParameter {
  return {
    ordinal: input.ordinal,
    paramIndex: input.paramIndex,
    replaySupported: true,
    isPointer: input.record,
    form: input.record ? "pointer" : "value",
    userCheck: false,
    elementSize: input.record ? RECORD_BYTES : null,
    elementTypeCategory: input.record ? "record" : null,
    boundKind: null,
    boundParameterIndex: null,
  };
}

function switchSite(input: { readonly functionName: string; readonly ordinal: number }): Record<string, unknown> {
  return {
    site_id: "irsite_" + String(input.ordinal).padStart(32, "0"),
    function: input.functionName,
    function_linkage: "external",
    block_ordinal: 0,
    instruction_ordinal: 0,
    source: { file: "planner-fixture.c", line: input.ordinal },
    kind: "switch",
    width_bits: 32,
    selector: { operand: 0, status: "dynamic", value_ref: "%tag" },
    default_target: "default",
    cases: [0, 2, 3, 4].map((value) => ({
      value: String(value),
      status: "constant",
      target: "case_" + value,
    })),
  };
}

function profile(): ExplorerProfile {
  const producerFunction = "producer_function";
  const consumerFunction = "consumer_function";
  const profileBundle: ProfileBundle = {
    root: "/fixture",
    manifestPath: "/fixture/manifest.json",
    manifestSha256: MANIFEST_HASH,
    layoutEpoch: "fixture",
    pageSize: 4096,
    capacityQ: 4096,
    ordinaryLoadEnd: 0n,
    pretouchStart: 0n,
    identity: {
      profileElfSha256: MANIFEST_HASH,
      signedProfileElfSha256: MANIFEST_HASH,
      edlAbiSha256: MANIFEST_HASH,
      fieldsSha256: MANIFEST_HASH,
    },
    marshalLayout: {},
    marshalLayoutSha256: LAYOUT_HASH,
    collectorLayoutSpec: "fixture",
    artifactDigests: new Map<string, string>(),
    artifactPaths: new Map<string, string>(),
    pageUniverse: new Map<bigint, PageUniverseEntry>(),
    fields: [],
    fieldById: new Map<string, ProfileField>(),
    selectors: [],
    selectorByOrdinal: new Map<number, ProfileSelector>(),
  };
  const producerMarshal: MarshalEcall = {
    ordinal: SELECTOR.producer,
    replaySupported: true,
    params: [
      marshalParameter({ ordinal: SELECTOR.producer, paramIndex: 0, record: false }),
      marshalParameter({ ordinal: SELECTOR.producer, paramIndex: 5, record: true }),
    ],
  };
  const consumerMarshal: MarshalEcall = {
    ordinal: SELECTOR.consumer,
    replaySupported: true,
    params: [
      marshalParameter({ ordinal: SELECTOR.consumer, paramIndex: 4, record: false }),
      marshalParameter({ ordinal: SELECTOR.consumer, paramIndex: 1, record: true }),
    ],
  };
  const fact = {
    schema: "atfield-ir-facts-v2",
    translation_unit: "planner-fixture.o",
    module_id: "irtu_" + "01".repeat(16),
    source: { input_file: "planner-fixture.c", ir_filename: "planner-fixture.ll" },
    complete: true,
    definitions: [producerFunction, consumerFunction].map((symbol, index) => ({
      symbol,
      linkage: "external",
      source_file: "planner-fixture.c",
      line: index + 1,
    })),
    direct_calls: [],
    unknown_indirect: [],
    guidance_sites: [
      switchSite({ functionName: producerFunction, ordinal: 1 }),
      switchSite({ functionName: consumerFunction, ordinal: 2 }),
    ],
  };
  return {
    bundle: profileBundle,
    binding: { bundleManifestSha256: MANIFEST_HASH, marshalLayoutSha256: LAYOUT_HASH },
    edlAbiSha256: MANIFEST_HASH,
    marshalSpecSha256: LAYOUT_HASH,
    marshalSpecBytes: new Uint8Array(),
    abi: {
      ecalls: [
        { ordinal: SELECTOR.producer, name: producerFunction, visibility: "public" },
        { ordinal: SELECTOR.consumer, name: consumerFunction, visibility: "public" },
      ],
    },
    ecalls: new Map<number, MarshalEcall>([
      [SELECTOR.producer, producerMarshal],
      [SELECTOR.consumer, consumerMarshal],
    ]),
    scalarParameters: [],
    scalarParameterByKey: new Map<string, ScalarParameter>(),
    irFacts: [fact],
    reachability: [
      {
        ordinal: SELECTOR.producer,
        reachable_functions: [producerFunction],
        reachable_fields: ["fixture-field"],
        unknown_indirect: false,
        unknown_external: false,
        function_closure_complete: true,
      },
      {
        ordinal: SELECTOR.consumer,
        reachable_functions: [consumerFunction],
        reachable_fields: ["fixture-field"],
        unknown_indirect: false,
        unknown_external: false,
        function_closure_complete: true,
      },
    ],
  };
}

function encodeAll(profileValue: ExplorerProfile, plans: ReturnType<typeof deriveCandidatesFromCase>): Uint8Array[] {
  return plans.map((plan) => encodeMutationSpec(profileValue.binding, plan.rule));
}

test("planner emits one producer write with a verified consumer dataflow target", () => {
  // Given: several calls reuse one object, another object has equal bytes, and producer/consumer parameter indices differ.
  const profileValue = profile();
  const baseline = capture([
    event({
      generation: 1,
      callSeq: 0,
      selectorOrdinal: SELECTOR.producer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "inout", paramIndex: 5, word: 0 })],
      bufferOutputs: [outputBuffer({ address: ADDRESS_A, paramIndex: 5, word: 1 })],
    }),
    event({
      generation: 1,
      callSeq: 1,
      selectorOrdinal: SELECTOR.producer,
      selectorSeq: 1,
      bufferInputs: [inputBuffer({ address: ADDRESS_B, direction: "inout", paramIndex: 5, word: 0 })],
      bufferOutputs: [outputBuffer({ address: ADDRESS_B, paramIndex: 5, word: 1 })],
    }),
    event({
      generation: 1,
      callSeq: 2,
      selectorOrdinal: SELECTOR.producer,
      selectorSeq: 2,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "inout", paramIndex: 5, word: 2 })],
      bufferOutputs: [outputBuffer({ address: ADDRESS_A, paramIndex: 5, word: 2 })],
    }),
    event({
      generation: 1,
      callSeq: 3,
      selectorOrdinal: SELECTOR.consumer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ address: ADDRESS_C, direction: "in", paramIndex: 1, word: 2 })],
    }),
    event({
      generation: 1,
      callSeq: 4,
      selectorOrdinal: SELECTOR.consumer,
      selectorSeq: 1,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "in", paramIndex: 1, word: 2 })],
    }),
  ]);

  // When: the real planner derives candidates and each candidate is passed to the real binary encoder.
  const edges = inferCaptureProducerConsumerFlow(baseline);
  const plans = deriveCandidatesFromCase(profileValue, baseline, {
    budget: 10000,
    includeHistory: false,
  });
  const encoded = encodeAll(profileValue, plans);

  // Then: only the latest same-object producer binds; alternatives stay separate and carry its own ABI parameter index.
  const verifiedEdge = edges.find((edge) => edge.consumer.callSeq === 4 && edge.identityVerified);
  expect(verifiedEdge?.producer.callSeq).toBe(2);
  expect(verifiedEdge?.producer.selectorOrdinal).toBe(SELECTOR.producer);
  expect(verifiedEdge?.producer.paramIndex).toBe(5);
  expect(edges.some((edge) => edge.consumer.callSeq === 3 && edge.identityVerified)).toBe(false);
  expect(edges.some((edge) => edge.consumer.callSeq === 3 && !edge.identityVerified)).toBe(true);

  if (!verifiedEdge) throw new Error("expected a verified producer edge for the latest object version");
  expect(validateProducerConsumerBinding(verifiedEdge, {
    runId: RUN_ID,
    currentRunId: RUN_ID,
    instanceGeneration: 1,
    objectVersion: verifiedEdge.producer.objectVersion,
    latestObjectVersion: verifiedEdge.producer.objectVersion,
    byteLength: RECORD_BYTES,
    elementSize: RECORD_BYTES,
    verifiedIdentity: true,
    storageAddress: ADDRESS_A,
    producerCallSeq: 2,
    producerParamIndex: 5,
  })).toEqual({ valid: true, reason: null });

  const linked = plans.filter((plan) =>
    plan.rule.dataflowTarget?.consumerSelectorOrdinal === SELECTOR.consumer &&
    plan.rule.dataflowTarget.consumerSelectorSeq === 1 &&
    plan.rule.dataflowTarget.consumerByteOffset === 0);
  expect(linked).toHaveLength(3);
  expect(linked.map((plan) => plan.rule.replacementBits).sort()).toEqual([
    "0x00000000",
    "0x00000003",
    "0x00000004",
  ]);
  expect(new Set(linked.map((plan) => mutationRuleKey(plan.rule))).size).toBe(3);

  const additionalGenerationEvents = Array.from({ length: 6 }, (_, index) => {
    const generation = index + 2;
    const producerCallSeq = 5 + index * 2;
    return [
      event({
        generation,
        callSeq: producerCallSeq,
        selectorOrdinal: SELECTOR.producer,
        selectorSeq: 0,
        bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "inout", paramIndex: 5, word: 2 })],
        bufferOutputs: [outputBuffer({ address: ADDRESS_A, paramIndex: 5, word: 2 })],
      }),
      event({
        generation,
        callSeq: producerCallSeq + 1,
        selectorOrdinal: SELECTOR.consumer,
        selectorSeq: 0,
        bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "in", paramIndex: 1, word: 2 })],
      }),
    ];
  }).flat();
  const reservationBaseline = capture([...baseline.events, ...additionalGenerationEvents]);
  const reservationPlans = deriveCandidatesFromCase(profileValue, reservationBaseline, {
    budget: 10000,
    includeHistory: false,
  });
  const linkedKeyForConsumer = (generation: number, selectorSeq: number): string => {
    const plan = reservationPlans.find((item) =>
      item.rule.dataflowTarget?.consumerGeneration === generation &&
      item.rule.dataflowTarget.consumerSelectorSeq === selectorSeq);
    const key = plan ? linkedConsumerCallKey(plan.rule) : null;
    if (!key) throw new Error("expected a linked plan for consumer generation " + generation);
    return key;
  };
  const measuredConsumerKeys = new Set([
    linkedKeyForConsumer(1, 1),
    ...Array.from({ length: 4 }, (_, index) => linkedKeyForConsumer(index + 2, 0)),
  ]);
  const prioritizedPlans = deriveCandidatesFromCase(profileValue, reservationBaseline, {
    budget: 6,
    includeHistory: false,
    measuredFieldCallKeys: measuredConsumerKeys,
  });
  const unreservedPlans = deriveCandidatesFromCase(profileValue, reservationBaseline, {
    budget: 6,
    includeHistory: false,
  });
  const unreservedLinkedKeys = new Set(unreservedPlans.flatMap((plan) => {
    const key = linkedConsumerCallKey(plan.rule);
    return key === null ? [] : [key];
  }));
  const prioritizedLinkedKeys = prioritizedPlans.flatMap((plan) => {
    const key = linkedConsumerCallKey(plan.rule);
    return key === null ? [] : [key];
  });
  expect(prioritizedLinkedKeys).toHaveLength(6);
  expect(prioritizedLinkedKeys.slice(0, 5).every((key) => measuredConsumerKeys.has(key))).toBe(true);
  expect(new Set(prioritizedLinkedKeys.slice(0, 5))).toEqual(measuredConsumerKeys);
  expect(measuredConsumerKeys.has(prioritizedLinkedKeys[5]!)).toBe(false);
  expect([...measuredConsumerKeys].some((key) => !unreservedLinkedKeys.has(key))).toBe(true);
  expect(reserveLinkedConsumerCallKeys(prioritizedPlans, measuredConsumerKeys, 1))
    .toEqual(prioritizedLinkedKeys.slice(0, 1));
  expect(reserveLinkedConsumerCallKeys(prioritizedPlans, measuredConsumerKeys, 5))
    .toEqual(prioritizedLinkedKeys.slice(0, 5));
  expect(reserveLinkedConsumerCallKeys(prioritizedPlans, measuredConsumerKeys, 6))
    .toEqual(prioritizedLinkedKeys);

  for (const plan of linked) {
    expect(plan.rule.opKind).toBe("mutate_buffer");
    expect(plan.rule.bufferSubOp).toBe("write_le");
    expect(plan.rule.execMode).toBe(0);
    expect(plan.rule.selectorOrdinal).toBe(SELECTOR.producer);
    expect(plan.rule.selectorSeq).toBe(2);
    expect(plan.rule.paramIndex).toBe(5);
    expect(plan.rule.byteOffset).toBe(0);
    expect(plan.rule.widthBytes).toBe(4);
    expect(plan.rule.expectedBits).toBe("0x00000002");
    expect(plan.rule.prefixMutations).toBeUndefined();
    expect(plan.rule.dataflowTarget).toMatchObject({
      consumerGeneration: 1,
      consumerCallSeq: 4,
      consumerSelectorOrdinal: SELECTOR.consumer,
      consumerSelectorSeq: 1,
      consumerParamIndex: 1,
      consumerByteOffset: 0,
      consumerWidthBytes: 4,
      baselineBits: "0x00000002",
      propagatedBits: plan.rule.replacementBits,
      bufferByteLength: RECORD_BYTES,
      elementSize: RECORD_BYTES,
    });
    const bytes = encodeMutationSpec(profileValue.binding, plan.rule);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ruleOffset = MUTATION_SPEC_HEADER_BYTES;
    const opOffset = ruleOffset + MUTATION_SPEC_RULE_BYTES;
    expect(view.getUint16(ruleOffset + 20, true)).toBe(1);
    expect(view.getUint16(opOffset, true)).toBe(2);
    expect(view.getUint16(opOffset + 2, true)).toBe(3);
    expect(view.getUint32(ruleOffset + 8, true)).toBe(SELECTOR.producer);
    expect(Number(view.getBigUint64(ruleOffset + 12, true))).toBe(2);
    expect(view.getUint32(opOffset + 8, true)).toBe(5);
    expect(bytes.byteLength).toBe(MUTATION_SPEC_HEADER_BYTES + MUTATION_SPEC_RULE_BYTES + MUTATION_SPEC_SCALAR_OP_BYTES);
  }
  const keyedPlan = linked[0];
  if (!keyedPlan?.rule.dataflowTarget) throw new Error("expected a linked plan for identity checks");
  const baseKey = mutationRuleKey(keyedPlan.rule);
  expect(mutationRuleKey({
    ...keyedPlan.rule,
    dataflowTarget: {
      ...keyedPlan.rule.dataflowTarget,
      consumerSelectorSeq: keyedPlan.rule.dataflowTarget.consumerSelectorSeq + 1,
    },
  })).not.toBe(baseKey);
  expect(mutationRuleKey({
    ...keyedPlan.rule,
    dataflowTarget: {
      ...keyedPlan.rule.dataflowTarget,
      consumerParamIndex: keyedPlan.rule.dataflowTarget.consumerParamIndex + 1,
    },
  })).not.toBe(baseKey);
  expect(() => encodeMutationSpec(profileValue.binding, {
    ...keyedPlan.rule,
    dataflowTarget: {
      ...keyedPlan.rule.dataflowTarget,
      propagatedBits: "0x00000002",
    },
  })).toThrow(/dataflowTarget values differ/);
  expect(() => encodeMutationSpec(profileValue.binding, {
    ...keyedPlan.rule,
    dataflowTarget: {
      ...keyedPlan.rule.dataflowTarget,
      consumerGeneration: 2,
    },
  })).toThrow(/dataflowTarget is outside/);
  expect(() => encodeMutationSpec(profileValue.binding, {
    ...keyedPlan.rule,
    dataflowTarget: {
      ...keyedPlan.rule.dataflowTarget,
      bufferByteLength: 3,
    },
  })).toThrow(/dataflowTarget is outside/);
  expect(() => encodeMutationSpec(profileValue.binding, {
    ...keyedPlan.rule,
    execMode: 1,
  })).toThrow(/dataflowTarget requires/);
  expect(mutationRuleKey({ ...keyedPlan.rule, widthBytes: 8 })).not.toBe(baseKey);
  expect(mutationRuleKey({ ...keyedPlan.rule, signedness: "signed" })).not.toBe(baseKey);
  expect(mutationRuleKey({
    ...keyedPlan.rule,
    expansionBudget: { perBufferBytes: 4096, totalBytes: 8192 },
  })).not.toBe(baseKey);
  expect(encoded).toHaveLength(plans.length);

  const boundedPlans = deriveCandidatesFromCase(profileValue, baseline, {
    budget: 2,
    includeHistory: false,
  });
  expect(boundedPlans).toHaveLength(2);
  expect(boundedPlans.some((plan) => plan.rule.dataflowTarget !== undefined)).toBe(true);
  expect(boundedPlans.some((plan) =>
    plan.rule.dataflowTarget === undefined &&
    plan.rule.opKind === "mutate_buffer" &&
    plan.rule.bufferSubOp === "write_le" &&
    (plan.rule.execMode ?? 0) === 0 &&
    plan.rule.selectorOrdinal === SELECTOR.producer &&
    plan.rule.selectorSeq === 2 &&
    plan.rule.paramIndex === 5)).toBe(true);

  const transformedBaseline = capture(baseline.events.map((entry) =>
    entry.callSeq === 2
      ? {
          ...entry,
          bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "inout", paramIndex: 5, word: 0 })],
        }
      : entry));
  const transformedPlans = deriveCandidatesFromCase(profileValue, transformedBaseline, {
    budget: 10000,
    includeHistory: false,
  });
  expect(transformedPlans.every((plan) => {
    const target = plan.rule.dataflowTarget;
    return target === undefined ||
      target.consumerSelectorOrdinal !== SELECTOR.consumer ||
      target.consumerSelectorSeq !== 1 ||
      target.consumerByteOffset !== 0;
  })).toBe(true);

  const truncatedBaseline = capture(baseline.events.map((entry) => ({
    ...entry,
    bufferInputs: entry.bufferInputs?.map((buffer) =>
      buffer.storageAddress === ADDRESS_A ? { ...buffer, byteLength: RECORD_BYTES + 1 } : buffer),
    bufferOutputs: entry.bufferOutputs?.map((buffer) =>
      buffer.storageAddress === ADDRESS_A ? { ...buffer, byteLength: RECORD_BYTES + 1 } : buffer),
  })));
  const truncatedPlans = deriveCandidatesFromCase(profileValue, truncatedBaseline, {
    budget: 10000,
    includeHistory: false,
  });
  expect(truncatedPlans.every((plan) => plan.rule.dataflowTarget === undefined)).toBe(true);
});

test("planner skips cross-generation producers because the encoded prefix has no generation field", () => {
  // Given: equal address and content across two enclave generations.
  const profileValue = profile();
  const baseline = capture([
    event({
      generation: 1,
      callSeq: 0,
      selectorOrdinal: SELECTOR.producer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "inout", paramIndex: 5, word: 0 })],
      bufferOutputs: [outputBuffer({ address: ADDRESS_A, paramIndex: 5, word: 2 })],
    }),
    event({
      generation: 2,
      callSeq: 1,
      selectorOrdinal: SELECTOR.consumer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "in", paramIndex: 1, word: 2 })],
    }),
  ]);

  // When: inference and candidate planning run across the generation boundary.
  const edges = inferCaptureProducerConsumerFlow(baseline);
  const plans = deriveCandidatesFromCase(profileValue, baseline, {
    budget: 10000,
    includeHistory: false,
  });

  // Then: no cross-generation dataflow edge or prefix mutation is executable.
  expect(edges).toHaveLength(0);
  expect(plans.every((plan) => plan.rule.prefixMutations === undefined)).toBe(true);
  expect(encodeAll(profileValue, plans)).toHaveLength(plans.length);
});

test("planner treats missing addresses and future producers as non-executable hints", () => {
  // Given: one capture lacks identity and another places the producer after the consumer.
  const profileValue = profile();
  const missingAddress = capture([
    event({
      generation: 1,
      callSeq: 0,
      selectorOrdinal: SELECTOR.producer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ direction: "inout", paramIndex: 5, word: 0 })],
      bufferOutputs: [outputBuffer({ paramIndex: 5, word: 2 })],
    }),
    event({
      generation: 1,
      callSeq: 1,
      selectorOrdinal: SELECTOR.consumer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ direction: "in", paramIndex: 1, word: 2 })],
    }),
  ]);
  const futureProducer = capture([
    event({
      generation: 1,
      callSeq: 0,
      selectorOrdinal: SELECTOR.consumer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "in", paramIndex: 1, word: 2 })],
    }),
    event({
      generation: 1,
      callSeq: 1,
      selectorOrdinal: SELECTOR.producer,
      selectorSeq: 0,
      bufferInputs: [inputBuffer({ address: ADDRESS_A, direction: "inout", paramIndex: 5, word: 0 })],
      bufferOutputs: [outputBuffer({ address: ADDRESS_A, paramIndex: 5, word: 2 })],
    }),
  ]);

  // When: the real planner derives plans for both captures.
  const missingEdges = inferCaptureProducerConsumerFlow(missingAddress);
  const missingPlans = deriveCandidatesFromCase(profileValue, missingAddress, {
    budget: 10000,
    includeHistory: false,
  });
  const futureEdges = inferCaptureProducerConsumerFlow(futureProducer);
  const futurePlans = deriveCandidatesFromCase(profileValue, futureProducer, {
    budget: 10000,
    includeHistory: false,
  });

  // Then: identityless digest matches remain hints; no prefix points forward in time.
  expect(missingEdges.length).toBeGreaterThan(0);
  expect(missingEdges.every((edge) => !edge.identityVerified)).toBe(true);
  expect(missingPlans.every((plan) => plan.rule.prefixMutations === undefined)).toBe(true);
  expect(futureEdges).toHaveLength(0);
  expect(futurePlans.every((plan) => plan.rule.prefixMutations === undefined)).toBe(true);
  expect(encodeAll(profileValue, missingPlans)).toHaveLength(missingPlans.length);
  expect(encodeAll(profileValue, futurePlans)).toHaveLength(futurePlans.length);
});
