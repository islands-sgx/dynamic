import { expect, test } from "bun:test";
import { linkedDataflowFailure, type LinkedRunEvidence } from "../../lib/explorer/linked-proof.ts";
import type { CallCaptureDocument, CallCaptureEvent, ScalarMutationRule } from "../../lib/explorer/contract.ts";

const oldBytes = "03000000aabbccdd";
const newBytes = "01000000aabbccdd";
const location = "0x0000000000001000";
const buffer = (prefixHex: string, direction: "in" | "inout") => ({
  paramIndex: 0, direction, isString: false, elementSize: 4, byteLength: 8,
  fnv1a64: "0x0000000000000001", prefixHex, storageAddress: location,
});
const event = (callSeq: number, selectorOrdinal: number, bytes: string, mutation: CallCaptureEvent["mutation"] = null): CallCaptureEvent => ({
  generation: 1, callSeq, selectorOrdinal, selectorSeq: 0, transportStatus: 0,
  scalarInputs: [], bufferInputs: [buffer(bytes, callSeq === 1 ? "inout" : "in")],
  bufferOutputs: callSeq === 1 ? [buffer(bytes, "inout")] : [],
  retval: null, scalarOutputs: [], mutation,
});
const applied = {
  paramIndex: 0, widthBytes: 4 as const, signedness: "unsigned" as const,
  expectedBits: "0x00000003", observedBits: "0x00000003",
  replacementBits: "0x00000001", applied: true, reason: "applied",
  byteOffset: 0,
};
const document = (bytes: string, changed: boolean): CallCaptureDocument => ({
  bundleManifestSha256: "a".repeat(64), marshalLayoutSha256: "b".repeat(64), runId: changed ? "candidate" : "baseline",
  events: [event(1, 1, bytes, changed ? applied : null), event(2, 2, bytes)],
  end: {
    processReturnCode: 0, termination: "exited", timedOut: false, complete: true,
    ecallCount: 2, targetMatchCount: changed ? 1 : 0,
    mutationAppliedCount: changed ? 1 : 0, incompleteReasons: [],
  },
});
const rule: ScalarMutationRule = {
  opKind: "mutate_buffer", bufferSubOp: "write_le", execMode: 0,
  selectorOrdinal: 1, selectorSeq: 0, paramIndex: 0, byteOffset: 0, sliceLength: 4,
  widthBytes: 4, signedness: "unsigned", expectedBits: "0x00000003",
  replacementBits: "0x00000001",
  dataflowTarget: {
    consumerGeneration: 1, consumerCallSeq: 2, consumerSelectorOrdinal: 2, consumerSelectorSeq: 0,
    consumerParamIndex: 0, consumerByteOffset: 0, consumerWidthBytes: 4,
    baselineBits: "0x00000003", propagatedBits: "0x00000001",
    bufferByteLength: 8, elementSize: 4,
  },
};
const trace = (fields: unknown[] = [{}]): LinkedRunEvidence => ({
  complete: true, exitCode: 0, traceValid: true,
  traceText: JSON.stringify({
    record_type: "ecall", instance_generation: 1, call_seq: 2,
    selector_ordinal: 2, selector_seq: 0, measurement_valid: true, fields,
  }) + "\n",
});

test("producer-only linked proof checks the complete transferred buffer and measured consumer", () => {
  expect(linkedDataflowFailure(document(oldBytes, false), document(newBytes, true), rule, trace())).toBeNull();
});

test("linked proof rejects a consumer missing from the real call sequence", () => {
  const candidate = document(newBytes, true);
  candidate.events.pop();
  expect(linkedDataflowFailure(document(oldBytes, false), candidate, rule, trace())).toContain("consumer call is missing");
});

test("linked proof rejects mismatched and incomplete transferred bytes", () => {
  const candidate = document(newBytes, true);
  candidate.events[1]!.bufferInputs![0]!.prefixHex = oldBytes;
  expect(linkedDataflowFailure(document(oldBytes, false), candidate, rule, trace())).toContain("output differs");
  candidate.events[1]!.bufferInputs![0]!.prefixHex = newBytes.slice(0, 8);
  expect(linkedDataflowFailure(document(oldBytes, false), candidate, rule, trace())).toContain("complete buffer capture");
});

test("linked proof requires the consumer to enter a valid measured Field", () => {
  expect(linkedDataflowFailure(document(oldBytes, false), document(newBytes, true), rule, trace([]))).toContain("measured Field");
});

test("linked proof requires baseline buffer identity and forbids a disguised consumer write", () => {
  const baseline = document(oldBytes, false);
  baseline.events[1]!.bufferInputs![0]!.storageAddress = "0x0000000000002000";
  expect(linkedDataflowFailure(baseline, document(newBytes, true), rule, trace())).toContain("identity is unproven");
  const forged = { ...rule, prefixMutations: [{ selectorOrdinal: 1, selectorSeq: 1, paramIndex: 0, byteOffset: 0,
    widthBytes: 4 as const, expectedBits: "0x00000003", replacementBits: "0x00000001" }] };
  expect(linkedDataflowFailure(document(oldBytes, false), document(newBytes, true), forged, trace())).toContain("does not match");
});
