import { describe, expect, test } from "bun:test";
import {
  FORMAL_SAMPLES, formalTargetsAccepted, hasAppliedCoupledEvidence, validateSampleSelection,
} from "../../tools/validate-milestone.ts";
import { linkedDataflowFailure } from "../../lib/explorer/linked-proof.ts";
import type { CallCaptureDocument, CallCaptureEvent, ScalarMutationRule } from "../../lib/explorer/contract.ts";

const binding = { bundleManifestSha256: "11".repeat(32), marshalLayoutSha256: "22".repeat(32) };
const attempt = {
  status: "run_finished",
  runId: "run-coupled",
  mutation: {
    opKind: "mutate_buffer", targetGeneration: 1, execMode: 1,
    selectorOrdinal: 2, selectorSeq: 0, paramIndex: 7,
    prefixMutations: [{
      selectorOrdinal: 1, selectorSeq: 0, paramIndex: 5,
      byteOffset: 0, widthBytes: 4, expectedBits: "0x00000000", replacementBits: "0x00000003",
    }],
  },
};
function capture(prefixApplied = true): string {
  const records = [
    {
      type: "capture_start", schema: "atfield-call-capture-v1", run_id: "run-coupled",
      bundle_manifest_sha256: binding.bundleManifestSha256,
      marshal_layout_sha256: binding.marshalLayoutSha256,
    },
    {
      type: "ecall", schema: "atfield-call-capture-v1", generation: 1, call_seq: 0,
      selector_ordinal: 1, selector_seq: 0, transport_status: 0,
      scalar_inputs: [], retval: null, scalar_outputs: [],
      mutation: {
        param_index: 5, width_bytes: 4, byte_offset: 0, signedness: "unsigned",
        expected_bits: "0x00000000", observed_bits: "0x00000000",
        replacement_bits: "0x00000003", applied: prefixApplied,
        reason: prefixApplied ? "applied" : "expected_value_mismatch",
      },
    },
    {
      type: "ecall", schema: "atfield-call-capture-v1", generation: 1, call_seq: 1,
      selector_ordinal: 2, selector_seq: 0, transport_status: 0,
      scalar_inputs: [], retval: null, scalar_outputs: [],
      mutation: {
        param_index: 7, width_bytes: 4, byte_offset: 0, signedness: "unsigned",
        expected_bits: "0x00000001", observed_bits: "0x00000001",
        replacement_bits: "0x00000002", applied: true, reason: "applied",
      },
    },
    {
      type: "capture_end", schema: "atfield-call-capture-v1", process_return_code: 0,
      termination: "exited", timed_out: false, complete: true, ecall_count: 2,
      target_match_count: 1, mutation_applied_count: prefixApplied ? 2 : 1, incomplete_reasons: [],
    },
  ];
  return records.map((item) => JSON.stringify(item)).join("\n") + "\n";
}


function linkedFixture(candidateConsumerHex = "04000000", includeCandidateConsumer = true) {
  const bytes = (prefixHex: string, kind: "input" | "output", paramIndex: number) => ({
    paramIndex,
    direction: "inout",
    isString: false,
    elementSize: 4,
    byteLength: 4,
    fnv1a64: "0x0000000000000000",
    storageAddress: "0x0000000000001000",
    prefixHex,
  });
  const event = (
    callSeq: number, selectorOrdinal: number, paramIndex: number, prefixHex: string,
    mutation: CallCaptureEvent["mutation"] = null, producer = false,
  ): CallCaptureEvent => ({
    generation: 1, callSeq, selectorOrdinal, selectorSeq: 0, transportStatus: 0,
    scalarInputs: [], retval: null, scalarOutputs: [], mutation,
    bufferInputs: [bytes(prefixHex, "input", paramIndex)],
    ...(producer ? { bufferOutputs: [bytes(prefixHex, "output", paramIndex)] } : {}),
  });
  const document = (events: CallCaptureEvent[]): CallCaptureDocument => ({
    ...binding,
    runId: "linked-run",
    events,
    end: {
      processReturnCode: 0, termination: "exited", timedOut: false, complete: true,
      ecallCount: events.length, targetMatchCount: 1, mutationAppliedCount: 1, incompleteReasons: [],
    },
  });
  const baselineBytes = "03000000";
  const baseline = document([
    event(0, 1, 5, baselineBytes, null, true),
    event(1, 2, 7, baselineBytes),
  ]);
  const candidateEvents = [
    event(0, 1, 5, "04000000", {
      paramIndex: 5, widthBytes: 4, signedness: "unsigned",
      expectedBits: "0x00000003", observedBits: "0x00000003",
      replacementBits: "0x00000004", applied: true, reason: "applied", byteOffset: 0,
    }, true),
  ];
  if (includeCandidateConsumer) candidateEvents.push(event(1, 2, 7, candidateConsumerHex));
  const candidate = document(candidateEvents);
  const rule: ScalarMutationRule = {
    opKind: "mutate_buffer", bufferSubOp: "write_le", execMode: 0,
    selectorOrdinal: 1, selectorSeq: 0, paramIndex: 5,
    byteOffset: 0, sliceLength: 4, widthBytes: 4, signedness: "unsigned",
    expectedBits: "0x00000003", replacementBits: "0x00000004",
    dataflowTarget: {
      consumerGeneration: 1, consumerCallSeq: 1, consumerSelectorOrdinal: 2,
      consumerSelectorSeq: 0, consumerParamIndex: 7, consumerByteOffset: 0,
      consumerWidthBytes: 4, baselineBits: "0x00000003", propagatedBits: "0x00000004",
      bufferByteLength: 4, elementSize: 4,
    },
  };
  const traceText = JSON.stringify({
    record_type: "ecall", instance_generation: 1, call_seq: 1,
    selector_ordinal: 2, selector_seq: 0, measurement_valid: true, fields: [{ field_id: "f" }],
  }) + "\n";
  return { baseline, candidate, rule, run: { complete: true, exitCode: 0, traceText, traceValid: true } };
}


describe("formal milestone acceptance gates", () => {
  test("formal mode requires six configurations, executed candidate budget, and opportunity-driven linked proof", () => {
    expect(FORMAL_SAMPLES).toHaveLength(6);
    expect(() => validateSampleSelection(["ehsm"], false)).toThrow(/six configured samples/);
    expect(() => validateSampleSelection([...FORMAL_SAMPLES].slice(1), false)).toThrow(/six configured samples/);
    expect(() => validateSampleSelection(["ehsm"], true)).not.toThrow();
    expect(() => validateSampleSelection(["ehsm", "ehsm"], true)).toThrow(/unique/);
    const phase = (name: string, candidateRuns = 16, acceptedCompleteCandidates = 1,
      linkedExecutions = 0) => ({ name, attempt: 0, valid: true, candidateRuns, acceptedCompleteCandidates, linkedExecutions,
        coldOpportunities: 0, coldTransfers: 0, coldProofFailures: [] });
    const target = (sample: string, candidateRuns = 16, acceptedCompleteCandidates = 1,
      linkedEncodable = 0, linkedExecutions = 0, coupledEncodable = 0) => ({
      sample, valid: true,
      planningAudits: [
        { phase: "default", attempt: 0, coupledEncodable, linkedEncodable },
        { phase: "self-test", attempt: 0, coupledEncodable, linkedEncodable },
      ],
      phases: [phase("default", candidateRuns, acceptedCompleteCandidates, linkedExecutions),
        phase("self-test", candidateRuns, acceptedCompleteCandidates, linkedExecutions)],
    });
    const baselineGreenWithoutCandidates = FORMAL_SAMPLES.map((sample) => target(sample, 0, 0));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, baselineGreenWithoutCandidates, [], 16)).toBe(false);
    const complete = FORMAL_SAMPLES.map((sample) => target(sample));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, complete, [], 16)).toBe(true);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, complete.slice(1), [], 16)).toBe(false);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, complete.map((item, i) =>
      i === 2 ? { ...item, valid: false } : item), [], 16)).toBe(false);
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample) => target(sample, 16, 0)), [], 16)).toBe(false);
    // Historical prefix-only opportunity is informational; linked proof has its own gate.
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample, i) => target(sample, 16, 1, 0, 0, i === 3 ? 96 : 0)), [], 16)).toBe(true);
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample, i) => target(sample, 16, 1, i === 3 ? 96 : 0, 0)), [], 16)).toBe(false);
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample, i) => target(sample, 16, 1, i === 3 ? 96 : 0, i === 3 ? 1 : 0)), [], 16)).toBe(true);
    const coldOpportunityUnproved = FORMAL_SAMPLES.map((sample, i) => ({
      ...target(sample),
      phases: [i === 2 ? { ...phase("default"), coldOpportunities: 1 } : phase("default"), phase("self-test")],
    }));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, coldOpportunityUnproved, [], 16)).toBe(false);
    const coldOpportunityProved = coldOpportunityUnproved.map((item, i) => i === 2
      ? { ...item, phases: [{ ...phase("default"), coldOpportunities: 1, coldTransfers: 1 }, phase("self-test")] }
      : item);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, coldOpportunityProved, [], 16)).toBe(true);
    const retryAfterInvalidBaseline = FORMAL_SAMPLES.map((sample, i) => i === 3 ? {
      ...target(sample, 16, 1, 1, 1),
      planningAudits: [
        { phase: "default", attempt: 1, coupledEncodable: 0, linkedEncodable: 1 },
        { phase: "self-test", attempt: 0, coupledEncodable: 0, linkedEncodable: 1 },
      ],
      phases: [
        { ...phase("default", 0, 0), valid: false },
        { ...phase("default", 16, 1, 1), attempt: 1 },
        phase("self-test", 16, 1, 1),
      ],
    } : target(sample));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, retryAfterInvalidBaseline, [], 16)).toBe(true);
    const executionInWrongPhase = FORMAL_SAMPLES.map((sample, i) => ({
      sample, valid: true,
      planningAudits: [
        { phase: "default", attempt: 0, coupledEncodable: 0, linkedEncodable: i === 3 ? 96 : 0 },
        { phase: "self-test", attempt: 0, coupledEncodable: 0, linkedEncodable: 0 },
      ],
      phases: [phase("default", 16, 1, 0), phase("self-test", 16, 1, i === 3 ? 1 : 0)],
    }));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, executionInWrongPhase, [], 16)).toBe(false);
  });

  test("linked proof requires a real measured consumer and byte-for-byte propagation", () => {
    const good = linkedFixture();
    expect(linkedDataflowFailure(good.baseline, good.candidate, good.rule, good.run)).toBeNull();
    const missing = linkedFixture("04000000", false);
    expect(linkedDataflowFailure(missing.baseline, missing.candidate, missing.rule, missing.run)).toMatch(/consumer call is missing/);
    const mismatch = linkedFixture("03000000", true);
    expect(linkedDataflowFailure(mismatch.baseline, mismatch.candidate, mismatch.rule, mismatch.run)).toMatch(/producer output differs from consumer input/);
  });

  test("an encoding-failed attempt cannot count; a launched run needs applied prefix and target collector records", () => {
    expect(hasAppliedCoupledEvidence({ ...attempt, status: "encoding_failed" }, capture(), binding)).toBe(false);
    expect(hasAppliedCoupledEvidence(attempt, capture(false), binding)).toBe(false);
    expect(hasAppliedCoupledEvidence(attempt, capture(), binding)).toBe(true);
    expect(hasAppliedCoupledEvidence(attempt, capture(), binding, "other-run")).toBe(false);
    expect(hasAppliedCoupledEvidence(attempt, capture().replace("run-coupled", "another-run"), binding)).toBe(false);
  });
});
