import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import {
  FORMAL_SAMPLES, captureFormalRegistrySnapshot, compareS3HoldoutCoverage,
  formalPhaseSpecsForSample, formalSeedEvidenceFailure, formalTargetsAccepted,
  hasAppliedCoupledEvidence, linkedCandidateVerdictFailure, loadFormalHostSeeds,
  resolveFormalHoldoutContract, validateSampleSelection, verifyAcceptedWorkset,
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


function phaseEvidence(spec: ReturnType<typeof formalPhaseSpecsForSample>[number], candidateRuns = 16,
  acceptedCompleteCandidates = 1, linkedExecutions = 0) {
  return {
    name: spec.name, seedId: spec.id, seedArgs: spec.args, role: spec.role,
    includeInWorkset: spec.includeInWorkset,
    attempt: 0, valid: true, baselineAccepted: true, baselineRunId: "run-" + spec.id,
    candidateRuns, acceptedCompleteCandidates, linkedExecutions,
    ...(spec.includeInWorkset ? {} : { holdoutCoverage: { passed: true, observedEffects: 1, missedEffects: 0,
      missingFieldIds: 0, timingCallCount: 1000, invalidTimingCalls: 0, duplicateTimingCalls: 0 } }),
    coldOpportunities: 0, coldTransfers: 0, coldProofFailures: [],
  };
}
function targetEvidence(sample: string, candidateRuns = 16, acceptedCompleteCandidates = 1,
  linkedEncodable = 0, linkedExecutions = 0, coupledEncodable = 0) {
  const snapshot = captureFormalRegistrySnapshot([sample]);
  const targetConfig = snapshot.targets[0]!;
  const specs = targetConfig.phases;
  const phaseBudget = targetConfig.strategy === "baseline-only" ? 0 : candidateRuns;
  return {
    sample, valid: true, formalConfigSha256: snapshot.sha256, acquisitionStrategy: targetConfig.strategy,
    sourceTraces: specs.filter((spec) => spec.includeInWorkset).map((spec) => ({ run_id: "run-" + spec.id, sha256: "trace-" + spec.id })),
    worksetPath: sample + "/workset.v2.json", worksetSha256: "00".repeat(32),
    planningAudits: specs.map((spec) => ({ phase: spec.name, seedId: spec.id, attempt: 0, coupledEncodable, linkedEncodable })),
    phases: specs.map((spec) => phaseEvidence(spec, phaseBudget,
      targetConfig.strategy === "baseline-only" ? 0 : acceptedCompleteCandidates, linkedExecutions)),
  };
}

describe("formal milestone acceptance gates", () => {
  test("complete rejected linked measurements retain their semantic reason", () => {
    expect(linkedCandidateVerdictFailure(false, true, false, true,
      "linked consumer did not enter a valid measured Field"))
      .toBe("candidate measurement completed but was rejected: linked consumer did not enter a valid measured Field");
    expect(linkedCandidateVerdictFailure(false, false, false, false, "collector exited early"))
      .toBe("candidate measurement is incomplete: collector exited early");
    expect(linkedCandidateVerdictFailure(true, true, true, true, null)).toBeNull();
    expect(linkedCandidateVerdictFailure(false, true, true, true,
      "linked consumer did not enter a valid measured Field"))
      .toBe("candidate result and verdict disagree: linked consumer did not enter a valid measured Field");
  });

  test("formal target lists require executed candidate budget and opportunity-driven linked proof", () => {
    expect(FORMAL_SAMPLES).toHaveLength(6);
    expect(() => validateSampleSelection([], false)).toThrow(/at least one/);
    expect(() => validateSampleSelection(["wolfssl-pbkdf2-sha256"], false)).not.toThrow();
    expect(() => validateSampleSelection(["ehsm"], true)).not.toThrow();
    expect(() => validateSampleSelection(["ehsm", "ehsm"], true)).toThrow(/unique/);
    const baselineGreenWithoutCandidates = FORMAL_SAMPLES.map((sample) => targetEvidence(sample, 0, 0));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, baselineGreenWithoutCandidates, [], 16)).toBe(false);
    const complete = FORMAL_SAMPLES.map((sample) => targetEvidence(sample));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, complete, [], 16)).toBe(true);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, complete.slice(1), [], 16)).toBe(false);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, complete.map((item, i) =>
      i === 2 ? { ...item, valid: false } : item), [], 16)).toBe(false);
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample) => targetEvidence(sample, 16, 0)), [], 16)).toBe(false);
    // Historical prefix-only opportunity is informational; linked proof has its own gate.
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample, i) => targetEvidence(sample, 16, 1, 0, 0, i === 3 ? 96 : 0)), [], 16)).toBe(true);
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample, i) => targetEvidence(sample, 16, 1, i === 3 ? 96 : 0, 0)), [], 16)).toBe(false);
    expect(formalTargetsAccepted(FORMAL_SAMPLES,
      FORMAL_SAMPLES.map((sample, i) => targetEvidence(sample, 16, 1, i === 3 ? 96 : 0, i === 3 ? 1 : 0)), [], 16)).toBe(true);
    const coldOpportunityUnproved = FORMAL_SAMPLES.map((sample, i) => {
      const specs = formalPhaseSpecsForSample(sample);
      return {
        ...targetEvidence(sample),
        phases: specs.map((spec) => i === 2 && spec.name === "default"
          ? { ...phaseEvidence(spec), coldOpportunities: 1 } : phaseEvidence(spec)),
      };
    });
    expect(formalTargetsAccepted(FORMAL_SAMPLES, coldOpportunityUnproved, [], 16)).toBe(false);
    const coldOpportunityProved = coldOpportunityUnproved.map((item, i) => i === 2
      ? { ...item, phases: (item.phases as Array<Record<string, unknown>>).map((p) => p.name === "default"
        ? { ...p, coldOpportunities: 1, coldTransfers: 1 } : p) }
      : item);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, coldOpportunityProved, [], 16)).toBe(true);
    const retryAfterInvalidBaseline = FORMAL_SAMPLES.map((sample, i) => i === 3 ? {
      ...targetEvidence(sample, 16, 1, 1, 1),
      planningAudits: [
        { phase: "default", seedId: "default", attempt: 1, coupledEncodable: 0, linkedEncodable: 1 },
        { phase: "self-test", seedId: "self-test", attempt: 0, coupledEncodable: 0, linkedEncodable: 1 },
      ],
      phases: [
        { ...phaseEvidence(formalPhaseSpecsForSample(sample)[0]!, 0, 0), valid: false, baselineAccepted: false },
        { ...phaseEvidence(formalPhaseSpecsForSample(sample)[0]!, 16, 1, 1), attempt: 1 },
        phaseEvidence(formalPhaseSpecsForSample(sample)[1]!, 16, 1, 1),
        ...formalPhaseSpecsForSample(sample).slice(2).map((spec) => phaseEvidence(spec, 16, 1, 1)),
      ],
    } : targetEvidence(sample));
    expect(formalTargetsAccepted(FORMAL_SAMPLES, retryAfterInvalidBaseline, [], 16)).toBe(true);
    const executionInWrongPhase = FORMAL_SAMPLES.map((sample, i) => {
      const specs = formalPhaseSpecsForSample(sample);
      const base = targetEvidence(sample);
      return {
        ...base,
        planningAudits: specs.map((spec) => ({ phase: spec.name, seedId: spec.id, attempt: 0,
          coupledEncodable: 0, linkedEncodable: i === 3 && spec.name === "default" ? 96 : 0 })),
        phases: specs.map((spec) => phaseEvidence(spec, 16, 1, i === 3 && spec.name === "self-test" ? 1 : 0)),
      };
    });
    expect(formalTargetsAccepted(FORMAL_SAMPLES, executionInWrongPhase, [], 16)).toBe(false);
    expect(loadFormalHostSeeds("ehsm")).toEqual([]);
    expect(loadFormalHostSeeds("ehsm-opt-1")).toEqual([
      { id: "sm4-check", phase: "sm4-check", role: "main", args: ["--sm4-check"], includeInWorkset: true },
    ]);
    const optSpecs = formalPhaseSpecsForSample("ehsm-opt-1");
    expect(optSpecs.at(-1)).toEqual({ id: "sm4-check", name: "sm4-check", role: "main", args: ["--sm4-check"], includeInWorkset: true });
    const missingSm4 = complete.map((item) => item.sample === "ehsm-opt-1"
      ? { ...item, phases: (item.phases as unknown[]).filter((p) => (p as Record<string, unknown>).name !== "sm4-check") }
      : item);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, missingSm4, [], 16)).toBe(false);
    const duplicatedSm4 = complete.map((item) => item.sample === "ehsm-opt-1"
      ? { ...item, phases: [...(item.phases as unknown[]), ...(item.phases as unknown[]).filter((p) => (p as Record<string, unknown>).name === "sm4-check")] }
      : item);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, duplicatedSm4, [], 16)).toBe(false);
    const rejectedSm4 = complete.map((item) => item.sample === "ehsm-opt-1"
      ? { ...item, phases: (item.phases as Array<Record<string, unknown>>).map((p) => p.name === "sm4-check"
        ? { ...p, baselineAccepted: false } : p) }
      : item);
    expect(formalTargetsAccepted(FORMAL_SAMPLES, rejectedSm4, [], 16)).toBe(false);
  });

  test("accepted workset binding rejects a changed artifact", () => {
    const sample = "qe3";
    const snapshot = captureFormalRegistrySnapshot([sample]);
    const target = targetEvidence(sample);
    const root = mkdtempSync(path.join(tmpdir(), "formal-workset-"));
    const worksetPath = path.join(root, sample, "workset.v2.json");
    const original = JSON.stringify({ schema: "atfield-workset-v2", source_traces: [] }) + "\n";
    try {
      mkdirSync(path.dirname(worksetPath), { recursive: true });
      writeFileSync(worksetPath, original);
      target.worksetSha256 = createHash("sha256").update(original).digest("hex");
      expect(verifyAcceptedWorkset(target, root)).toBe(true);
      expect(formalTargetsAccepted([sample], [target], [], 16, snapshot, root)).toBe(true);
      writeFileSync(worksetPath, JSON.stringify({ schema: "atfield-workset-v2", source_traces: [], tampered: true }) + "\n");
      expect(verifyAcceptedWorkset(target, root)).toBe(false);
      expect(formalTargetsAccepted([sample], [target], [], 16, snapshot, root)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("baseline-only registered bench phases isolate 100/1000 holdouts from training workset", () => {
    for (const sample of ["wolfssl-pbkdf2-sha256", "yescrypt-kdf-rw"]) {
      const snapshot = captureFormalRegistrySnapshot([sample]);
      const config = snapshot.targets[0]!;
      expect(config.strategy).toBe("baseline-only");
      expect(config.holdout).toEqual({ timingSelectorNames: ["timing"], expectedTimingCalls: 1000 });
      expect(resolveFormalHoldoutContract({
        selectors: [
          { name: "other", ordinal: 5, reachableFields: ["field"] },
          { name: "timing", ordinal: 41, reachableFields: ["field"] },
        ],
        fields: [{ id: "field" }],
      } as never, config.holdout!)).toEqual({ timingSelectorOrdinals: [41], expectedTimingCalls: 1000 });
      expect(() => resolveFormalHoldoutContract({
        selectors: [{ name: "renamed", ordinal: 5, reachableFields: ["field"] }],
        fields: [{ id: "field" }],
      } as never, config.holdout!)).toThrow(/absent from Profile bundle/);
      expect(config.phases.map((phase) => [phase.args, phase.includeInWorkset])).toEqual([
        [["--self-test"], true], [["100", "1000"], false],
      ]);
      const accepted = targetEvidence(sample, 16, 1);
      expect(formalTargetsAccepted([sample], [accepted], [], 16, snapshot)).toBe(true);
      const holdout = config.phases[1]!;
      const contaminated = { ...accepted, sourceTraces: [...accepted.sourceTraces,
        { run_id: "run-" + holdout.id, sha256: "holdout" }] };
      expect(formalTargetsAccepted([sample], [contaminated], [], 16, snapshot)).toBe(false);
      const duplicateTrainingTrace = { ...accepted, sourceTraces: [...accepted.sourceTraces, accepted.sourceTraces[0]] };
      expect(formalTargetsAccepted([sample], [duplicateTrainingTrace], [], 16, snapshot)).toBe(false);
      const duplicateRun = { ...accepted, phases: (accepted.phases as Array<Record<string, unknown>>).map((phase) =>
        phase.name === holdout.name ? { ...phase, baselineRunId: "run-training-self-test" } : phase) };
      expect(formalTargetsAccepted([sample], [duplicateRun], [], 16, snapshot)).toBe(false);
      const failedHoldout = { ...accepted, phases: (accepted.phases as Array<Record<string, unknown>>).map((phase) =>
        phase.name === holdout.name ? { ...phase, holdoutCoverage: { passed: false, observedEffects: 2, missedEffects: 1,
          missingFieldIds: 0, timingCallCount: 999, invalidTimingCalls: 1, duplicateTimingCalls: 0 } } : phase) };
      expect(formalTargetsAccepted([sample], [failedHoldout], [], 16, snapshot)).toBe(false);
      const alteredRegistry = { ...snapshot, sha256: "00".repeat(32), targets: snapshot.targets.map((item) => ({
        ...item, phases: item.phases.map((phase) => phase.name === "holdout" ? { ...phase, args: ["1", "1000"] } : phase),
      })) };
      expect(formalTargetsAccepted([sample], [accepted], [], 16, alteredRegistry)).toBe(false);
    }
  });

  test("registry digest and parsed seed changes invalidate frozen acceptance", () => {
    const snapshot = captureFormalRegistrySnapshot(["ehsm-opt-1"]);
    const accepted = targetEvidence("ehsm-opt-1");
    expect(formalTargetsAccepted(["ehsm-opt-1"], [accepted], [], 16, snapshot)).toBe(true);
    const changed = { ...snapshot, sha256: "ff".repeat(32), targets: snapshot.targets.map((item) => ({
      ...item, phases: item.phases.map((phase) => phase.name === "sm4-check" ? { ...phase, args: [] } : phase),
    })) };
    expect(formalTargetsAccepted(["ehsm-opt-1"], [accepted], [], 16, changed)).toBe(false);
    const alteredArgs = { ...snapshot, targets: snapshot.targets.map((item) => ({
      ...item, phases: item.phases.map((phase) => phase.name === "sm4-check" ? { ...phase, args: [] } : phase),
    })) };
    expect(formalTargetsAccepted(["ehsm-opt-1"], [accepted], [], 16, alteredArgs)).toBe(false);
  });

  test("holdout requires every training Field, all S3 effects, and exactly 1000 valid timing ECALLs", () => {
    const fields = ["field"];
    const trace = (effects: Array<"R" | "W" | "X">, count = 1000,
      measurementValid = true, observedFields = fields, selectorOrdinal = 5) => {
      const parsed = {
        observedFieldIds: observedFields,
        observations: [{ fieldId: "field", pageRva: 0x1000n, accessed: true, dirty: effects.includes("W"), effects }],
      } as never;
      const records = Array.from({ length: count }, (_, callSeq) => JSON.stringify({
        record_type: "ecall", instance_generation: 1, call_seq: callSeq,
        selector_ordinal: selectorOrdinal, selector_seq: callSeq, measurement_valid: measurementValid,
        fields: observedFields.map((field_id) => ({ field_id })),
      }));
      return { parsed, traceText: records.join("\n") + "\n" };
    };
    const training = { observedFieldIds: fields,
      observations: [{ fieldId: "field", pageRva: 0x1000n, accessed: true, dirty: false, effects: ["R"] }] } as never;
    const validHoldout = trace(["R"]);
    expect(compareS3HoldoutCoverage([training], [validHoldout], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: true, observedEffects: 1, missedEffects: [], missingFieldIds: [],
      timingCallCount: 1000, invalidTimingCalls: 0, duplicateTimingCalls: 0 });
    expect(compareS3HoldoutCoverage([training], [trace(["R"], 999)], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: false, timingCallCount: 999 });
    expect(compareS3HoldoutCoverage([training], [trace(["R"], 1000, false)], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: false, invalidTimingCalls: 1000 });
    expect(compareS3HoldoutCoverage([training], [trace(["R"], 1000, true, [], 2)], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: false, timingCallCount: 0, missingFieldIds: ["field"] });
    expect(compareS3HoldoutCoverage([training], [trace(["R"], 1000, true, [])], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: false, invalidTimingCalls: 1000, missingFieldIds: ["field"] });
    const duplicatedTimingEvent = trace(["R"]);
    const firstTimingEvent = duplicatedTimingEvent.traceText.split("\n")[0]!;
    expect(compareS3HoldoutCoverage([training], [{ ...duplicatedTimingEvent,
      traceText: duplicatedTimingEvent.traceText + firstTimingEvent + "\n" }], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: false, timingCallCount: 1000, duplicateTimingCalls: 1 });
    expect(compareS3HoldoutCoverage([training], [trace(["R", "W"])], {
      timingSelectorOrdinals: [5], expectedTimingCalls: 1000,
    })).toMatchObject({ passed: false, missedEffects: [JSON.stringify(["field", "0x1000", "W"])] });
  });

  test("formal seed arguments bind config, attempt manifest, runner metadata, and native run_start", () => {
    const expected = formalPhaseSpecsForSample("ehsm-opt-2").at(-1)!;
    const attempt = { seed: { id: expected.id, args: expected.args, env: {} } };
    const meta = { seed_id: expected.id, argv: expected.args };
    const trace = JSON.stringify({ record_type: "run_start", seed_id: expected.id, argv: expected.args }) + "\n";
    expect(formalSeedEvidenceFailure(expected, attempt, meta, trace)).toBeNull();
    expect(formalSeedEvidenceFailure(expected, attempt, { ...meta, argv: [] }, trace)).toMatch(/metadata/);
    expect(formalSeedEvidenceFailure(expected, attempt, meta,
      JSON.stringify({ record_type: "run_start", seed_id: expected.id, argv: [] }) + "\n")).toMatch(/trace run_start/);
    expect(formalSeedEvidenceFailure(expected, { seed: { id: expected.id, args: [] } }, meta, trace)).toMatch(/attempt seed/);
    expect(formalSeedEvidenceFailure(expected, {}, meta, trace)).toMatch(/attempt seed/);
    expect(formalSeedEvidenceFailure(expected, attempt, meta, trace + trace)).toMatch(/exactly one run_start/);
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
