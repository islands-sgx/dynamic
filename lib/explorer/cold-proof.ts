import { parseStrictJson } from "../bundle/profile-bundle.ts";
import type { CallCaptureDocument, CallCaptureEvent, CapturedBufferInput, CapturedBufferOutput } from "./contract.ts";

export interface ColdCallPosition {
  generation: number;
  callSeq: number;
  selectorOrdinal: number;
  selectorSeq: number;
}

export interface ColdTransferEvidence {
  source: ColdCallPosition & { paramIndex: number };
  consumer: ColdCallPosition & { paramIndex: number };
  sha256: string;
  byteLength: number;
  elementSize: number;
  storageAddress: string;
  scope: "same_process_fresh_enclave";
  crossProcessPortabilityProven: false;
}

export interface ColdGenerationResult {
  generation: number;
  target?: ColdCallPosition;
  opportunityCount: number;
  provenTransfers: ColdTransferEvidence[];
  reason: string | null;
}

export interface ColdFirstFieldResult {
  status: "proved" | "absent" | "invalid";
  reason: string | null;
  opportunityCount: number;
  provenTransfers: ColdTransferEvidence[];
  generations: ColdGenerationResult[];
}

interface TraceCall extends ColdCallPosition {
  fields: unknown[];
  measurementValid: true;
}


const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const safeInt = (value: unknown, min = 0): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= min;
const nonzeroAddress = (value: unknown): value is string =>
  typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value) && !/^0x0+$/i.test(value);
const sameAddress = (left: string, right: string): boolean => left.toLowerCase() === right.toLowerCase();
const validSha256 = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

function parseTrace(traceText: string): { runId: string; calls: TraceCall[] } {
  if (traceText.startsWith("\uFEFF")) throw new TypeError("canonical trace must not start with a UTF-8 BOM");
  const lines = traceText.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length < 2) throw new TypeError("canonical trace must contain run_start and run_end");
  const records = lines.map((line, index) => {
    if (line.trim() === "") throw new TypeError("canonical trace line " + (index + 1) + " is empty");
    const value = parseStrictJson(line, "canonical trace line " + (index + 1));
    if (!isRecord(value)) throw new TypeError("canonical trace line " + (index + 1) + " must be an object");
    return value;
  });
  const start = records[0]!;
  const end = records.at(-1)!;
  if (start.schema !== "atfield-canonical-trace-v1" || start.record_type !== "run_start" ||
      typeof start.run_id !== "string" || start.run_id.length === 0 || start.instance_generation !== null)
    throw new TypeError("canonical trace has an invalid run_start record");
  const endTimedOut = end.timed_out ?? end.timeout;
  if (end.schema !== start.schema || end.record_type !== "run_end" || end.run_id !== start.run_id ||
      end.completion !== "complete" || end.termination !== "exited" || end.process_return_code !== 0 ||
      endTimedOut !== false || !Array.isArray(end.incomplete_reasons) || end.incomplete_reasons.length !== 0)
    throw new TypeError("canonical trace has an invalid or incomplete run_end record");

  const calls: TraceCall[] = [];
  const selectorCounts = new Map<string, number>();
  let currentGeneration = 0;
  for (let index = 1; index < records.length - 1; index++) {
    const record = records[index]!;
    if (record.schema !== start.schema || record.record_type !== "ecall" || record.run_id !== start.run_id ||
        !safeInt(record.call_seq) || record.call_seq !== index - 1 ||
        !safeInt(record.instance_generation, 1) || record.instance_generation < currentGeneration ||
        !safeInt(record.selector_ordinal) || !safeInt(record.selector_seq) ||
        record.measurement_valid !== true || !Array.isArray(record.measurement_invalid_reasons) ||
        record.measurement_invalid_reasons.length !== 0 || !Array.isArray(record.fields))
      throw new TypeError("canonical trace has an invalid ECALL record at position " + (index - 1));
    const generation = record.instance_generation;
    currentGeneration = generation;
    const selectorKey = generation + ":" + record.selector_ordinal;
    const expectedSeq = selectorCounts.get(selectorKey) ?? 0;
    if (record.selector_seq !== expectedSeq) throw new TypeError("canonical trace selector_seq is not contiguous");
    selectorCounts.set(selectorKey, expectedSeq + 1);
    for (const field of record.fields) {
      if (!isRecord(field) || typeof field.field_id !== "string" || field.field_id.length === 0)
        throw new TypeError("canonical trace contains an invalid Field entry");
    }
    calls.push({
      generation,
      callSeq: record.call_seq,
      selectorOrdinal: record.selector_ordinal,
      selectorSeq: record.selector_seq,
      fields: record.fields,
      measurementValid: true,
    });
  }
  const endCallCount = end.ecall_count ?? end.record_count;
  if (endCallCount !== calls.length || end.instance_generation !== (calls.at(-1)?.generation ?? null))
    throw new TypeError("canonical trace run_end does not match its ECALL records");
  return { runId: start.run_id, calls };
}

function capturePosition(event: CallCaptureEvent): ColdCallPosition {
  return {
    generation: event.generation,
    callSeq: event.callSeq,
    selectorOrdinal: event.selectorOrdinal,
    selectorSeq: event.selectorSeq,
  };
}

function validCapture(capture: CallCaptureDocument, calls: readonly TraceCall[], traceRunId: string): string | null {
  if (capture.runId !== traceRunId) return "call capture and canonical trace have different run ids";
  if (!capture.end.complete || capture.end.processReturnCode !== 0 || capture.end.termination !== "exited" ||
      capture.end.timedOut || capture.end.incompleteReasons.length !== 0)
    return "call capture is incomplete or unsuccessful";
  if (capture.end.ecallCount !== calls.length || capture.events.length !== calls.length)
    return "call capture and canonical trace have different ECALL counts";
  const seen = new Set<string>();
  for (const [index, event] of capture.events.entries()) {
    if (!safeInt(event.generation, 1) || !safeInt(event.callSeq) || !safeInt(event.selectorOrdinal) ||
        !safeInt(event.selectorSeq)) return "call capture contains an invalid call position";
    const key = [event.generation, event.callSeq, event.selectorOrdinal, event.selectorSeq].join(":");
    if (seen.has(key)) return "call capture contains a duplicated call position";
    seen.add(key);
    const trace = calls[index];
    if (!trace || trace.generation !== event.generation || trace.callSeq !== event.callSeq ||
        trace.selectorOrdinal !== event.selectorOrdinal || trace.selectorSeq !== event.selectorSeq)
      return "call capture positions do not match canonical trace order";
    for (const buffers of [event.bufferInputs ?? [], event.bufferOutputs ?? []]) {
      const params = new Set<number>();
      for (const buffer of buffers) {
        if (!safeInt(buffer.paramIndex) || params.has(buffer.paramIndex) || !safeInt(buffer.byteLength) ||
            !safeInt(buffer.elementSize, 1)) return "call capture contains an invalid or duplicated buffer parameter";
        params.add(buffer.paramIndex);
      }
    }
  }
  return null;
}

function outputBuffers(event: CallCaptureEvent): CapturedBufferOutput[] {
  return event.bufferOutputs ?? [];
}
function inputBuffers(event: CallCaptureEvent): CapturedBufferInput[] {
  return event.bufferInputs ?? [];
}

/**
 * Proves that an input to the first measured Field in each fresh enclave generation
 * aliases the latest prior-generation host output with the same full-buffer shape,
 * storage address, and SHA-256. The address evidence is process-local; this says
 * nothing about import or portability across host processes.
 */
export function proveColdFirstFieldTransfer(
  capture: CallCaptureDocument,
  canonicalTraceText: string,
): ColdFirstFieldResult {
  let trace: { runId: string; calls: TraceCall[] };
  try {
    trace = parseTrace(canonicalTraceText);
  } catch (error) {
    return { status: "invalid", reason: (error as Error).message, opportunityCount: 0, provenTransfers: [], generations: [] };
  }
  const invalidCapture = validCapture(capture, trace.calls, trace.runId);
  if (invalidCapture) return { status: "invalid", reason: invalidCapture, opportunityCount: 0, provenTransfers: [], generations: [] };

  const generationNumbers = [...new Set(trace.calls.map((call) => call.generation))].filter((generation) => generation > 1).sort((a, b) => a - b);
  if (generationNumbers.length === 0) {
    return { status: "absent", reason: "canonical trace contains no enclave generation greater than one", opportunityCount: 0, provenTransfers: [], generations: [] };
  }
  const generationResults: ColdGenerationResult[] = [];
  const allTransfers: ColdTransferEvidence[] = [];
  let totalOpportunities = 0;
  for (const generation of generationNumbers) {
    const targetTrace = trace.calls.find((call) => call.generation === generation && call.fields.length > 0);
    if (!targetTrace) {
      generationResults.push({ generation, opportunityCount: 0, provenTransfers: [], reason: "generation has no successfully measured Field entry" });
      continue;
    }
    const targetEvent = capture.events.find((event) => event.generation === targetTrace.generation &&
      event.callSeq === targetTrace.callSeq && event.selectorOrdinal === targetTrace.selectorOrdinal &&
      event.selectorSeq === targetTrace.selectorSeq);
    if (!targetEvent) {
      generationResults.push({ generation, target: targetTrace, opportunityCount: 0, provenTransfers: [], reason: "first measured Field call is missing from call capture" });
      continue;
    }

    let opportunities = 0;
    const transfers: ColdTransferEvidence[] = [];
    let ambiguity: string | null = null;
    for (const input of inputBuffers(targetEvent)) {
      if (input.direction !== "in") continue;
      const address = input.storageAddress;
      if (!nonzeroAddress(address)) continue;
      const shapeMatches: Array<{ event: CallCaptureEvent; buffer: CapturedBufferOutput }> = [];
      for (const event of capture.events) {
        if (event.callSeq >= targetEvent.callSeq) continue;
        for (const output of outputBuffers(event)) {
          if (nonzeroAddress(output.storageAddress) && sameAddress(output.storageAddress, address) &&
              output.byteLength === input.byteLength &&
              output.elementSize === input.elementSize)
            shapeMatches.push({ event, buffer: output });
        }
      }
      if (shapeMatches.length === 0 || !shapeMatches.some(({ event }) => event.generation < generation)) continue;
      opportunities++;
      const latestCallSeq = Math.max(...shapeMatches.map(({ event }) => event.callSeq));
      const latest = shapeMatches.filter(({ event }) => event.callSeq === latestCallSeq);
      if (latest.length !== 1) {
        ambiguity = "latest same-address output is ambiguous for input parameter " + input.paramIndex;
        continue;
      }
      const { event: sourceEvent, buffer: sourceOutput } = latest[0]!;
      if (sourceEvent.generation >= generation) {
        ambiguity = "intervening same-generation output superseded the prior-generation object for input parameter " + input.paramIndex;
        continue;
      }
      if (!validSha256(input.sha256) || !validSha256(sourceOutput.sha256)) continue;
      if (input.sha256 !== sourceOutput.sha256) continue;
      transfers.push({
        source: { ...capturePosition(sourceEvent), paramIndex: sourceOutput.paramIndex },
        consumer: { ...capturePosition(targetEvent), paramIndex: input.paramIndex },
        sha256: input.sha256,
        byteLength: input.byteLength,
        elementSize: input.elementSize,
        storageAddress: address,
        scope: "same_process_fresh_enclave",
        crossProcessPortabilityProven: false,
      });
    }
    totalOpportunities += opportunities;
    if (ambiguity) {
      generationResults.push({ generation, target: targetTrace, opportunityCount: opportunities, provenTransfers: [], reason: ambiguity });
      continue;
    }
    const reason = opportunities > 0 && transfers.length === opportunities ? null : opportunities > 0
      ? "prior-generation object opportunity exists but full SHA-256 evidence did not prove transfer"
      : "first measured Field inputs have no same-address, same-shape prior-generation output";
    generationResults.push({ generation, target: targetTrace, opportunityCount: opportunities, provenTransfers: transfers, reason });
    allTransfers.push(...transfers);
  }
  const measuredGenerations = generationResults.filter((result) => result.target !== undefined);
  const failed = measuredGenerations.find((result) => result.opportunityCount > 0 && result.reason !== null);
  if (measuredGenerations.length === 0) {
    return { status: "absent", reason: "no generation greater than one has a measured Field entry", opportunityCount: totalOpportunities, provenTransfers: allTransfers, generations: generationResults };
  }
  if (failed) {
    return {
      status: "absent",
      reason: "generation " + failed.generation + ": " + failed.reason,
      opportunityCount: totalOpportunities,
      provenTransfers: allTransfers,
      generations: generationResults,
    };
  }
  if (allTransfers.length === 0) {
    const reason = generationResults.find((result) => result.reason !== null)?.reason ??
      "no prior-generation host object opportunity was found";
    return { status: "absent", reason, opportunityCount: totalOpportunities, provenTransfers: [], generations: generationResults };
  }
  return { status: "proved", reason: null, opportunityCount: totalOpportunities, provenTransfers: allTransfers, generations: generationResults };
}
