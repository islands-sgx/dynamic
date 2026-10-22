import type {
  CallCaptureDocument,
  CallCaptureEvent,
  CapturedBufferInput,
  CapturedBufferOutput,
  ScalarMutationRule,
} from "./contract.ts";

export interface LinkedRunEvidence {
  complete: boolean;
  exitCode: number | null;
  traceText: string;
  traceValid: boolean;
}

type BufferCapture = CapturedBufferInput | CapturedBufferOutput;

function uniqueEvent(
  capture: CallCaptureDocument,
  generation: number,
  callSeq: number,
  selectorOrdinal: number,
  selectorSeq: number,
): CallCaptureEvent | null {
  const found = capture.events.filter((event) =>
    event.generation === generation && event.callSeq === callSeq &&
    event.selectorOrdinal === selectorOrdinal && event.selectorSeq === selectorSeq);
  return found.length === 1 ? found[0]! : null;
}

function uniqueBuffer(
  event: CallCaptureEvent,
  kind: "input" | "output",
  paramIndex: number,
): BufferCapture | null {
  const buffers = kind === "input" ? event.bufferInputs : event.bufferOutputs;
  const found = (buffers ?? []).filter((buffer) => buffer.paramIndex === paramIndex);
  return found.length === 1 ? found[0]! : null;
}

function completeBytes(buffer: BufferCapture | null, byteLength: number, elementSize: number): string | null {
  if (!buffer || buffer.byteLength !== byteLength || buffer.elementSize !== elementSize ||
      buffer.prefixHex.length !== byteLength * 2 || !/^(?:[0-9a-f]{2})*$/.test(buffer.prefixHex)) return null;
  return buffer.prefixHex;
}

function wordAt(bytes: string, offset: number, width: number): string | null {
  if (!Number.isSafeInteger(offset) || ![1, 2, 4, 8].includes(width) ||
      offset < 0 || (offset + width) * 2 > bytes.length) return null;
  let bits = 0n;
  for (let i = 0; i < width; i++) {
    bits |= BigInt(parseInt(bytes.slice((offset + i) * 2, (offset + i + 1) * 2), 16)) << BigInt(8 * i);
  }
  return "0x" + bits.toString(16).padStart(width * 2, "0");
}

function measuredConsumer(run: LinkedRunEvidence, target: NonNullable<ScalarMutationRule["dataflowTarget"]>): boolean {
  let found = 0;
  for (const line of run.traceText.split(/\r?\n/)) {
    if (!line) continue;
    let record: Record<string, unknown>;
    try { record = JSON.parse(line) as Record<string, unknown>; } catch { return false; }
    if (record.record_type !== "ecall" ||
        record.instance_generation !== target.consumerGeneration ||
        record.call_seq !== target.consumerCallSeq ||
        record.selector_ordinal !== target.consumerSelectorOrdinal ||
        record.selector_seq !== target.consumerSelectorSeq) continue;
    found++;
    if (record.measurement_valid !== true || !Array.isArray(record.fields) || record.fields.length === 0) return false;
  }
  return found === 1;
}

/* A linked candidate changes the producer once and observes what the real host
   passes to its later consumer. Only fully captured buffers can prove this
   transfer; a short prefix or a non-cryptographic digest is insufficient. */
export function linkedDataflowFailure(
  baseline: CallCaptureDocument,
  candidate: CallCaptureDocument,
  rule: ScalarMutationRule,
  run: LinkedRunEvidence,
): string | null {
  const target = rule.dataflowTarget;
  if (!target) return null;
  if (rule.opKind !== "mutate_buffer" || rule.bufferSubOp !== "write_le" ||
      (rule.execMode ?? 0) !== 0 || (rule.prefixMutations?.length ?? 0) !== 0 ||
      target.consumerByteOffset !== rule.byteOffset ||
      target.consumerWidthBytes !== rule.widthBytes ||
      target.baselineBits !== rule.expectedBits ||
      target.propagatedBits !== rule.replacementBits)
    return "linked observation does not match the producer mutation";
  if (!run.complete || run.exitCode !== 0 || !run.traceValid ||
      !candidate.end.complete) return "linked proof requires a complete successful business run";
  const generation = rule.targetGeneration ?? 1;
  const baselineProducer = baseline.events.filter((event) =>
    event.generation === generation && event.selectorOrdinal === rule.selectorOrdinal &&
    event.selectorSeq === rule.selectorSeq);
  if (baselineProducer.length !== 1) return "linked baseline producer is missing or duplicated";
  const producerCallSeq = baselineProducer[0]!.callSeq;
  if (target.consumerGeneration !== generation || target.consumerCallSeq <= producerCallSeq)
    return "linked producer and consumer order is invalid";
  const beforeProducer = uniqueEvent(baseline, generation, producerCallSeq, rule.selectorOrdinal, rule.selectorSeq);
  const afterProducer = uniqueEvent(candidate, generation, producerCallSeq, rule.selectorOrdinal, rule.selectorSeq);
  const beforeConsumer = uniqueEvent(baseline, target.consumerGeneration, target.consumerCallSeq,
    target.consumerSelectorOrdinal, target.consumerSelectorSeq);
  const afterConsumer = uniqueEvent(candidate, target.consumerGeneration, target.consumerCallSeq,
    target.consumerSelectorOrdinal, target.consumerSelectorSeq);
  if (!beforeProducer || !afterProducer || !beforeConsumer || !afterConsumer)
    return "linked producer or consumer call is missing or duplicated";
  const priorInput = uniqueBuffer(beforeProducer, "input", rule.paramIndex);
  const priorOutput = uniqueBuffer(beforeProducer, "output", rule.paramIndex);
  const priorConsumer = uniqueBuffer(beforeConsumer, "input", target.consumerParamIndex);
  const nextInput = uniqueBuffer(afterProducer, "input", rule.paramIndex);
  const nextOutput = uniqueBuffer(afterProducer, "output", rule.paramIndex);
  const nextConsumer = uniqueBuffer(afterConsumer, "input", target.consumerParamIndex);
  if (priorInput?.direction !== "inout" || priorOutput?.direction !== "inout" ||
      nextInput?.direction !== "inout" || nextOutput?.direction !== "inout" ||
      !priorConsumer || !["in", "inout"].includes(priorConsumer.direction) ||
      !nextConsumer || !["in", "inout"].includes(nextConsumer.direction))
    return "linked buffer direction or parameter is invalid";
  if (!priorInput.storageAddress || /^0x0+$/.test(priorInput.storageAddress) ||
      priorInput.storageAddress !== priorOutput.storageAddress ||
      priorInput.storageAddress !== priorConsumer.storageAddress)
    return "linked baseline buffer identity is unproven";
  const mutation = afterProducer.mutation;
  if (!mutation?.applied || mutation.reason !== "applied" ||
      mutation.paramIndex !== rule.paramIndex || mutation.byteOffset !== rule.byteOffset ||
      mutation.widthBytes !== rule.widthBytes || mutation.expectedBits !== rule.expectedBits ||
      mutation.replacementBits !== rule.replacementBits)
    return "linked producer mutation was not applied as planned";

  const shape = [target.bufferByteLength, target.elementSize] as const;
  const oldInput = completeBytes(priorInput, ...shape);
  const oldOutput = completeBytes(priorOutput, ...shape);
  const oldConsumer = completeBytes(priorConsumer, ...shape);
  const newInput = completeBytes(nextInput, ...shape);
  const newOutput = completeBytes(nextOutput, ...shape);
  const newConsumer = completeBytes(nextConsumer, ...shape);
  if ([oldInput, oldOutput, oldConsumer, newInput, newOutput, newConsumer].some((value) => value === null))
    return "linked proof lacks a complete buffer capture";
  if (oldOutput !== oldConsumer || newOutput !== newConsumer)
    return "linked producer output differs from consumer input";
  if ([oldInput, oldOutput, oldConsumer].some((value) =>
      wordAt(value!, target.consumerByteOffset, target.consumerWidthBytes) !== target.baselineBits))
    return "linked baseline word is inconsistent";
  if ([newInput, newOutput, newConsumer].some((value) =>
      wordAt(value!, target.consumerByteOffset, target.consumerWidthBytes) !== target.propagatedBits))
    return "linked replacement did not propagate";
  if (oldOutput === newOutput) return "linked producer output did not change";
  if (!measuredConsumer(run, target)) return "linked consumer did not enter a valid measured Field";
  return null;
}
