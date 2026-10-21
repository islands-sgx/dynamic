import type {
  CallCaptureDocument,
  CallCaptureEvent,
  CapturedBufferInput,
  ScalarMutationRule,
} from "./contract.ts";
import type { ExplorerProfile, MarshalEcall, MarshalParameter } from "./profile.ts";
import { generateProfileScalarCandidates } from "./profile.ts";

export interface PlannedMutation {
  rule: ScalarMutationRule;
  value: string;
  priority: number;
  evidenceSiteIds: string[];
}

export interface DeriveCaseOptions {
  budget: number;
  depth?: number;
  parentMutation?: PlannedMutation;
  includeBuffers?: boolean;
  includeHistory?: boolean;
}

function fail(message: string): never {
  throw new TypeError(message);
}

function integerValue(value: string, label: string): bigint {
  if (!/^-?(0|[1-9][0-9]*)$/.test(value)) fail(label + " is not canonical decimal");
  return BigInt(value);
}

function capturedValue(event: CallCaptureEvent, paramIndex: number): bigint | undefined {
  const value = event.scalarInputs.find((item) => item.paramIndex === paramIndex);
  if (!value) return undefined;
  const raw = BigInt(value.bits);
  if (value.signedness === "unsigned") return raw;
  const width = BigInt(value.widthBytes * 8);
  const sign = 1n << (width - 1n);
  return raw >= sign ? raw - (1n << width) : raw;
}

function pointerDependencies(
  scalarIndex: number,
  marshal: MarshalEcall,
): MarshalParameter[] {
  return marshal.params.filter((param) => param.isPointer && param.boundParameterIndex === scalarIndex);
}

function preservesDependentBufferBounds(
  profile: ExplorerProfile,
  ordinal: number,
  scalarIndex: number,
  replacement: bigint,
  baselineEvent: CallCaptureEvent,
): boolean {
  const marshal = profile.ecalls.get(ordinal);
  if (!marshal || !marshal.replaySupported) return false;
  const dependencies = pointerDependencies(scalarIndex, marshal);
  if (dependencies.length === 0) return true;
  if (replacement < 0n) return false;
  for (const pointer of dependencies) {
    if (!pointer.replaySupported || pointer.userCheck ||
        (pointer.boundKind !== "size_bytes" && pointer.boundKind !== "count_elements")) return false;
    const oldValue = capturedValue(baselineEvent, scalarIndex);
    if (oldValue === undefined || oldValue < 0n) return false;
    let oldBytes = oldValue;
    let newBytes = replacement;
    if (pointer.boundKind === "count_elements") {
      if (pointer.elementSize === null || pointer.elementSize < 1) return false;
      const elementSize = BigInt(pointer.elementSize);
      oldBytes *= elementSize;
      newBytes *= elementSize;
    } else if (pointer.boundKind === "size_bytes" && pointer.elementSize !== null && pointer.elementSize > 1) {
      const elementSize = BigInt(pointer.elementSize);
      if (oldBytes % elementSize === 0n && newBytes % elementSize !== 0n) return false;
    }
    const limit = (1n << 64n) - 1n;
    if (oldBytes > limit || newBytes > limit || newBytes > oldBytes) return false;
  }
  return true;
}

function bitsForValue(value: bigint, widthBits: number): string {
  const widthBytes = widthBits / 8;
  if (![1, 2, 4, 8].includes(widthBytes) || !Number.isInteger(widthBytes)) {
    fail("scalar width is unsupported by the native mutation contract");
  }
  const unsigned = BigInt.asUintN(widthBits, value);
  return "0x" + unsigned.toString(16).padStart(widthBytes * 2, "0");
}

function eventCandidates(
  capture: CallCaptureDocument,
  ordinal: number,
  paramIndex: number,
): CallCaptureEvent[] {
  return capture.events.filter((event) => event.selectorOrdinal === ordinal &&
    event.scalarInputs.some((input) => input.paramIndex === paramIndex));
}

function isOneShotEcall(profile: ExplorerProfile, ordinal: number, maxSeq: number): boolean {
  if (maxSeq > 0) return false;
  const ecall = abiEcall(profile, ordinal);
  const marshal = profile.ecalls.get(ordinal);
  if (marshal && marshal.params.length === 0) return true;
  const entryName = typeof ecall?.name === "string" ? ecall.name : null;
  if (!entryName) return false;
  for (const rawFact of profile.irFacts) {
    if (!rawFact || typeof rawFact !== "object") continue;
    const fact = rawFact as Record<string, unknown>;
    if (!Array.isArray(fact.direct_calls)) continue;
    for (const rawCall of fact.direct_calls) {
      if (!rawCall || typeof rawCall !== "object") continue;
      const dc = rawCall as Record<string, unknown>;
      if (dc.caller === entryName && dc.callee === "abort") return true;
    }
  }
  return false;
}

function hasReachableFields(profile: ExplorerProfile, ordinal: number): boolean {
  for (const raw of profile.reachability) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (r.ordinal === ordinal && Array.isArray(r.reachable_fields)) {
      return r.reachable_fields.length > 0;
    }
  }
  return true;
}

function abiEcall(profile: ExplorerProfile, ordinal: number): Record<string, unknown> | undefined {
  const ecalls = profile.abi.ecalls;
  if (!Array.isArray(ecalls)) return undefined;
  return ecalls.find((raw) => raw !== null && typeof raw === "object" &&
    !Array.isArray(raw) && (raw as Record<string, unknown>).ordinal === ordinal) as
    Record<string, unknown> | undefined;
}

function reachableSwitchConstants(profile: ExplorerProfile, ordinal: number, widthBits: number): bigint[] {
  const reachSet = new Set<string>();
  for (const raw of profile.reachability) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (r.ordinal === ordinal && Array.isArray(r.reachable_functions)) {
      for (const fn of r.reachable_functions) {
        if (typeof fn === "string") reachSet.add(fn);
      }
    }
  }
  const values = new Set<bigint>();
  const maxVal = (1n << BigInt(widthBits)) - 1n;
  for (const rawFact of profile.irFacts) {
    if (!rawFact || typeof rawFact !== "object") continue;
    const fact = rawFact as Record<string, unknown>;
    if (!Array.isArray(fact.guidance_sites)) continue;
    for (const rawSite of fact.guidance_sites) {
      if (!rawSite || typeof rawSite !== "object") continue;
      const site = rawSite as Record<string, unknown>;
      if (site.kind !== "switch" || site.width_bits !== widthBits) continue;
      if (reachSet.size > 0 && typeof site.function === "string" && !reachSet.has(site.function)) continue;
      if (!Array.isArray(site.cases)) continue;
      for (const rawCase of site.cases) {
        if (!rawCase || typeof rawCase !== "object") continue;
        const c = rawCase as Record<string, unknown>;
        if (typeof c.value === "string" && /^-?[0-9]+$/.test(c.value)) {
          const v = BigInt.asUintN(widthBits, BigInt(c.value));
          if (v >= 0n && v <= maxVal) values.add(v);
        }
      }
    }
  }
  return [...values].sort((a, b) => (b > a ? 1 : b < a ? -1 : 0));
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

export function mutationRuleKey(rule: ScalarMutationRule): string {
  const opKind = rule.opKind ?? "replace_scalar";
  const gen = rule.targetGeneration ?? 1;
  const exec = rule.execMode ?? 0;
  return [
    opKind,
    gen,
    exec,
    rule.selectorOrdinal,
    rule.selectorSeq,
    rule.paramIndex,
    rule.bufferSubOp ?? "",
    rule.byteOffset ?? "",
    rule.sliceLength ?? "",
    rule.repeatCount ?? "",
    rule.expectedBits,
    rule.replacementBits,
  ].join(":");
}

export function planScalarMutations(
  profile: ExplorerProfile,
  baseline: CallCaptureDocument,
  budget: number,
): PlannedMutation[] {
  if (!Number.isSafeInteger(budget) || budget < 0) fail("candidate budget must be a safe nonnegative integer");
  if (budget === 0) return [];
  const guidance = generateProfileScalarCandidates(profile, Math.max(budget, 1));
  const plans = new Map<string, PlannedMutation>();
  for (const candidate of guidance) {
    const scalar = profile.scalarParameterByKey.get(candidate.selector_ordinal + ":" + candidate.param_index);
    const ecall = abiEcall(profile, candidate.selector_ordinal);
    if (!scalar || !ecall || ecall.visibility !== "public") continue;
    const marshal = profile.ecalls.get(candidate.selector_ordinal);
    if (!marshal || !marshal.replaySupported) continue;
    const replacement = integerValue(candidate.value, "guidance candidate value");
    const signBit = 1n << BigInt(scalar.width_bits - 1);
    const minValue = scalar.signedness === "signed" ? -signBit : 0n;
    const maxValue = scalar.signedness === "signed" ? signBit - 1n : (signBit << 1n) - 1n;
    if (replacement < minValue || replacement > maxValue) continue;
    const widthBytes = scalar.width_bits / 8;
    for (const event of eventCandidates(baseline, scalar.ordinal, scalar.param_index)) {
      const captured = event.scalarInputs.find((input) => input.paramIndex === scalar.param_index);
      if (!captured || captured.widthBytes !== widthBytes || captured.signedness !== scalar.signedness) continue;
      if (!preservesDependentBufferBounds(
        profile,
        scalar.ordinal,
        scalar.param_index,
        replacement,
        event,
      )) continue;
      const rule: ScalarMutationRule = {
        ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
        selectorOrdinal: scalar.ordinal,
        selectorSeq: event.selectorSeq,
        paramIndex: scalar.param_index,
        widthBytes: widthBytes as 1 | 2 | 4 | 8,
        signedness: scalar.signedness,
        expectedBits: captured.bits,
        replacementBits: bitsForValue(replacement, scalar.width_bits),
      };
      if (rule.expectedBits === rule.replacementBits) continue;
      const valueKey = mutationRuleKey(rule);
      const existing = plans.get(valueKey);
      if (existing) {
        if (candidate.priority > existing.priority) existing.priority = candidate.priority;
        existing.evidenceSiteIds = sortedUnique([...existing.evidenceSiteIds, ...candidate.evidence_site_ids]);
      } else {
        plans.set(valueKey, {
          rule,
          value: candidate.value,
          priority: candidate.priority,
          evidenceSiteIds: sortedUnique(candidate.evidence_site_ids),
        });
      }
    }
  }
  return [...plans.values()]
    .sort((left, right) =>
      right.priority - left.priority ||
      left.rule.selectorOrdinal - right.rule.selectorOrdinal ||
      left.rule.selectorSeq - right.rule.selectorSeq ||
      left.rule.paramIndex - right.rule.paramIndex ||
      (BigInt(left.value) < BigInt(right.value) ? -1 : BigInt(left.value) > BigInt(right.value) ? 1 : 0) ||
      left.evidenceSiteIds.join(",").localeCompare(right.evidenceSiteIds.join(",")),
    )
    .slice(0, budget);
}

function decodeHexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function readLeUnsigned(bytes: Uint8Array, offset: number, width: 1 | 2 | 4 | 8): bigint {
  let acc = 0n;
  for (let i = 0; i < width; i++) {
    acc |= BigInt(bytes[offset + i]!) << BigInt(i * 8);
  }
  return acc;
}

function candidateOffsetsForBuffer(
  buf: CapturedBufferInput,
  prefixLen: number,
  parentPlan?: PlannedMutation,
): number[] {
  const offsets = new Set<number>();
  if (prefixLen <= 0) return [];
  const limit = buf.isString ? Math.max(1, prefixLen - 1) : prefixLen;
  if (limit <= 0) return [];

  if (parentPlan && parentPlan.rule.opKind === "mutate_buffer" &&
      parentPlan.rule.byteOffset !== undefined) {
    const base = parentPlan.rule.byteOffset;
    for (const delta of [-4, -2, -1, 1, 2, 4, 8, 16]) {
      const next = base + delta;
      if (next >= 0 && next < limit) offsets.add(next);
    }
  }

  for (const fixed of [0, 1, buf.elementSize, Math.floor(limit / 2), limit - 1]) {
    if (fixed >= 0 && fixed < limit) offsets.add(fixed);
  }
  const stride = limit <= 32 ? 4 : limit <= 128 ? 16 : 32;
  for (let off = 0; off < limit; off += stride) {
    offsets.add(off);
  }
  return [...offsets].sort((a, b) => a - b);
}

export function deriveCandidatesFromCase(
  profile: ExplorerProfile,
  parentCapture: CallCaptureDocument,
  options: DeriveCaseOptions,
): PlannedMutation[] {
  const budget = options.budget;
  if (!Number.isSafeInteger(budget) || budget < 0) fail("candidate budget must be a safe nonnegative integer");
  if (budget === 0) return [];

  const plans = new Map<string, PlannedMutation>();
  const addPlan = (plan: PlannedMutation): void => {
    if (plan.rule.expectedBits === plan.rule.replacementBits &&
        (plan.rule.opKind ?? "replace_scalar") !== "extend_history") {
      return;
    }
    const key = mutationRuleKey(plan.rule);
    const existing = plans.get(key);
    if (existing) {
      if (plan.priority > existing.priority) existing.priority = plan.priority;
      existing.evidenceSiteIds = sortedUnique([...existing.evidenceSiteIds, ...plan.evidenceSiteIds]);
    } else {
      plans.set(key, plan);
    }
  };

  const hasNativeBufferCapture = parentCapture.events.some((ev) => ev.bufferInputs !== undefined);

  const maxSeqByGenSelAll = new Map<string, number>();
  for (const ev of parentCapture.events) {
    const k = ev.generation + ":" + ev.selectorOrdinal;
    const prev = maxSeqByGenSelAll.get(k) ?? -1;
    if (ev.selectorSeq > prev) maxSeqByGenSelAll.set(k, ev.selectorSeq);
  }

  // 1. Base IR-guided & boundary scalar mutations across representative occurrences of every selector
  for (const scalarPlan of planScalarMutations(profile, parentCapture, Math.max(budget * 16, 1024))) {
    const gen = scalarPlan.rule.targetGeneration ?? 1;
    const maxSeq = maxSeqByGenSelAll.get(gen + ":" + scalarPlan.rule.selectorOrdinal) ?? 0;
    if (hasNativeBufferCapture && (!hasReachableFields(profile, scalarPlan.rule.selectorOrdinal) || isOneShotEcall(profile, scalarPlan.rule.selectorOrdinal, maxSeq) || (scalarPlan.rule.selectorSeq !== 0 && scalarPlan.rule.selectorSeq !== maxSeq))) {
      continue;
    }
    const marshal = profile.ecalls.get(scalarPlan.rule.selectorOrdinal);
    const isBoundParam = marshal
      ? pointerDependencies(scalarPlan.rule.paramIndex, marshal).length > 0
      : false;
    if (hasNativeBufferCapture) {
      addPlan({
        ...scalarPlan,
        rule: { ...scalarPlan.rule, execMode: 1 },
        priority: scalarPlan.priority,
      });
      if (!isBoundParam) {
        addPlan({
          ...scalarPlan,
          priority: Math.max(100, scalarPlan.priority - 15),
        });
      }
    } else {
      addPlan(scalarPlan);
    }
  }

  // If parentPlan was a scalar mutation, derive neighborhood scalar refinements & sandboxed pre-call variants
  const parentPlan = options.parentMutation;
  if (parentPlan && (parentPlan.rule.opKind ?? "replace_scalar") === "replace_scalar") {
    const scalar = profile.scalarParameterByKey.get(
      parentPlan.rule.selectorOrdinal + ":" + parentPlan.rule.paramIndex,
    );
    if (scalar) {
      const signBit = 1n << BigInt(scalar.width_bits - 1);
      const minValue = scalar.signedness === "signed" ? -signBit : 0n;
      const maxValue = scalar.signedness === "signed" ? signBit - 1n : (signBit << 1n) - 1n;
      const baseVal = BigInt(parentPlan.value);
      const neighbors = [baseVal - 1n, baseVal + 1n, baseVal - 2n, baseVal + 2n, baseVal * 2n, baseVal >> 1n];
      const widthBytes = (scalar.width_bits / 8) as 1 | 2 | 4 | 8;
      for (const event of eventCandidates(parentCapture, scalar.ordinal, scalar.param_index)) {
        const captured = event.scalarInputs.find((i) => i.paramIndex === scalar.param_index);
        if (!captured) continue;
        for (const nextVal of neighbors) {
          if (nextVal < minValue || nextVal > maxValue) continue;
          if (!preservesDependentBufferBounds(profile, scalar.ordinal, scalar.param_index, nextVal, event)) continue;
          const repBits = bitsForValue(nextVal, scalar.width_bits);
          if (repBits === captured.bits) continue;
          addPlan({
            rule: {
              ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
              selectorOrdinal: scalar.ordinal,
              selectorSeq: event.selectorSeq,
              paramIndex: scalar.param_index,
              widthBytes,
              signedness: scalar.signedness,
              expectedBits: captured.bits,
              replacementBits: repBits,
            },
            value: nextVal.toString(10),
            priority: parentPlan.priority + 35,
            evidenceSiteIds: parentPlan.evidenceSiteIds,
          });
        }
      }
    }
  }

  // 2. Structured Buffer Mutations (xor_byte, fill_slice, write_le) derived from captured buffer inputs
  if (options.includeBuffers !== false) {
    const maxSeqByGenSel = new Map<string, number>();
    for (const ev of parentCapture.events) {
      const k = ev.generation + ":" + ev.selectorOrdinal;
      const prev = maxSeqByGenSel.get(k) ?? -1;
      if (ev.selectorSeq > prev) maxSeqByGenSel.set(k, ev.selectorSeq);
    }

    for (const event of parentCapture.events) {
      const marshal = profile.ecalls.get(event.selectorOrdinal);
      const ecall = abiEcall(profile, event.selectorOrdinal);
      if (!marshal || !marshal.replaySupported || marshal.params.length === 0 || !ecall || ecall.visibility !== "public") continue;
      if (hasNativeBufferCapture && !hasReachableFields(profile, event.selectorOrdinal)) continue;
      const buffers = event.bufferInputs ?? [];
      if (buffers.length === 0) continue;

      const maxSeq = maxSeqByGenSel.get(event.generation + ":" + event.selectorOrdinal) ?? 0;
      if (hasNativeBufferCapture && isOneShotEcall(profile, event.selectorOrdinal, maxSeq)) continue;
      const isLastOccurrence = event.selectorSeq === maxSeq;
      if (event.selectorSeq !== 0 && !isLastOccurrence) continue;

      for (const buf of buffers) {
        const prefixBytes = decodeHexBytes(buf.prefixHex);
        if (prefixBytes.length === 0) continue;
        const offsets = candidateOffsetsForBuffer(buf, prefixBytes.length, parentPlan);

        // (a) Single-byte XOR flips at structured & refined neighborhood offsets
        for (const off of offsets) {
          const origByte = prefixBytes[off]!;
          const expHex = "0x" + origByte.toString(16).padStart(2, "0");
          for (const mask of [0x01, 0xff, 0x80]) {
            const repByte = (origByte ^ mask) & 0xff;
            const repHex = "0x" + repByte.toString(16).padStart(2, "0");
            const isRefinedChild = parentPlan?.rule.opKind === "mutate_buffer" &&
              parentPlan.rule.paramIndex === buf.paramIndex &&
              parentPlan.rule.byteOffset !== undefined &&
              Math.abs(parentPlan.rule.byteOffset - off) <= 4;
            const basePrio = isRefinedChild ? 990 : (off === 0 || off === prefixBytes.length - 1 ? 975 : 940);

            // In-place buffer mutation (execMode: 0) when on final occurrence or non-0 offset
            if (isLastOccurrence || off > 0) {
              addPlan({
                rule: {
                  opKind: "mutate_buffer",
                  bufferSubOp: "xor_byte",
                  ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
                  execMode: 0,
                  selectorOrdinal: event.selectorOrdinal,
                  selectorSeq: event.selectorSeq,
                  paramIndex: buf.paramIndex,
                  byteOffset: off,
                  sliceLength: 1,
                  widthBytes: 1,
                  signedness: "unsigned",
                  expectedBits: expHex,
                  replacementBits: repHex,
                },
                value: `buf_xor:p${buf.paramIndex}@${off}^0x${mask.toString(16)}`,
                priority: basePrio,
                evidenceSiteIds: [`buf:e${event.selectorOrdinal}:p${buf.paramIndex}:off${off}`],
              });
            }

            // Sandboxed pre-call buffer mutation (execMode: 1) so legal error paths / baseline checks complete cleanly
            addPlan({
              rule: {
                opKind: "mutate_buffer",
                bufferSubOp: "xor_byte",
                ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
                execMode: 1,
                selectorOrdinal: event.selectorOrdinal,
                selectorSeq: event.selectorSeq,
                paramIndex: buf.paramIndex,
                byteOffset: off,
                sliceLength: 1,
                widthBytes: 1,
                signedness: "unsigned",
                expectedBits: expHex,
                replacementBits: repHex,
              },
              value: `precall_buf_xor:p${buf.paramIndex}@${off}^0x${mask.toString(16)}`,
              priority: basePrio + 5,
              evidenceSiteIds: [`buf_precall:e${event.selectorOrdinal}:p${buf.paramIndex}:off${off}`],
            });
          }
        }

        // (b) Slice fill mutations (0x00, 0xff, '0', 'g')
        const fillLen = buf.isString
          ? Math.max(1, prefixBytes.length - 1)
          : Math.min(prefixBytes.length, 64);
        if (fillLen >= 1) {
          const expHex = "0x" + prefixBytes[0]!.toString(16).padStart(2, "0");
          const fillPatterns = buf.isString ? [0x30, 0x67, 0x41] : [0x00, 0xff, 0x55];
          for (const fillByte of fillPatterns) {
            const repHex = "0x" + fillByte.toString(16).padStart(2, "0");
            for (const execMode of [1, 0]) {
              addPlan({
                rule: {
                  opKind: "mutate_buffer",
                  bufferSubOp: "fill_slice",
                  ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
                  execMode,
                  selectorOrdinal: event.selectorOrdinal,
                  selectorSeq: event.selectorSeq,
                  paramIndex: buf.paramIndex,
                  byteOffset: 0,
                  sliceLength: fillLen,
                  widthBytes: 1,
                  signedness: "unsigned",
                  expectedBits: expHex,
                  replacementBits: repHex,
                },
                value: `buf_fill(exec=${execMode}):p${buf.paramIndex}[0..${fillLen}]=${repHex}`,
                priority: execMode === 1 ? 965 : 920,
                evidenceSiteIds: [`buf_fill:e${event.selectorOrdinal}:p${buf.paramIndex}:${repHex}`],
              });
            }
          }
        }

        // (c) Typed element / struct header little-endian word writes (write_le)
        const elemW = ([1, 2, 4, 8].includes(buf.elementSize)
          ? buf.elementSize
          : (prefixBytes.length >= 4 ? 4 : 1)) as 1 | 2 | 4 | 8;
        if (elemW > 1 && prefixBytes.length >= elemW) {
          const wordOffsets = new Set<number>([0]);
          if (buf.elementSize > elemW && prefixBytes.length >= buf.elementSize && (buf.elementSize - elemW) % elemW === 0) {
            wordOffsets.add(buf.elementSize - elemW);
          }
          if (prefixBytes.length >= 2 * elemW) wordOffsets.add(elemW);
          const bufParam = marshal.params.find((param) => param.paramIndex === buf.paramIndex);
          const switchWordVals = bufParam?.elementTypeCategory === "record"
            ? reachableSwitchConstants(profile, event.selectorOrdinal, elemW * 8)
            : [];
          for (const wOff of wordOffsets) {
            if (wOff + elemW > prefixBytes.length) continue;
            const obsWord = readLeUnsigned(prefixBytes, wOff, elemW);
            const expWordHex = bitsForValue(obsWord, elemW * 8);
            for (const swVal of switchWordVals) {
              const repWordHex = bitsForValue(swVal, elemW * 8);
              if (repWordHex === expWordHex) continue;
              for (const execMode of [1, 0]) {
                addPlan({
                  rule: {
                    opKind: "mutate_buffer",
                    bufferSubOp: "write_le",
                    ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
                    execMode,
                    selectorOrdinal: event.selectorOrdinal,
                    selectorSeq: event.selectorSeq,
                    paramIndex: buf.paramIndex,
                    byteOffset: wOff,
                    sliceLength: elemW,
                    widthBytes: elemW,
                    signedness: "unsigned",
                    expectedBits: expWordHex,
                    replacementBits: repWordHex,
                  },
                  value: `buf_word_const(exec=${execMode}):p${buf.paramIndex}@${wOff}=${repWordHex}`,
                  priority: execMode === 1 ? 974 : 927,
                  evidenceSiteIds: [`buf_word_const:e${event.selectorOrdinal}:p${buf.paramIndex}:off${wOff}:${repWordHex}`],
                });
              }
            }
            for (const wordVal of [0n, 1n, 2n, (1n << BigInt(elemW * 8)) - 1n]) {
              const repWordHex = bitsForValue(wordVal, elemW * 8);
              if (repWordHex === expWordHex) continue;
              const isZeroOrOne = wordVal === 0n || wordVal === 1n;
              for (const execMode of [1, 0]) {
                addPlan({
                  rule: {
                    opKind: "mutate_buffer",
                    bufferSubOp: "write_le",
                    ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
                    execMode,
                    selectorOrdinal: event.selectorOrdinal,
                    selectorSeq: event.selectorSeq,
                    paramIndex: buf.paramIndex,
                    byteOffset: wOff,
                    sliceLength: elemW,
                    widthBytes: elemW,
                    signedness: "unsigned",
                    expectedBits: expWordHex,
                    replacementBits: repWordHex,
                  },
                  value: `buf_word(exec=${execMode}):p${buf.paramIndex}@${wOff}=${repWordHex}`,
                  priority: execMode === 1 ? (isZeroOrOne ? 988 : 968) : 925,
                  evidenceSiteIds: [`buf_word:e${event.selectorOrdinal}:p${buf.paramIndex}:off${wOff}:${repWordHex}`],
                });
              }
            }
          }
        }
      }
    }
  }

  // 3. Bounded Legal Call-History Extensions (extend_history)
  if ((options.includeHistory === true || (options.includeHistory !== false && hasNativeBufferCapture)) && (options.depth ?? 0) < 2) {
    for (const event of parentCapture.events) {
      const marshal = profile.ecalls.get(event.selectorOrdinal);
      const ecall = abiEcall(profile, event.selectorOrdinal);
      if (!marshal || !marshal.replaySupported || !ecall || ecall.visibility !== "public") continue;
      const maxSeqHist = maxSeqByGenSelAll.get(event.generation + ":" + event.selectorOrdinal) ?? 0;
      if (hasNativeBufferCapture && (!hasReachableFields(profile, event.selectorOrdinal) || isOneShotEcall(profile, event.selectorOrdinal, maxSeqHist))) continue;

      const firstParamIndex = marshal.params[0]?.paramIndex ?? 0;
      for (const repeatCount of [1, 2]) {
        addPlan({
          rule: {
            opKind: "extend_history",
            ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
            execMode: repeatCount,
            repeatCount,
            selectorOrdinal: event.selectorOrdinal,
            selectorSeq: event.selectorSeq,
            paramIndex: firstParamIndex,
            widthBytes: 1,
            signedness: "unsigned",
            expectedBits: "0x00",
            replacementBits: "0x00",
          },
          value: `extend_history:e${event.selectorOrdinal}@s${event.selectorSeq}+${repeatCount}`,
          priority: (repeatCount === 1 && event.selectorSeq === 0) ? 985 : (repeatCount === 1 ? 945 : 910),
          evidenceSiteIds: [`history:g${event.generation}:e${event.selectorOrdinal}:s${event.selectorSeq}:r${repeatCount}`],
        });
      }
    }
  }

  const sortedAll = [...plans.values()].sort((left, right) =>
    right.priority - left.priority ||
    left.rule.selectorOrdinal - right.rule.selectorOrdinal ||
    left.rule.selectorSeq - right.rule.selectorSeq ||
    left.rule.paramIndex - right.rule.paramIndex ||
    left.value.localeCompare(right.value),
  );
  if (!hasNativeBufferCapture) {
    return sortedAll.slice(0, budget);
  }
  const buckets = new Map<string, PlannedMutation[]>();
  for (const item of sortedAll) {
    const bKey = item.rule.selectorOrdinal + ":" + (item.rule.opKind ?? "replace_scalar") + ":" + (item.rule.bufferSubOp ?? "");
    const list = buckets.get(bKey) ?? [];
    list.push(item);
    buckets.set(bKey, list);
  }
  const interleaved: PlannedMutation[] = [];
  const bucketLists = [...buckets.values()];
  let idx = 0;
  while (interleaved.length < budget) {
    let any = false;
    for (const list of bucketLists) {
      if (idx < list.length) {
        interleaved.push(list[idx]!);
        any = true;
        if (interleaved.length >= budget) break;
      }
    }
    if (!any) break;
    idx++;
  }
  return interleaved;
}

export function deriveChildCandidatesFromFeedback(
  profile: ExplorerProfile,
  baselineCapture: CallCaptureDocument,
  discoveredCapture: CallCaptureDocument,
  parentPlan: PlannedMutation,
  depth: number,
  budget: number,
): PlannedMutation[] {
  if (budget <= 0 || depth <= 0) return [];
  const hasNativeBufferCapture = discoveredCapture.events.some((ev) => ev.bufferInputs !== undefined);
  const plans = new Map<string, PlannedMutation>();
  const addPlan = (plan: PlannedMutation): void => {
    if (plan.rule.expectedBits === plan.rule.replacementBits &&
        (plan.rule.opKind ?? "replace_scalar") !== "extend_history") {
      return;
    }
    const key = mutationRuleKey(plan.rule);
    const existing = plans.get(key);
    if (existing) {
      if (plan.priority > existing.priority) existing.priority = plan.priority;
      existing.evidenceSiteIds = sortedUnique([...existing.evidenceSiteIds, ...plan.evidenceSiteIds]);
    } else {
      plans.set(key, plan);
    }
  };

  const opKind = parentPlan.rule.opKind ?? "replace_scalar";
  const wantGen = parentPlan.rule.targetGeneration ?? 1;
  const parentExec = opKind === "extend_history"
    ? (parentPlan.rule.repeatCount ?? parentPlan.rule.execMode ?? 1)
    : (parentPlan.rule.execMode ?? 0);

  // Locate the corresponding baseline event so child rules remain replayable from seed
  const baseEvent = baselineCapture.events.find((ev) =>
    ev.generation === wantGen &&
    ev.selectorOrdinal === parentPlan.rule.selectorOrdinal &&
    ev.selectorSeq === parentPlan.rule.selectorSeq);

  // Observed return / output state from the discovered case boosts priority
  const discEvent = discoveredCapture.events.find((ev) => ev.mutation?.applied === true);
  const retvalBits = discEvent?.retval?.bits ?? "none";

  // Case A: Parent was a scalar mutation -> derive neighborhood scalar values & history-coupled scalar/buffer probes
  if (opKind === "replace_scalar" && baseEvent) {
    const scalar = profile.scalarParameterByKey.get(
      parentPlan.rule.selectorOrdinal + ":" + parentPlan.rule.paramIndex,
    );
    if (scalar) {
      const signBit = 1n << BigInt(scalar.width_bits - 1);
      const minValue = scalar.signedness === "signed" ? -signBit : 0n;
      const maxValue = scalar.signedness === "signed" ? signBit - 1n : (signBit << 1n) - 1n;
      let baseVal = 0n;
      try { baseVal = BigInt(parentPlan.value); } catch { baseVal = BigInt(parentPlan.rule.replacementBits); }
      const neighbors = [
        baseVal - 1n, baseVal + 1n, baseVal - 2n, baseVal + 2n,
        baseVal * 2n, baseVal >> 1n, baseVal ^ 1n,
      ];
      const widthBytes = (scalar.width_bits / 8) as 1 | 2 | 4 | 8;
      const captured = baseEvent.scalarInputs.find((i) => i.paramIndex === scalar.param_index);
      if (captured) {
        for (const nextVal of neighbors) {
          if (nextVal < minValue || nextVal > maxValue) continue;
          if (!preservesDependentBufferBounds(profile, scalar.ordinal, scalar.param_index, nextVal, baseEvent)) continue;
          const repBits = bitsForValue(nextVal, scalar.width_bits);
          if (repBits === captured.bits) continue;
          addPlan({
            rule: {
              ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
              ...(parentExec > 0 ? { execMode: parentExec } : {}),
              selectorOrdinal: scalar.ordinal,
              selectorSeq: baseEvent.selectorSeq,
              paramIndex: scalar.param_index,
              widthBytes,
              signedness: scalar.signedness,
              expectedBits: captured.bits,
              replacementBits: repBits,
            },
            value: nextVal.toString(10),
            priority: hasNativeBufferCapture ? Math.min(1010, parentPlan.priority + 10) : Math.max(80, parentPlan.priority - 40),
            evidenceSiteIds: parentPlan.evidenceSiteIds,
          });
        }
      }
    }
  }

  // Case B: Parent was a buffer or scalar mutation -> derive neighboring byte offsets and cross-parameter struct-word probes on baseEvent
  if ((opKind === "mutate_buffer" || opKind === "replace_scalar") && baseEvent) {
    for (const otherBuf of baseEvent.bufferInputs ?? []) {
      const pBytes = decodeHexBytes(otherBuf.prefixHex);
      const elemW = ([1, 2, 4, 8].includes(otherBuf.elementSize)
        ? otherBuf.elementSize
        : (pBytes.length >= 4 ? 4 : 1)) as 1 | 2 | 4 | 8;
      if (elemW > 1 && pBytes.length >= elemW) {
        const wOffsets = [0];
        if (otherBuf.elementSize > elemW && pBytes.length >= otherBuf.elementSize && (otherBuf.elementSize - elemW) % elemW === 0) {
          wOffsets.push(otherBuf.elementSize - elemW);
        }
        const childMarshal = profile.ecalls.get(baseEvent.selectorOrdinal);
        const childParam = childMarshal?.params.find((param) => param.paramIndex === otherBuf.paramIndex);
        const childSwitchVals = childParam?.elementTypeCategory === "record" && elemW === 4
          ? reachableSwitchConstants(profile, baseEvent.selectorOrdinal, elemW * 8)
          : [];
        for (const wOff of wOffsets) {
          if (wOff + elemW > pBytes.length) continue;
          const obsW = readLeUnsigned(pBytes, wOff, elemW);
          const expHex = bitsForValue(obsW, elemW * 8);
          for (const swVal of childSwitchVals) {
            const repHex = bitsForValue(swVal, elemW * 8);
            if (repHex === expHex) continue;
            addPlan({
              rule: {
                opKind: "mutate_buffer",
                bufferSubOp: "write_le",
                ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
                execMode: 1,
                selectorOrdinal: baseEvent.selectorOrdinal,
                selectorSeq: baseEvent.selectorSeq,
                paramIndex: otherBuf.paramIndex,
                byteOffset: wOff,
                sliceLength: elemW,
                widthBytes: elemW,
                signedness: "unsigned",
                expectedBits: expHex,
                replacementBits: repHex,
              },
              value: `derived_buf_word_const(d=${depth}):p${otherBuf.paramIndex}@${wOff}=${repHex}`,
              priority: Math.min(1013, parentPlan.priority + 19),
              evidenceSiteIds: [
                ...parentPlan.evidenceSiteIds,
                `derived_word_const:d${depth}:e${baseEvent.selectorOrdinal}:p${otherBuf.paramIndex}:off${wOff}:${repHex}`,
              ],
            });
          }
          for (const wVal of [0n, 1n]) {
            const repHex = bitsForValue(wVal, elemW * 8);
            if (repHex === expHex) continue;
            addPlan({
              rule: {
                opKind: "mutate_buffer",
                bufferSubOp: "write_le",
                ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
                execMode: 1,
                selectorOrdinal: baseEvent.selectorOrdinal,
                selectorSeq: baseEvent.selectorSeq,
                paramIndex: otherBuf.paramIndex,
                byteOffset: wOff,
                sliceLength: elemW,
                widthBytes: elemW,
                signedness: "unsigned",
                expectedBits: expHex,
                replacementBits: repHex,
              },
              value: `derived_buf_word(d=${depth}):p${otherBuf.paramIndex}@${wOff}=${repHex}`,
              priority: Math.min(1012, parentPlan.priority + 18),
              evidenceSiteIds: [
                ...parentPlan.evidenceSiteIds,
                `derived_word:d${depth}:e${baseEvent.selectorOrdinal}:p${otherBuf.paramIndex}:off${wOff}:${repHex}`,
              ],
            });
          }
        }
      }
    }
    const buf = (baseEvent.bufferInputs ?? []).find((b) => b.paramIndex === parentPlan.rule.paramIndex) ?? (baseEvent.bufferInputs ?? [])[0];
    if (buf) {
      const prefixBytes = decodeHexBytes(buf.prefixHex);
      const limit = buf.isString ? Math.max(1, prefixBytes.length - 1) : prefixBytes.length;
      const baseOff = parentPlan.rule.byteOffset ?? 0;
      const neighborOffsets = new Set<number>();
      for (const delta of [-4, -2, -1, 1, 2, 3, 4, 8, 12, 16]) {
        const nextOff = baseOff + delta;
        if (nextOff >= 0 && nextOff < limit) neighborOffsets.add(nextOff);
      }
      for (const off of neighborOffsets) {
        const origByte = prefixBytes[off]!;
        const expHex = "0x" + origByte.toString(16).padStart(2, "0");
        for (const mask of [0x01, 0xff, 0x80, 0x55]) {
          const repByte = (origByte ^ mask) & 0xff;
          const repHex = "0x" + repByte.toString(16).padStart(2, "0");
          addPlan({
            rule: {
              opKind: "mutate_buffer",
              bufferSubOp: "xor_byte",
              ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
              execMode: parentExec,
              selectorOrdinal: baseEvent.selectorOrdinal,
              selectorSeq: baseEvent.selectorSeq,
              paramIndex: buf.paramIndex,
              byteOffset: off,
              sliceLength: 1,
              widthBytes: 1,
              signedness: "unsigned",
              expectedBits: expHex,
              replacementBits: repHex,
            },
            value: `derived_buf_xor(d=${depth}):p${buf.paramIndex}@${off}^0x${mask.toString(16)}`,
            priority: Math.min(1010, parentPlan.priority + 15),
            evidenceSiteIds: [
              ...parentPlan.evidenceSiteIds,
              `derived_buf:d${depth}:e${baseEvent.selectorOrdinal}:p${buf.paramIndex}:off${off}`,
            ],
          });
        }
      }
    }
  }

  // Case C: Parent was a call-history extension (or pre-call) -> derive deeper history + history-coupled buffer & scalar mutations!
  if ((opKind === "extend_history" || parentExec >= 1) && baseEvent) {
    const nextRepeat = Math.min(4, parentExec + 1);
    if (nextRepeat > parentExec) {
      addPlan({
        rule: {
          opKind: "extend_history",
          ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
          execMode: nextRepeat,
          repeatCount: nextRepeat,
          selectorOrdinal: baseEvent.selectorOrdinal,
          selectorSeq: baseEvent.selectorSeq,
          paramIndex: parentPlan.rule.paramIndex,
          widthBytes: 1,
          signedness: "unsigned",
          expectedBits: "0x00",
          replacementBits: "0x00",
        },
        value: `derived_extend_history(d=${depth}):e${baseEvent.selectorOrdinal}@s${baseEvent.selectorSeq}+${nextRepeat}`,
        priority: Math.min(1010, parentPlan.priority + 15),
        evidenceSiteIds: [
          ...parentPlan.evidenceSiteIds,
          `derived_history:d${depth}:g${wantGen}:e${baseEvent.selectorOrdinal}:s${baseEvent.selectorSeq}:r${nextRepeat}`,
        ],
      });
    }

    // Derive history-coupled buffer mutations on the extended call history (execMode = parentExec)
    for (const buf of baseEvent.bufferInputs ?? []) {
      const prefixBytes = decodeHexBytes(buf.prefixHex);
      if (prefixBytes.length === 0) continue;
      const limit = buf.isString ? Math.max(1, prefixBytes.length - 1) : prefixBytes.length;
      for (const off of [0, Math.min(1, limit - 1), Math.floor(limit / 2), limit - 1]) {
        if (off < 0 || off >= limit) continue;
        const origByte = prefixBytes[off]!;
        const expHex = "0x" + origByte.toString(16).padStart(2, "0");
        const repHex = "0x" + ((origByte ^ 0x01) & 0xff).toString(16).padStart(2, "0");
        addPlan({
          rule: {
            opKind: "mutate_buffer",
            bufferSubOp: "xor_byte",
            ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
            execMode: parentExec,
            selectorOrdinal: baseEvent.selectorOrdinal,
            selectorSeq: baseEvent.selectorSeq,
            paramIndex: buf.paramIndex,
            byteOffset: off,
            sliceLength: 1,
            widthBytes: 1,
            signedness: "unsigned",
            expectedBits: expHex,
            replacementBits: repHex,
          },
          value: `history_coupled_buf_xor(d=${depth},r=${parentExec}):p${buf.paramIndex}@${off}`,
          priority: Math.min(1015, parentPlan.priority + 20),
          evidenceSiteIds: [
            ...parentPlan.evidenceSiteIds,
            `history_buf:d${depth}:r${parentExec}:e${baseEvent.selectorOrdinal}:p${buf.paramIndex}:off${off}`,
          ],
        });
      }
    }

    // Derive history-coupled scalar mutations on the extended call history (execMode = parentExec)
    for (const scInput of baseEvent.scalarInputs) {
      const scalar = profile.scalarParameterByKey.get(baseEvent.selectorOrdinal + ":" + scInput.paramIndex);
      if (!scalar) continue;
      const obsVal = capturedValue(baseEvent, scInput.paramIndex);
      if (obsVal === undefined) continue;
      const candidates = obsVal > 0n ? [0n, 1n, obsVal - 1n] : [1n, 2n];
      for (const nextVal of candidates) {
        if (!preservesDependentBufferBounds(profile, scalar.ordinal, scalar.param_index, nextVal, baseEvent)) continue;
        const repBits = bitsForValue(nextVal, scalar.width_bits);
        if (repBits === scInput.bits) continue;
        addPlan({
          rule: {
            opKind: "replace_scalar",
            ...(wantGen !== 1 ? { targetGeneration: wantGen } : {}),
            execMode: parentExec,
            selectorOrdinal: baseEvent.selectorOrdinal,
            selectorSeq: baseEvent.selectorSeq,
            paramIndex: scInput.paramIndex,
            widthBytes: scInput.widthBytes,
            signedness: scInput.signedness,
            expectedBits: scInput.bits,
            replacementBits: repBits,
          },
          value: nextVal.toString(10),
          priority: hasNativeBufferCapture ? Math.min(1010, parentPlan.priority + 10) : Math.max(80, parentPlan.priority - 40),
          evidenceSiteIds: [
            ...parentPlan.evidenceSiteIds,
            `history_scalar:d${depth}:r${parentExec}:e${baseEvent.selectorOrdinal}:p${scInput.paramIndex}:${nextVal.toString(10)}`,
          ],
        });
      }
    }
  }

  return [...plans.values()]
    .sort((left, right) =>
      right.priority - left.priority ||
      left.rule.selectorOrdinal - right.rule.selectorOrdinal ||
      left.rule.selectorSeq - right.rule.selectorSeq ||
      left.rule.paramIndex - right.rule.paramIndex ||
      left.value.localeCompare(right.value),
    )
    .slice(0, budget);
}
