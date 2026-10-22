import type {
  CallCaptureDocument,
  CallCaptureEvent,
  CapturedBufferInput,
  CapturedBufferOutput,
  DataflowTarget,
  ScalarMutationRule,
} from "./contract.ts";
import type { ExplorerProfile, MarshalEcall, MarshalParameter } from "./profile.ts";
import { CALL_CAPTURE_MAX_BUF_PREFIX_BYTES } from "./contract.ts";
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
  frontier?: FrontierEntry[];
  measuredFieldCallKeys?: ReadonlySet<string>;
  expansionBufferBudgetBytes?: bigint;
  expansionTotalBudgetBytes?: bigint;
  parentMutation?: PlannedMutation;
  includeBuffers?: boolean;
  includeHistory?: boolean;
}

export function linkedConsumerCallKey(rule: ScalarMutationRule): string | null {
  const target = rule.dataflowTarget;
  return target
    ? [target.consumerGeneration, target.consumerCallSeq,
        target.consumerSelectorOrdinal, target.consumerSelectorSeq].join(":")
    : null;
}

export function reserveLinkedConsumerCallKeys(
  plans: readonly PlannedMutation[],
  measuredFieldCallKeys: ReadonlySet<string>,
  candidateBudget: number,
): string[] {
  if (!Number.isSafeInteger(candidateBudget) || candidateBudget < 0) {
    fail("linked consumer reservation budget must be a safe nonnegative integer");
  }
  const seen = new Set<string>();
  const measured: string[] = [];
  const unmeasured: string[] = [];
  for (const plan of plans) {
    const key = linkedConsumerCallKey(plan.rule);
    if (key === null || seen.has(key)) continue;
    seen.add(key);
    (measuredFieldCallKeys.has(key) ? measured : unmeasured).push(key);
  }
  const reserved = measured.slice(0, candidateBudget);
  if (reserved.length < candidateBudget && unmeasured.length > 0) reserved.push(unmeasured[0]!);
  return reserved;
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

export const DEFAULT_EXPANSION_BUFFER_BUDGET_BYTES = 64n * 1024n;
export const DEFAULT_EXPANSION_TOTAL_BUDGET_BYTES = 256n * 1024n;

export interface FrontierEntry {
  reason: string;
  selectorOrdinal: number;
  selectorSeq: number;
  paramIndex: number;
  candidateValue: string;
  affectedBuffers: Array<{ paramIndex: number; oldBytes: string; newBytes: string }>;
  targetGeneration?: number;
  candidateKey?: string;
  seedId?: string;
  stage?: "planning" | "execution";
  rule?: ScalarMutationRule;
}

export interface LinkedExpansionCheckResult {
  status: "in_place_ok" | "expanded_ok" | "expansion_budget_exceeded" | "unsupported";
  reason: string | null;
  affectedBuffers: Array<{ paramIndex: number; oldBytes: bigint; newBytes: bigint }>;
}

export function evaluateLinkedBufferExpansion(
  profile: ExplorerProfile,
  ordinal: number,
  scalarIndex: number,
  replacement: bigint,
  baselineEvent: CallCaptureEvent,
  perBufferBudgetBytes: bigint = DEFAULT_EXPANSION_BUFFER_BUDGET_BYTES,
  totalBudgetBytes: bigint = DEFAULT_EXPANSION_TOTAL_BUDGET_BYTES,
): LinkedExpansionCheckResult {
  const marshal = profile.ecalls.get(ordinal);
  if (!marshal || !marshal.replaySupported) {
    return { status: "unsupported", reason: "unsupported_mutation_layout", affectedBuffers: [] };
  }
  const dependencies = pointerDependencies(scalarIndex, marshal);
  if (dependencies.length === 0) {
    return { status: "in_place_ok", reason: null, affectedBuffers: [] };
  }
  if (replacement < 0n) {
    return { status: "unsupported", reason: "negative_bound_value", affectedBuffers: [] };
  }
  const affectedBuffers: Array<{ paramIndex: number; oldBytes: bigint; newBytes: bigint }> = [];
  let anyExpanded = false;
  let totalNewBytes = 0n;
  const limit64 = (1n << 64n) - 1n;
  for (const pointer of dependencies) {
    if (!pointer.replaySupported || pointer.userCheck ||
        (pointer.boundKind !== "size_bytes" && pointer.boundKind !== "count_elements")) {
      return { status: "unsupported", reason: "pointer_bound_unproven", affectedBuffers: [] };
    }
    const oldValue = capturedValue(baselineEvent, scalarIndex);
    if (oldValue === undefined || oldValue < 0n) {
      return { status: "unsupported", reason: "pointer_bound_unproven", affectedBuffers: [] };
    }
    let oldBytes = oldValue;
    let newBytes = replacement;
    if (pointer.boundKind === "count_elements") {
      if (pointer.elementSize === null || pointer.elementSize < 1) {
        return { status: "unsupported", reason: "pointer_bound_unproven", affectedBuffers: [] };
      }
      const elementSize = BigInt(pointer.elementSize);
      oldBytes *= elementSize;
      newBytes *= elementSize;
    } else if (pointer.boundKind === "size_bytes" && pointer.elementSize !== null && pointer.elementSize > 1) {
      const elementSize = BigInt(pointer.elementSize);
      if (oldBytes % elementSize === 0n && newBytes % elementSize !== 0n && pointer.elementTypeCategory !== "record") {
        return { status: "unsupported", reason: "nonintegral_element_bound", affectedBuffers: [] };
      }
    }
    if (oldBytes > limit64 || newBytes > limit64) {
      return { status: "unsupported", reason: "bound_multiplication_overflow", affectedBuffers: [] };
    }
    if (newBytes > oldBytes) anyExpanded = true;
    totalNewBytes += newBytes;
    affectedBuffers.push({ paramIndex: pointer.paramIndex, oldBytes, newBytes });
  }
  for (const item of affectedBuffers) {
    if (item.newBytes > perBufferBudgetBytes || totalNewBytes > totalBudgetBytes) {
      return { status: "expansion_budget_exceeded", reason: "expansion_budget_exceeded", affectedBuffers };
    }
  }
  return {
    status: anyExpanded ? "expanded_ok" : "in_place_ok",
    reason: null,
    affectedBuffers,
  };
}

function preservesDependentBufferBounds(
  profile: ExplorerProfile,
  ordinal: number,
  scalarIndex: number,
  replacement: bigint,
  baselineEvent: CallCaptureEvent,
  allowLinkedExpansion: boolean = false,
  frontier?: FrontierEntry[],
  budgets?: { perBufferBytes?: bigint; totalBytes?: bigint },
): boolean {
  const res = evaluateLinkedBufferExpansion(
    profile, ordinal, scalarIndex, replacement, baselineEvent,
    budgets?.perBufferBytes ?? DEFAULT_EXPANSION_BUFFER_BUDGET_BYTES,
    budgets?.totalBytes ?? DEFAULT_EXPANSION_TOTAL_BUDGET_BYTES);
  if (res.status === "in_place_ok") return true;
  if (allowLinkedExpansion && res.status === "expanded_ok") return true;
  if (res.status === "expansion_budget_exceeded" && frontier) {
    frontier.push({
      reason: res.reason ?? "expansion_budget_exceeded",
      selectorOrdinal: ordinal,
      selectorSeq: baselineEvent.selectorSeq,
      paramIndex: scalarIndex,
      candidateValue: replacement.toString(10),
      affectedBuffers: res.affectedBuffers.map((b) => ({
        paramIndex: b.paramIndex,
        oldBytes: b.oldBytes.toString(10),
        newBytes: b.newBytes.toString(10),
      })),
    });
  }
  return false;
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

function recordCandidatePoolLimit(
  frontier: FrontierEntry[] | undefined,
  allPlans: readonly PlannedMutation[],
  selectedPlans: readonly PlannedMutation[],
): void {
  if (!frontier) return;
  const selectedKeys = new Set(selectedPlans.map((plan) => mutationRuleKey(plan.rule)));
  for (const plan of allPlans) {
    const candidateKey = mutationRuleKey(plan.rule);
    if (selectedKeys.has(candidateKey)) continue;
    frontier.push({
      reason: "candidate_pool_limit",
      selectorOrdinal: plan.rule.selectorOrdinal,
      selectorSeq: plan.rule.selectorSeq,
      paramIndex: plan.rule.paramIndex,
      candidateValue: plan.value,
      affectedBuffers: [],
      targetGeneration: plan.rule.targetGeneration ?? 1,
      candidateKey,
      stage: "planning",
      rule: plan.rule,
    });
  }
}

export function mutationRuleKey(rule: ScalarMutationRule): string {
  const opKind = rule.opKind ?? "replace_scalar";
  const gen = rule.targetGeneration ?? 1;
  const exec = rule.execMode ?? 0;
  const prefixKey = (rule.prefixMutations ?? []).map((pfx) =>
    [pfx.selectorOrdinal, pfx.selectorSeq, pfx.paramIndex, pfx.byteOffset,
     pfx.widthBytes, pfx.expectedBits, pfx.replacementBits].join(",")).join("|");
  const expansionBudgetKey = rule.expansionBudget
    ? [rule.expansionBudget.perBufferBytes, rule.expansionBudget.totalBytes].join(",")
    : "";
  const dataflowTargetKey = rule.dataflowTarget
    ? [
        rule.dataflowTarget.consumerGeneration,
        rule.dataflowTarget.consumerCallSeq,
        rule.dataflowTarget.consumerSelectorOrdinal,
        rule.dataflowTarget.consumerSelectorSeq,
        rule.dataflowTarget.consumerParamIndex,
        rule.dataflowTarget.consumerByteOffset,
        rule.dataflowTarget.consumerWidthBytes,
        rule.dataflowTarget.baselineBits,
        rule.dataflowTarget.propagatedBits,
        rule.dataflowTarget.bufferByteLength,
        rule.dataflowTarget.elementSize,
      ].join(",")
    : "";
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
    rule.widthBytes,
    rule.signedness,
    rule.expectedBits,
    rule.replacementBits,
    prefixKey,
    expansionBudgetKey,
    dataflowTargetKey,
  ].join(":");
}

export function planScalarMutations(
  profile: ExplorerProfile,
  baseline: CallCaptureDocument,
  budget: number,
  options?: {
    allowLinkedExpansion?: boolean;
    frontier?: FrontierEntry[];
    expansionBufferBudgetBytes?: bigint;
    expansionTotalBudgetBytes?: bigint;
  },
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
        options?.allowLinkedExpansion === true,
        options?.frontier,
        { perBufferBytes: options?.expansionBufferBudgetBytes, totalBytes: options?.expansionTotalBudgetBytes },
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

function completeCapturedBufferBytes(
  buffer: Pick<CapturedBufferInput | CapturedBufferOutput, "byteLength" | "prefixHex">,
): Uint8Array | undefined {
  const capturedBytes = buffer.prefixHex.length / 2;
  if (buffer.byteLength <= 0 ||
      capturedBytes > CALL_CAPTURE_MAX_BUF_PREFIX_BYTES ||
      capturedBytes !== buffer.byteLength) return undefined;
  return decodeHexBytes(buffer.prefixHex);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
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
  const dataflowEdges = inferCaptureProducerConsumerFlow(parentCapture);

  const maxSeqByGenSelAll = new Map<string, number>();
  for (const ev of parentCapture.events) {
    const k = ev.generation + ":" + ev.selectorOrdinal;
    const prev = maxSeqByGenSelAll.get(k) ?? -1;
    if (ev.selectorSeq > prev) maxSeqByGenSelAll.set(k, ev.selectorSeq);
  }

  // 1. Base IR-guided & boundary scalar mutations across representative occurrences of every selector
  for (const scalarPlan of planScalarMutations(profile, parentCapture, Math.max(budget * 16, 1024), {
    allowLinkedExpansion: hasNativeBufferCapture,
    frontier: options.frontier,
    expansionBufferBudgetBytes: options.expansionBufferBudgetBytes,
    expansionTotalBudgetBytes: options.expansionTotalBudgetBytes,
  })) {
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
          if (!preservesDependentBufferBounds(profile, scalar.ordinal, scalar.param_index, nextVal, event, hasNativeBufferCapture, options.frontier, { perBufferBytes: options.expansionBufferBudgetBytes, totalBytes: options.expansionTotalBudgetBytes })) continue;
          const repBits = bitsForValue(nextVal, scalar.width_bits);
          if (repBits === captured.bits) continue;
          addPlan({
            rule: {
              ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
              ...(hasNativeBufferCapture ? { execMode: 1 } : {}),
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
          const switchWordVals = (bufParam?.elementTypeCategory === "record" && (bufParam.elementSize ?? 0) > 8)
            ? reachableSwitchConstants(profile, event.selectorOrdinal, elemW * 8)
            : [];
          for (const wOff of wordOffsets) {
            if (wOff + elemW > prefixBytes.length) continue;
            const obsWord = readLeUnsigned(prefixBytes, wOff, elemW);
            const expWordHex = bitsForValue(obsWord, elemW * 8);
            const isProducerBuf = buf.direction === "inout";
            for (const swVal of switchWordVals) {
              const repWordHex = bitsForValue(swVal, elemW * 8);
              if (repWordHex === expWordHex) continue;
              const modes = isProducerBuf ? [0, 1] : [1, 0];
              for (const execMode of modes) {
                const prio = isProducerBuf && execMode === 0
                  ? (event.selectorSeq === 0 ? 1005 : 1001)
                  : execMode === 1
                  ? 994
                  : 955;
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
                  priority: prio,
                  evidenceSiteIds: [`buf_word_const:e${event.selectorOrdinal}:p${buf.paramIndex}:off${wOff}:${repWordHex}:m${execMode}`],
                });
              }
              if (!isProducerBuf) {
                for (const edge of dataflowEdges) {
                  if (!edge.identityVerified || edge.crossInstance ||
                      edge.producer.generation !== event.generation ||
                      edge.consumer.generation !== event.generation ||
                      edge.consumer.callSeq !== event.callSeq ||
                      edge.consumer.selectorOrdinal !== event.selectorOrdinal ||
                      edge.consumer.selectorSeq !== event.selectorSeq ||
                      edge.consumer.paramIndex !== buf.paramIndex ||
                      edge.producer.callSeq >= event.callSeq ||
                      edge.consumer.storageAddress !== buf.storageAddress ||
                      edge.consumer.byteLength !== buf.byteLength ||
                      edge.producer.byteLength !== edge.consumer.byteLength ||
                      edge.producer.elementSize !== edge.consumer.elementSize ||
                      edge.consumer.elementSize !== buf.elementSize) continue;
                  const binding = validateProducerConsumerBinding(edge, {
                    runId: parentCapture.runId,
                    currentRunId: parentCapture.runId,
                    instanceGeneration: event.generation,
                    objectVersion: edge.producer.objectVersion,
                    latestObjectVersion: edge.producer.objectVersion,
                    byteLength: edge.producer.byteLength,
                    elementSize: edge.producer.elementSize,
                    verifiedIdentity: edge.identityVerified,
                    storageAddress: edge.producer.storageAddress,
                    producerCallSeq: edge.producer.callSeq,
                    producerParamIndex: edge.producer.paramIndex,
                  });
                  if (!binding.valid) continue;
                  const producerEvent = parentCapture.events.find((candidate) =>
                    candidate.generation === edge.producer.generation &&
                    candidate.callSeq === edge.producer.callSeq &&
                    candidate.selectorOrdinal === edge.producer.selectorOrdinal &&
                    candidate.selectorSeq === edge.producer.selectorSeq);
                  if (!producerEvent) continue;
                  const producerMarshal = profile.ecalls.get(edge.producer.selectorOrdinal);
                  const producerParameter = producerMarshal?.params.find(
                    (parameter) => parameter.paramIndex === edge.producer.paramIndex);
                  const producerInput = producerEvent.bufferInputs?.find(
                    (input) => input.paramIndex === edge.producer.paramIndex);
                  const producerOutput = producerEvent.bufferOutputs?.find(
                    (output) => output.paramIndex === edge.producer.paramIndex);
                  if (!producerInput || !producerOutput ||
                      producerInput.direction !== "inout" || producerOutput.direction !== "inout" ||
                      producerInput.storageAddress !== edge.producer.storageAddress ||
                      producerOutput.storageAddress !== edge.producer.storageAddress ||
                      buf.storageAddress !== edge.consumer.storageAddress ||
                      producerInput.byteLength !== edge.producer.byteLength ||
                      producerOutput.byteLength !== edge.producer.byteLength ||
                      buf.byteLength !== edge.consumer.byteLength ||
                      producerInput.byteLength !== producerOutput.byteLength ||
                      producerOutput.byteLength !== buf.byteLength ||
                      producerInput.elementSize !== edge.producer.elementSize ||
                      producerOutput.elementSize !== edge.producer.elementSize ||
                      buf.elementSize !== edge.consumer.elementSize ||
                      producerInput.elementSize !== producerOutput.elementSize ||
                      producerOutput.elementSize !== buf.elementSize ||
                      producerParameter?.elementTypeCategory !== "record" ||
                      producerParameter.elementSize !== buf.elementSize ||
                      (producerParameter.elementSize ?? 0) <= 8) continue;
                  const producerConstants = reachableSwitchConstants(
                    profile, edge.producer.selectorOrdinal, elemW * 8);
                  if (!producerConstants.includes(swVal)) continue;
                  const producerInputBytes = completeCapturedBufferBytes(producerInput);
                  const producerOutputBytes = completeCapturedBufferBytes(producerOutput);
                  const consumerInputBytes = completeCapturedBufferBytes(buf);
                  if (!producerInputBytes || !producerOutputBytes || !consumerInputBytes ||
                      !equalBytes(producerOutputBytes, consumerInputBytes) ||
                      wOff + elemW > producerInputBytes.length) continue;
                  const producerObserved = readLeUnsigned(producerInputBytes, wOff, elemW);
                  if (!producerConstants.includes(producerObserved) ||
                      producerObserved !== obsWord ||
                      producerObserved === swVal) continue;
                  const baselineBits = bitsForValue(producerObserved, elemW * 8);
                  const dataflowTarget: DataflowTarget = {
                    consumerGeneration: edge.consumer.generation,
                    consumerCallSeq: edge.consumer.callSeq,
                    consumerSelectorOrdinal: edge.consumer.selectorOrdinal,
                    consumerSelectorSeq: edge.consumer.selectorSeq,
                    consumerParamIndex: edge.consumer.paramIndex,
                    consumerByteOffset: wOff,
                    consumerWidthBytes: elemW,
                    baselineBits,
                    propagatedBits: repWordHex,
                    bufferByteLength: producerInput.byteLength,
                    elementSize: producerInput.elementSize,
                  };
                  addPlan({
                    rule: {
                      opKind: "mutate_buffer",
                      bufferSubOp: "write_le",
                      ...(event.generation !== 1 ? { targetGeneration: event.generation } : {}),
                      execMode: 0,
                      selectorOrdinal: edge.producer.selectorOrdinal,
                      selectorSeq: edge.producer.selectorSeq,
                      paramIndex: edge.producer.paramIndex,
                      byteOffset: wOff,
                      sliceLength: elemW,
                      widthBytes: elemW,
                      signedness: "unsigned",
                      expectedBits: baselineBits,
                      replacementBits: repWordHex,
                      dataflowTarget,
                    },
                    value: `buf_word_linked(exec=0):p${edge.producer.paramIndex}@${wOff}=${repWordHex}->e${edge.consumer.selectorOrdinal}#${edge.consumer.selectorSeq}:p${edge.consumer.paramIndex}`,
                    priority: isLastOccurrence ? 1004 : 1000,
                    evidenceSiteIds: [`buf_word_linked:e${edge.consumer.selectorOrdinal}:p${edge.consumer.paramIndex}:off${wOff}:${repWordHex}:producer${edge.producer.callSeq}:p${edge.producer.paramIndex}`],
                  });
                }
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
    const selected = sortedAll.slice(0, budget);
    recordCandidatePoolLimit(options.frontier, sortedAll, selected);
    return selected;
  }
  const buckets = new Map<string, PlannedMutation[]>();
  for (const item of sortedAll) {
    const isExpand = (item.rule.opKind ?? "replace_scalar") === "replace_scalar" &&
      BigInt(item.rule.replacementBits) > BigInt(item.rule.expectedBits);
    const category = item.rule.dataflowTarget ? "linked" : "direct";
    const bKey = category + ":" + item.rule.selectorOrdinal + ":" +
      (item.rule.opKind ?? "replace_scalar") + ":" +
      (item.rule.bufferSubOp ?? (isExpand ? "expand" : "base"));
    const list = buckets.get(bKey) ?? [];
    list.push(item);
    buckets.set(bKey, list);
  }
  const linkedPlans = sortedAll.filter((item) => item.rule.dataflowTarget !== undefined);
  const linkedCandidate = linkedPlans.find((item) => {
    const key = linkedConsumerCallKey(item.rule);
    return key !== null && options.measuredFieldCallKeys?.has(key) === true;
  }) ?? linkedPlans[0];
  const isDirectWriteLe = (item: PlannedMutation): boolean =>
    item.rule.dataflowTarget === undefined &&
    (item.rule.opKind ?? "replace_scalar") === "mutate_buffer" &&
    item.rule.bufferSubOp === "write_le" &&
    (item.rule.execMode ?? 0) === 0;
  const directLinkedCounterpart = linkedCandidate
    ? sortedAll.find((item) =>
        isDirectWriteLe(item) &&
        (item.rule.targetGeneration ?? 1) === (linkedCandidate.rule.targetGeneration ?? 1) &&
        item.rule.selectorOrdinal === linkedCandidate.rule.selectorOrdinal &&
        item.rule.selectorSeq === linkedCandidate.rule.selectorSeq &&
        item.rule.paramIndex === linkedCandidate.rule.paramIndex)
    : undefined;
  const directCandidate = directLinkedCounterpart ?? sortedAll.find(isDirectWriteLe);
  const interleaved: PlannedMutation[] = [];
  const reserved = new Set<PlannedMutation>();
  if (options.measuredFieldCallKeys && options.measuredFieldCallKeys.size > 0) {
    for (const key of reserveLinkedConsumerCallKeys(linkedPlans, options.measuredFieldCallKeys, budget)) {
      const plan = linkedPlans.find((item) => linkedConsumerCallKey(item.rule) === key);
      if (plan && interleaved.length < budget) {
        interleaved.push(plan);
        reserved.add(plan);
      }
    }
    if (interleaved.length < budget && directCandidate) {
      interleaved.push(directCandidate);
      reserved.add(directCandidate);
    }
  } else if (linkedCandidate) {
    if (budget >= 2 && directCandidate) {
      interleaved.push(directCandidate);
      reserved.add(directCandidate);
    }
    if (interleaved.length < budget) {
      interleaved.push(linkedCandidate);
      reserved.add(linkedCandidate);
    }
  }
  const bucketLists = [...buckets.values()]
    .map((list) => list.filter((item) => !reserved.has(item)));
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
  recordCandidatePoolLimit(options.frontier, sortedAll, interleaved);
  return interleaved;
}

export function deriveChildCandidatesFromFeedback(
  profile: ExplorerProfile,
  baselineCapture: CallCaptureDocument,
  discoveredCapture: CallCaptureDocument,
  parentPlan: PlannedMutation,
  depth: number,
  budget: number,
  frontier?: FrontierEntry[],
  budgets?: { perBufferBytes?: bigint; totalBytes?: bigint },
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
          if (!preservesDependentBufferBounds(profile, scalar.ordinal, scalar.param_index, nextVal, baseEvent, parentExec > 0, frontier, budgets)) continue;
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

  // Case A2: Parent was a write_le buffer mutation -> immediately spawn sibling IR switch constants on the same buffer/offset/execMode
  if (opKind === "mutate_buffer" && parentPlan.rule.bufferSubOp === "write_le" && baseEvent) {
    const targetBuf = (baseEvent.bufferInputs ?? []).find((b) => b.paramIndex === parentPlan.rule.paramIndex);
    if (targetBuf) {
      const elemW = parentPlan.rule.widthBytes;
      const swVals = reachableSwitchConstants(profile, parentPlan.rule.selectorOrdinal, elemW * 8);
      for (const swVal of swVals) {
        const repWordHex = bitsForValue(swVal, elemW * 8);
        if (repWordHex === parentPlan.rule.expectedBits || repWordHex === parentPlan.rule.replacementBits) continue;
        addPlan({
          rule: {
            ...parentPlan.rule,
            replacementBits: repWordHex,
          },
          value: `derived_buf_word_const(d=${depth},exec=${parentExec}):p${targetBuf.paramIndex}@${parentPlan.rule.byteOffset ?? 0}=${repWordHex}`,
          priority: 1008,
          evidenceSiteIds: [`derived_buf_word_const:d${depth}:e${parentPlan.rule.selectorOrdinal}:p${targetBuf.paramIndex}:${repWordHex}:m${parentExec}`],
        });
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
        if (!preservesDependentBufferBounds(profile, scalar.ordinal, scalar.param_index, nextVal, baseEvent, parentExec > 0, frontier, budgets)) continue;
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

  const sortedPlans = [...plans.values()]
    .sort((left, right) =>
      right.priority - left.priority ||
      left.rule.selectorOrdinal - right.rule.selectorOrdinal ||
      left.rule.selectorSeq - right.rule.selectorSeq ||
      left.rule.paramIndex - right.rule.paramIndex ||
      left.value.localeCompare(right.value),
    );
  const selected = sortedPlans.slice(0, budget);
  recordCandidatePoolLimit(frontier, sortedPlans, selected);
  return selected;
}


export interface CaptureDataflowEdge {
  producer: {
    generation: number;
    callSeq: number;
    selectorOrdinal: number;
    selectorSeq: number;
    paramIndex: number;
    byteLength: number;
    elementSize: number;
    fnv1a64: string;
    storageAddress?: string;
    objectVersion: number;
  };
  consumer: {
    generation: number;
    callSeq: number;
    selectorOrdinal: number;
    selectorSeq: number;
    paramIndex: number;
    byteLength: number;
    elementSize: number;
    fnv1a64: string;
    storageAddress?: string;
  };
  crossInstance: boolean;
  identityVerified: boolean;
}

type CapturedBufferContent = Pick<CapturedBufferInput, "byteLength" | "fnv1a64" | "prefixHex">;

interface CapturedObjectVersion {
  generation: number;
  callSeq: number;
  selectorOrdinal: number;
  selectorSeq: number;
  paramIndex: number;
  byteLength: number;
  elementSize: number;
  fnv1a64: string;
  prefixHex: string;
  storageAddress?: string;
  objectVersion: number;
}

function sameCapturedContent(left: CapturedBufferContent, right: CapturedBufferContent): boolean {
  return left.byteLength === right.byteLength &&
    left.fnv1a64 === right.fnv1a64 &&
    left.prefixHex === right.prefixHex;
}

function rangesOverlap(left: CapturedObjectVersion, right: CapturedBufferOutput): boolean {
  if (!left.storageAddress || !right.storageAddress) return false;
  const leftStart = BigInt(left.storageAddress);
  const rightStart = BigInt(right.storageAddress);
  const leftEnd = leftStart + BigInt(left.byteLength);
  const rightEnd = rightStart + BigInt(right.byteLength);
  return leftStart < rightEnd && rightStart < leftEnd;
}

export function inferCaptureProducerConsumerFlow(capture: CallCaptureDocument): CaptureDataflowEdge[] {
  const edges: CaptureDataflowEdge[] = [];
  const activeWrites: CapturedObjectVersion[] = [];
  let nextObjectVersion = 1;
  const orderedEvents = capture.events
    .map((event, index) => ({ event, index }))
    .sort((left, right) => left.event.callSeq - right.event.callSeq || left.index - right.index);

  for (const { event } of orderedEvents) {
    for (const inBuf of event.bufferInputs ?? []) {
      if (inBuf.byteLength <= 0) continue;
      const matchingWrites = activeWrites.filter((write) =>
        write.generation === event.generation &&
        write.callSeq < event.callSeq &&
        sameCapturedContent(write, inBuf));
      const exactIdentityWrites = inBuf.storageAddress
        ? matchingWrites.filter((write) => write.storageAddress === inBuf.storageAddress)
        : [];
      const producers = exactIdentityWrites.length > 0 ? exactIdentityWrites : matchingWrites;
      for (const producer of producers) {
        const identityVerified = producer.storageAddress !== undefined &&
          inBuf.storageAddress !== undefined &&
          producer.storageAddress === inBuf.storageAddress &&
          producer.byteLength === inBuf.byteLength &&
          producer.elementSize === inBuf.elementSize;
        edges.push({
          producer: {
            generation: producer.generation,
            callSeq: producer.callSeq,
            selectorOrdinal: producer.selectorOrdinal,
            selectorSeq: producer.selectorSeq,
            paramIndex: producer.paramIndex,
            byteLength: producer.byteLength,
            elementSize: producer.elementSize,
            fnv1a64: producer.fnv1a64,
            ...(producer.storageAddress === undefined ? {} : { storageAddress: producer.storageAddress }),
            objectVersion: producer.objectVersion,
          },
          consumer: {
            generation: event.generation,
            callSeq: event.callSeq,
            selectorOrdinal: event.selectorOrdinal,
            selectorSeq: event.selectorSeq,
            paramIndex: inBuf.paramIndex,
            byteLength: inBuf.byteLength,
            elementSize: inBuf.elementSize,
            fnv1a64: inBuf.fnv1a64,
            ...(inBuf.storageAddress === undefined ? {} : { storageAddress: inBuf.storageAddress }),
          },
          crossInstance: false,
          identityVerified,
        });
      }
    }
    const orderedOutputs = [...(event.bufferOutputs ?? [])]
      .sort((left, right) => left.paramIndex - right.paramIndex);
    for (const outBuf of orderedOutputs) {
      if (outBuf.byteLength <= 0) continue;
      if (outBuf.storageAddress === undefined) {
        for (let index = activeWrites.length - 1; index >= 0; index--) {
          if (activeWrites[index]?.generation === event.generation) activeWrites.splice(index, 1);
        }
      } else {
        for (let index = activeWrites.length - 1; index >= 0; index--) {
          const previous = activeWrites[index];
          if (previous?.generation === event.generation &&
              (!previous.storageAddress || rangesOverlap(previous, outBuf))) {
            activeWrites.splice(index, 1);
          }
        }
      }
      activeWrites.push({
        generation: event.generation,
        callSeq: event.callSeq,
        selectorOrdinal: event.selectorOrdinal,
        selectorSeq: event.selectorSeq,
        paramIndex: outBuf.paramIndex,
        byteLength: outBuf.byteLength,
        elementSize: outBuf.elementSize,
        fnv1a64: outBuf.fnv1a64,
        prefixHex: outBuf.prefixHex,
        ...(outBuf.storageAddress === undefined ? {} : { storageAddress: outBuf.storageAddress }),
        objectVersion: nextObjectVersion,
      });
      nextObjectVersion++;
    }
  }
  return edges;
}

export type ProducerConsumerFailureReason =
  | "stale_producer_object"
  | "producer_generation_mismatch"
  | "producer_length_mismatch"
  | "producer_element_size_mismatch"
  | "producer_identity_unverified";

export function validateProducerConsumerBinding(
  edge: CaptureDataflowEdge,
  candidateObject: {
    runId: string;
    currentRunId: string;
    instanceGeneration: number;
    objectVersion: number;
    latestObjectVersion: number;
    byteLength: number;
    elementSize: number;
    verifiedIdentity: boolean;
    storageAddress?: string;
    producerCallSeq?: number;
    producerParamIndex?: number;
  },
): { valid: boolean; reason: ProducerConsumerFailureReason | null } {
  if (!edge.identityVerified || !candidateObject.verifiedIdentity ||
      !edge.producer.storageAddress ||
      candidateObject.storageAddress !== edge.producer.storageAddress) {
    return { valid: false, reason: "producer_identity_unverified" };
  }
  if (candidateObject.runId !== candidateObject.currentRunId ||
      candidateObject.objectVersion !== candidateObject.latestObjectVersion ||
      candidateObject.objectVersion !== edge.producer.objectVersion ||
      candidateObject.producerCallSeq !== edge.producer.callSeq ||
      candidateObject.producerParamIndex !== edge.producer.paramIndex) {
    return { valid: false, reason: "stale_producer_object" };
  }
  if (edge.crossInstance ||
      edge.producer.generation !== edge.consumer.generation ||
      candidateObject.instanceGeneration !== edge.producer.generation) {
    return { valid: false, reason: "producer_generation_mismatch" };
  }
  if (candidateObject.byteLength !== edge.producer.byteLength ||
      edge.producer.byteLength !== edge.consumer.byteLength) {
    return { valid: false, reason: "producer_length_mismatch" };
  }
  if (candidateObject.elementSize !== edge.producer.elementSize ||
      edge.producer.elementSize !== edge.consumer.elementSize) {
    return { valid: false, reason: "producer_element_size_mismatch" };
  }
  return { valid: true, reason: null };
}

export type ColdReorderFailureReason =
  | "missing_initializer_or_restoration_prefix"
  | "instance_bound_handle_not_transferable"
  | "unverified_cross_instance_transfer";

export function evaluateColdInstanceFirstCallReorder(
  capture: CallCaptureDocument,
  request: {
    targetGeneration: number;
    targetConsumerCallSeq: number;
    preserveInitializerCalls: boolean;
    inputPortability: "verified_portable_serialized" | "instance_bound_handle" | "unverified";
  },
): {
  allowed: boolean;
  reason: ColdReorderFailureReason | null;
  requiredPrefixCallSeqs: number[];
} {
  const genEvents = capture.events.filter((ev) => ev.generation === request.targetGeneration);
  const targetEvent = genEvents.find((ev) => ev.callSeq === request.targetConsumerCallSeq);
  const prefixEvents = genEvents.filter((ev) => ev.callSeq < request.targetConsumerCallSeq);
  const requiredPrefixCallSeqs = prefixEvents.map((ev) => ev.callSeq);
  if (!targetEvent || !request.preserveInitializerCalls) {
    return {
      allowed: false,
      reason: "missing_initializer_or_restoration_prefix",
      requiredPrefixCallSeqs,
    };
  }
  if (request.inputPortability === "instance_bound_handle") {
    return {
      allowed: false,
      reason: "instance_bound_handle_not_transferable",
      requiredPrefixCallSeqs,
    };
  }
  if (request.inputPortability !== "verified_portable_serialized") {
    return {
      allowed: false,
      reason: "unverified_cross_instance_transfer",
      requiredPrefixCallSeqs,
    };
  }
  return {
    allowed: true,
    reason: null,
    requiredPrefixCallSeqs,
  };
}

export interface OnlineScalarFeedback {
  measurementComplete: boolean;
  accepted: boolean;
  businessOutcome: "ok" | "rejected";
  pageDeltaCount: number;
  newFieldEntry: boolean;
}

/** Derive a small next-step scalar batch from one canonical replay outcome.
 * Values come from the observed scalar and the ABI's actual size/count bindings;
 * the baseline capture remains the source of expected bits and call positions.
 */
export function deriveOnlineScalarCandidates(
  profile: ExplorerProfile,
  baselineCapture: CallCaptureDocument,
  observedCapture: CallCaptureDocument,
  parentPlan: PlannedMutation,
  feedback: OnlineScalarFeedback,
  budgets?: { perBufferBytes?: bigint; totalBytes?: bigint },
): PlannedMutation[] {
  if (!feedback.measurementComplete || !observedCapture.end.complete ||
      (parentPlan.rule.opKind ?? "replace_scalar") !== "replace_scalar") return [];

  const ordinal = parentPlan.rule.selectorOrdinal;
  const paramIndex = parentPlan.rule.paramIndex;
  const generation = parentPlan.rule.targetGeneration ?? 1;
  const selectorSeq = parentPlan.rule.selectorSeq;
  const baseEvent = baselineCapture.events.find((event) => event.generation === generation &&
    event.selectorOrdinal === ordinal && event.selectorSeq === selectorSeq);
  const observedEvent = observedCapture.events.find((event) => event.generation === generation &&
    event.selectorOrdinal === ordinal && event.selectorSeq === selectorSeq &&
    event.mutation?.applied === true && event.mutation.paramIndex === paramIndex);
  const scalar = profile.scalarParameterByKey.get(ordinal + ":" + paramIndex);
  const marshal = profile.ecalls.get(ordinal);
  if (!baseEvent || !observedEvent || !scalar || !marshal || !marshal.replaySupported) return [];
  const baselineInput = baseEvent.scalarInputs.find((item) => item.paramIndex === paramIndex);
  const observedInput = observedEvent.scalarInputs.find((item) => item.paramIndex === paramIndex);
  if (!baselineInput || !observedInput ||
      baselineInput.widthBytes * 8 !== scalar.width_bits ||
      baselineInput.signedness !== scalar.signedness ||
      observedInput.widthBytes !== baselineInput.widthBytes ||
      observedInput.signedness !== baselineInput.signedness) return [];

  const current = capturedValue(observedEvent, paramIndex);
  if (current === undefined) return [];
  const signBit = 1n << BigInt(scalar.width_bits - 1);
  const minValue = scalar.signedness === "signed" ? -signBit : 0n;
  const maxValue = scalar.signedness === "signed" ? signBit - 1n : (signBit << 1n) - 1n;
  const values = new Set<bigint>();
  const dependencies = pointerDependencies(paramIndex, marshal);

  // Ground size/count probes in the observed marshaled extent. This can expose
  // legal bounds from later call histories without inventing ABI offsets.
  for (const dependency of dependencies) {
    if (!dependency.replaySupported || dependency.userCheck ||
        (dependency.boundKind !== "size_bytes" && dependency.boundKind !== "count_elements")) continue;
    const buffer = observedEvent.bufferInputs?.find((item) => item.paramIndex === dependency.paramIndex);
    if (!buffer) continue;
    const unit = dependency.boundKind === "count_elements" ? dependency.elementSize : 1;
    if (unit === null || unit < 1 || buffer.byteLength % unit !== 0) continue;
    const observedBound = BigInt(buffer.byteLength / unit);
    values.add(observedBound);
    values.add(observedBound + 1n);
  }

  if (feedback.businessOutcome === "rejected") {
    values.add(current - 1n);
  } else if (feedback.pageDeltaCount > 0 || feedback.newFieldEntry) {
    const step = 1n + BigInt(Math.min(feedback.pageDeltaCount, 7)) +
      (feedback.newFieldEntry ? 1n : 0n);
    values.add(current + step);
    values.add(current - 1n);
  } else {
    const step = current === 0n ? 1n : (current < 0n ? -current : current);
    values.add(current + step);
    values.add(current - step);
  }

  const plans = new Map<string, PlannedMutation>();
  for (const value of values) {
    if (value < minValue || value > maxValue || value === current ||
        !preservesDependentBufferBounds(profile, ordinal, paramIndex, value, baseEvent,
          (parentPlan.rule.execMode ?? 0) > 0, undefined, budgets)) continue;
    const rule: ScalarMutationRule = {
      ...(generation !== 1 ? { targetGeneration: generation } : {}),
      ...(parentPlan.rule.execMode !== undefined ? { execMode: parentPlan.rule.execMode } : {}),
      ...(parentPlan.rule.prefixMutations ? { prefixMutations: parentPlan.rule.prefixMutations } : {}),
      selectorOrdinal: ordinal,
      selectorSeq,
      paramIndex,
      widthBytes: baselineInput.widthBytes,
      signedness: scalar.signedness,
      expectedBits: baselineInput.bits,
      replacementBits: bitsForValue(value, scalar.width_bits),
    };
    const plan: PlannedMutation = {
      rule,
      value: value.toString(10),
      priority: parentPlan.priority + 120 + feedback.pageDeltaCount * 10 +
        (feedback.newFieldEntry ? 20 : 0) + (feedback.accepted ? 0 : -20),
      evidenceSiteIds: sortedUnique([...parentPlan.evidenceSiteIds,
        `online:${feedback.businessOutcome}:field${feedback.newFieldEntry ? 1 : 0}:pages${feedback.pageDeltaCount}`]),
    };
    plans.set(mutationRuleKey(rule), plan);
  }
  return [...plans.values()].slice(0, 4);
}
