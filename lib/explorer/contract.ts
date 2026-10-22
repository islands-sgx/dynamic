import { parseStrictJson } from "../bundle/profile-bundle.ts";
import type { CanonicalRun } from "../runner/canonical-runner.ts";

export const MUTATION_SPEC_VERSION = 2;
export const MUTATION_SPEC_VERSION_LEGACY = 1;
export const MUTATION_SPEC_HEADER_BYTES = 88;
export const MUTATION_SPEC_RULE_BYTES = 24;
export const MUTATION_SPEC_SCALAR_OP_BYTES = 32;
export const MUTATION_SPEC_PREFIX_OP_BYTES = 48;
export const MUTATION_SPEC_BUDGET_OP_BYTES = 24;
export const MUTATION_SPEC_MAX_PREFIX_OPS = 8;
export const CALL_CAPTURE_SCHEMA = "atfield-call-capture-v1" as const;
export const CALL_CAPTURE_MAX_BUF_PREFIX_BYTES = 128;

export type MutationOpKind = "replace_scalar" | "mutate_buffer" | "extend_history";
export type BufferSubOpKind = "xor_byte" | "fill_slice" | "write_le";

export interface MutationBinding {
  bundleManifestSha256: string;
  marshalLayoutSha256: string;
}

export interface ScalarMutationRule {
  opKind?: MutationOpKind;
  targetGeneration?: number;
  execMode?: number;
  selectorOrdinal: number;
  selectorSeq: number;
  paramIndex: number;
  widthBytes: 1 | 2 | 4 | 8;
  signedness: "unsigned" | "signed";
  expectedBits: string;
  replacementBits: string;
  bufferSubOp?: BufferSubOpKind;
  byteOffset?: number;
  sliceLength?: number;
  repeatCount?: number;
  prefixMutations?: PrefixMutation[];
  dataflowTarget?: DataflowTarget;
  expansionBudget?: { readonly perBufferBytes: number; readonly totalBytes: number };
}

/* A planned, recorded scalar write applied to an earlier call's buffer
   contents, addressed by that call's (selectorOrdinal, selectorSeq). Each
   applied prefix mutation is captured on that call's own mutation record so
   the executed input is always derivable from the trace. */
export interface PrefixMutation {
  selectorOrdinal: number;
  selectorSeq: number;
  paramIndex: number;
  byteOffset: number;
  widthBytes: 1 | 2 | 4 | 8;
  expectedBits: string;
  replacementBits: string;
}

export interface DataflowTarget {
  consumerGeneration: number;
  consumerCallSeq: number;
  consumerSelectorOrdinal: number;
  consumerSelectorSeq: number;
  consumerParamIndex: number;
  consumerByteOffset: number;
  consumerWidthBytes: 1 | 2 | 4 | 8;
  baselineBits: string;
  propagatedBits: string;
  bufferByteLength: number;
  elementSize: number;
}

export interface CapturedScalarBits {
  paramIndex: number;
  widthBytes: 1 | 2 | 4 | 8;
  signedness: "unsigned" | "signed";
  bits: string;
}

export interface CapturedBufferInput {
  paramIndex: number;
  direction: "in" | "inout";
  isString: boolean;
  elementSize: number;
  byteLength: number;
  fnv1a64: string;
  sha256?: string;
  prefixHex: string;
  storageAddress?: string;
}

export interface CapturedBufferOutput {
  paramIndex: number;
  direction: "out" | "inout";
  isString: boolean;
  elementSize: number;
  byteLength: number;
  fnv1a64: string;
  sha256?: string;
  prefixHex: string;
  storageAddress?: string;
}

export interface CapturedMutation {
  paramIndex: number;
  widthBytes: 1 | 2 | 4 | 8;
  signedness: "unsigned" | "signed";
  expectedBits: string;
  observedBits: string | null;
  replacementBits: string;
  applied: boolean;
  reason: string | null;
  byteOffset?: number;
}

export interface CapturedReturnValue {
  widthBytes: 1 | 2 | 4 | 8;
  signedness: "unsigned" | "signed";
  bits: string;
}

export interface CallCaptureEvent {
  generation: number;
  callSeq: number;
  selectorOrdinal: number;
  selectorSeq: number;
  transportStatus: number;
  scalarInputs: CapturedScalarBits[];
  bufferInputs?: CapturedBufferInput[];
  bufferOutputs?: CapturedBufferOutput[];
  retval: CapturedReturnValue | null;
  scalarOutputs: CapturedScalarBits[];
  mutation: CapturedMutation | null;
}

export interface CallCaptureEnd {
  processReturnCode: number | null;
  termination: "exited" | "signaled" | "timeout" | "unknown";
  timedOut: boolean;
  complete: boolean;
  ecallCount: number;
  targetMatchCount: number;
  mutationAppliedCount: number;
  incompleteReasons: string[];
}

export interface CallCaptureDocument extends MutationBinding {
  marshalSpecSha256?: string;
  runId: string;
  events: CallCaptureEvent[];
  end: CallCaptureEnd;
}

export interface CaptureExpectation extends MutationBinding {
  marshalSpecSha256?: string;
  runId: string;
  mutation?: {
    targetGeneration?: number;
    execMode?: number;
    opKind?: MutationOpKind;
    selectorOrdinal: number;
    selectorSeq: number;
    paramIndex: number;
    prefixMutations?: Pick<PrefixMutation, "selectorOrdinal" | "selectorSeq">[];
  };
}

function fail(message: string): never {
  throw new TypeError(message);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(label + " must be an object");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const allowed = new Set(expected);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) fail(label + " has unsupported key " + unknown);
  const missing = expected.find((key) => !Object.hasOwn(value, key));
  if (missing) fail(label + " is missing " + missing);
}

function integer(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    fail(label + " must be a safe integer greater than or equal to " + minimum);
  }
  return value;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) fail(label + " must be a nonempty NUL-free string");
  return value;
}

function digestBytes(value: string, label: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) fail(label + " must be lowercase SHA-256 hex");
  const result = new Uint8Array(32);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function widthBytes(value: unknown, label: string): 1 | 2 | 4 | 8 {
  if (value !== 1 && value !== 2 && value !== 4 && value !== 8) {
    fail(label + " must be 1, 2, 4, or 8 bytes");
  }
  return value;
}

export function validateBits(value: unknown, width: 1 | 2 | 4 | 8, label: string): string {
  if (typeof value !== "string" ||
      !new RegExp("^0x[0-9a-f]{" + (width * 2) + "}$").test(value)) {
    fail(label + " must use fixed-width lowercase hexadecimal bits");
  }
  return value;
}

function bitsBigInt(value: string, width: number, label: string): bigint {
  validateBits(value, width as 1 | 2 | 4 | 8, label);
  return BigInt(value);
}

function putU16(view: DataView, offset: number, value: number): void {
  view.setUint16(offset, value, true);
}

function putU32(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value, true);
}

function putU64(view: DataView, offset: number, value: bigint): void {
  if (value < 0n || value >= (1n << 64n)) fail("mutation bits are outside uint64");
  view.setBigUint64(offset, value, true);
}

function validateMutationRule(rule: ScalarMutationRule): void {
  integer(rule.selectorOrdinal, "selectorOrdinal");
  integer(rule.selectorSeq, "selectorSeq");
  integer(rule.paramIndex, "paramIndex");
  const generation = integer(rule.targetGeneration ?? 1, "targetGeneration", 1);
  const mode = integer(rule.execMode ?? 0, "execMode");
  if (generation > 255 || mode > 4 || rule.selectorOrdinal >= 64 || rule.paramIndex >= 64) {
    fail("mutation target is outside the protocol range");
  }
  if (rule.expansionBudget) {
    integer(rule.expansionBudget.perBufferBytes, "expansionBudget.perBufferBytes", 1);
    integer(rule.expansionBudget.totalBytes, "expansionBudget.totalBytes", 1);
    if (rule.expansionBudget.perBufferBytes > 0xffffffff) fail("expansion buffer budget exceeds uint32");
  }
  widthBytes(rule.widthBytes, "widthBytes");
  if (rule.signedness !== "unsigned" && rule.signedness !== "signed") {
    fail("signedness must be unsigned or signed");
  }
  const width = rule.widthBytes;
  const max = 1n << BigInt(width * 8);
  const expectedBits = bitsBigInt(rule.expectedBits, width, "expectedBits");
  const replacementBits = bitsBigInt(rule.replacementBits, width, "replacementBits");
  if (expectedBits >= max || replacementBits >= max) {
    fail("mutation bits exceed the scalar width");
  }
  if ((rule.opKind ?? "replace_scalar") === "replace_scalar" && expectedBits === replacementBits) {
    fail("scalar replacement is a no-op");
  }
  const prefixes = rule.prefixMutations ?? [];
  if (prefixes.length > MUTATION_SPEC_MAX_PREFIX_OPS) {
    fail("too many prefix mutations");
  }
  const seenPrefixCalls = new Set<string>();
  for (const [index, prefix] of prefixes.entries()) {
    const label = "prefixMutations[" + index + "]";
    if (!Number.isInteger(prefix.selectorOrdinal) || prefix.selectorOrdinal < 0 ||
        prefix.selectorOrdinal >= 64) {
      fail(label + ".selectorOrdinal out of range");
    }
    integer(prefix.selectorSeq, label + ".selectorSeq");
    if (!Number.isInteger(prefix.paramIndex) || prefix.paramIndex < 0 || prefix.paramIndex >= 64) {
      fail(label + ".paramIndex out of range");
    }
    if (!Number.isInteger(prefix.byteOffset) || prefix.byteOffset < 0 || prefix.byteOffset > 0xffffffff) {
      fail(label + ".byteOffset out of range");
    }
    const pWidth = widthBytes(prefix.widthBytes, label + ".widthBytes");
    const pMax = 1n << BigInt(pWidth * 8);
    if (bitsBigInt(prefix.expectedBits, pWidth, label + ".expectedBits") >= pMax ||
        bitsBigInt(prefix.replacementBits, pWidth, label + ".replacementBits") >= pMax) {
      fail(label + " bits exceed the scalar width");
    }
    if (prefix.selectorOrdinal === rule.selectorOrdinal &&
        BigInt(prefix.selectorSeq) === BigInt(rule.selectorSeq)) {
      fail(label + " addresses the mutation target call");
    }
    const callKey = prefix.selectorOrdinal + ":" + prefix.selectorSeq;
    if (seenPrefixCalls.has(callKey)) {
      fail(label + " duplicates another prefix mutation target call");
    }
    seenPrefixCalls.add(callKey);
  }
  if (rule.dataflowTarget) {
    const target = rule.dataflowTarget;
    if ((rule.opKind ?? "replace_scalar") !== "mutate_buffer" ||
        rule.bufferSubOp !== "write_le" ||
        mode !== 0 ||
        rule.byteOffset === undefined ||
        (rule.sliceLength !== undefined && rule.sliceLength !== rule.widthBytes) ||
        prefixes.length !== 0) {
      fail("dataflowTarget requires a single mode-0 write_le producer mutation");
    }
    const consumerGeneration = integer(target.consumerGeneration, "dataflowTarget.consumerGeneration", 1);
    const consumerCallSeq = integer(target.consumerCallSeq, "dataflowTarget.consumerCallSeq");
    const consumerSelectorOrdinal = integer(target.consumerSelectorOrdinal, "dataflowTarget.consumerSelectorOrdinal");
    integer(target.consumerSelectorSeq, "dataflowTarget.consumerSelectorSeq");
    const consumerParamIndex = integer(target.consumerParamIndex, "dataflowTarget.consumerParamIndex");
    const consumerByteOffset = integer(target.consumerByteOffset, "dataflowTarget.consumerByteOffset");
    const consumerWidth = widthBytes(target.consumerWidthBytes, "dataflowTarget.consumerWidthBytes");
    const bufferByteLength = integer(target.bufferByteLength, "dataflowTarget.bufferByteLength", 1);
    integer(target.elementSize, "dataflowTarget.elementSize", 1);
    if (consumerGeneration !== generation ||
        consumerSelectorOrdinal >= 64 || consumerParamIndex >= 64 ||
        consumerByteOffset > 0xffffffff || bufferByteLength > 0xffffffff ||
        target.elementSize > 0xffffffff ||
        consumerCallSeq === 0 ||
        consumerWidth !== rule.widthBytes ||
        consumerByteOffset !== rule.byteOffset ||
        consumerByteOffset > bufferByteLength - consumerWidth) {
      fail("dataflowTarget is outside the producer mutation's verified buffer");
    }
    validateBits(target.baselineBits, consumerWidth, "dataflowTarget.baselineBits");
    validateBits(target.propagatedBits, consumerWidth, "dataflowTarget.propagatedBits");
    if (target.baselineBits !== rule.expectedBits ||
        target.propagatedBits !== rule.replacementBits) {
      fail("dataflowTarget values differ from the producer mutation");
    }
  }
}

export function encodeMutationSpec(binding: MutationBinding, rule: ScalarMutationRule): Uint8Array {
  digestBytes(binding.bundleManifestSha256, "bundleManifestSha256");
  digestBytes(binding.marshalLayoutSha256, "marshalLayoutSha256");
  validateMutationRule(rule);

  const prefixes = rule.prefixMutations ?? [];
  const ruleRecordBytes = MUTATION_SPEC_RULE_BYTES + MUTATION_SPEC_SCALAR_OP_BYTES +
    prefixes.length * MUTATION_SPEC_PREFIX_OP_BYTES +
    (rule.expansionBudget ? MUTATION_SPEC_BUDGET_OP_BYTES : 0);
  const totalBytes = MUTATION_SPEC_HEADER_BYTES + ruleRecordBytes;
  const bytes = new Uint8Array(totalBytes);
  bytes.set(new TextEncoder().encode("ATFMUT\0\0"), 0);
  const view = new DataView(bytes.buffer);
  putU16(view, 8, prefixes.length > 0 || rule.expansionBudget ? MUTATION_SPEC_VERSION : MUTATION_SPEC_VERSION_LEGACY);
  putU16(view, 10, MUTATION_SPEC_HEADER_BYTES);
  putU32(view, 12, totalBytes);
  putU32(view, 16, 1);
  putU32(view, 20, 0);
  bytes.set(digestBytes(binding.bundleManifestSha256, "bundleManifestSha256"), 24);
  bytes.set(digestBytes(binding.marshalLayoutSha256, "marshalLayoutSha256"), 56);

  const targetGen = rule.targetGeneration ?? 1;
  const execMode = rule.execMode ?? 0;
  const ruleFlags = (targetGen === 1 && execMode === 0)
    ? 0
    : ((targetGen & 0xff) | ((execMode & 0xff) << 8));

  const ruleOffset = MUTATION_SPEC_HEADER_BYTES;
  putU32(view, ruleOffset, ruleRecordBytes);
  putU16(view, ruleOffset + 4, 1);
  putU16(view, ruleOffset + 6, ruleFlags);
  putU32(view, ruleOffset + 8, rule.selectorOrdinal);
  view.setBigUint64(ruleOffset + 12, BigInt(rule.selectorSeq), true);
  putU16(view, ruleOffset + 20, 1 + prefixes.length + (rule.expansionBudget ? 1 : 0));
  putU16(view, ruleOffset + 22, 0);

  const opOffset = ruleOffset + MUTATION_SPEC_RULE_BYTES;
  const opKind = rule.opKind ?? "replace_scalar";
  if (opKind === "replace_scalar") {
    putU16(view, opOffset, 1);
    putU16(view, opOffset + 2, 0);
    putU32(view, opOffset + 4, MUTATION_SPEC_SCALAR_OP_BYTES);
    putU32(view, opOffset + 8, rule.paramIndex);
    bytes[opOffset + 12] = rule.signedness === "unsigned" ? 0 : 1;
    bytes[opOffset + 13] = rule.widthBytes;
    putU16(view, opOffset + 14, 0);
    putU64(view, opOffset + 16, bitsBigInt(rule.expectedBits, rule.widthBytes, "expectedBits"));
    putU64(view, opOffset + 24, bitsBigInt(rule.replacementBits, rule.widthBytes, "replacementBits"));
  } else if (opKind === "mutate_buffer") {
    const subOp = rule.bufferSubOp ?? "xor_byte";
    const subOpCode = subOp === "xor_byte" ? 1 : subOp === "fill_slice" ? 2 : 3;
    putU16(view, opOffset, 2);
    putU16(view, opOffset + 2, subOpCode);
    putU32(view, opOffset + 4, MUTATION_SPEC_SCALAR_OP_BYTES);
    putU32(view, opOffset + 8, rule.paramIndex);
    putU32(view, opOffset + 12, rule.byteOffset ?? 0);
    putU32(view, opOffset + 16, rule.sliceLength ?? rule.widthBytes);
    putU32(view, opOffset + 20, Number(bitsBigInt(rule.expectedBits, rule.widthBytes, "expectedBits") & 0xffffffffn));
    putU64(view, opOffset + 24, bitsBigInt(rule.replacementBits, rule.widthBytes, "replacementBits"));
  } else {
    const repeatCount = rule.repeatCount ?? 1;
    putU16(view, opOffset, 3);
    putU16(view, opOffset + 2, repeatCount);
    putU32(view, opOffset + 4, MUTATION_SPEC_SCALAR_OP_BYTES);
    putU32(view, opOffset + 8, rule.byteOffset === undefined ? 0xffffffff : rule.paramIndex);
    putU32(view, opOffset + 12, rule.byteOffset ?? 0);
    putU64(view, opOffset + 16, bitsBigInt(rule.expectedBits, rule.widthBytes, "expectedBits"));
    putU64(view, opOffset + 24, bitsBigInt(rule.replacementBits, rule.widthBytes, "replacementBits"));
  }
  for (const [index, prefix] of prefixes.entries()) {
    const pOff = opOffset + MUTATION_SPEC_SCALAR_OP_BYTES + index * MUTATION_SPEC_PREFIX_OP_BYTES;
    putU16(view, pOff, 4);
    putU16(view, pOff + 2, 0);
    putU32(view, pOff + 4, MUTATION_SPEC_PREFIX_OP_BYTES);
    putU32(view, pOff + 8, prefix.selectorOrdinal);
    view.setBigUint64(pOff + 12, BigInt(prefix.selectorSeq), true);
    putU32(view, pOff + 20, prefix.paramIndex);
    bytes[pOff + 24] = 0;
    bytes[pOff + 25] = prefix.widthBytes;
    putU16(view, pOff + 26, 0);
    putU32(view, pOff + 28, prefix.byteOffset);
    putU64(view, pOff + 32, bitsBigInt(prefix.expectedBits, prefix.widthBytes, "prefix.expectedBits"));
    putU64(view, pOff + 40, bitsBigInt(prefix.replacementBits, prefix.widthBytes, "prefix.replacementBits"));
  }
  if (rule.expansionBudget) {
    const offset = opOffset + MUTATION_SPEC_SCALAR_OP_BYTES + prefixes.length * MUTATION_SPEC_PREFIX_OP_BYTES;
    putU16(view, offset, 5);
    putU32(view, offset + 4, MUTATION_SPEC_BUDGET_OP_BYTES);
    putU64(view, offset + 8, BigInt(rule.expansionBudget.perBufferBytes));
    putU64(view, offset + 16, BigInt(rule.expansionBudget.totalBytes));
  }
  return bytes;
}

function parseCapturedScalar(value: unknown, label: string): CapturedScalarBits {
  const item = object(value, label);
  exactKeys(item, ["param_index", "width_bytes", "signedness", "bits"], label);
  const paramIndex = integer(item.param_index, label + ".param_index");
  const width = widthBytes(item.width_bytes, label + ".width_bytes");
  if (item.signedness !== "unsigned" && item.signedness !== "signed") {
    fail(label + ".signedness must be unsigned or signed");
  }
  const bits = validateBits(item.bits, width, label + ".bits");
  return { paramIndex, widthBytes: width, signedness: item.signedness, bits };
}

function parseCapturedBufferOutput(value: unknown, label: string): CapturedBufferOutput {
  const item = object(value, label);
  exactKeys(item, ["param_index", "direction", "is_string", "element_size", "byte_length", "fnv1a64", "prefix_hex",
    ...(item.sha256 !== undefined ? ["sha256"] : []),
    ...(item.storage_address !== undefined ? ["storage_address"] : [])], label);
  const paramIndex = integer(item.param_index, label + ".param_index");
  if (item.direction !== "out" && item.direction !== "inout") {
    fail(label + ".direction must be out or inout");
  }
  if (typeof item.is_string !== "boolean") fail(label + ".is_string must be boolean");
  const elementSize = integer(item.element_size, label + ".element_size", 1);
  const byteLength = integer(item.byte_length, label + ".byte_length", 1);
  const fnv1a64 = validateBits(item.fnv1a64, 8, label + ".fnv1a64");
  if (item.sha256 !== undefined && (typeof item.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(item.sha256))) {
    fail(label + ".sha256 must be lowercase SHA-256 hex");
  }
  const sha256 = item.sha256 as string | undefined;
  if (typeof item.prefix_hex !== "string" || !/^[0-9a-f]*$/.test(item.prefix_hex) || item.prefix_hex.length % 2 !== 0) {
    fail(label + ".prefix_hex must be lowercase hex bytes");
  }
  return {
    paramIndex,
    direction: item.direction,
    isString: item.is_string,
    elementSize,
    byteLength,
    fnv1a64,
    ...(sha256 !== undefined ? { sha256 } : {}),
    prefixHex: item.prefix_hex,
    ...(item.storage_address !== undefined ? { storageAddress: validateBits(item.storage_address, 8, label + ".storage_address") } : {}),
  };
}

function parseCapturedBufferInput(value: unknown, label: string): CapturedBufferInput {
  const item = object(value, label);
  exactKeys(item, ["param_index", "direction", "is_string", "element_size", "byte_length", "fnv1a64", "prefix_hex",
    ...(item.sha256 !== undefined ? ["sha256"] : []),
    ...(item.storage_address !== undefined ? ["storage_address"] : [])], label);
  const paramIndex = integer(item.param_index, label + ".param_index");
  if (item.direction !== "in" && item.direction !== "inout") {
    fail(label + ".direction must be in or inout");
  }
  if (typeof item.is_string !== "boolean") fail(label + ".is_string must be boolean");
  const elementSize = integer(item.element_size, label + ".element_size", 1);
  const byteLength = integer(item.byte_length, label + ".byte_length", 1);
  const fnv1a64 = validateBits(item.fnv1a64, 8, label + ".fnv1a64");
  if (item.sha256 !== undefined && (typeof item.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(item.sha256))) {
    fail(label + ".sha256 must be lowercase SHA-256 hex");
  }
  const sha256 = item.sha256 as string | undefined;
  if (typeof item.prefix_hex !== "string" || !/^[0-9a-f]*$/.test(item.prefix_hex) || item.prefix_hex.length % 2 !== 0) {
    fail(label + ".prefix_hex must be lowercase hex bytes");
  }
  return {
    paramIndex,
    direction: item.direction,
    isString: item.is_string,
    elementSize,
    byteLength,
    fnv1a64,
    ...(sha256 !== undefined ? { sha256 } : {}),
    prefixHex: item.prefix_hex,
    ...(item.storage_address !== undefined ? { storageAddress: validateBits(item.storage_address, 8, label + ".storage_address") } : {}),
  };
}

function parseCapturedMutation(value: unknown, label: string): CapturedMutation | null {
  if (value === null) return null;
  const mutation = object(value, label);
  exactKeys(
    mutation,
    ["param_index", "width_bytes", "signedness", "expected_bits", "observed_bits",
      "replacement_bits", "applied", "reason", ...(mutation.byte_offset !== undefined ? ["byte_offset"] : [])],
    label,
  );
  const paramIndex = integer(mutation.param_index, label + ".param_index");
  const width = widthBytes(mutation.width_bytes, label + ".width_bytes");
  if (mutation.signedness !== "unsigned" && mutation.signedness !== "signed") {
    fail(label + ".signedness must be unsigned or signed");
  }
  const expectedBits = validateBits(mutation.expected_bits, width, label + ".expected_bits");
  const observedBits = mutation.observed_bits === null ? null : validateBits(mutation.observed_bits, width, label + ".observed_bits");
  const replacementBits = validateBits(mutation.replacement_bits, width, label + ".replacement_bits");
  if (typeof mutation.applied !== "boolean") fail(label + ".applied must be boolean");
  if (mutation.reason !== null && typeof mutation.reason !== "string") fail(label + ".reason must be a string or null");
  return {
    paramIndex,
    widthBytes: width,
    signedness: mutation.signedness,
    expectedBits,
    observedBits,
    replacementBits,
    applied: mutation.applied,
    reason: mutation.reason,
    ...(mutation.byte_offset !== undefined ? { byteOffset: integer(mutation.byte_offset, label + ".byte_offset") } : {}),
  };
}

function parseCapturedReturn(value: unknown, label: string): CapturedReturnValue {
  const item = object(value, label);
  exactKeys(item, ["width_bytes", "signedness", "bits"], label);
  const width = widthBytes(item.width_bytes, label + ".width_bytes");
  if (item.signedness !== "unsigned" && item.signedness !== "signed") {
    fail(label + ".signedness must be unsigned or signed");
  }
  return { widthBytes: width, signedness: item.signedness, bits: validateBits(item.bits, width, label + ".bits") };
}

function parseEvent(value: unknown, label: string): CallCaptureEvent {
  const raw = object(value, label);
  const required = [
    "type", "generation", "call_seq", "selector_ordinal", "selector_seq", "transport_status",
    "scalar_inputs", "retval", "scalar_outputs", "mutation",
  ];
  const allowed = [...required];
  if (raw.schema !== undefined) allowed.push("schema");
  if (raw.buffer_inputs !== undefined) allowed.push("buffer_inputs");
  if (raw.buffer_outputs !== undefined) allowed.push("buffer_outputs");
  exactKeys(raw, allowed, label);
  if (raw.schema !== undefined && raw.schema !== CALL_CAPTURE_SCHEMA) {
    fail(label + ".schema must be " + CALL_CAPTURE_SCHEMA);
  }
  if (raw.type !== "ecall") fail(label + ".type must be ecall");
  if (!Array.isArray(raw.scalar_inputs) || !Array.isArray(raw.scalar_outputs)) {
    fail(label + " scalar input/output lists must be arrays");
  }
  const inputs = raw.scalar_inputs.map((entry, index) => parseCapturedScalar(entry, label + ".scalar_inputs[" + index + "]"));
  const outputs = raw.scalar_outputs.map((entry, index) => parseCapturedScalar(entry, label + ".scalar_outputs[" + index + "]"));
  for (const list of [inputs, outputs]) {
    for (let index = 1; index < list.length; index++) {
      if (list[index - 1]!.paramIndex >= list[index]!.paramIndex) {
        fail(label + " scalar parameter arrays must be strictly sorted by param_index");
      }
    }
  }
  let bufferInputs: CapturedBufferInput[] | undefined;
  if (raw.buffer_inputs !== undefined) {
    if (!Array.isArray(raw.buffer_inputs)) fail(label + ".buffer_inputs must be an array");
    bufferInputs = raw.buffer_inputs.map((entry, index) =>
      parseCapturedBufferInput(entry, label + ".buffer_inputs[" + index + "]"));
  }
  let bufferOutputs: CapturedBufferOutput[] | undefined;
  if (raw.buffer_outputs !== undefined) {
    if (!Array.isArray(raw.buffer_outputs)) fail(label + ".buffer_outputs must be an array");
    bufferOutputs = raw.buffer_outputs.map((entry, index) =>
      parseCapturedBufferOutput(entry, label + ".buffer_outputs[" + index + "]"));
  }
  const retval = raw.retval === null ? null : parseCapturedReturn(raw.retval, label + ".retval");
  return {
    generation: integer(raw.generation, label + ".generation", 1),
    callSeq: integer(raw.call_seq, label + ".call_seq"),
    selectorOrdinal: integer(raw.selector_ordinal, label + ".selector_ordinal"),
    selectorSeq: integer(raw.selector_seq, label + ".selector_seq"),
    transportStatus: integer(raw.transport_status, label + ".transport_status"),
    scalarInputs: inputs,
    ...(bufferInputs !== undefined ? { bufferInputs } : {}),
    ...(bufferOutputs !== undefined ? { bufferOutputs } : {}),
    retval,
    scalarOutputs: outputs,
    mutation: parseCapturedMutation(raw.mutation, label + ".mutation"),
  };
}

interface NativeCapturePrefix extends MutationBinding {
  marshalSpecSha256?: string;
  runId: string;
  events: CallCaptureEvent[];
}

function matchesExpectedTarget(
  event: CallCaptureEvent,
  mutation: NonNullable<CaptureExpectation["mutation"]>,
): boolean {
  const wantGen = mutation.targetGeneration ?? 1;
  return event.generation === wantGen &&
    event.selectorOrdinal === mutation.selectorOrdinal &&
    event.selectorSeq === mutation.selectorSeq;
}

export function parseNativeCallCapture(text: string, expected: CaptureExpectation): NativeCapturePrefix {
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0 || lines.some((line) => line.length === 0)) fail("native call capture contains an empty record");
  const records = lines.map((line, index) => object(parseStrictJson(line, "call capture line " + (index + 1)), "call capture line " + (index + 1)));
  const start = records[0]!;
  const startKeys = start.marshal_spec_sha256 !== undefined
    ? ["type", "schema", "run_id", "bundle_manifest_sha256", "marshal_layout_sha256", "marshal_spec_sha256"]
    : ["type", "schema", "run_id", "bundle_manifest_sha256", "marshal_layout_sha256"];
  exactKeys(start, startKeys, "call capture start");
  if (start.type !== "capture_start" || start.schema !== CALL_CAPTURE_SCHEMA) fail("invalid call capture start record");
  const runId = string(start.run_id, "call capture run_id");
  if (runId !== expected.runId) fail("call capture run_id differs from canonical runner");
  const bundleDigest = string(start.bundle_manifest_sha256, "call capture bundle digest");
  const marshalDigest = string(start.marshal_layout_sha256, "call capture marshal digest");
  let marshalSpecDigest: string | undefined;
  if (start.marshal_spec_sha256 !== undefined) {
    marshalSpecDigest = string(start.marshal_spec_sha256, "call capture marshal spec digest");
    digestBytes(marshalSpecDigest, "call capture marshal spec digest");
  }
  if (bundleDigest !== expected.bundleManifestSha256 ||
      marshalDigest !== expected.marshalLayoutSha256 ||
      (expected.marshalSpecSha256 !== undefined && marshalSpecDigest !== expected.marshalSpecSha256)) {
    fail("call capture is bound to different Profile bundle artifacts");
  }
  const events = records.slice(1).map((record, index) => parseEvent(record, "call capture ecall[" + index + "]"));
  const plannedPrefixCalls = new Set(
    (expected.mutation?.prefixMutations ?? []).map(
      (pfx) => pfx.selectorOrdinal + ":" + pfx.selectorSeq,
    ),
  );
  for (const event of events) {
    const isTarget = expected.mutation !== undefined && matchesExpectedTarget(event, expected.mutation);
    const isPlannedPrefix = plannedPrefixCalls.has(
      event.selectorOrdinal + ":" + event.selectorSeq,
    );
    if (!isTarget && !isPlannedPrefix && event.mutation !== null) {
      fail("call capture contains a mutation outside the selected ECALL occurrence");
    }
    if (!expected.mutation && event.mutation !== null) {
      fail("baseline call capture contains a mutation");
    }
  }
  const perSelector = new Map<string, number>();
  for (let index = 0; index < events.length; index++) {
    const event = events[index]!;
    if (event.callSeq !== index) fail("call capture call_seq must be contiguous from zero");
    const selectorKey = event.generation + ":" + event.selectorOrdinal;
    const previous = perSelector.get(selectorKey);
    if ((previous === undefined && event.selectorSeq !== 0) ||
        (previous !== undefined && event.selectorSeq !== previous + 1)) {
      fail("call capture selector_seq must be contiguous within each generation and selector");
    }
    perSelector.set(selectorKey, event.selectorSeq);
  }
  return {
    runId,
    bundleManifestSha256: bundleDigest,
    marshalLayoutSha256: marshalDigest,
    ...(marshalSpecDigest !== undefined ? { marshalSpecSha256: marshalSpecDigest } : {}),
    events,
  };
}

function traceEcallMetadata(traceText: string): Array<{
  generation: number;
  callSeq: number;
  selectorOrdinal: number;
  selectorSeq: number;
}> {
  const lines = traceText.split(/\r?\n/).filter((line) => line.length > 0);
  const records = lines.map((line, index) => object(parseStrictJson(line, "canonical trace line " + (index + 1)), "canonical trace record"));
  return records.filter((record) => record.record_type === "ecall").map((record) => ({
    generation: integer(record.instance_generation, "canonical ecall generation", 1),
    callSeq: integer(record.call_seq, "canonical ecall call_seq"),
    selectorOrdinal: integer(record.selector_ordinal, "canonical ecall selector_ordinal"),
    selectorSeq: integer(record.selector_seq, "canonical ecall selector_seq"),
  }));
}

function sameTraceEvents(
  captureEvents: CallCaptureEvent[],
  traceText: string,
): boolean {
  const traceEvents = traceEcallMetadata(traceText);
  if (captureEvents.length !== traceEvents.length) return false;
  return captureEvents.every((event, index) => {
    const trace = traceEvents[index]!;
    return event.generation === trace.generation &&
      event.callSeq === trace.callSeq &&
      event.selectorOrdinal === trace.selectorOrdinal &&
      event.selectorSeq === trace.selectorSeq;
  });
}

function isCompleteRun(run: CanonicalRun): boolean {
  return run.completion === "complete" && !run.timedOut && run.exitCode === 0 && run.parsedTrace !== undefined;
}

export function appendCallCaptureEnd(
  nativeText: string,
  run: CanonicalRun,
  expected: CaptureExpectation,
): { text: string; capture: CallCaptureDocument } {
  const prefix = parseNativeCallCapture(nativeText, expected);
  let sequenceMatches = false;
  try { sequenceMatches = sameTraceEvents(prefix.events, run.traceText); } catch {}
  const rule = expected.mutation;
  const targetMatchCount = rule
    ? prefix.events.filter((event) => matchesExpectedTarget(event, rule)).length
    : 0;
  const mutationRecords = prefix.events.flatMap((event) => event.mutation === null ? [] : [event.mutation]);
  const mutationAppliedCount = mutationRecords.filter((mutation) => mutation.applied).length;
  const reasons = [...run.incompleteReasons];
  if (!sequenceMatches) reasons.push("native capture ECALL sequence differs from canonical trace");
  const plannedMutationCount = rule ? 1 + (rule.prefixMutations?.length ?? 0) : 0;
  if (!rule && mutationRecords.length !== 0) reasons.push("baseline capture contains a mutation record");
  if (rule && targetMatchCount !== 1) reasons.push("candidate target occurrence is missing or duplicated");
  if (rule && mutationRecords.length !== plannedMutationCount) {
    reasons.push("candidate must contain exactly the planned mutation records");
  }
  if (rule && mutationAppliedCount !== plannedMutationCount) {
    reasons.push("candidate mutations were not all applied");
  }
  if (rule && mutationRecords.some((m) => m.reason !== "applied")) {
    reasons.push("candidate mutation reason is not applied");
  }
  const mutationContractValid = rule
    ? targetMatchCount === 1 && mutationRecords.length === plannedMutationCount &&
      mutationAppliedCount === plannedMutationCount &&
      mutationRecords.every((m) => m.reason === "applied")
    : mutationRecords.length === 0;
  const end: CallCaptureEnd = {
    processReturnCode: run.exitCode,
    termination: run.termination,
    timedOut: run.timedOut,
    complete: isCompleteRun(run) && sequenceMatches && mutationContractValid,
    ecallCount: prefix.events.length,
    targetMatchCount,
    mutationAppliedCount,
    incompleteReasons: [...new Set(reasons)],
  };
  const endRecord = {
    type: "capture_end",
    schema: CALL_CAPTURE_SCHEMA,
    process_return_code: end.processReturnCode,
    termination: end.termination,
    timed_out: end.timedOut,
    complete: end.complete,
    ecall_count: end.ecallCount,
    target_match_count: end.targetMatchCount,
    mutation_applied_count: end.mutationAppliedCount,
    incomplete_reasons: end.incompleteReasons,
  };
  const text = (nativeText.endsWith("\n") ? nativeText : nativeText + "\n") + JSON.stringify(endRecord) + "\n";
  const capture = parseCallCapture(text, expected);
  return { text, capture };
}

export function parseCallCapture(text: string, expected: CaptureExpectation): CallCaptureDocument {
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length < 2 || lines.some((line) => line.length === 0)) fail("call capture must contain start and end records");
  const parsed = lines.map((line, index) => object(parseStrictJson(line, "call capture line " + (index + 1)), "call capture line " + (index + 1)));
  const endRaw = parsed.at(-1)!;
  const endKeys = ["type", "schema", "process_return_code", "timed_out", "complete", "ecall_count",
    "target_match_count", "mutation_applied_count", "incomplete_reasons"];
  if (Object.hasOwn(endRaw, "termination")) endKeys.push("termination");
  exactKeys(endRaw, endKeys, "call capture end");
  if (endRaw.type !== "capture_end" || endRaw.schema !== CALL_CAPTURE_SCHEMA) fail("invalid call capture end record");
  const endTermination = endRaw.termination;
  const end: CallCaptureEnd = {
    processReturnCode: endRaw.process_return_code === null
      ? null
      : integer(endRaw.process_return_code, "call capture process_return_code"),
    termination: endTermination === "exited" || endTermination === "signaled" ||
        endTermination === "timeout" ? endTermination : "unknown",
    timedOut: typeof endRaw.timed_out === "boolean" ? endRaw.timed_out : fail("call capture timed_out must be boolean"),
    complete: typeof endRaw.complete === "boolean" ? endRaw.complete : fail("call capture complete must be boolean"),
    ecallCount: integer(endRaw.ecall_count, "call capture ecall_count"),
    targetMatchCount: integer(endRaw.target_match_count, "call capture target_match_count"),
    mutationAppliedCount: integer(endRaw.mutation_applied_count, "call capture mutation_applied_count"),
    incompleteReasons: Array.isArray(endRaw.incomplete_reasons) &&
      endRaw.incomplete_reasons.every((reason) => typeof reason === "string")
      ? endRaw.incomplete_reasons as string[]
      : fail("call capture incomplete_reasons must be a string array"),
  };
  const prefixText = lines.slice(0, -1).join("\n") + "\n";
  const prefix = parseNativeCallCapture(prefixText, expected);
  if (end.ecallCount !== prefix.events.length) fail("call capture end ecall_count differs from native records");
  const targetMatchCount = expected.mutation
    ? prefix.events.filter((event) => matchesExpectedTarget(event, expected.mutation!)).length
    : 0;
  const mutationAppliedCount = prefix.events.filter((event) => event.mutation?.applied === true).length;
  if (end.targetMatchCount !== targetMatchCount || end.mutationAppliedCount !== mutationAppliedCount) {
    fail("call capture end mutation counters differ from native records");
  }
  if (end.complete && (end.timedOut || end.processReturnCode !== 0 || end.incompleteReasons.length !== 0)) {
    fail("complete call capture has an invalid process result");
  }
  return { ...prefix, end };
}

export function captureHasExactlyOneMutation(
  capture: CallCaptureDocument,
  rule: ScalarMutationRule,
  options?: { allowBusinessRejectionExit?: boolean },
): boolean {
  const plannedCount = 1 + (rule.prefixMutations?.length ?? 0);
  if (capture.end.timedOut ||
      capture.end.targetMatchCount !== 1 ||
      capture.end.mutationAppliedCount !== plannedCount) return false;
  const allowBizReject = options?.allowBusinessRejectionExit === true;
  if (!capture.end.complete) {
    if (!allowBizReject || capture.end.processReturnCode === null ||
        capture.end.processReturnCode === 0 || capture.end.termination !== "exited") {
      return false;
    }
    const expectedReason = "host process exit code was " + String(capture.end.processReturnCode);
    if (capture.end.incompleteReasons.length === 0 ||
        capture.end.incompleteReasons.some((r) => r !== expectedReason)) {
      return false;
    }
  } else if (capture.end.processReturnCode !== 0) {
    return false;
  }
  const mutationEvents = capture.events.filter((event) => event.mutation !== null);
  if (mutationEvents.length !== plannedCount) return false;
  const wantGen = rule.targetGeneration ?? 1;
  const target = mutationEvents.find((event) => event.generation === wantGen &&
    event.selectorOrdinal === rule.selectorOrdinal && event.selectorSeq === rule.selectorSeq);
  if (!target) return false;
  /* Every planned prefix mutation must appear as an applied record on its
     designated call — the executed inputs are fully accounted for. */
  for (const pfx of rule.prefixMutations ?? []) {
    const pEvent = mutationEvents.find((ev) =>
      ev.generation === wantGen && ev.callSeq < target.callSeq &&
      ev.selectorOrdinal === pfx.selectorOrdinal &&
        BigInt(ev.selectorSeq) === BigInt(pfx.selectorSeq));
    if (!pEvent) return false;
    const pMut = pEvent.mutation!;
    if (!pMut.applied || pMut.reason !== "applied" ||
        pMut.paramIndex !== pfx.paramIndex ||
        pMut.widthBytes !== pfx.widthBytes ||
        pMut.byteOffset !== pfx.byteOffset ||
        pMut.expectedBits !== pfx.expectedBits ||
        pMut.replacementBits !== pfx.replacementBits ||
        pMut.observedBits !== pfx.expectedBits) return false;
  }
  const event = mutationEvents.find((ev) =>
    ev.generation === wantGen &&
    ev.selectorOrdinal === rule.selectorOrdinal &&
    ev.selectorSeq === rule.selectorSeq);
  if (!event) return false;
  const mutation = event.mutation!;
  if (!mutation.applied || mutation.reason !== "applied" ||
      mutation.widthBytes !== rule.widthBytes ||
      mutation.signedness !== rule.signedness ||
      mutation.expectedBits !== rule.expectedBits) return false;
  const opKind = rule.opKind ?? "replace_scalar";
  if (opKind === "replace_scalar") {
    if (mutation.observedBits !== rule.expectedBits ||
        mutation.replacementBits !== rule.replacementBits) return false;
    const scalar = event.scalarInputs.find((input) => input.paramIndex === rule.paramIndex);
    return mutation.paramIndex === rule.paramIndex && scalar?.bits === rule.replacementBits;
  }
  if (opKind === "mutate_buffer") {
    if (mutation.paramIndex !== rule.paramIndex || mutation.observedBits === null || mutation.observedBits === undefined) return false;
    if (mutation.observedBits === rule.expectedBits) {
      return mutation.replacementBits === rule.replacementBits;
    }
    if (rule.bufferSubOp === "xor_byte") {
      let xorMask = (BigInt(rule.expectedBits) ^ BigInt(rule.replacementBits)) & 0xffn;
      if (xorMask === 0n) xorMask = 1n;
      const wantRep = (BigInt(mutation.observedBits) ^ xorMask) & 0xffn;
      return BigInt(mutation.replacementBits) === wantRep;
    }
    return mutation.replacementBits === rule.replacementBits;
  }
  if (opKind === "extend_history") {
    return mutation.replacementBits === rule.replacementBits &&
      (mutation.observedBits === null || mutation.observedBits === undefined || mutation.observedBits === rule.expectedBits);
  }
  return mutation.observedBits === rule.expectedBits &&
    mutation.replacementBits === rule.replacementBits;
}

export function sameCallInputsExceptMutation(
  baseline: CallCaptureDocument,
  candidate: CallCaptureDocument,
  rule: ScalarMutationRule,
): boolean {
  const opKind = rule.opKind ?? "replace_scalar";
  const wantGen = rule.targetGeneration ?? 1;
  const extraCalls = opKind === "extend_history"
    ? (rule.repeatCount ?? rule.execMode ?? 1)
    : 0;

  if (extraCalls === 0) {
    const targetIdx = baseline.events.findIndex((event) =>
      event.generation === wantGen &&
      event.selectorOrdinal === rule.selectorOrdinal &&
      event.selectorSeq === rule.selectorSeq);
    if (targetIdx < 0) return false;
    if (candidate.events.length !== baseline.events.length &&
        candidate.events.length !== targetIdx + 1) {
      return false;
    }
    let targetSeen = false;
    for (let index = 0; index < candidate.events.length; index++) {
      const before = baseline.events[index]!;
      const after = candidate.events[index]!;
      if (before.generation !== after.generation || before.callSeq !== after.callSeq ||
          before.selectorOrdinal !== after.selectorOrdinal || before.selectorSeq !== after.selectorSeq ||
          before.scalarInputs.length !== after.scalarInputs.length) return false;
      const target = before.generation === wantGen &&
        before.selectorOrdinal === rule.selectorOrdinal &&
        before.selectorSeq === rule.selectorSeq;
      if (target) {
        if (targetSeen) return false;
        targetSeen = true;
      }
      for (let scalarIndex = 0; scalarIndex < before.scalarInputs.length; scalarIndex++) {
        const left = before.scalarInputs[scalarIndex]!;
        const right = after.scalarInputs[scalarIndex]!;
        if (left.paramIndex !== right.paramIndex || left.widthBytes !== right.widthBytes ||
            left.signedness !== right.signedness) return false;
        const allowRuntimeBoundLength = opKind === "mutate_buffer" &&
          (rule.execMode ?? 0) === 0 && index > targetIdx;
        if (opKind === "replace_scalar" && target && left.paramIndex === rule.paramIndex) {
          if (left.bits !== rule.expectedBits || right.bits !== rule.replacementBits) return false;
        } else if (left.bits !== right.bits && !allowRuntimeBoundLength) {
          return false;
        }
      }
    }
    return targetSeen;
  }

  if (candidate.events.length !== baseline.events.length + extraCalls) return false;
  const targetIdx = baseline.events.findIndex((event) =>
    event.generation === wantGen &&
    event.selectorOrdinal === rule.selectorOrdinal &&
    event.selectorSeq === rule.selectorSeq);
  if (targetIdx < 0) return false;
  for (let index = 0; index < targetIdx; index++) {
    const before = baseline.events[index]!;
    const after = candidate.events[index]!;
    if (before.generation !== after.generation || before.callSeq !== after.callSeq ||
        before.selectorOrdinal !== after.selectorOrdinal || before.selectorSeq !== after.selectorSeq) return false;
  }
  const mutatedEvent = candidate.events[targetIdx]!;
  return mutatedEvent.generation === wantGen &&
    mutatedEvent.selectorOrdinal === rule.selectorOrdinal &&
    mutatedEvent.selectorSeq === rule.selectorSeq &&
    mutatedEvent.mutation?.applied === true;
}
