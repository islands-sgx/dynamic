import { createHash } from "node:crypto";
import type {
  AbiEcall,
  AbiField,
  AbiParameter,
  AbiTypeDefinition,
  AbiTypeNode,
  CapturedObjectRef,
  CapturedObjectSnapshot,
  CapturedValue,
} from "../sequence/types";
import {
  ReplayPlanningError,
  type PlannedBufferParameter,
  type PlannedScalarParameter,
  type ReplayBaselineCall,
  type ReplayBufferOperation,
  type ReplayBufferShape,
  type ReplayBundleInputs,
  type ReplayCandidate,
  type ReplayLimits,
  type ReplayMarshalParameterV1,
  type ReplayPlanOptions,
  type ReplayPlanV1,
  type ReplayScalarOperation,
  type ReplaySignedness,
  type ReplayMemoryObject,
} from "./types";

export * from "./types";

const DEFAULT_LIMITS: ReplayLimits = {
  max_depth: 8,
  max_total_bytes: 1 << 20,
  max_objects: 128,
  max_array_elements: 1 << 16,
  max_candidates: 16,
};
const HARD_LIMITS: ReplayLimits = {
  max_depth: 64,
  max_total_bytes: 1 << 24,
  max_objects: 4096,
  max_array_elements: 1 << 20,
  max_candidates: 16,
};
const DIGEST_RE = /^(?:sha256:)?[0-9a-f]{64}$/i;

function fail(code: string, message: string): never {
  throw new ReplayPlanningError(code, message);
}

function safeInteger(value: unknown, label: string, min = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min) {
    fail("invalid_layout", label + " must be a safe integer >= " + min);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    fail("invalid_binding", label + " must be a SHA-256 digest");
  }
  return value.replace(/^sha256:/i, "").toLowerCase();
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function bytesHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function fromJsonBytes(value: readonly number[] | undefined, label: string): Uint8Array {
  if (!value) return new Uint8Array();
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index++) {
    const byte = value[index];
    if (typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      fail("invalid_capture", label + " contains a non-byte value");
    }
    bytes[index] = byte;
  }
  return bytes;
}

function integerValue(value: unknown, label: string): bigint {
  if (value && typeof value === "object" && !Array.isArray(value) && "kind" in value) {
    const wrapped = value as { kind?: unknown; value?: unknown };
    if (wrapped.kind !== "scalar") fail("invalid_capture", label + " is not a captured scalar");
    value = wrapped.value;
  }
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^(?:-?(?:0|[1-9][0-9]*)|0x[0-9a-f]+)$/i.test(value)) {
    return BigInt(value);
  }
  fail("invalid_capture", label + " is not an integer scalar");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function limitsFor(options?: ReplayPlanOptions): ReplayLimits {
  const limits = { ...DEFAULT_LIMITS, ...options?.limits };
  for (const key of Object.keys(limits) as Array<keyof ReplayLimits>) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0 || limits[key] > HARD_LIMITS[key]) {
      fail("invalid_limits", key + " is outside its hard safety ceiling");
    }
  }
  return limits;
}

function normalizeDirection(direction: string): "value" | "in" | "out" | "inout" {
  if (direction === "val") return "value";
  if (direction === "value" || direction === "in" || direction === "out" || direction === "inout") {
    return direction;
  }
  fail("unsupported_direction", "unspecified direction cannot be replayed");
}

function typeDefinitions(bundle: ReplayBundleInputs): Map<string, AbiTypeDefinition> {
  return new Map(bundle.abi.types.map((definition) => [definition.name, definition]));
}

function pointedType(parameter: AbiParameter): AbiTypeNode {
  let type = parameter.type;
  if (type.kind === "pointer") {
    if (!type.to) fail("invalid_abi", "pointer parameter " + parameter.name + " has no pointee");
    type = type.to;
  }
  return type;
}

function builtinWidth(name: string): number | undefined {
  const widths: Record<string, number> = {
    int8_t: 1, uint8_t: 1, char: 1, signed_char: 1, unsigned_char: 1, bool: 1, _Bool: 1,
    int16_t: 2, uint16_t: 2, short: 2, unsigned_short: 2,
    int32_t: 4, uint32_t: 4, int: 4, unsigned: 4, unsigned_int: 4, float: 4,
    int64_t: 8, uint64_t: 8, long_long: 8, unsigned_long_long: 8, size_t: 8,
    intptr_t: 8, uintptr_t: 8, double: 8,
  };
  return widths[name];
}

function isIntegerType(type: AbiTypeNode, defs: Map<string, AbiTypeDefinition>, seen = new Set<string>()): boolean {
  if (type.kind === "builtin") return type.name !== "void" && type.name !== "float" && type.name !== "double";
  if (type.kind === "enum") return true;
  if (type.kind === "named" && type.name) {
    if (seen.has(type.name)) return false;
    seen.add(type.name);
    const definition = defs.get(type.name);
    return definition?.kind === "enum";
  }
  return false;
}

function assertNoUnsafePointee(
  type: AbiTypeNode,
  defs: Map<string, AbiTypeDefinition>,
  limits: ReplayLimits,
  depth = 1,
  stack = new Set<string>(),
): void {
  if (depth > limits.max_depth) fail("recursion_depth", "pointee type exceeds the replay recursion depth");
  if (type.kind === "builtin") {
    if (type.name === "void" || !type.name) fail("opaque_type", "void or anonymous pointee cannot be reconstructed");
    return;
  }
  if (type.kind === "pointer") fail("nested_pointer", "nested pointers are explicitly unsupported");
  if (type.kind === "named") {
    if (!type.name) fail("opaque_type", "anonymous named pointee is unsupported");
    if (stack.has(type.name)) fail("type_cycle", "cyclic ABI type " + type.name + " is unsupported");
    const definition = defs.get(type.name);
    if (!definition || definition.kind === "named" && definition.resolved === false) {
      fail("opaque_type", "unresolved ABI type " + type.name + " is unsupported");
    }
    if (definition.kind === "enum") return;
    if (definition.kind === "union") fail("opaque_type", "union pointee lacks a stable active member");
    if (definition.kind !== "struct" || !definition.fields) fail("opaque_type", "unsupported named pointee " + type.name);
    const next = new Set(stack);
    next.add(type.name);
    for (const field of definition.fields) assertNoUnsafeField(field, defs, limits, depth + 1, next);
    return;
  }
  if (type.kind === "struct" || type.kind === "union") {
    const definition = defs.get(type.name ?? "");
    if (!definition || definition.kind === "named" && definition.resolved === false) {
      fail("opaque_type", "unresolved aggregate pointee is unsupported");
    }
    if (type.kind === "union") fail("opaque_type", "union pointee lacks a stable active member");
    if (!definition.fields) fail("opaque_type", "aggregate pointee has no field description");
    for (const field of definition.fields) assertNoUnsafeField(field, defs, limits, depth + 1, stack);
    return;
  }
  fail("opaque_type", "unsupported pointee type");
}

function assertNoUnsafeField(
  field: AbiField,
  defs: Map<string, AbiTypeDefinition>,
  limits: ReplayLimits,
  depth: number,
  stack: Set<string>,
): void {
  if (field.pointer_depth > 0 || field.form === "pointer" || field.type.kind === "pointer") {
    fail("nested_pointer", "field " + field.name + " contains a nested pointer");
  }
  for (const dimension of field.array_dimensions) {
    safeInteger(dimension, "array dimension", 1);
  }
  assertNoUnsafePointee(field.type, defs, limits, depth, stack);
}

function layoutIndex(layout: ReplayBundleInputs["marshal_layout"]): Map<number, ReplayMarshalParameterV1> {
  const byIndex = new Map<number, ReplayMarshalParameterV1>();
  for (const parameter of layout.parameters) {
    const index = safeInteger(parameter.parameter_index, "parameter_index");
    if (byIndex.has(index)) fail("invalid_layout", "duplicate marshal parameter index " + index);
    safeInteger(parameter.ms_offset, "ms_offset");
    safeInteger(parameter.ms_size, "ms_size");
    if (typeof parameter.name !== "string" || !parameter.name) fail("invalid_layout", "marshal parameter name is missing");
    if (typeof parameter.source_type !== "string" || !parameter.source_type) fail("invalid_layout", "compiler-probed source_type is missing");
    safeInteger(parameter.width_bytes, "width_bytes", 1);
    if (parameter.element_width_bytes !== undefined) safeInteger(parameter.element_width_bytes, "element_width_bytes", 1);
    if (typeof parameter.is_pointer !== "boolean") fail("invalid_layout", "is_pointer must be boolean");
    byIndex.set(index, parameter);
  }
  return byIndex;
}

function baselineScalar(
  baseline: ReplayBaselineCall,
  parameter: AbiParameter,
  index: number,
): bigint {
  if (!Object.hasOwn(baseline.arguments, parameter.name)) {
    fail("invalid_capture", "baseline call is missing argument " + parameter.name);
  }
  return integerValue(baseline.arguments[parameter.name], "argument " + parameter.name + " (param " + index + ")");
}

function parseIntegerInput(value: unknown, label: string): bigint {
  return integerValue(value, label);
}

function valueBits(value: bigint, widthBytes: number, signedness: ReplaySignedness, label: string): bigint {
  const bits = BigInt(widthBytes * 8);
  const unsignedMax = (1n << bits) - 1n;
  const min = signedness === "signed" ? -(1n << (bits - 1n)) : 0n;
  const max = signedness === "signed" ? (1n << (bits - 1n)) - 1n : unsignedMax;
  if (value < min || value > max) fail("integer_overflow", label + " does not fit " + (signedness === "signed" ? "signed" : "unsigned") + " " + bits + "-bit integer");
  return value < 0n ? (1n << bits) + value : value;
}

function formatBits(bits: bigint, widthBytes: number): string {
  return "0x" + bits.toString(16).padStart(widthBytes * 2, "0");
}

function checkedBound(value: bigint, limits: ReplayLimits, label: string): number {
  if (value < 0n) fail("invalid_bound", label + " cannot be negative");
  if (value > BigInt(limits.max_total_bytes)) fail("resource_limit", label + " exceeds max_total_bytes");
  return Number(value);
}

function refFromValue(value: CapturedValue | undefined): CapturedObjectRef | null {
  if (value === null || value === undefined) return null;
  if (isObject(value) && value.kind === "object_ref") return value as unknown as CapturedObjectRef;
  if (isObject(value) && value.kind === "scalar" && value.value === null) return null;
  fail("invalid_capture", "pointer argument must be null or an object_ref");
}

function objectKey(objectId: string, generation: number): string {
  return objectId + "\u0000" + generation;
}

interface MutableObject {
  object_id: string;
  generation: number;
  kind: "buffer" | "record";
  capacity: number;
  original: Uint8Array;
  bytes: Uint8Array;
}

function snapshotCapacity(snapshot: CapturedObjectSnapshot, label: string): number {
  const capacity = snapshot.capacity ?? snapshot.bytes?.length ?? snapshot.actual_length;
  if (capacity === undefined) fail("invalid_capture", label + " has no bounded capacity");
  return safeInteger(capacity, label + ".capacity");
}

function gatherObjects(
  baseline: ReplayBaselineCall,
  limits: ReplayLimits,
): { objects: Map<string, MutableObject>; totalBytes: number } {
  const objects = new Map<string, MutableObject>();
  const active = new Set<string>();
  let totalBytes = 0;

  const visitValue = (value: CapturedValue | undefined, depth: number): void => {
    if (depth > limits.max_depth) fail("recursion_depth", "captured object graph exceeds max_depth");
    if (value === null || value === undefined || !isObject(value) || value.kind !== "object_ref") return;
    const ref = value as unknown as CapturedObjectRef;
    const objectId = ref.object_id;
    if (typeof objectId !== "string" || !objectId) fail("invalid_capture", "object_ref.object_id is missing");
    const snapshot = baseline.objects[objectId];
    if (!snapshot) fail("invalid_capture", "object_ref points to missing object " + objectId);
    if (snapshot.kind === "opaque") fail("opaque_object", "opaque captured object " + objectId + " cannot be reconstructed");
    const snapshotGeneration = safeInteger(snapshot.generation, objectId + ".snapshot generation");
    const generation = safeInteger(ref.generation ?? snapshotGeneration, objectId + ".generation");
    if (generation !== snapshotGeneration) fail("stale_object_generation", "object_ref generation does not match captured snapshot for " + objectId);
    const key = objectKey(objectId, generation);
    if (active.has(key)) fail("object_cycle", "captured object graph contains a cycle at " + objectId);
    const existing = objects.get(key);
    if (existing) return;
    if (objects.size >= limits.max_objects) fail("resource_limit", "captured object graph exceeds max_objects");
    const capacity = snapshotCapacity(snapshot, objectId);
    totalBytes += capacity;
    if (totalBytes > limits.max_total_bytes) fail("resource_limit", "captured objects exceed max_total_bytes");
    const source = fromJsonBytes(snapshot.bytes, objectId + ".bytes");
    if (source.length > capacity) fail("invalid_capture", objectId + " bytes exceed captured capacity");
    const storage = new Uint8Array(capacity);
    storage.set(source);
    objects.set(key, {
      object_id: objectId, generation,
      kind: snapshot.kind === "record" ? "record" : "buffer",
      capacity, original: storage.slice(), bytes: storage.slice(),
    });
    active.add(key);
    if (snapshot.fields) {
      const fieldNames = Object.keys(snapshot.fields).sort();
      for (const name of fieldNames) visitValue(snapshot.fields[name], depth + 1);
    }
    active.delete(key);
  };

  for (const name of Object.keys(baseline.arguments).sort()) visitValue(baseline.arguments[name], 1);
  for (const name of Object.keys(baseline.outputs).sort()) visitValue(baseline.outputs[name], 1);
  return { objects, totalBytes };
}

function resolvedReference(
  value: CapturedValue | undefined,
  baseline: ReplayBaselineCall,
  objects: Map<string, MutableObject>,
): { ref: CapturedObjectRef; object: MutableObject } | null {
  const ref = refFromValue(value);
  if (!ref) return null;
  const snapshot = baseline.objects[ref.object_id];
  if (!snapshot) fail("invalid_capture", "missing object " + ref.object_id);
  const generation = safeInteger(ref.generation ?? snapshot.generation, ref.object_id + ".generation");
  if (generation !== snapshot.generation) fail("stale_object_generation", "object_ref generation does not match captured snapshot for " + ref.object_id);
  const object = objects.get(objectKey(ref.object_id, generation));
  if (!object) fail("invalid_capture", "unregistered object " + ref.object_id);
  return { ref: { ...ref, generation }, object };
}

function scalarOverrides(
  abiParams: readonly AbiParameter[],
  layoutByIndex: Map<number, ReplayMarshalParameterV1>,
  baseline: ReplayBaselineCall,
  candidates: readonly ReplayCandidate[],
  defs: Map<string, AbiTypeDefinition>,
): Map<number, bigint> {
  const values = new Map<number, bigint>();
  for (let index = 0; index < abiParams.length; index++) {
    const parameter = abiParams[index]!;
    const layout = layoutByIndex.get(index)!;
    if (layout.is_pointer) continue;
    values.set(index, baselineScalar(baseline, parameter, index));
  }
  for (const candidate of candidates) {
    if (candidate.kind !== "scalar") continue;
    const index = candidate.param_index;
    const parameter = abiParams[index];
    const layout = layoutByIndex.get(index);
    if (!parameter || !layout) fail("invalid_candidate", "candidate param_index is outside the ECALL ABI");
    if (layout.is_pointer || parameter.pointer_depth > 0 || parameter.type.kind === "pointer") {
      fail("invalid_candidate", "scalar candidate targets a pointer parameter");
    }
    if (!isIntegerType(parameter.type, defs)) {
      fail("unsupported_scalar", "only integer scalars can be replaced");
    }
    if (layout.signedness !== "signed" && layout.signedness !== "unsigned") {
      fail("invalid_layout", "integer scalar is missing compiler-probed signedness");
    }
    const current = baselineScalar(baseline, parameter, index);
    const expected = parseIntegerInput(candidate.expected_value, "candidate expected_value");
    if (current !== expected) fail("baseline_mismatch", "scalar expected_value does not match baseline param " + index);
    const replacement = parseIntegerInput(candidate.replacement_value, "candidate replacement_value");
    valueBits(current, layout.width_bytes, layout.signedness, "baseline scalar");
    valueBits(replacement, layout.width_bytes, layout.signedness, "replacement scalar");
    values.set(index, replacement);
  }
  return values;
}

function boundValue(
  expression: unknown,
  mode: "size" | "count",
  parameter: AbiParameter,
  indexByName: Map<string, number>,
  scalarValues: Map<number, bigint>,
  limits: ReplayLimits,
): bigint | null {
  if (!expression || !isObject(expression)) return null;
  if (expression.kind === "integer") {
    return parseIntegerInput(expression.value, parameter.name + " " + mode + " literal");
  }
  if (expression.kind !== "identifier" || typeof expression.name !== "string") {
    fail("invalid_abi", parameter.name + " has an unsupported " + mode + " expression");
  }
  const boundIndex = indexByName.get(expression.name);
  if (boundIndex === undefined) fail("unbound_length", parameter.name + " " + mode + " identifier " + expression.name + " is not an ECALL parameter");
  const value = scalarValues.get(boundIndex);
  if (value === undefined) fail("unbound_length", parameter.name + " " + mode + " parameter is not a scalar");
  if (value < 0n || value > BigInt(limits.max_total_bytes)) fail("invalid_bound", parameter.name + " " + mode + " value is outside replay bounds");
  return value;
}

function arrayCount(parameter: AbiParameter, limits: ReplayLimits): bigint | null {
  if (parameter.array_dimensions.length === 0) return null;
  let product = 1n;
  for (const dimension of parameter.array_dimensions) {
    const n = BigInt(safeInteger(dimension, parameter.name + " array dimension", 1));
    product *= n;
    if (product > BigInt(limits.max_array_elements)) fail("resource_limit", parameter.name + " array exceeds max_array_elements");
  }
  return product;
}

function elementWidth(
  parameter: AbiParameter,
  layout: ReplayMarshalParameterV1,
  type: AbiTypeNode,
): number {
  if (layout.element_width_bytes !== undefined) return layout.element_width_bytes;
  if (type.kind === "builtin" && type.name) {
    const width = builtinWidth(type.name);
    if (width !== undefined) return width;
    if (type.name === "wchar_t" || type.name === "char16_t" || type.name === "char32_t") {
      fail("invalid_layout", parameter.name + " requires compiler-probed character width");
    }
  }
  fail("invalid_layout", parameter.name + " requires compiler-probed element_width_bytes");
}

function terminatedLength(bytes: Uint8Array, offset: number, width: number, maxBytes: number, label: string): number {
  if (width < 1 || width > 4 || maxBytes % width !== 0) fail("invalid_string", label + " has invalid character width");
  const end = Math.min(bytes.length, offset + maxBytes);
  for (let at = offset; at + width <= end; at += width) {
    let zero = true;
    for (let j = 0; j < width; j++) if (bytes[at + j] !== 0) zero = false;
    if (zero) return at + width - offset;
  }
  fail("missing_terminator", label + " has no terminator within its bounded capacity");
}

function resolveByteLength(
  parameter: AbiParameter,
  indexByName: Map<string, number>,
  scalarValues: Map<number, bigint>,
  limits: ReplayLimits,
  width: number,
  ref: CapturedObjectRef | null,
  object: MutableObject | null,
): { length: number; count: number } {
  const attrs = parameter.attributes;
  if (attrs?.user_check) fail("user_check", "user_check parameter " + parameter.name + " is explicitly unsupported");
  if (attrs?.isptr) fail("nested_pointer", "isptr parameter " + parameter.name + " is explicitly unsupported");
  const size = boundValue(attrs?.size, "size", parameter, indexByName, scalarValues, limits);
  const count = boundValue(attrs?.count, "count", parameter, indexByName, scalarValues, limits);
  const dimensions = arrayCount(parameter, limits);
  let byteLength: bigint | null = null;
  let elements: bigint | null = null;
  if (dimensions !== null && (size !== null || count !== null)) {
    fail("unsupported_bound", parameter.name + " cannot combine fixed array dimensions with size and count attributes");
  }
  if (size !== null || count !== null) {
    const sizeBytes = size ?? BigInt(width);
    const countElements = count ?? 1n;
    if (sizeBytes < 0n || countElements < 0n) fail("invalid_bound", parameter.name + " size and count cannot be negative");
    const requestedBytes = sizeBytes * countElements;
    checkedBound(requestedBytes, limits, parameter.name + " size*count");
    if (requestedBytes % BigInt(width) !== 0n) fail("invalid_bound", parameter.name + " size*count is not aligned to element width");
    elements = requestedBytes / BigInt(width);
    byteLength = requestedBytes;
  } else if (dimensions !== null) {
    elements = dimensions;
    byteLength = dimensions * BigInt(width);
  } else if (ref?.length !== undefined) {
    byteLength = BigInt(safeInteger(ref.length, parameter.name + " captured slice length"));
  } else if (object) {
    const offset = safeInteger(ref?.offset ?? 0, parameter.name + " captured slice offset");
    byteLength = BigInt(object.capacity - offset);
  }


  const isString = attrs?.string === true;
  const isWString = attrs?.wstring === true;
  if (attrs?.string && attrs?.wstring) fail("invalid_abi", parameter.name + " cannot be both string and wstring");
  if ((isString || isWString) && parameter.direction !== "in" && parameter.direction !== "inout") {
    fail("unsupported_direction", "string and wstring buffers require input direction");
  }

  if (byteLength === null) {
    if (!object || !ref) fail("unbounded_pointer", parameter.name + " has no bounded capture");
    const offset = safeInteger(ref.offset ?? 0, parameter.name + " captured slice offset");
    byteLength = BigInt(object.capacity - offset);
  }
  let byteLengthNumber = checkedBound(byteLength, limits, parameter.name + " buffer length");
  if (elements !== null && elements > BigInt(limits.max_array_elements)) fail("resource_limit", parameter.name + " exceeds max_array_elements");
  if (byteLengthNumber % width !== 0) fail("invalid_bound", parameter.name + " byte length is not aligned to element width");
  if (elements === null) elements = BigInt(byteLengthNumber / width);
  if (elements * BigInt(width) !== BigInt(byteLengthNumber)) fail("invalid_bound", parameter.name + " size/count shape is inconsistent");

  if ((isString || isWString) && object && ref && byteLengthNumber === object.capacity - (ref.offset ?? 0)) {
    const actualTerminatedLength = terminatedLength(object.original, ref.offset ?? 0, width, byteLengthNumber, parameter.name);
    byteLengthNumber = actualTerminatedLength;
    elements = BigInt(byteLengthNumber / width);
  }
  if ((isString || isWString) && !object) fail("invalid_capture", parameter.name + " string has no captured object");
  return { length: byteLengthNumber, count: Number(elements) };
}

function checkStringTerminator(bytes: Uint8Array, width: number, label: string): void {
  if (bytes.length < width || bytes.length % width !== 0) fail("invalid_string", label + " byte length is not a whole character sequence");
  for (let i = 0; i < width; i++) {
    if (bytes[bytes.length - width + i] !== 0) fail("missing_terminator", label + " replacement must preserve its terminator");
  }
}

function canonicalValue(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_plan", "plan contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalValue).join(",") + "]";
  if (isObject(value)) return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonicalValue(value[key])).join(",") + "}";
  fail("invalid_plan", "plan contains a non-JSON value");
}

export function canonicalReplayPlanJson(plan: ReplayPlanV1): string {
  return canonicalValue(plan);
}

export function buildReplayPlan(
  bundle: ReplayBundleInputs,
  baseline: ReplayBaselineCall,
  candidates: readonly ReplayCandidate[],
  options?: ReplayPlanOptions,
): ReplayPlanV1 {
  const limits = limitsFor(options);
  const manifestSha = digest(bundle.manifest_sha256, "bundle manifest SHA");
  const layoutSha = digest(bundle.marshal_layout_sha256, "marshal layout SHA");
  if (bundle.abi.schema !== "atfield-edl-abi-v1") fail("invalid_abi", "bundle ABI schema must be atfield-edl-abi-v1");
  const layout = bundle.marshal_layout;
  if (layout.schema !== "atfield-marshal-layout-v1" || layout.compiler_probed !== true) {
    fail("unprobed_layout", "replay requires the compiler-probed atfield-marshal-layout-v1 artifact");
  }
  const selector = safeInteger(baseline.ordinal, "baseline ordinal");
  const selectorSeq = safeInteger(baseline.selector_seq, "baseline selector_seq");
  const instanceGeneration = safeInteger(baseline.instance_generation, "baseline instance_generation");
  const callSeq = safeInteger(baseline.call_seq, "baseline call_seq");
  if (layout.selector_ordinal !== selector) fail("layout_mismatch", "marshal layout selector does not match captured baseline");
  const ecall = bundle.abi.ecalls.find((item) => item.ordinal === selector);
  if (!ecall) fail("invalid_capture", "baseline selector is absent from bundled ABI");
  safeInteger(layout.marshal_size, "marshal_size");
  if (ecall.parameters.length > 64) fail("resource_limit", "ECALL has more than 64 parameters");
  const byIndex = layoutIndex(layout);
  if (byIndex.size !== ecall.parameters.length) fail("layout_mismatch", "marshal layout parameter count differs from ABI");
  for (const parameter of byIndex.values()) {
    if (parameter.ms_offset + parameter.ms_size > layout.marshal_size) fail("layout_mismatch", "marshal parameter exceeds marshal_size");
  }
  const indexByName = new Map<string, number>();
  for (let index = 0; index < ecall.parameters.length; index++) {
    const parameter = ecall.parameters[index]!;
    const marshal = byIndex.get(index);
    if (!marshal) fail("layout_mismatch", "marshal layout is missing parameter " + index);
    if (marshal.name !== parameter.name) fail("layout_mismatch", "marshal parameter order/name differs from ABI at index " + index);
    const expectedDirection = normalizeDirection(parameter.direction);
    if (normalizeDirection(marshal.direction) !== expectedDirection) fail("layout_mismatch", "marshal direction differs from ABI for " + parameter.name);
    const abiPointer = parameter.pointer_depth > 0 || parameter.type.kind === "pointer" || parameter.form === "pointer";
    if (abiPointer !== marshal.is_pointer) fail("layout_mismatch", "pointer shape differs from ABI for " + parameter.name);
    indexByName.set(parameter.name, index);
  }
  if (candidates.length > limits.max_candidates) fail("resource_limit", "candidate count exceeds max_candidates");
  const seenCandidates = new Set<number>();
  for (const candidate of candidates) {
    const index = safeInteger(candidate.param_index, "candidate param_index");
    if (!byIndex.has(index) || index >= ecall.parameters.length) fail("invalid_candidate", "candidate param_index is outside the ECALL ABI");
    if (seenCandidates.has(index)) fail("invalid_candidate", "multiple candidates target one parameter");
    seenCandidates.add(index);
  }

  const contract = bundle.contracts?.[selector];
  if (contract?.sizeQuery) {
    const stability = contract.sizeQuery.stability;
    if (!stability) fail("fresh_instance_required", "size-query replay requires explicit stability evidence");
    if (stability.kind === "fresh-instance-differential") {
      fail("fresh_instance_required", "size-query replay requires differential evidence from fresh enclave instances");
    }
    if (!stability.evidenceId.trim()) fail("invalid_contract", "size-query stability evidenceId is empty");
  }

  const defs = typeDefinitions(bundle);
  const scalarValues = scalarOverrides(ecall.parameters, byIndex, baseline, candidates, defs);
  const { objects: objectMap } = gatherObjects(baseline, limits);
  const originalObjects = new Map<string, Uint8Array>();
  for (const [key, object] of objectMap) originalObjects.set(key, object.original.slice());

  const parameters: Array<PlannedScalarParameter | PlannedBufferParameter> = [];
  const scalarOps: ReplayScalarOperation[] = [];
  const bufferOps: ReplayBufferOperation[] = [];

  for (let index = 0; index < ecall.parameters.length; index++) {
    const parameter = ecall.parameters[index]!;
    const marshal = byIndex.get(index)!;
    const direction = normalizeDirection(parameter.direction);
    const candidate = candidates.find((item) => item.param_index === index);
    if (!marshal.is_pointer) {
      if (direction !== "value") fail("layout_mismatch", "non-pointer scalar has a pointer direction");
      const signedness = marshal.signedness;
      if (signedness !== "signed" && signedness !== "unsigned") fail("invalid_layout", "scalar " + parameter.name + " has no compiler-probed signedness");
      if (![1, 2, 4, 8].includes(marshal.width_bytes)) fail("invalid_layout", "scalar width must be 1, 2, 4, or 8 bytes");
      if (!isIntegerType(parameter.type, defs)) fail("unsupported_scalar", "non-integer scalar " + parameter.name + " cannot be replayed");
      const original = baselineScalar(baseline, parameter, index);
      const effective = scalarValues.get(index) ?? original;
      const expectedBits = formatBits(valueBits(original, marshal.width_bytes, signedness, parameter.name), marshal.width_bytes);
      const effectiveBits = formatBits(valueBits(effective, marshal.width_bytes, signedness, parameter.name), marshal.width_bytes);
      parameters.push({
        kind: "scalar", param_index: index, name: parameter.name,
        width_bytes: marshal.width_bytes, signedness, direction: "value",
        expected_bits: expectedBits, effective_bits: effectiveBits,
      });
      if (candidate?.kind === "scalar") {
        scalarOps.push({
          op: "replace_scalar", param_index: index, width_bytes: marshal.width_bytes,
          signedness, expected_bits: expectedBits, replacement_bits: effectiveBits,
        });
      } else if (candidate) fail("invalid_candidate", "bytes candidate targets scalar " + parameter.name);
      continue;
    }

    if (direction === "value") fail("layout_mismatch", "pointer parameter has value direction");
    const attrs = parameter.attributes;
    if (attrs?.user_check) fail("user_check", "user_check parameter " + parameter.name + " is explicitly unsupported");
    if (parameter.pointer_depth > 1) fail("nested_pointer", "nested pointer parameter " + parameter.name + " is explicitly unsupported");
    if (attrs?.isptr) fail("nested_pointer", "isptr parameter " + parameter.name + " is explicitly unsupported");
    const pointee = pointedType(parameter);
    const isVoidBytePointer = pointee.kind === "builtin" && pointee.name === "void";
    if (isVoidBytePointer) {
      if (attrs?.size === null || attrs?.size === undefined || attrs.count !== null) {
        fail("opaque_type", "void pointer " + parameter.name + " requires an explicit byte-size bound");
      }
    } else {
      assertNoUnsafePointee(pointee, defs, limits);
    }
    if ((attrs?.string || attrs?.wstring) && pointee.kind === "builtin") {
      const isWide = attrs.wstring === true;
      if (isWide && pointee.name !== "wchar_t" && pointee.name !== "char16_t" && pointee.name !== "char32_t") {
        fail("invalid_abi", parameter.name + " wstring does not point to a wide character type");
      }
      if (!isWide && pointee.name !== "char" && pointee.name !== "int8_t" && pointee.name !== "uint8_t") {
        fail("invalid_abi", parameter.name + " string does not point to a byte character type");
      }
    }
    const width = isVoidBytePointer ? 1 : elementWidth(parameter, marshal, pointee);
    if (!Object.hasOwn(baseline.arguments, parameter.name)) fail("invalid_capture", "baseline call is missing argument " + parameter.name);
    const ref = resolvedReference(baseline.arguments[parameter.name], baseline, objectMap);
    const isNull = ref === null;
    let offset = 0;
    let object: MutableObject | null = null;
    if (ref) {
      object = ref.object;
      offset = safeInteger(ref.ref.offset ?? 0, parameter.name + " object offset");
      if (offset > object.capacity) fail("invalid_capture", parameter.name + " offset exceeds captured object capacity");
    }
    const original = object ? originalObjects.get(objectKey(object.object_id, object.generation))! : new Uint8Array();
    const resolved = resolveByteLength(parameter, indexByName, scalarValues, limits, width, ref?.ref ?? null, object);
    const length = resolved.length;
    if (ref && offset + length > object!.capacity) fail("shape_mismatch", parameter.name + " bound exceeds captured object capacity");
    if (ref && direction !== "out" && offset + length > original.length) {
      fail("invalid_capture", parameter.name + " input bytes are shorter than its bounded shape");
    }
    if (length > limits.max_total_bytes) fail("resource_limit", parameter.name + " buffer exceeds max_total_bytes");
    const count = resolved.count;
    const capturedSliceCapacity = ref ? safeInteger(ref.ref.length ?? (object!.capacity - offset), parameter.name + " baseline slice capacity") : 0;
    const rebuildOwnedBuffer = ref !== null && length !== capturedSliceCapacity;
    if (count > limits.max_array_elements) fail("resource_limit", parameter.name + " exceeds max_array_elements");
    const isString = attrs?.string === true || attrs?.wstring === true;
    const capturedSliceLength = ref
      ? safeInteger(baseline.buffer_evidence?.[index]?.base_slice.length ?? ref.ref.length ?? length, parameter.name + " captured base-slice length")
      : 0;
    if (capturedSliceLength % width !== 0) fail("invalid_capture", parameter.name + " captured slice is not aligned to element width");
    if (ref && offset + capturedSliceLength > object!.capacity) fail("invalid_capture", parameter.name + " captured base slice exceeds object capacity");
    if (ref && direction !== "out" && offset + capturedSliceLength > original.length) {
      fail("invalid_capture", parameter.name + " captured base slice exceeds available bytes");
    }
    let expectedSlice = new Uint8Array(capturedSliceLength);
    let effectiveSlice = new Uint8Array(length);
    if (ref) {
      expectedSlice.set(original.slice(offset, offset + capturedSliceLength));
      effectiveSlice.set(object!.bytes.slice(offset, offset + length));
    }
    if (direction === "out") {
      effectiveSlice.fill(0);
      if (object) object.bytes.fill(0, offset, offset + length);
    }
    if (isString && !isNull) checkStringTerminator(effectiveSlice, width, parameter.name);
    const expectedShape: ReplayBufferShape | null = ref ? {
      object_id: object!.object_id,
      object_generation: object!.generation,
      offset,
      byte_length: capturedSliceLength,
      element_width_bytes: width,
      element_count: capturedSliceLength / width,
      object_capacity: object!.capacity,
      object_sha256: sha256(original),
      slice_sha256: sha256(expectedSlice),
    } : null;
    const effectiveShape: ReplayBufferShape | null = ref ? {
      object_id: object!.object_id,
      object_generation: object!.generation,
      offset,
      byte_length: length,
      element_width_bytes: width,
      element_count: count,
      object_capacity: object!.capacity,
      object_sha256: sha256(original),
      slice_sha256: sha256(effectiveSlice),
    } : null;
    parameters.push({
      kind: "buffer",
      param_index: index,
      name: parameter.name,
      direction,
      is_null: isNull,
      element_width_bytes: width,
      element_count: isNull ? 0 : count,
      array_dimensions: [...parameter.array_dimensions],
      byte_length: isNull ? 0 : length,
      copy_back: direction === "out" || direction === "inout",
      owned_storage: "single_pointer_copy",
      rebuild_owned_buffer: rebuildOwnedBuffer,
      object_id: ref?.ref.object_id ?? null,
      object_generation: ref ? object!.generation : null,
      offset: ref ? offset : 0,
      expected_shape: expectedShape,
      effective_shape: effectiveShape,
      effective_slice_sha256: isNull ? null : sha256(effectiveSlice),
    });

    if (candidate?.kind === "bytes") {
      if (!ref || !object) fail("invalid_candidate", "byte candidate cannot create storage for a null pointer");
      const evidence = baseline.buffer_evidence?.[index];
      if (!evidence) fail("missing_buffer_evidence", "byte mutation requires explicit object, generation, base-slice, capacity, and digest evidence");
      const evidenceOffset = safeInteger(evidence.base_slice.offset, parameter.name + " evidence base offset");
      const evidenceLength = safeInteger(evidence.base_slice.length, parameter.name + " evidence base length");
      const evidenceCapacity = safeInteger(evidence.capacity, parameter.name + " evidence capacity");
      const evidenceGeneration = safeInteger(evidence.generation, parameter.name + " evidence generation");
      const evidenceSha = digest(evidence.sha256, parameter.name + " evidence SHA");
      if (evidence.object_id !== object.object_id || evidenceGeneration !== object.generation || evidenceOffset !== offset || evidenceLength !== capturedSliceLength || evidenceCapacity !== object.capacity) {
        fail("missing_buffer_evidence", "byte mutation evidence does not match the captured object shape");
      }
      if (sha256(expectedSlice) !== evidenceSha) fail("baseline_mismatch", "capture buffer digest does not match its base slice");
      if (candidate.expected_length !== capturedSliceLength) fail("baseline_mismatch", "byte candidate expected length differs from captured buffer shape");
      const expectedSha = digest(candidate.expected_sha256, "candidate expected buffer SHA");
      if (sha256(expectedSlice) !== expectedSha) fail("baseline_mismatch", "byte candidate digest differs from captured baseline slice");
      const replacement = fromJsonBytes(candidate.replacement_bytes, "candidate replacement_bytes");
      if (replacement.length !== length) fail("shape_mismatch", "byte candidate replacement must match the effective owned-buffer shape");
      if (isString) checkStringTerminator(replacement, width, parameter.name);
      object.bytes.set(replacement, offset);
      bufferOps.push({
        op: "replace_buffer",
        param_index: index,
        expected_shape: expectedShape!,
        replacement_shape: {
          object_id: object.object_id, object_generation: object.generation, offset,
          byte_length: replacement.length, element_width_bytes: width, element_count: replacement.length / width,
          object_capacity: object.capacity, object_sha256: sha256(object.bytes), slice_sha256: sha256(replacement),
        },
        replacement_bytes_hex: bytesHex(replacement),
        replacement_sha256: sha256(replacement),
      });
    } else if (candidate) fail("invalid_candidate", "scalar candidate targets buffer " + parameter.name);
  }

  const memory: ReplayMemoryObject[] = [...objectMap.values()]
    .sort((left, right) => left.object_id < right.object_id ? -1 : left.object_id > right.object_id ? 1 : left.generation - right.generation)
    .map((object) => ({
      object_id: object.object_id,
      generation: object.generation,
      kind: object.kind,
      capacity: object.capacity,
      baseline_sha256: sha256(object.original),
      initial_sha256: sha256(object.bytes),
      initial_bytes_hex: bytesHex(object.bytes),
    }));

  const plan: ReplayPlanV1 = {
    schema: "atfield-replay-plan-v1",
    version: 1,
    binding: {
      bundle_manifest_sha256: manifestSha,
      marshal_layout_sha256: layoutSha,
    },
    target: {
      selector_ordinal: selector,
      selector_seq: selectorSeq,
      instance_generation: instanceGeneration,
      call_seq: callSeq,
      ecall_name: ecall.name,
    },
    action: "reconstruct_captured_call_once",
    parameters: parameters.sort((left, right) => left.param_index - right.param_index),
    memory,
    scalar_ops: scalarOps.sort((left, right) => left.param_index - right.param_index),
    buffer_ops: bufferOps.sort((left, right) => left.param_index - right.param_index),
  };
  canonicalValue(plan);
  return plan;
}
