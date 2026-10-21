import {
  ABI_SCHEMA_NAME,
  type AbiAttributeSet,
  type AbiEcall,
  type AbiField,
  type AbiParameter,
  type AbiTypeDefinition,
  type AbiTypeNode,
  type BoundExpression,
  type CapturedObjectRef,
  type CapturedObjectSnapshot,
  type CapturedRecord,
  type CapturedValue,
  type Edger8rAbiSchema,
  type JsonScalar,
  type ReplayContract,
  type ReplayContracts,
  type ValueKind,
} from "./types.ts";

export * from "./types.ts";

export type ModeledValue =
  | { kind: "scalar"; value: JsonScalar }
  | { kind: "object_ref"; objectId: string; generation: number; offset: number; length: number };
export interface ModeledObject {
  kind: ValueKind;
  objectId: string;
  instanceGeneration: number;
  generation: number;
  value?: JsonScalar;
  capacity?: number;
  actualLength?: number;
  bytes?: number[];
  fields?: Record<string, ModeledValue>;
  activeMember?: string;
}
export interface ObjectAccess {
  ordinal: number;
  callSeq: number;
  position: number;
  parameterPath: string;
  objectId: string;
  generation: number;
  start: number;
  end: number;
  kind: ValueKind;
  direction: "read" | "write";
}
export interface SequenceAction {
  instanceGeneration: number;
  callSeq: number;
  position: number;
  ordinal: number;
  arguments: Record<string, { input?: ModeledValue; output?: ModeledValue }>;
  reads: ObjectAccess[];
  writes: ObjectAccess[];
}
export interface DataflowCandidate {
  instanceGeneration: number;
  producer: { position: number; ordinal: number; callSeq: number; parameterPath: string };
  consumer: { position: number; ordinal: number; callSeq: number; parameterPath: string };
  objectId: string;
  generationFrom: number;
  generationTo: number;
  overlap: { start: number; end: number };
  confidence: "high" | "medium";
  evidence: string[];
}
export interface SequenceDiagnostic {
  code: string;
  message: string;
  ordinal?: number;
  callSeq?: number;
  instanceGeneration?: number;
}
export interface ActionStream {
  instanceGeneration: number;
  actions: SequenceAction[];
  objects: ModeledObject[];
  dataflowCandidates: DataflowCandidate[];
  records: CapturedRecord[];
}
export interface SizeQueryObservation {
  ordinal: number;
  bufferParameter: string;
  lengthParameter: string;
  queryCallSeqsByInstance: Record<number, number[]>;
  positiveCapacitiesByInstance: Record<number, number[]>;
  sameInstanceFillByInstance: Record<number, boolean>;
  stabilityEvidence?: string;
  pure: boolean;
  idempotent: boolean;
  fallbackReason?: "stability-unproven" | "query-not-pure-idempotent" | "unstable-contract";
}
export interface ActionSequence {
  schema: typeof ABI_SCHEMA_NAME;
  streams: ActionStream[];
  sizeQueries: SizeQueryObservation[];
  blockers: SequenceDiagnostic[];
}
export interface CapacityLadderDecision {
  ordinal: number;
  strategy: "capacity-ladder";
  bufferParameter: string;
  skippedQueryCallSeqs: number[];
  initialCapacity: number;
  maximumCapacity: number | null;
  growthFactor: 2;
  freshInstancePerAttempt: true;
  queryResultReusable: false;
  reason: "stability-unproven" | "query-not-pure-idempotent" | "unstable-contract";
}
export interface QueryReplayDecision {
  ordinal: number;
  strategy: "query-then-replay";
  bufferParameter: string;
  lengthParameter: string;
  queryCallSeqs: number[];
  stabilityEvidence: string;
  queryAndReplayShareInstance: true;
}
export interface ReplayRun {
  runIndex: number;
  instanceId: string;
  sourceInstanceGeneration: number;
  actions: SequenceAction[];
  objects: ModeledObject[];
}
export interface ReplayPlan {
  eligible: boolean;
  instancePolicy: "fresh-per-run";
  runs: ReplayRun[];
  sizeQueries: Array<QueryReplayDecision | CapacityLadderDecision>;
  blockers: SequenceDiagnostic[];
}
export interface ReplayPlanOptions {
  repetitions?: number;
  sourceInstanceGeneration?: number;
  maximumCapacityByOrdinal?: Readonly<Record<number, number>>;
}
export type AppendResult =
  | { ok: true; sequence: ActionSequence }
  | { ok: false; code: string; ordinals: number[] };

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isInteger = (v: unknown): v is number => Number.isSafeInteger(v);
const isScalar = (v: unknown): v is JsonScalar =>
  v === null || typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v));
const has = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

function requireTypeNode(value: unknown, path: string, depth = 0): asserts value is AbiTypeNode {
  if (!isRecord(value) || depth > 32 || typeof value.kind !== "string") throw new TypeError(`malformed ABI type at ${path}`);
  if (["bounds", "members", "element", "dimensions", "type_ref"].some((key) => has(value, key))) throw new TypeError(`unsupported ABI type shape at ${path}`);
  if (value.kind === "pointer") {
    if (!has(value, "to")) throw new TypeError(`pointer at ${path} is missing to`);
    requireTypeNode(value.to, `${path}.to`, depth + 1);
    return;
  }
  if (!["builtin", "named", "struct", "union", "enum"].includes(value.kind) || typeof value.name !== "string" || value.name.length === 0) {
    throw new TypeError(`unsupported ABI type kind at ${path}`);
  }
  if (value.kind === "named" && value.resolved !== undefined && typeof value.resolved !== "boolean") throw new TypeError(`invalid named type resolution at ${path}`);
}
function requireBound(value: unknown, path: string): void {
  if (value === null) return;
  if (!isRecord(value)) throw new TypeError(`invalid bound expression at ${path}`);
  if (value.kind === "integer" && isInteger(value.value) && value.value >= 0) return;
  if (value.kind === "identifier" && typeof value.name === "string" && value.name.length > 0) return;
  throw new TypeError(`invalid bound expression at ${path}`);
}
function requireAttributes(value: unknown, path: string): asserts value is AbiAttributeSet | null {
  if (value === null) return;
  if (!isRecord(value) || !has(value, "size") || !has(value, "count")) throw new TypeError(`invalid edger8r attributes at ${path}`);
  requireBound(value.size, `${path}.size`);
  requireBound(value.count, `${path}.count`);
  for (const flag of ["string", "wstring", "user_check", "isptr", "isary", "readonly"]) {
    if (typeof value[flag] !== "boolean") throw new TypeError(`invalid edger8r attribute ${path}.${flag}`);
  }
}
function requireField(value: unknown, path: string, parameter = false): asserts value is AbiField | AbiParameter {
  if (!isRecord(value) || typeof value.name !== "string" || value.name.length === 0 || !has(value, "type")) throw new TypeError(`malformed ABI field at ${path}`);
  if (["bounds", "members", "type_ref"].some((key) => has(value, key))) throw new TypeError(`unsupported legacy ABI field shape at ${path}`);
  requireTypeNode(value.type, `${path}.type`);
  if (!isInteger(value.pointer_depth) || value.pointer_depth < 0 || !Array.isArray(value.array_dimensions) ||
      value.array_dimensions.some((n) => !isInteger(n) || n < 0)) throw new TypeError(`invalid pointer or array shape at ${path}`);
  if (pointerDepth(value.type) !== value.pointer_depth) throw new TypeError(`pointer_depth disagrees with recursive type at ${path}`);
  if (parameter || has(value, "form")) {
    if (!["value", "pointer"].includes(String(value.form))) throw new TypeError(`invalid form at ${path}`);
    const needsPointerForm = value.pointer_depth > 0 || value.array_dimensions.length > 0;
    if ((value.form === "pointer") !== needsPointerForm) throw new TypeError(`form disagrees with pointer/array shape at ${path}`);
  }
  if (parameter || has(value, "direction")) {
    if (!["value", "in", "out", "inout", "unspecified"].includes(String(value.direction))) throw new TypeError(`invalid direction at ${path}`);
  }
  if (parameter && !has(value, "attributes")) throw new TypeError(`missing attributes at ${path}`);
  if (has(value, "attributes")) requireAttributes(value.attributes, `${path}.attributes`);
}
function pointerDepth(type: AbiTypeNode): number {
  return type.kind === "pointer" ? 1 + pointerDepth(type.to!) : 0;
}
function requireSchema(schema: Edger8rAbiSchema): void {
  if (!isRecord(schema) || schema.schema !== ABI_SCHEMA_NAME) throw new TypeError(`expected ${ABI_SCHEMA_NAME}`);
  if (!isRecord(schema.tool) || !isRecord(schema.input) || !Array.isArray(schema.types) || !Array.isArray(schema.ecalls) || !Array.isArray(schema.ocalls)) {
    throw new TypeError("ABI schema requires tool, input, types, ecalls, and ocalls");
  }
  const definitions = new Map<string, AbiTypeDefinition>();
  for (const [i, raw] of schema.types.entries()) {
    if (!isRecord(raw) || !["struct", "union", "enum", "named"].includes(String(raw.kind)) || typeof raw.name !== "string" || !raw.name) throw new TypeError(`malformed ABI type definition ${i}`);
    const def = raw as unknown as AbiTypeDefinition;
    if (definitions.has(def.name)) throw new TypeError(`duplicate ABI type definition ${def.name}`);
    definitions.set(def.name, def);
    if (def.kind === "struct" || def.kind === "union") {
      if (!Array.isArray(raw.fields)) throw new TypeError(`record ${def.name} is missing fields`);
      for (const [j, field] of raw.fields.entries()) requireField(field, `types[${i}].fields[${j}]`);
    } else if (def.kind === "enum") {
      if (!Array.isArray(raw.values)) throw new TypeError(`enum ${def.name} is missing values`);
      for (const item of raw.values) {
        if (!isRecord(item) || typeof item.name !== "string" || !(item.value === null || (isRecord(item.value) && ((item.value.kind === "integer" && isInteger(item.value.value)) || (item.value.kind === "identifier" && typeof item.value.name === "string"))))) {
          throw new TypeError(`malformed enum value in ${def.name}`);
        }
      }
    } else if (typeof raw.resolved !== "boolean") throw new TypeError(`named definition ${def.name} must state resolved`);
  }
  const ordinals = new Set<number>();
  for (const [i, raw] of schema.ecalls.entries()) {
    if (!isRecord(raw) || !isInteger(raw.ordinal) || raw.ordinal < 0 || typeof raw.name !== "string" ||
        typeof raw.visibility !== "string" || typeof raw.switchless !== "boolean" || !Array.isArray(raw.parameters)) {
      throw new TypeError(`malformed ECALL declaration ${i}`);
    }
    requireTypeNode(raw.return_type, `ecalls[${i}].return_type`);
    if (ordinals.has(raw.ordinal)) throw new TypeError(`duplicate ECALL ordinal ${raw.ordinal}`);
    ordinals.add(raw.ordinal);
    const names = new Set<string>();
    for (const [j, parameter] of raw.parameters.entries()) {
      requireField(parameter, `ecalls[${i}].parameters[${j}]`, true);
      if (names.has(parameter.name)) throw new TypeError(`duplicate parameter ${parameter.name} in ECALL ordinal ${raw.ordinal}`);
      names.add(parameter.name);
    }
  }
  const verifyRef = (type: AbiTypeNode, path: string, seen = new Set<string>()): void => {
    if (type.kind === "pointer") return verifyRef(type.to!, path, seen);
    if (type.kind === "builtin") return;
    if (seen.has(type.name!)) return;
    const def = definitions.get(type.name!);
    if (!def) throw new TypeError(`unresolved ABI type reference ${type.name} at ${path}`);
    if (type.kind !== "named" && type.kind !== def.kind) throw new TypeError(`ABI type reference kind mismatch for ${type.name} at ${path}`);
    const next = new Set(seen); next.add(type.name!);
    if (def.kind === "struct" || def.kind === "union") for (const field of def.fields!) verifyRef(field.type, `${path}.${field.name}`, next);
  };
  for (const [i, def] of schema.types.entries()) {
    if (def.kind === "struct" || def.kind === "union") for (const field of def.fields!) verifyRef(field.type, `types[${i}].${field.name}`);
  }
  for (const [i, ecall] of schema.ecalls.entries()) {
    verifyRef(ecall.return_type, `ecalls[${i}].return_type`);
    for (const param of ecall.parameters) verifyRef(param.type, `ecalls[${i}].${param.name}`);
  }
}

function definitionOf(type: AbiTypeNode, schema: Edger8rAbiSchema): AbiTypeDefinition | undefined {
  if (type.kind === "pointer") return definitionOf(type.to!, schema);
  if (type.kind === "struct" || type.kind === "union" || type.kind === "enum" || type.kind === "named") {
    return schema.types.find((def) => def.name === type.name);
  }
  return undefined;
}
function baseKind(type: AbiTypeNode, schema: Edger8rAbiSchema, seen = new Set<string>()): ValueKind | "unknown" {
  if (type.kind === "pointer") return baseKind(type.to!, schema, seen);
  if (type.kind === "builtin") return type.name === "void" ? "opaque" : "scalar";
  if (seen.has(type.name!)) return "unknown";
  const def = definitionOf(type, schema);
  if (!def) return "unknown";
  if (def.kind === "named") return def.resolved ? "unknown" : "opaque";
  if (def.kind === "struct" || def.kind === "union") return "record";
  if (def.kind === "enum") return "scalar";
  return "unknown";
}
function fieldKind(field: AbiField, schema: Edger8rAbiSchema): ValueKind | "unknown" {
  const base = baseKind(field.type, schema);
  if (base === "unknown" || base === "opaque") return base;
  if (base === "record") return "record";
  if (field.array_dimensions.length > 0) return "buffer";
  if (field.pointer_depth > 0) {
    if (base === "scalar" && (field.attributes?.size || field.attributes?.count || field.attributes?.string || field.attributes?.wstring || field.attributes?.isary)) return "buffer";
    return "scalar";
  }
  return base;
}
function fixedExtent(dimensions: readonly number[]): boolean {
  return dimensions.length > 0 && dimensions.every((n) => isInteger(n) && n > 0);
}
function validBound(value: BoundExpression | null | undefined): boolean {
  return value !== null && value !== undefined;
}
function hasUsableBound(field: AbiField): boolean {
  return fixedExtent(field.array_dimensions) || (field.attributes !== undefined && field.attributes !== null &&
    (validBound(field.attributes.size) || validBound(field.attributes.count)));
}
function recordDefinition(type: AbiTypeNode, schema: Edger8rAbiSchema): AbiTypeDefinition | undefined {
  const def = definitionOf(type, schema);
  return def && (def.kind === "struct" || def.kind === "union") ? def : undefined;
}
function classifyField(field: AbiField, schema: Edger8rAbiSchema, blockers: SequenceDiagnostic[], ordinal?: number): ValueKind | undefined {
  if (field.pointer_depth > 1) blockers.push({ code: "multi_level_pointer", message: `parameter/member ${field.name} has pointer depth ${field.pointer_depth}`, ordinal });
  const pointerLike = field.pointer_depth > 0;
  if (pointerLike && field.attributes === undefined) blockers.push({ code: "unknown_attributes", message: `parameter/member ${field.name} is missing edger8r attributes`, ordinal });
  else if (pointerLike && field.attributes === null) blockers.push({ code: "unknown_user_check", message: `parameter/member ${field.name} has unknown user_check status`, ordinal });
  else if (pointerLike && field.attributes?.user_check === true) blockers.push({ code: "user_check", message: `parameter/member ${field.name} uses user_check`, ordinal });
  const kind = fieldKind(field, schema);
  if (kind === "unknown") {
    blockers.push({ code: "unknown_type", message: `parameter/member ${field.name} has unresolved ABI type`, ordinal });
    return undefined;
  }
  if (kind === "record" && !recordDefinition(field.type, schema)) {
    blockers.push({ code: "unknown_record_definition", message: `parameter/member ${field.name} has no record definition`, ordinal });
    return undefined;
  }
  if ((kind === "buffer" || kind === "opaque") && (pointerLike || field.array_dimensions.length > 0) && !hasUsableBound(field)) {
    blockers.push({ code: "unknown_buffer_bounds", message: `parameter/member ${field.name} has no usable size/count/array extent`, ordinal });
  }
  return kind;
}

const objectKey = (instance: number, id: string, generation: number): string => `${instance}\u0000${id}\u0000${generation}`;
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
function normalizeObject(instance: number, objectId: string, raw: CapturedObjectSnapshot): ModeledObject {
  if (!isRecord(raw) || !["scalar", "buffer", "record", "opaque"].includes(String(raw.kind)) || !isInteger(raw.generation) || raw.generation < 0) {
    throw new TypeError(`malformed object snapshot ${objectId}`);
  }
  const object: ModeledObject = { kind: raw.kind, objectId, instanceGeneration: instance, generation: raw.generation };
  if (raw.kind === "scalar") {
    if (!isScalar(raw.value)) throw new TypeError(`scalar snapshot ${objectId} has invalid value`);
    object.value = raw.value;
  } else if (raw.kind === "buffer" || raw.kind === "opaque") {
    if (!isInteger(raw.capacity) || raw.capacity < 0 || !isInteger(raw.actual_length) || raw.actual_length < 0 || raw.actual_length > raw.capacity || !Array.isArray(raw.bytes)) {
      throw new TypeError(`byte object ${objectId} has invalid capacity or actual length`);
    }
    if (raw.bytes.length !== raw.actual_length || raw.bytes.some((b) => !isInteger(b) || b < 0 || b > 255)) throw new TypeError(`byte object ${objectId} does not match actual length`);
    object.capacity = raw.capacity; object.actualLength = raw.actual_length; object.bytes = [...raw.bytes];
  } else {
    if (!isRecord(raw.fields)) throw new TypeError(`record object ${objectId} has invalid fields`);
    object.fields = {};
    if (raw.active_member !== undefined) object.activeMember = raw.active_member;
  }
  return object;
}
function isObjectRef(value: CapturedValue | undefined): value is CapturedObjectRef {
  return isRecord(value) && value.kind === "object_ref" && typeof value.object_id === "string";
}
interface RawObjectEntry { raw: CapturedObjectSnapshot; observedAt: number; instance: number; objectId: string }
interface BuildContext {
  schema: Edger8rAbiSchema;
  blockers: SequenceDiagnostic[];
  rawObjects: Map<string, RawObjectEntry>;
  models: Map<string, ModeledObject>;
  identities: Map<string, string>;
  building: Set<string>;
}
function findObject(context: BuildContext, instance: number, objectId: string, generation: number | undefined, callSeq: number): { key: string; entry: RawObjectEntry } | undefined {
  const entries = [...context.rawObjects.entries()].filter(([, item]) => item.instance === instance && item.objectId === objectId &&
    item.observedAt <= callSeq && (generation === undefined || item.raw.generation === generation));
  entries.sort((a, b) => b[1].raw.generation - a[1].raw.generation || b[1].observedAt - a[1].observedAt);
  return entries[0] ? { key: entries[0][0], entry: entries[0][1] } : undefined;
}
function mapValue(rawValue: CapturedValue | undefined, expected: ValueKind | undefined, type: AbiTypeNode, instance: number, callSeq: number, context: BuildContext, path: string, level = 0): ModeledValue {
  if (level > 20) {
    context.blockers.push({ code: "record_depth_limit", message: `ABI value ${path} exceeds supported record depth`, callSeq, instanceGeneration: instance });
    return { kind: "scalar", value: null };
  }
  if (!isObjectRef(rawValue)) {
    const value = isRecord(rawValue) && rawValue.kind === "scalar" ? rawValue.value : rawValue;
    if (expected !== "scalar" || !isScalar(value)) {
      context.blockers.push({ code: "capture_type_mismatch", message: `capture ${path} does not match its ABI type`, callSeq, instanceGeneration: instance });
      return { kind: "scalar", value: null };
    }
    return { kind: "scalar", value };
  }
  if (!expected || expected === "scalar") {
    context.blockers.push({ code: "capture_type_mismatch", message: `capture ${path} unexpectedly references an object`, callSeq, instanceGeneration: instance });
    return { kind: "scalar", value: null };
  }
  const found = findObject(context, instance, rawValue.object_id, rawValue.generation, callSeq);
  if (!found) {
    context.blockers.push({ code: "missing_object_generation", message: `capture ${path} references unavailable object generation`, callSeq, instanceGeneration: instance });
    return { kind: "scalar", value: null };
  }
  if (found.entry.raw.kind !== expected) {
    context.blockers.push({ code: "capture_type_mismatch", message: `object ${rawValue.object_id} kind does not match ABI type for ${path}`, callSeq, instanceGeneration: instance });
    return { kind: "scalar", value: null };
  }
  const object = materializeObject(found.key, found.entry, type, context, level + 1);
  const capacity = object.capacity ?? 1;
  const offset = rawValue.offset ?? 0;
  const length = rawValue.length ?? Math.max(0, capacity - offset);
  if (!isInteger(offset) || offset < 0 || !isInteger(length) || length < 0 || offset + length > capacity ||
      ((object.kind === "scalar" || object.kind === "record") && (offset !== 0 || length !== 1))) {
    context.blockers.push({ code: "invalid_object_view", message: `capture ${path} has a view outside capacity`, callSeq, instanceGeneration: instance });
    return { kind: "scalar", value: null };
  }
  return { kind: "object_ref", objectId: object.objectId, generation: object.generation, offset, length };
}
function materializeObject(key: string, entry: RawObjectEntry, type: AbiTypeNode, context: BuildContext, level: number): ModeledObject {
  const kind = entry.raw.kind;
  const identity = `${kind}:${type.kind}:${type.name ?? ""}`;
  const prior = context.identities.get(key);
  if (prior && prior !== identity) context.blockers.push({ code: "object_type_conflict", message: `object ${entry.objectId} has conflicting ABI type identities`, instanceGeneration: entry.instance });
  context.identities.set(key, identity);
  const cached = context.models.get(key);
  if (cached) return cached;
  if (context.building.has(key)) {
    context.blockers.push({ code: "recursive_object_graph", message: `object ${entry.objectId} contains a recursive graph`, instanceGeneration: entry.instance });
    return { kind: "record", objectId: entry.objectId, instanceGeneration: entry.instance, generation: entry.raw.generation, fields: {} };
  }
  const object = normalizeObject(entry.instance, entry.objectId, entry.raw);
  context.models.set(key, object);
  if (object.kind !== "record") return object;
  context.building.add(key);
  const definition = recordDefinition(type, context.schema);
  const fields = definition?.fields ?? [];
  const rawFields = entry.raw.fields ?? {};
  const union = definition?.kind === "union";
  const active = entry.raw.active_member;
  if (union && (!active || !fields.some((field) => field.name === active))) {
    context.blockers.push({ code: "unknown_union_variant", message: `union object ${entry.objectId} has no active field`, instanceGeneration: entry.instance });
  }
  const selected = union && active ? fields.filter((field) => field.name === active) : fields;
  const names = new Set(selected.map((field) => field.name));
  for (const name of Object.keys(rawFields)) if (!names.has(name)) context.blockers.push({ code: "unknown_record_field", message: `record object ${entry.objectId} has unknown field ${name}`, instanceGeneration: entry.instance });
  const modeled: Record<string, ModeledValue> = {};
  for (const field of selected) {
    if (!has(rawFields, field.name)) {
      context.blockers.push({ code: "missing_record_field", message: `record object ${entry.objectId} is missing field ${field.name}`, instanceGeneration: entry.instance });
      continue;
    }
    const valueKind = classifyField(field, context.schema, context.blockers);
    modeled[field.name] = mapValue(rawFields[field.name], valueKind, field.type, entry.instance, entry.observedAt, context, `${entry.objectId}.${field.name}`, level + 1);
  }
  object.fields = modeled;
  object.activeMember = active;
  context.building.delete(key);
  return object;
}
function addAccess(value: ModeledValue, action: SequenceAction, path: string, direction: "read" | "write", objects: Map<string, ModeledObject>, destination: ObjectAccess[], visited = new Set<string>()): void {
  if (value.kind !== "object_ref") return;
  const key = objectKey(action.instanceGeneration, value.objectId, value.generation);
  const object = objects.get(key);
  if (!object) return;
  const byteObject = object.kind === "buffer" || object.kind === "opaque";
  const effectiveLength = byteObject ? Math.min(value.length, Math.max(0, (object.actualLength ?? 0) - value.offset)) : value.length;
  destination.push({ ordinal: action.ordinal, callSeq: action.callSeq, position: action.position, parameterPath: path, objectId: value.objectId, generation: value.generation,
    start: value.offset, end: value.offset + effectiveLength, kind: object.kind, direction });
  if (object.kind !== "record" || !object.fields || visited.has(key)) return;
  const next = new Set(visited); next.add(key);
  for (const [name, field] of Object.entries(object.fields)) addAccess(field, action, `${path}.${name}`, direction, objects, destination, next);
}
function findDataflow(actions: readonly SequenceAction[]): DataflowCandidate[] {
  const results: DataflowCandidate[] = [];
  for (const consumer of actions) for (const read of consumer.reads) {
    if (read.start === read.end) continue;
    for (const producer of actions) {
      if (producer.position >= consumer.position || producer.instanceGeneration !== consumer.instanceGeneration) continue;
      for (const write of producer.writes) {
        if (write.objectId !== read.objectId || write.generation > read.generation || write.start === write.end) continue;
        const start = Math.max(write.start, read.start), end = Math.min(write.end, read.end);
        if (start >= end) continue;
        const sameRange = write.start === read.start && write.end === read.end;
        const sameGeneration = write.generation === read.generation;
        const evidence = ["same-object-identity", "overlapping-slices", "producer-before-consumer", sameGeneration ? "same-generation" : "generation-advanced"];
        if (write.kind === "opaque" || read.kind === "opaque") evidence.push("opaque-identity-only");
        results.push({
          instanceGeneration: consumer.instanceGeneration,
          producer: { position: producer.position, ordinal: producer.ordinal, callSeq: producer.callSeq, parameterPath: write.parameterPath },
          consumer: { position: consumer.position, ordinal: consumer.ordinal, callSeq: consumer.callSeq, parameterPath: read.parameterPath },
          objectId: read.objectId, generationFrom: write.generation, generationTo: read.generation, overlap: { start, end },
          confidence: sameRange && sameGeneration ? "high" : "medium", evidence,
        });
      }
    }
  }
  return results;
}

function asObjectRef(value: CapturedValue | undefined): CapturedObjectRef | undefined {
  return isObjectRef(value) ? value : undefined;
}
function capacityOf(value: CapturedValue | undefined, record: CapturedRecord): number | undefined {
  const ref = asObjectRef(value);
  if (!ref) return undefined;
  const object = record.objects[ref.object_id];
  if (!object || (object.kind !== "buffer" && object.kind !== "opaque") || (ref.generation !== undefined && ref.generation !== object.generation)) return undefined;
  return object.capacity;
}
function scalarOf(value: CapturedValue | undefined, record: CapturedRecord): JsonScalar | undefined {
  if (value === undefined) return undefined;
  if (isScalar(value)) return value;
  if (isRecord(value) && value.kind === "scalar" && isScalar(value.value)) return value.value;
  const ref = asObjectRef(value);
  if (!ref) return undefined;
  const object = record.objects[ref.object_id];
  return object?.kind === "scalar" && (ref.generation === undefined || ref.generation === object.generation) && isScalar(object.value) ? object.value : undefined;
}
function queryFingerprint(record: CapturedRecord, bufferParameter: string, lengthParameter: string): string {
  const inputs: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(record.arguments)) {
    if (name === bufferParameter || name === lengthParameter) continue;
    const ref = asObjectRef(value);
    if (!ref) inputs[name] = value;
    else {
      const object = record.objects[ref.object_id];
      if (!object) inputs[name] = "missing-object";
      else {
        const { generation: _generation, ...content } = object;
        inputs[name] = content;
      }
    }
  }
  return stableJson(inputs);
}
function externalStability(contract: ReplayContract | undefined): string | undefined {
  const stability = contract?.sizeQuery?.stability;
  if ((stability?.kind === "abi-contract" || stability?.kind === "external-contract") && stability.evidenceId.trim()) {
    return `${stability.kind}:${stability.evidenceId}`;
  }
  return undefined;
}
function detectSizeQueries(streams: readonly ActionStream[], ecalls: Map<number, AbiEcall>, schema: Edger8rAbiSchema, contracts: ReplayContracts): SizeQueryObservation[] {
  const observations: SizeQueryObservation[] = [];
  for (const [ordinal, ecall] of ecalls) {
    const contract = contracts[ordinal];
    const configured = contract?.sizeQuery;
    const candidates = configured
      ? ecall.parameters.filter((param) => param.name === configured.bufferParameter)
      : ecall.parameters.filter((param) => ["buffer", "opaque"].includes(fieldKind(param, schema)));
    for (const bufferField of candidates) {
      const queryRecords: Record<number, CapturedRecord[]> = {};
      const positives: Record<number, number[]> = {};
      const sameFill: Record<number, boolean> = {};
      for (const stream of streams) {
        const records = stream.records.filter((record) => record.ordinal === ordinal);
        const zeroes = records.filter((record) => capacityOf(record.arguments[bufferField.name], record) === 0);
        const capacities = records.map((record) => capacityOf(record.arguments[bufferField.name], record)).filter((n): n is number => n !== undefined && n > 0);
        const gen = stream.instanceGeneration;
        if (zeroes.length) queryRecords[gen] = zeroes;
        if (capacities.length) positives[gen] = capacities;
        sameFill[gen] = zeroes.length > 0 && capacities.length > 0;
      }
      if (!Object.keys(queryRecords).length || !Object.keys(positives).length) continue;
      const lengthParameter = configured?.lengthParameter ?? "";
      const lengthExists = lengthParameter.length > 0 && ecall.parameters.some((param) => param.name === lengthParameter);
      let evidence = configured && lengthExists ? externalStability(contract) : undefined;
      const stability = configured ? contract?.sizeQuery?.stability : undefined;
      if (!evidence && configured && lengthExists && stability?.kind === "fresh-instance-differential" &&
          isInteger(stability.minimumInstances) && stability.minimumInstances >= 2) {
        const samples = Object.values(queryRecords).map((items) => items[0]);
        if (samples.length >= stability.minimumInstances) {
          const fingerprints = new Set(samples.map((record) => queryFingerprint(record, bufferField.name, lengthParameter)));
          const lengths = samples.map((record) => scalarOf(record.outputs[lengthParameter], record));
          if (fingerprints.size === 1 && lengths.every((n) => n !== undefined) && new Set(lengths).size === 1) evidence = `fresh-instance-differential:${samples.length}`;
        }
      }
      let fallbackReason: SizeQueryObservation["fallbackReason"];
      if (!configured || !lengthExists || !Object.values(sameFill).some(Boolean) || !evidence) fallbackReason = "stability-unproven";
      else if (stability && stability.kind !== "fresh-instance-differential" && !externalStability(contract)) fallbackReason = "unstable-contract";
      else if (contract?.pure !== true || contract.idempotent !== true) fallbackReason = "query-not-pure-idempotent";
      observations.push({
        ordinal, bufferParameter: bufferField.name, lengthParameter,
        queryCallSeqsByInstance: Object.fromEntries(Object.entries(queryRecords).map(([gen, rs]) => [gen, rs.map((r) => r.call_seq)])),
        positiveCapacitiesByInstance: positives, sameInstanceFillByInstance: sameFill, stabilityEvidence: evidence,
        pure: contract?.pure === true, idempotent: contract?.idempotent === true, fallbackReason,
      });
    }
  }
  return observations;
}
function uniqueDiagnostics(values: readonly SequenceDiagnostic[]): SequenceDiagnostic[] {
  const seen = new Set<string>();
  return values.filter((item) => {
    const key = `${item.code}:${item.ordinal ?? ""}:${item.callSeq ?? ""}:${item.instanceGeneration ?? ""}:${item.message}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}

export function buildActionSequence(schema: Edger8rAbiSchema, records: readonly CapturedRecord[], contracts: ReplayContracts = {}): ActionSequence {
  requireSchema(schema);
  for (const [ordinalText, contract] of Object.entries(contracts)) {
    const ordinal = Number(ordinalText);
    const declaration = schema.ecalls.find((ecall) => ecall.ordinal === ordinal);
    if (!declaration) throw new TypeError(`contract references unknown ECALL ordinal ${ordinalText}`);
    if (contract.sizeQuery) {
      const buffer = declaration.parameters.find((parameter) => parameter.name === contract.sizeQuery!.bufferParameter);
      if (!buffer || !["buffer", "opaque"].includes(fieldKind(buffer, schema))) throw new TypeError(`invalid size-query buffer parameter for ECALL ${ordinal}`);
      if (!declaration.parameters.some((parameter) => parameter.name === contract.sizeQuery!.lengthParameter)) throw new TypeError(`invalid size-query length parameter for ECALL ${ordinal}`);
    }
  }
  const blockers: SequenceDiagnostic[] = [];
  const ecalls = new Map(schema.ecalls.map((e) => [e.ordinal, e]));
  const grouped = new Map<number, CapturedRecord[]>();
  for (const record of records) {
    if (!isRecord(record) || !isInteger(record.instance_generation) || record.instance_generation < 0 || !isInteger(record.call_seq) ||
        record.call_seq < 0 || !isInteger(record.ordinal) || !isRecord(record.arguments) || !isRecord(record.outputs) || !isRecord(record.objects)) {
      throw new TypeError("malformed captured record");
    }
    if (!ecalls.has(record.ordinal)) throw new TypeError(`capture references unknown ECALL ordinal ${record.ordinal}`);
    const list = grouped.get(record.instance_generation) ?? [];
    list.push(record); grouped.set(record.instance_generation, list);
  }
  const streams: ActionStream[] = [];
  for (const [instanceGeneration, unsorted] of grouped) {
    const instanceRecords = [...unsorted].sort((a, b) => a.call_seq - b.call_seq);
    for (let i = 1; i < instanceRecords.length; i++) if (instanceRecords[i - 1].call_seq === instanceRecords[i].call_seq) throw new TypeError(`duplicate call_seq in instance ${instanceGeneration}`);
    const rawObjects = new Map<string, RawObjectEntry>();
    const latest = new Map<string, number>();
    for (const record of instanceRecords) for (const [objectId, raw] of Object.entries(record.objects)) {
      normalizeObject(instanceGeneration, objectId, raw);
      const key = objectKey(instanceGeneration, objectId, raw.generation);
      const prior = rawObjects.get(key);
      if (prior && stableJson(prior.raw) !== stableJson(raw)) blockers.push({ code: "generation_state_conflict", message: `object ${objectId} generation ${raw.generation} has conflicting snapshots`, callSeq: record.call_seq, instanceGeneration });
      else if (!prior) rawObjects.set(key, { raw, observedAt: record.call_seq, instance: instanceGeneration, objectId });
      const previous = latest.get(objectId);
      if (previous !== undefined && raw.generation < previous) blockers.push({ code: "generation_regressed", message: `object ${objectId} generation moved backwards`, callSeq: record.call_seq, instanceGeneration });
      latest.set(objectId, Math.max(previous ?? raw.generation, raw.generation));
    }
    const context: BuildContext = { schema, blockers, rawObjects, models: new Map(), identities: new Map(), building: new Set() };
    const actions: SequenceAction[] = [];
    for (const [position, record] of instanceRecords.entries()) {
      const ecall = ecalls.get(record.ordinal)!;
      const names = new Set(ecall.parameters.map((param) => param.name));
      for (const name of Object.keys(record.arguments)) if (!names.has(name)) throw new TypeError(`unknown argument ${name} in ECALL ordinal ${record.ordinal}`);
      for (const name of Object.keys(record.outputs)) if (!names.has(name)) throw new TypeError(`unknown output ${name} in ECALL ordinal ${record.ordinal}`);
      const action: SequenceAction = { instanceGeneration, callSeq: record.call_seq, position, ordinal: record.ordinal, arguments: {}, reads: [], writes: [] };
      for (const parameter of ecall.parameters) {
        if (!has(record.arguments, parameter.name)) throw new TypeError(`missing argument ${parameter.name} in ECALL ordinal ${record.ordinal}`);
        const kind = classifyField(parameter, schema, blockers, record.ordinal);
        const direction = parameter.direction;
        if (direction === "unspecified") blockers.push({ code: "unknown_direction", message: `ECALL ${record.ordinal} parameter ${parameter.name} has unspecified direction`, ordinal: record.ordinal, callSeq: record.call_seq, instanceGeneration });
        const values: { input?: ModeledValue; output?: ModeledValue } = {};
        if (direction === "value" || direction === "in" || direction === "inout" || direction === "unspecified") {
          values.input = mapValue(record.arguments[parameter.name], kind, parameter.type, instanceGeneration, record.call_seq, context, parameter.name);
        }
        if (direction === "out" || direction === "inout" || direction === "unspecified") {
          if (!has(record.outputs, parameter.name)) blockers.push({ code: "missing_output_capture", message: `ECALL ${record.ordinal} parameter ${parameter.name} has no captured output`, ordinal: record.ordinal, callSeq: record.call_seq, instanceGeneration });
          values.output = mapValue(record.outputs[parameter.name] ?? record.arguments[parameter.name], kind, parameter.type, instanceGeneration, record.call_seq, context, `${parameter.name}.output`);
        }
        action.arguments[parameter.name] = values;
      }
      actions.push(action);
    }
    const objects = [...context.models.values()];
    const index = new Map(objects.map((object) => [objectKey(object.instanceGeneration, object.objectId, object.generation), object]));
    for (const action of actions) {
      const ecall = ecalls.get(action.ordinal)!;
      for (const parameter of ecall.parameters) {
        const values = action.arguments[parameter.name];
        const direction = parameter.direction;
        if ((direction === "value" || direction === "in" || direction === "inout" || direction === "unspecified") && values.input) addAccess(values.input, action, parameter.name, "read", index, action.reads);
        if ((direction === "out" || direction === "inout" || direction === "unspecified") && values.output) addAccess(values.output, action, `${parameter.name}.output`, "write", index, action.writes);
      }
    }
    streams.push({ instanceGeneration, actions, objects, dataflowCandidates: findDataflow(actions), records: instanceRecords });
  }
  const sizeQueries = detectSizeQueries(streams, ecalls, schema, contracts);
  for (const query of sizeQueries) if (query.fallbackReason) blockers.push({ code: "capacity_ladder_required", message: `ECALL ${query.ordinal} requires a bounded capacity ladder`, ordinal: query.ordinal });
  return { schema: ABI_SCHEMA_NAME, streams, sizeQueries, blockers: uniqueDiagnostics(blockers) };
}
function cloneValue<T>(value: T): T {
  if (Array.isArray(value)) return value.map((item) => cloneValue(item)) as T;
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneValue(child)])) as T;
  return value;
}
export function createReplayPlan(sequence: ActionSequence, options: ReplayPlanOptions = {}): ReplayPlan {
  const repetitions = options.repetitions ?? 1;
  if (!isInteger(repetitions) || repetitions < 1) throw new TypeError("repetitions must be a positive integer");
  const blockers = sequence.blockers.filter((item) => item.code !== "capacity_ladder_required");
  const requested = sequence.streams.find((stream) => stream.instanceGeneration === options.sourceInstanceGeneration);
  const querySource = sequence.sizeQueries.length ? sequence.streams.find((stream) =>
    sequence.sizeQueries.some((query) => query.sameInstanceFillByInstance[stream.instanceGeneration])) : undefined;
  const capacitySource = sequence.sizeQueries.length ? sequence.streams.find((stream) =>
    sequence.sizeQueries.some((query) => (query.positiveCapacitiesByInstance[stream.instanceGeneration]?.length ?? 0) > 0)) : undefined;
  const source = requested ?? (options.sourceInstanceGeneration === undefined ? querySource ?? capacitySource ?? sequence.streams[0] : undefined);
  if (!source) return { eligible: false, instancePolicy: "fresh-per-run", runs: [], sizeQueries: [], blockers: [...blockers, { code: "source_instance_missing", message: "requested source instance generation is not present" }] };
  const decisions: Array<QueryReplayDecision | CapacityLadderDecision> = [];
  for (const query of sequence.sizeQueries) {
    const callSeqs = query.queryCallSeqsByInstance[source.instanceGeneration] ?? [];
    if (query.sameInstanceFillByInstance[source.instanceGeneration] && query.stabilityEvidence && query.pure && query.idempotent && !query.fallbackReason) {
      decisions.push({ ordinal: query.ordinal, strategy: "query-then-replay", bufferParameter: query.bufferParameter, lengthParameter: query.lengthParameter,
        queryCallSeqs: callSeqs, stabilityEvidence: query.stabilityEvidence, queryAndReplayShareInstance: true });
      continue;
    }
    const capacities = query.positiveCapacitiesByInstance[source.instanceGeneration] ?? [];
    const initialCapacity = capacities.length ? Math.max(...capacities) : 1;
    const maximumCapacity = options.maximumCapacityByOrdinal?.[query.ordinal] ?? null;
    decisions.push({ ordinal: query.ordinal, strategy: "capacity-ladder", bufferParameter: query.bufferParameter, skippedQueryCallSeqs: callSeqs,
      initialCapacity, maximumCapacity, growthFactor: 2, freshInstancePerAttempt: true, queryResultReusable: false,
      reason: query.fallbackReason ?? "stability-unproven" });
    if (maximumCapacity === null) blockers.push({ code: "capacity_max_required", message: `ECALL ${query.ordinal} capacity ladder needs an explicit maximum`, ordinal: query.ordinal });
    else if (!isInteger(maximumCapacity) || maximumCapacity < initialCapacity) blockers.push({ code: "invalid_capacity_maximum", message: `ECALL ${query.ordinal} capacity maximum is invalid`, ordinal: query.ordinal });
  }
  if (blockers.length) return { eligible: false, instancePolicy: "fresh-per-run", runs: [], sizeQueries: decisions, blockers: uniqueDiagnostics(blockers) };
  const skipped = new Set<string>();
  for (const decision of decisions) if (decision.strategy === "capacity-ladder") {
    for (const callSeq of decision.skippedQueryCallSeqs) skipped.add(`${decision.ordinal}:${callSeq}`);
  }
  const actions = source.actions.filter((action) => !skipped.has(`${action.ordinal}:${action.callSeq}`));
  const needed = new Set<string>();
  const collectValue = (value: ModeledValue): void => {
    if (value.kind === "object_ref") needed.add(objectKey(source.instanceGeneration, value.objectId, value.generation));
  };
  for (const action of actions) for (const values of Object.values(action.arguments)) {
    if (values.input) collectValue(values.input);
    if (values.output) collectValue(values.output);
  }
  const objectIndex = new Map(source.objects.map((object) => [objectKey(object.instanceGeneration, object.objectId, object.generation), object]));
  const pending = [...needed];
  while (pending.length) {
    const key = pending.pop()!;
    const object = objectIndex.get(key);
    for (const field of Object.values(object?.fields ?? {})) if (field.kind === "object_ref") {
      const nestedKey = objectKey(source.instanceGeneration, field.objectId, field.generation);
      if (!needed.has(nestedKey)) { needed.add(nestedKey); pending.push(nestedKey); }
    }
  }
  const objects = source.objects.filter((object) => needed.has(objectKey(object.instanceGeneration, object.objectId, object.generation)));
  const runs = Array.from({ length: repetitions }, (_, runIndex): ReplayRun => ({
    runIndex, instanceId: `fresh-${runIndex}`, sourceInstanceGeneration: source.instanceGeneration,
    actions: cloneValue(actions), objects: cloneValue(objects),
  }));
  return { eligible: true, instancePolicy: "fresh-per-run", runs, sizeQueries: decisions, blockers: [] };
}
export function appendSequence(base: ActionSequence, appended: ActionSequence, contracts: ReplayContracts = {}): AppendResult {
  if (base.streams.length !== 1 || appended.streams.length !== 1) return { ok: false, code: "append_requires_single_instance_streams", ordinals: [] };
  const left = base.streams[0], right = appended.streams[0];
  if (left.instanceGeneration !== right.instanceGeneration) return { ok: false, code: "append_crosses_instance_generation", ordinals: [] };
  const counts = new Map<number, number>();
  for (const action of left.actions) counts.set(action.ordinal, (counts.get(action.ordinal) ?? 0) + 1);
  const missing = new Set<number>();
  for (const action of right.actions) {
    const count = counts.get(action.ordinal) ?? 0, contract = contracts[action.ordinal];
    if (count > 0 && (contract?.pure !== true || contract.idempotent !== true)) missing.add(action.ordinal);
    counts.set(action.ordinal, count + 1);
  }
  if (missing.size) return { ok: false, code: "same_eid_requires_pure_idempotent", ordinals: [...missing].sort((a, b) => a - b) };
  const objectMap = new Map<string, ModeledObject>();
  for (const object of [...left.objects, ...right.objects]) {
    const key = objectKey(object.instanceGeneration, object.objectId, object.generation), existing = objectMap.get(key);
    if (existing && stableJson(existing) !== stableJson(object)) return { ok: false, code: "object_generation_conflict", ordinals: [] };
    objectMap.set(key, cloneValue(object));
  }
  const actions = [...cloneValue(left.actions), ...cloneValue(right.actions)].map((action, position) => ({ ...action, position, reads: [], writes: [] }));
  const objects = [...objectMap.values()], index = new Map(objects.map((object) => [objectKey(object.instanceGeneration, object.objectId, object.generation), object]));
  for (const action of actions) for (const [name, values] of Object.entries(action.arguments)) {
    if (values.input) addAccess(values.input, action, name, "read", index, action.reads);
    if (values.output) addAccess(values.output, action, `${name}.output`, "write", index, action.writes);
  }
  const stream: ActionStream = { instanceGeneration: left.instanceGeneration, actions, objects, dataflowCandidates: findDataflow(actions), records: [...left.records, ...right.records] };
  const sizeQueries = [...base.sizeQueries, ...appended.sizeQueries].filter((q, i, all) => all.findIndex((candidate) => candidate.ordinal === q.ordinal) === i);
  return { ok: true, sequence: { schema: ABI_SCHEMA_NAME, streams: [stream], sizeQueries, blockers: uniqueDiagnostics([...base.blockers, ...appended.blockers]) } };
}

