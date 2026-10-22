import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

export const PROFILE_BUNDLE_SCHEMA = "atfield-profile-bundle-v1";
export const PAGE_SIZE = 4096;
const PAGE_BIG = BigInt(PAGE_SIZE);
const DIGEST_RE = /^(?:sha256:)?[0-9a-f]{64}$/i;
const EFFECT_ORDER = ["X", "R", "W"] as const;

export class ProfileBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProfileBundleError";
  }
}

export type JsonObject = Record<string, unknown>;
export type Effect = "X" | "R" | "W";

export interface PageUniverseEntry {
  rva: bigint;
  maxPermissions: Effect[];
  regionKind: string;
}

export interface Extent {
  kind: "function" | "object";
  start: bigint;
  end: bigint;
  exact: boolean;
}

export interface ProfileField {
  id: string;
  name: string;
  raw: JsonObject;
  staticPages: Array<{ rva: bigint; effects: Effect[] }>;
  resourcePages: Array<{ rva: bigint; effects: Effect[] }>;
  layoutExtents: Extent[];
}

export interface ProfileSelector {
  ordinal: number;
  name: string;
  visibility: string;
  switchless: boolean;
  entryRva: bigint;
  reachableFields: string[];
  reachability: unknown;
}

export interface ProfileBundle {
  root: string;
  manifestPath: string;
  manifestSha256: string;
  layoutEpoch: string;
  pageSize: number;
  capacityQ: number;
  ordinaryLoadEnd: bigint;
  pretouchStart: bigint;
  identity: {
    profileElfSha256: string;
    signedProfileElfSha256: string;
    edlAbiSha256: string;
    fieldsSha256: string;
  };
  marshalLayout: JsonObject;
  marshalLayoutSha256: string;
  collectorLayoutSpec: string;
  artifactDigests: Map<string, string>;
  artifactPaths: Map<string, string>;
  pageUniverse: Map<bigint, PageUniverseEntry>;
  fields: ProfileField[];
  fieldById: Map<string, ProfileField>;
  selectors: ProfileSelector[];
  selectorByOrdinal: Map<number, ProfileSelector>;
}

export function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new ProfileBundleError("canonical JSON does not allow non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (isObject(value)) {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key])).join(",") + "}";
  }
  throw new ProfileBundleError("canonical JSON contains an unsupported value");
}

export function normalizeDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new ProfileBundleError(label + " must be a SHA-256 hex digest");
  }
  return value.replace(/^sha256:/i, "").toLowerCase();
}

export function parseRva(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new ProfileBundleError(label + " must be a 0x-prefixed RVA string");
  }
  const result = BigInt(value);
  if (result < 0n || result >= (1n << 64n)) {
    throw new ProfileBundleError(label + " is outside uint64");
  }
  return result;
}

export function formatRva(value: bigint): string {
  return "0x" + value.toString(16);
}

export function canonicalEffects(effects: Iterable<string>): Effect[] {
  const set = new Set(effects);
  if ([...set].some((value) => value !== "X" && value !== "R" && value !== "W")) {
    throw new ProfileBundleError("page effects must contain only X, R, and W");
  }
  if (set.has("X") && set.has("W")) {
    throw new ProfileBundleError("a page cannot have X and W effects");
  }
  if (set.has("W") && !set.has("R")) {
    throw new ProfileBundleError("a W effect requires R|W");
  }
  return EFFECT_ORDER.filter((effect) => set.has(effect));
}

export function parsePermissions(value: unknown, label: string): Effect[] {
  let parts: string[];
  if (typeof value === "string") {
    const compact = value.toUpperCase().replace(/[|,+\s-]/g, "");
    if (!compact || /[^XRW]/.test(compact)) {
      throw new ProfileBundleError(label + " has invalid permission string");
    }
    parts = [...compact];
  } else if (Array.isArray(value)) {
    if (!value.every((part) => typeof part === "string")) {
      throw new ProfileBundleError(label + " permissions must be strings");
    }
    parts = value.map((part) => (part as string).toUpperCase());
  } else if (typeof value === "number" && Number.isSafeInteger(value)) {
    if (value < 0 || value > 7) {
      throw new ProfileBundleError(label + " permission mask must use R=1, W=2, X=4");
    }
    parts = [];
    if (value & 4) parts.push("X");
    if (value & 1) parts.push("R");
    if (value & 2) parts.push("W");
  } else {
    throw new ProfileBundleError(label + " requires max_permissions");
  }
  const effects = canonicalEffects(parts);
  if (effects.length === 0) throw new ProfileBundleError(label + " has no usable permissions");
  return effects;
}

function parseInteger(value: unknown, label: string): number {
  let result: number;
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    result = value;
  } else if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/.test(value)) {
    result = Number(value);
  } else {
    throw new ProfileBundleError(label + " must be a safe nonnegative integer");
  }
  if (!Number.isSafeInteger(result) || result < 0) {
    throw new ProfileBundleError(label + " must be a safe nonnegative integer");
  }
  return result;
}

export function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/* JSON.parse accepts duplicate keys. Bundle and trace digests must describe one unambiguous document. */
export function parseStrictJson(text: string, label: string): unknown {
  let at = 0;
  const fail = (message: string): never => {
    throw new ProfileBundleError(label + " is invalid JSON at byte " + at + ": " + message);
  };
  const whitespace = (): void => {
    while (at < text.length && /[\t\n\r ]/.test(text[at]!)) at++;
  };
  const stringValue = (): string => {
    const start = at;
    if (text[at] !== "\"") return fail("expected string");
    at++;
    while (at < text.length) {
      const ch = text[at++]!;
      if (ch === "\"") {
        try {
          return JSON.parse(text.slice(start, at)) as string;
        } catch {
          return fail("malformed string");
        }
      }
      if (ch === "\\") {
        if (at >= text.length) return fail("truncated escape");
        at++;
      }
    }
    return fail("unterminated string");
  };
  const value = (): unknown => {
    whitespace();
    const ch = text[at];
    if (ch === "\"") return stringValue();
    if (ch === "{") {
      at++;
      whitespace();
      const result: JsonObject = Object.create(null) as JsonObject;
      const keys = new Set<string>();
      if (text[at] === "}") {
        at++;
        return result;
      }
      for (;;) {
        whitespace();
        const key = stringValue();
        if (keys.has(key)) return fail("duplicate object key " + JSON.stringify(key));
        keys.add(key);
        whitespace();
        if (text[at++] !== ":") return fail("expected colon");
        result[key] = value();
        whitespace();
        if (text[at] === "}") {
          at++;
          return result;
        }
        if (text[at++] !== ",") return fail("expected comma or object end");
      }
    }
    if (ch === "[") {
      at++;
      whitespace();
      const result: unknown[] = [];
      if (text[at] === "]") {
        at++;
        return result;
      }
      for (;;) {
        result.push(value());
        whitespace();
        if (text[at] === "]") {
          at++;
          return result;
        }
        if (text[at++] !== ",") return fail("expected comma or array end");
      }
    }
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(literal, at)) {
        at += literal.length;
        return parsed;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at));
    if (number) {
      at += number[0].length;
      const parsed = Number(number[0]);
      if (!Number.isFinite(parsed)) return fail("number is not finite");
      return parsed;
    }
    return fail("expected a JSON value");
  };

  const parsed = value();
  whitespace();
  if (at !== text.length) fail("trailing data");
  return parsed;
}

function assertObject(value: unknown, label: string): JsonObject {
  if (!isObject(value)) throw new ProfileBundleError(label + " must be an object");
  return value;
}

function assertKeys(value: JsonObject, required: string[], allowed: string[], label: string): void {
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new ProfileBundleError(label + " is missing " + key);
  }
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unknown.length) throw new ProfileBundleError(label + " has unsupported key " + unknown[0]);
}

function validateIrFactsV2(raw: unknown, index: number): JsonObject {
  const label = "ir_facts.facts[" + index + "]";
  const fact = assertObject(raw, label);
  const required = [
    "schema", "translation_unit", "module_id", "backend_ir_sha256", "object_sha256",
    "compile_variant", "source", "callgraph_complete", "guidance_complete", "diagnostics",
    "definitions", "direct_calls", "unknown_indirect", "guidance_sites",
  ];
  assertKeys(fact, required, [...required, "module_data_uses", "module_data_uses_complete"], label);
  if (fact.schema !== IR_FACTS_SCHEMA) throw new ProfileBundleError(label + ".schema must be " + IR_FACTS_SCHEMA);
  requireString(fact.translation_unit, label + ".translation_unit");
  requireString(fact.module_id, label + ".module_id");
  const variant = assertObject(fact.compile_variant, label + ".compile_variant");
  const variantKeys = ["target_triple", "optimization_level", "relocation_model", "backend_flags"];
  assertKeys(variant, variantKeys, variantKeys, label + ".compile_variant");
  requireString(variant.target_triple, label + ".compile_variant.target_triple");
  if (!["0", "1", "2", "3"].includes(String(variant.optimization_level)) || variant.relocation_model !== "pic") {
    throw new ProfileBundleError(label + ".compile_variant has unsupported code generation settings");
  }
  if (!Array.isArray(variant.backend_flags) || !variant.backend_flags.every((item) => typeof item === "string")) {
    throw new ProfileBundleError(label + ".compile_variant.backend_flags must be a string array");
  }
  const source = assertObject(fact.source, label + ".source");
  assertKeys(source, ["input_file", "ir_filename"], ["input_file", "ir_filename"], label + ".source");
  requireString(source.input_file, label + ".source.input_file");
  requireString(source.ir_filename, label + ".source.ir_filename");
  if (typeof fact.callgraph_complete !== "boolean" || typeof fact.guidance_complete !== "boolean") {
    throw new ProfileBundleError(label + " completeness fields must be boolean");
  }
  if (!Array.isArray(fact.diagnostics) || !fact.diagnostics.every((item) => typeof item === "string")) {
    throw new ProfileBundleError(label + ".diagnostics must be a string array");
  }
  if (!Array.isArray(fact.definitions) || !Array.isArray(fact.direct_calls) ||
      !Array.isArray(fact.unknown_indirect) || !Array.isArray(fact.guidance_sites)) {
    throw new ProfileBundleError(label + " definition and callgraph fields must be arrays");
  }
  fact.definitions.forEach((rawDefinition, definitionIndex) => {
    const dlabel = label + ".definitions[" + definitionIndex + "]";
    const definition = assertObject(rawDefinition, dlabel);
    assertKeys(definition, ["symbol", "linkage", "source_file", "address_use"],
      ["symbol", "linkage", "source_file", "address_use", "line"], dlabel);
    requireString(definition.symbol, dlabel + ".symbol");
    requireString(definition.linkage, dlabel + ".linkage");
    requireString(definition.source_file, dlabel + ".source_file");
    const use = assertObject(definition.address_use, dlabel + ".address_use");
    const useRequired = ["address_taken", "complete", "reasons"];
    const useOptional = ["non_direct_uses", "non_direct_metadata_uses", "inline_asm_summaries"];
    assertKeys(use, useRequired, [...useRequired, ...useOptional], dlabel + ".address_use");
    if (typeof use.address_taken !== "boolean" || typeof use.complete !== "boolean") {
      throw new ProfileBundleError(dlabel + ".address_use flags must be boolean");
    }
    for (const key of ["reasons", ...useOptional]) {
      if (use[key] !== undefined && (!Array.isArray(use[key]) || !(use[key] as unknown[]).every((item) => typeof item === "string"))) {
        throw new ProfileBundleError(dlabel + ".address_use." + key + " must be a string array");
      }
    }
    if (definition.line !== undefined && (typeof definition.line !== "number" ||
        !Number.isSafeInteger(definition.line) || definition.line < 0)) {
      throw new ProfileBundleError(dlabel + ".line must be a safe nonnegative integer");
    }
  });
  if (fact.module_data_uses !== undefined) {
    if (!Array.isArray(fact.module_data_uses)) throw new ProfileBundleError(label + ".module_data_uses must be an array");
    fact.module_data_uses.forEach((rawUse, useIndex) => {
      const ulabel = label + ".module_data_uses[" + useIndex + "]";
      const use = assertObject(rawUse, ulabel);
      assertKeys(use, ["symbol", "owner"], ["symbol", "owner"], ulabel);
      requireString(use.symbol, ulabel + ".symbol");
      requireString(use.owner, ulabel + ".owner");
    });
  }
  if (fact.module_data_uses_complete !== undefined && typeof fact.module_data_uses_complete !== "boolean") {
    throw new ProfileBundleError(label + ".module_data_uses_complete must be boolean");
  }
  if ((fact.module_data_uses === undefined) !== (fact.module_data_uses_complete === undefined)) {
    throw new ProfileBundleError(label + " must provide module_data_uses and module_data_uses_complete together");
  }
  return fact;
}

export function validateIrFactsAggregateV2(raw: unknown): JsonObject[] {
  const aggregate = assertObject(raw, "ir_facts");
  assertKeys(aggregate, ["schema", "facts"], ["schema", "facts"], "ir_facts");
  if (aggregate.schema !== IR_FACTS_AGGREGATE_SCHEMA || !Array.isArray(aggregate.facts)) {
    throw new ProfileBundleError("expected " + IR_FACTS_AGGREGATE_SCHEMA);
  }
  const facts = aggregate.facts.map((fact, index) => validateIrFactsV2(fact, index));
  const moduleIds = facts.map((fact) => fact.module_id as string);
  if (new Set(moduleIds).size !== moduleIds.length ||
      moduleIds.some((moduleId, index) => index > 0 && moduleIds[index - 1]! >= moduleId)) {
    throw new ProfileBundleError("IR facts must be sorted by unique module_id");
  }
  return facts;
}

function safeArtifactPath(root: string, relativePath: unknown, label: string): string {
  if (typeof relativePath !== "string" || relativePath.length === 0 || path.isAbsolute(relativePath) ||
      /^[a-zA-Z]:[\\/]/.test(relativePath)) {
    throw new ProfileBundleError(label + " path must be relative to the bundle root");
  }
  const parts = relativePath.split(/[\\/]/);
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    throw new ProfileBundleError(label + " path must not contain empty, dot, or parent components");
  }
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
    throw new ProfileBundleError(label + " path escapes the bundle root");
  }
  let real: string;
  try {
    real = realpathSync(resolved);
    if (!statSync(real).isFile()) throw new Error("not a regular file");
  } catch (error) {
    throw new ProfileBundleError(label + " artifact is unavailable: " + String(error));
  }
  const realRelative = path.relative(root, real);
  if (realRelative === ".." || realRelative.startsWith(".." + path.sep) || path.isAbsolute(realRelative)) {
    throw new ProfileBundleError(label + " symlink escapes the bundle root");
  }
  return real;
}

function parsePageEntries(value: unknown, label: string, pageUniverse: Map<bigint, PageUniverseEntry>): Array<{ rva: bigint; effects: Effect[] }> {
  if (!Array.isArray(value)) throw new ProfileBundleError(label + " must be an array");
  const merged = new Map<bigint, Set<Effect>>();
  for (let index = 0; index < value.length; index++) {
    const raw = value[index];
    let rva: bigint;
    let effectValue: unknown;
    if (typeof raw === "string") {
      rva = parseRva(raw, label + "[" + index + "]");
      effectValue = undefined;
    } else {
      const entry = assertObject(raw, label + "[" + index + "]");
      const key = Object.hasOwn(entry, "rva") ? "rva" : "page_rva";
      rva = parseRva(entry[key], label + "[" + index + "]." + key);
      effectValue = entry.effects;
    }
    const universe = pageUniverse.get(rva);
    if (!universe) throw new ProfileBundleError(label + " references a page outside page_universe: " + formatRva(rva));
    const effects = effectValue === undefined
      ? universe.maxPermissions
      : canonicalEffects(Array.isArray(effectValue) ? effectValue as string[] : []);
    if (effects.length === 0) throw new ProfileBundleError(label + " page has no effects: " + formatRva(rva));
    for (const effect of effects) {
      if (!universe.maxPermissions.includes(effect)) {
        throw new ProfileBundleError(label + " effect " + effect + " exceeds max_permissions at " + formatRva(rva));
      }
    }
    const existing = merged.get(rva) ?? new Set<Effect>();
    effects.forEach((effect) => existing.add(effect));
    merged.set(rva, existing);
  }
  return [...merged].map(([rva, effects]) => ({ rva, effects: canonicalEffects([...effects]) }));
}

function parseFields(value: unknown, pageUniverse: Map<bigint, PageUniverseEntry>): ProfileField[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new ProfileBundleError("fields must be a nonempty array");
  }
  const seen = new Set<string>();
  return value.map((raw, index) => {
    const field = assertObject(raw, "fields[" + index + "]");
    if (typeof field.id !== "string" || field.id.length === 0) {
      throw new ProfileBundleError("fields[" + index + "].id must be a nonempty string");
    }
    if (seen.has(field.id)) throw new ProfileBundleError("duplicate Field id " + field.id);
    seen.add(field.id);
    const name = typeof field.name === "string" && field.name.length
      ? field.name
      : typeof field.function === "string" && field.function.length
        ? field.function
        : field.id;
    const staticPages = field.static_pages === undefined
      ? []
      : parsePageEntries(field.static_pages, "Field " + field.id + ".static_pages", pageUniverse);
    const resourcePages = field.resource_pages === undefined
      ? []
      : parsePageEntries(field.resource_pages, "Field " + field.id + ".resource_pages", pageUniverse);
    let layoutExtents: Extent[] = [];
    if (field.layout_extents !== undefined) {
      if (!Array.isArray(field.layout_extents)) {
        throw new ProfileBundleError("Field " + field.id + ".layout_extents must be an array");
      }
      layoutExtents = field.layout_extents.map((rawExtent, extentIndex) => {
        const extent = assertObject(rawExtent, "Field " + field.id + ".layout_extents[" + extentIndex + "]");
        if (extent.kind !== "function" && extent.kind !== "object") {
          throw new ProfileBundleError("Field " + field.id + " extent kind must be function or object");
        }
        if (typeof extent.exact !== "boolean") {
          throw new ProfileBundleError("Field " + field.id + " extent exact flag must be boolean");
        }
        const start = parseRva(extent.start_rva, "Field " + field.id + " extent start_rva");
        const end = parseRva(extent.end_rva, "Field " + field.id + " extent end_rva");
        if (end <= start) throw new ProfileBundleError("Field " + field.id + " extent must have positive size");
        return { kind: extent.kind, start, end, exact: extent.exact };
      });
    }
    return {
      id: field.id,
      name,
      raw: field,
      staticPages,
      resourcePages,
      layoutExtents,
    };
  });
}

function parseSelectors(value: unknown, fields: ProfileField[]): ProfileSelector[] {
  if (!Array.isArray(value)) throw new ProfileBundleError("selectors must be an array");
  const fieldIds = new Set(fields.map((field) => field.id));
  const ordinals = new Set<number>();
  const names = new Set<string>();
  const selectors = value.map((raw, index) => {
    const selector = assertObject(raw, "selectors[" + index + "]");
    const selectorKeys = ["ordinal", "name", "visibility", "switchless", "entry_rva", "reachable_fields", "reachability"];
    assertKeys(selector, selectorKeys, selectorKeys, "selectors[" + index + "]");
    const ordinal = parseInteger(selector.ordinal, "selectors[" + index + "].ordinal");
    if (ordinals.has(ordinal)) throw new ProfileBundleError("duplicate selector ordinal " + ordinal);
    ordinals.add(ordinal);
    if (typeof selector.name !== "string" || !selector.name) {
      throw new ProfileBundleError("selectors[" + index + "].name must be nonempty");
    }
    if (names.has(selector.name)) throw new ProfileBundleError("duplicate selector name " + selector.name);
    names.add(selector.name);
    if (typeof selector.visibility !== "string" || !selector.visibility) {
      throw new ProfileBundleError("selector " + selector.name + " visibility must be nonempty");
    }
    if (typeof selector.switchless !== "boolean") {
      throw new ProfileBundleError("selector " + selector.name + " switchless must be boolean");
    }
    const entryRva = parseRva(selector.entry_rva, "selector " + selector.name + ".entry_rva");
    if (!Array.isArray(selector.reachable_fields)) {
      throw new ProfileBundleError("selector " + selector.name + ".reachable_fields must be an array");
    }
    const reachableEntries = selector.reachable_fields;
    const reachableFields = reachableEntries.map((id, fieldIndex) => {
      if (typeof id !== "string" || !fieldIds.has(id)) {
        throw new ProfileBundleError("selector " + selector.name + " references unknown Field " + String(id));
      }
      if (reachableEntries.indexOf(id) !== fieldIndex) {
        throw new ProfileBundleError("selector " + selector.name + " repeats Field " + id);
      }
      return id;
    });
    if (selector.reachability === undefined || selector.reachability === null ||
        (typeof selector.reachability !== "string" && !isObject(selector.reachability))) {
      throw new ProfileBundleError("selector " + selector.name + ".reachability must be a string or object");
    }
    return {
      ordinal,
      name: selector.name,
      visibility: selector.visibility,
      switchless: selector.switchless,
      entryRva,
      reachableFields,
      reachability: selector.reachability,
    };
  });
  selectors.sort((a, b) => a.ordinal - b.ordinal);
  selectors.forEach((selector, index) => {
    if (selector.ordinal !== index) {
      throw new ProfileBundleError("selector ordinals must be contiguous from zero");
    }
  });
  return selectors;
}

const EDL_ABI_SCHEMA = "atfield-edl-abi-v1";
const MARSHAL_LAYOUT_SCHEMA = "atfield-marshal-layout-v1";
const IR_FACTS_AGGREGATE_SCHEMA = "atfield-ir-facts-aggregate-v2";
const IR_FACTS_SCHEMA = "atfield-ir-facts-v2";
const REACHABILITY_SCHEMA = "atfield-reachability-v1";
const MEASUREMENT_PROFILE_SCHEMA = "atfield-measurement-profile-v1";

function readArtifactObject(filename: string, label: string): JsonObject {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(filename));
  } catch (error) {
    throw new ProfileBundleError(label + " is not valid UTF-8: " + String(error));
  }
  return assertObject(parseStrictJson(text, label), label);
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ProfileBundleError(label + " must be a nonempty string");
  }
  return value;
}

function parseExactUnsigned(value: unknown, label: string): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)$/.test(value)) {
    return BigInt(value);
  }
  throw new ProfileBundleError(label + " must be an exact unsigned integer");
}

function assertPortableEvidencePaths(value: unknown, label: string, key = ""): void {
  const pathKey = /(?:^|_)(?:path|file|dir|directory|translation_unit|ir_filename|source_file|imports)$/i.test(key);
  if (typeof value === "string" && pathKey) {
    if (!value || path.isAbsolute(value) || /^[A-Za-z]:/.test(value) || value.includes("\\") ||
        value.split("/").some((part) => part === "" || part === "." || part === "..")) {
      throw new ProfileBundleError(label + " contains a nonportable or external path");
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertPortableEvidencePaths(entry, label + "[" + index + "]", key));
    return;
  }
  if (!isObject(value)) return;
  for (const [childKey, child] of Object.entries(value)) {
    if (childKey === "compiler" && typeof child === "string" && path.isAbsolute(child)) {
      throw new ProfileBundleError(label + ".compiler must not expose an external path");
    }
    assertPortableEvidencePaths(child, label + "." + childKey, childKey);
  }
}

function jsonEqual(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b);
}

function requireObjectArtifact(artifactPaths: Map<string, string>, name: string): JsonObject {
  const filename = artifactPaths.get(name);
  if (!filename) throw new ProfileBundleError("missing bundled " + name + " artifact");
  return readArtifactObject(filename, "artifacts." + name);
}

function validateMeasurementCollector(measurement: JsonObject, layout: JsonObject): string {
  const collector = assertObject(measurement.collector, "measurement.collector");
  if (collector.abi !== "atfield-4gate-native-v1" || collector.page_size !== PAGE_SIZE) {
    throw new ProfileBundleError("measurement collector ABI or page size is unsupported");
  }
  const tcs = collector.tcs_ranges;
  const ssa = collector.ssa_ranges;
  if (!Array.isArray(tcs) || tcs.length !== 1 || !isObject(tcs[0]) ||
      !Array.isArray(ssa) || ssa.length !== 1 || !isObject(ssa[0])) {
    throw new ProfileBundleError("measurement collector requires one TCS and one contiguous SSA range");
  }
  const gateRange = assertObject(collector.gate_helper_range, "measurement.collector.gate_helper_range");
  const gateStart = parseRva(gateRange.start_rva, "measurement gate start_rva");
  const gateEnd = parseRva(gateRange.end_rva, "measurement gate end_rva");
  const enclaveSize = BigInt(parseInteger(layout.enclave_size, "layout.enclave_size"));
  if (gateStart >= gateEnd || gateEnd > enclaveSize || gateStart % PAGE_BIG !== 0n ||
      gateEnd % PAGE_BIG !== 0n) {
    throw new ProfileBundleError("measurement gate range is invalid");
  }
  const gm = formatRva(parseRva(collector.guard_manager_rva, "measurement guard_manager_rva"));
  const spec = requireString(collector.layout_spec, "measurement collector.layout_spec");
  const tokens = new Map<string, string>();
  for (const part of spec.split(";")) {
    const equals = part.indexOf("=");
    if (equals <= 0 || equals === part.length - 1) {
      throw new ProfileBundleError("measurement collector layout_spec has a malformed entry");
    }
    const name = part.slice(0, equals);
    if (tokens.has(name)) throw new ProfileBundleError("measurement collector layout_spec repeats " + name);
    tokens.set(name, part.slice(equals + 1));
  }
  if (tokens.get("gm") !== gm) {
    throw new ProfileBundleError("measurement collector layout_spec gm does not match guard_manager_rva");
  }
  const gate = formatRva(gateStart) + ":" + formatRva(gateEnd);
  if (tokens.get("gate") !== gate) {
    throw new ProfileBundleError("measurement collector layout_spec gate does not match gate_helper_range");
  }

  const tcsStart = formatRva(parseRva(tcs[0].start_rva, "measurement TCS start_rva"));
  const ssaStart = formatRva(parseRva(ssa[0].start_rva, "measurement SSA start_rva"));
  const pretouch = assertObject(collector.pretouch, "measurement.collector.pretouch");
  const pretouchStart = formatRva(parseRva(pretouch.start_rva, "measurement pretouch start_rva"));
  const pretouchEnd = formatRva(parseRva(pretouch.end_rva, "measurement pretouch end_rva"));
  const capacityQ = parseExactUnsigned(pretouch.capacity_q, "measurement pretouch capacity_q");
  if (BigInt(pretouchStart) + capacityQ !== BigInt(pretouchEnd) ||
      BigInt(pretouchStart) !== parseRva(layout.pretouch_start, "layout.pretouch_start") ||
      parseExactUnsigned(layout.capacity_q, "layout.capacity_q") !== capacityQ) {
    throw new ProfileBundleError("measurement collector pretouch range differs from the bundle layout");
  }
  const expected = ["tcs=" + tcsStart, "ssa=" + ssaStart, "gm=" + gm];
  if (collector.active_field_rva !== null && collector.active_field_rva !== undefined) {
    expected.push("active=" + formatRva(parseRva(collector.active_field_rva, "measurement active_field_rva")));
  }
  expected.push("pretouch=" + pretouchStart + ":" + pretouchEnd, "gate=" + gate);
  const stacks = collector.stack_ranges;
  if (!Array.isArray(stacks)) throw new ProfileBundleError("measurement collector stack_ranges must be an array");
  if (stacks.length) {
    const starts = stacks.map((entry, index) =>
      parseRva(assertObject(entry, "measurement stack range " + index).start_rva, "measurement stack start"));
    const ends = stacks.map((entry, index) =>
      parseRva(assertObject(entry, "measurement stack range " + index).end_rva, "measurement stack end"));
    const low = starts.reduce((a, b) => a < b ? a : b);
    const high = ends.reduce((a, b) => a > b ? a : b);
    expected.push("stack=" + formatRva(low) + ":" + formatRva(high));
  }
  const excluded = collector.excluded_regions;
  if (!Array.isArray(excluded)) throw new ProfileBundleError("measurement collector excluded_regions must be an array");
  if (excluded.length) {
    const ranges = excluded.map((entry, index) => {
      const range = assertObject(entry, "measurement excluded region " + index);
      return formatRva(parseRva(range.start, "measurement excluded start")) + ":" +
        formatRva(parseRva(range.end, "measurement excluded end"));
    });
    expected.push("excl=" + ranges.join(","));
  }
  if (spec !== expected.join(";")) {
    throw new ProfileBundleError("measurement collector layout_spec is not the canonical projection of its verified layout");
  }
  return spec;
}

function validateEvidenceArtifacts(
  root: string,
  artifactPaths: Map<string, string>,
  artifactDigests: Map<string, string>,
  identity: ProfileBundle["identity"],
  layout: JsonObject,
  fieldsValue: unknown,
  selectorsValue: unknown,
): { marshalLayout: JsonObject; marshalLayoutSha256: string; collectorLayoutSpec: string; relroPages: Set<bigint> } {
  const fieldsDocument = requireObjectArtifact(artifactPaths, "fields");
  if (fieldsDocument.schema !== "atfield-fields-v1" || !Array.isArray(fieldsDocument.fields) ||
      !jsonEqual(fieldsDocument.fields, fieldsValue)) {
    throw new ProfileBundleError("bundled fields artifact differs from Profile bundle fields");
  }
  const fieldIds = fieldsDocument.fields.map((field, index) => {
    const value = assertObject(field, "fields[" + index + "]");
    return requireString(value.id, "fields[" + index + "].id");
  });

  const abi = requireObjectArtifact(artifactPaths, "edl_abi");
  if (abi.schema !== EDL_ABI_SCHEMA) throw new ProfileBundleError("expected " + EDL_ABI_SCHEMA);
  const abiEcalls = abi.ecalls;
  if (!Array.isArray(abiEcalls) || abiEcalls.length === 0) {
    throw new ProfileBundleError("SDK EDL ABI requires a nonempty ecalls array");
  }
  abiEcalls.forEach((raw, index) => {
    const ecall = assertObject(raw, "EDL ABI ecall " + index);
    if (parseInteger(ecall.ordinal, "EDL ABI ordinal") !== index ||
        typeof ecall.name !== "string" || !ecall.name ||
        (ecall.visibility !== "public" && ecall.visibility !== "private") ||
        typeof ecall.switchless !== "boolean") {
      throw new ProfileBundleError("SDK EDL ABI ecall order or fields are invalid at ordinal " + index);
    }
  });

  const marshalLayout = requireObjectArtifact(artifactPaths, "marshal_layout");
  if (marshalLayout.schema !== MARSHAL_LAYOUT_SCHEMA) {
    throw new ProfileBundleError("expected " + MARSHAL_LAYOUT_SCHEMA);
  }
  const marshalInput = assertObject(marshalLayout.input, "marshal_layout.input");
  if (normalizeDigest(marshalInput.edl_abi_sha256, "marshal_layout.input.edl_abi_sha256") !==
      identity.edlAbiSha256) {
    throw new ProfileBundleError("marshal_layout EDL ABI digest differs from the bundled ABI");
  }
  if (!Array.isArray(marshalLayout.ecalls) || marshalLayout.ecalls.length !== abiEcalls.length) {
    throw new ProfileBundleError("marshal_layout ECALL set differs from the SDK ABI");
  }
  marshalLayout.ecalls.forEach((raw, index) => {
    const ecall = assertObject(raw, "marshal_layout.ecalls[" + index + "]");
    const abiEcall = assertObject(abiEcalls[index], "edl_abi.ecalls[" + index + "]");
    if (parseInteger(ecall.ordinal, "marshal_layout ECALL ordinal") !== index ||
        ecall.name !== abiEcall.name || ecall.visibility !== abiEcall.visibility ||
        ecall.switchless !== abiEcall.switchless || !Array.isArray(ecall.params)) {
      throw new ProfileBundleError("marshal_layout ECALL identity differs from the SDK ABI at ordinal " + index);
    }
    const abiParams = Array.isArray(abiEcall.parameters) ? abiEcall.parameters : [];
    if (ecall.params.length !== abiParams.length) {
      throw new ProfileBundleError("marshal_layout parameter count differs from the SDK ABI at ordinal " + index);
    }
    ecall.params.forEach((rawParam: unknown, paramIndex: number) => {
      const param = assertObject(rawParam, "marshal_layout ECALL parameter");
      const abiParam = assertObject(abiParams[paramIndex], "EDL ABI parameter");
      if (param.name !== abiParam.name) {
        throw new ProfileBundleError("marshal_layout parameter order differs from the SDK ABI at ordinal " + index);
      }
      if (param.ms_signed !== null && typeof param.ms_signed !== "boolean") {
        throw new ProfileBundleError("marshal_layout signedness must be boolean or null");
      }
      if (param.ms_offset !== null || param.ms_size !== null) {
        const msSize = parseExactUnsigned(ecall.ms_size, "marshal_layout ECALL ms_size");
        const offset = parseExactUnsigned(param.ms_offset, "marshal_layout ms_offset");
        const size = parseExactUnsigned(param.ms_size, "marshal_layout ms_size");
        if (offset + size > msSize) throw new ProfileBundleError("marshal_layout parameter exceeds its ECALL struct");
      }
    });
  });

  const aggregate = requireObjectArtifact(artifactPaths, "ir_facts");
  const facts = validateIrFactsAggregateV2(aggregate);
  facts.forEach((fact, index) => {
    if (!/^irtu_[0-9a-f]{32}$/.test(String(fact.module_id)) ||
        normalizeDigest(fact.backend_ir_sha256, "IR backend digest") !== fact.backend_ir_sha256 ||
        normalizeDigest(fact.object_sha256, "IR object digest") !== fact.object_sha256) {
      throw new ProfileBundleError("invalid single-TU IR facts at index " + index);
    }
  });

  const reachability = requireObjectArtifact(artifactPaths, "reachability");
  if (reachability.schema !== REACHABILITY_SCHEMA) throw new ProfileBundleError("expected " + REACHABILITY_SCHEMA);
  const reachInput = assertObject(reachability.input, "reachability.input");
  if (normalizeDigest(reachInput.profile_elf_sha256, "reachability.input.profile_elf_sha256") !== identity.profileElfSha256 ||
      normalizeDigest(reachInput.edl_abi_sha256, "reachability.input.edl_abi_sha256") !== identity.edlAbiSha256 ||
      normalizeDigest(reachInput.live_fields_sha256, "reachability.input.live_fields_sha256") !== identity.fieldsSha256) {
    throw new ProfileBundleError("reachability input does not bind the bundled Profile ELF, ABI, and fields");
  }
  const analysis = assertObject(reachability.analysis, "reachability.analysis");
  if (normalizeDigest(analysis.profile_elf_sha256, "reachability.analysis.profile_elf_sha256") !== identity.profileElfSha256) {
    throw new ProfileBundleError("reachability analysis does not bind the bundled Profile ELF");
  }
  if (!Array.isArray(reachInput.ir_facts_tus) || reachInput.ir_facts_tus.length !== facts.length) {
    throw new ProfileBundleError("reachability IR fact set differs from the aggregate");
  }
  const factsByModule = new Map<string, Record<string, unknown>>();
  for (const fact of facts) {
    factsByModule.set(fact.module_id as string, fact);
  }
  const expectedObjects = reachInput.expected_objects;
  if (!Array.isArray(expectedObjects) || expectedObjects.length !== facts.length) {
    throw new ProfileBundleError("reachability expected_objects must cover the aggregate objects");
  }
  const expectedByTu = new Map<string, string>();
  expectedObjects.forEach((raw, index) => {
    const expected = assertObject(raw, "reachability.input.expected_objects[" + index + "]");
    assertKeys(expected, ["translation_unit", "object_sha256"], ["translation_unit", "object_sha256"],
      "reachability.input.expected_objects[" + index + "]");
    const tu = requireString(expected.translation_unit, "reachability expected object translation_unit");
    const objectDigest = normalizeDigest(expected.object_sha256, "reachability expected object digest");
    if (expectedByTu.has(tu)) throw new ProfileBundleError("reachability expected_objects repeats a translation unit");
    expectedByTu.set(tu, objectDigest);
  });
  for (const fact of facts) {
    if (expectedByTu.get(String(fact.translation_unit)) !== fact.object_sha256) {
      throw new ProfileBundleError("reachability expected_objects does not bind aggregate object " + fact.translation_unit);
    }
  }
  const seenEvidenceModules = new Set<string>();
  reachInput.ir_facts_tus.forEach((raw, index) => {
    const evidence = assertObject(raw, "reachability.input.ir_facts_tus[" + index + "]");
    const modId = typeof evidence.module_id === "string" ? evidence.module_id : "";
    const fact = factsByModule.get(modId);
    if (!fact || seenEvidenceModules.has(modId)) {
      throw new ProfileBundleError("reachability input does not bind aggregate IR fact " + index);
    }
    seenEvidenceModules.add(modId);
    const factDigest = sha256(new TextEncoder().encode(canonicalJson(fact)));
    const variantDigest = sha256(new TextEncoder().encode(canonicalJson(fact.compile_variant)));
    if (evidence.translation_unit !== fact.translation_unit || evidence.module_id !== fact.module_id ||
        normalizeDigest(evidence.backend_ir_sha256, "reachability backend digest") !== fact.backend_ir_sha256 ||
        normalizeDigest(evidence.object_sha256, "reachability object digest") !== fact.object_sha256 ||
        normalizeDigest(evidence.variant_sha256, "reachability variant digest") !== variantDigest ||
        normalizeDigest(evidence.facts_sha256, "reachability fact digest") !== factDigest) {
      throw new ProfileBundleError("reachability input does not bind aggregate IR fact " + index);
    }
  });
  if (!Array.isArray(reachability.live_field_ids) ||
      !jsonEqual(reachability.live_field_ids, fieldIds) ||
      !Array.isArray(reachability.ecalls) || reachability.ecalls.length !== abiEcalls.length) {
    throw new ProfileBundleError("reachability selector or live Field set differs from the bundled ABI and fields");
  }
  const selectors = selectorsValue;
  if (!Array.isArray(selectors)) throw new ProfileBundleError("Profile bundle selectors must be an array");
  reachability.ecalls.forEach((raw, index) => {
    const ecall = assertObject(raw, "reachability.ecalls[" + index + "]");
    const abiEcall = assertObject(abiEcalls[index], "edl_abi.ecalls[" + index + "]");
    const selector = assertObject(selectors[index], "selectors[" + index + "]");
    if (parseInteger(ecall.ordinal, "reachability ordinal") !== index ||
        ecall.name !== abiEcall.name || ecall.visibility !== abiEcall.visibility ||
        ecall.switchless !== abiEcall.switchless || selector.name !== ecall.name ||
        parseInteger(selector.ordinal, "selector ordinal") !== index) {
      throw new ProfileBundleError("reachability selector identity differs from the SDK ABI at ordinal " + index);
    }
    const ecallKeys = [
      "ordinal", "name", "entry_symbol", "visibility", "private", "switchless", "status",
      "callgraph_complete", "guidance_complete", "function_closure_complete", "field_reachability_complete",
      "reachable_fields", "reachable_functions", "reachable_function_instances", "unknown_indirect",
      "unknown_external", "reachability", "evidence",
    ];
    assertKeys(ecall, ecallKeys, ecallKeys, "reachability.ecalls[" + index + "]");
    if (ecall.status !== "verified" && ecall.status !== "unknown") {
      throw new ProfileBundleError("reachability status must be verified or unknown");
    }
    for (const key of ["private", "callgraph_complete", "guidance_complete", "function_closure_complete",
      "field_reachability_complete", "unknown_indirect", "unknown_external"]) {
      if (typeof ecall[key] !== "boolean") throw new ProfileBundleError("reachability " + key + " must be boolean");
    }
    if (typeof ecall.entry_symbol !== "string" || typeof ecall.reachability !== "string" ||
        !Array.isArray(ecall.reachable_functions) ||
        !ecall.reachable_functions.every((name: unknown) => typeof name === "string") ||
        !Array.isArray(ecall.reachable_function_instances) || !isObject(ecall.evidence)) {
      throw new ProfileBundleError("reachability ECALL analyzer evidence is malformed");
    }
    if (!Array.isArray(ecall.reachable_fields) ||
        ecall.reachable_fields.some((id: unknown) => typeof id !== "string" || !fieldIds.includes(id)) ||
        new Set(ecall.reachable_fields).size !== ecall.reachable_fields.length) {
      throw new ProfileBundleError("reachability contains unknown or repeated live Field ids");
    }
    const uncertain = ecall.status === "unknown" || !ecall.callgraph_complete ||
      !ecall.function_closure_complete || !ecall.field_reachability_complete ||
      ecall.unknown_indirect || ecall.unknown_external;
    if (uncertain && (ecall.reachable_fields.length !== fieldIds.length ||
        fieldIds.some((id) => !ecall.reachable_fields.includes(id)))) {
      throw new ProfileBundleError("unknown reachability must conservatively include all live Fields");
    }
  });

  const measurement = requireObjectArtifact(artifactPaths, "measurement_manifest");
  if (measurement.schema !== MEASUREMENT_PROFILE_SCHEMA) {
    throw new ProfileBundleError("expected " + MEASUREMENT_PROFILE_SCHEMA);
  }
  const measurementIdentity = assertObject(measurement.identity, "measurement.identity");
  const measuredProfileSha = normalizeDigest(measurementIdentity.profile_elf_sha256, "measurement profile ELF digest");
  const measuredSignedSha = normalizeDigest(measurementIdentity.signed_profile_elf_sha256, "measurement signed ELF digest");
  if (measuredProfileSha !== identity.profileElfSha256 ||
      measuredSignedSha !== identity.signedProfileElfSha256 ||
      normalizeDigest(measurementIdentity.fields_sha256, "measurement fields digest") !== identity.fieldsSha256) {
    throw new ProfileBundleError("measurement manifest identity differs from the bundled Profile artifacts");
  }
  const measuredLayout = assertObject(measurement.layout, "measurement.layout");
  const layoutKeys = [
    "metadata_version", "ssa_frame_pages", "page_size", "enclave_size", "ordinary_load_end",
    "pretouch_start", "capacity_q", "pretouch_segment", "regions", "excluded_regions",
    "relro_ranges", "relro_pages",
  ];
  assertKeys(measuredLayout, layoutKeys, layoutKeys, "measurement.layout");
  for (const key of ["regions", "excluded_regions"]) {
    if (!jsonEqual(measuredLayout[key], layout[key])) {
      throw new ProfileBundleError("measurement layout differs from bundle layout at " + key);
    }
  }
  for (const key of ["page_size", "enclave_size", "ssa_frame_pages"]) {
    if (parseExactUnsigned(measuredLayout[key], "measurement.layout." + key) !==
        parseExactUnsigned(layout[key], "layout." + key)) {
      throw new ProfileBundleError("measurement layout differs from bundle layout at " + key);
    }
  }
  for (const key of ["ordinary_load_end", "pretouch_start"]) {
    if (parseRva(measuredLayout[key], "measurement.layout." + key) !== parseRva(layout[key], "layout." + key)) {
      throw new ProfileBundleError("measurement layout differs from bundle layout at " + key);
    }
  }
  if (parseExactUnsigned(measuredLayout.capacity_q, "measurement.layout.capacity_q") !==
      parseExactUnsigned(layout.capacity_q, "layout.capacity_q")) {
    throw new ProfileBundleError("measurement layout differs from bundle layout at capacity_q");
  }
  const measurementArtifacts = assertObject(measurement.artifacts, "measurement.artifacts");
  assertKeys(measurementArtifacts, ["profile_elf", "signed_profile_elf"],
    ["profile_elf", "signed_profile_elf"], "measurement.artifacts");
  for (const name of ["profile_elf", "signed_profile_elf"]) {
    const item = assertObject(measurementArtifacts[name], "measurement.artifacts." + name);
    assertKeys(item, ["path", "sha256"], ["path", "sha256"], "measurement.artifacts." + name);
    const embeddedPath = safeArtifactPath(root, item.path, "measurement.artifacts." + name);
    if (embeddedPath !== artifactPaths.get(name) ||
        normalizeDigest(item.sha256, "measurement.artifacts." + name + ".sha256") !== artifactDigests.get(name)) {
      throw new ProfileBundleError("measurement manifest artifact differs from bundled " + name);
    }
  }
  const collectorLayoutSpec = validateMeasurementCollector(measurement, layout);

  for (const [name, document] of [
    ["edl_abi", abi], ["marshal_layout", marshalLayout], ["ir_facts", aggregate],
    ["reachability", reachability], ["measurement_manifest", measurement],
  ] as Array<[string, JsonObject]>) {
    assertPortableEvidencePaths(document, "artifacts." + name);
  }
  if (!Array.isArray(measuredLayout.relro_pages)) {
    throw new ProfileBundleError("measurement.layout.relro_pages must be an array");
  }
  const relroPages = new Set<bigint>(
    measuredLayout.relro_pages.map((entry, idx) => parseRva(entry, "measurement.layout.relro_pages[" + idx + "]")),
  );
  return {
    marshalLayout,
    marshalLayoutSha256: artifactDigests.get("marshal_layout")!,
    collectorLayoutSpec,
    relroPages,
  };
}
export function loadProfileBundle(manifestFilename: string): ProfileBundle {
  let manifestPath: string;
  let root: string;
  let manifestBytes: Buffer;
  try {
    manifestPath = realpathSync(path.resolve(manifestFilename));
    root = realpathSync(path.dirname(manifestPath));
    manifestBytes = readFileSync(manifestPath);
  } catch (error) {
    throw new ProfileBundleError("cannot read Profile bundle manifest: " + String(error));
  }
  const manifest = assertObject(parseStrictJson(manifestBytes.toString("utf8"), "Profile bundle manifest"), "Profile bundle");
  assertKeys(
    manifest,
    ["schema", "identity", "layout", "artifacts", "fields", "selectors", "page_universe"],
    ["schema", "identity", "layout", "artifacts", "fields", "selectors", "page_universe"],
    "Profile bundle",
  );
  if (manifest.schema !== PROFILE_BUNDLE_SCHEMA) {
    throw new ProfileBundleError("expected " + PROFILE_BUNDLE_SCHEMA);
  }

  const identity = assertObject(manifest.identity, "identity");
  assertKeys(identity, ["profile_elf_sha256", "signed_profile_elf_sha256", "edl_abi_sha256", "fields_sha256"],
    ["profile_elf_sha256", "signed_profile_elf_sha256", "edl_abi_sha256", "fields_sha256"], "identity");
  const identityDigests = {
    profileElfSha256: normalizeDigest(identity.profile_elf_sha256, "identity.profile_elf_sha256"),
    signedProfileElfSha256: normalizeDigest(identity.signed_profile_elf_sha256, "identity.signed_profile_elf_sha256"),
    edlAbiSha256: normalizeDigest(identity.edl_abi_sha256, "identity.edl_abi_sha256"),
    fieldsSha256: normalizeDigest(identity.fields_sha256, "identity.fields_sha256"),
  };

  const layout = assertObject(manifest.layout, "layout");
  const requiredLayout = ["epoch", "page_size", "capacity_q", "ordinary_load_end", "pretouch_start", "enclave_size", "ssa_frame_pages", "regions", "excluded_regions"];
  assertKeys(layout, requiredLayout, requiredLayout, "layout");
  const layoutEpoch = normalizeDigest(layout.epoch, "layout.epoch");
  const pageSize = parseInteger(layout.page_size, "layout.page_size");
  if (pageSize !== PAGE_SIZE) throw new ProfileBundleError("layout.page_size must be 4096");
  const capacityQ = parseInteger(layout.capacity_q, "layout.capacity_q");
  if (capacityQ === 0 || capacityQ % PAGE_SIZE !== 0) {
    throw new ProfileBundleError("layout.capacity_q must be a positive 4096-byte multiple");
  }
  const ordinaryLoadEnd = parseRva(layout.ordinary_load_end, "layout.ordinary_load_end");
  const pretouchStart = parseRva(layout.pretouch_start, "layout.pretouch_start");
  const enclaveSize = parseInteger(layout.enclave_size, "layout.enclave_size");
  const ssaFramePages = parseInteger(layout.ssa_frame_pages, "layout.ssa_frame_pages");
  if (enclaveSize === 0 || !Array.isArray(layout.regions) || !layout.regions.every(isObject) ||
      !Array.isArray(layout.excluded_regions) || !layout.excluded_regions.every(isObject)) {
    throw new ProfileBundleError("layout requires positive enclave_size, regions, and excluded_regions");
  }
  const expectedPretouch = (ordinaryLoadEnd + PAGE_BIG - 1n) & -PAGE_BIG;
  if (pretouchStart !== expectedPretouch) {
    throw new ProfileBundleError("layout.pretouch_start must equal page-aligned ordinary_load_end");
  }
  if (pretouchStart + BigInt(capacityQ) >= (1n << 64n)) {
    throw new ProfileBundleError("pretouch reservation exceeds uint64 RVA space");
  }

  const canonicalEpochInput = {
    profile_elf_sha256: identityDigests.profileElfSha256,
    signed_profile_elf_sha256: identityDigests.signedProfileElfSha256,
    page_size: pageSize,
    capacity_q: capacityQ,
    ordinary_load_end: formatRva(ordinaryLoadEnd),
    pretouch_start: formatRva(pretouchStart),
    enclave_size: enclaveSize,
    ssa_frame_pages: ssaFramePages,
    regions: layout.regions,
    excluded_regions: layout.excluded_regions,
  };
  const calculatedEpoch = sha256(new TextEncoder().encode(canonicalJson(canonicalEpochInput)));
  if (layoutEpoch !== calculatedEpoch) {
    throw new ProfileBundleError("layout.epoch does not match the canonical effective-layout digest");
  }

  const artifacts = assertObject(manifest.artifacts, "artifacts");
  const artifactNames = ["profile_elf", "signed_profile_elf", "host", "edl_abi", "fields", "measurement_manifest", "marshal_layout", "ir_facts", "reachability"];
  assertKeys(artifacts, artifactNames, artifactNames, "artifacts");
  const actualArtifactDigests = new Map<string, string>();
  const artifactPaths = new Map<string, string>();
  for (const name of artifactNames) {
    const artifact = assertObject(artifacts[name], "artifacts." + name);
    assertKeys(artifact, ["path", "sha256"], ["path", "sha256"], "artifacts." + name);
    const expected = normalizeDigest(artifact.sha256, "artifacts." + name + ".sha256");
    const filename = safeArtifactPath(root, artifact.path, "artifacts." + name);
    const actual = sha256(readFileSync(filename));
    if (actual !== expected) {
      throw new ProfileBundleError("artifact digest mismatch for " + name);
    }
    actualArtifactDigests.set(name, actual);
    artifactPaths.set(name, filename);
  }
  const identityPairs: Array<[string, string]> = [
    ["profile_elf", identityDigests.profileElfSha256],
    ["signed_profile_elf", identityDigests.signedProfileElfSha256],
    ["edl_abi", identityDigests.edlAbiSha256],
    ["fields", identityDigests.fieldsSha256],
  ];
  for (const [name, digest] of identityPairs) {
    if (actualArtifactDigests.get(name) !== digest) {
      throw new ProfileBundleError("identity digest does not match artifacts." + name);
    }
  }
  const evidence = validateEvidenceArtifacts(
    root, artifactPaths, actualArtifactDigests, identityDigests, layout, manifest.fields, manifest.selectors,
  );

  if (!Array.isArray(manifest.page_universe) || manifest.page_universe.length === 0) {
    throw new ProfileBundleError("page_universe must be a nonempty array");
  }
  const pageUniverse = new Map<bigint, PageUniverseEntry>();
  for (let index = 0; index < manifest.page_universe.length; index++) {
    const rawPage = assertObject(manifest.page_universe[index], "page_universe[" + index + "]");
    assertKeys(rawPage, ["rva", "max_permissions", "region_kind"],
      ["rva", "max_permissions", "region_kind"], "page_universe[" + index + "]");
    const rva = parseRva(rawPage.rva, "page_universe[" + index + "].rva");
    if (rva % PAGE_BIG !== 0n) throw new ProfileBundleError("page_universe RVA must be page aligned");
    if (typeof rawPage.region_kind !== "string" || !rawPage.region_kind) {
      throw new ProfileBundleError("page_universe region_kind must be a nonempty string");
    }
    if (pageUniverse.has(rva)) throw new ProfileBundleError("duplicate page_universe RVA " + formatRva(rva));
    const parsedPerms = parsePermissions(rawPage.max_permissions, "page_universe[" + index + "].max_permissions");
    const maxPermissions = evidence.relroPages.has(rva)
      ? parsedPerms.filter((perm) => perm !== "W")
      : parsedPerms;
    pageUniverse.set(rva, {
      rva,
      maxPermissions,
      regionKind: rawPage.region_kind,
    });
  }

  const fields = parseFields(manifest.fields, pageUniverse);
  const fieldById = new Map(fields.map((field) => [field.id, field]));
  const selectors = parseSelectors(manifest.selectors, fields);
  const selectorByOrdinal = new Map(selectors.map((selector) => [selector.ordinal, selector]));

  return {
    root,
    manifestPath,
    manifestSha256: sha256(manifestBytes),
    layoutEpoch,
    pageSize,
    capacityQ,
    ordinaryLoadEnd,
    pretouchStart,
    identity: identityDigests,
    marshalLayout: evidence.marshalLayout,
    marshalLayoutSha256: evidence.marshalLayoutSha256,
    collectorLayoutSpec: evidence.collectorLayoutSpec,
    artifactDigests: actualArtifactDigests,
    artifactPaths,
    pageUniverse,
    fields,
    fieldById,
    selectors,
    selectorByOrdinal,
  };
}
