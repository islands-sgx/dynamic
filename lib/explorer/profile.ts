import { readFileSync } from "node:fs";
import {
  isObject,
  loadProfileBundle,
  normalizeDigest,
  parseStrictJson,
  sha256,
  type ProfileBundle,
} from "../bundle/profile-bundle.ts";
import { generateScalarReplacementCandidates, type ScalarParameter } from "../guidance/index.ts";
import type { MutationBinding } from "./contract.ts";

export interface MarshalParameter {
  ordinal: number;
  paramIndex: number;
  replaySupported: boolean;
  isPointer: boolean;
  form: string | null;
  userCheck: boolean;
  elementSize: number | null;
  elementTypeCategory: string | null;
  boundKind: "size_bytes" | "count_elements" | "string" | null;
  boundParameterIndex: number | null;
}

export interface MarshalEcall {
  ordinal: number;
  replaySupported: boolean;
  params: MarshalParameter[];
}

export interface ExplorerProfile {
  bundle: ProfileBundle;
  binding: MutationBinding;
  edlAbiSha256: string;
  marshalSpecSha256: string;
  marshalSpecBytes: Uint8Array;
  abi: Record<string, unknown>;
  ecalls: Map<number, MarshalEcall>;
  scalarParameters: ScalarParameter[];
  scalarParameterByKey: Map<string, ScalarParameter>;
  irFacts: unknown[];
  reachability: unknown[];
}

function fail(message: string): never {
  throw new TypeError(message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isObject(value)) fail(label + " must be an object");
  return value;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) fail(label + " must be an array");
  return value;
}

function exactKeys(value: Record<string, unknown>, required: string[], allowed: string[], label: string): void {
  const allowedSet = new Set(allowed);
  for (const key of required) if (!Object.hasOwn(value, key)) fail(label + " is missing " + key);
  const unknown = Object.keys(value).find((key) => !allowedSet.has(key));
  if (unknown) fail(label + " has unsupported key " + unknown);
}

function nonnegative(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(label + " must be a safe nonnegative integer");
  }
  return value;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") fail(label + " must be a boolean");
  return value;
}

function nonempty(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(label + " must be a nonempty NUL-free string");
  }
  return value;
}

function readBundleArtifact(bundle: ProfileBundle, name: string): { value: unknown; digest: string } {
  const filename = bundle.artifactPaths.get(name);
  const expected = bundle.artifactDigests.get(name);
  if (!filename || !expected) fail("Profile bundle is missing artifact " + name);
  let bytes: Uint8Array;
  try {
    bytes = readFileSync(filename);
  } catch (error) {
    fail("cannot read Profile bundle artifact " + name + ": " + String(error));
  }
  const digest = sha256(bytes);
  if (digest !== normalizeDigest(expected, "artifact " + name + " digest")) {
    fail("Profile bundle artifact " + name + " changed after bundle verification");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return { value: parseStrictJson(text, "Profile bundle artifact " + name), digest };
}

const INTEGER_TYPES: Record<string, { width: number; signedness: "signed" | "unsigned" }> = {
  "_Bool": { width: 8, signedness: "unsigned" },
  "bool": { width: 8, signedness: "unsigned" },
  "signed char": { width: 8, signedness: "signed" },
  "unsigned char": { width: 8, signedness: "unsigned" },
  "short": { width: 16, signedness: "signed" },
  "short int": { width: 16, signedness: "signed" },
  "signed short": { width: 16, signedness: "signed" },
  "signed short int": { width: 16, signedness: "signed" },
  "unsigned short": { width: 16, signedness: "unsigned" },
  "unsigned short int": { width: 16, signedness: "unsigned" },
  "int": { width: 32, signedness: "signed" },
  "signed": { width: 32, signedness: "signed" },
  "signed int": { width: 32, signedness: "signed" },
  "unsigned": { width: 32, signedness: "unsigned" },
  "unsigned int": { width: 32, signedness: "unsigned" },
  "long": { width: 64, signedness: "signed" },
  "long int": { width: 64, signedness: "signed" },
  "signed long": { width: 64, signedness: "signed" },
  "signed long int": { width: 64, signedness: "signed" },
  "unsigned long": { width: 64, signedness: "unsigned" },
  "unsigned long int": { width: 64, signedness: "unsigned" },
  "long long": { width: 64, signedness: "signed" },
  "long long int": { width: 64, signedness: "signed" },
  "signed long long": { width: 64, signedness: "signed" },
  "signed long long int": { width: 64, signedness: "signed" },
  "unsigned long long": { width: 64, signedness: "unsigned" },
  "unsigned long long int": { width: 64, signedness: "unsigned" },
  "size_t": { width: 64, signedness: "unsigned" },
  "ssize_t": { width: 64, signedness: "signed" },
  "intptr_t": { width: 64, signedness: "signed" },
  "uintptr_t": { width: 64, signedness: "unsigned" },
  "ptrdiff_t": { width: 64, signedness: "signed" },
  "int8_t": { width: 8, signedness: "signed" },
  "uint8_t": { width: 8, signedness: "unsigned" },
  "int16_t": { width: 16, signedness: "signed" },
  "uint16_t": { width: 16, signedness: "unsigned" },
  "int32_t": { width: 32, signedness: "signed" },
  "uint32_t": { width: 32, signedness: "unsigned" },
  "int64_t": { width: 64, signedness: "signed" },
  "uint64_t": { width: 64, signedness: "unsigned" },
};

function typeScalar(typeValue: unknown, label: string): { width: number; signedness: "signed" | "unsigned" } | undefined {
  const type = record(typeValue, label);
  if (type.kind === "builtin") {
    if (typeof type.name !== "string") fail(label + ".name must be a string for builtin types");
    const known = INTEGER_TYPES[type.name];
    if (!known) return undefined;
    if (type.signedness === "signed" || type.signedness === "unsigned") {
      return { width: known.width, signedness: type.signedness };
    }
    if (type.name === "char") return undefined;
    return known;
  }
  return undefined;
}

function parseMarshalLayout(value: unknown, abi: Record<string, unknown>): {
  ecalls: Map<number, MarshalEcall>;
  scalarParameters: ScalarParameter[];
  scalarParameterByKey: Map<string, ScalarParameter>;
} {
  const layout = record(value, "marshal_layout");
  exactKeys(layout, ["schema", "input", "tool", "ecalls"], ["schema", "input", "tool", "ecalls"], "marshal_layout");
  if (layout.schema !== "atfield-marshal-layout-v1") fail("marshal_layout schema is unsupported");
  const abiEcalls = array(abi.ecalls, "edl_abi.ecalls");
  const layoutEcalls = array(layout.ecalls, "marshal_layout.ecalls");
  const layoutByOrdinal = new Map<number, Record<string, unknown>>();
  for (const [index, raw] of layoutEcalls.entries()) {
    const item = record(raw, "marshal_layout.ecalls[" + index + "]");
    const ordinal = nonnegative(item.ordinal, "marshal_layout ECALL ordinal");
    if (layoutByOrdinal.has(ordinal)) fail("marshal_layout has duplicate ECALL ordinal " + ordinal);
    layoutByOrdinal.set(ordinal, item);
  }

  const ecalls = new Map<number, MarshalEcall>();
  const scalarParameters: ScalarParameter[] = [];
  const scalarParameterByKey = new Map<string, ScalarParameter>();
  for (const [abiIndex, rawEcall] of abiEcalls.entries()) {
    const abiEcall = record(rawEcall, "edl_abi.ecalls[" + abiIndex + "]");
    const ordinal = nonnegative(abiEcall.ordinal, "edl_abi ECALL ordinal");
    const layoutEcall = layoutByOrdinal.get(ordinal);
    if (!layoutEcall) continue;
    const layoutParams = array(layoutEcall.params, "marshal_layout ECALL params");
    const abiParams = array(abiEcall.parameters, "edl_abi ECALL parameters");
    if (layoutParams.length !== abiParams.length) fail("marshal_layout parameter count differs from edl_abi");
    const paramsByName = new Map<string, number>();
    for (const [paramIndex, rawParameter] of abiParams.entries()) {
      const parameter = record(rawParameter, "edl_abi parameter");
      const name = nonempty(parameter.name, "edl_abi parameter name");
      if (paramsByName.has(name)) fail("edl_abi ECALL repeats a parameter name");
      paramsByName.set(name, paramIndex);
    }
    const params: MarshalParameter[] = [];
    for (const [paramIndex, rawParameter] of abiParams.entries()) {
      const parameter = record(rawParameter, "edl_abi parameter");
      const measured = record(layoutParams[paramIndex], "marshal_layout parameter");
      const replaySupported = boolean(measured.replay_supported, "marshal_layout parameter replay_supported");
      const isPointer = boolean(measured.is_pointer, "marshal_layout parameter is_pointer");
      const form = typeof measured.form === "string" ? measured.form : null;
      const userCheck = measured.user_check === true;
      const rawElementSize = measured.element_size;
      const elementSize = rawElementSize === null || rawElementSize === undefined
        ? null
        : nonnegative(rawElementSize, "marshal_layout parameter element_size");
      const elementTypeCategory = typeof measured.element_type_category === "string"
        ? measured.element_type_category
        : null;
      let boundKind: MarshalParameter["boundKind"] = null;
      let boundParameterIndex: number | null = null;
      const rawBound = measured.bound ?? measured.size_bound ?? measured.count_bound ?? measured.string_bound;
      if (rawBound !== null && rawBound !== undefined) {
        const bound = record(rawBound, "marshal_layout parameter bound");
        if (bound.kind === "size_bytes" || bound.kind === "count_elements" || bound.kind === "string") {
          boundKind = bound.kind;
        }
        const source = bound.source === null || bound.source === undefined
          ? undefined
          : record(bound.source, "marshal_layout bound source");
        if (source?.kind === "parameter") {
          const boundName = nonempty(source.name, "marshal_layout bound parameter name");
          const found = paramsByName.get(boundName);
          if (found === undefined) fail("marshal_layout bound refers to an unknown ABI parameter");
          boundParameterIndex = found;
        }
      }
      params.push({
        ordinal,
        paramIndex,
        replaySupported,
        isPointer,
        form,
        userCheck,
        elementSize,
        elementTypeCategory,
        boundKind,
        boundParameterIndex,
      });

      if (parameter.parameter_form !== "value" || parameter.direction !== "value" ||
          parameter.pointer_depth !== 0 || !Array.isArray(parameter.array_dimensions) ||
          parameter.array_dimensions.length !== 0 || isPointer || form !== "value" ||
          measured.marshaled_form !== "value" || !replaySupported) continue;
      const scalar = typeScalar(parameter.type, "edl_abi parameter type");
      if (!scalar) continue;
      const size = nonnegative(measured.ms_size, "marshal_layout scalar ms_size");
      const signed = measured.ms_signed;
      if (![1, 2, 4, 8].includes(size) || scalar.width !== size * 8 ||
          typeof signed !== "boolean" || (signed ? "signed" : "unsigned") !== scalar.signedness) continue;
      const parameterInfo: ScalarParameter = {
        ordinal,
        param_index: paramIndex,
        width_bits: scalar.width,
        signedness: scalar.signedness,
      };
      scalarParameters.push(parameterInfo);
      scalarParameterByKey.set(ordinal + ":" + paramIndex, parameterInfo);
    }
    ecalls.set(ordinal, {
      ordinal,
      replaySupported: layoutEcall.replay_supported === true,
      params,
    });
  }
  scalarParameters.sort((left, right) =>
    left.ordinal - right.ordinal || left.param_index - right.param_index);
  return { ecalls, scalarParameters, scalarParameterByKey };
}

function legacyGuidanceFacts(value: unknown): unknown[] {
  const aggregate = record(value, "ir_facts");
  exactKeys(aggregate, ["schema", "facts"], ["schema", "facts"], "ir_facts");
  if (aggregate.schema !== "atfield-ir-facts-aggregate-v1") fail("ir_facts schema is unsupported");
  return array(aggregate.facts, "ir_facts.facts").map((raw, index) => {
    const fact = record(raw, "ir_facts.facts[" + index + "]");
    const required = [
      "schema", "translation_unit", "module_id", "backend_ir_sha256", "object_sha256",
      "compile_variant", "source", "callgraph_complete", "guidance_complete", "diagnostics",
      "definitions", "direct_calls", "unknown_indirect", "guidance_sites",
    ];
    exactKeys(fact, required, required, "ir_facts.facts[" + index + "]");
    if (fact.schema !== "atfield-ir-facts-v1") fail("IR fact schema is unsupported");
    const source = record(fact.source, "IR fact source");
    exactKeys(source, ["input_file", "ir_filename"], ["input_file", "ir_filename"], "IR fact source");
    const diagnostics = array(fact.diagnostics, "IR fact diagnostics");
    if (!diagnostics.every((entry) => typeof entry === "string")) fail("IR fact diagnostics must contain strings");
    return {
      schema: fact.schema,
      translation_unit: nonempty(fact.translation_unit, "IR fact translation_unit"),
      module_id: nonempty(fact.module_id, "IR fact module_id"),
      source: {
        input_file: nonempty(source.input_file, "IR fact source.input_file"),
        ir_filename: nonempty(source.ir_filename, "IR fact source.ir_filename"),
      },
      complete: boolean(fact.callgraph_complete, "IR fact callgraph_complete") &&
        boolean(fact.guidance_complete, "IR fact guidance_complete"),
      definitions: array(fact.definitions, "IR fact definitions"),
      direct_calls: array(fact.direct_calls, "IR fact direct_calls"),
      unknown_indirect: array(fact.unknown_indirect, "IR fact unknown_indirect"),
      guidance_sites: array(fact.guidance_sites, "IR fact guidance_sites"),
    };
  });
}

function guidanceReachability(value: unknown): unknown[] {
  const root = record(value, "reachability");
  if (root.schema !== "atfield-reachability-v1") fail("reachability schema is unsupported");
  const ecalls = array(root.ecalls, "reachability.ecalls");
  const seen = new Set<number>();
  return ecalls.map((raw, index) => {
    const item = record(raw, "reachability.ecalls[" + index + "]");
    const ordinal = nonnegative(item.ordinal, "reachability ECALL ordinal");
    if (seen.has(ordinal)) fail("reachability repeats ECALL ordinal " + ordinal);
    seen.add(ordinal);
    if (item.status !== "verified" && item.status !== "unknown") {
      fail("reachability status must be verified or unknown");
    }
    if (!Array.isArray(item.reachable_functions) ||
        !item.reachable_functions.every((entry) => typeof entry === "string")) {
      fail("reachability reachable_functions must be a string array");
    }
    return {
      ordinal,
      reachable_fields: Array.isArray(item.reachable_fields) ? item.reachable_fields : undefined,
      reachable_functions: item.reachable_functions,
      unknown_indirect: boolean(item.unknown_indirect, "reachability unknown_indirect"),
      unknown_external: boolean(item.unknown_external, "reachability unknown_external"),
      function_closure_complete: boolean(item.function_closure_complete, "reachability function_closure_complete"),
    };
  });
}

export function loadExplorerProfile(bundlePath: string): ExplorerProfile {
  const bundle = loadProfileBundle(bundlePath);
  const abiArtifact = readBundleArtifact(bundle, "edl_abi");
  const marshalArtifact = readBundleArtifact(bundle, "marshal_layout");
  const irArtifact = readBundleArtifact(bundle, "ir_facts");
  const reachabilityArtifact = readBundleArtifact(bundle, "reachability");
  const abi = record(abiArtifact.value, "edl_abi");
  if (abi.schema !== "atfield-edl-abi-v1") fail("edl_abi schema is unsupported");
  const layout = parseMarshalLayout(marshalArtifact.value, abi);
  const irFacts = legacyGuidanceFacts(irArtifact.value);
  const reachability = guidanceReachability(reachabilityArtifact.value);

function hexDigestBytes(hex: string): Buffer {
  return Buffer.from(normalizeDigest(hex, "marshal spec digest"), "hex");
}

function categoryCode(cat: unknown): number {
  switch (cat) {
    case "integer": return 1;
    case "character": return 2;
    case "enum": return 3;
    case "boolean": return 4;
    case "pointer": return 5;
    case "record":
    case "struct": return 12;
    case "union": return 13;
    case "array": return 14;
    default: return 255;
  }
}

function signednessCode(sign: unknown): number {
  if (sign === false || sign === "unsigned") return 0;
  if (sign === true || sign === "signed") return 1;
  return 255;
}

function typeKindCode(kind: unknown): number {
  switch (kind) {
    case "builtin": return 1;
    case "named": return 2;
    case "enum": return 3;
    case "struct":
    case "record": return 4;
    case "union": return 5;
    case "pointer": return 6;
    default: return 255;
  }
}

function directionCode(dir: unknown): number {
  switch (dir) {
    case "value": return 0;
    case "in": return 1;
    case "out": return 2;
    case "inout": return 3;
    default: return 0;
  }
}

function encodeMarshalProjection(
  marshalLayoutDoc: Record<string, unknown>,
  abiDoc: Record<string, unknown>,
  scalarParameterByKey: Map<string, ScalarParameter>,
  bundleManifestSha256: string,
  marshalLayoutSha256: string,
  edlAbiSha256: string,
): Uint8Array {
  const layoutEcalls = [...array(marshalLayoutDoc.ecalls, "marshal_layout.ecalls")]
    .map((e, idx) => record(e, "marshal_layout.ecalls[" + idx + "]"))
    .sort((a, b) => nonnegative(a.ordinal, "ordinal") - nonnegative(b.ordinal, "ordinal"));
  const abiEcalls = array(abiDoc.ecalls, "edl_abi.ecalls")
    .map((e, idx) => record(e, "edl_abi.ecalls[" + idx + "]"));
  const abiByOrdinal = new Map<number, Record<string, unknown>>();
  for (const ae of abiEcalls) {
    abiByOrdinal.set(nonnegative(ae.ordinal, "edl_abi ordinal"), ae);
  }

  const ecallBuffers: Buffer[] = [];
  for (const le of layoutEcalls) {
    const ordinal = nonnegative(le.ordinal, "marshal_layout ordinal");
    const ae = abiByOrdinal.get(ordinal);
    const abiParams = ae ? array(ae.parameters, "edl_abi parameters").map((p, i) => record(p, "param[" + i + "]")) : [];
    const paramIndexByName = new Map<string, number>();
    abiParams.forEach((ap, idx) => {
      if (typeof ap.name === "string") paramIndexByName.set(ap.name, idx);
    });
    const lparams = array(le.params, "marshal_layout params").map((p, i) => record(p, "lparam[" + i + "]"));
    const paramCount = lparams.length;
    const recordLen = 28 + paramCount * 56;
    const buf = Buffer.alloc(recordLen, 0);
    const msSize = typeof le.ms_size === "number" ? le.ms_size : 0;
    const hasRetval = le.has_retval === true && msSize > 0;
    const replaySupported = le.replay_supported === true;
    const flags = (replaySupported ? 1 : 0) | (hasRetval ? 2 : 0);

    buf.writeUInt32LE(recordLen, 0);
    buf.writeUInt32LE(ordinal, 4);
    buf.writeUInt32LE(msSize, 8);
    buf.writeUInt16LE(paramCount, 12);
    buf.writeUInt16LE(flags, 14);
    if (hasRetval) {
      const retOff = typeof le.retval_offset === "number" ? le.retval_offset : 0;
      const retSz = typeof le.retval_size === "number" ? le.retval_size : 4;
      const retCat = categoryCode(le.retval_type_category ?? "integer");
      const retSign = signednessCode(le.retval_signed ?? false);
      const retKind = typeKindCode(le.abi_return_type_kind ?? (isObject(ae?.return_type) ? (ae!.return_type as Record<string, unknown>).kind : "builtin"));
      buf.writeUInt32LE(retOff, 16);
      buf.writeUInt16LE(retSz, 20);
      buf[22] = retCat;
      buf[23] = retSign;
      buf[24] = retKind;
    }

    for (let pi = 0; pi < paramCount; pi++) {
      const lp = lparams[pi]!;
      const ap = abiParams[pi];
      const pOff = 28 + pi * 56;
      const isPtr = lp.is_pointer === true;
      const arrayDecay = lp.array_decay === true;
      const pReplay = lp.replay_supported === true;
      const userCheck = lp.user_check === true;
      const isStr = lp.string === true;
      const isWstr = lp.wstring === true;
      const scalarSupp = lp.scalar_mutation_supported === true || scalarParameterByKey.has(ordinal + ":" + pi);
      const pflags =
        (isPtr ? 1 : 0) |
        (arrayDecay ? 2 : 0) |
        (pReplay ? 4 : 0) |
        (userCheck ? 8 : 0) |
        (isStr ? 16 : 0) |
        (isWstr ? 32 : 0) |
        (scalarSupp ? 64 : 0);
      const msOff = typeof lp.ms_offset === "number" ? lp.ms_offset : 0;
      const msSz = typeof lp.ms_size === "number" ? lp.ms_size : (isPtr ? 8 : 4);
      const elemSz = typeof lp.element_size === "number" && lp.element_size > 0 ? lp.element_size : 0;
      const dir = directionCode(lp.direction ?? ap?.direction ?? "value");
      const cat = isPtr ? 5 : categoryCode(lp.ms_type_category ?? "integer");
      const sign = isPtr ? 255 : signednessCode(lp.ms_signed);
      const abiTypeObj = isObject(lp.abi_type) ? lp.abi_type : (isObject(ap?.type) ? ap!.type as Record<string, unknown> : null);
      const tKind = isPtr ? 6 : typeKindCode(lp.abi_type_kind ?? abiTypeObj?.kind ?? "builtin");
      const ptrDepth = isPtr ? (typeof lp.pointer_depth === "number" && lp.pointer_depth > 0 ? lp.pointer_depth : (arrayDecay ? 0 : 1)) : 0;
      const elemCat = elemSz > 0 ? categoryCode(lp.element_type_category ?? "integer") : 0;
      const elemSign = elemSz > 0 ? signednessCode(lp.element_signed) : 255;
      const elemKind = elemSz > 0 ? typeKindCode(lp.abi_element_type_kind ?? (isObject(abiTypeObj?.to) ? (abiTypeObj!.to as Record<string, unknown>).kind : "builtin")) : 0;

      let sizeSource = 0;
      let sizeParamIdx = 0xffff;
      let sizeLiteral = 0n;
      let countSource = 0;
      let countParamIdx = 0xffff;
      let countLiteral = 0n;
      const fixedCount = typeof lp.fixed_array_element_count === "number" && lp.fixed_array_element_count > 0
        ? BigInt(lp.fixed_array_element_count)
        : 0n;

      const applyBound = (bObj: Record<string, unknown> | null) => {
        if (!bObj || fixedCount > 0n) return;
        const bKind = bObj.kind;
        const src = isObject(bObj.source) ? bObj.source as Record<string, unknown> : null;
        if (!src) return;
        if (bKind === "size_bytes") {
          if (src.kind === "literal" && typeof src.value === "number" && src.value >= 0) {
            sizeSource = 1;
            sizeLiteral = BigInt(src.value);
          } else if (src.kind === "parameter" && typeof src.name === "string" && paramIndexByName.has(src.name)) {
            sizeSource = 2;
            sizeParamIdx = paramIndexByName.get(src.name)!;
          }
        } else if (bKind === "count_elements") {
          if (src.kind === "literal" && typeof src.value === "number" && src.value >= 0) {
            countSource = 1;
            countLiteral = BigInt(src.value);
          } else if (src.kind === "parameter" && typeof src.name === "string" && paramIndexByName.has(src.name)) {
            countSource = 2;
            countParamIdx = paramIndexByName.get(src.name)!;
          }
        }
      };
      if (isObject(lp.size_bound)) applyBound(lp.size_bound as Record<string, unknown>);
      if (isObject(lp.count_bound)) applyBound(lp.count_bound as Record<string, unknown>);
      if (isObject(lp.bound)) applyBound(lp.bound as Record<string, unknown>);

      buf.writeUInt16LE(pi, pOff + 0);
      buf.writeUInt16LE(pflags, pOff + 2);
      buf.writeUInt32LE(msOff, pOff + 4);
      buf.writeUInt32LE(msSz, pOff + 8);
      buf.writeUInt32LE(elemSz, pOff + 12);
      buf[pOff + 16] = dir;
      buf[pOff + 17] = cat;
      buf[pOff + 18] = sign;
      buf[pOff + 19] = tKind;
      buf[pOff + 20] = ptrDepth;
      buf[pOff + 21] = elemCat;
      buf[pOff + 22] = elemSign;
      buf[pOff + 23] = elemKind;
      buf[pOff + 24] = sizeSource;
      buf[pOff + 25] = countSource;
      buf.writeUInt16LE(sizeParamIdx, pOff + 26);
      buf.writeUInt16LE(countParamIdx, pOff + 28);
      buf.writeUInt16LE(0, pOff + 30);
      buf.writeBigUInt64LE(sizeLiteral, pOff + 32);
      buf.writeBigUInt64LE(countLiteral, pOff + 40);
      buf.writeBigUInt64LE(fixedCount, pOff + 48);
    }
    ecallBuffers.push(buf);
  }

  const bodyLen = ecallBuffers.reduce((acc, b) => acc + b.length, 0);
  const totalLen = 120 + bodyLen;
  const header = Buffer.alloc(120, 0);
  header.write("ATFMAR\0\0", 0, "ascii");
  header.writeUInt16LE(1, 8);
  header.writeUInt16LE(120, 10);
  header.writeUInt32LE(totalLen, 12);
  header.writeUInt32LE(ecallBuffers.length, 16);
  header.writeUInt32LE(0, 20);
  hexDigestBytes(bundleManifestSha256).copy(header, 24);
  hexDigestBytes(marshalLayoutSha256).copy(header, 56);
  hexDigestBytes(edlAbiSha256).copy(header, 88);
  return new Uint8Array(Buffer.concat([header, ...ecallBuffers]));
}
  const marshalSpecBytes = encodeMarshalProjection(
    record(marshalArtifact.value, "marshal_layout"),
    abi,
    layout.scalarParameterByKey,
    bundle.manifestSha256,
    marshalArtifact.digest,
    abiArtifact.digest,
  );
  const marshalSpecSha256 = sha256(marshalSpecBytes);
  return {
    bundle,
    binding: {
      bundleManifestSha256: bundle.manifestSha256,
      marshalLayoutSha256: marshalArtifact.digest,
    },
    edlAbiSha256: abiArtifact.digest,
    marshalSpecSha256,
    marshalSpecBytes,
    abi,
    ecalls: layout.ecalls,
    scalarParameters: layout.scalarParameters,
    scalarParameterByKey: layout.scalarParameterByKey,
    irFacts,
    reachability,
  };
}

export function generateProfileScalarCandidates(
  profile: ExplorerProfile,
  budget: number,
): ReturnType<typeof generateScalarReplacementCandidates> {
  if (!Number.isSafeInteger(budget) || budget < 0) fail("candidate budget must be a safe nonnegative integer");
  return generateScalarReplacementCandidates(
    profile.irFacts,
    profile.reachability,
    profile.scalarParameters,
    { budget },
  );
}

export function canonicalProfileJson(value: unknown): string {
  const canonical = (item: unknown): string => {
    if (item === null || typeof item === "string" || typeof item === "boolean") return JSON.stringify(item);
    if (typeof item === "number") {
      if (!Number.isFinite(item)) fail("canonical profile JSON cannot contain non-finite numbers");
      return JSON.stringify(item);
    }
    if (Array.isArray(item)) return "[" + item.map(canonical).join(",") + "]";
    if (isObject(item)) {
      const keys = Object.keys(item).sort();
      return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonical(item[key])).join(",") + "}";
    }
    return fail("canonical profile JSON contains an unsupported value");
  };
  return canonical(value);
}
