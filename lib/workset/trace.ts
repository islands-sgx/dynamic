import { readFileSync } from "node:fs";
import {
  canonicalEffects,
  formatRva,
  isObject,
  normalizeDigest,
  parseRva,
  parseStrictJson,
  sha256,
  type Effect,
  type ProfileBundle,
} from "../bundle/profile-bundle.ts";

export const TRACE_SCHEMA = "atfield-canonical-trace-v1";
export const CANONICAL_TRACE_SCHEMA = TRACE_SCHEMA;
export const FIELD_PHASES = ["S0_BRIDGE", "S1_ENTER", "S2_PRETOUCH", "S3_BODY"] as const;
export type FieldPhase = (typeof FIELD_PHASES)[number];
export type TraceMode = "profile" | "explore" | "verify-pretouch";

export interface TraceObservation {
  fieldId: string;
  pageRva: bigint;
  accessed: boolean;
  dirty: boolean;
  effects: Effect[];
}

export interface ParseTraceOptions {
  allowBusinessRejectionExit?: boolean;
  expectedSelectedEnclaveSha256?: string;
  requireReadinessInstalled?: boolean;
}

export interface ParsedTrace {
  runId: string;
  mode: string;
  traceSha256: string;
  bundleManifestSha256: string;
  layoutEpoch: string;
  selectedEnclaveSha256: string;
  ecallCount: number;
  observedFieldIds: string[];
  measuredFieldIds: string[];
  observations: TraceObservation[];
  runCompletion?: "complete" | "incomplete";
  processReturnCode?: number;
  termination?: "exited" | "signaled" | "timeout" | "unknown";
  businessRejected?: boolean;
}

const RUN_START_KEYS = new Set([
  "schema",
  "record_type",
  "run_id",
  "layout_epoch",
  "bundle_manifest_sha256",
  "instance_generation",
  "sample",
  "mode",
  "start_time",
  "selected_enclave_sha256",
  "host_sha256",
  "interposer_sha256",
  "artifacts",
  "seed_id",
  "argv",
]);

const ECALL_KEYS = new Set([
  "schema",
  "record_type",
  "run_id",
  "layout_epoch",
  "bundle_manifest_sha256",
  "instance_generation",
  "call_seq",
  "selector_ordinal",
  "selector_seq",
  "tag",
  "elapsed_ns",
  "sgx_status",
  "abi_return_type",
  "abi_return_value",
  "out_status_i32",
  "business_result",
  "measurement_valid",
  "measurement_invalid_reasons",
  "readiness_installed",
  "fields",
  "ecall_ad",
  "aex",
  "diagnostics",
]);

const RUN_END_KEYS = new Set([
  "schema",
  "record_type",
  "run_id",
  "layout_epoch",
  "bundle_manifest_sha256",
  "instance_generation",
  "process_return_code",
  "termination",
  "timed_out",
  "timeout",
  "ecall_count",
  "record_count",
  "completion",
  "incomplete_reasons",
]);

const AEX_KEYS = new Set([
  "count",
  "protocol_gate_count",
  "unexpected_count",
  "outside_window_count",
  "by_gate",
  "by_stage",
  "fault_events",
]);

const AEX_GATES = ["GATE_A", "GATE_B", "GATE_C"] as const;
const AEX_STAGES = ["S0_BRIDGE", "S1_ENTER", "S2_PRETOUCH", "S3_BODY", "POST_FIELD"] as const;

export class TraceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TraceError";
  }
}

export function validateSelectedEnclaveSha256(
  value: unknown,
  bundle: ProfileBundle,
  expectedSelectedEnclaveSha256?: string,
  label = "trace selected_enclave_sha256",
): string {
  let selected: string;
  try { selected = normalizeDigest(value, label); }
  catch (error) { fail((error as Error).message); }
  if (expectedSelectedEnclaveSha256 !== undefined) {
    if (selected !== normalizeDigest(expectedSelectedEnclaveSha256, label + " expected frozen target SHA-256")) {
      fail(label + " does not match the frozen run target");
    }
  } else if (selected !== bundle.identity.profileElfSha256 && selected !== bundle.identity.signedProfileElfSha256) {
    fail(label + " does not match the Profile bundle");
  }
  return selected;
}

function fail(message: string): never {
  throw new TraceError(message);
}

function assertAllowedKeys(value: Record<string, unknown>, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(label + " has unsupported key " + key);
  }
}

function nonemptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") fail(label + " must be a nonempty string");
  return value;
}

function booleanField(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") fail(label + " must be a boolean");
  return value;
}

function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(label + " must be a safe nonnegative integer");
  }
  return value;
}

function signedInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    fail(label + " must be a safe integer");
  }
  return value;
}

function rva(value: unknown, pageSize: number, label: string): bigint {
  let parsed: bigint;
  try {
    parsed = parseRva(value, label);
  } catch (error) {
    fail((error as Error).message);
  }
  if (parsed < 0n || parsed % BigInt(pageSize) !== 0n) fail(label + " must be page-aligned");
  return parsed;
}

export { canonicalEffects };

function accessEffects(maxPermissions: Effect[], accessed: boolean, dirty: boolean, label: string): Effect[] {
  if (!accessed && !dirty) return [];
  if (maxPermissions.includes("W") && maxPermissions.includes("X")) {
    fail(label + " violates W^X page permissions");
  }
  if (dirty) {
    if (!maxPermissions.includes("R") || !maxPermissions.includes("W")) {
      fail(label + " reports D on a page without R|W permission");
    }
    return ["R", "W"];
  }
  if (maxPermissions.includes("X")) {
    return maxPermissions.includes("R") ? ["X", "R"] : ["X"];
  }
  if (maxPermissions.includes("W")) {
    if (!maxPermissions.includes("R")) fail(label + " W page lacks R permission");
    return ["R", "W"];
  }
  if (maxPermissions.includes("R")) return ["R"];
  fail(label + " A bit is set on a page without usable permissions");
}

function validateCommonEnvelope(
  record: Record<string, unknown>,
  expectedRunId: string,
  bundle: ProfileBundle,
  label: string,
): void {
  if (record.schema !== TRACE_SCHEMA) fail(label + " must use schema " + TRACE_SCHEMA);
  if (nonemptyString(record.run_id, label + ".run_id") !== expectedRunId) {
    fail(label + ".run_id does not match run_start.run_id");
  }
  if (nonemptyString(record.layout_epoch, label + ".layout_epoch") !== bundle.layoutEpoch) {
    fail(label + ".layout_epoch does not match the Profile bundle");
  }
  const bundleDigest = normalizeDigest(record.bundle_manifest_sha256, label + ".bundle_manifest_sha256");
  if (bundleDigest !== bundle.manifestSha256) {
    fail(label + ".bundle_manifest_sha256 does not match the Profile bundle");
  }
}

interface MutablePageObservation {
  accessed: boolean;
  dirty: boolean;
  effects: Set<Effect>;
}

function validatePhase(
  value: unknown,
  label: string,
  bundle: ProfileBundle,
  pagesByRva: Map<bigint, MutablePageObservation>,
  collectEffects: boolean,
): void {
  if (!isObject(value)) fail(label + " must be an object");
  assertAllowedKeys(value, new Set(["page_size", "complete", "page_effects", "duration_ns"]), label);
  if (integer(value.page_size, label + ".page_size") !== bundle.pageSize) {
    fail(label + ".page_size does not match the Profile bundle");
  }
  if (!booleanField(value.complete, label + ".complete")) {
    fail(label + " page set is not complete");
  }
  if (!Array.isArray(value.page_effects)) fail(label + ".page_effects must be an array");
  for (const [index, rawEffect] of value.page_effects.entries()) {
    const effectLabel = label + ".page_effects[" + index + "]";
    if (!isObject(rawEffect)) fail(effectLabel + " must be an object");
    assertAllowedKeys(rawEffect, new Set(["rva", "a", "d"]), effectLabel);
    const pageRva = rva(rawEffect.rva, bundle.pageSize, effectLabel + ".rva");
    const universe = bundle.pageUniverse.get(pageRva);
    if (!universe) fail(label + " references page outside page_universe: " + formatRva(pageRva));
    const accessed = booleanField(rawEffect.a, effectLabel + ".a");
    const dirty = booleanField(rawEffect.d, effectLabel + ".d");
    if (dirty && !accessed) fail(effectLabel + " has D without A");
    const effects = accessEffects(universe.maxPermissions, accessed, dirty, effectLabel);
    if (collectEffects && effects.length > 0) {
      let existing = pagesByRva.get(pageRva);
      if (!existing) {
        existing = { accessed: false, dirty: false, effects: new Set<Effect>() };
        pagesByRva.set(pageRva, existing);
      }
      if (accessed) existing.accessed = true;
      if (dirty) existing.dirty = true;
      effects.forEach((effect) => existing!.effects.add(effect));
    }
  }
}

function validateAex(
  aexValue: unknown,
  fieldCount: number,
  runMode: string,
  lineLabel: string,
): void {
  if (aexValue === undefined) return;
  if (!isObject(aexValue)) fail(lineLabel + ".aex must be an object");
  assertAllowedKeys(aexValue, AEX_KEYS, lineLabel + ".aex");
  const count = integer(aexValue.count, lineLabel + ".aex.count");
  const faultEvents = aexValue.fault_events === undefined ? [] : aexValue.fault_events;
  if (!Array.isArray(faultEvents)) fail(lineLabel + ".aex.fault_events must be an array");
  const hasClassification =
    aexValue.protocol_gate_count !== undefined ||
    aexValue.unexpected_count !== undefined ||
    aexValue.outside_window_count !== undefined ||
    aexValue.by_gate !== undefined ||
    aexValue.by_stage !== undefined;
  if (!hasClassification) {
    if (count > 0 || faultEvents.length > 0) fail(lineLabel + " has nonzero AEX count or unclassified fault_events and is incomplete");
    return;
  }
  const protocolGateCount = integer(aexValue.protocol_gate_count, lineLabel + ".aex.protocol_gate_count");
  const unexpectedCount = integer(aexValue.unexpected_count, lineLabel + ".aex.unexpected_count");
  const outsideWindowCount = aexValue.outside_window_count === undefined ? 0 :
    integer(aexValue.outside_window_count, lineLabel + ".aex.outside_window_count");
  if (count !== protocolGateCount + unexpectedCount + outsideWindowCount) {
    fail(lineLabel + ".aex.count does not equal protocol_gate_count + unexpected_count + outside_window_count");
  }
  if (!isObject(aexValue.by_gate)) fail(lineLabel + ".aex.by_gate must be an object");
  assertAllowedKeys(aexValue.by_gate, new Set(AEX_GATES), lineLabel + ".aex.by_gate");
  const gateA = integer(aexValue.by_gate.GATE_A, lineLabel + ".aex.by_gate.GATE_A");
  const gateB = integer(aexValue.by_gate.GATE_B, lineLabel + ".aex.by_gate.GATE_B");
  const gateC = integer(aexValue.by_gate.GATE_C, lineLabel + ".aex.by_gate.GATE_C");
  if (gateA + gateB + gateC !== protocolGateCount) {
    fail(lineLabel + ".aex.by_gate sum does not equal protocol_gate_count");
  }
  if (!isObject(aexValue.by_stage)) fail(lineLabel + ".aex.by_stage must be an object");
  assertAllowedKeys(aexValue.by_stage, new Set(AEX_STAGES), lineLabel + ".aex.by_stage");
  const stageProtocolExpected: Record<(typeof AEX_STAGES)[number], number> = {
    S0_BRIDGE: gateA,
    S1_ENTER: gateB,
    S2_PRETOUCH: gateC,
    S3_BODY: 0,
    POST_FIELD: 0,
  };
  let stageUnexpectedSum = 0;
  let stageOutsideWindowSum = 0;
  for (const stage of AEX_STAGES) {
    const stageObj = aexValue.by_stage[stage];
    if (!isObject(stageObj)) fail(lineLabel + ".aex.by_stage." + stage + " must be an object");
    assertAllowedKeys(stageObj, new Set(["protocol_gate", "unexpected", "outside_window"]), lineLabel + ".aex.by_stage." + stage);
    const stageProto = integer(stageObj.protocol_gate, lineLabel + ".aex.by_stage." + stage + ".protocol_gate");
    const stageUnexp = integer(stageObj.unexpected, lineLabel + ".aex.by_stage." + stage + ".unexpected");
    const stageOutside = stageObj.outside_window === undefined ? 0 :
      integer(stageObj.outside_window, lineLabel + ".aex.by_stage." + stage + ".outside_window");
    if (stageOutside > 0 && stage !== "POST_FIELD") {
      fail(lineLabel + ".aex.by_stage." + stage + " cannot classify an AEX outside the Field window");
    }
    stageOutsideWindowSum += stageOutside;
    if (stageProto !== stageProtocolExpected[stage]) {
      fail(lineLabel + ".aex.by_stage." + stage + ".protocol_gate does not match verified gate boundary count");
    }
    stageUnexpectedSum += stageUnexp;
  }
  if (stageUnexpectedSum !== unexpectedCount) {
    fail(lineLabel + ".aex.by_stage unexpected sum does not equal unexpected_count");
  }
  if (stageOutsideWindowSum !== outsideWindowCount) {
    fail(lineLabel + ".aex.by_stage outside_window sum does not equal outside_window_count");
  }
  if (faultEvents.length !== outsideWindowCount) {
    fail(lineLabel + ".aex.fault_events must preserve every outside_window AEX and no other event");
  }
  for (let i = 0; i < faultEvents.length; i++) {
    const event = faultEvents[i];
    if (!isObject(event) ||
        event.outside_window !== true ||
        event.stage !== "POST_FIELD" ||
        event.active_flag !== 0 ||
        event.active_flag_valid !== true ||
        event.host_gate !== 80 ||
        event.watcher_slot_closed !== true ||
        event.strict_retractions_clear !== true ||
        event.pte_healed_observed !== false) {
      fail(lineLabel + ".aex.fault_events[" + i + "] lacks completed Gate D outside-window proof");
    }
  }
  if (unexpectedCount > 0) {
    fail(lineLabel + " has nonzero AEX count and is incomplete");
  }
  if (fieldCount === 0 && protocolGateCount > 0) {
    fail(lineLabel + " reports protocol_gate AEX without any entered Field");
  }
  if (runMode === "verify-pretouch") {
    if (gateC !== 0) {
      fail(lineLabel + " verify-pretouch mode must preserve TLB at GATE_C (GATE_C count must be 0)");
    }
    if (fieldCount > 0 && (gateA < fieldCount || gateB < fieldCount)) {
      fail(lineLabel + " verify-pretouch mode is missing required GATE_A/GATE_B shootdowns");
    }
  } else if (runMode === "profile" || runMode === "explore") {
    if (fieldCount > 0 && (gateA < fieldCount || gateB < fieldCount || gateC < fieldCount)) {
      fail(lineLabel + " acquisition mode is missing required GATE_A/GATE_B/GATE_C shootdowns");
    }
  }
}

export function parseCanonicalTrace(
  source: string,
  label: string,
  bundle: ProfileBundle,
  options?: ParseTraceOptions,
): ParsedTrace {
  if (source.startsWith("\uFEFF")) fail(label + " must not start with a UTF-8 BOM");
  const rawLines = source.split(/\r?\n/);
  if (rawLines.at(-1) === "") rawLines.pop();
  if (rawLines.length < 2) fail(label + " last record must be run_end");
  const records = rawLines.map((line, index) => {
    if (line.trim() === "") fail(label + " line " + (index + 1) + " is empty");
    let parsed: unknown;
    try {
      parsed = parseStrictJson(line, label + " line " + (index + 1));
    } catch (error) {
      fail((error as Error).message);
    }
    if (!isObject(parsed)) fail(label + " line " + (index + 1) + " must be a JSON object");
    return parsed;
  });

  const first = records[0]!;
  assertAllowedKeys(first, RUN_START_KEYS, label + " run_start");
  if (first.record_type !== "run_start") fail(label + " must start with a run_start record");
  const runId = nonemptyString(first.run_id, label + " run_start.run_id");
  validateCommonEnvelope(first, runId, bundle, label + " run_start");
  if (first.instance_generation !== null) fail(label + " run_start.instance_generation must be null");
  nonemptyString(first.sample, label + " run_start.sample");
  const runMode = nonemptyString(first.mode, label + " run_start.mode");
  nonemptyString(first.start_time, label + " run_start.start_time");
  const selectedEnclaveSha256 = validateSelectedEnclaveSha256(
    first.selected_enclave_sha256,
    bundle,
    options?.expectedSelectedEnclaveSha256,
    label + " run_start.selected_enclave_sha256",
  );
  if (first.argv !== undefined && (!Array.isArray(first.argv) || !first.argv.every((arg) => typeof arg === "string"))) {
    fail(label + " run_start.argv must be a string array");
  }

  const last = records.at(-1)!;
  if (last.record_type !== "run_end") fail(label + " last record must be run_end");
  assertAllowedKeys(last, RUN_END_KEYS, label + " run_end");
  validateCommonEnvelope(last, runId, bundle, label + " run_end");
  const timedOutRaw = last.timed_out ?? last.timeout;
  if (booleanField(timedOutRaw, label + " run_end.timed_out")) fail(label + " timed out");
  const procRc = signedInteger(last.process_return_code, label + " run_end.process_return_code");
  const terminationRaw = last.termination === undefined ? "unknown" : last.termination;
  if (terminationRaw !== "exited" && terminationRaw !== "signaled" &&
      terminationRaw !== "timeout" && terminationRaw !== "unknown") {
    fail(label + " run_end.termination must be exited, signaled, timeout, or unknown");
  }
  const termination = terminationRaw as "exited" | "signaled" | "timeout" | "unknown";
  const allowBizReject = options?.allowBusinessRejectionExit === true;
  if (!allowBizReject) {
    if (last.completion !== "complete") fail(label + " completion is not complete");
    if (procRc !== 0) {
      fail(label + " process_return_code is nonzero");
    }
    if (!Array.isArray(last.incomplete_reasons) || last.incomplete_reasons.length > 0) {
      fail(label + " has incomplete_reasons in run_end");
    }
  } else {
    if (last.completion !== "complete" && last.completion !== "incomplete") {
      fail(label + " completion must be complete or incomplete");
    }
    if (!Array.isArray(last.incomplete_reasons) ||
        !last.incomplete_reasons.every((r) => typeof r === "string")) {
      fail(label + " incomplete_reasons must be a string array");
    }
    if (last.completion === "complete") {
      if (procRc !== 0) fail(label + " process_return_code is nonzero");
      if (last.incomplete_reasons.length > 0) fail(label + " has incomplete_reasons in run_end");
    } else {
      if (termination !== "exited") {
        fail(label + " business-rejection runs must exit cleanly (termination=" + termination + ")");
      }
      if (procRc === 0) fail(label + " completion is not complete");
      const expectedReason = "host process exit code was " + String(procRc);
      if (last.incomplete_reasons.length === 0 ||
          last.incomplete_reasons.some((r) => r !== expectedReason)) {
        fail(label + " incomplete run has non-business-exit incomplete_reasons");
      }
    }
  }

  const ecallRecords = records.slice(1, -1);
  const expectedEcallCount = integer(last.ecall_count ?? last.record_count, label + " run_end.ecall_count");
  if (ecallRecords.length !== expectedEcallCount) {
    fail(label + " ecall_count does not match emitted ECALL records");
  }

  let currentGeneration = 0;
  const selectorCounts = new Map<string, number>();
  const knownFields = new Set(bundle.fields.map((field) => field.id));
  const knownSelectors = new Map(bundle.selectors.map((selector) => [selector.ordinal, selector]));
  const observedFieldIds = new Set<string>();
  const measuredFieldIds = new Set<string>();
  const observationsByFieldAndPage = new Map<string, Map<bigint, MutablePageObservation>>();

  for (const [index, record] of ecallRecords.entries()) {
    const lineLabel = label + " ecall[" + index + "]";
    assertAllowedKeys(record, ECALL_KEYS, lineLabel);
    if (record.record_type !== "ecall") fail(lineLabel + " must have record_type ecall");
    validateCommonEnvelope(record, runId, bundle, lineLabel);
    const callSeq = integer(record.call_seq, lineLabel + ".call_seq");
    if (index === 0 && callSeq !== 0) fail(lineLabel + " call_seq must start at zero");
    if (callSeq !== index) fail(lineLabel + " call_seq has a gap");
    const generation = integer(record.instance_generation, lineLabel + ".instance_generation");
    if (generation < 1 || generation < currentGeneration) {
      fail(lineLabel + ".instance_generation must be positive and nondecreasing");
    }
    currentGeneration = generation;

    const selectorOrdinal = integer(record.selector_ordinal, lineLabel + ".selector_ordinal");
    const selector = knownSelectors.get(selectorOrdinal);
    if (!selector) fail(lineLabel + " references unknown selector ordinal " + selectorOrdinal);
    const selectorSeq = integer(record.selector_seq, lineLabel + ".selector_seq");
    const selectorKey = generation + ":" + selectorOrdinal;
    const expectedSelectorSeq = selectorCounts.get(selectorKey) ?? 0;
    if (selectorSeq !== expectedSelectorSeq) {
      fail(lineLabel + " selector_seq must increment by one within generation " + generation);
    }
    selectorCounts.set(selectorKey, expectedSelectorSeq + 1);

    signedInteger(record.sgx_status, lineLabel + ".sgx_status");
    if (record.readiness_installed !== undefined) booleanField(record.readiness_installed, lineLabel + ".readiness_installed");
    if (options?.requireReadinessInstalled && !booleanField(record.readiness_installed, lineLabel + ".readiness_installed")) {
      fail(lineLabel + " ReadyTable was not installed for the measured ECALL");
    }
    if (!booleanField(record.measurement_valid, lineLabel + ".measurement_valid")) {
      fail(lineLabel + " measurement is invalid");
    }
    if (!Array.isArray(record.measurement_invalid_reasons) || record.measurement_invalid_reasons.length > 0) {
      fail(lineLabel + " measurement is invalid");
    }
    if (!Array.isArray(record.fields)) fail(lineLabel + ".fields must be an array");

    validateAex(record.aex, record.fields.length, runMode, lineLabel);

    for (const [fieldIndex, rawField] of record.fields.entries()) {
      const fieldLabel = lineLabel + ".fields[" + fieldIndex + "]";
      if (!isObject(rawField)) fail(fieldLabel + " must be an object");
      assertAllowedKeys(rawField, new Set(["field_id", "phases", "s0", "s1", "s2", "s3", "gate_c_postclear"]), fieldLabel);
      const fieldId = nonemptyString(rawField.field_id, fieldLabel + ".field_id");
      if (!knownFields.has(fieldId)) fail(lineLabel + " references unknown Field " + fieldId);
      if (!selector.reachableFields.includes(fieldId)) {
        fail(lineLabel + " observes Field " + fieldId + " outside selector " + selector.name + " reachable_fields");
      }

      const phases = isObject(rawField.phases) ? rawField.phases : null;
      const phaseObject: Record<FieldPhase, unknown> = phases ? {
        S0_BRIDGE: phases.S0_BRIDGE,
        S1_ENTER: phases.S1_ENTER,
        S2_PRETOUCH: phases.S2_PRETOUCH,
        S3_BODY: phases.S3_BODY,
      } : {
        S0_BRIDGE: rawField.s0,
        S1_ENTER: rawField.s1,
        S2_PRETOUCH: rawField.s2,
        S3_BODY: rawField.s3,
      };
      if (phases) assertAllowedKeys(phases, new Set(FIELD_PHASES), fieldLabel + ".phases");

      const pagesByRva = new Map<bigint, MutablePageObservation>();
      for (const phaseName of FIELD_PHASES) {
        validatePhase(
          phaseObject[phaseName],
          lineLabel + " Field " + fieldId + " " + phaseName,
          bundle,
          pagesByRva,
          phaseName === "S3_BODY",
        );
      }
      if (runMode !== "verify-pretouch" && pagesByRva.size === 0) {
        fail(lineLabel + " Field " + fieldId + " S3_BODY has no observed page effects");
      }
      measuredFieldIds.add(fieldId);
      if (pagesByRva.size > 0) {
        observedFieldIds.add(fieldId);
        let fieldMap = observationsByFieldAndPage.get(fieldId);
        if (!fieldMap) {
          fieldMap = new Map<bigint, MutablePageObservation>();
          observationsByFieldAndPage.set(fieldId, fieldMap);
        }
        for (const [pageRva, obs] of pagesByRva) {
          let merged = fieldMap.get(pageRva);
          if (!merged) {
            merged = { accessed: false, dirty: false, effects: new Set<Effect>() };
            fieldMap.set(pageRva, merged);
          }
          if (obs.accessed) merged.accessed = true;
          if (obs.dirty) merged.dirty = true;
          obs.effects.forEach((eff) => merged!.effects.add(eff));
        }
      }
    }
  }

  const finalGeneration = last.instance_generation;
  if ((ecallRecords.length === 0 && finalGeneration !== null) ||
      (ecallRecords.length > 0 && integer(finalGeneration, label + " run_end.instance_generation") !== currentGeneration)) {
    fail(label + " run_end.instance_generation does not match the final ECALL generation");
  }

  const observations: TraceObservation[] = [];
  for (const [fieldId, fieldMap] of observationsByFieldAndPage) {
    const sortedRvas = [...fieldMap.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const pageRva of sortedRvas) {
      const obs = fieldMap.get(pageRva)!;
      observations.push({
        fieldId,
        pageRva,
        accessed: obs.accessed,
        dirty: obs.dirty,
        effects: canonicalEffects(obs.effects),
      });
    }
  }

  const anyEcallRejected = ecallRecords.some((rec) => {
    if (typeof rec.sgx_status === "number" && rec.sgx_status !== 0) return true;
    if (typeof rec.out_status_i32 === "number" && rec.out_status_i32 !== 0) return true;
    if (typeof rec.abi_return_value === "number" && rec.abi_return_value !== 0) return true;
    if (typeof rec.abi_return_value === "string" && rec.abi_return_value !== "0") return true;
    if (isObject(rec.business_result)) {
      if (typeof rec.business_result.status === "number" && rec.business_result.status !== 0) return true;
      if (typeof rec.business_result.value === "number" && rec.business_result.value !== 0) return true;
      if (typeof rec.business_result.value === "string" && rec.business_result.value !== "0") return true;
    }
    return false;
  });
  return {
    runId,
    mode: runMode,
    traceSha256: sha256(new TextEncoder().encode(source)),
    bundleManifestSha256: bundle.manifestSha256,
    layoutEpoch: bundle.layoutEpoch,
    selectedEnclaveSha256,
    ecallCount: ecallRecords.length,
    observedFieldIds: [...observedFieldIds],
    measuredFieldIds: [...measuredFieldIds],
    observations,
    runCompletion: last.completion === "complete" ? "complete" : "incomplete",
    processReturnCode: procRc,
    termination,
    businessRejected: (termination === "exited" && procRc !== 0) || anyEcallRejected,
  };
}

export function readCanonicalTrace(
  filename: string,
  bundle: ProfileBundle,
  options?: ParseTraceOptions,
): ParsedTrace {
  let bytes: Uint8Array;
  try {
    bytes = readFileSync(filename);
  } catch (error) {
    fail("cannot read trace " + filename + ": " + String(error));
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail("trace " + filename + " must not start with a UTF-8 BOM");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail("trace " + filename + " is not valid UTF-8");
  }
  return parseCanonicalTrace(text, filename, bundle, options);
}
