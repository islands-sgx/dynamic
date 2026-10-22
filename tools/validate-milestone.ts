import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadExplorerProfile } from "../lib/explorer/profile.ts";
import { exploreSeeds, type ExplorerResult } from "../lib/explorer/explorer.ts";
import { readFinalizableCorpus } from "../lib/explorer/corpus.ts";
import { parseCallCapture, encodeMutationSpec, type CallCaptureDocument, type MutationBinding, type ScalarMutationRule } from "../lib/explorer/contract.ts";
import { deriveCandidatesFromCase } from "../lib/explorer/planner.ts";
import { buildWorkset } from "../lib/workset/build.ts";
import { readCanonicalTrace, type ParsedTrace } from "../lib/workset/trace.ts";
import type { ProfileBundle } from "../lib/bundle/profile-bundle.ts";
import { linkedDataflowFailure } from "../lib/explorer/linked-proof.ts";
import { proveColdFirstFieldTransfer } from "../lib/explorer/cold-proof.ts";

export const FORMAL_SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm", "ehsm-opt-1", "ehsm-opt-2"] as const;
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RESERVED_PHASES = new Set(["default", "self-test"]);
const FORMAL_SEED_REGISTRY_PATH = path.join(REPO_ROOT, "formal", "host-seeds.json");
export type FormalAcquisitionStrategy = "explore" | "baseline-only";
export interface FormalHostSeedSpec { id: string; phase: string; role: "main" | "supplemental"; args: string[]; includeInWorkset: boolean }
export interface FormalPhaseSpec { id: string; name: string; role: "main" | "supplemental"; args: string[]; includeInWorkset: boolean }
export interface FormalHoldoutContract { timingSelectorNames: string[]; expectedTimingCalls: number }
export interface ResolvedHoldoutContract { timingSelectorOrdinals: number[]; expectedTimingCalls: number }
interface FormalTargetConfig { strategy: FormalAcquisitionStrategy; phases: FormalPhaseSpec[]; additionalSeeds: FormalHostSeedSpec[]; holdout: FormalHoldoutContract | null }
export interface FormalTargetSnapshot { sample: string; strategy: FormalAcquisitionStrategy; phases: FormalPhaseSpec[]; holdout: FormalHoldoutContract | null }
export interface FormalRegistrySnapshot { sha256: string; targets: FormalTargetSnapshot[] }
function parseFormalSeedRegistry(bytes: string): Record<string, unknown> {
  const doc = asRecord(JSON.parse(bytes), "formal host seed registry");
  if (doc.schema !== "atfield-formal-host-seed-registry-v1") throw new TypeError("invalid formal host seed registry schema");
  return asRecord(doc.targets, "formal host seed registry targets");
}
function formalSeedRegistry(): Record<string, unknown> {
  if (!existsSync(FORMAL_SEED_REGISTRY_PATH)) return {};
  return parseFormalSeedRegistry(readFileSync(FORMAL_SEED_REGISTRY_PATH, "utf8"));
}
function validateFormalSeedArray(raw: unknown, sample: string, label: string): FormalHostSeedSpec[] {
  if (!Array.isArray(raw)) throw new TypeError(label + " must be an array for " + sample);
  const ids = new Set<string>(), phases = new Set<string>();
  return raw.map((item, index) => {
    const seed = asRecord(item, label + " " + index);
    if (typeof seed.id !== "string" || seed.id.trim() === "" || seed.id.includes("\0") || ids.has(seed.id))
      throw new TypeError(label + " IDs must be unique, nonempty strings for " + sample);
    if (typeof seed.phase !== "string" || seed.phase.trim() === "" || seed.phase.includes("\0") || phases.has(seed.phase))
      throw new TypeError(label + " phase names must be unique, nonempty strings for " + sample);
    if (seed.role !== "main" && seed.role !== "supplemental")
      throw new TypeError(label + " role must be main or supplemental for " + sample);
    if (!Array.isArray(seed.args) || !seed.args.every((arg) => typeof arg === "string" && !arg.includes("\0")))
      throw new TypeError(label + " args must be NUL-free strings for " + sample);
    if (seed.includeInWorkset !== undefined && typeof seed.includeInWorkset !== "boolean")
      throw new TypeError(label + " includeInWorkset must be boolean for " + sample);
    ids.add(seed.id); phases.add(seed.phase);
    return { id: seed.id, phase: seed.phase, role: seed.role, args: [...seed.args], includeInWorkset: seed.includeInWorkset !== false };
  });
}
function formalTargetConfig(sample: string, registry = formalSeedRegistry()): FormalTargetConfig {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(sample)) throw new TypeError("invalid sample ID");
  const raw = registry[sample];
  const config = raw === undefined ? {} : asRecord(raw, "formal target config " + sample);
  const strategy = config.strategy ?? "explore";
  if (strategy !== "explore" && strategy !== "baseline-only")
    throw new TypeError("formal acquisition strategy must be explore or baseline-only for " + sample);
  if (strategy === "baseline-only") {
    const seeds = validateFormalSeedArray(config.phases, sample, "phases");
    const names = new Set<string>(RESERVED_PHASES), ids = new Set<string>();
    for (const seed of seeds) {
      if (names.has(seed.phase) || ids.has(seed.id)) throw new TypeError("formal phase names and IDs must be unique for " + sample);
      names.add(seed.phase); ids.add(seed.id);
    }
    if (!seeds.some((seed) => seed.role === "main" && seed.includeInWorkset) ||
        !seeds.some((seed) => !seed.includeInWorkset))
      throw new TypeError("baseline-only target requires a main training phase and an isolated holdout phase for " + sample);
    const rawHoldout = asRecord(config.holdout, "baseline-only holdout contract " + sample);
    const timingSelectorNames = rawHoldout.timingSelectorNames;
    const expectedTimingCalls = rawHoldout.expectedTimingCalls;
    if (!Array.isArray(timingSelectorNames) || timingSelectorNames.length === 0 ||
        !timingSelectorNames.every((name) => typeof name === "string" && name.trim() !== "" && !name.includes("\0")) ||
        new Set(timingSelectorNames).size !== timingSelectorNames.length ||
        !Number.isSafeInteger(expectedTimingCalls) || (expectedTimingCalls as number) < 1)
      throw new TypeError("baseline-only holdout requires unique selector names and a positive expected call count for " + sample);
    const holdout = { timingSelectorNames: [...timingSelectorNames] as string[], expectedTimingCalls: expectedTimingCalls as number };
    return { strategy, additionalSeeds: [], holdout, phases: seeds.map((seed) => ({
      id: seed.id, name: seed.phase, role: seed.role, args: seed.args, includeInWorkset: seed.includeInWorkset,
    })) };
  }
  const additionalSeeds = validateFormalSeedArray(config.additionalSeeds ?? [], sample, "additionalSeeds");
  if (additionalSeeds.some((seed) => RESERVED_PHASES.has(seed.phase)))
    throw new TypeError("additional formal phase names must not shadow built-in phases for " + sample);
  const phases: FormalPhaseSpec[] = [
    { id: "default", name: "default", role: "main", args: [], includeInWorkset: true },
    { id: "self-test", name: "self-test", role: "supplemental", args: ["--self-test"], includeInWorkset: true },
    ...additionalSeeds.map((seed) => ({ id: seed.id, name: seed.phase, role: seed.role, args: [...seed.args], includeInWorkset: seed.includeInWorkset })),
  ];
  const ids = new Set<string>(), names = new Set<string>();
  for (const phase of phases) {
    if (ids.has(phase.id) || names.has(phase.name)) throw new TypeError("formal phase seeds must have unique IDs and names for " + sample);
    ids.add(phase.id); names.add(phase.name);
  }
  if (config.holdout !== undefined) throw new TypeError("holdout contract is only valid for baseline-only targets: " + sample);
  return { strategy, phases, additionalSeeds, holdout: null };
}
export function loadFormalHostSeeds(sample: string): FormalHostSeedSpec[] {
  return formalTargetConfig(sample).additionalSeeds;
}
export function formalAcquisitionStrategyForSample(sample: string, snapshot?: FormalRegistrySnapshot): FormalAcquisitionStrategy {
  return snapshot?.targets.find((target) => target.sample === sample)?.strategy ?? formalTargetConfig(sample).strategy;
}
export function formalPhaseSpecsForSample(sample: string, snapshot?: FormalRegistrySnapshot): FormalPhaseSpec[] {
  const target = snapshot?.targets.find((item) => item.sample === sample);
  return target ? target.phases : formalTargetConfig(sample).phases;
}
export interface HoldoutTraceEvidence { parsed: ParsedTrace; traceText: string }
export interface S3HoldoutCoverage {
  passed: boolean;
  trainingTraceCount: number;
  holdoutTraceCount: number;
  observedEffects: number;
  missedEffects: string[];
  trainingFieldIds: string[];
  holdoutFieldIds: string[];
  missingFieldIds: string[];
  timingCallCount: number;
  invalidTimingCalls: number;
  duplicateTimingCalls: number;
}
export function resolveFormalHoldoutContract(
  bundle: Pick<ProfileBundle, "selectors" | "fields">,
  contract: FormalHoldoutContract,
): ResolvedHoldoutContract {
  const byName = new Map<string, ProfileBundle["selectors"][number]>();
  for (const selector of bundle.selectors) {
    if (byName.has(selector.name)) throw new TypeError("Profile bundle has duplicate selector name: " + selector.name);
    byName.set(selector.name, selector);
  }
  const selectors = contract.timingSelectorNames.map((name) => {
    const selector = byName.get(name);
    if (!selector) throw new TypeError("configured holdout timing selector is absent from Profile bundle: " + name);
    return selector;
  });
  const timingFields = new Set<string>(selectors.flatMap((selector) => selector.reachableFields));
  if (bundle.fields.some((field) => !timingFields.has(field.id)))
    throw new TypeError("configured holdout timing selectors do not reach every Profile Field");
  return { timingSelectorOrdinals: selectors.map((selector) => selector.ordinal),
    expectedTimingCalls: contract.expectedTimingCalls };
}
function s3EffectKeys(traces: readonly ParsedTrace[]): Set<string> {
  const keys = new Set<string>();
  for (const trace of traces) for (const observation of trace.observations) {
    for (const effect of observation.effects)
      keys.add(JSON.stringify([observation.fieldId, "0x" + observation.pageRva.toString(16), effect]));
  }
  return keys;
}
export function compareS3HoldoutCoverage(
  trainingTraces: readonly ParsedTrace[], holdoutTraces: readonly HoldoutTraceEvidence[], contract: ResolvedHoldoutContract,
): S3HoldoutCoverage {
  const training = s3EffectKeys(trainingTraces);
  const holdout = s3EffectKeys(holdoutTraces.map((item) => item.parsed));
  const missedEffects = [...holdout].filter((key) => !training.has(key)).sort();
  const trainingFieldIds = [...new Set(trainingTraces.flatMap((trace) => trace.observedFieldIds))].sort();
  const holdoutFieldIds = [...new Set(holdoutTraces.flatMap((item) => item.parsed.observedFieldIds))].sort();
  const missingFieldIds = trainingFieldIds.filter((fieldId) => !holdoutFieldIds.includes(fieldId));
  const selectors = new Set(contract.timingSelectorOrdinals);
  const timingCalls = new Set<string>();
  let invalidTimingCalls = 0, duplicateTimingCalls = 0;
  for (const evidence of holdoutTraces) for (const line of evidence.traceText.split(/\r?\n/)) {
    if (!line) continue;
    let raw: unknown;
    try { raw = JSON.parse(line); } catch { invalidTimingCalls++; continue; }
    if (!raw || typeof raw !== "object" || (raw as Record<string, unknown>).record_type !== "ecall" ||
        !selectors.has((raw as Record<string, unknown>).selector_ordinal as number)) continue;
    const record = raw as Record<string, unknown>;
    const key = [record.instance_generation, record.call_seq, record.selector_ordinal, record.selector_seq].join(":");
    if (timingCalls.has(key)) duplicateTimingCalls++;
    timingCalls.add(key);
    const fields = Array.isArray(record.fields) ? record.fields : [];
    const fieldIds = new Set(fields.flatMap((field) => field && typeof field === "object" &&
      typeof (field as Record<string, unknown>).field_id === "string" ? [(field as Record<string, unknown>).field_id as string] : []));
    if (record.measurement_valid !== true ||
        !Number.isSafeInteger(record.instance_generation) || !Number.isSafeInteger(record.call_seq) ||
        !Number.isSafeInteger(record.selector_seq) ||
        trainingFieldIds.some((fieldId) => !fieldIds.has(fieldId))) invalidTimingCalls++;
  }
  const timingCallCount = timingCalls.size;
  const passed = holdoutTraces.length > 0 && trainingFieldIds.length > 0 && missingFieldIds.length === 0 &&
    missedEffects.length === 0 && timingCallCount === contract.expectedTimingCalls &&
    invalidTimingCalls === 0 && duplicateTimingCalls === 0;
  return { passed, trainingTraceCount: trainingTraces.length, holdoutTraceCount: holdoutTraces.length,
    observedEffects: holdout.size, missedEffects, trainingFieldIds, holdoutFieldIds, missingFieldIds,
    timingCallCount, invalidTimingCalls, duplicateTimingCalls };
}

export function captureFormalRegistrySnapshot(samples: readonly string[]): FormalRegistrySnapshot {
  const bytes = readFileSync(FORMAL_SEED_REGISTRY_PATH, "utf8");
  const registry = parseFormalSeedRegistry(bytes);
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    targets: samples.map((sample) => {
      const config = formalTargetConfig(sample, registry);
      return { sample, strategy: config.strategy, phases: config.phases, holdout: config.holdout };
    }),
  };
}
export function verifyAcceptedWorkset(target: Record<string, unknown>, artifactRoot: string): boolean {
  try {
    const sample = target.sample;
    const relativePath = target.worksetPath;
    const expectedSha256 = target.worksetSha256;
    if (typeof sample !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(sample) ||
        relativePath !== sample + "/workset.v2.json" || typeof expectedSha256 !== "string" ||
        !/^[a-f0-9]{64}$/.test(expectedSha256)) return false;
    const root = realpathSync(artifactRoot);
    const candidate = path.resolve(root, relativePath);
    const candidateRelative = path.relative(root, candidate);
    if (candidateRelative === ".." || candidateRelative.startsWith(".." + path.sep) || path.isAbsolute(candidateRelative))
      return false;
    const worksetPath = realpathSync(candidate);
    const worksetRelative = path.relative(root, worksetPath);
    if (worksetRelative === ".." || worksetRelative.startsWith(".." + path.sep) || path.isAbsolute(worksetRelative))
      return false;
    return createHash("sha256").update(readFileSync(worksetPath)).digest("hex") === expectedSha256;
  } catch {
    return false;
  }
}
export function validateSampleSelection(samples: readonly string[], _pilot: boolean): void {
  if (!samples.length) throw new TypeError("at least one sample is required");
  if (new Set(samples).size !== samples.length) throw new TypeError("sample IDs must be unique");
  if (samples.some((sample) => !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(sample)))
    throw new TypeError("sample IDs must be simple path-safe identifiers");
}
export function formalTargetsAccepted(samples: readonly string[], targets: readonly Record<string, unknown>[], failures: readonly string[], budget: number,
  registrySnapshot = captureFormalRegistrySnapshot(samples), worksetArtifactRoot?: string): boolean {
  try { validateSampleSelection(samples, false); } catch { return false; }
  if (failures.length || targets.length !== samples.length || registrySnapshot.targets.length !== samples.length) return false;
  const actual = targets.map((target) => target.sample).sort();
  const expected = [...samples].sort();
  return actual.length === expected.length && actual.every((sample, i) => sample === expected[i]) &&
    targets.every((target) => {
      if (target.valid !== true || !Array.isArray(target.phases)) return false;
      const audits = Array.isArray(target.planningAudits) ? target.planningAudits : [];
      const targetConfig = registrySnapshot.targets.find((item) => item.sample === target.sample);
      if (!targetConfig || target.formalConfigSha256 !== registrySnapshot.sha256 ||
          target.acquisitionStrategy !== targetConfig.strategy || !Array.isArray(target.sourceTraces) ||
          target.worksetPath !== target.sample + "/workset.v2.json" ||
          typeof target.worksetSha256 !== "string" || !/^[a-f0-9]{64}$/.test(target.worksetSha256) ||
          (worksetArtifactRoot !== undefined && !verifyAcceptedWorkset(target, worksetArtifactRoot))) return false;
      const expectedPhases = targetConfig.phases;
      const sourceTraceIds = new Set(target.sourceTraces.flatMap((item) => !!item && typeof item === "object" &&
        typeof (item as Record<string, unknown>).run_id === "string" ? [(item as Record<string, unknown>).run_id as string] : []));
      if (sourceTraceIds.size !== target.sourceTraces.length) return false;
      const phaseRecords = target.phases as unknown[];
      if (targetConfig.strategy === "baseline-only") {
        const baselineRuns = targetConfig.phases.map((spec) => {
          const matching = phaseRecords.filter((value) => !!value && typeof value === "object" && !Array.isArray(value) &&
            (value as Record<string, unknown>).name === spec.name &&
            (value as Record<string, unknown>).seedId === spec.id &&
            JSON.stringify((value as Record<string, unknown>).seedArgs) === JSON.stringify(spec.args) &&
            (value as Record<string, unknown>).valid === true);
          if (matching.length !== 1) return null;
          const runId = (matching[0] as Record<string, unknown>).baselineRunId;
          return typeof runId === "string" && runId ? { includeInWorkset: spec.includeInWorkset, runId } : null;
        });
        if (baselineRuns.some((item) => item === null) || new Set(baselineRuns.map((item) => item!.runId)).size !== baselineRuns.length)
          return false;
        const trainingRunIds = new Set(baselineRuns.filter((item) => item!.includeInWorkset).map((item) => item!.runId));
        if (sourceTraceIds.size !== trainingRunIds.size || [...trainingRunIds].some((runId) => !sourceTraceIds.has(runId)))
          return false;
      }
      if (phaseRecords.some((value) => {
        if (!value || typeof value !== "object" || Array.isArray(value)) return true;
        const record = value as Record<string, unknown>;
        return !expectedPhases.some((spec) => spec.name === record.name);
      })) return false;
      return expectedPhases.every((expected) => {
        const matching = phaseRecords.filter((value) => !!value && typeof value === "object" && !Array.isArray(value) &&
          (value as Record<string, unknown>).name === expected.name &&
          (value as Record<string, unknown>).seedId === expected.id &&
          JSON.stringify((value as Record<string, unknown>).seedArgs) === JSON.stringify(expected.args) &&
          (value as Record<string, unknown>).role === expected.role &&
          (value as Record<string, unknown>).includeInWorkset === expected.includeInWorkset &&
          (value as Record<string, unknown>).valid === true);
        if (matching.length !== 1) return false;
        const phase = matching[0] as Record<string, unknown>;
        if (phase.baselineAccepted !== true || typeof phase.baselineRunId !== "string" ||
            typeof phase.candidateRuns !== "number") return false;
        if (targetConfig.strategy === "explore") {
          if (phase.candidateRuns < budget || typeof phase.acceptedCompleteCandidates !== "number" ||
              phase.acceptedCompleteCandidates < 1) return false;
        } else if (phase.candidateRuns !== 0) return false;
        if (expected.includeInWorkset ? !sourceTraceIds.has(phase.baselineRunId) : sourceTraceIds.has(phase.baselineRunId)) return false;
        if (!expected.includeInWorkset) {
          const coverage = phase.holdoutCoverage;
          if (!coverage || typeof coverage !== "object" || Array.isArray(coverage) ||
              (coverage as Record<string, unknown>).passed !== true ||
              (coverage as Record<string, unknown>).missedEffects !== 0 ||
              (coverage as Record<string, unknown>).missingFieldIds !== 0 ||
              (coverage as Record<string, unknown>).timingCallCount !== targetConfig.holdout?.expectedTimingCalls ||
              (coverage as Record<string, unknown>).invalidTimingCalls !== 0 ||
              (coverage as Record<string, unknown>).duplicateTimingCalls !== 0) return false;
        }
        const phaseAudits = audits.filter((item) => !!item && typeof item === "object" && !Array.isArray(item) &&
          (item as Record<string, unknown>).phase === expected.name &&
          (item as Record<string, unknown>).seedId === expected.id &&
          (item as Record<string, unknown>).attempt === phase.attempt);
        if (phaseAudits.length === 0 || phaseAudits.some((item) => {
          const count = (item as Record<string, unknown>).coupledEncodable;
          const linkedCount = (item as Record<string, unknown>).linkedEncodable;
          return !Number.isSafeInteger(count) || (count as number) < 0 ||
            !Number.isSafeInteger(linkedCount) || (linkedCount as number) < 0;
        })) return false;
        const linkedOpportunity = phaseAudits.some((item) =>
          ((item as Record<string, unknown>).linkedEncodable as number) > 0);
        if (targetConfig.strategy === "explore" &&
            (!Number.isSafeInteger(phase.coldOpportunities) || !Number.isSafeInteger(phase.coldTransfers) ||
             (phase.coldOpportunities as number) < 0 || (phase.coldTransfers as number) < 0 ||
             (phase.coldTransfers as number) !== (phase.coldOpportunities as number) ||
             !Array.isArray(phase.coldProofFailures) || phase.coldProofFailures.length !== 0)) return false;
        return targetConfig.strategy === "baseline-only" || !linkedOpportunity ||
          (typeof phase.linkedExecutions === "number" && phase.linkedExecutions >= 1);
      });
    });
}
export function hasAppliedCoupledEvidence(value: unknown, captureText: string, binding: MutationBinding, expectedRunId?: string): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const a = value as Record<string, unknown>, m = a.mutation as Record<string, unknown> | undefined;
  if (a.status !== "run_finished" || typeof a.runId !== "string" || !a.runId || (expectedRunId !== undefined && a.runId !== expectedRunId) ||
      !m || typeof m !== "object" || !Array.isArray(m.prefixMutations) || !m.prefixMutations.length ||
      !Number.isSafeInteger(m.selectorOrdinal) || !Number.isSafeInteger(m.selectorSeq) ||
      !Number.isSafeInteger(m.paramIndex)) return false;
  const pfx = m.prefixMutations as Array<Record<string, unknown>>;
  if (pfx.some((p) => !p || !Number.isSafeInteger(p.selectorOrdinal) ||
      !Number.isSafeInteger(p.selectorSeq) || !Number.isSafeInteger(p.paramIndex) ||
      !Number.isSafeInteger(p.widthBytes) || !Number.isSafeInteger(p.byteOffset) ||
      typeof p.expectedBits !== "string" || typeof p.replacementBits !== "string")) return false;
  try {
    const cap = parseCallCapture(captureText, { ...binding, runId: a.runId, mutation: {
      ...(typeof m.targetGeneration === "number" ? { targetGeneration: m.targetGeneration } : {}),
      ...(typeof m.execMode === "number" ? { execMode: m.execMode } : {}),
      ...(typeof m.opKind === "string" ? { opKind: m.opKind as never } : {}),
      selectorOrdinal: m.selectorOrdinal as number, selectorSeq: m.selectorSeq as number,
      paramIndex: m.paramIndex as number,
      prefixMutations: pfx.map((p) => ({ selectorOrdinal: p.selectorOrdinal as number, selectorSeq: p.selectorSeq as number })),
    }});
    if (cap.end.timedOut || cap.end.ecallCount === 0 || cap.end.targetMatchCount !== 1 ||
        cap.end.mutationAppliedCount !== pfx.length + 1) return false;
    const gen = typeof m.targetGeneration === "number" ? m.targetGeneration : 1;
    const target = cap.events.find((e) => e.generation === gen && e.selectorOrdinal === m.selectorOrdinal && e.selectorSeq === m.selectorSeq);
    if (!target?.mutation?.applied || target.mutation.reason !== "applied") return false;
    return pfx.every((p) => {
      const es = cap.events.filter((e) => e.generation === gen && e.selectorOrdinal === p.selectorOrdinal && e.selectorSeq === p.selectorSeq);
      const x = es[0]?.mutation;
      return es.length === 1 && x?.applied === true && x.reason === "applied" &&
        x.paramIndex === p.paramIndex && x.widthBytes === p.widthBytes && x.byteOffset === p.byteOffset &&
        x.expectedBits === p.expectedBits && x.observedBits === p.expectedBits && x.replacementBits === p.replacementBits;
    });
  } catch { return false; }
}

interface VerifiedRunArtifacts {
  manifest: Record<string, unknown>;
  meta: Record<string, unknown>;
  capture: CallCaptureDocument;
  trace: ReturnType<typeof readCanonicalTrace>;
  traceText: string;
}
function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(label + " must be an object");
  return value as Record<string, unknown>;
}
function artifactPathInside(runDirectory: string, filename: unknown): string {
  if (typeof filename !== "string" || !filename) throw new TypeError("run artifact path is missing");
  const root = realpathSync(runDirectory), resolved = realpathSync(filename);
  const relative = path.relative(root, resolved);
  if (!relative || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
    throw new TypeError("run artifact path escapes its attempt directory");
  }
  return resolved;
}
function readVerifiedRunArtifacts(
  runDirectory: string, expectedRunId: string,
  bundle: ReturnType<typeof loadExplorerProfile>["bundle"],
  binding: MutationBinding, rule?: ScalarMutationRule,
): VerifiedRunArtifacts {
  const manifest = asRecord(JSON.parse(readFileSync(path.join(runDirectory, "attempt.json"), "utf8")), "attempt manifest");
  if (manifest.schema !== "atfield-explorer-attempt-v1" || manifest.status !== "run_finished" ||
      manifest.runId !== expectedRunId || manifest.completion !== "complete" ||
      manifest.exitCode !== 0 || manifest.termination !== "exited") {
    throw new TypeError("attempt manifest does not identify a complete successful run");
  }
  const manifestBinding = asRecord(manifest.binding, "attempt binding");
  if (manifestBinding.bundleManifestSha256 !== binding.bundleManifestSha256 ||
      manifestBinding.marshalLayoutSha256 !== binding.marshalLayoutSha256) {
    throw new TypeError("attempt is bound to different Profile artifacts");
  }
  const artifactPaths = asRecord(manifest.artifactPaths, "attempt artifact paths");
  const tracePath = artifactPathInside(runDirectory, artifactPaths.trace);
  const metaPath = artifactPathInside(runDirectory, artifactPaths.meta);
  const meta = asRecord(JSON.parse(readFileSync(metaPath, "utf8")), "canonical run metadata");
  const traceBytes = readFileSync(tracePath), traceHash = hash(traceBytes);
  if (meta.schema !== "atfield-canonical-run-meta-v1" || meta.run_id !== expectedRunId ||
      meta.bundle_manifest_sha256 !== binding.bundleManifestSha256 || meta.trace_sha256 !== traceHash ||
      meta.exit_code !== 0 || meta.termination !== "exited" || meta.timed_out !== false ||
      meta.completion !== "complete" || typeof meta.trace_path !== "string" ||
      realpathSync(meta.trace_path) !== tracePath) {
    throw new TypeError("canonical run metadata does not match the complete trace artifact");
  }
  const trace = readCanonicalTrace(tracePath, bundle);
  if (trace.runId !== expectedRunId || trace.runCompletion !== "complete" ||
      trace.processReturnCode !== 0 || trace.traceSha256 !== traceHash) {
    throw new TypeError("canonical trace does not match the completed run metadata");
  }
  const expectation = {
    ...binding, runId: expectedRunId,
    ...(rule ? { mutation: {
      ...(rule.targetGeneration !== undefined ? { targetGeneration: rule.targetGeneration } : {}),
      ...(rule.execMode !== undefined ? { execMode: rule.execMode } : {}),
      ...(rule.opKind !== undefined ? { opKind: rule.opKind } : {}),
      selectorOrdinal: rule.selectorOrdinal, selectorSeq: rule.selectorSeq, paramIndex: rule.paramIndex,
      ...(rule.prefixMutations?.length ? { prefixMutations: rule.prefixMutations.map((prefix) => ({
        selectorOrdinal: prefix.selectorOrdinal, selectorSeq: prefix.selectorSeq,
      })) } : {}),
    } } : {}),
  };
  const capture = parseCallCapture(readFileSync(path.join(runDirectory, "calls.jsonl"), "utf8"), expectation);
  if (!capture.end.complete || capture.events.length === 0) throw new TypeError("native call capture is incomplete or empty");
  return { manifest, meta, capture, trace, traceText: new TextDecoder("utf-8", { fatal: true }).decode(traceBytes) };
}
export function linkedCandidateVerdictFailure(
  resultAccepted: boolean,
  resultMeasurementComplete: boolean,
  verdictAccepted: boolean,
  verdictMeasurementComplete: boolean,
  reason: unknown,
): string | null {
  const detail = typeof reason === "string" && reason.trim() !== "" ? reason.trim() : null;
  const suffix = detail ? ": " + detail : "";
  if (resultAccepted !== verdictAccepted || resultMeasurementComplete !== verdictMeasurementComplete) {
    return "candidate result and verdict disagree" + suffix;
  }
  if (!verdictMeasurementComplete) return "candidate measurement is incomplete" + suffix;
  if (!verdictAccepted) return "candidate measurement completed but was rejected" + suffix;
  return null;
}

function inspectLinkedCandidate(
  baselineDirectory: string, baselineRunId: string, candidateDirectory: string,
  candidateRunId: string | undefined, candidateAccepted: boolean, candidateMeasurementComplete: boolean,
  bundle: ReturnType<typeof loadExplorerProfile>["bundle"], binding: MutationBinding,
): { linked: boolean; failure: string | null } {
  let linked = false;
  try {
    const raw = asRecord(JSON.parse(readFileSync(path.join(candidateDirectory, "attempt.json"), "utf8")), "candidate attempt");
    const rule = asRecord(raw.mutation, "candidate mutation") as unknown as ScalarMutationRule;
    if (!rule.dataflowTarget) return { linked: false, failure: null };
    linked = true;
    if (!baselineDirectory || !baselineRunId) throw new TypeError("baseline run artifacts are unavailable");
    if (!candidateRunId || raw.runId !== candidateRunId) throw new TypeError("candidate result and attempt run IDs differ");
    const verdict = asRecord(JSON.parse(readFileSync(path.join(candidateDirectory, "verdict.json"), "utf8")), "candidate verdict");
    if (verdict.runId !== candidateRunId) throw new TypeError("candidate verdict run ID differs");
    if (typeof verdict.accepted !== "boolean" || typeof verdict.measurementComplete !== "boolean") {
      throw new TypeError("candidate verdict acceptance fields are invalid");
    }
    const statusFailure = linkedCandidateVerdictFailure(
      candidateAccepted, candidateMeasurementComplete,
      verdict.accepted, verdict.measurementComplete, verdict.reason,
    );
    if (statusFailure) throw new TypeError(statusFailure);
    encodeMutationSpec(binding, rule);
    const baseline = readVerifiedRunArtifacts(baselineDirectory, baselineRunId, bundle, binding);
    const candidate = readVerifiedRunArtifacts(candidateDirectory, candidateRunId, bundle, binding, rule);
    if (JSON.stringify(baseline.manifest.seed) !== JSON.stringify(candidate.manifest.seed)) {
      throw new TypeError("baseline and candidate use different seeds");
    }
    const failure = linkedDataflowFailure(baseline.capture, candidate.capture, rule, {
      complete: true, exitCode: 0, traceText: candidate.traceText, traceValid: true,
    });
    return { linked: true, failure };
  } catch (error) {
    return { linked, failure: linked ? (error instanceof Error ? error.message : String(error)) : null };
  }
}

interface Phase { name: string; attempt: number; result: ExplorerResult; valid: boolean; invalidReason?: string }
interface Input {
  sample: string; bundlePath: string; profile: ReturnType<typeof loadExplorerProfile>;
  freeze: { manifestPath: string; manifestSha256: string; artifacts: Record<string, { path: string; sha256: string }> };
}
const hash = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
function snapshot(dir: string, out: Record<string, string>): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith(".")) continue;
    const f = path.join(dir, e.name);
    if (e.isDirectory()) snapshot(f, out);
    else if (/\.(ts|c|h)$/.test(e.name)) out[f] = hash(readFileSync(f));
  }
}
function checkFreeze(src: Record<string, string>, collector: string, collectorHash: string, inputs: Input[]): void {
  for (const [f, h] of Object.entries(src)) if (hash(readFileSync(f)) !== h) throw new Error("source changed during validation: " + f);
  if (hash(readFileSync(collector)) !== collectorHash) throw new Error("collector changed during validation");
  for (const i of inputs) {
    if (hash(readFileSync(i.freeze.manifestPath)) !== i.freeze.manifestSha256) throw new Error("bundle manifest changed: " + i.sample);
    for (const a of Object.values(i.freeze.artifacts)) if (hash(readFileSync(a.path)) !== a.sha256)
      throw new Error("bundle artifact changed: " + i.sample);
  }
}
export function formalSeedEvidenceFailure(
  expected: FormalPhaseSpec,
  attempt: unknown,
  meta: unknown,
  traceText: string,
): string | null {
  try {
    const attemptRecord = asRecord(attempt, "attempt manifest");
    const seed = asRecord(attemptRecord.seed, "attempt seed");
    if (seed.id !== expected.id || JSON.stringify(seed.args) !== JSON.stringify(expected.args))
      return "attempt seed ID or args differ from configured seed";
    const runMeta = asRecord(meta, "canonical run metadata");
    if (runMeta.seed_id !== expected.id || JSON.stringify(runMeta.argv) !== JSON.stringify(expected.args))
      return "canonical run metadata seed ID or argv differ from configured seed";
    const starts = traceText.split(/\r?\n/).filter((line) => line).map((line) => JSON.parse(line))
      .filter((record) => !!record && typeof record === "object" && (record as Record<string, unknown>).record_type === "run_start");
    if (starts.length !== 1) return "trace must contain exactly one run_start record";
    const start = starts[0] as Record<string, unknown>;
    if (start.seed_id !== expected.id || JSON.stringify(start.argv) !== JSON.stringify(expected.args))
      return "trace run_start seed ID or argv differ from configured seed";
    return null;
  } catch (error) {
    return "seed evidence is invalid: " + (error instanceof Error ? error.message : String(error));
  }
}

function phaseValidity(p: Phase, binding: MutationBinding, budget: number, expected: FormalPhaseSpec,
  strategy: FormalAcquisitionStrategy, bundle: ReturnType<typeof loadExplorerProfile>["bundle"]): string | null {
  if (p.result.seedResults.length !== 1 || p.result.baselineRuns !== 1) return "expected exactly one baseline seed";
  const s = p.result.seedResults[0]!;
  if (!s.baselineAccepted || !s.baselineArtifactPath || !s.baselineRunId) return s.baselineReason ?? "baseline was not accepted";
  try {
    const verified = readVerifiedRunArtifacts(s.baselineArtifactPath, s.baselineRunId, bundle, binding);
    const evidenceFailure = formalSeedEvidenceFailure(expected, verified.manifest, verified.meta, verified.traceText);
    if (evidenceFailure) return evidenceFailure;
    if (verified.trace.runCompletion !== "complete" || verified.trace.processReturnCode !== 0)
      return "baseline trace is not a successful complete run";
    if (!verified.capture.end.complete || !verified.capture.events.length) return "baseline capture is incomplete or empty";
    if (p.result.bundleManifestSha256 !== binding.bundleManifestSha256) return "bundle identity mismatch";
    if (strategy === "baseline-only") return p.result.candidateRuns === 0
      ? null : "baseline-only phase launched mutation candidates";
    const acceptedCompleteCandidates = p.result.seedResults.flatMap((seed) => seed.candidates)
      .filter((candidate) => candidate.accepted && candidate.measurementComplete === true).length;
    if (p.result.candidateRuns < budget) return "candidateRuns " + p.result.candidateRuns + " below required " + budget + "; frontier=" + JSON.stringify(p.result.unexploredFrontier);
    if (acceptedCompleteCandidates < 1) return "no accepted complete candidate; candidateRuns=" + p.result.candidateRuns + "; frontier=" + JSON.stringify(p.result.unexploredFrontier);
    return null;
  } catch (e) { return "baseline capture invalid: " + String(e); }
}
function writeJson(f: string, o: unknown): void { writeFileSync(f, JSON.stringify(o, null, 2) + "\n", { mode: 0o600 }); }
async function run(): Promise<void> {
  const [outArg, rootArg, budgetArg, ...rest] = process.argv.slice(2);
  if (!outArg || !rootArg || !budgetArg) throw new TypeError("usage: bun tools/validate-milestone.ts OUTPUT SAMPLE_BUILD_ROOT BUDGET [--pilot] SAMPLE...");
  const out = path.resolve(outArg); mkdirSync(out, { recursive: true, mode: 0o700 });
  const pilot = rest.includes("--pilot"), samples = rest.filter((x) => x !== "--pilot");
  const runId = randomUUID(), budget = Number(budgetArg), completed: Record<string, unknown>[] = [], failures: string[] = [];
  let frozen: Record<string, unknown> | undefined;
  const partialPath = path.join(out, "partial.json");
  try {
    validateSampleSelection(samples, pilot);
    const formalRegistrySnapshot = captureFormalRegistrySnapshot(samples);
    const needsCandidates = formalRegistrySnapshot.targets.some((target) => target.strategy === "explore");
    if (!Number.isSafeInteger(budget) || budget < (needsCandidates ? 1 : 0))
      throw new TypeError(needsCandidates ? "budget must be positive for exploration targets" : "budget must be nonnegative");
    const root = path.resolve(rootArg);
    const inputs: Input[] = samples.map((sample) => {
      const bundlePath = path.join(root, sample, "protect", "profile-bundle.json"), profile = loadExplorerProfile(bundlePath);
      const artifacts: Record<string, { path: string; sha256: string }> = {};
      for (const [name, f] of profile.bundle.artifactPaths) artifacts[name] = { path: f, sha256: hash(readFileSync(f)) };
      return { sample, bundlePath, profile, freeze: {
        manifestPath: profile.bundle.manifestPath, manifestSha256: profile.bundle.manifestSha256, artifacts,
      }};
    });
    const collector = path.resolve("build/libatfield_native_sgx.so"), collectorHash = hash(readFileSync(collector));
    const sources: Record<string, string> = {}; snapshot(path.join(REPO_ROOT, "lib"), sources); snapshot(path.join(REPO_ROOT, "src"), sources);
    if (hash(readFileSync(FORMAL_SEED_REGISTRY_PATH)) !== formalRegistrySnapshot.sha256)
      throw new Error("formal seed registry changed while its configuration snapshot was captured");
    sources[FORMAL_SEED_REGISTRY_PATH] = formalRegistrySnapshot.sha256;
    const script = path.resolve(fileURLToPath(import.meta.url)); sources[script] = hash(readFileSync(script));
    frozen = { collectorSha256: collectorHash, sources, formalRegistry: formalRegistrySnapshot,
      inputs: inputs.map((i) => ({ sample: i.sample, ...i.freeze })) };
    writeJson(path.join(out, "frozen.json"), frozen);

    for (const i of inputs) {
      const { sample, profile, bundlePath } = i, dest = path.join(out, sample), corpusPath = path.join(dest, "corpus");
      mkdirSync(dest, { recursive: true, mode: 0o700 });
      const phases: Phase[] = [];
      const targetConfig = formalRegistrySnapshot.targets.find((target) => target.sample === sample)!;
      const phaseSpecs = targetConfig.phases;
      let resolvedHoldoutContract: ResolvedHoldoutContract | null = null;
      if (targetConfig.holdout)
        resolvedHoldoutContract = resolveFormalHoldoutContract(profile.bundle, targetConfig.holdout);
      const candidateBudget = targetConfig.strategy === "baseline-only" ? 0 : budget;
      for (const spec of phaseSpecs) {
        const phaseCorpusPath = spec.includeInWorkset ? corpusPath : path.join(dest, "isolated", spec.name, "corpus");
        const { name, role, args } = { name: spec.name, role: spec.role, args: spec.args };
        for (let attempt = 0; attempt < 6; attempt++) {
          const result = await exploreSeeds({
            bundlePath, corpusPath: phaseCorpusPath, role, seeds: [{ id: spec.id, args: [...args], env: {} }],
            collectorPath: collector, candidateBudget, expansionBufferBudgetBytes: 262144n,
            expansionTotalBudgetBytes: 1048576n, enclCpu: 46, watchCpu: 1,
          });
          const p: Phase = { name, attempt, result, valid: false };
          p.invalidReason = result.bundleManifestSha256 === profile.binding.bundleManifestSha256
            ? phaseValidity(p, profile.binding, candidateBudget, spec, targetConfig.strategy, profile.bundle) : "result bundle identity mismatch";
          p.valid = p.invalidReason === null; phases.push(p);
          writeJson(path.join(dest, name + "-" + attempt + ".result.json"), result);
          console.log(JSON.stringify({ sample, strategy: targetConfig.strategy, phase: name, seedId: spec.id, seedArgs: args, role, includeInWorkset: spec.includeInWorkset, attempt, baselineAccepted: result.seedResults[0]?.baselineAccepted,
            candidates: result.candidateRuns, accepted: result.acceptedCandidates, valid: p.valid, invalidReason: p.invalidReason }));
          if (result.seedResults.every((seed) => seed.baselineAccepted)) break;
        }
      }
      const corpus = readFinalizableCorpus(corpusPath, bundlePath);
      const workset = buildWorkset(profile.bundle, corpus.map((t) => t.parsedTrace));
      const worksetArtifactPath = path.join(dest, "workset.v2.json");
      writeJson(worksetArtifactPath, workset);
      const worksetPath = path.relative(out, worksetArtifactPath);
      const worksetSha256 = createHash("sha256").update(readFileSync(worksetArtifactPath)).digest("hex");
      const holdoutCoverageByAttempt = new Map<string, S3HoldoutCoverage>();
      for (const p of phases) {
        const spec = phaseSpecs.find((item) => item.name === p.name);
        if (!spec || spec.includeInWorkset) continue;
        const holdoutTraces: HoldoutTraceEvidence[] = [];
        try {
          for (const seed of p.result.seedResults) {
            if (!seed.baselineArtifactPath) throw new TypeError("holdout baseline artifacts are missing");
            const manifest = asRecord(JSON.parse(readFileSync(path.join(seed.baselineArtifactPath, "attempt.json"), "utf8")), "holdout attempt");
            const artifactPaths = asRecord(manifest.artifactPaths, "holdout artifacts");
            const tracePath = artifactPathInside(seed.baselineArtifactPath, artifactPaths.trace);
            holdoutTraces.push({ parsed: readCanonicalTrace(tracePath, profile.bundle), traceText: readFileSync(tracePath, "utf8") });
          }
          if (!resolvedHoldoutContract) throw new TypeError("isolated holdout phase has no timing call contract");
          holdoutCoverageByAttempt.set(p.name + ":" + p.attempt,
            compareS3HoldoutCoverage(corpus.map((trace) => trace.parsedTrace), holdoutTraces, resolvedHoldoutContract));
        } catch (error) {
          holdoutCoverageByAttempt.set(p.name + ":" + p.attempt, { passed: false,
            trainingTraceCount: corpus.length, holdoutTraceCount: holdoutTraces.length, observedEffects: 0,
            missedEffects: [error instanceof Error ? error.message : String(error)],
            trainingFieldIds: [], holdoutFieldIds: [], missingFieldIds: [], timingCallCount: 0,
            invalidTimingCalls: 0, duplicateTimingCalls: 0 });
        }
      }
      const planningAudits: Array<{ phase: string; seedId: string; attempt: number; plans: number; coupled: number; coupledEncodable: number; linkedEncodable: number; failures: Array<{ rule: unknown; reason: string }> }> = [];
      for (const p of phases) for (const s of p.result.seedResults) {
        if (!s.baselineAccepted || !s.baselineArtifactPath || !s.baselineRunId) continue;
        const cap = parseCallCapture(readFileSync(path.join(s.baselineArtifactPath, "calls.jsonl"), "utf8"), { ...profile.binding, runId: s.baselineRunId });
        const plans = deriveCandidatesFromCase(profile, cap, { budget: 20000, expansionBufferBudgetBytes: 262144n, expansionTotalBudgetBytes: 1048576n });
        const errors: Array<{ rule: unknown; reason: string }> = [];
        let coupledEncodable = 0, linkedEncodable = 0;
        for (const plan of plans) try {
          encodeMutationSpec(profile.binding, plan.rule);
          if ((plan.rule.prefixMutations?.length ?? 0) > 0) coupledEncodable++;
          if (plan.rule.dataflowTarget) linkedEncodable++;
        } catch (e) {
          if (!(e instanceof Error)) throw e;
          errors.push({ rule: plan.rule, reason: e.message });
        }
        planningAudits.push({ phase: p.name, seedId: s.seedId, attempt: p.attempt, plans: plans.length,
          coupled: plans.filter((x) => (x.rule.prefixMutations?.length ?? 0) > 0).length,
          coupledEncodable, linkedEncodable, failures: errors });
      }
      const fields = workset.fields.map((f) => ({ id: f.id, name: f.name,
        observed: f.pages.filter((x) => x.evidence.observed.length > 0).length,
        closure: f.pages.filter((x) => x.evidence["layout-closure"].length > 0 && x.evidence.observed.length === 0).length }));
      const candidates = phases.flatMap((p) => p.result.seedResults.flatMap((s) => s.candidates));
      const countAppliedCoupled = (items: readonly { artifactPath?: string; runId?: string }[]) => items.filter((c) => {
        if (!c.artifactPath || !c.runId) return false;
        try { return hasAppliedCoupledEvidence(
          JSON.parse(readFileSync(path.join(c.artifactPath, "attempt.json"), "utf8")),
          readFileSync(path.join(c.artifactPath, "calls.jsonl"), "utf8"), profile.binding, c.runId); } catch { return false; }
      }).length;
      const phaseSummaries = phases.map((p) => {
        const phaseCandidates = p.result.seedResults.flatMap((s) => s.candidates);
        const coupledExecutions = countAppliedCoupled(phaseCandidates);
        const linkedProofFailures: Array<{ runId?: string; reason: string }> = [];
        let linkedExecutions = 0;
        for (const seed of p.result.seedResults) for (const candidate of seed.candidates) {
          if (!candidate.artifactPath) continue;
          const proof = inspectLinkedCandidate(
            seed.baselineArtifactPath ?? "", seed.baselineRunId ?? "",
            candidate.artifactPath, candidate.runId, candidate.accepted,
            candidate.measurementComplete === true, profile.bundle, profile.binding,
          );
          if (!proof.linked) continue;
          if (proof.failure) linkedProofFailures.push({ runId: candidate.runId, reason: proof.failure });
          else linkedExecutions++;
        }
        const linkedPlansAvailable = planningAudits.filter((audit) => audit.phase === p.name && audit.seedId === p.result.seedResults[0]?.seedId && audit.attempt === p.attempt)
          .reduce((sum, audit) => sum + audit.linkedEncodable, 0);
        let coldOpportunities = 0, coldTransfers = 0;
        const coldProofFailures: Array<{ runId?: string; reason: string }> = [];
        for (const seed of p.result.seedResults) {
          if (!seed.baselineAccepted) continue;
          if (!seed.baselineArtifactPath || !seed.baselineRunId) {
            coldProofFailures.push({ reason: "accepted baseline has no raw artifact path or run ID" });
            continue;
          }
          try {
            const baseline = readVerifiedRunArtifacts(seed.baselineArtifactPath, seed.baselineRunId,
              profile.bundle, profile.binding);
            const proof = proveColdFirstFieldTransfer(baseline.capture, baseline.traceText);
            coldOpportunities += proof.opportunityCount;
            coldTransfers += proof.provenTransfers.length;
            if (proof.status === "invalid" || proof.opportunityCount !== proof.provenTransfers.length)
              coldProofFailures.push({ runId: seed.baselineRunId, reason: proof.reason ?? "cold transfer was not proved" });
          } catch (error) {
            coldProofFailures.push({ runId: seed.baselineRunId,
              reason: error instanceof Error ? error.message : String(error) });
          }
        }
        const missingColdProof = targetConfig.strategy === "explore" && coldProofFailures.length > 0;
        const missingLinkedProof = targetConfig.strategy === "explore" && linkedPlansAvailable > 0 && linkedExecutions === 0;
        const invalidReason = missingLinkedProof
          ? "encodable linked dataflow plans available (" + linkedPlansAvailable +
            ") but no independently verified accepted complete linked execution; failures=" +
            JSON.stringify(linkedProofFailures.slice(0, 3)) + "; frontier entries=" + p.result.unexploredFrontier.length
          : missingColdProof ? "fresh-enclave first-Field object transfer proof failed: " +
            JSON.stringify(coldProofFailures) : p.invalidReason;
        const phaseValid = p.valid && !missingLinkedProof && !missingColdProof &&
          (phaseSpecs.find((spec) => spec.name === p.name)?.includeInWorkset !== false ||
            holdoutCoverageByAttempt.get(p.name + ":" + p.attempt)?.passed === true);
        const phaseSpec = phaseSpecs.find((spec) => spec.name === p.name);
        return {
          name: p.name, seedId: phaseSpec?.id, seedArgs: phaseSpec?.args, role: phaseSpec?.role,
          includeInWorkset: phaseSpec?.includeInWorkset,
          baselineRunId: p.result.seedResults[0]?.baselineRunId,
          holdoutCoverage: phaseSpec?.includeInWorkset === false
            ? (() => { const c = holdoutCoverageByAttempt.get(p.name + ":" + p.attempt); return c ? {
              passed: c.passed, observedEffects: c.observedEffects, missedEffects: c.missedEffects.length,
              missingFieldIds: c.missingFieldIds.length, timingCallCount: c.timingCallCount,
              invalidTimingCalls: c.invalidTimingCalls, duplicateTimingCalls: c.duplicateTimingCalls,
            } : null; })()
            : undefined,
          attempt: p.attempt, valid: phaseValid, invalidReason,
          baselineAccepted: p.result.seedResults.every((s) => s.baselineAccepted),
          candidateRuns: p.result.candidateRuns,
          accepted: p.result.acceptedCandidates,
          acceptedCompleteCandidates: phaseCandidates.filter((candidate) =>
            candidate.accepted && candidate.measurementComplete === true).length,
          coupledExecutions, linkedPlansAvailable, linkedExecutions, linkedProofFailures,
          coldOpportunities, coldTransfers, coldProofFailures,
          cost: p.result.costSummary, frontierCount: p.result.unexploredFrontier.length,
          unexploredFrontier: p.result.unexploredFrontier,
        };
      });
      const valid = phaseSpecs.every((spec) => phaseSummaries.some((phase) => phase.name === spec.name &&
        phase.seedId === spec.id && JSON.stringify(phase.seedArgs) === JSON.stringify(spec.args) &&
        phase.role === spec.role && phase.includeInWorkset === spec.includeInWorkset && phase.valid));
      if (!valid) failures.push(sample + ": every configured host seed phase needs an accepted attempt with complete candidate, linked, and cold proof evidence");
      const coupledExecutions = phaseSummaries.reduce((sum, phase) => sum + phase.coupledExecutions, 0);
      const linkedExecutions = phaseSummaries.reduce((sum, phase) => sum + phase.linkedExecutions, 0);
      completed.push({ sample, bundleManifestSha256: profile.binding.bundleManifestSha256,
        formalConfigSha256: formalRegistrySnapshot.sha256, acquisitionStrategy: targetConfig.strategy, valid,
        worksetPath, worksetSha256,
        phases: phaseSummaries, fields, planningAudits,
        accepted: candidates.filter((x) => x.accepted).length,
        rejected: candidates.filter((x) => !x.accepted).length,
        coupledExecutions, linkedExecutions, sourceTraces: workset.source_traces });
      writeJson(partialPath, { schema: "atfield-milestone-v3", status: "partial", mode: pilot ? "pilot" : "formal",
        runId, budgetPerPhase: budget, frozen, completedSamples: completed,
        requiredSamples: samples, failures });
      checkFreeze(sources, collector, collectorHash, inputs);
    }
    const success = pilot
      ? failures.length === 0 && completed.length === samples.length && completed.every((target) =>
        target.valid === true && verifyAcceptedWorkset(target, out))
      : formalTargetsAccepted(samples, completed, failures, budget, formalRegistrySnapshot, out);
    if (!success) {
      failures.push(pilot ? "pilot targets did not pass their phase validation" :
        "formal acceptance requires every requested target and configured phase to meet its seed, trace, workset, candidate, and holdout evidence policy");
      const failed = { schema: "atfield-milestone-v3", status: "failed", mode: pilot ? "pilot" : "formal", runId,
        budgetPerPhase: budget, frozen, completedSamples: completed, requiredSamples: samples, failures };
      writeJson(path.join(out, "failed.json"), failed); writeJson(partialPath, failed); process.exitCode = 1; return;
    }
    writeJson(path.join(out, pilot ? "pilot.json" : "acceptance.json"), {
      schema: "atfield-milestone-v3", status: pilot ? "pilot" : "accepted", mode: pilot ? "pilot" : "formal",
      runId, budgetPerPhase: budget, frozen, targets: completed });
    if (existsSync(partialPath)) unlinkSync(partialPath);
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
    const failed = { schema: "atfield-milestone-v3", status: "failed", mode: pilot ? "pilot" : "formal",
      runId, budgetPerPhase: Number.isSafeInteger(budget) ? budget : null,
      frozen, completedSamples: completed, failures };
    writeJson(path.join(out, "failed.json"), failed); writeJson(partialPath, failed);
    console.error(failures.at(-1)); process.exitCode = 1;
  }
}
if (import.meta.main) void run();
