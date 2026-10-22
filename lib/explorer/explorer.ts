import {
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statfsSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { runCanonicalHost, type CanonicalRun } from "../runner/canonical-runner.ts";
import { canonicalProfileJson, loadExplorerProfile, type ExplorerProfile } from "./profile.ts";
import {
  appendCallCaptureEnd,
  captureHasExactlyOneMutation,
  encodeMutationSpec,
  sameCallInputsExceptMutation,
  type CallCaptureDocument,
  type CallCaptureEvent,
  type MutationOpKind,
  type ScalarMutationRule,
} from "./contract.ts";
import {
  deriveCandidatesFromCase,
  deriveChildCandidatesFromFeedback,
  deriveOnlineScalarCandidates,
  linkedConsumerCallKey,
  reserveLinkedConsumerCallKeys,
  mutationRuleKey,
  type FrontierEntry,
  type PlannedMutation,
  DEFAULT_EXPANSION_BUFFER_BUDGET_BYTES,
  DEFAULT_EXPANSION_TOTAL_BUDGET_BYTES,
} from "./planner.ts";
import { appendValidatedCorpusTrace, type TraceCorpusRole } from "./corpus.ts";
import { readLifecycleCost, type LifecycleCost } from "./lifecycle.ts";
import { linkedDataflowFailure } from "./linked-proof.ts";

export interface ExplorerSeed {
  id: string;
  args: string[];
  env: Record<string, string>;
}

export interface ExplorerOptions {
  bundlePath: string;
  corpusPath: string;
  role: TraceCorpusRole;
  seeds: readonly ExplorerSeed[];
  collectorPath?: string;
  candidateBudget?: number;
  timeoutMs?: number;
  killGraceMs?: number;
  enclCpu?: number;
  watchCpu?: number;
  tempRoot?: string;
  expansionBufferBudgetBytes?: bigint;
  expansionTotalBudgetBytes?: bigint;
}

export interface PageEffectDelta {
  fieldId: string;
  pageRva: string;
  effects: string[];
}

export interface CandidateAttempt {
  candidateIndex: number;
  opKind?: MutationOpKind;
  depth?: number;
  parentCandidateIndex?: number | null;
  parentRunId?: string;
  spawnedChildrenCount?: number;
  selectorOrdinal: number;
  selectorSeq: number;
  paramIndex: number;
  value: string;
  priority: number;
  accepted: boolean;
  novel: boolean;
  reason: string | null;
  pageDelta: PageEffectDelta[];
  stateSha256: string | null;
  historySha256?: string | null;
  runId?: string;
  traceSha256?: string | null;
  committedCorpusRole?: TraceCorpusRole | null;
  targetEnteredField?: boolean;
  newFieldEntry?: boolean;
  measurementComplete?: boolean;
  businessOutcome?: "ok" | "rejected";
  runTerminalState?: "complete" | "business_rejection_exit" | "incomplete";
  processReturnCode?: number | null;
  artifactPath?: string;
  candidateKey?: string;
}

export interface SeedExplorationResult {
  seedId: string;
  baselineRunId?: string;
  baselineTraceSha256?: string | null;
  baselineArtifactPath?: string;
  baselineAccepted: boolean;
  baselineReason: string | null;
  baselinePageEffects: number;
  candidates: CandidateAttempt[];
  feedback: CandidateAttempt[];
  unexploredFrontier: FrontierEntry[];
}

export interface ExplorerCostSummary {
  totalRealEcalls: number;
  totalEnclaveInstances: number;
  totalPrefixReplays: number;
  failedProbes: number;
  totalElapsedMs: number;
  unmeasuredRuns: number;
  interruptedEcalls: number;
}

export interface ExplorerResult {
  bundleManifestSha256: string;
  seedResults: SeedExplorationResult[];
  baselineRuns: number;
  candidateRuns: number;
  acceptedCandidates: number;
  uniqueFeedbackStates: number;
  unexploredFrontier: FrontierEntry[];
  costSummary?: ExplorerCostSummary;
}

interface RunWithCapture {
  run: CanonicalRun;
  capture?: CallCaptureDocument;
  captureError?: string;
  cost?: LifecycleCost;
}

class CandidatePreparationError extends Error {
  constructor(readonly artifactPath: string, message: string) {
    super(message);
    this.name = "CandidatePreparationError";
  }
}

const RUNTIME_ENV_ALLOWLIST = ["PATH", "LD_LIBRARY_PATH", "SGX_AESM_ADDR", "LANG", "LC_ALL", "TZ"] as const;

function fail(message: string): never {
  throw new TypeError(message);
}

function validateSeed(value: ExplorerSeed): ExplorerSeed {
  if (!value || typeof value.id !== "string" || value.id.length === 0 || value.id.includes("\0")) fail("seed id is invalid");
  if (!Array.isArray(value.args) || !value.args.every((arg) => typeof arg === "string" && !arg.includes("\0"))) fail("seed args are invalid");
  if (!value.env || typeof value.env !== "object" || Array.isArray(value.env)) fail("seed env is invalid");
  const env: Record<string, string> = {};
  for (const [key, item] of Object.entries(value.env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof item !== "string" || item.includes("\0")) fail("seed env entry is invalid");
    if (key === "PATH" || key.startsWith("LD_") || key === "HOME" || key.startsWith("TMP") || key === "TEMP" || key.startsWith("XDG_") || key.startsWith("ATFIELD_") || key === "SGX_MODE") fail("seed env overrides canonical runtime state");
    env[key] = item;
  }
  return { id: value.id, args: [...value.args], env };
}

function requireBudget(value: number | undefined): number {
  const result = value ?? 64;
  if (!Number.isSafeInteger(result) || result < 0) fail("candidateBudget must be a safe nonnegative integer");
  return result;
}

function baseRuntimeEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of RUNTIME_ENV_ALLOWLIST) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}

async function withCleanRunnerEnvironment<T>(
  environment: Record<string, string>,
  action: () => Promise<T>,
): Promise<T> {
  const previous = { ...process.env } as Record<string, string>;
  for (const key of Object.keys(process.env)) delete process.env[key];
  for (const [key, value] of Object.entries(environment)) process.env[key] = value;
  try {
    return await action();
  } finally {
    for (const key of Object.keys(process.env)) delete process.env[key];
    for (const [key, value] of Object.entries(previous)) process.env[key] = value;
  }
}

const TMPFS_MAGIC = 0x01021994n;

function createTmpfsScratch(tempRoot: string | undefined): string {
  const root = path.resolve(tempRoot ?? tmpdir());
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (statfsSync(root, { bigint: true }).type !== TMPFS_MAGIC) {
    throw new Error("explorer scratch root is not tmpfs: " + root);
  }
  const scratch = mkdtempSync(path.join(root, "atfield-explorer-"));
  try {
    if (statfsSync(scratch, { bigint: true }).type !== TMPFS_MAGIC) {
      throw new Error("explorer scratch directory is not tmpfs: " + scratch);
    }
    return scratch;
  } catch (error) {
    rmSync(scratch, { recursive: true, force: true });
    throw error;
  }
}

function persistScratchArtifacts(scratchDirectory: string, runDirectory: string): void {
  for (const name of ["calls.jsonl", "lifecycle.jsonl", "marshal.spec", "mutation.spec"]) {
    const source = path.join(scratchDirectory, name);
    if (existsSync(source)) cpSync(source, path.join(runDirectory, name));
  }
}

async function canonicalReplay(
  profile: ExplorerProfile,
  seed: ExplorerSeed,
  runDirectory: string,
  collectorPath: string | undefined,
  timeoutMs: number,
  killGraceMs: number,
  enclCpu: number | undefined,
  watchCpu: number | undefined,
  tempRoot: string | undefined,
  mutation?: ScalarMutationRule,
): Promise<RunWithCapture> {
  mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
  const manifestPath = path.join(runDirectory, "attempt.json");
  const manifest = {
    schema: "atfield-explorer-attempt-v1",
    binding: profile.binding,
    seed,
    mutation: mutation ?? null,
    candidateKey: mutation ? mutationRuleKey(mutation) : null,
    startedAt: new Date().toISOString(),
  };
  writeFileSync(manifestPath, JSON.stringify({ ...manifest, status: "preparing" }, null, 2) + "\n", { mode: 0o600 });
  const scratchDirectory = createTmpfsScratch(tempRoot);
  try {
    const runnerTempRoot = path.join(scratchDirectory, "runner");
    mkdirSync(runnerTempRoot, { recursive: true, mode: 0o700 });
    const capturePath = path.join(scratchDirectory, "calls.jsonl");
    const lifecyclePath = path.join(scratchDirectory, "lifecycle.jsonl");
    const marshalSpecPath = path.join(scratchDirectory, "marshal.spec");
    writeFileSync(marshalSpecPath, profile.marshalSpecBytes, { mode: 0o600 });
    const runnerEnvironment: Record<string, string> = {
      ...baseRuntimeEnv(),
      ...seed.env,
      ATFIELD_CALL_CAPTURE_PATH: capturePath,
      ATFIELD_LIFECYCLE_PATH: lifecyclePath,
      ATFIELD_CAPTURE_BUFFERS: "1",
      ATFIELD_MARSHAL_LAYOUT_SHA256: profile.binding.marshalLayoutSha256,
      ATFIELD_EDL_ABI_SHA256: profile.edlAbiSha256,
      ATFIELD_MARSHAL_SPEC_PATH: marshalSpecPath,
    };
    if (mutation) {
      const specPath = path.join(scratchDirectory, "mutation.spec");
      try {
        writeFileSync(specPath, encodeMutationSpec(profile.binding, mutation), { mode: 0o600 });
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        writeFileSync(manifestPath, JSON.stringify({ ...manifest, status: "encoding_failed", reason: error.message }, null, 2) + "\n", { mode: 0o600 });
        throw new CandidatePreparationError(runDirectory, error.message);
      }
      runnerEnvironment.ATFIELD_MUTATION_SPEC_PATH = specPath;
    }

    let run: CanonicalRun;
    try {
      run = await withCleanRunnerEnvironment(runnerEnvironment, async () =>
        runCanonicalHost({
          bundlePath: profile.bundle.manifestPath,
          args: seed.args,
          seedId: seed.id,
          collectorPath,
          timeoutMs,
          killGraceMs,
          sample: "dynamic-explorer",
          mode: "explore",
          gateMode: "c-flush",
          enclCpu,
          watchCpu,
          tempRoot: runnerTempRoot,
          env: runnerEnvironment,
          artifactDir: runDirectory,
        }));
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      writeFileSync(manifestPath, JSON.stringify({ ...manifest, status: "runner_failed", reason: error.message }, null, 2) + "\n", { mode: 0o600 });
      throw error;
    }
    writeFileSync(path.join(runDirectory, "stdout.log"), run.stdout, { mode: 0o600 });
    writeFileSync(path.join(runDirectory, "stderr.log"), run.stderr, { mode: 0o600 });
    writeFileSync(manifestPath, JSON.stringify({ ...manifest, status: "run_finished", runId: run.runId,
      completion: run.completion, termination: run.termination, exitCode: run.exitCode,
      incompleteReasons: run.incompleteReasons, artifactPaths: run.artifactPaths }, null, 2) + "\n", { mode: 0o600 });
    const cost = readLifecycleCost(lifecyclePath, mutation);
    if (!existsSync(capturePath)) return { run, cost, captureError: "native call capture was not produced" };
    let nativeText: string;
    try {
      nativeText = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(capturePath));
    } catch (error) {
      return { run, cost, captureError: "native call capture is not valid UTF-8: " + String(error) };
    }
    try {
      const expectation = {
        ...profile.binding,
        runId: run.runId,
        ...(mutation ? {
          mutation: {
            ...(mutation.targetGeneration !== undefined ? { targetGeneration: mutation.targetGeneration } : {}),
            ...(mutation.execMode !== undefined ? { execMode: mutation.execMode } : {}),
            ...(mutation.opKind !== undefined ? { opKind: mutation.opKind } : {}),
            selectorOrdinal: mutation.selectorOrdinal,
            selectorSeq: mutation.selectorSeq,
            paramIndex: mutation.paramIndex,
            ...(mutation.prefixMutations?.length ? {
              prefixMutations: mutation.prefixMutations.map((pfx) => ({
                selectorOrdinal: pfx.selectorOrdinal,
                selectorSeq: pfx.selectorSeq,
              })),
            } : {}),
          },
        } : {}),
      };
      const completed = appendCallCaptureEnd(nativeText, run, expectation);
      writeFileSync(capturePath, completed.text, { mode: 0o600 });
      return { run, cost, capture: completed.capture };
    } catch (error) {
      return { run, cost, captureError: error instanceof Error ? error.message : String(error) };
    }
  } finally {
    persistScratchArtifacts(scratchDirectory, runDirectory);
    rmSync(scratchDirectory, { recursive: true, force: true });
  }
}

function reasonFor(result: RunWithCapture): string | null {
  if (result.captureError) return result.captureError;
  if (result.run.completion !== "complete") return result.run.incompleteReasons.join("; ") || "canonical trace is incomplete";
  if (result.run.timedOut) return "canonical run timed out";
  if (result.run.exitCode !== 0) return "canonical host did not exit successfully";
  if (!result.capture?.end.complete) return result.capture?.end.incompleteReasons.join("; ") || "call capture is incomplete";
  return null;
}

function observationKeys(run: CanonicalRun): Set<string> {
  const result = new Set<string>();
  const trace = run.parsedTrace ?? run.committedTrace;
  if (run.timedOut || !trace) return result;
  for (const observation of trace.observations) {
    for (const effect of observation.effects) {
      result.add(JSON.stringify([
        observation.fieldId,
        "0x" + observation.pageRva.toString(16),
        effect,
      ]));
    }
  }
  return result;
}

function effectMap(keys: Set<string>): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const key of keys) {
    const [fieldId, pageRva, effect] = JSON.parse(key) as [string, string, string];
    const pageKey = fieldId + "\0" + pageRva;
    const effects = result.get(pageKey) ?? new Set<string>();
    effects.add(effect);
    result.set(pageKey, effects);
  }
  return result;
}

function pageDelta(baseline: Set<string>, candidate: Set<string>): PageEffectDelta[] {
  const newKeys = [...candidate].filter((key) => !baseline.has(key));
  const byPage = effectMap(new Set(newKeys));
  return [...byPage.entries()]
    .map(([key, effects]) => {
      const split = key.indexOf("\0");
      return {
        fieldId: key.slice(0, split),
        pageRva: key.slice(split + 1),
        effects: [...effects].sort(),
      };
    })
    .sort((left, right) =>
      left.fieldId.localeCompare(right.fieldId) ||
      (BigInt(left.pageRva) < BigInt(right.pageRva) ? -1 : BigInt(left.pageRva) > BigInt(right.pageRva) ? 1 : 0),
    );
}

function stableBufferState(buffers: CallCaptureEvent["bufferInputs"] | CallCaptureEvent["bufferOutputs"]): unknown {
  return (buffers ?? []).map((buffer) => ({
    param_index: buffer.paramIndex,
    direction: buffer.direction,
    byte_length: buffer.byteLength,
    element_size: buffer.elementSize,
    is_string: buffer.isString,
    fnv1a64: buffer.fnv1a64,
    ...(buffer.sha256 ? { sha256: buffer.sha256 } : {}),
  }));
}

function scalarState(event: CallCaptureEvent | undefined): unknown {
  if (!event) return null;
  return {
    generation: event.generation,
    call_seq: event.callSeq,
    selector_ordinal: event.selectorOrdinal,
    selector_seq: event.selectorSeq,
    transport_status: event.transportStatus,
    scalar_inputs: event.scalarInputs,
    retval: event.retval,
    scalar_outputs: event.scalarOutputs,
    buffer_inputs: stableBufferState(event.bufferInputs),
    buffer_outputs: stableBufferState(event.bufferOutputs),
  };
}

function callHistoryDigest(capture: CallCaptureDocument): string {
  const history = canonicalProfileJson(
    capture.events.map((event) => ({
      generation: event.generation,
      call_seq: event.callSeq,
      selector_ordinal: event.selectorOrdinal,
      selector_seq: event.selectorSeq,
      transport_status: event.transportStatus,
      scalar_inputs: event.scalarInputs,
      retval: event.retval,
      scalar_outputs: event.scalarOutputs,
      buffer_inputs: stableBufferState(event.bufferInputs),
      buffer_outputs: stableBufferState(event.bufferOutputs),
    })),
  );
  return createHash("sha256").update(history).digest("hex");
}

function stateDigest(
  capture: CallCaptureDocument,
  rule: ScalarMutationRule,
  pageKeys: Set<string>,
  evidenceSiteIds: string[],
): string {
  const wantGen = rule.targetGeneration ?? 1;
  const event = capture.events.find((item) =>
    item.generation === wantGen &&
    item.selectorOrdinal === rule.selectorOrdinal &&
    item.selectorSeq === rule.selectorSeq);
  const state = canonicalProfileJson({
    state: scalarState(event),
    call_count: capture.events.length,
    field_page_effects: [...pageKeys].sort(),
    ir_frontier: [...evidenceSiteIds].sort(),
  });
  return createHash("sha256").update(state).digest("hex");
}

function measuredFieldCallKeys(traceText: string): Set<string> {
  const keys = new Set<string>();
  for (const line of traceText.split(/\r?\n/)) {
    if (!line) continue;
    try {
      const rec = JSON.parse(line) as Record<string, unknown>;
      if (rec.record_type === "ecall" && rec.measurement_valid === true &&
          Array.isArray(rec.fields) && rec.fields.length > 0) {
        keys.add([rec.instance_generation, rec.call_seq, rec.selector_ordinal, rec.selector_seq].join(":"));
      }
    } catch {}
  }
  return keys;
}

function measuredFieldSelectors(traceText: string): Set<string> {
  const keys = new Set<string>();
  for (const line of traceText.split(/\r?\n/)) {
    if (!line) continue;
    try {
      const rec = JSON.parse(line) as Record<string, unknown>;
      if (rec.record_type === "ecall" && rec.measurement_valid === true &&
          Array.isArray(rec.fields) && rec.fields.length > 0) {
        keys.add([rec.instance_generation, rec.selector_ordinal, rec.selector_seq].join(":"));
      }
    } catch {}
  }
  return keys;
}

function ruleFieldSelectorKeys(rule: ScalarMutationRule): string[] {
  const generation = rule.targetGeneration ?? 1;
  const keys = [generation + ":" + rule.selectorOrdinal + ":" + rule.selectorSeq];
  const consumer = rule.dataflowTarget;
  if (consumer) keys.push(consumer.consumerGeneration + ":" + consumer.consumerSelectorOrdinal + ":" + consumer.consumerSelectorSeq);
  return keys;
}

function targetFieldCallKeys(traceText: string, rule: ScalarMutationRule): Set<string> {
  const targetKeys = new Set(ruleFieldSelectorKeys(rule));
  const calls = new Set<string>();
  for (const line of traceText.split(/\r?\n/)) {
    if (!line) continue;
    try {
      const rec = JSON.parse(line) as Record<string, unknown>;
      if (rec.record_type !== "ecall" || rec.measurement_valid !== true ||
          !Array.isArray(rec.fields) || rec.fields.length === 0) continue;
      const selectorKey = [rec.instance_generation, rec.selector_ordinal, rec.selector_seq].join(":");
      if (targetKeys.has(selectorKey))
        calls.add([rec.instance_generation, rec.call_seq, rec.selector_ordinal, rec.selector_seq].join(":"));
    } catch {}
  }
  return calls;
}

function acceptedCandidateFeedback(
  baseline: RunWithCapture,
  candidate: RunWithCapture,
  plan: PlannedMutation,
): {
  accepted: boolean;
  reason: string | null;
  measurementComplete: boolean;
  businessOutcome: "ok" | "rejected";
  runTerminalState: "complete" | "business_rejection_exit" | "incomplete";
} {
  if (!baseline.capture) {
    return {
      accepted: false,
      reason: "baseline call capture is unavailable",
      measurementComplete: false,
      businessOutcome: "rejected",
      runTerminalState: "incomplete",
    };
  }
  if (candidate.captureError || candidate.run.timedOut) {
    return {
      accepted: false,
      reason: reasonFor(candidate),
      measurementComplete: false,
      businessOutcome: "rejected",
      runTerminalState: "incomplete",
    };
  }
  const trace = candidate.run.parsedTrace ?? candidate.run.committedTrace;
  const allowBizReject = candidate.run.parsedTrace === undefined && candidate.run.committedTrace !== undefined;
  if (!candidate.capture || !trace) {
    return {
      accepted: false,
      reason: reasonFor(candidate) ?? "candidate did not produce a complete four-phase trace and capture",
      measurementComplete: false,
      businessOutcome: "rejected",
      runTerminalState: "incomplete",
    };
  }
  if (!captureHasExactlyOneMutation(candidate.capture, plan.rule, { allowBusinessRejectionExit: allowBizReject })) {
    return {
      accepted: false,
      reason: "candidate capture does not prove exactly one matching mutation",
      measurementComplete: false,
      businessOutcome: trace.businessRejected ? "rejected" : "ok",
      runTerminalState: allowBizReject ? "business_rejection_exit" : "incomplete",
    };
  }
  if (!sameCallInputsExceptMutation(baseline.capture, candidate.capture, plan.rule)) {
    return {
      accepted: false,
      reason: "candidate call flow or non-target inputs changed",
      measurementComplete: false,
      businessOutcome: trace.businessRejected ? "rejected" : "ok",
      runTerminalState: allowBizReject ? "business_rejection_exit" : "incomplete",
    };
  }
  const linkedReason = linkedDataflowFailure(baseline.capture, candidate.capture, plan.rule, {
    complete: candidate.run.completion === "complete",
    exitCode: candidate.run.exitCode,
    traceText: candidate.run.traceText,
    traceValid: candidate.run.parsedTrace !== undefined,
  });
  if (linkedReason !== null) {
    return {
      accepted: false,
      reason: linkedReason,
      measurementComplete: true,
      businessOutcome: trace.businessRejected ? "rejected" : "ok",
      runTerminalState: candidate.run.completion === "complete" ? "complete" :
        allowBizReject ? "business_rejection_exit" : "incomplete",
    };
  }
  return {
    accepted: true,
    reason: null,
    measurementComplete: true,
    businessOutcome: trace.businessRejected ? "rejected" : "ok",
    runTerminalState: allowBizReject ? "business_rejection_exit" : "complete",
  };
}

interface QueuedCandidate {
  plan: PlannedMutation;
  depth: number;
  parentCandidateIndex: number | null;
  parentRunId: string;
  initialOrder: number;
}

export async function exploreSeeds(options: ExplorerOptions): Promise<ExplorerResult> {
  const profile = loadExplorerProfile(options.bundlePath);
  const budget = requireBudget(options.candidateBudget);
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) fail("timeoutMs must be in 1..300000");
  const killGraceMs = options.killGraceMs ?? 500;
  if (!Number.isSafeInteger(killGraceMs) || killGraceMs < 0) fail("killGraceMs must be nonnegative");
  const expansionBudget = {
    perBufferBytes: Number(options.expansionBufferBudgetBytes ?? DEFAULT_EXPANSION_BUFFER_BUDGET_BYTES),
    totalBytes: Number(options.expansionTotalBudgetBytes ?? DEFAULT_EXPANSION_TOTAL_BUDGET_BYTES),
  };
  if (!Number.isSafeInteger(expansionBudget.perBufferBytes) || expansionBudget.perBufferBytes < 1 ||
      expansionBudget.perBufferBytes > 0xffffffff || !Number.isSafeInteger(expansionBudget.totalBytes) ||
      expansionBudget.totalBytes < 1) fail("expansion budgets must be positive protocol-sized integers");
  const evidenceRoot = path.join(path.resolve(options.corpusPath), "runs");
  mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 });
  const temporaryRoot = mkdtempSync(path.join(evidenceRoot, "exploration-"));
  const seedResults: SeedExplorationResult[] = [];
  const exploreStartMs = Date.now();
  let remainingBudget = budget;
  let candidateRuns = 0;
  let acceptedCandidates = 0;
  let totalRealEcalls = 0;
  let totalEnclaveInstances = 0;
  let totalPrefixReplays = 0;
  let failedProbes = 0;
  let unmeasuredRuns = 0;
  let interruptedEcalls = 0;
  const seenStates = new Set<string>();
  const seenHistories = new Set<string>();
  const uniqueFeedback = new Set<string>();
  {
    for (const [seedIndex, rawSeed] of options.seeds.entries()) {
      const seed = validateSeed(rawSeed);
      const seedRoot = path.join(temporaryRoot, "seed-" + seedIndex);
      const baseline = await canonicalReplay(
        profile, seed, path.join(seedRoot, "baseline"),
        options.collectorPath, timeoutMs, killGraceMs,
        options.enclCpu, options.watchCpu, options.tempRoot,
      );
      if (baseline.cost) {
        totalRealEcalls += baseline.cost.realEcalls;
        totalEnclaveInstances += baseline.cost.enclaveInstances;
        interruptedEcalls += baseline.cost.interruptedEcalls;
      } else {
        unmeasuredRuns++;
      }
      const baselineReason = reasonFor(baseline);
      const baselineAccepted = baselineReason === null && baseline.capture !== undefined;
      const baselinePages = observationKeys(baseline.run);
      if (baselineAccepted) appendValidatedCorpusTrace(options.corpusPath, options.role, baseline.run, profile.bundle);
      const candidates: CandidateAttempt[] = [];
      const feedback: CandidateAttempt[] = [];
      const seedFrontier: FrontierEntry[] = [];
      if (baselineAccepted && baseline.capture && remainingBudget > 0) {
        const baselineHistory = callHistoryDigest(baseline.capture);
        const baselineFieldCalls = measuredFieldCallKeys(baseline.run.traceText);
        const enteredFieldCallKeys = new Set(baselineFieldCalls);
        const baselineFieldSelectors = measuredFieldSelectors(baseline.run.traceText);
        seenHistories.add(baselineHistory);

        const seenCandidateKeys = new Set<string>();
        let orderCounter = 0;
        const pendingQueue: QueuedCandidate[] = [];
        const enqueuePlans = (
          plans: readonly PlannedMutation[],
          depth: number,
          parentCandidateIndex: number | null,
          parentRunId: string,
        ): number => {
          let added = 0;
          for (const plan of plans) {
            plan.rule = { ...plan.rule, expansionBudget };
            const key = mutationRuleKey(plan.rule);
            if (seenCandidateKeys.has(key)) continue;
            seenCandidateKeys.add(key);
            pendingQueue.push({
              plan,
              depth,
              parentCandidateIndex,
              parentRunId,
              initialOrder: orderCounter++,
            });
            added++;
          }
          return added;
        };

        const rootPoolBudget = Math.max(remainingBudget * 3, 96);
        const rootPlans = deriveCandidatesFromCase(profile, baseline.capture, {
          budget: rootPoolBudget,
          depth: 0,
          frontier: seedFrontier,
          measuredFieldCallKeys: baselineFieldCalls,
          expansionBufferBudgetBytes: options.expansionBufferBudgetBytes,
          expansionTotalBudgetBytes: options.expansionTotalBudgetBytes,
        });
        const reservedLinkedConsumerKeys = reserveLinkedConsumerCallKeys(
          rootPlans, baselineFieldCalls, remainingBudget,
        );
        let nextLinkedConsumerReservation = 0;
        for (const plan of rootPlans) {
          seenStates.add(stateDigest(baseline.capture, plan.rule, baselinePages, plan.evidenceSiteIds));
        }
        enqueuePlans(rootPlans, 0, null, baseline.run.runId);

        const cumulativePages = new Set<string>(baselinePages);
        const targetFeedbackScore = new Map<string, number>();
        const siteFeedbackScore = new Map<string, number>();
        const opKindCounts = new Map<string, number>();
        const selectorCounts = new Map<string, number>();
        const fieldTargetCounts = new Map<string, number>();
        const hasNativeBuffersInBaseline = baseline.capture.events.some((ev) => ev.bufferInputs !== undefined);
        const exploredSites = new Set<string>();
        const targetKey = (rule: ScalarMutationRule): string =>
          (rule.opKind ?? "replace_scalar") + ":" + (rule.targetGeneration ?? 1) + ":" +
          rule.selectorOrdinal + ":" + rule.selectorSeq + ":" + rule.paramIndex;
        const onlineScore = (item: QueuedCandidate): number => {
          const plan = item.plan;
          const opKind = plan.rule.opKind ?? "replace_scalar";
          const tScore = targetFeedbackScore.get(targetKey(plan.rule)) ?? 0;
          let sScore = 0;
          let uncovered = 0;
          for (const siteId of plan.evidenceSiteIds) {
            sScore += siteFeedbackScore.get(siteId) ?? 0;
            if (!exploredSites.has(siteId)) uncovered++;
          }
          const cappedSScore = hasNativeBuffersInBaseline ? Math.max(-60, Math.min(120, sScore)) : sScore;
          const cappedTScore = hasNativeBuffersInBaseline ? Math.max(-100, Math.min(150, tScore)) : tScore;
          const cappedUncovered = hasNativeBuffersInBaseline ? (uncovered > 0 ? 40 : 0) : uncovered * 40;
          const subKey = plan.rule.bufferSubOp ?? "";
          const famKey = plan.rule.selectorOrdinal + ":" + opKind + ":" + subKey +
            (plan.rule.dataflowTarget ? ":dataflow" : "");
          const opCount = opKindCounts.get(famKey) ?? 0;
          const selCount = selectorCounts.get(String(plan.rule.selectorOrdinal)) ?? 0;
          const familyBonus = hasNativeBuffersInBaseline
            ? (opCount === 0 ? 450 : -75 * opCount)
            : 0;
          const selectorBonus = hasNativeBuffersInBaseline
            ? (selCount === 0 ? 550 : -60 * selCount)
            : 0;
          const childBonus = (hasNativeBuffersInBaseline && item.depth === 1) ? 5 : 0;
          const target = plan.rule.dataflowTarget;
          const measuredConsumerBonus = target && baselineFieldCalls.has([
            target.consumerGeneration, target.consumerCallSeq,
            target.consumerSelectorOrdinal, target.consumerSelectorSeq,
          ].join(":")) ? 150 : 0;
          const fieldTargetKey = ruleFieldSelectorKeys(plan.rule)
            .find((key) => baselineFieldSelectors.has(key));
          const fieldTargetCount = fieldTargetKey ? fieldTargetCounts.get(fieldTargetKey) ?? 0 : 0;
          const fieldTargetBonus = fieldTargetKey ? (fieldTargetCount === 0 ? 480 : -90 * fieldTargetCount) : 0;
          return plan.priority + cappedTScore + cappedSScore + cappedUncovered +
            familyBonus + selectorBonus + childBonus + measuredConsumerBonus + fieldTargetBonus;
        };

        const maxDerivationDepth = 3;
        let candidateIndex = 0;
        while (remainingBudget > 0 && pendingQueue.length > 0) {
          let bestIdx = -1;
          while (nextLinkedConsumerReservation < reservedLinkedConsumerKeys.length && bestIdx < 0) {
            const key = reservedLinkedConsumerKeys[nextLinkedConsumerReservation++]!;
            bestIdx = pendingQueue.findIndex((item) => linkedConsumerCallKey(item.plan.rule) === key);
          }
          if (bestIdx < 0) {
            bestIdx = 0;
            let bestScore = onlineScore(pendingQueue[0]!);
            for (let i = 1; i < pendingQueue.length; i++) {
              const score = onlineScore(pendingQueue[i]!);
              if (score > bestScore ||
                  (score === bestScore && pendingQueue[i]!.initialOrder < pendingQueue[bestIdx]!.initialOrder)) {
                bestIdx = i;
                bestScore = score;
              }
            }
          }
          const bestScore = onlineScore(pendingQueue[bestIdx]!);
          const [queued] = pendingQueue.splice(bestIdx, 1);
          const { plan, depth, parentCandidateIndex, parentRunId } = queued!;
          remainingBudget--;
          const candidateDirectory = path.join(seedRoot, "candidate-" + candidateIndex);
          let candidate: RunWithCapture;
          try {
            candidate = await canonicalReplay(
            profile,
            seed,
            candidateDirectory,
            options.collectorPath,
            timeoutMs,
            killGraceMs,
            options.enclCpu,
            options.watchCpu,
            options.tempRoot,
            plan.rule,
          );
          } catch (error) {
            if (!(error instanceof CandidatePreparationError)) throw error;
            candidates.push({ candidateIndex, selectorOrdinal: plan.rule.selectorOrdinal,
              selectorSeq: plan.rule.selectorSeq, paramIndex: plan.rule.paramIndex, value: plan.value,
              priority: bestScore, accepted: false, novel: false, reason: "encoding_failed: " + error.message,
              pageDelta: [], stateSha256: null, artifactPath: error.artifactPath,
              candidateKey: mutationRuleKey(plan.rule), measurementComplete: false, runTerminalState: "incomplete" });
            failedProbes++;
            candidateIndex++;
            continue;
          }
          candidateRuns++;
          if (candidate.cost) {
            totalRealEcalls += candidate.cost.realEcalls;
            totalEnclaveInstances += candidate.cost.enclaveInstances;
            totalPrefixReplays += candidate.cost.prefixReplays;
            interruptedEcalls += candidate.cost.interruptedEcalls;
          } else {
            unmeasuredRuns++;
          }
          const verdict = acceptedCandidateFeedback(baseline, candidate, plan);
          if (verdict.measurementComplete) {
            const sub = plan.rule.bufferSubOp ?? "";
            const family = plan.rule.selectorOrdinal + ":" + (plan.rule.opKind ?? "replace_scalar") + ":" + sub +
              (plan.rule.dataflowTarget ? ":dataflow" : "");
            opKindCounts.set(family, (opKindCounts.get(family) ?? 0) + 1);
            const selector = String(plan.rule.selectorOrdinal);
            selectorCounts.set(selector, (selectorCounts.get(selector) ?? 0) + 1);
          }
          if (candidate.capture?.events.some((event) => event.mutation?.reason === "expansion_budget_exceeded")) {
            seedFrontier.push({ reason: "expansion_budget_exceeded", stage: "execution", seedId: seed.id,
              targetGeneration: plan.rule.targetGeneration ?? 1, candidateKey: mutationRuleKey(plan.rule),
              rule: plan.rule, selectorOrdinal: plan.rule.selectorOrdinal, selectorSeq: plan.rule.selectorSeq,
              paramIndex: plan.rule.paramIndex, candidateValue: plan.value, affectedBuffers: [] });
          }
          if (!verdict.accepted) failedProbes++;
          const businessOk = verdict.businessOutcome === "ok";
          const candidatePages = verdict.accepted && businessOk && candidate.capture
            ? observationKeys(candidate.run)
            : new Set<string>();
          const delta = verdict.accepted && candidate.capture
            ? pageDelta(cumulativePages, candidatePages)
            : [];
          const digest = verdict.accepted && businessOk && candidate.capture
            ? stateDigest(candidate.capture, plan.rule, candidatePages, plan.evidenceSiteIds)
            : null;
          const histDigest = verdict.accepted && businessOk && candidate.capture
            ? callHistoryDigest(candidate.capture)
            : null;
          const novelState = digest !== null && !seenStates.has(digest);
          const novelHistory = histDigest !== null && !seenHistories.has(histDigest);
          // Distinct histories and a first measured target-Field call are useful even when page effects match.
          const candidateTargetFieldCalls = verdict.accepted && businessOk
            ? targetFieldCallKeys(candidate.run.traceText, plan.rule) : new Set<string>();
          const targetEnteredField = candidateTargetFieldCalls.size > 0;
          const newFieldEntry = [...candidateTargetFieldCalls].some((key) => !enteredFieldCallKeys.has(key));
          if (verdict.accepted && businessOk && verdict.measurementComplete) {
            for (const key of candidateTargetFieldCalls) enteredFieldCallKeys.add(key);
          }
          const novel = novelState || novelHistory || delta.length > 0 || newFieldEntry;
          if (digest !== null && novelState) {
            seenStates.add(digest);
            uniqueFeedback.add(digest);
          }
          if (histDigest !== null && novelHistory) {
            seenHistories.add(histDigest);
            uniqueFeedback.add(histDigest);
          }
          for (const key of candidatePages) cumulativePages.add(key);

          let spawnedChildrenCount = 0;
          if (verdict.accepted && candidate.capture && novel && depth < maxDerivationDepth &&
              (!hasNativeBuffersInBaseline || delta.length > 0 || plan.rule.opKind === "extend_history")) {
            const childPlans = deriveChildCandidatesFromFeedback(
              profile,
              baseline.capture,
              candidate.capture,
              plan,
              depth + 1,
              Math.max(remainingBudget * 2, 32),
              seedFrontier,
              {
                perBufferBytes: options.expansionBufferBudgetBytes,
                totalBytes: options.expansionTotalBudgetBytes,
              },
            );
            spawnedChildrenCount = enqueuePlans(
              childPlans,
              depth + 1,
              candidateIndex,
              candidate.run.runId,
            );
          }
          // Derive the next scalar step only after this fresh-process replay
          // passes the canonical measurement gate. A complete business rejection
          // may offer an adjacent search value, but earns no Field/page feedback.
          if (verdict.measurementComplete && candidate.capture && depth < maxDerivationDepth) {
            const onlinePlans = deriveOnlineScalarCandidates(
              profile,
              baseline.capture,
              candidate.capture,
              plan,
              {
                measurementComplete: verdict.measurementComplete,
                accepted: verdict.accepted,
                businessOutcome: verdict.businessOutcome,
                pageDeltaCount: delta.length,
                newFieldEntry,
              },
              {
                perBufferBytes: options.expansionBufferBudgetBytes,
                totalBytes: options.expansionTotalBudgetBytes,
              },
            );
            spawnedChildrenCount += enqueuePlans(
              onlinePlans,
              depth + 1,
              candidateIndex,
              candidate.run.runId,
            );
          }

          const tKey = targetKey(plan.rule);
          const tPrev = targetFeedbackScore.get(tKey) ?? 0;
          const rewardNovelOnly = !hasNativeBuffersInBaseline && novel;
          const tDelta = delta.length > 0 ? 250 : rewardNovelOnly ? 100 : verdict.accepted ? -25 : -50;
          targetFeedbackScore.set(tKey, tPrev + tDelta);
          for (const siteId of plan.evidenceSiteIds) {
            exploredSites.add(siteId);
            const sPrev = siteFeedbackScore.get(siteId) ?? 0;
            const sDelta = delta.length > 0 ? 150 : rewardNovelOnly ? 60 : -15;
            siteFeedbackScore.set(siteId, sPrev + sDelta);
          }
          const fieldTargetKey = ruleFieldSelectorKeys(plan.rule)
            .find((key) => baselineFieldSelectors.has(key));
          if (fieldTargetKey && targetEnteredField && verdict.measurementComplete) {
            fieldTargetCounts.set(fieldTargetKey, (fieldTargetCounts.get(fieldTargetKey) ?? 0) + 1);
          }
          const shouldCommit = verdict.accepted && businessOk && (novel || delta.length > 0) &&
            (candidate.run.completion === "complete" || targetEnteredField || delta.length > 0);
          const commitRole: TraceCorpusRole | null = shouldCommit
            ? (candidate.run.completion === "complete" ? options.role : "supplemental")
            : null;
          const candTraceSha256 = candidate.run.traceText
            ? createHash("sha256").update(candidate.run.traceText).digest("hex")
            : null;
          const attempt: CandidateAttempt = {
            candidateIndex,
            runId: candidate.run.runId,
            traceSha256: candTraceSha256,
            committedCorpusRole: commitRole,
            targetEnteredField,
            newFieldEntry,
            opKind: plan.rule.opKind ?? "replace_scalar",
            depth,
            parentCandidateIndex,
            parentRunId,
            spawnedChildrenCount,
            selectorOrdinal: plan.rule.selectorOrdinal,
            selectorSeq: plan.rule.selectorSeq,
            paramIndex: plan.rule.paramIndex,
            value: plan.value,
            priority: bestScore,
            accepted: verdict.accepted,
            novel,
            reason: verdict.reason,
            pageDelta: delta,
            stateSha256: digest,
            historySha256: histDigest,
            measurementComplete: verdict.measurementComplete,
            businessOutcome: verdict.businessOutcome,
            runTerminalState: verdict.runTerminalState,
            processReturnCode: candidate.run.exitCode,
            artifactPath: candidateDirectory,
            candidateKey: mutationRuleKey(plan.rule),
          };
          candidates.push(attempt);
          writeFileSync(path.join(candidateDirectory, "verdict.json"), JSON.stringify(attempt, null, 2) + "\n", { mode: 0o600 });
          if (attempt.accepted) acceptedCandidates++;
          if (!attempt.accepted && options.corpusPath) {
            const rejectedDir = path.join(options.corpusPath, "rejected", candidate.run.runId);
            mkdirSync(rejectedDir, { recursive: true, mode: 0o700 });
            cpSync(candidateDirectory, rejectedDir, { recursive: true });
          }
          if (commitRole !== null) {
            appendValidatedCorpusTrace(options.corpusPath, commitRole, candidate.run, profile.bundle);
            feedback.push(attempt);
          }
          candidateIndex++;
        }
        for (const queued of pendingQueue) {
          seedFrontier.push({ reason: "candidate_budget_exhausted", stage: "planning", seedId: seed.id,
            targetGeneration: queued.plan.rule.targetGeneration ?? 1, candidateKey: mutationRuleKey(queued.plan.rule),
            rule: queued.plan.rule, selectorOrdinal: queued.plan.rule.selectorOrdinal,
            selectorSeq: queued.plan.rule.selectorSeq, paramIndex: queued.plan.rule.paramIndex,
            candidateValue: queued.plan.value, affectedBuffers: [] });
        }
      }
      const baseTraceSha256 = baseline.run.traceText
        ? createHash("sha256").update(baseline.run.traceText).digest("hex")
        : null;
      seedResults.push({
        seedId: seed.id,
        baselineRunId: baseline.run.runId,
        baselineTraceSha256: baseTraceSha256,
        baselineArtifactPath: path.join(seedRoot, "baseline"),
        baselineAccepted,
        baselineReason,
        baselinePageEffects: baselinePages.size,
        candidates,
        feedback,
        unexploredFrontier: seedFrontier.map((entry) => ({ ...entry, seedId: seed.id,
          stage: entry.stage ?? "planning" })),
      });
    }
  }

  return {
    bundleManifestSha256: profile.bundle.manifestSha256,
    seedResults,
    baselineRuns: seedResults.length,
    candidateRuns,
    acceptedCandidates,
    uniqueFeedbackStates: uniqueFeedback.size,
    unexploredFrontier: seedResults.flatMap((seed) => seed.unexploredFrontier),
    costSummary: {
      totalRealEcalls,
      totalEnclaveInstances,
      totalPrefixReplays,
      failedProbes,
      totalElapsedMs: Math.max(0, Date.now() - exploreStartMs),
      unmeasuredRuns,
      interruptedEcalls,
    },
  };
}
