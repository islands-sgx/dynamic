import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
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
  mutationRuleKey,
  type PlannedMutation,
} from "./planner.ts";
import { appendValidatedCorpusTrace, type TraceCorpusRole } from "./corpus.ts";

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
}

export interface SeedExplorationResult {
  seedId: string;
  baselineAccepted: boolean;
  baselineReason: string | null;
  baselinePageEffects: number;
  candidates: CandidateAttempt[];
  feedback: CandidateAttempt[];
}

export interface ExplorerResult {
  bundleManifestSha256: string;
  seedResults: SeedExplorationResult[];
  baselineRuns: number;
  candidateRuns: number;
  acceptedCandidates: number;
  uniqueFeedbackStates: number;
}

interface RunWithCapture {
  run: CanonicalRun;
  capture?: CallCaptureDocument;
  captureError?: string;
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

async function canonicalReplay(
  profile: ExplorerProfile,
  seed: ExplorerSeed,
  runDirectory: string,
  collectorPath: string | undefined,
  timeoutMs: number,
  killGraceMs: number,
  enclCpu: number | undefined,
  watchCpu: number | undefined,
  mutation?: ScalarMutationRule,
): Promise<RunWithCapture> {
  mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
  const runnerTempRoot = path.join(runDirectory, "runner");
  mkdirSync(runnerTempRoot, { recursive: true, mode: 0o700 });
  const capturePath = path.join(runDirectory, "calls.jsonl");
  const marshalSpecPath = path.join(runDirectory, "marshal.spec");
  writeFileSync(marshalSpecPath, profile.marshalSpecBytes, { mode: 0o600 });
  const runnerEnvironment: Record<string, string> = {
    ...baseRuntimeEnv(),
    ...seed.env,
    ATFIELD_CALL_CAPTURE_PATH: capturePath,
    ATFIELD_CAPTURE_BUFFERS: "1",
    ATFIELD_MARSHAL_LAYOUT_SHA256: profile.binding.marshalLayoutSha256,
    ATFIELD_EDL_ABI_SHA256: profile.edlAbiSha256,
    ATFIELD_MARSHAL_SPEC_PATH: marshalSpecPath,
  };
  if (mutation) {
    const specPath = path.join(runDirectory, "mutation.spec");
    writeFileSync(specPath, encodeMutationSpec(profile.binding, mutation), { mode: 0o600 });
    runnerEnvironment.ATFIELD_MUTATION_SPEC_PATH = specPath;
  }

  const run = await withCleanRunnerEnvironment(runnerEnvironment, async () =>
    runCanonicalHost({
      bundlePath: profile.bundle.manifestPath,
      args: seed.args,
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
    }));
  if (!existsSync(capturePath)) return { run, captureError: "native call capture was not produced" };
  let nativeText: string;
  try {
    nativeText = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(capturePath));
  } catch (error) {
    return { run, captureError: "native call capture is not valid UTF-8: " + String(error) };
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
        },
      } : {}),
    };
    const completed = appendCallCaptureEnd(nativeText, run, expectation);
    writeFileSync(capturePath, completed.text, { mode: 0o600 });
    return { run, capture: completed.capture };
  } catch (error) {
    return { run, captureError: error instanceof Error ? error.message : String(error) };
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
  if (run.completion !== "complete" || run.timedOut || !run.parsedTrace) return result;
  for (const observation of run.parsedTrace.observations) {
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

function scalarState(event: CallCaptureEvent | undefined): unknown {
  if (!event) return null;
  return {
    generation: event.generation,
    call_seq: event.callSeq,
    selector_ordinal: event.selectorOrdinal,
    selector_seq: event.selectorSeq,
    transport_status: event.transportStatus,
    retval: event.retval,
    scalar_outputs: event.scalarOutputs,
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
      retval: event.retval,
      scalar_outputs: event.scalarOutputs,
      buffer_fnv1a64: (event.bufferInputs ?? []).map((b) => [b.paramIndex, b.byteLength, b.fnv1a64]),
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

function acceptedCandidateFeedback(
  baseline: RunWithCapture,
  candidate: RunWithCapture,
  plan: PlannedMutation,
): { accepted: boolean; reason: string | null } {
  const reason = reasonFor(candidate);
  if (reason) return { accepted: false, reason };
  if (!baseline.capture) return { accepted: false, reason: "baseline call capture is unavailable" };
  if (!candidate.capture || !candidate.run.parsedTrace) {
    return { accepted: false, reason: "candidate did not produce a complete four-phase trace and capture" };
  }
  if (!captureHasExactlyOneMutation(candidate.capture, plan.rule)) {
    return { accepted: false, reason: "candidate capture does not prove exactly one matching mutation" };
  }
  if (!sameCallInputsExceptMutation(baseline.capture, candidate.capture, plan.rule)) {
    return { accepted: false, reason: "candidate call flow or non-target inputs changed" };
  }
  return { accepted: true, reason: null };
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
  const temporaryRoot = mkdtempSync(path.join(options.tempRoot ?? tmpdir(), "atfield-explorer-"));
  const seedResults: SeedExplorationResult[] = [];
  let remainingBudget = budget;
  let candidateRuns = 0;
  let acceptedCandidates = 0;
  const seenStates = new Set<string>();
  const seenHistories = new Set<string>();
  const uniqueFeedback = new Set<string>();
  try {
    for (const [seedIndex, rawSeed] of options.seeds.entries()) {
      const seed = validateSeed(rawSeed);
      const seedRoot = path.join(temporaryRoot, "seed-" + seedIndex);
      const baseline = await canonicalReplay(
        profile, seed, path.join(seedRoot, "baseline"),
        options.collectorPath, timeoutMs, killGraceMs,
        options.enclCpu, options.watchCpu,
      );
      const baselineReason = reasonFor(baseline);
      const baselineAccepted = baselineReason === null && baseline.capture !== undefined;
      const baselinePages = observationKeys(baseline.run);
      if (baselineAccepted) appendValidatedCorpusTrace(options.corpusPath, options.role, baseline.run, profile.bundle);
      const candidates: CandidateAttempt[] = [];
      const feedback: CandidateAttempt[] = [];
      if (baselineAccepted && baseline.capture && remainingBudget > 0) {
        const baselineHistory = callHistoryDigest(baseline.capture);
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
        });
        for (const plan of rootPlans) {
          seenStates.add(stateDigest(baseline.capture, plan.rule, baselinePages, plan.evidenceSiteIds));
        }
        enqueuePlans(rootPlans, 0, null, baseline.run.runId);

        const cumulativePages = new Set<string>(baselinePages);
        const targetFeedbackScore = new Map<string, number>();
        const siteFeedbackScore = new Map<string, number>();
        const opKindCounts = new Map<string, number>();
        const selectorCounts = new Map<number, number>();
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
          const famKey = plan.rule.selectorOrdinal + ":" + opKind;
          const opCount = opKindCounts.get(famKey) ?? 0;
          const selCount = selectorCounts.get(plan.rule.selectorOrdinal) ?? 0;
          const familyBonus = hasNativeBuffersInBaseline
            ? (opCount === 0 ? 450 : -75 * opCount)
            : 0;
          const selectorBonus = hasNativeBuffersInBaseline
            ? (selCount === 0 ? 550 : -60 * selCount)
            : 0;
          const childBonus = (hasNativeBuffersInBaseline && item.depth > 0) ? 35 : 0;
          return plan.priority + cappedTScore + cappedSScore + cappedUncovered + familyBonus + selectorBonus + childBonus;
        };

        const maxDerivationDepth = 3;
        let candidateIndex = 0;
        while (remainingBudget > 0 && pendingQueue.length > 0) {
          let bestIdx = 0;
          let bestScore = onlineScore(pendingQueue[0]!);
          for (let i = 1; i < pendingQueue.length; i++) {
            const score = onlineScore(pendingQueue[i]!);
            if (score > bestScore ||
                (score === bestScore && pendingQueue[i]!.initialOrder < pendingQueue[bestIdx]!.initialOrder)) {
              bestIdx = i;
              bestScore = score;
            }
          }
          const [queued] = pendingQueue.splice(bestIdx, 1);
          const { plan, depth, parentCandidateIndex, parentRunId } = queued!;
          const chosenOp = plan.rule.selectorOrdinal + ":" + (plan.rule.opKind ?? "replace_scalar");
          opKindCounts.set(chosenOp, (opKindCounts.get(chosenOp) ?? 0) + 1);
          selectorCounts.set(plan.rule.selectorOrdinal, (selectorCounts.get(plan.rule.selectorOrdinal) ?? 0) + 1);
          remainingBudget--;
          candidateRuns++;
          const candidate = await canonicalReplay(
            profile,
            seed,
            path.join(seedRoot, "candidate-" + candidateIndex),
            options.collectorPath,
            timeoutMs,
            killGraceMs,
            options.enclCpu,
            options.watchCpu,
            plan.rule,
          );
          const verdict = acceptedCandidateFeedback(baseline, candidate, plan);
          const candidatePages = verdict.accepted && candidate.capture
            ? observationKeys(candidate.run)
            : new Set<string>();
          const delta = verdict.accepted && candidate.capture && candidate.run.completion === "complete"
            ? pageDelta(cumulativePages, candidatePages)
            : [];
          const digest = verdict.accepted && candidate.capture
            ? stateDigest(candidate.capture, plan.rule, candidatePages, plan.evidenceSiteIds)
            : null;
          const histDigest = verdict.accepted && candidate.capture
            ? callHistoryDigest(candidate.capture)
            : null;
          const novelState = digest !== null && !seenStates.has(digest);
          const novelHistory = histDigest !== null && !seenHistories.has(histDigest);
          // Distinct call histories continue exploration even when their current page set is identical
          const hasNativeBufferCapture = candidate.capture?.events.some((ev) => ev.bufferInputs !== undefined) ?? false;
          const novel = novelState || (hasNativeBufferCapture && novelHistory) || delta.length > 0;
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
          if (verdict.accepted && candidate.capture && novel && depth < maxDerivationDepth) {
            const childPlans = deriveChildCandidatesFromFeedback(
              profile,
              baseline.capture,
              candidate.capture,
              plan,
              depth + 1,
              Math.max(remainingBudget * 2, 32),
            );
            spawnedChildrenCount = enqueuePlans(
              childPlans,
              depth + 1,
              candidateIndex,
              candidate.run.runId,
            );
          }

          const tKey = targetKey(plan.rule);
          const tPrev = targetFeedbackScore.get(tKey) ?? 0;
          const tDelta = delta.length > 0 ? 250 : novel ? 100 : verdict.accepted ? -25 : -50;
          targetFeedbackScore.set(tKey, tPrev + tDelta);
          for (const siteId of plan.evidenceSiteIds) {
            exploredSites.add(siteId);
            const sPrev = siteFeedbackScore.get(siteId) ?? 0;
            const sDelta = delta.length > 0 ? 150 : novel ? 60 : -15;
            siteFeedbackScore.set(siteId, sPrev + sDelta);
          }
          const attempt: CandidateAttempt = {
            candidateIndex,
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
          };
          candidates.push(attempt);
          if (attempt.accepted) acceptedCandidates++;
          if (attempt.accepted && (attempt.novel || delta.length > 0)) {
            appendValidatedCorpusTrace(options.corpusPath, options.role, candidate.run, profile.bundle);
            feedback.push(attempt);
          }
          candidateIndex++;
        }
      }
      seedResults.push({
        seedId: seed.id,
        baselineAccepted,
        baselineReason,
        baselinePageEffects: baselinePages.size,
        candidates,
        feedback,
      });
    }
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }

  return {
    bundleManifestSha256: profile.bundle.manifestSha256,
    seedResults,
    baselineRuns: seedResults.length,
    candidateRuns,
    acceptedCandidates,
    uniqueFeedbackStates: uniqueFeedback.size,
  };
}
