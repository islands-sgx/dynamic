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
import { readCanonicalTrace } from "../lib/workset/trace.ts";
import { linkedDataflowFailure } from "../lib/explorer/linked-proof.ts";
import { proveColdFirstFieldTransfer } from "../lib/explorer/cold-proof.ts";

export const FORMAL_SAMPLES = ["qe3", "signal-cds", "sgxwallet", "ehsm", "ehsm-opt-1", "ehsm-opt-2"] as const;
const PHASES = ["default", "self-test"] as const;
export function validateSampleSelection(samples: readonly string[], pilot: boolean): void {
  if (!samples.length) throw new TypeError("at least one sample is required");
  if (new Set(samples).size !== samples.length) throw new TypeError("sample IDs must be unique");
  if (pilot) return;
  const a = [...samples].sort(), b = [...FORMAL_SAMPLES].sort();
  if (a.length !== b.length || a.some((x, i) => x !== b[i]))
    throw new TypeError("formal milestone requires exactly the six configured samples; use --pilot for a subset");
}
export function formalTargetsAccepted(samples: readonly string[], targets: readonly Record<string, unknown>[], failures: readonly string[], budget: number): boolean {
  try { validateSampleSelection(samples, false); } catch { return false; }
  if (failures.length || targets.length !== FORMAL_SAMPLES.length) return false;
  const actual = targets.map((target) => target.sample).sort();
  const expected = [...FORMAL_SAMPLES].sort();
  return actual.length === expected.length && actual.every((sample, i) => sample === expected[i]) &&
    targets.every((target) => {
      if (target.valid !== true || !Array.isArray(target.phases)) return false;
      const audits = Array.isArray(target.planningAudits) ? target.planningAudits : [];
      return PHASES.every((name) => (target.phases as unknown[]).some((value) => {
        if (!value || typeof value !== "object" || Array.isArray(value)) return false;
        const phase = value as Record<string, unknown>;
        if (phase.name !== name || phase.valid !== true || typeof phase.candidateRuns !== "number" ||
            phase.candidateRuns < budget || typeof phase.acceptedCompleteCandidates !== "number" ||
            phase.acceptedCompleteCandidates < 1) return false;
        const phaseAudits = audits.filter((item) => !!item && typeof item === "object" && !Array.isArray(item) &&
          (item as Record<string, unknown>).phase === name &&
          (item as Record<string, unknown>).attempt === phase.attempt);
        if (phaseAudits.length === 0 || phaseAudits.some((item) => {
          const count = (item as Record<string, unknown>).coupledEncodable;
          const linkedCount = (item as Record<string, unknown>).linkedEncodable;
          return !Number.isSafeInteger(count) || (count as number) < 0 ||
            !Number.isSafeInteger(linkedCount) || (linkedCount as number) < 0;
        })) return false;
        const linkedOpportunity = phaseAudits.some((item) =>
          ((item as Record<string, unknown>).linkedEncodable as number) > 0);
        if (!Number.isSafeInteger(phase.coldOpportunities) || !Number.isSafeInteger(phase.coldTransfers) ||
            (phase.coldOpportunities as number) < 0 || (phase.coldTransfers as number) < 0 ||
            (phase.coldTransfers as number) !== (phase.coldOpportunities as number) ||
            !Array.isArray(phase.coldProofFailures) || phase.coldProofFailures.length !== 0) return false;
        return !linkedOpportunity || (typeof phase.linkedExecutions === "number" && phase.linkedExecutions >= 1);
      }));
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
  capture: CallCaptureDocument;
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
  return { manifest, capture, traceText: new TextDecoder("utf-8", { fatal: true }).decode(traceBytes) };
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
    if (candidateAccepted !== true || candidateMeasurementComplete !== true) {
      throw new TypeError("explorer did not accept this candidate as a complete measurement");
    }
    const verdict = asRecord(JSON.parse(readFileSync(path.join(candidateDirectory, "verdict.json"), "utf8")), "candidate verdict");
    if (verdict.runId !== candidateRunId || verdict.accepted !== true || verdict.measurementComplete !== true) {
      throw new TypeError("candidate verdict is not accepted and complete");
    }
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
function phaseValidity(p: Phase, binding: MutationBinding, budget: number): string | null {
  if (p.result.seedResults.length !== 1 || p.result.baselineRuns !== 1) return "expected exactly one baseline seed";
  const s = p.result.seedResults[0]!;
  if (!s.baselineAccepted || !s.baselineArtifactPath || !s.baselineRunId) return s.baselineReason ?? "baseline was not accepted";
  try {
    const c = parseCallCapture(readFileSync(path.join(s.baselineArtifactPath, "calls.jsonl"), "utf8"), { ...binding, runId: s.baselineRunId });
    if (!c.end.complete || !c.events.length) return "baseline capture is incomplete or empty";
    if (p.result.bundleManifestSha256 !== binding.bundleManifestSha256) return "bundle identity mismatch";
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
    if (!Number.isSafeInteger(budget) || budget < 1) throw new TypeError("budget must be positive");
    validateSampleSelection(samples, pilot);
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
    const sources: Record<string, string> = {}; snapshot("lib", sources); snapshot("src", sources);
    const script = path.resolve(fileURLToPath(import.meta.url)); sources[script] = hash(readFileSync(script));
    frozen = { collectorSha256: collectorHash, sources,
      inputs: inputs.map((i) => ({ sample: i.sample, ...i.freeze })) };
    writeJson(path.join(out, "frozen.json"), frozen);

    for (const i of inputs) {
      const { sample, profile, bundlePath } = i, dest = path.join(out, sample), corpusPath = path.join(dest, "corpus");
      mkdirSync(dest, { recursive: true, mode: 0o700 });
      const phases: Phase[] = [];
      for (const [name, role, args] of [["default", "main", []], ["self-test", "supplemental", ["--self-test"]]] as const) {
        for (let attempt = 0; attempt < 6; attempt++) {
          const result = await exploreSeeds({
            bundlePath, corpusPath, role, seeds: [{ id: name, args: [...args], env: {} }],
            collectorPath: collector, candidateBudget: budget, expansionBufferBudgetBytes: 262144n,
            expansionTotalBudgetBytes: 1048576n, enclCpu: 46, watchCpu: 1,
          });
          const p: Phase = { name, attempt, result, valid: false };
          p.invalidReason = result.bundleManifestSha256 === profile.binding.bundleManifestSha256
            ? phaseValidity(p, profile.binding, budget) : "result bundle identity mismatch";
          p.valid = p.invalidReason === null; phases.push(p);
          writeJson(path.join(dest, name + "-" + attempt + ".result.json"), result);
          console.log(JSON.stringify({ sample, phase: name, attempt, baselineAccepted: result.seedResults[0]?.baselineAccepted,
            candidates: result.candidateRuns, accepted: result.acceptedCandidates, valid: p.valid, invalidReason: p.invalidReason }));
          if (result.seedResults.every((seed) => seed.baselineAccepted)) break;
        }
      }
      const corpus = readFinalizableCorpus(corpusPath, bundlePath);
      const workset = buildWorkset(profile.bundle, corpus.map((t) => t.parsedTrace));
      writeJson(path.join(dest, "workset.v2.json"), workset);
      const planningAudits: Array<{ phase: string; attempt: number; plans: number; coupled: number; coupledEncodable: number; linkedEncodable: number; failures: Array<{ rule: unknown; reason: string }> }> = [];
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
        planningAudits.push({ phase: p.name, attempt: p.attempt, plans: plans.length,
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
        const linkedPlansAvailable = planningAudits.filter((audit) => audit.phase === p.name && audit.attempt === p.attempt)
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
        const missingColdProof = coldProofFailures.length > 0;
        const missingLinkedProof = linkedPlansAvailable > 0 && linkedExecutions === 0;
        const invalidReason = missingLinkedProof
          ? "encodable linked dataflow plans available (" + linkedPlansAvailable +
            ") but no independently verified accepted complete linked execution; failures=" +
            JSON.stringify(linkedProofFailures.slice(0, 3)) + "; frontier entries=" + p.result.unexploredFrontier.length
          : missingColdProof ? "fresh-enclave first-Field object transfer proof failed: " +
            JSON.stringify(coldProofFailures) : p.invalidReason;
        const phaseValid = p.valid && !missingLinkedProof && !missingColdProof;
        return {
          name: p.name, attempt: p.attempt, valid: phaseValid, invalidReason,
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
      const valid = PHASES.every((name) => phaseSummaries.some((phase) => phase.name === name && phase.valid));
      if (!valid) failures.push(sample + ": default and self-test phases need an accepted attempt with complete candidate, linked, and cold proof evidence");
      const coupledExecutions = phaseSummaries.reduce((sum, phase) => sum + phase.coupledExecutions, 0);
      const linkedExecutions = phaseSummaries.reduce((sum, phase) => sum + phase.linkedExecutions, 0);
      completed.push({ sample, bundleManifestSha256: profile.binding.bundleManifestSha256, valid,
        phases: phaseSummaries, fields, planningAudits,
        accepted: candidates.filter((x) => x.accepted).length,
        rejected: candidates.filter((x) => !x.accepted).length,
        coupledExecutions, linkedExecutions, sourceTraces: workset.source_traces });
      writeJson(partialPath, { schema: "atfield-milestone-v3", status: "partial", mode: pilot ? "pilot" : "formal",
        runId, budgetPerPhase: budget, frozen, completedSamples: completed,
        requiredSamples: pilot ? samples : FORMAL_SAMPLES, failures });
      checkFreeze(sources, collector, collectorHash, inputs);
    }
    const success = pilot
      ? failures.length === 0 && completed.length === samples.length && completed.every((target) => target.valid === true)
      : formalTargetsAccepted(samples, completed, failures, budget);
    if (!success) {
      failures.push(pilot ? "pilot targets did not pass their phase validation" :
        "formal acceptance requires six configurations, budget candidate runs, accepted complete candidates, independently verified linked execution, and cold first-Field transfer when prior-generation objects are observed");
      const failed = { schema: "atfield-milestone-v3", status: "failed", mode: pilot ? "pilot" : "formal", runId,
        budgetPerPhase: budget, frozen, completedSamples: completed, requiredSamples: pilot ? samples : FORMAL_SAMPLES, failures };
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
