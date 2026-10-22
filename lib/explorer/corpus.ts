import {
  linkSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { loadProfileBundle, type ProfileBundle } from "../bundle/profile-bundle.ts";
import { parseCanonicalTrace, readCanonicalTrace, type ParsedTrace } from "../workset/trace.ts";
import type { CanonicalRun } from "../runner/canonical-runner.ts";

export type TraceCorpusRole = "main" | "supplemental";

export interface CorpusTrace {
  role: TraceCorpusRole;
  path: string;
  runId: string;
  traceSha256: string;
  parsedTrace: ParsedTrace;
}

function fail(message: string): never {
  throw new TypeError(message);
}

function validateRole(role: string): asserts role is TraceCorpusRole {
  if (role !== "main" && role !== "supplemental") fail("trace corpus role must be main or supplemental");
}

function validatedCorpusTrace(
  run: CanonicalRun,
  bundle: ProfileBundle,
  role: TraceCorpusRole,
): ParsedTrace {
  if (run.timedOut) {
    fail("only complete, non-timeout, successful canonical traces can enter the corpus");
  }
  const allowBizReject = role === "supplemental" && run.committedTrace !== undefined;
  const expectedTrace = allowBizReject ? run.committedTrace : run.parsedTrace;
  if (!allowBizReject && (run.completion !== "complete" || run.exitCode !== 0 || !expectedTrace)) {
    fail("only complete, non-timeout, successful canonical traces can enter the corpus");
  }
  if (!expectedTrace) {
    fail("only complete, non-timeout, successful canonical traces can enter the corpus");
  }
  const parsed = parseCanonicalTrace(
    run.traceText,
    "canonical explorer corpus trace",
    bundle,
    { allowBusinessRejectionExit: allowBizReject },
  );
  if (parsed.runId !== run.runId || parsed.traceSha256 !== expectedTrace.traceSha256) {
    fail("canonical run trace identity differs from its parsed result");
  }
  if (parsed.mode !== "profile" && parsed.mode !== "explore") {
    fail("only acquisition-mode (profile or explore) traces can enter the corpus");
  }
  return parsed;
}

export function appendValidatedCorpusTrace(
  corpusDirectory: string,
  role: TraceCorpusRole,
  run: CanonicalRun,
  bundle: ProfileBundle,
): string {
  validateRole(role);
  validatedCorpusTrace(run, bundle, role);
  mkdirSync(path.resolve(corpusDirectory), { recursive: true, mode: 0o700 });
  const root = realpathSync(path.resolve(corpusDirectory));
  const roleDirectory = path.join(root, role);
  mkdirSync(roleDirectory, { recursive: true, mode: 0o700 });
  if (!lstatSync(roleDirectory).isDirectory()) fail("trace corpus role path must be a directory");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(run.runId)) {
    fail("canonical run id is not a UUID");
  }
  const destination = path.join(roleDirectory, run.runId + ".jsonl");
  const temporary = path.join(roleDirectory, ".tmp-" + randomUUID());
  writeFileSync(temporary, run.traceText, { flag: "wx", mode: 0o600 });
  try {
    linkSync(temporary, destination);
  } finally {
    rmSync(temporary, { force: true });
  }
  return destination;
}

export function readFinalizableCorpus(
  corpusDirectory: string,
  bundlePath: string,
): CorpusTrace[] {
  let root: string;
  try {
    root = realpathSync(path.resolve(corpusDirectory));
  } catch (error) {
    fail("trace corpus directory is unavailable: " + String(error));
  }
  if (!lstatSync(root).isDirectory()) fail("trace corpus path must be a directory");
  const bundle = loadProfileBundle(bundlePath);
  const roles: TraceCorpusRole[] = ["main", "supplemental"];
  /* "rejected" holds preserved evidence from failed candidates — it is not a
     corpus role and its contents are never validated into the corpus. */
  const nonRoleEntries = new Set(["rejected", "runs"]);
  const traces: CorpusTrace[] = [];
  let mainCount = 0;
  const entries = readdirSync(root, { withFileTypes: true });
  const unknownRole = entries.find((entry) =>
    !roles.includes(entry.name as TraceCorpusRole) && !nonRoleEntries.has(entry.name));
  if (unknownRole) fail("trace corpus contains unsupported entry " + unknownRole.name);
  for (const role of roles) {
    const roleDirectory = path.join(root, role);
    try {
      if (!lstatSync(roleDirectory).isDirectory()) fail("trace corpus role path must be a directory");
    } catch (error) {
      if (role === "main") continue;
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    const files = readdirSync(roleDirectory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const file of files) {
      if (!file.isFile() || !/^[0-9a-f-]+\.jsonl$/i.test(file.name)) {
        fail("trace corpus contains an unsupported file " + path.join(role, file.name));
      }
      const filename = path.join(roleDirectory, file.name);
      const parsedTrace = readCanonicalTrace(filename, bundle, { allowBusinessRejectionExit: role === "supplemental" });
      const expectedId = file.name.slice(0, -".jsonl".length);
      if (parsedTrace.runId !== expectedId) fail("trace corpus filename does not match the canonical run id");
      traces.push({ role, path: filename, runId: parsedTrace.runId, traceSha256: parsedTrace.traceSha256, parsedTrace });
      if (role === "main") mainCount++;
    }
  }
  if (mainCount === 0) fail("finalizing the trace corpus requires at least one complete main run");
  const coveredFields = new Set<string>();
  for (const trace of traces) {
    for (const obs of trace.parsedTrace.observations) {
      if (obs.effects.length > 0) coveredFields.add(obs.fieldId);
    }
  }
  for (const field of bundle.fields) {
    if (!coveredFields.has(field.id)) {
      fail("finalizing the trace corpus requires complete valid S3 observations for live Field " + field.id);
    }
  }
  return traces.sort((left, right) =>
    left.role.localeCompare(right.role) || left.runId.localeCompare(right.runId));
}
