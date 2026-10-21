#!/usr/bin/env bun
import { mkdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { exploreSeeds } from "../lib/explorer/explorer.ts";

interface CliOptions {
  bundlePath: string;
  corpusPath: string;
  role: "main" | "supplemental";
  hostArgs: string[];
  collectorPath?: string;
  candidateBudget: number;
  timeoutMs: number;
  killGraceMs: number;
  enclCpu?: number;
  watchCpu?: number;
  reportJsonPath?: string;
}

function fail(message: string): never { throw new TypeError(message); }

function integer(value: string, label: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) fail(label + " must be a decimal integer");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) fail(label + " is outside range");
  return parsed;
}

export function parseArgs(argv: string[]): CliOptions {
  const separator = argv.indexOf("--");
  if (separator < 0) fail("host arguments must follow --");
  const optionArgs = argv.slice(0, separator);
  const hostArgs = argv.slice(separator + 1);
  const values = new Map<string, string>();
  const allowed = ["--bundle", "--corpus", "--role", "--collector", "--budget", "--timeout-ms", "--kill-grace-ms", "--encl-cpu", "--watch-cpu", "--report-json"];
  for (let i = 0; i < optionArgs.length; i++) {
    const key = optionArgs[i]!;
    if (!allowed.includes(key)) fail("unsupported option " + key);
    if (values.has(key)) fail("option is repeated: " + key);
    const value = optionArgs[++i];
    if (!value || value === "--" || value.startsWith("--")) fail("option requires a value: " + key);
    values.set(key, value);
  }
  const bundlePath = values.get("--bundle");
  const corpusPath = values.get("--corpus");
  const role = values.get("--role");
  if (!corpusPath || !role) fail("--corpus and --role are required");
  if (role !== "main" && role !== "supplemental") fail("--role must be main or supplemental");
  if (!bundlePath) fail("--bundle is required");
  if (hostArgs.some((arg) => arg.includes("\0"))) fail("host arguments must be NUL-free strings");
  return {
    bundlePath: path.resolve(bundlePath),
    corpusPath: path.resolve(corpusPath),
    role,
    hostArgs: [...hostArgs],
    collectorPath: values.has("--collector") ? path.resolve(values.get("--collector")!) : undefined,
    candidateBudget: values.has("--budget") ? integer(values.get("--budget")!, "--budget", 0) : 64,
    timeoutMs: values.has("--timeout-ms") ? integer(values.get("--timeout-ms")!, "--timeout-ms", 1, 300000) : 30000,
    killGraceMs: values.has("--kill-grace-ms") ? integer(values.get("--kill-grace-ms")!, "--kill-grace-ms", 0) : 500,
    enclCpu: values.has("--encl-cpu") ? integer(values.get("--encl-cpu")!, "--encl-cpu", 0) : undefined,
    watchCpu: values.has("--watch-cpu") ? integer(values.get("--watch-cpu")!, "--watch-cpu", 0) : undefined,
    reportJsonPath: values.has("--report-json") ? path.resolve(values.get("--report-json")!) : undefined,
  };
}

function repositoryRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

function collectorPath(options: CliOptions): string {
  const candidate = options.collectorPath ?? path.join(repositoryRoot(), "build", "libatfield_native_sgx.so");
  const resolved = realpathSync(candidate);
  if (!statSync(resolved).isFile()) fail("collector path is not a regular file");
  return resolved;
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const options = parseArgs(argv);
  const result = await exploreSeeds({
    bundlePath: options.bundlePath,
    corpusPath: options.corpusPath,
    role: options.role,
    seeds: [{ id: "direct-host-sequence", args: options.hostArgs, env: {} }],
    collectorPath: collectorPath(options),
    candidateBudget: options.candidateBudget,
    timeoutMs: options.timeoutMs,
    killGraceMs: options.killGraceMs,
    enclCpu: options.enclCpu,
    watchCpu: options.watchCpu,
  });
  const baselineRejected = result.seedResults.filter((entry) => !entry.baselineAccepted).length;
  const rejectedCandidates = result.seedResults.flatMap((entry) => entry.candidates)
    .filter((entry) => !entry.accepted).length;
  if (options.reportJsonPath) {
    mkdirSync(path.dirname(options.reportJsonPath), { recursive: true });
    writeFileSync(options.reportJsonPath, JSON.stringify(result, null, 2) + "\n");
  }
  process.stdout.write(
    "Exploration finished: " + result.baselineRuns + " baseline run(s), " +
    result.candidateRuns + " candidate run(s), " + result.acceptedCandidates +
    " complete candidate(s), " + result.uniqueFeedbackStates + " unique feedback state(s), " +
    baselineRejected + " rejected baseline(s), " + rejectedCandidates + " rejected candidate(s).\n",
  );
}

if (import.meta.main) {
  main().catch((error) => {
    process.stderr.write((error instanceof Error ? error.message : String(error)) + "\n");
    process.exitCode = 1;
  });
}
