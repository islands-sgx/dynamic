#!/usr/bin/env bun
import process from "node:process";
import { runCanonicalHost, type GateMode } from "../lib/runner/canonical-runner.ts";

interface CliOptions {
  bundlePath: string;
  args: string[];
  collectorPath?: string;
  timeoutMs?: number;
  killGraceMs?: number;
  sample?: string;
  mode?: string;
  gateMode?: GateMode;
  enclCpu?: number;
  watchCpu?: number;
  artifactDir?: string;
  env?: Record<string, string>;
}

function usage(): string {
  return [
    "Run a Profile bundle host under the canonical native trace contract.",
    "",
    "Usage:",
    "  bun cli/run.ts --bundle <profile-bundle.json> [options] [-- <host-args...>]",
    "",
    "Options:",
    "  --bundle <file>         Profile bundle manifest or directory",
    "  --arg <value>           Single host argument (repeatable)",
    "  --collector <file>      Native LD_PRELOAD collector shared object",
    "  --timeout-ms <ms>       Per-run process timeout in milliseconds (default: 30000)",
    "  --kill-grace-ms <ms>    SIGTERM-to-SIGKILL grace period in milliseconds (default: 500)",
    "  --sample <name>         Sample label for run_start",
    "  --mode <mode>           Run mode: profile | explore | verify-pretouch (default: profile)",
    "  --gate-mode <mode>      4-gate mode: c-flush | c-preserve-tlb",
    "  --artifact-dir <dir>    Directory where trace artifacts are persisted",
    "  -- <host-args...>       Remaining arguments are passed directly to the host",
  ].join("\n");
}

function parsePositiveInt(value: string, flag: string): number {
  if (!/^[0-9]+$/.test(value)) throw new Error("invalid integer for " + flag);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error("out-of-range integer for " + flag);
  return parsed;
}

export function parseRunCliArgs(argv: string[]): CliOptions | { help: true } {
  let bundlePath = "";
  const args: string[] = [];
  let collectorPath: string | undefined;
  let timeoutMs: number | undefined;
  let killGraceMs: number | undefined;
  let sample: string | undefined;
  let mode: string | undefined;
  let gateMode: GateMode | undefined;
  let enclCpu: number | undefined;
  let watchCpu: number | undefined;
  let artifactDir: string | undefined;
  const env: Record<string, string> = {};

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (token === "--help" || token === "-h") return { help: true };
    if (token === "--") {
      args.push(...argv.slice(i + 1));
      break;
    }
    const next = argv[++i];
    if (next === undefined) throw new Error("missing value after " + token);
    if (token === "--bundle") bundlePath = next;
    else if (token === "--arg") args.push(next);
    else if (token === "--collector") collectorPath = next;
    else if (token === "--timeout-ms") timeoutMs = parsePositiveInt(next, token);
    else if (token === "--kill-grace-ms") killGraceMs = parsePositiveInt(next, token);
    else if (token === "--sample") sample = next;
    else if (token === "--mode") mode = next;
    else if (token === "--gate-mode") {
      if (next !== "c-flush" && next !== "c-preserve-tlb") {
        throw new Error("unsupported --gate-mode " + next);
      }
      gateMode = next;
    }
    else if (token === "--encl-cpu") enclCpu = parsePositiveInt(next, token);
    else if (token === "--watch-cpu") watchCpu = parsePositiveInt(next, token);
    else if (token === "--artifact-dir") artifactDir = next;
    else if (token === "--env") {
      const eq = next.indexOf("=");
      if (eq <= 0) throw new Error("invalid --env " + next);
      env[next.slice(0, eq)] = next.slice(eq + 1);
    }
    else throw new Error("unknown option " + token);
  }
  if (!bundlePath) throw new Error("missing required --bundle");
  return { bundlePath, args, collectorPath, timeoutMs, killGraceMs, sample, mode, gateMode, enclCpu, watchCpu, artifactDir, env };
}

async function main(): Promise<number> {
  try {
    const parsed = parseRunCliArgs(process.argv.slice(2));
    if ("help" in parsed) {
      console.log(usage());
      return 0;
    }
    const run = await runCanonicalHost(parsed);
    const summary = {
      schema: "atfield-canonical-runner-v1",
      run_id: run.runId,
      mode: run.mode,
      gate_mode: run.gateMode,
      cpu_config: {
        encl_cpu: run.cpuConfig.enclCpu,
        watch_cpu: run.cpuConfig.watchCpu,
        encl_cpu_source: run.cpuConfig.enclCpuSource,
        watch_cpu_source: run.cpuConfig.watchCpuSource,
        encl_cpu_isolated: run.cpuConfig.enclCpuIsolated,
        online_cpus: run.cpuConfig.onlineCpus,
        isolated_cpus: run.cpuConfig.isolatedCpus,
        process_initial_affinity_cpus: run.cpuConfig.processInitialAffinityCpus,
        effective_cpuset_cpus: run.cpuConfig.effectiveCpusetCpus,
        allowed_cpus: run.cpuConfig.allowedCpus,
        final_affinity_verified: run.cpuConfig.finalAffinityVerified ?? false,
      },
      seed_id: run.seedId,
      argv: run.argv,
      completion: run.completion,
      incomplete_reasons: run.incompleteReasons,
      timed_out: run.timedOut,
      exit_code: run.exitCode,
      trace_sha256: run.traceSha256,
      ecall_count: run.parsedTrace?.ecallCount ?? null,
      observed_fields: run.parsedTrace?.observedFieldIds ?? [],
      artifact_paths: run.artifactPaths ?? null,
    };
    console.log(JSON.stringify(summary, null, 2));
    return run.completion === "complete" ? 0 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

if (import.meta.main) {
  process.exitCode = await main();
}
