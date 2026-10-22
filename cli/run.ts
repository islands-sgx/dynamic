#!/usr/bin/env bun
import process from "node:process";
import { runCanonicalHost, type GateMode } from "../lib/runner/canonical-runner.ts";

interface CliOptions {
  bundlePath: string;
  args: string[];
  finalV2TargetPath?: string;
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
    "  --bundle <file>         Verified Profile bundle manifest or directory",
    "  --final-v2-target <file> Frozen v2 Final/ReadyTable measurement identity",
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

export function finalV2S3Verdict(
  targetKind: "profile" | "final-v2",
  completion: "complete" | "incomplete",
  s3PageCount: number,
  measuredFieldCount: number,
): "NOT_APPLICABLE" | "INCOMPLETE" | "FAIL" | "PASS" {
  if (targetKind !== "final-v2") return "NOT_APPLICABLE";
  if (completion !== "complete") return "INCOMPLETE";
  if (measuredFieldCount < 1 || s3PageCount > 0) return "FAIL";
  return "PASS";
}

type JsonRecord = Record<string, unknown>;
function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function eventFields(record: JsonRecord): Array<{ field_id?: unknown; s2: unknown; s3: unknown }> {
  if (!Array.isArray(record.fields)) return [];
  return record.fields.filter(isRecord).map((field) => {
    const phases = isRecord(field.phases) ? field.phases : field;
    return { field_id: field.field_id, s2: phases.S2_PRETOUCH ?? phases.s2 ?? null, s3: phases.S3_BODY ?? phases.s3 ?? null };
  });
}
function pageEffects(fieldPhase: unknown): unknown[] {
  return isRecord(fieldPhase) && Array.isArray(fieldPhase.page_effects) ? fieldPhase.page_effects : [];
}
function hasNonzeroBusinessResult(record: JsonRecord): boolean {
  if (typeof record.sgx_status === "number" && record.sgx_status !== 0) return true;
  if (typeof record.out_status_i32 === "number" && record.out_status_i32 !== 0) return true;
  if (typeof record.abi_return_value === "number" && record.abi_return_value !== 0) return true;
  if (typeof record.abi_return_value === "string" && record.abi_return_value !== "0") return true;
  const business = record.business_result;
  if (!isRecord(business)) return false;
  return (typeof business.status === "number" && business.status !== 0) ||
    (typeof business.value === "number" && business.value !== 0) ||
    (typeof business.value === "string" && business.value !== "0");
}
export function summarizeTraceEcalls(traceText: string): {
  total_ecalls: number; valid_empty_s3_ecalls: number; abnormal_ecalls: JsonRecord[];
} {
  let total = 0;
  let validEmptyS3 = 0;
  const abnormal: JsonRecord[] = [];
  for (const line of traceText.split(/\r?\n/)) {
    if (!line) continue;
    let value: unknown;
    try { value = JSON.parse(line); } catch { continue; }
    if (!isRecord(value) || value.record_type !== "ecall") continue;
    total++;
    const fields = eventFields(value);
    const s3Nonempty = fields.some((field) => pageEffects(field.s3).length > 0);
    const aex = isRecord(value.aex) ? value.aex : null;
    const unexpectedAex = !aex || typeof aex.unexpected_count !== "number" || aex.unexpected_count !== 0 ||
      (typeof aex.outside_window_count === "number" && aex.outside_window_count !== 0);
    const invalid = value.measurement_valid !== true ||
      !Array.isArray(value.measurement_invalid_reasons) || value.measurement_invalid_reasons.length !== 0 ||
      value.readiness_installed !== true;
    const businessAnomaly = hasNonzeroBusinessResult(value);
    const anomalous = invalid || unexpectedAex || businessAnomaly || s3Nonempty;
    if (fields.length > 0 && !s3Nonempty && !invalid && !unexpectedAex && !businessAnomaly) validEmptyS3++;
    if (anomalous) {
      abnormal.push({
        call_seq: value.call_seq ?? null, selector_ordinal: value.selector_ordinal ?? null, tag: value.tag ?? null,
        sgx_status: value.sgx_status ?? null, abi_return_value: value.abi_return_value ?? null, out_status_i32: value.out_status_i32 ?? null,
        measurement_valid: value.measurement_valid ?? null, measurement_invalid_reasons: value.measurement_invalid_reasons ?? null,
        readiness_installed: value.readiness_installed ?? null, fields, aex,
      });
    }
  }
  return { total_ecalls: total, valid_empty_s3_ecalls: validEmptyS3, abnormal_ecalls: abnormal };
}

function shortOutput(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.length > 512 ? trimmed.slice(-512) : trimmed;
}
function parsePositiveInt(value: string, flag: string): number {
  if (!/^[0-9]+$/.test(value)) throw new Error("invalid integer for " + flag);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error("out-of-range integer for " + flag);
  return parsed;
}

export function parseRunCliArgs(argv: string[]): CliOptions | { help: true } {
  let bundlePath = "";
  let finalV2TargetPath: string | undefined;
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
    else if (token === "--final-v2-target") finalV2TargetPath = next;
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
  return { bundlePath, args, finalV2TargetPath, collectorPath, timeoutMs, killGraceMs, sample, mode, gateMode, enclCpu, watchCpu, artifactDir, env };
}

async function main(): Promise<number> {
  try {
    const parsed = parseRunCliArgs(process.argv.slice(2));
    if ("help" in parsed) {
      console.log(usage());
      return 0;
    }
    const run = await runCanonicalHost(parsed);
    const s3PageCount = run.parsedTrace?.observations.length ?? 0;
    const measuredFieldCount = run.parsedTrace?.measuredFieldIds.length ?? 0;
    const s3Verdict = finalV2S3Verdict(run.targetKind, run.completion, s3PageCount, measuredFieldCount);
    const callDiagnostics = summarizeTraceEcalls(run.traceText);
    const summary = {
      schema: "atfield-canonical-runner-v1",
      run_id: run.runId,
      mode: run.mode,
      gate_mode: run.gateMode,
      target_kind: run.targetKind,
      selected_enclave_sha256: run.selectedEnclaveSha256,
      s3_body_page_observations: run.parsedTrace?.observations.map((observation) => ({
        field_id: observation.fieldId,
        page_rva: "0x" + observation.pageRva.toString(16),
        a: observation.accessed,
        d: observation.dirty,
        effects: observation.effects,
      })) ?? [],
      s3_body_rule: "raw S3_BODY page set must be empty for Final v2 PASS; S2 is never subtracted",
      final_v2_validation: run.targetKind === "final-v2" ? {
        criterion: "at least one valid target Field is measured and the raw S3_BODY page set is empty; S2 is never subtracted",
        verdict: s3Verdict,
        observed_page_count: s3PageCount,
        measured_field_ids: run.parsedTrace?.measuredFieldIds ?? [],
        manifest_field_count: run.finalV2Target?.manifestFieldCount ?? null,
        final_v2_target: run.finalV2Target ?? null,
        call_diagnostics: callDiagnostics,
      } : null,
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
      measured_fields: run.parsedTrace?.measuredFieldIds ?? [],
      artifact_paths: run.artifactPaths ?? null,
      child_stderr_excerpt: shortOutput(run.stderr),
    };
    console.log(JSON.stringify(summary, null, 2));
    return run.completion === "complete" && (run.targetKind !== "final-v2" || s3Verdict === "PASS") ? 0 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

if (import.meta.main) {
  process.exitCode = await main();
}
