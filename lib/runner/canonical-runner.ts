import { randomUUID } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  isObject,
  loadProfileBundle,
  normalizeDigest,
  parseStrictJson,
  sha256,
  type JsonObject,
  type ProfileBundle,
} from "../bundle/profile-bundle.ts";
import { parseCanonicalTrace, type ParsedTrace } from "../workset/trace.ts";
import { loadFinalV2RunTarget, type FinalV2RunTarget } from "./final-v2-target.ts";

const TRACE_SCHEMA = "atfield-canonical-trace-v1";

interface HostCommand {
  seed_id: string;
  argv: string[];
}

export type GateMode = "c-flush" | "c-preserve-tlb";

export interface CpuTopologyInput {
  online: string | readonly number[];
  isolated?: string | readonly number[];
  processInitialAffinity?: string | readonly number[];
  effectiveCpuset?: string | readonly number[];
  allowed?: string | readonly number[];
}

export interface RunnerCpuConfig {
  enclCpu: number;
  watchCpu: number;
  enclCpuSource: "explicit" | "auto-isolated" | "auto-online";
  watchCpuSource: "explicit" | "auto-housekeeping" | "auto-online";
  enclCpuIsolated: boolean;
  onlineCpus: string;
  isolatedCpus: string;
  processInitialAffinityCpus: string;
  effectiveCpusetCpus: string;
  allowedCpus: string;
  finalAffinityVerified?: boolean;
}

export interface RunOptions {
  bundlePath: string;
  args: string[];
  seedId?: string;
  finalV2TargetPath?: string;
  collectorPath?: string;
  timeoutMs?: number;
  killGraceMs?: number;
  sample?: string;
  mode?: string;
  gateMode?: GateMode;
  enclCpu?: number;
  watchCpu?: number;
  cpuTopology?: CpuTopologyInput;
  tempRoot?: string;
  artifactDir?: string;
  env?: Record<string, string>;
}

export interface RunSeedCommandsOptions extends Omit<RunOptions, "args"> {
  commands: HostCommand[];
}

export interface CanonicalRun {
  runId: string;
  mode: string;
  gateMode: GateMode;
  targetKind: "profile" | "final-v2";
  selectedEnclaveSha256: string;
  finalV2Target?: { manifestSha256: string; worksetSha256: string; capacityQ: number; signedFinalElfSha256: string; readyTableSha256: string; signedMeasurementFinalElfSha256: string; manifestFieldCount: number; productionConfigSha256: string; measurementConfigSha256: string; productionAexNotify: true; measurementAexNotify: false };
  cpuConfig: RunnerCpuConfig;
  seedId: string;
  argv: string[];
  completion: "complete" | "incomplete";
  incompleteReasons: string[];
  timedOut: boolean;
  exitCode: number | null;
  termination: ProcessTermination;
  traceSha256: string | null;
  parsedTrace?: ParsedTrace;
  committedTrace?: ParsedTrace;
  traceText: string;
  stdout: string;
  stderr: string;
  artifactPaths?: { trace: string; meta?: string; partial?: string; stdout?: string; stderr?: string };
}

interface ArtifactEntry {
  name: string;
  relativePath: string;
  sourcePath: string;
  sha256: string;
}

interface BundleArtifacts {
  bundle: ProfileBundle;
  bundleSha256: string;
  artifacts: ArtifactEntry[];
  host: ArtifactEntry;
  enclave: ArtifactEntry;
  manifestRelativePath: string;
  manifestPath: string;
}

interface CollectorArtifact {
  path: string;
  sha256: string;
}

interface PrefixScan {
  records: JsonObject[];
  prefixText: string;
  reasons: string[];
}

interface StreamCapture {
  promise: Promise<void>;
  text(): string;
  cancel(): Promise<void>;
}

function stringField(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function resolveBundleArtifact(bundle: ProfileBundle, value: unknown, name: string): ArtifactEntry {
  if (!isObject(value) || !stringField(value.path)) {
    throw new Error("Profile bundle artifact " + name + " is malformed");
  }
  const relativePath = value.path;
  if (path.isAbsolute(relativePath) ||
      relativePath.split(/[\\/]/).some((part) => !part || part === "." || part === "..")) {
    throw new Error("Profile bundle artifact " + name + " path is not bundle-relative");
  }
  const sourcePath = realpathSync(path.resolve(bundle.root, relativePath));
  const relative = path.relative(bundle.root, sourcePath);
  if (relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative) ||
      !statSync(sourcePath).isFile()) {
    throw new Error("Profile bundle artifact " + name + " escapes its root or is not a file");
  }
  return {
    name,
    relativePath,
    sourcePath,
    sha256: normalizeDigest(value.sha256, "artifacts." + name + ".sha256"),
  };
}

function readBundleArtifacts(bundlePath: string): BundleArtifacts {
  const bundle = loadProfileBundle(bundlePath);
  const manifestBytes = readFileSync(bundle.manifestPath);
  const parsed = parseStrictJson(
    new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes),
    "Profile bundle manifest",
  );
  if (!isObject(parsed) || !isObject(parsed.artifacts)) {
    throw new Error("Profile bundle artifacts are missing");
  }
  const artifacts = Object.entries(parsed.artifacts).map(([name, value]) =>
    resolveBundleArtifact(bundle, value, name));
  const host = artifacts.find((artifact) => artifact.name === "host");
  const enclave = artifacts.find((artifact) => artifact.name === "signed_profile_elf");
  if (!host || !enclave) throw new Error("Profile bundle host or signed Profile artifact is missing");
  const manifestRelativePath = path.relative(bundle.root, bundle.manifestPath);
  if (!manifestRelativePath || manifestRelativePath.startsWith("..") || path.isAbsolute(manifestRelativePath)) {
    throw new Error("Profile bundle manifest must be inside its root");
  }
  return {
    bundle,
    bundleSha256: sha256(manifestBytes),
    artifacts,
    host,
    enclave,
    manifestRelativePath,
    manifestPath: bundle.manifestPath,
  };
}

function verifyArtifacts(artifacts: BundleArtifacts, collector?: CollectorArtifact): void {
  if (sha256(readFileSync(artifacts.manifestPath)) !== artifacts.bundleSha256) {
    throw new Error("bundle manifest digest changed after validation");
  }
  for (const artifact of artifacts.artifacts) {
    if (sha256(readFileSync(artifact.sourcePath)) !== artifact.sha256) {
      throw new Error("artifact digest mismatch for " + artifact.name);
    }
  }
  if (collector && sha256(readFileSync(collector.path)) !== collector.sha256) {
    throw new Error("collector digest changed after validation");
  }
}

function readCollector(filename: string | undefined): CollectorArtifact | undefined {
  if (filename === undefined) return undefined;
  const resolved = realpathSync(path.resolve(filename));
  if (!statSync(resolved).isFile()) throw new Error("collector must be a regular file");
  return { path: resolved, sha256: sha256(readFileSync(resolved)) };
}

function validateHostArgs(args: string[]): void {
  if (!Array.isArray(args) || !args.every((arg) =>
    typeof arg === "string" && !arg.includes(String.fromCharCode(0)))) {
    throw new Error("host args must be NUL-free strings");
  }
}

function scanCollectorPrefix(text: string): PrefixScan {
  const records: JsonObject[] = [];
  const reasons: string[] = [];
  let lines = text.split(/\r?\n/);
  if (lines.at(-1) === "") lines = lines.slice(0, -1);
  if (lines.length === 0) reasons.push("collector trace has no records");
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    if (!line.length) {
      reasons.push("collector trace contains a blank line at " + (index + 1));
      break;
    }
    let value: unknown;
    try {
      value = parseStrictJson(line, "collector trace line " + (index + 1));
    } catch (error) {
      reasons.push(error instanceof Error ? error.message : String(error));
      break;
    }
    if (!isObject(value)) {
      reasons.push("collector trace record " + (index + 1) + " is not an object");
      break;
    }
    if (value.record_type === "run_end") {
      reasons.push("collector must not emit run_end");
      break;
    }
    if (records.length === 0 && value.record_type !== "run_start") {
      reasons.push("collector trace must start with run_start");
      break;
    }
    if (records.length > 0 && value.record_type !== "ecall") {
      reasons.push("collector trace has an unexpected record type at " + (index + 1));
      break;
    }
    records.push(value);
  }
  if (!records.length && reasons.length === 0) reasons.push("collector trace has no run_start");
  const prefixText = records.map((record) => JSON.stringify(record)).join("\n") +
    (records.length ? "\n" : "");
  return { records, prefixText, reasons };
}

function runnerEnd(
  records: JsonObject[],
  runId: string,
  bundle: ProfileBundle,
  exitCode: number | null,
  termination: ProcessTermination,
  timedOut: boolean,
  completion: "complete" | "incomplete",
  reasons: string[],
): JsonObject {
  const finalEcall = [...records].reverse().find((record) => record.record_type === "ecall");
  const generation = finalEcall && Number.isSafeInteger(finalEcall.instance_generation)
    ? finalEcall.instance_generation
    : null;
  return {
    schema: TRACE_SCHEMA,
    record_type: "run_end",
    run_id: runId,
    layout_epoch: bundle.layoutEpoch,
    bundle_manifest_sha256: bundle.manifestSha256,
    instance_generation: generation,
    process_return_code: exitCode ?? -1,
    termination,
    timeout: timedOut,
    record_count: records.filter((record) => record.record_type === "ecall").length,
    completion,
    incomplete_reasons: reasons,
  };
}

export type ProcessTermination = "exited" | "signaled" | "timeout" | "unknown";

function appendRunEnd(filename: string, rawText: string, end: JsonObject): void {
  const descriptor = openSync(filename, "a");
  try {
    if (rawText && !rawText.endsWith("\n")) writeSync(descriptor, "\n");
    writeSync(descriptor, JSON.stringify(end) + "\n");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function captureStream(stream: ReadableStream<Uint8Array>): StreamCapture {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const promise = (async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      chunks.push(value);
      total += value.length;
    }
  })();
  return {
    promise,
    text(): string {
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      return new TextDecoder().decode(bytes);
    },
    cancel: () => reader.cancel().then(() => undefined).catch(() => undefined),
  };
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

function killGroup(pid: number, signal: "SIGTERM" | "SIGKILL", fallback: () => void): void {
  try {
    process.kill(-pid, signal);
  } catch {
    fallback();
  }
}

async function stopGroup(
  pid: number,
  graceMs: number,
  completed: Promise<number>,
  fallback: (signal: "SIGTERM" | "SIGKILL") => void,
): Promise<number> {
  killGroup(pid, "SIGTERM", () => fallback("SIGTERM"));
  const outcome = await Promise.race([
    completed.then((code) => ({ code })),
    delay(graceMs).then(() => null),
  ]);
  if (outcome) return outcome.code;
  killGroup(pid, "SIGKILL", () => fallback("SIGKILL"));
  return await completed;
}

function makeBundleSnapshot(artifacts: BundleArtifacts, root: string): BundleArtifacts & {
  bundleRoot: string;
  hostPath: string;
  enclavePath: string;
} {
  const bundleRoot = path.join(root, "bundle");
  mkdirSync(bundleRoot, { recursive: true, mode: 0o700 });
  const snapshotEntries = artifacts.artifacts.map((artifact) => {
    const target = path.join(bundleRoot, artifact.relativePath);
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    copyFileSync(artifact.sourcePath, target);
    return { ...artifact, sourcePath: target };
  });
  const manifestPath = path.join(bundleRoot, artifacts.manifestRelativePath);
  mkdirSync(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  copyFileSync(artifacts.manifestPath, manifestPath);
  const host = snapshotEntries.find((artifact) => artifact.name === "host");
  const enclave = snapshotEntries.find((artifact) => artifact.name === "signed_profile_elf");
  if (!host || !enclave) throw new Error("bundle snapshot is missing its host or signed Profile ELF");
  return {
    ...artifacts,
    artifacts: snapshotEntries,
    host,
    enclave,
    manifestPath,
    bundleRoot,
    hostPath: host.sourcePath,
    enclavePath: enclave.sourcePath,
  };
}
function safeFileToken(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "seed";
}

export function parseCpuList(raw: string): number[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  const result = new Set<number>();
  for (const part of trimmed.split(",")) {
    const token = part.trim();
    if (!token) continue;
    const rangeMatch = /^([0-9]+)-([0-9]+)$/.exec(token);
    if (rangeMatch) {
      const start = Number(rangeMatch[1]);
      const end = Number(rangeMatch[2]);
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end < start) {
        throw new Error("invalid CPU range token: " + token);
      }
      for (let cpu = start; cpu <= end; cpu++) result.add(cpu);
      continue;
    }
    if (!/^[0-9]+$/.test(token)) {
      throw new Error("invalid CPU list token: " + token);
    }
    const cpu = Number(token);
    if (!Number.isSafeInteger(cpu) || cpu < 0) throw new Error("invalid CPU id: " + token);
    result.add(cpu);
  }
  return [...result].sort((a, b) => a - b);
}

export function formatCpuList(cpus: Iterable<number>): string {
  const sorted = [...new Set(cpus)].sort((a, b) => a - b);
  if (sorted.length === 0) return "";
  const ranges: string[] = [];
  let start = sorted[0]!;
  let prev = start;
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i]!;
    if (cur === prev + 1) {
      prev = cur;
    } else {
      ranges.push(start === prev ? String(start) : `${start}-${prev}`);
      start = prev = cur;
    }
  }
  ranges.push(start === prev ? String(start) : `${start}-${prev}`);
  return ranges.join(",");
}

function readOptionalFile(filePath: string): string {
  try {
    return readFileSync(filePath, "utf8").trim();
  } catch {
    return "";
  }
}

function toCpuSet(input: string | readonly number[] | undefined): Set<number> {
  if (input === undefined) return new Set<number>();
  if (typeof input === "string") return new Set(parseCpuList(input));
  const out = new Set<number>();
  for (const cpu of input) {
    if (!Number.isSafeInteger(cpu) || cpu < 0) throw new Error("invalid CPU id in topology: " + String(cpu));
    out.add(cpu);
  }
  return out;
}

export function resolveRunnerCpuConfig(options: Pick<RunOptions, "enclCpu" | "watchCpu" | "cpuTopology">): RunnerCpuConfig {
  let online: Set<number>;
  let isolated: Set<number>;
  let procInitial: Set<number>;
  let effectiveCpuset: Set<number>;
  let allowed: Set<number>;
  if (options.cpuTopology) {
    online = toCpuSet(options.cpuTopology.online);
    isolated = toCpuSet(options.cpuTopology.isolated);
    procInitial = options.cpuTopology.processInitialAffinity !== undefined
      ? toCpuSet(options.cpuTopology.processInitialAffinity)
      : new Set([...online].filter((cpu) => !isolated.has(cpu)));
    effectiveCpuset = options.cpuTopology.effectiveCpuset !== undefined
      ? toCpuSet(options.cpuTopology.effectiveCpuset)
      : (options.cpuTopology.allowed !== undefined ? toCpuSet(options.cpuTopology.allowed) : new Set([...online]));
    allowed = options.cpuTopology.allowed !== undefined
      ? toCpuSet(options.cpuTopology.allowed)
      : new Set([...online].filter((cpu) => effectiveCpuset.has(cpu)));
  } else {
    const onlineRaw = readOptionalFile("/sys/devices/system/cpu/online");
    online = onlineRaw ? new Set(parseCpuList(onlineRaw)) : new Set([0, 1]);
    const isolatedRaw = readOptionalFile("/sys/devices/system/cpu/isolated");
    isolated = isolatedRaw ? new Set(parseCpuList(isolatedRaw)) : new Set<number>();
    const statusRaw = readOptionalFile("/proc/self/status");
    const allowedLine = statusRaw
      .split(/\r?\n/)
      .find((line) => line.startsWith("Cpus_allowed_list:"));
    procInitial = allowedLine
      ? new Set(parseCpuList(allowedLine.slice("Cpus_allowed_list:".length)))
      : new Set([...online]);
    const cpusetRaw = readOptionalFile("/sys/fs/cgroup/cpuset.cpus.effective");
    effectiveCpuset = cpusetRaw
      ? new Set(parseCpuList(cpusetRaw))
      : new Set([...procInitial, ...isolated]);
    allowed = new Set<number>();
    for (const cpu of online) {
      if (effectiveCpuset.has(cpu) && (procInitial.has(cpu) || isolated.has(cpu) || cpusetRaw.length > 0)) {
        allowed.add(cpu);
      }
    }
  }

  const available = [...online].filter((cpu) => allowed.has(cpu)).sort((a, b) => a - b);
  if (options.enclCpu !== undefined && (!Number.isSafeInteger(options.enclCpu) || options.enclCpu < 0)) {
    throw new Error("configured enclave CPU (" + String(options.enclCpu) + ") must be a non-negative integer");
  }
  if (options.watchCpu !== undefined && (!Number.isSafeInteger(options.watchCpu) || options.watchCpu < 0)) {
    throw new Error("configured watcher CPU (" + String(options.watchCpu) + ") must be a non-negative integer");
  }

  if (options.enclCpu !== undefined) {
    if (!online.has(options.enclCpu)) {
      throw new Error(
        "configured enclave CPU " + options.enclCpu + " is not online (online CPUs: " +
        (formatCpuList(online) || "none") + "); pass an online CPU via --encl-cpu",
      );
    }
    if (!allowed.has(options.enclCpu)) {
      throw new Error(
        "configured enclave CPU " + options.enclCpu + " is outside allowed CPU affinity (" +
        (formatCpuList(allowed) || "none") + "); adjust taskset/cpuset or pass an allowed --encl-cpu",
      );
    }
  }
  if (options.watchCpu !== undefined) {
    if (!online.has(options.watchCpu)) {
      throw new Error(
        "configured watcher CPU " + options.watchCpu + " is not online (online CPUs: " +
        (formatCpuList(online) || "none") + "); pass an online CPU via --watch-cpu",
      );
    }
    if (!allowed.has(options.watchCpu)) {
      throw new Error(
        "configured watcher CPU " + options.watchCpu + " is outside allowed CPU affinity (" +
        (formatCpuList(allowed) || "none") + "); adjust taskset/cpuset or pass an allowed --watch-cpu",
      );
    }
  }
  if (options.enclCpu !== undefined && options.watchCpu !== undefined && options.enclCpu === options.watchCpu) {
    throw new Error(
      "enclave CPU (" + options.enclCpu + ") and watcher CPU (" + options.watchCpu +
      ") must not conflict; pass distinct --encl-cpu and --watch-cpu",
    );
  }
  if (available.length < 2) {
    throw new Error(
      "at least 2 distinct online allowed CPUs are required for enclave and watcher threads (available: " +
      (formatCpuList(available) || "none") + "); adjust CPU affinity/cpuset or bring another CPU online",
    );
  }

  let enclCpu: number;
  let enclCpuSource: RunnerCpuConfig["enclCpuSource"];
  if (options.enclCpu !== undefined) {
    enclCpu = options.enclCpu;
    enclCpuSource = "explicit";
  } else {
    const isolatedCandidate = available.find((cpu) => isolated.has(cpu) && cpu !== options.watchCpu);
    if (isolatedCandidate !== undefined) {
      enclCpu = isolatedCandidate;
      enclCpuSource = "auto-isolated";
    } else {
      const fallback = [...available].reverse().find((cpu) => cpu !== options.watchCpu);
      if (fallback === undefined) {
        throw new Error("unable to select an online allowed enclave CPU distinct from watcher CPU");
      }
      enclCpu = fallback;
      enclCpuSource = "auto-online";
    }
  }

  let watchCpu: number;
  let watchCpuSource: RunnerCpuConfig["watchCpuSource"];
  if (options.watchCpu !== undefined) {
    watchCpu = options.watchCpu;
    watchCpuSource = "explicit";
  } else {
    const housekeeping = available.filter((cpu) => !isolated.has(cpu) && cpu !== enclCpu);
    if (housekeeping.length > 0) {
      watchCpu = housekeeping.find((cpu) => cpu > 0) ?? housekeeping[0]!;
      watchCpuSource = "auto-housekeeping";
    } else {
      const fallback = available.find((cpu) => cpu !== enclCpu);
      if (fallback === undefined) {
        throw new Error("unable to select an online allowed watcher CPU distinct from enclave CPU " + enclCpu);
      }
      watchCpu = fallback;
      watchCpuSource = "auto-online";
    }
  }

  if (enclCpu === watchCpu) {
    throw new Error(
      "enclave CPU (" + enclCpu + ") and watcher CPU (" + watchCpu +
      ") must not conflict; pass distinct --encl-cpu and --watch-cpu",
    );
  }

  return {
    enclCpu,
    watchCpu,
    enclCpuSource,
    watchCpuSource,
    enclCpuIsolated: isolated.has(enclCpu),
    onlineCpus: formatCpuList(online),
    isolatedCpus: formatCpuList(isolated),
    processInitialAffinityCpus: formatCpuList(procInitial),
    effectiveCpusetCpus: formatCpuList(effectiveCpuset),
    allowedCpus: formatCpuList(allowed),
  };
}

async function runOne(
  artifacts: BundleArtifacts,
  collector: CollectorArtifact | undefined,
  command: HostCommand,
  options: Required<Pick<RunOptions, "timeoutMs" | "killGraceMs">> & RunOptions,
  finalTarget?: FinalV2RunTarget,
): Promise<CanonicalRun> {
  const runId = randomUUID();
  const root = mkdtempSync(path.join(options.tempRoot ?? tmpdir(), "atfield-run-"));
  try {
    const homeDir = path.join(root, "home");
    const stateDir = path.join(root, "state");
    const dataDir = path.join(root, "data");
    const cacheDir = path.join(root, "cache");
    const tempDir = path.join(root, "tmp");
    for (const directory of [homeDir, stateDir, dataDir, cacheDir, tempDir]) {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
    }
    const snapshot = makeBundleSnapshot(artifacts, root);
    let selectedImagePath = snapshot.enclavePath;
    let selectedReadyTablePath: string | undefined;
    if (finalTarget) {
      selectedImagePath = path.join(snapshot.bundleRoot, "final-v2-measurement.signed.so");
      selectedReadyTablePath = path.join(snapshot.bundleRoot, "final-v2-ready-table.bin");
      copyFileSync(finalTarget.selectedImagePath, selectedImagePath);
      copyFileSync(finalTarget.readyTablePath, selectedReadyTablePath);
    }
    const rawTracePath = path.join(root, "collector.trace.jsonl");
    const partialPath = path.join(root, "collector.trace.jsonl.partial");
    const collectorLink = collector ? path.join(root, "collector.so") : undefined;
    if (collector && collectorLink) copyFileSync(collector.path, collectorLink);
    const argv = command.argv.map((arg) =>
      arg.replaceAll("{state_dir}", stateDir).replaceAll("{bundle_root}", snapshot.bundleRoot));
    const inheritedPreload = options.env?.LD_PRELOAD;
    const preload = collector
      ? [collectorLink!, inheritedPreload].filter(Boolean).join(":")
      : inheritedPreload;
    if (finalTarget && options.mode !== undefined && options.mode !== "verify-pretouch") {
      throw new Error("a Final v2 target requires mode verify-pretouch");
    }
    let resolvedMode = finalTarget ? "verify-pretouch" : options.mode;
    let resolvedGateMode: GateMode;
    if (options.gateMode === "c-preserve-tlb" || resolvedMode === "verify-pretouch") {
      if (resolvedMode !== undefined && resolvedMode !== "verify-pretouch") {
        throw new Error("gateMode c-preserve-tlb requires mode verify-pretouch");
      }
      if (options.gateMode !== undefined && options.gateMode !== "c-preserve-tlb") {
        throw new Error("mode verify-pretouch requires gateMode c-preserve-tlb");
      }
      resolvedMode = "verify-pretouch";
      resolvedGateMode = "c-preserve-tlb";
    } else {
      resolvedMode = resolvedMode ?? "profile";
      if (resolvedMode !== "profile" && resolvedMode !== "explore") {
        throw new Error("unsupported runner mode " + resolvedMode + "; expected profile, explore, or verify-pretouch");
      }
      resolvedGateMode = "c-flush";
    }
    const ipiMask = resolvedGateMode === "c-preserve-tlb" ? "3" : "7";
    const cpuConfig = resolveRunnerCpuConfig(options);
    const inheritedEnv = Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] =>
          typeof entry[1] === "string" && !entry[0].startsWith("ATFIELD_"),
      ),
    );
    const env: Record<string, string> = {
      ...inheritedEnv,
      ...options.env,
      HOME: homeDir,
      XDG_STATE_HOME: stateDir,
      XDG_DATA_HOME: dataDir,
      XDG_CACHE_HOME: cacheDir,
      TMPDIR: tempDir,
      TMP: tempDir,
      TEMP: tempDir,
      ATFIELD_RUN_ID: runId,
      ATFIELD_SEED_ID: command.seed_id,
      ATFIELD_SEED_ARGV_JSON: JSON.stringify(argv),
      ATFIELD_BUNDLE_MANIFEST_SHA256: artifacts.bundleSha256,
      ATFIELD_LAYOUT_EPOCH: artifacts.bundle.layoutEpoch,
      ATFIELD_ENCLAVE_SHA256: finalTarget?.identity.signed_measurement_final_elf_sha256 ?? artifacts.bundle.identity.signedProfileElfSha256,
      ATFIELD_ENCLAVE_PATH: selectedImagePath,
      ATFIELD_BUNDLE_ROOT: snapshot.bundleRoot,
      ATFIELD_SAMPLE: options.sample ?? path.basename(artifacts.bundle.root),
      ATFIELD_MODE: resolvedMode,
      ATFIELD_GATE_MODE: resolvedGateMode,
      ATFIELD_USE_4GATE: "1",
      ATFIELD_IPI_MASK: ipiMask,
      ATFIELD_ENCL_CPU: String(cpuConfig.enclCpu),
      ATFIELD_WATCH_CPU: String(cpuConfig.watchCpu),
      ATFIELD_LAYOUT_SPEC: artifacts.bundle.collectorLayoutSpec,
      ATFIELD_TRACE_PATH: rawTracePath,
      ATFIELD_STATE_DIR: stateDir,
      ATFIELD_TARGET_KIND: finalTarget ? "final-v2" : "profile",
      ...(finalTarget && selectedReadyTablePath ? {
        ATFIELD_FINAL_V2_TARGET_SHA256: finalTarget.manifestSha256,
        ATFIELD_READY_TABLE: selectedReadyTablePath,
        ATFIELD_READY_TABLE_SHA256: finalTarget.identity.ready_table_sha256,
        ATFIELD_REQUIRE_READINESS: "1",
      } : {}),
    };
    if (collector && collectorLink) {
      env.LD_PRELOAD = preload!;
      env.ATFIELD_COLLECTOR_SHA256 = collector.sha256;
    }

    let timedOut = false;
    let outputTimedOut = false;
    let exitCode: number | null = null;
    let signalCode: string | null = null;
    let stdout = "";
    let stderr = "";
    let childProcess: Bun.Subprocess | undefined;
    let stdoutCapture: StreamCapture | undefined;
    let stderrCapture: StreamCapture | undefined;
    let completed: Promise<number> | undefined;
    let appendedRunEnd = false;
    let scan: PrefixScan = { records: [], prefixText: "", reasons: [] };
    try {
      verifyArtifacts(snapshot, collector && collectorLink ? { path: collectorLink, sha256: collector.sha256 } : undefined);
      if (finalTarget) {
        if (sha256(readFileSync(finalTarget.manifestPath)) !== finalTarget.manifestSha256) {
          throw new Error("Final v2 target manifest digest changed after validation");
        }
        for (const artifact of Object.values(finalTarget.artifacts)) {
          if (sha256(readFileSync(artifact.path)) !== artifact.sha256) {
            throw new Error("Final v2 target artifact digest changed after validation: " + artifact.path);
          }
        }
        if (sha256(readFileSync(selectedImagePath)) !== finalTarget.identity.signed_measurement_final_elf_sha256 ||
            !selectedReadyTablePath || sha256(readFileSync(selectedReadyTablePath)) !== finalTarget.identity.ready_table_sha256) {
          throw new Error("Final v2 snapshot image or ReadyTable differs from the frozen target");
        }
      }
      const spawned = Bun.spawn([snapshot.hostPath, ...argv], {
        cwd: stateDir,
        env,
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        detached: true,
      });
      childProcess = spawned;
      completed = childProcess.exited;
      stdoutCapture = captureStream(spawned.stdout);
      stderrCapture = captureStream(spawned.stderr);
      const outcome = await Promise.race([
        completed.then((code) => ({ code })),
        delay(options.timeoutMs).then(() => null),
      ]);
      if (outcome === null) {
        timedOut = true;
        exitCode = await stopGroup(
          childProcess.pid,
          options.killGraceMs,
          completed,
          (signal) => { try { childProcess!.kill(signal); } catch {} },
        );
      } else {
        exitCode = outcome.code;
      }
      const streams = await Promise.race([
        Promise.all([stdoutCapture.promise, stderrCapture.promise]).then(() => "done" as const),
        delay(1_000).then(() => "timeout" as const),
      ]);
      if (streams === "timeout") {
        outputTimedOut = true;
        await stopGroup(
          childProcess.pid,
          options.killGraceMs,
          completed,
          (signal) => { try { childProcess!.kill(signal); } catch {} },
        );
        await Promise.race([
          Promise.all([stdoutCapture.promise, stderrCapture.promise]).catch(() => undefined),
          delay(options.killGraceMs),
        ]);
        await Promise.all([stdoutCapture.cancel(), stderrCapture.cancel()]);
      }
      stdout = stdoutCapture.text();
      stderr = stderrCapture.text();
      signalCode = childProcess.signalCode == null ? null : String(childProcess.signalCode);
    } catch (error) {
      if (childProcess && completed) {
        try {
          await stopGroup(childProcess.pid, options.killGraceMs, completed,
            (signal) => { try { childProcess!.kill(signal); } catch {} });
        } catch {}
      }
      stderr = (stderr ? stderr + "\n" : "") + String(error);
    }

    let rawBytes = new Uint8Array();
    let rawText = "";
    let decodingError = "";
    try {
      rawBytes = readFileSync(rawTracePath);
      rawText = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
    } catch (error) {
      if (rawBytes.length) decodingError = "collector trace is not valid UTF-8";
    }
    scan = scanCollectorPrefix(rawText);
    if (decodingError) scan.reasons.push(decodingError);
    const traceError = stderr.split(/\r?\n/).some((line) => line.startsWith("ATFIELD_TRACE_ERROR:"));
    const termination: ProcessTermination =
      timedOut || outputTimedOut ? "timeout"
      : signalCode !== null ? "signaled"
      : exitCode !== null ? "exited"
      : "unknown";
    const runReasons = [...scan.reasons];
    if (timedOut) runReasons.push("host process timed out");
    if (outputTimedOut) runReasons.push("host output pipes did not close before the final deadline");
    if (termination === "signaled") {
      runReasons.push("host process terminated by signal " + String(signalCode));
    } else if (exitCode !== 0) {
      runReasons.push("host process exit code was " + String(exitCode));
    }
    if (traceError) runReasons.push("collector reported ATFIELD_TRACE_ERROR");

    let finalText = "";
    let parsedTrace: ParsedTrace | undefined;
    let committedTrace: ParsedTrace | undefined;
    let completion: "complete" | "incomplete" = "incomplete";
    let incompleteReasons = [...new Set(runReasons)];
    const canComplete = incompleteReasons.length === 0 && scan.records.length > 0;
    if (canComplete) {
      const candidateEnd = runnerEnd(scan.records, runId, artifacts.bundle, exitCode, termination, false, "complete", []);
      try {
        if (rawBytes.length) {
          appendRunEnd(rawTracePath, rawText, candidateEnd);
          appendedRunEnd = true;
          finalText = readFileSync(rawTracePath, "utf8");
        } else {
          finalText = scan.prefixText + JSON.stringify(candidateEnd) + "\n";
        }
      } catch (error) {
        incompleteReasons.push("runner could not append run_end: " + String(error));
      }
      if (incompleteReasons.length === 0) {
        try {
          parsedTrace = parseCanonicalTrace(finalText, "runner final trace", artifacts.bundle,
            finalTarget ? { expectedSelectedEnclaveSha256: finalTarget.identity.signed_measurement_final_elf_sha256, requireReadinessInstalled: true } : undefined);
          if (parsedTrace.runId !== runId) throw new Error("trace run_id differs from runner run_id");
          completion = "complete";
          incompleteReasons = [];
        } catch (error) {
          incompleteReasons.push(error instanceof Error ? error.message : String(error));
        }
      }
    }

    if (completion === "incomplete") {
      if (rawBytes.length) writeFileSync(partialPath, rawBytes, { mode: 0o600 });
      const end = runnerEnd(
        scan.records,
        runId,
        artifacts.bundle,
        exitCode,
        termination,
        timedOut || outputTimedOut,
        "incomplete",
        incompleteReasons.length ? incompleteReasons : ["collector trace was incomplete"],
      );
      if (rawBytes.length && scan.reasons.length === 0 && scan.records.length > 0 && !appendedRunEnd) {
        try {
          appendRunEnd(rawTracePath, rawText, end);
          finalText = readFileSync(rawTracePath, "utf8");
        } catch (error) {
          incompleteReasons.push("runner could not append run_end: " + String(error));
          finalText = scan.prefixText + JSON.stringify(runnerEnd(
            scan.records, runId, artifacts.bundle, exitCode, termination, timedOut || outputTimedOut,
            "incomplete", incompleteReasons,
          )) + "\n";
        }
      } else {
        finalText = scan.prefixText + JSON.stringify(end) + "\n";
      }
      if (
        !timedOut &&
        !outputTimedOut &&
        !traceError &&
        scan.reasons.length === 0 &&
        scan.records.length > 0 &&
        exitCode !== null &&
        exitCode !== 0
      ) {
        try {
          const candidateCommitted = parseCanonicalTrace(
            finalText,
            "runner committed trace",
            artifacts.bundle,
            {
              allowBusinessRejectionExit: true,
              ...(finalTarget ? { expectedSelectedEnclaveSha256: finalTarget.identity.signed_measurement_final_elf_sha256, requireReadinessInstalled: true } : {}),
            },
          );
          if (candidateCommitted.runId === runId && candidateCommitted.ecallCount > 0) {
            committedTrace = candidateCommitted;
          }
        } catch {
          committedTrace = undefined;
        }
      }
    }

    const finalAffinityVerified =
      !stderr.includes("encl_setaffinity_failed") &&
      !stderr.includes("watcher_init_or_setaffinity_failed") &&
      !stderr.includes("invalid_or_missing_cpu_configuration") &&
      (scan.records.some((r) => r.record_type === "ecall") || completion === "complete");
    const finalCpuConfig: RunnerCpuConfig = {
      ...cpuConfig,
      finalAffinityVerified,
    };
    const result: CanonicalRun = {
      runId,
      mode: resolvedMode,
      gateMode: resolvedGateMode,
      targetKind: finalTarget ? "final-v2" : "profile",
      selectedEnclaveSha256: finalTarget?.identity.signed_measurement_final_elf_sha256 ?? artifacts.bundle.identity.signedProfileElfSha256,
      ...(finalTarget ? { finalV2Target: {
        manifestSha256: finalTarget.manifestSha256,
        worksetSha256: finalTarget.identity.workset_sha256,
        capacityQ: finalTarget.identity.capacity_q,
        signedFinalElfSha256: finalTarget.identity.signed_final_elf_sha256,
        readyTableSha256: finalTarget.identity.ready_table_sha256,
        signedMeasurementFinalElfSha256: finalTarget.identity.signed_measurement_final_elf_sha256,
        manifestFieldCount: finalTarget.manifestFieldCount,
        productionConfigSha256: finalTarget.identity.production_config_sha256,
        measurementConfigSha256: finalTarget.identity.measurement_config_sha256,
        productionAexNotify: finalTarget.identity.production_aex_notify,
        measurementAexNotify: finalTarget.identity.measurement_aex_notify,
      } } : {}),
      cpuConfig: finalCpuConfig,
      seedId: command.seed_id,
      argv,
      completion,
      incompleteReasons,
      timedOut: timedOut || outputTimedOut,
      exitCode,
      termination,
      traceSha256: parsedTrace?.traceSha256 ?? (finalText ? sha256(new TextEncoder().encode(finalText)) : null),
      parsedTrace,
      ...(committedTrace ? { committedTrace } : {}),
      traceText: finalText,
      stdout,
      stderr,
    };

    if (options.artifactDir) {
      mkdirSync(options.artifactDir, { recursive: true });
      const token = safeFileToken(command.seed_id) + "-" + runId;
      const traceOut = path.join(options.artifactDir, token + ".trace.jsonl");
      const metaOut = path.join(options.artifactDir, token + ".meta.json");
      const stdoutOut = path.join(options.artifactDir, token + ".stdout.log");
      const stderrOut = path.join(options.artifactDir, token + ".stderr.log");
      writeFileSync(stdoutOut, stdout, { mode: 0o600 });
      writeFileSync(stderrOut, stderr, { mode: 0o600 });
      writeFileSync(traceOut, finalText, { mode: 0o600 });
      const meta = {
        schema: "atfield-canonical-run-meta-v1",
        run_id: runId,
        mode: resolvedMode,
        gate_mode: resolvedGateMode,
        target_kind: finalTarget ? "final-v2" : "profile",
        selected_enclave_sha256: finalTarget?.identity.signed_measurement_final_elf_sha256 ?? artifacts.bundle.identity.signedProfileElfSha256,
        final_v2_target: finalTarget ? {
          manifest_sha256: finalTarget.manifestSha256,
          workset_sha256: finalTarget.identity.workset_sha256,
          capacity_q: finalTarget.identity.capacity_q,
          production_signed_final_sha256: finalTarget.identity.signed_final_elf_sha256,
          ready_table_sha256: finalTarget.identity.ready_table_sha256,
          signed_measurement_final_sha256: finalTarget.identity.signed_measurement_final_elf_sha256,
          production_config_sha256: finalTarget.identity.production_config_sha256,
          measurement_config_sha256: finalTarget.identity.measurement_config_sha256,
          production_aex_notify: finalTarget.identity.production_aex_notify,
          measurement_aex_notify: finalTarget.identity.measurement_aex_notify,
          measurement_signing_metadata_delta: finalTarget.identity.measurement_signing_metadata_delta,
        } : null,
        use_4gate: true,
        ipi_mask: Number(ipiMask),
        cpu_config: {
          encl_cpu: finalCpuConfig.enclCpu,
          watch_cpu: finalCpuConfig.watchCpu,
          encl_cpu_source: finalCpuConfig.enclCpuSource,
          watch_cpu_source: finalCpuConfig.watchCpuSource,
          encl_cpu_isolated: finalCpuConfig.enclCpuIsolated,
          online_cpus: finalCpuConfig.onlineCpus,
          isolated_cpus: finalCpuConfig.isolatedCpus,
          process_initial_affinity_cpus: finalCpuConfig.processInitialAffinityCpus,
          effective_cpuset_cpus: finalCpuConfig.effectiveCpusetCpus,
          allowed_cpus: finalCpuConfig.allowedCpus,
          final_affinity_verified: finalCpuConfig.finalAffinityVerified,
        },
        bundle_manifest_sha256: artifacts.bundleSha256,
        layout_epoch: artifacts.bundle.layoutEpoch,
        seed_id: command.seed_id,
        argv,
        trace_path: traceOut,
        stdout_path: stdoutOut,
        stdout_bytes: new TextEncoder().encode(stdout).length,
        stdout_sha256: sha256(new TextEncoder().encode(stdout)),
        stderr_path: stderrOut,
        stderr_bytes: new TextEncoder().encode(stderr).length,
        stderr_sha256: sha256(new TextEncoder().encode(stderr)),
        trace_sha256: result.traceSha256,
        exit_code: exitCode,
        termination,
        timed_out: timedOut || outputTimedOut,
        completion,
        incomplete_reasons: incompleteReasons,
      };
      writeFileSync(metaOut, JSON.stringify(meta, null, 2) + "\n", { mode: 0o600 });
      result.artifactPaths = { trace: traceOut, meta: metaOut, stdout: stdoutOut, stderr: stderrOut };
      if (rawBytes.length && completion === "incomplete") {
        const partialOut = traceOut + ".partial";
        writeFileSync(partialOut, rawBytes, { mode: 0o600 });
        result.artifactPaths.partial = partialOut;
      }
    }
    return result;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export async function runCanonicalHost(options: RunOptions): Promise<CanonicalRun> {
  validateHostArgs(options.args);
  const seedId = options.seedId ?? "canonical-host";
  if (seedId.trim() === "" || seedId.includes("\0")) {
    throw new Error("seedId must be a nonempty NUL-free string");
  }
  const timeoutMs = options.timeoutMs ?? 30_000;
  const killGraceMs = options.killGraceMs ?? 500;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("timeoutMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(killGraceMs) || killGraceMs < 0) {
    throw new Error("killGraceMs must be a nonnegative safe integer");
  }
  const artifacts = readBundleArtifacts(options.bundlePath);
  const finalTarget = options.finalV2TargetPath ? loadFinalV2RunTarget(options.finalV2TargetPath, artifacts.bundle) : undefined;
  const collector = readCollector(options.collectorPath);
  const normalizedOptions = { ...options, timeoutMs, killGraceMs };
  return await runOne(artifacts, collector, { seed_id: seedId, argv: options.args }, normalizedOptions, finalTarget);
}

export async function runSeedCommands(options: RunSeedCommandsOptions): Promise<CanonicalRun[]> {
  if (!Array.isArray(options.commands) || options.commands.length === 0) {
    throw new Error("commands must be a nonempty array");
  }
  const seenIds = new Set<string>();
  for (const [index, cmd] of options.commands.entries()) {
    if (!cmd || typeof cmd.seed_id !== "string" || cmd.seed_id.trim() === "" || cmd.seed_id.includes("\0")) {
      throw new Error("commands[" + index + "].seed_id must be a nonempty NUL-free string");
    }
    if (seenIds.has(cmd.seed_id)) {
      throw new Error("duplicate seed_id " + cmd.seed_id);
    }
    seenIds.add(cmd.seed_id);
    validateHostArgs(cmd.argv);
  }
  const timeoutMs = options.timeoutMs ?? 30_000;
  const killGraceMs = options.killGraceMs ?? 500;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("timeoutMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(killGraceMs) || killGraceMs < 0) {
    throw new Error("killGraceMs must be a nonnegative safe integer");
  }
  const artifacts = readBundleArtifacts(options.bundlePath);
  const finalTarget = options.finalV2TargetPath ? loadFinalV2RunTarget(options.finalV2TargetPath, artifacts.bundle) : undefined;
  const collector = readCollector(options.collectorPath);
  const results: CanonicalRun[] = [];
  for (const cmd of options.commands) {
    const normalizedOptions: Required<Pick<RunOptions, "timeoutMs" | "killGraceMs">> & RunOptions = {
      ...options,
      args: cmd.argv,
      timeoutMs,
      killGraceMs,
    };
    results.push(await runOne(artifacts, collector, cmd, normalizedOptions, finalTarget));
  }
  return results;
}
