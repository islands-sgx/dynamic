#!/usr/bin/env bun

import { randomUUID } from "node:crypto";
import { mkdirSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { loadProfileBundle } from "../lib/bundle/profile-bundle.ts";
import { buildWorkset } from "../lib/workset/build.ts";
import { readFinalizableCorpus } from "../lib/explorer/corpus.ts";
import { readCanonicalTrace } from "../lib/workset/trace.ts";

function usage(): string {
  return "usage: bun cli/atfield-workset.ts --bundle MANIFEST [--corpus CORPUS_DIR] [--trace TRACE.jsonl ...] --out WORKSET.json";
}

function parseArgs(argv: string[]): { bundle: string; corpus?: string; traces: string[]; out: string } {
  let bundle: string | undefined;
  let corpus: string | undefined;
  let out: string | undefined;
  const traces: string[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    const equal = arg.indexOf("=");
    const key = equal < 0 ? arg : arg.slice(0, equal);
    const inlineValue = equal < 0 ? undefined : arg.slice(equal + 1);
    if (key !== "--bundle" && key !== "--corpus" && key !== "--trace" && key !== "--out") {
      throw new Error("unrecognized argument: " + key);
    }
    if (key !== "--trace" && seen.has(key)) throw new Error("argument " + key + " was repeated");
    seen.add(key);
    const value = inlineValue ?? argv[++index];
    if (!value || value.startsWith("--")) throw new Error("argument " + key + " requires one value");
    if (key === "--bundle") bundle = value;
    else if (key === "--corpus") corpus = value;
    else if (key === "--trace") traces.push(value);
    else out = value;
  }
  if (!bundle || !out || (!corpus && traces.length === 0)) {
    throw new Error("--bundle, at least one --trace or --corpus, and --out are required");
  }
  return { bundle, ...(corpus ? { corpus } : {}), traces, out };
}

export function makeWorksetFromFiles(bundlePath: string, tracePaths: string[], outputPath?: string,
  supplementalTracePaths: ReadonlySet<string> = new Set()) {
  const bundle = loadProfileBundle(bundlePath);
  if (outputPath !== undefined) {
    const output = path.resolve(outputPath);
    let outputReal = output;
    try {
      outputReal = realpathSync(output);
    } catch {
      try { outputReal = path.join(realpathSync(path.dirname(output)), path.basename(output)); } catch {}
    }
    const inputs = [bundle.manifestPath, ...bundle.artifactPaths.values(), ...tracePaths.map((item) => realpathSync(item))];
    if (inputs.some((input) => input === outputReal)) {
      throw new Error("--out must not replace the Profile bundle manifest, an artifact, or a source trace");
    }
  }
  const seenRunIds = new Set<string>();
  const traces = tracePaths.map((tracePath) => {
    const trace = readCanonicalTrace(tracePath, bundle, { allowBusinessRejectionExit: supplementalTracePaths.has(tracePath) });
    if (seenRunIds.has(trace.runId)) throw new Error("duplicate trace run_id " + trace.runId);
    seenRunIds.add(trace.runId);
    return trace;
  });
  return buildWorkset(bundle, traces);
}

export function main(argv: string[] = process.argv.slice(2)): number {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    return 0;
  }
  let temporary: string | undefined;
  try {
    const parsed = parseArgs(argv);
    const output = path.resolve(parsed.out);
    const corpusTraces = parsed.corpus
      ? readFinalizableCorpus(parsed.corpus, parsed.bundle)
      : [];
    const supplementalTracePaths = new Set(corpusTraces.filter((entry) => entry.role === "supplemental").map((entry) => entry.path));
    const result = makeWorksetFromFiles(parsed.bundle, [...corpusTraces.map((entry) => entry.path), ...parsed.traces], output, supplementalTracePaths);
    mkdirSync(path.dirname(output), { recursive: true });
    temporary = path.join(path.dirname(output), "." + path.basename(output) + "." + randomUUID() + ".tmp");
    writeFileSync(temporary, JSON.stringify(result, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
    renameSync(temporary, output);
    temporary = undefined;
    return 0;
  } catch (error) {
    if (temporary) {
      try { unlinkSync(temporary); } catch {}
    }
    console.error(usage());
    console.error("atfield-workset: error: " + (error instanceof Error ? error.message : String(error)));
    return 2;
  }
}

if (import.meta.main) process.exitCode = main();
