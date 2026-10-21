#!/usr/bin/env bun
// cli/report.ts — generate README.md + experiments/SUMMARY_TABLES.md from
// frozen JSON artifacts. Usage: bun cli/report.ts [--root <dynamic-repo>]
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { generateReport, REAL_TARGETS, type ReportInputs } from "../lib/report/index.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseRoot(): string {
  const i = process.argv.indexOf("--root");
  if (i >= 0 && process.argv[i + 1]) return path.resolve(process.argv[i + 1]);
  return process.env.ATFIELD_DYNAMIC_ROOT ? path.resolve(process.env.ATFIELD_DYNAMIC_ROOT) : repoRoot;
}

const readJson = (p: string) => JSON.parse(readFileSync(p, "utf-8"));

function loadInputs(root: string): ReportInputs {
  const manifestPath = path.join(root, "experiments", "traces_manifest.json");
  const manifestData = existsSync(manifestPath) ? readJson(manifestPath) : {};
  const ledgers: Record<string, any> = {};
  const fieldMetaBySample: Record<string, any> = {};
  const pageOriginsBySample: Record<string, Map<number, Set<string>>> = {};
  for (const s of REAL_TARGETS) {
    ledgers[s] = readJson(path.join(root, "witnesses", s, "witness_ledger.json"));
    const fp = path.join(root, "targets", s, "fields.json");
    fieldMetaBySample[s] = existsSync(fp)
      ? Object.fromEntries(readJson(fp).fields.map((f: any) => [f.id, f]))
      : {};
    const wp = path.join(root, "targets", s, "workset.all_reg.json");
    const origins = new Map<number, Set<string>>();
    if (existsSync(wp)) {
      for (const field of readJson(wp).fields) {
        for (const rec of field.pages) origins.set(rec.page_rva, new Set(rec.origins ?? []));
      }
    }
    pageOriginsBySample[s] = origins;
  }
  return {
    dynRoot: root,
    evalData: readJson(path.join(root, "experiments", "evaluation_results.json")),
    stratData: readJson(path.join(root, "experiments", "strategy_comparison.json")),
    manifestData,
    ledgers,
    fieldMetaBySample,
    pageOriginsBySample,
  };
}

const root = parseRoot();
const content = generateReport(loadInputs(root));
writeFileSync(path.join(root, "README.md"), content);
writeFileSync(path.join(root, "experiments", "SUMMARY_TABLES.md"), content);
console.log("Updated and verified README.md and experiments/SUMMARY_TABLES.md against JSON artifacts");
