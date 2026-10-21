// tests/bun/report.test.ts — golden-output regression for the TS report port.
// The generator must reproduce the committed experiments/SUMMARY_TABLES.md
// byte-for-byte from the same JSON artifacts the Python tool consumed.
import { describe, expect, test } from "bun:test";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fmt, generateReport, REAL_TARGETS, type ReportInputs } from "../../lib/report/index.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (p: string) => JSON.parse(readFileSync(p, "utf-8"));

function loadInputs(): ReportInputs {
  const manifestPath = path.join(root, "experiments", "traces_manifest.json");
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
      for (const field of readJson(wp).fields)
        for (const rec of field.pages) origins.set(rec.page_rva, new Set(rec.origins ?? []));
    }
    pageOriginsBySample[s] = origins;
  }
  return {
    dynRoot: root,
    evalData: readJson(path.join(root, "experiments", "evaluation_results.json")),
    stratData: readJson(path.join(root, "experiments", "strategy_comparison.json")),
    manifestData: existsSync(manifestPath) ? readJson(manifestPath) : {},
    ledgers,
    fieldMetaBySample,
    pageOriginsBySample,
  };
}

describe("fmt: Python %.Nf compatibility", () => {
  // Exact-decimal-expansion half-even rounding (CPython dtoa semantics).
  const cases: Array<[number, number, string]> = [
    [0.065, 2, "0.07"], // double is 0.0650000000000000013... -> rounds up
    [0.075, 2, "0.07"], // double is 0.0749999999999999972... -> rounds down
    [2.5, 0, "2"], // exact tie -> even
    [3.5, 0, "4"],
    [0.5, 0, "0"],
    [1.5, 0, "2"],
    [-0.5, 0, "-0"],
    [-2.5, 0, "-2"],
    [2.675, 2, "2.67"], // classic banker case: 2.67499999...
    [1.005, 2, "1.00"],
    [0.125, 2, "0.12"],
    [0.375, 2, "0.38"],
    [16.234, 1, "16.2"],
    [99.995, 2, "100.00"],
    [4.545, 2, "4.54"],
    [1234.5678, 2, "1234.57"],
    [0.055, 2, "0.06"],
    [0.085, 2, "0.09"],
    [0.0455, 3, "0.045"],
  ];
  for (const [v, d, want] of cases) {
    test(`fmt(${v}, ${d}) === ${want}`, () => {
      expect(fmt(v, d)).toBe(want);
    });
  }
});

describe("generateReport golden output", () => {
  test("reproduces committed SUMMARY_TABLES.md byte-for-byte", () => {
    const committed = readFileSync(path.join(root, "experiments", "SUMMARY_TABLES.md"), "utf-8");
    const generated = generateReport(loadInputs());
    expect(generated).toBe(committed);
  });
});
