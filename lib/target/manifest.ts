// lib/target/manifest.ts
// Load build metadata and dynamic-owned scenario/oracle configurations.
// Ported from tools/target_manifest.py.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

export const SCENARIO_SCHEMA = "atfield-dynamic-scenarios-v1";
const FIXTURE_TARGET_NAMES = new Set(["sqlite"]);

export function dynamicRoot(): string {
  return path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
}

export function defaultSampleRoot(): string {
  return process.env.ATFIELD_SAMPLE_ROOT ?? path.join(dynamicRoot(), "..", "sample");
}

export function ensureRealTargetName(name: string): void {
  if (FIXTURE_TARGET_NAMES.has(name))
    throw new Error(`${JSON.stringify(name)} is a research fixture, not a real target`);
}

function readDynamicScenarios(targetName: string): Record<string, unknown> {
  const scenarioPath = path.join(dynamicRoot(), "targets", targetName, "scenarios.json");
  if (!existsSync(scenarioPath))
    throw new Error(`Missing dynamic scenario/oracle for real target ${JSON.stringify(targetName)}: ${scenarioPath}`);
  const scenarios = JSON.parse(readFileSync(scenarioPath, "utf-8"));
  if (scenarios === null || typeof scenarios !== "object" || Array.isArray(scenarios))
    throw new Error(`Dynamic scenarios for ${JSON.stringify(targetName)} must be a JSON object: ${scenarioPath}`);
  if (scenarios.schema !== SCENARIO_SCHEMA)
    throw new Error(`Dynamic scenarios for ${JSON.stringify(targetName)} require schema ${JSON.stringify(SCENARIO_SCHEMA)}; found ${JSON.stringify(scenarios.schema)} in ${scenarioPath}`);
  if (scenarios.name !== targetName)
    throw new Error(`Dynamic scenarios target name mismatch: manifest=${JSON.stringify(targetName)}, scenarios=${JSON.stringify(scenarios.name)} in ${scenarioPath}`);
  return scenarios;
}

export function loadTargetManifest(targetOrPath: string, sampleRoot: string = defaultSampleRoot()): Record<string, unknown> {
  const p = path.resolve(targetOrPath);
  if (!existsSync(p) && FIXTURE_TARGET_NAMES.has(targetOrPath)) ensureRealTargetName(targetOrPath);
  let manifestPath: string;
  if (existsSync(p) && p.endsWith(".json")) {
    manifestPath = p;
  } else if (existsSync(path.join(dynamicRoot(), "targets", targetOrPath, "target_manifest.json"))) {
    manifestPath = path.resolve(path.join(dynamicRoot(), "targets", targetOrPath, "target_manifest.json"));
  } else {
    manifestPath = path.resolve(path.join(sampleRoot, "build", "real", targetOrPath, "protect", "target_manifest.json"));
    if (!existsSync(manifestPath))
      throw new Error(`Cannot locate target_manifest.json for ${JSON.stringify(targetOrPath)} at ${manifestPath}`);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
  const targetName = String(manifest.name ?? "");
  if (!targetName) throw new Error(`Target manifest has no non-empty name: ${manifestPath}`);
  ensureRealTargetName(targetName);
  const scenarios = readDynamicScenarios(targetName);
  delete manifest.scenarios_json;
  delete manifest.scenarios;
  manifest.manifest_path = manifestPath;
  manifest.scenarios = scenarios;
  return manifest;
}

export function discoverRealTargetManifests(
  namesOrPaths?: string[],
  sampleRoot: string = defaultSampleRoot(),
): Array<Record<string, unknown>> {
  if (namesOrPaths?.length)
    return namesOrPaths.map((x) => loadTargetManifest(x, sampleRoot));
  const base = path.join(sampleRoot, "build", "real");
  const found: string[] = [];
  if (existsSync(base)) {
    for (const entry of readdirSync(base)) {
      const mp = path.join(base, entry, "protect", "target_manifest.json");
      if (existsSync(mp)) found.push(mp);
    }
  }
  found.sort();
  const manifests: Array<Record<string, unknown>> = [];
  for (const mp of found) {
    const name = String(JSON.parse(readFileSync(mp, "utf-8")).name ?? "");
    if (FIXTURE_TARGET_NAMES.has(name)) continue;
    manifests.push(loadTargetManifest(mp, sampleRoot));
  }
  return manifests;
}

export function preferCurrentSampleManifests(requests: string[], sampleRoot: string = defaultSampleRoot()): string[] {
  return requests.map((r) => {
    if (existsSync(path.resolve(r))) return path.resolve(r);
    const mp = path.join(sampleRoot, "build", "real", r, "protect", "target_manifest.json");
    if (!existsSync(mp))
      throw new Error(`Cannot rebuild ${JSON.stringify(r)} without current sample build metadata: ${mp}`);
    return mp;
  });
}
