#!/usr/bin/env bun
import process from "node:process";
import { loadProfileBundle } from "../lib/bundle/profile-bundle.ts";
import { freezeFinalV2RunTarget } from "../lib/runner/final-v2-target.ts";

const FLAGS = new Set([
  "--bundle", "--workset", "--fields", "--final-elf", "--signed-final-elf", "--pretouch-verified",
  "--ready-table-json", "--ready-table", "--measurement-patch-json", "--measurement-final-elf",
  "--signed-measurement-final-elf", "--out",
]);
function usage(): string {
  return [
    "Freeze and verify one Final v2 C-preserve-TLB measurement target.",
    "",
    "Usage: bun cli/freeze-final-v2-target.ts --bundle BUNDLE --workset WORKSET --fields FIELDS",
    "  --final-elf FINAL --signed-final-elf SIGNED_FINAL --pretouch-verified VERIFIED",
    "  --ready-table-json READY_JSON --ready-table READY_BIN",
    "  --measurement-patch-json PATCH_JSON --measurement-final-elf GATED_FINAL",
    "  --signed-measurement-final-elf SIGNED_GATED_FINAL --out TARGET_JSON",
    "",
    "Artifact paths are frozen as absolute paths and may be in separate directories.",
  ].join("\n");
}
function parse(argv: string[]): Record<string, string> | null {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]!;
    if (key === "--help" || key === "-h") return null;
    if (!FLAGS.has(key)) throw new Error("unknown option " + key);
    if (values[key]) throw new Error("repeated option " + key);
    const value = argv[++i];
    if (!value) throw new Error("missing value after " + key);
    values[key] = value;
  }
  for (const key of FLAGS) if (!values[key]) throw new Error("missing required " + key);
  return values;
}
async function main(): Promise<number> {
  try {
    const args = parse(process.argv.slice(2));
    if (!args) { console.log(usage()); return 0; }
    const bundle = loadProfileBundle(args["--bundle"]!);
    const target = freezeFinalV2RunTarget({
      bundle,
      workset: args["--workset"]!,
      fields: args["--fields"]!,
      finalElf: args["--final-elf"]!,
      signedFinalElf: args["--signed-final-elf"]!,
      pretouchVerified: args["--pretouch-verified"]!,
      readyTableJson: args["--ready-table-json"]!,
      readyTable: args["--ready-table"]!,
      measurementPatchJson: args["--measurement-patch-json"]!,
      measurementFinalElf: args["--measurement-final-elf"]!,
      signedMeasurementFinalElf: args["--signed-measurement-final-elf"]!,
      output: args["--out"]!,
    });
    console.log(JSON.stringify({
      schema: "atfield-final-v2-run-target-summary-v1",
      target_manifest: target.manifestPath,
      target_manifest_sha256: target.manifestSha256,
      profile_bundle_manifest_sha256: target.identity.profile_bundle_manifest_sha256,
      workset_sha256: target.identity.workset_sha256,
      capacity_q: target.identity.capacity_q,
      final_elf_sha256: target.identity.final_elf_sha256,
      signed_final_elf_sha256: target.identity.signed_final_elf_sha256,
      ready_table_sha256: target.identity.ready_table_sha256,
      selected_signed_measurement_final_sha256: target.identity.signed_measurement_final_elf_sha256,
      verdict: "PASS",
    }, null, 2));
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
if (import.meta.main) process.exitCode = await main();
