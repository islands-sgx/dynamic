#!/usr/bin/env bun
import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { sha256 } from "../lib/bundle/profile-bundle.ts";
import { deriveMeasurementConfigXml } from "../lib/runner/final-v2-target.ts";

function main(): number {
  try {
    const argv = process.argv.slice(2);
    if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
      console.log("Usage: bun cli/derive-final-v2-config.ts --production-config-xml PROD_XML --out DIAGNOSTIC_XML");
      return 0;
    }
    if (argv.length !== 4 || argv[0] !== "--production-config-xml" || argv[2] !== "--out") throw new Error("expected --production-config-xml PROD_XML --out DIAGNOSTIC_XML");
    const productionBytes = readFileSync(argv[1]!);
    const production = new TextDecoder("utf-8", { fatal: true }).decode(productionBytes);
    const measurement = deriveMeasurementConfigXml(production);
    const measurementBytes = new TextEncoder().encode(measurement);
    writeFileSync(argv[3]!, measurementBytes, { mode: 0o600, flag: "wx" });
    console.log(JSON.stringify({ production_config_sha256: sha256(productionBytes), measurement_config_sha256: sha256(measurementBytes), production_aex_notify: true, measurement_aex_notify: false, changed_element: "EnableAEXNotify" }, null, 2));
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
if (import.meta.main) process.exitCode = main();
