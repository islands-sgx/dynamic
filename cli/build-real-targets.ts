#!/usr/bin/env bun
// cli/build-real-targets.ts — prepare dynamic artifacts from sample build
// metadata and dynamic-owned scenarios. Replaces tools/build_real_targets.py.
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { readJson, writeJson } from "../lib/workset/elf.ts";
import { patchElf4gate } from "../lib/workset/patch-4gate.ts";
import { discoverRealTargetManifests, dynamicRoot, preferCurrentSampleManifests } from "../lib/target/manifest.ts";

function run(cmd: string[], quiet = false): void {
  const r = spawnSync(cmd[0], cmd.slice(1), quiet ? { stdio: ["ignore", "ignore", "inherit"] } : { stdio: "inherit" });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`command failed (${r.status}): ${cmd.join(" ")}`);
}

function prepareTargetFromManifest(manifest: Record<string, unknown>): Record<string, unknown> {
  const dynRoot = dynamicRoot();
  const name = manifest.name as string;
  const outDir = path.join(dynRoot, "targets", name);
  const scenarioPath = path.join(outDir, "scenarios.json");
  if (!existsSync(scenarioPath))
    throw new Error(`Missing dynamic-owned scenarios for ${name}: ${scenarioPath}`);
  const localScenarios = JSON.parse(readFileSync(scenarioPath, "utf-8"));
  if (JSON.stringify(localScenarios) !== JSON.stringify(manifest.scenarios))
    throw new Error(`Loaded scenario/oracle differs from dynamic source ${scenarioPath}`);
  mkdirSync(outDir, { recursive: true });

  const persisted: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(manifest))
    if (!["manifest_path", "scenarios", "scenarios_json"].includes(k)) persisted[k] = v;
  writeJson(path.join(outDir, "target_manifest.json"), persisted);

  const copyPairs: Array<[string, string]> = [
    ["profile_elf", "enclave.profile.so"],
    ["profile_signed_elf", "enclave.profile.signed.so"],
    ["fields_json", "fields.json"],
    ["selectors_json", "selectors.json"],
    ["protect_config_xml", "Enclave.protect.config.xml"],
    ["all_reg_workset_json", "workset.all_reg.json"],
    ["all_reg_final_elf", "enclave.all_reg.final.so"],
    ["all_reg_signed_elf", "enclave.all_reg.final.signed.so"],
    ["all_reg_unstripped_signed_elf", "enclave.all_reg.final.signed.unstripped.so"],
    ["all_reg_pretouch_finalized_json", "pretouch.all_reg.finalized.json"],
    ["all_reg_pretouch_verified_json", "pretouch.all_reg.verified.json"],
    ["all_reg_ready_bin", "enclave.all_reg.ready.bin"],
    ["all_reg_ready_json", "enclave.all_reg.ready.json"],
  ];
  for (const [srcKey, dstName] of copyPairs) {
    const src = String(manifest[srcKey]);
    if (!existsSync(src)) throw new Error(`Missing sample artifact ${srcKey}=${src} for ${name}`);
    copyFileSync(src, path.join(outDir, dstName));
  }

  const protectXml = path.join(outDir, "Enclave.protect.config.xml");
  const aex0Xml = path.join(outDir, "Enclave.aex0.config.xml");
  writeFileSync(aex0Xml, readFileSync(protectXml, "utf-8").replace("<EnableAEXNotify>1</EnableAEXNotify>", "<EnableAEXNotify>0</EnableAEXNotify>"));

  const sgxSign = String(manifest.sgx_sign);
  const signKey = String(manifest.signing_key_path);
  const objcopy = String(manifest.objcopy);
  const implRoot = String(manifest.implement_root);
  const pretouchTool = path.join(implRoot, "build", "pretouch", "pretouch.ts");
  const readinessTool = path.join(implRoot, "build", "readiness", "readiness.ts");
  const capacityQ = Number(manifest.protect_q);

  const profileElf = path.join(outDir, "enclave.profile.so");
  const signedProfile = path.join(outDir, "enclave.profile.signed.so");
  const signedProfileAex0 = path.join(outDir, "enclave.profile.aex0.signed.so");
  run([sgxSign, "sign", "-key", signKey, "-enclave", profileElf, "-out", signedProfileAex0, "-config", aex0Xml], true);

  const fieldsFile = path.join(outDir, "fields.json");
  const profile4gateElf = path.join(outDir, "enclave.profile.4gate.so");
  const profile4gateSignedAex0 = path.join(outDir, "enclave.profile.4gate.aex0.signed.so");
  patchElf4gate(profileElf, fieldsFile, capacityQ, profile4gateElf, path.join(outDir, "enclave.profile.4gate.json"));
  run([sgxSign, "sign", "-key", signKey, "-enclave", profile4gateElf, "-out", profile4gateSignedAex0, "-config", aex0Xml], true);

  const allRegFinal = path.join(outDir, "enclave.all_reg.final.so");
  const allRegSignedAex0 = path.join(outDir, "enclave.all_reg.final.aex0.signed.so");
  run([sgxSign, "sign", "-key", signKey, "-enclave", allRegFinal, "-out", allRegSignedAex0, "-config", aex0Xml], true);

  const allReg4gateElf = path.join(outDir, "enclave.all_reg.4gate.so");
  const allReg4gateSignedAex0 = path.join(outDir, "enclave.all_reg.4gate.aex0.signed.so");
  patchElf4gate(allRegFinal, fieldsFile, capacityQ, allReg4gateElf, path.join(outDir, "enclave.all_reg.4gate.json"));
  run([sgxSign, "sign", "-key", signKey, "-enclave", allReg4gateElf, "-out", allReg4gateSignedAex0, "-config", aex0Xml], true);

  const wsAllReg = readJson(path.join(outDir, "workset.all_reg.json"));
  const wsXr = structuredClone(wsAllReg);
  for (const f of wsXr.fields ?? [])
    for (const pg of f.pages ?? [])
      if ((pg.max_permissions & 5) === 5 && !(pg.effects ?? []).includes("R")) pg.effects = ["X", "R"];
  const wsXrFile = path.join(outDir, "workset.all_reg_xr.json");
  writeJson(wsXrFile, wsXr);

  const xrFinal = path.join(outDir, "enclave.all_reg_xr.final.so");
  const xrFinalized = path.join(outDir, "pretouch.all_reg_xr.finalized.json");
  const xrVerified = path.join(outDir, "pretouch.all_reg_xr.verified.json");
  const xrSignedUnstripped = path.join(outDir, "enclave.all_reg_xr.final.signed.unstripped.so");
  const xrSignedAex1 = path.join(outDir, "enclave.all_reg_xr.final.signed.so");
  const xrSignedAex0 = path.join(outDir, "enclave.all_reg_xr.final.aex0.signed.so");
  const xrReadyBin = path.join(outDir, "enclave.all_reg_xr.ready.bin");
  const xrReadyJson = path.join(outDir, "enclave.all_reg_xr.ready.json");

  run([pretouchTool, "finalize", "--profile-elf", profileElf, "--signed-profile-elf", signedProfile, "--workset", wsXrFile, "--fields", fieldsFile, "--capacity-q", String(capacityQ), "--out-elf", xrFinal, "--out-json", xrFinalized]);
  run([sgxSign, "sign", "-key", signKey, "-enclave", xrFinal, "-out", xrSignedUnstripped, "-config", protectXml], true);
  run([sgxSign, "sign", "-key", signKey, "-enclave", xrFinal, "-out", xrSignedAex0, "-config", aex0Xml], true);
  run([objcopy, "--strip-all", "--keep-section=.note.sgxmeta", xrSignedUnstripped, xrSignedAex1]);
  run([pretouchTool, "verify", "--profile-elf", profileElf, "--signed-profile-elf", signedProfile, "--final-elf", xrFinal, "--signed-final-elf", xrSignedAex1, "--workset", wsXrFile, "--fields", fieldsFile, "--capacity-q", String(capacityQ), "--out-json", xrVerified]);
  run([readinessTool, "--workset", wsXrFile, "--fields", fieldsFile, "--pretouch", xrVerified, "--final-elf", xrFinal, "--signed-final-elf", xrSignedAex1, "--out", xrReadyBin, "--out-json", xrReadyJson]);

  const xr4gateElf = path.join(outDir, "enclave.all_reg_xr.4gate.so");
  const xr4gateSignedAex0 = path.join(outDir, "enclave.all_reg_xr.4gate.aex0.signed.so");
  patchElf4gate(xrFinal, fieldsFile, capacityQ, xr4gateElf, path.join(outDir, "enclave.all_reg_xr.4gate.json"));
  run([sgxSign, "sign", "-key", signKey, "-enclave", xr4gateElf, "-out", xr4gateSignedAex0, "-config", aex0Xml], true);

  writeJson(path.join(outDir, "signer_layout.json"), wsAllReg.layout);
  return {
    name,
    fields: wsAllReg.fields.length,
    all_reg_pages: wsAllReg.fields[0].pages.length,
    post_start: `0x${(wsAllReg.layout.pretouch_start as number).toString(16)}`,
    capacity_q: wsAllReg.layout.capacity_q,
  };
}

const manifests = discoverRealTargetManifests(preferCurrentSampleManifests(process.argv.slice(2)));
for (const m of manifests) {
  console.log(`=== Preparing ${m.name} from ${m.manifest_path} ===`);
  const summary = prepareTargetFromManifest(m);
  console.log(`Prepared ${m.name}: ${JSON.stringify(summary)}`);
}
