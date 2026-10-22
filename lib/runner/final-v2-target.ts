import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { isObject, normalizeDigest, parseStrictJson, sha256, type JsonObject, type ProfileBundle } from "../bundle/profile-bundle.ts";
import { ElfFile, elfLoadEquivalence, parseSignedMetadata } from "../workset/elf.ts";
import { patchElf4gate } from "../workset/patch-4gate.ts";

export const FINAL_V2_TARGET_SCHEMA = "atfield-final-v2-run-target-v2";
const NAMES = ["workset", "fields", "final_elf", "signed_final_elf", "pretouch_verified", "ready_table_json", "ready_table", "measurement_patch_json", "measurement_final_elf", "signed_measurement_final_elf", "production_config_xml", "measurement_config_xml"] as const;
type Name = (typeof NAMES)[number];
type Ref = { path: string; sha256: string };
type Identity = {
  profile_bundle_manifest_sha256: string; layout_epoch: string; workset_schema: "atfield-workset-v2";
  workset_sha256: string; fields_sha256: string; capacity_q: number; final_elf_sha256: string;
  signed_final_elf_sha256: string; pretouch_verified_sha256: string; ready_table_manifest_sha256: string;
  ready_table_sha256: string; measurement_patch_sha256: string; measurement_final_elf_sha256: string;
  signed_measurement_final_elf_sha256: string; production_config_sha256: string; measurement_config_sha256: string;
  production_aex_notify: true; measurement_aex_notify: false; measurement_signing_metadata_delta: "aex-notify-only";
};
type Manifest = { schema: string; identity: Identity; artifacts: Record<Name, Ref> };
export interface FinalV2RunTarget {
  manifestPath: string; manifestSha256: string; identity: Identity;
  artifacts: Record<Name, { path: string; sha256: string }>;
  selectedImagePath: string; readyTablePath: string; manifestFieldCount: number;
}
function fail(message: string): never { throw new Error("Final v2 target: " + message); }
function hashFile(file: string): string { return sha256(readFileSync(file)); }
function norm(value: unknown): string { return typeof value === "string" ? value.replace(/^sha256:/i, "").toLowerCase() : ""; }
function digest(value: unknown, label: string): string {
  try { return normalizeDigest(value, label); } catch (e) { return fail((e as Error).message); }
}
function json(file: string, label: string): JsonObject {
  const value = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(file)), label);
  if (!isObject(value)) fail(label + " must be an object");
  return value;
}
function resolveArtifact(manifestFile: string, value: unknown, name: string): { path: string; sha256: string } {
  if (!isObject(value) || typeof value.path !== "string") fail("artifact " + name + " is malformed");
  if (!path.isAbsolute(value.path) && value.path.split(/[\\/]/).some((part) => !part || part === "." || part === "..")) fail("artifact " + name + " path must be clean");
  const root = path.dirname(manifestFile);
  const resolved = realpathSync(path.isAbsolute(value.path) ? value.path : path.resolve(root, value.path));
  if (!statSync(resolved).isFile()) fail("artifact " + name + " is not a regular file");
  const sha = digest(value.sha256, "artifacts." + name + ".sha256");
  if (hashFile(resolved) !== sha) fail("artifact digest mismatch for " + name);
  return { path: resolved, sha256: sha };
}
function freezeArtifact(file: string): Ref {
  const resolved = realpathSync(file);
  if (!statSync(resolved).isFile()) fail("artifact is not a regular file: " + file);
  return { path: resolved, sha256: hashFile(resolved) };
}
function sameLoadGeometry(a: ElfFile, b: ElfFile): boolean {
  const geometry = (e: ElfFile): string => JSON.stringify({
    loads: e.loads.map((s) => [s.index, s.offset, s.vaddr, s.filesz, s.memsz, s.flags, s.align]),
    relro: e.relro.map((s) => [s.offset, s.vaddr, s.filesz, s.memsz, s.flags, s.align]),
  });
  return geometry(a) === geometry(b);
}
const SGX_FLAGS_AEX_NOTIFY = 0x400;
export function deriveMeasurementConfigXml(productionConfigXml: string): string {
  if (!/<EnclaveConfiguration\s*>/.test(productionConfigXml) || !/<\/EnclaveConfiguration\s*>/.test(productionConfigXml)) fail("production SGX config must be an EnclaveConfiguration document");
  const tagCount = productionConfigXml.match(/<EnableAEXNotify\b/g)?.length ?? 0;
  const matches = [...productionConfigXml.matchAll(/^([ \t]*<EnableAEXNotify>[ \t]*)1([ \t]*<\/EnableAEXNotify>[ \t]*)(\r?)$/gm)];
  if (tagCount !== 1 || matches.length !== 1) fail("production SGX config must have one explicit EnableAEXNotify=1 element");
  const match = matches[0]!;
  return productionConfigXml.replace(match[0], match[1]! + "0" + match[2]! + match[3]!);
}
export function assertMeasurementConfigDerived(productionConfigXml: string, measurementConfigXml: string): void {
  if (deriveMeasurementConfigXml(productionConfigXml) !== measurementConfigXml) fail("measurement SGX config must differ from the production config only by EnableAEXNotify=0");
}
export function assertFinalV2AexMetadata(production: Record<string, unknown>, measurement: Record<string, unknown>): void {
  const prodFlags = production.attributes_flags, measureFlags = measurement.attributes_flags;
  if (typeof prodFlags !== "number" || !Number.isSafeInteger(prodFlags) || typeof measureFlags !== "number" || !Number.isSafeInteger(measureFlags)) fail("signed SGX metadata is missing valid attributes.flags");
  if ((prodFlags & SGX_FLAGS_AEX_NOTIFY) === 0 || (measureFlags & SGX_FLAGS_AEX_NOTIFY) !== 0 || (prodFlags ^ measureFlags) !== SGX_FLAGS_AEX_NOTIFY) fail("signed measurement Final must differ from production Final only by disabling AEX_NOTIFY");
  const stable = (meta: Record<string, unknown>, flags: number) => ({
    version: meta.version, metadata_size: meta.metadata_size, ssa_frame_pages: meta.ssa_frame_pages,
    enclave_size: meta.enclave_size, attributes_flags: flags & ~SGX_FLAGS_AEX_NOTIFY,
    attributes_xfrm: meta.attributes_xfrm, layout_entries: meta.layout_entries,
  });
  if (JSON.stringify(stable(production, prodFlags)) !== JSON.stringify(stable(measurement, measureFlags))) fail("production and measurement signed SGX metadata layout differs beyond the AEX_NOTIFY bit");
}
export function assertWorksetDigestBound(expectedSha256: string, claimedSha256: unknown, label: string): void {
  if (digest(claimedSha256, label) !== digest(expectedSha256, "frozen workset SHA-256")) fail(label + " does not match the frozen workset digest");
}
export function assertFinalV2BundleIdentity(bundle: ProfileBundle, id: Identity): void {
  if (digest(id.profile_bundle_manifest_sha256, "identity.profile_bundle_manifest_sha256") !== bundle.manifestSha256) fail("target belongs to a different Profile bundle");
  if (norm(id.layout_epoch) !== norm(bundle.layoutEpoch) || id.workset_schema !== "atfield-workset-v2" || !Number.isSafeInteger(id.capacity_q) || id.capacity_q !== bundle.capacityQ) fail("target layout/Q does not match the frozen v2 Profile bundle");
  if (id.production_aex_notify !== true || id.measurement_aex_notify !== false || id.measurement_signing_metadata_delta !== "aex-notify-only") fail("target must declare production AEX_NOTIFY=1 and diagnostic measurement AEX_NOTIFY=0");
}
function validate(bundle: ProfileBundle, base: string, raw: Manifest): FinalV2RunTarget {
  if (raw.schema !== FINAL_V2_TARGET_SCHEMA || !isObject(raw.identity) || !isObject(raw.artifacts)) fail("expected " + FINAL_V2_TARGET_SCHEMA);
  const id = raw.identity;
  assertFinalV2BundleIdentity(bundle, id);
  const files = {} as Record<Name, { path: string; sha256: string }>;
  for (const name of NAMES) files[name] = resolveArtifact(base, raw.artifacts[name], name);
  const sha = (n: Name) => files[n].sha256;
  const claims: Array<[unknown, Name, string]> = [
    [id.workset_sha256, "workset", "workset"], [id.fields_sha256, "fields", "fields"], [id.final_elf_sha256, "final_elf", "production Final"],
    [id.signed_final_elf_sha256, "signed_final_elf", "signed production Final"], [id.pretouch_verified_sha256, "pretouch_verified", "pretouch verification"],
    [id.ready_table_manifest_sha256, "ready_table_json", "ReadyTable manifest"], [id.ready_table_sha256, "ready_table", "ReadyTable binary"],
    [id.measurement_patch_sha256, "measurement_patch_json", "measurement patch manifest"], [id.measurement_final_elf_sha256, "measurement_final_elf", "measurement Final"],
    [id.signed_measurement_final_elf_sha256, "signed_measurement_final_elf", "signed measurement Final"],
    [id.production_config_sha256, "production_config_xml", "production SGX config"],
    [id.measurement_config_sha256, "measurement_config_xml", "diagnostic SGX config"],
  ];
  for (const [claim, name, label] of claims) if (digest(claim, "identity." + label) !== sha(name)) fail(label + " SHA does not match frozen bytes");
  const productionConfig = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(files.production_config_xml.path));
  const measurementConfig = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(files.measurement_config_xml.path));
  assertMeasurementConfigDerived(productionConfig, measurementConfig);
  const workset = json(files.workset.path, "workset");
  if (workset.schema !== "atfield-workset-v2" || norm(workset.layout_epoch) !== norm(bundle.layoutEpoch) || digest(workset.bundle_manifest_sha256, "workset.bundle_manifest_sha256") !== bundle.manifestSha256 || workset.capacity_q !== bundle.capacityQ) fail("workset is not the frozen v2 workset for this Profile bundle/layout");
  if (sha("fields") !== bundle.identity.fieldsSha256) fail("fields differ from the Profile bundle");
  const pretouch = json(files.pretouch_verified.path, "pretouch verification");
  assertWorksetDigestBound(sha("workset"), pretouch.workset_sha256, "pretouch.workset_sha256");
  if (pretouch.schema !== "atfield-pretouch-final-v1" || digest(pretouch.fields_sha256, "pretouch.fields_sha256") !== sha("fields") || digest(pretouch.final_elf_sha256, "pretouch.final_elf_sha256") !== sha("final_elf") || digest(pretouch.signed_final_elf_sha256, "pretouch.signed_final_elf_sha256") !== sha("signed_final_elf") || pretouch.capacity_q !== bundle.capacityQ) fail("pretouch verification does not bind this workset, Q, and production Final pair");
  const ready = json(files.ready_table_json.path, "ReadyTable manifest");
  assertWorksetDigestBound(sha("workset"), ready.workset_sha256, "ready.workset_sha256");
  if (ready.schema !== "atfield-ready-table-v3" || ready.workset_schema !== "atfield-workset-v2" || digest(ready.fields_sha256, "ready.fields_sha256") !== sha("fields") || digest(ready.final_elf_sha256, "ready.final_elf_sha256") !== sha("final_elf") || digest(ready.signed_final_elf_sha256, "ready.signed_final_elf_sha256") !== sha("signed_final_elf") || digest(ready.table_sha256, "ready.table_sha256") !== sha("ready_table") || digest(ready.bundle_manifest_sha256, "ready.bundle_manifest_sha256") !== bundle.manifestSha256 || norm(ready.layout_epoch) !== norm(bundle.layoutEpoch) || digest(ready.measurement_profile_elf_sha256, "ready.measurement_profile_elf_sha256") !== bundle.identity.profileElfSha256 || digest(ready.measurement_signed_profile_elf_sha256, "ready.measurement_signed_profile_elf_sha256") !== bundle.identity.signedProfileElfSha256) fail("ReadyTable v3 does not match the v2 workset, Profile identity, and signed production Final");
  const patch = json(files.measurement_patch_json.path, "4-gate patch manifest");
  if (patch.schema !== "atfield-4gate-patch-v1" || digest(patch.input_elf_sha256, "patch.input_elf_sha256") !== sha("final_elf") || digest(patch.output_elf_sha256, "patch.output_elf_sha256") !== sha("measurement_final_elf")) fail("measurement Final was not patched from the frozen production Final");
  const production = new ElfFile(files.final_elf.path), signedProduction = new ElfFile(files.signed_final_elf.path);
  const measurement = new ElfFile(files.measurement_final_elf.path), signedMeasurement = new ElfFile(files.signed_measurement_final_elf.path);
  if (!sameLoadGeometry(production, signedProduction) || !sameLoadGeometry(production, measurement) || !sameLoadGeometry(production, signedMeasurement)) fail("PT_LOAD/PT_GNU_RELRO geometry differs across production and measurement Final images");
  elfLoadEquivalence(production, signedProduction);
  elfLoadEquivalence(measurement, signedMeasurement);
  assertFinalV2AexMetadata(parseSignedMetadata(signedProduction), parseSignedMetadata(signedMeasurement));
  const temp = mkdtempSync(path.join(tmpdir(), "atfield-final-v2-patch-check-"));
  try {
    const reproduced = path.join(temp, "measurement.elf");
    patchElf4gate(files.final_elf.path, files.fields.path, bundle.capacityQ, reproduced, path.join(temp, "patch.json"));
    if (hashFile(reproduced) !== sha("measurement_final_elf") || !readFileSync(reproduced).equals(readFileSync(files.measurement_final_elf.path))) fail("measurement Final differs from the exact 4-gate patch of frozen production Final");
  } finally { rmSync(temp, { recursive: true, force: true }); }
  return { manifestPath: realpathSync(base), manifestSha256: hashFile(base), identity: id, artifacts: files, selectedImagePath: files.signed_measurement_final_elf.path, readyTablePath: files.ready_table.path, manifestFieldCount: bundle.fields.length };
}
export function loadFinalV2RunTarget(filename: string, bundle: ProfileBundle): FinalV2RunTarget {
  const base = realpathSync(path.resolve(filename));
  if (!statSync(base).isFile()) fail("manifest must be a regular file");
  return validate(bundle, base, json(base, "target manifest") as unknown as Manifest);
}
export interface FreezeFinalV2Input {
  bundle: ProfileBundle; workset: string; fields: string; finalElf: string; signedFinalElf: string;
  pretouchVerified: string; readyTableJson: string; readyTable: string; measurementPatchJson: string;
  measurementFinalElf: string; signedMeasurementFinalElf: string; productionConfigXml: string; measurementConfigXml: string; output: string;
}
export function freezeFinalV2RunTarget(input: FreezeFinalV2Input): FinalV2RunTarget {
  const output = path.resolve(input.output), root = path.dirname(output);
  mkdirSync(root, { recursive: true });
  const artifacts = {
    workset: freezeArtifact(input.workset), fields: freezeArtifact(input.fields), final_elf: freezeArtifact(input.finalElf),
    signed_final_elf: freezeArtifact(input.signedFinalElf), pretouch_verified: freezeArtifact(input.pretouchVerified),
    ready_table_json: freezeArtifact(input.readyTableJson), ready_table: freezeArtifact(input.readyTable),
    measurement_patch_json: freezeArtifact(input.measurementPatchJson), measurement_final_elf: freezeArtifact(input.measurementFinalElf),
    signed_measurement_final_elf: freezeArtifact(input.signedMeasurementFinalElf),
    production_config_xml: freezeArtifact(input.productionConfigXml), measurement_config_xml: freezeArtifact(input.measurementConfigXml),
  } satisfies Record<Name, Ref>;
  const identity: Identity = {
    profile_bundle_manifest_sha256: input.bundle.manifestSha256, layout_epoch: input.bundle.layoutEpoch, workset_schema: "atfield-workset-v2",
    workset_sha256: artifacts.workset.sha256, fields_sha256: artifacts.fields.sha256, capacity_q: input.bundle.capacityQ,
    final_elf_sha256: artifacts.final_elf.sha256, signed_final_elf_sha256: artifacts.signed_final_elf.sha256,
    pretouch_verified_sha256: artifacts.pretouch_verified.sha256, ready_table_manifest_sha256: artifacts.ready_table_json.sha256,
    ready_table_sha256: artifacts.ready_table.sha256, measurement_patch_sha256: artifacts.measurement_patch_json.sha256,
    measurement_final_elf_sha256: artifacts.measurement_final_elf.sha256, signed_measurement_final_elf_sha256: artifacts.signed_measurement_final_elf.sha256,
    production_config_sha256: artifacts.production_config_xml.sha256, measurement_config_sha256: artifacts.measurement_config_xml.sha256,
    production_aex_notify: true, measurement_aex_notify: false, measurement_signing_metadata_delta: "aex-notify-only",
  };
  writeFileSync(output, JSON.stringify({ schema: FINAL_V2_TARGET_SCHEMA, identity, artifacts }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  try { return loadFinalV2RunTarget(output, input.bundle); }
  catch (e) { rmSync(output, { force: true }); throw e; }
}
