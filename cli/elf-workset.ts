#!/usr/bin/env bun
// Bun producer for atfield-workset-v1 artifacts.
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import process from "node:process";
import path from "node:path";
import {
  ElfFile, WorksetError, makeLayout, produceWorkset, readJson, writeJson, PAGE,
} from "../lib/workset/elf.ts";

function usage(): string {
  return [
    "Produce full committed REG Field worksets from signed SGX metadata.",
    "Usage: bun cli/elf-workset.ts --profile-elf <f> --signed-elf <f> --fields <f>",
    "           --capacity-q <n> --out <f> [--selectors <f> --edl <f>]",
    "           [--layout <f> | --layout-out <f>]",
  ].join("\n");
}

const args = new Map<string, string>();
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) args.set(argv[i], argv[i + 1]);
const req = (k: string) => { const v = args.get(k); if (!v) throw new WorksetError(`missing ${k}`); return v; };

try {
  const capacityQ = parseInt(req("--capacity-q"), 10);
  if (!(capacityQ > 0) || capacityQ % PAGE) throw new WorksetError("--capacity-q must be a positive multiple of 4096");
  const profile = new ElfFile(req("--profile-elf"));
  const signed = new ElfFile(req("--signed-elf"));
  const sha = (f: string) => createHash("sha256").update(readFileSync(f)).digest("hex");
  let layout: Record<string, unknown>;
  if (args.get("--layout")) {
    layout = readJson(args.get("--layout")!);
    if (layout.schema !== "atfield-signer-layout-v1") throw new WorksetError("--layout must be an atfield-signer-layout-v1 JSON");
    if (layout.signed_elf_sha256 !== sha(args.get("--signed-elf")!)) throw new WorksetError("--layout does not match --signed-elf identity");
    if (layout.profile_elf_sha256 !== sha(args.get("--profile-elf")!)) throw new WorksetError("--layout does not match --profile-elf identity");
    if (layout.capacity_q !== capacityQ) throw new WorksetError("--layout Q differs from --capacity-q");
  } else {
    layout = makeLayout(profile, signed, capacityQ);
  }
  if (args.get("--layout-out")) writeJson(args.get("--layout-out")!, layout);
  const result = produceWorkset(profile, layout, req("--fields"), args.get("--selectors") ?? null, args.get("--edl") ?? null);
  writeJson(req("--out"), result);
  const fields = result.fields as Array<Record<string, unknown>>;
  console.log(`workset: fields=${fields.length} committed_REG_pages_per_field=${(fields[0].pages as unknown[]).length} ordinary_load_end=0x${(layout.ordinary_load_end as number).toString(16)} post_start=0x${(layout.pretouch_start as number).toString(16)} Q=${layout.capacity_q} excluded_layout_ranges=${(layout.excluded_regions as unknown[]).length}`);
  console.log(`wrote ${args.get("--out")}`);
  process.exit(0);
} catch (exc) {
  if (exc instanceof WorksetError || exc instanceof Error) {
    console.error(`workset: error: ${exc instanceof Error ? exc.message : exc}`);
    process.exit(2);
  }
  throw exc;
}
