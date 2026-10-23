// lib/workset/elf.ts
// Build FieldTargetPages from a signed SGX layout and frozen ELF inputs.
// TypeScript producer for atfield-workset-v1 and atfield-signer-layout-v1 artifacts.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeSync, fsyncSync, openSync, closeSync } from "node:fs";
import path from "node:path";

export const PAGE = 4096;
const ELFCLASS64 = 2, ELFDATA2LSB = 1, ET_DYN = 3, EM_X86_64 = 62;
const PT_LOAD = 1, PT_GNU_RELRO = 0x6474e552;
const PF_X = 1, PF_W = 2, PF_R = 4;
const SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXECINSTR = 4;
const SHT_SYMTAB = 2, SHT_DYNSYM = 11, SHT_NOTE = 7;
const MAGIC = 0x86a80294635d0e4cn;
const GROUP_FLAG = 1 << 12;
const DIR_LAYOUT = 1;
const PAGE_ATTR_EADD = 1;
export const SI_FLAG_R = 1, SI_FLAG_W = 2, SI_FLAG_X = 4;
const SI_FLAG_PT_MASK = 0xff << 8, SI_FLAG_TCS = 1 << 8, SI_FLAG_REG = 2 << 8;
const LAYOUT_NAMES: Record<number, string> = {
  1: "HEAP_MIN", 2: "HEAP_INIT", 3: "HEAP_MAX", 4: "TCS", 5: "TD",
  6: "SSA", 7: "STACK_MAX", 8: "STACK_MIN", 10: "GUARD",
  11: "HEAP_DYN_MIN", 12: "HEAP_DYN_INIT", 13: "HEAP_DYN_MAX",
  14: "TCS_DYN", 15: "TD_DYN", 16: "SSA_DYN", 17: "STACK_DYN_MAX",
  18: "STACK_DYN_MIN", 20: "RSRV_MIN", 21: "RSRV_INIT", 22: "RSRV_MAX",
  23: "USER_REGION",
};
const SPECIAL_IDS = new Set([4, 6, 10, 14, 16]);

export class WorksetError extends Error {}

export const alignDown = (n: number, a: number = PAGE): number => n & -a;
export const alignUp = (n: number, a: number = PAGE): number => (n + a - 1) & -a;

// Python json.dumps(value, indent=2, sort_keys=True) + "\n" byte format:
// sorted keys recursively; bigint values emit their full decimal digits
// (JSON numbers >2^53 are preserved via the context.source reviver in
// readJson); ensure_ascii escaping for >0x7F code units.
function pySerialize(v: unknown, level: number): string {
  const pad = "  ".repeat(level);
  const padIn = "  ".repeat(level + 1);
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) {
    if (!v.length) return "[]";
    return "[\n" + v.map((x) => padIn + pySerialize(x, level + 1)).join(",\n") + "\n" + pad + "]";
  }
  const keys = Object.keys(v as Record<string, unknown>).filter((k) => (v as Record<string, unknown>)[k] !== undefined).sort();
  if (!keys.length) return "{}";
  return "{\n" + keys.map((k) => padIn + JSON.stringify(k) + ": " + pySerialize((v as Record<string, unknown>)[k], level + 1)).join(",\n") + "\n" + pad + "}";
}
export function jsonDumps(value: unknown): string {
  const s = pySerialize(value, 0);
  return s.replace(/[\u0080-\uFFFF]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")) + "\n";
}

export function writeJson(file: string, value: unknown): void {
  const target = path.resolve(file);
  mkdirSync(path.dirname(target), { recursive: true });
  const tmp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.tmp`);
  try {
    const fd = openSync(tmp, "w");
    try { writeSync(fd, jsonDumps(value)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, target);
  } catch (e) {
    try { unlinkSync(tmp); } catch {}
    throw e;
  }
}

export function readJson(file: string): Record<string, unknown> {
  let value: unknown;
  const revive = (_k: string, v: unknown, ctx?: { source?: string }) => {
    if (typeof v === "number" && ctx?.source && /^-?[0-9]+$/.test(ctx.source)) {
      const b = BigInt(ctx.source);
      if (b > BigInt(Number.MAX_SAFE_INTEGER) || b < -BigInt(Number.MAX_SAFE_INTEGER)) return b;
    }
    return v;
  };
  try { value = JSON.parse(readFileSync(file, "utf-8"), revive as (k: string, v: unknown) => unknown); }
  catch (exc) { throw new WorksetError(`cannot read JSON ${file}: ${exc}`); }
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new WorksetError(`JSON root must be an object: ${file}`);
  return value as Record<string, unknown>;
}

const U64_RE = /^(?:0[xX][0-9a-fA-F]{1,16}|[0-9]+)$/;
export function parseU64(value: unknown, label: string): bigint {
  let result: bigint;
  try {
    if (typeof value === "boolean") throw new Error("boolean");
    if (typeof value === "number" && Number.isInteger(value)) result = BigInt(value);
    else if (typeof value === "bigint") result = value;
    else if (typeof value === "string" && U64_RE.test(value)) result = BigInt(value);
    else throw new Error("not an integer or hexadecimal string");
  } catch {
    throw new WorksetError(`${label} must be an unsigned 64-bit integer: ${JSON.stringify(value)}`);
  }
  if (result < 0n || result >= 1n << 64n)
    throw new WorksetError(`${label} is outside uint64: ${JSON.stringify(value)}`);
  return result;
}

function readCstr(blob: Buffer, at: number): string {
  if (at < 0 || at >= blob.length) return "";
  let end = blob.indexOf(0, at);
  if (end < 0) end = blob.length;
  return blob.subarray(at, end).toString("utf-8"); // Node replaces invalid bytes with U+FFFD
}

export interface ElfSegment {
  index: number; offset: number; vaddr: number; filesz: number; memsz: number;
  flags: number; align: number; end?: number;
}
export interface ElfSection {
  index: number; nameoff: number; type: number; flags: number; addr: number;
  offset: number; size: number; link: number; info: number; align: number;
  entsize: number; name: string;
}
export interface ElfSymbol {
  name: string; value: number; size: number; info: number; other: number;
  shndx: number; file_offset: number; table_name: string;
}

export class ElfFile {
  readonly path: string;
  readonly data: Buffer;
  readonly loads: ElfSegment[] = [];
  readonly relro: ElfSegment[] = [];
  readonly sections: ElfSection[] = [];
  readonly byName: Map<string, ElfSection[]> = new Map();
  private symbolsCache: ElfSymbol[] | null = null;
  private symbolsByName: Map<string, ElfSymbol[]> | null = null;
  private uniqueSymbols = new Map<string, ElfSymbol>();

  constructor(file: string) {
    this.path = path.normalize(file);
    try { this.data = readFileSync(this.path); }
    catch (exc) { throw new WorksetError(`cannot read ELF ${this.path}: ${exc}`); }
    const d = this.data;
    if (d.length < 64 || d.readUInt32LE(0) !== 0x464c457f)
      throw new WorksetError(`not an ELF file: ${this.path}`);
    if (d[4] !== ELFCLASS64 || d[5] !== ELFDATA2LSB)
      throw new WorksetError(`expected little-endian ELF64: ${this.path}`);
    const etype = d.readUInt16LE(16), machine = d.readUInt16LE(18);
    const phoff = Number(d.readBigUInt64LE(32)), shoff = Number(d.readBigUInt64LE(40));
    const ehsize = d.readUInt16LE(52), phentsize = d.readUInt16LE(54);
    const phnum = d.readUInt16LE(56), shentsize = d.readUInt16LE(58);
    const shnum = d.readUInt16LE(60), shstrndx = d.readUInt16LE(62);
    if (machine !== EM_X86_64 || etype !== ET_DYN)
      throw new WorksetError(`expected x86-64 ET_DYN enclave ELF: ${this.path}`);
    if (ehsize < 64 || phentsize < 56 || shentsize < 64 || phnum === 0 || shnum === 0)
      throw new WorksetError(`unsupported or incomplete ELF tables: ${this.path}`);
    if (phoff + phentsize * phnum > d.length || shoff + shentsize * shnum > d.length)
      throw new WorksetError(`ELF table exceeds file size: ${this.path}`);
    for (let index = 0; index < phnum; index++) {
      const base = phoff + index * phentsize;
      const pType = d.readUInt32LE(base), pFlags = d.readUInt32LE(base + 4);
      const pOffset = Number(d.readBigUInt64LE(base + 8)), pVaddr = Number(d.readBigUInt64LE(base + 16));
      const pFilesz = Number(d.readBigUInt64LE(base + 32)), pMemsz = Number(d.readBigUInt64LE(base + 40));
      const pAlign = Number(d.readBigUInt64LE(base + 48));
      if (pType === PT_LOAD) {
        if (pFilesz > pMemsz || pOffset + pFilesz > d.length)
          throw new WorksetError(`invalid PT_LOAD ${index} in ${this.path}`);
        this.loads.push({ index, offset: pOffset, vaddr: pVaddr, filesz: pFilesz, memsz: pMemsz, flags: pFlags, align: pAlign });
      } else if (pType === PT_GNU_RELRO) {
        if (pMemsz === 0) throw new WorksetError(`empty PT_GNU_RELRO ${index} in ${this.path}`);
        this.relro.push({ index, offset: pOffset, vaddr: pVaddr, filesz: pFilesz, memsz: pMemsz, flags: pFlags, align: pAlign, end: pVaddr + pMemsz });
      }
    }
    if (!this.loads.length) throw new WorksetError(`ELF has no PT_LOAD segments: ${this.path}`);
    if (shstrndx >= shnum) throw new WorksetError(`invalid section-name string table: ${this.path}`);
    const raw: ElfSection[] = [];
    for (let index = 0; index < shnum; index++) {
      const base = shoff + index * shentsize;
      const nameoff = d.readUInt32LE(base), stype = d.readUInt32LE(base + 4);
      const flags = Number(d.readBigUInt64LE(base + 8)), addr = Number(d.readBigUInt64LE(base + 16));
      const offset = Number(d.readBigUInt64LE(base + 24)), size = Number(d.readBigUInt64LE(base + 32));
      const link = d.readUInt32LE(base + 40), info = d.readUInt32LE(base + 44);
      const addralign = Number(d.readBigUInt64LE(base + 48)), entsize = Number(d.readBigUInt64LE(base + 56));
      if (stype !== 8 && offset + size > d.length)
        throw new WorksetError(`section ${index} exceeds file size: ${this.path}`);
      raw.push({ index, nameoff, type: stype, flags, addr, offset, size, link, info, align: addralign, entsize, name: "" });
    }
    const strSec = raw[shstrndx];
    const strings = d.subarray(strSec.offset, strSec.offset + strSec.size);
    for (const s of raw) s.name = readCstr(strings, s.nameoff);
    this.sections = raw;
    for (const s of raw) {
      if (!s.name) continue;
      const l = this.byName.get(s.name) ?? [];
      l.push(s); this.byName.set(s.name, l);
    }
  }

  sectionData(section: ElfSection): Buffer {
    return this.data.subarray(section.offset, section.offset + section.size);
  }

  loadedOffset(address: number, width = 1): number {
    for (const s of this.loads) {
      const lo = s.vaddr, hi = s.vaddr + s.filesz;
      if (lo <= address && address + width <= hi) return s.offset + address - lo;
    }
    throw new WorksetError(`RVA ${address.toString(16).padStart(2, "0")} is not file-backed by PT_LOAD in ${this.path}`);
  }

  noteDescriptor(): Buffer {
    const notes = this.byName.get(".note.sgxmeta") ?? [];
    if (notes.length !== 1)
      throw new WorksetError(`expected one .note.sgxmeta section in ${this.path}; found ${notes.length}`);
    const section = notes[0];
    if (section.type !== SHT_NOTE)
      throw new WorksetError(`.note.sgxmeta is not SHT_NOTE in ${this.path}`);
    const blob = this.sectionData(section);
    let offset = 0;
    while (offset + 12 <= blob.length) {
      const namesz = blob.readUInt32LE(offset), descsz = blob.readUInt32LE(offset + 4), noteType = blob.readUInt32LE(offset + 8);
      offset += 12;
      const nameEnd = offset + namesz;
      if (nameEnd > blob.length) break;
      const owner = blob.subarray(offset, nameEnd).toString("latin1").replace(/\0+$/, "");
      const starts = [nameEnd, offset + alignUp(namesz, 4)];
      if (owner === "sgx_metadata" && noteType === 1) {
        for (const descStart of starts) {
          const descEnd = descStart + descsz;
          if (descEnd > blob.length) continue;
          const desc = blob.subarray(descStart, descEnd);
          if (desc.length >= 0x6000 && desc.readBigUInt64LE(0) === MAGIC) return desc.subarray(0, 0x6000);
        }
      }
      const nextNote = Math.max(...starts) + alignUp(descsz, 4);
      if (namesz === 0 && descsz === 0) break;
      offset = nextNote;
    }
    throw new WorksetError(`SGX metadata note not found in ${this.path}`);
  }

  symbols(): ElfSymbol[] {
    if (this.symbolsCache) return this.symbolsCache;
    const result: ElfSymbol[] = [];
    for (const section of this.sections) {
      if (section.type !== SHT_SYMTAB && section.type !== SHT_DYNSYM) continue;
      if (section.link >= this.sections.length)
        throw new WorksetError(`symbol table has invalid string table in ${this.path}`);
      const strSec = this.sections[section.link];
      const strings = this.data.subarray(strSec.offset, strSec.offset + strSec.size);
      const entsize = section.entsize || 24;
      if (entsize < 24 || section.size % entsize)
        throw new WorksetError(`invalid symbol table size in ${this.path}`);
      const blob = this.sectionData(section);
      for (let off = 0; off < blob.length; off += entsize) {
        const nameoff = blob.readUInt32LE(off), info = blob.readUInt8(off + 4), other = blob.readUInt8(off + 5);
        const shndx = blob.readUInt16LE(off + 6), value = Number(blob.readBigUInt64LE(off + 8)), size = Number(blob.readBigUInt64LE(off + 16));
        const name = readCstr(strings, nameoff);
        if (name) result.push({ name, value, size, info, other, shndx, file_offset: section.offset + off, table_name: section.name });
      }
    }
    const byName = new Map<string, ElfSymbol[]>();
    for (const sym of result) {
      const l = byName.get(sym.name) ?? [];
      l.push(sym); byName.set(sym.name, l);
    }
    this.symbolsCache = result;
    this.symbolsByName = byName;
    return result;
  }

  symbolsNamed(name: string): ElfSymbol[] {
    if (!this.symbolsByName) this.symbols();
    return this.symbolsByName!.get(name) ?? [];
  }

  uniqueSymbol(name: string): ElfSymbol {
    const cached = this.uniqueSymbols.get(name);
    if (cached) return cached;
    const defs = this.symbolsNamed(name).filter((s) => s.shndx !== 0);
    const unique = new Map<string, ElfSymbol>();
    for (const s of defs) unique.set(`${s.value},${s.size},${s.shndx}`, s);
    if (unique.size !== 1)
      throw new WorksetError(`symbol ${name} has ${unique.size} definitions in ${this.path}`);
    const result = [...unique.values()][0];
    this.uniqueSymbols.set(name, result);
    return result;
  }
}

export function parseSignedMetadata(elf: ElfFile): Record<string, unknown> {
  const desc = elf.noteDescriptor();
  const magic = desc.readBigUInt64LE(0);
  const version = desc.readBigUInt64LE(8);
  const metadataSize = desc.readUInt32LE(16);
  const ssaFramePages = desc.readUInt32LE(24);
  const enclaveSize = Number(desc.readBigUInt64LE(40));
  const attributesFlags = Number(desc.readBigUInt64LE(48));
  const attributesXfrm = Number(desc.readBigUInt64LE(56));
  if (magic !== MAGIC)
    throw new WorksetError(`bad .note.sgxmeta magic in ${elf.path}: 0x${magic.toString(16)}`);
  if (metadataSize < 0x750 || metadataSize > desc.length)
    throw new WorksetError(`invalid signer metadata_size ${metadataSize} in ${elf.path}`);
  const dirsOffset = 8 + 8 + 24 + 8 + 16 + 1808;
  if (dirsOffset + 32 > metadataSize) throw new WorksetError("SGX metadata directory table exceeds metadata_size");
  const directories = [0, 1, 2, 3].map((i) => [desc.readUInt32LE(dirsOffset + i * 8), desc.readUInt32LE(dirsOffset + i * 8 + 4)]);
  const [layoutOffset, layoutSize] = directories[DIR_LAYOUT];
  if (layoutSize === 0 || layoutSize % 32 || layoutOffset + layoutSize > metadataSize)
    throw new WorksetError(`invalid DIR_LAYOUT offset=${layoutOffset} size=${layoutSize}`);
  const entries: Record<string, unknown>[] = [];
  for (let offset = layoutOffset; offset < layoutOffset + layoutSize; offset += 32) {
    const entryId = desc.readUInt16LE(offset);
    if (entryId & GROUP_FLAG) {
      const groupId = desc.readUInt16LE(offset), entryCount = desc.readUInt16LE(offset + 2);
      const loadTimes = desc.readUInt32LE(offset + 4), loadStep = Number(desc.readBigUInt64LE(offset + 8));
      if (entryCount > entries.length)
        throw new WorksetError(`layout group at 0x${offset.toString(16)} exceeds prior entry table`);
      const template = entryCount ? entries.slice(-entryCount) : [];
      for (let rep = 1; rep <= loadTimes; rep++) {
        for (const prior of template) {
          const clone = { ...(prior as Record<string, unknown>) };
          clone.rva = (prior.rva as number) + loadStep * rep;
          clone.name = `${prior.name}_group_${rep}`;
          clone.group_id = groupId;
          entries.push(clone);
        }
      }
      continue;
    }
    const identity = desc.readUInt16LE(offset), attributes = desc.readUInt16LE(offset + 2);
    const pages = desc.readUInt32LE(offset + 4), rva = Number(desc.readBigUInt64LE(offset + 8));
    const contentSize = desc.readUInt32LE(offset + 16), contentOffset = desc.readUInt32LE(offset + 20);
    const siFlags = Number(desc.readBigUInt64LE(offset + 24));
    entries.push({ id: identity, name: LAYOUT_NAMES[identity] ?? `LAYOUT_${identity}`, attributes, pages, rva, content_size: contentSize, content_offset: contentOffset, si_flags: siFlags });
  }
  return { version: Number(version), metadata_size: metadataSize, ssa_frame_pages: ssaFramePages, enclave_size: enclaveSize, attributes_flags: attributesFlags, attributes_xfrm: attributesXfrm, layout_entries: entries };
}

export function signerPatchPayloads(signed: ElfFile): Array<[number, Buffer]> {
  const desc = signed.noteDescriptor();
  const metadataSize = desc.readUInt32LE(16);
  if (metadataSize < 0x750 || metadataSize > desc.length)
    throw new WorksetError(`invalid signer metadata_size ${metadataSize} in ${signed.path}`);
  const dirsOffset = 8 + 8 + 24 + 8 + 16 + 1808;
  const patchOffset = desc.readUInt32LE(dirsOffset), patchSize = desc.readUInt32LE(dirsOffset + 4);
  if (patchSize === 0 || patchSize % 32 || patchOffset + patchSize > metadataSize)
    throw new WorksetError(`invalid DIR_PATCH offset=${patchOffset} size=${patchSize} in ${signed.path}`);
  const patches: Array<[number, Buffer]> = [];
  const spans: Array<[number, number]> = [];
  for (let offset = patchOffset; offset < patchOffset + patchSize; offset += 32) {
    const destination = Number(desc.readBigUInt64LE(offset));
    const source = desc.readUInt32LE(offset + 8), size = desc.readUInt32LE(offset + 12);
    if (size === 0 || source + size > metadataSize)
      throw new WorksetError(`invalid DIR_PATCH entry dst=0x${destination.toString(16)} src=${source} size=${size}`);
    if (spans.some(([b, e]) => Math.max(destination, b) < Math.min(destination + size, e)))
      throw new WorksetError("overlapping DIR_PATCH destinations are unsupported");
    spans.push([destination, destination + size]);
    patches.push([destination, desc.subarray(source, source + size)]);
  }
  return patches;
}

export function patchedLoadMemory(elf: ElfFile, patches: Array<[number, Buffer]>): Buffer[] {
  const memories = elf.loads.map((s) => {
    const raw = elf.data.subarray(s.offset, s.offset + s.filesz);
    return Buffer.concat([raw, Buffer.alloc(s.memsz - s.filesz)]);
  });
  for (const [destination, payload] of patches) {
    const matches: Array<[number, number]> = [];
    for (let index = 0; index < elf.loads.length; index++) {
      const s = elf.loads[index];
      if (s.vaddr <= destination && destination + payload.length <= s.vaddr + s.memsz)
        matches.push([index, destination - s.vaddr]);
    }
    if (matches.length !== 1)
      throw new WorksetError(`DIR_PATCH destination 0x${destination.toString(16)}+0x${payload.length.toString(16)} maps to ${matches.length} PT_LOAD ranges`);
    const [index, offset] = matches[0];
    payload.copy(memories[index], offset);
  }
  return memories;
}

export function elfLoadEquivalence(profile: ElfFile, signed: ElfFile): void {
  const identity = (e: ElfFile) => e.loads.map((s) => [s.vaddr, s.filesz, s.memsz, s.flags, s.align].join(","));
  if (identity(profile).join("|") !== identity(signed).join("|"))
    throw new WorksetError("Profile ELF and signed ELF PT_LOAD layout differs; use the matching signer output");
  const relroId = (e: ElfFile) => e.relro.map((s) => [s.offset, s.vaddr, s.filesz, s.memsz, s.flags, s.align].join(","));
  if (relroId(profile).join("|") !== relroId(signed).join("|"))
    throw new WorksetError("Profile ELF and signed ELF PT_GNU_RELRO layout differs; use the matching signer output");
  const patches = signerPatchPayloads(signed);
  const profileMemory = patchedLoadMemory(profile, patches);
  const signedMemory = patchedLoadMemory(signed, patches);
  for (let i = 0; i < profile.loads.length; i++) {
    if (!profileMemory[i].equals(signedMemory[i])) {
      const off = profileMemory[i].findIndex((b, j) => b !== signedMemory[i][j]);
      throw new WorksetError(`Profile and signed ELF loaded bytes differ after DIR_PATCH at RVA 0x${(profile.loads[i].vaddr + off).toString(16)}`);
    }
  }
}

export function locatePretouchSegment(elf: ElfFile, capacityQ: number): [ElfSection | null, ElfSegment | null] {
  const sections = elf.byName.get(".atfield_pretouch") ?? [];
  if (sections.length > 1) throw new WorksetError("multiple .atfield_pretouch sections");
  if (!sections.length) return [null, null];
  const section = sections[0];
  if (section.type !== 1 || (section.flags & (SHF_ALLOC | SHF_EXECINSTR)) !== (SHF_ALLOC | SHF_EXECINSTR) || section.flags & SHF_WRITE)
    throw new WorksetError(".atfield_pretouch must be allocated, executable and read-only");
  const owners = elf.loads.filter((s) => s.vaddr <= section.addr && section.addr + section.size <= s.vaddr + s.memsz);
  if (owners.length !== 1) throw new WorksetError(".atfield_pretouch must belong to exactly one PT_LOAD");
  const segment = owners[0];
  if (segment.flags !== (PF_R | PF_X) || segment.vaddr % PAGE || segment.align < PAGE || segment.filesz !== segment.memsz)
    throw new WorksetError("post PT_LOAD must be page-aligned RX with p_filesz == p_memsz");
  if (capacityQ && segment.memsz !== capacityQ)
    throw new WorksetError(`signed .atfield_pretouch size ${segment.memsz} differs from configured Q=${capacityQ}`);
  if (segment.vaddr !== alignUp(Math.max(...elf.loads.filter((s) => s !== segment).map((s) => s.vaddr + s.memsz))))
    throw new WorksetError(".atfield_pretouch is not immediately after ordinary PT_LOAD memory");
  if (segment !== elf.loads.reduce((a, b) => (a.vaddr > b.vaddr ? a : b)))
    throw new WorksetError(".atfield_pretouch PT_LOAD is not the last load segment");
  if (section.addr !== segment.vaddr || section.size !== segment.memsz)
    throw new WorksetError(".atfield_pretouch output section must fill its dedicated PT_LOAD");
  return [section, segment];
}

export function signerRegions(metadata: Record<string, unknown>): [Record<string, unknown>[], Record<string, unknown>[]] {
  const included: Record<string, unknown>[] = [], excluded: Record<string, unknown>[] = [];
  for (const entry of metadata.layout_entries as Record<string, unknown>[]) {
    const identity = entry.id as number, name = entry.name as string;
    const start = entry.rva as number, pages = entry.pages as number;
    const end = start + pages * PAGE;
    if (pages === 0) continue;
    if (start % PAGE || end > (metadata.enclave_size as number))
      throw new WorksetError(`signer region ${name} has invalid page range [0x${start.toString(16)},0x${end.toString(16)})`);
    const pageType = (entry.si_flags as number) & SI_FLAG_PT_MASK;
    const perms = (entry.si_flags as number) & 7;
    const region: Record<string, unknown> = { kind: "signer", name, start_rva: start, end_rva: end, pages, permissions: perms, si_flags: entry.si_flags, attributes: entry.attributes, layout_id: identity };
    if (SPECIAL_IDS.has(identity) || pageType === SI_FLAG_TCS) {
      region.excluded_reason = "TCS/SSA/guard control region";
      excluded.push(region);
    } else if (pageType !== SI_FLAG_REG) {
      region.excluded_reason = `non-REG SGX page type 0x${pageType.toString(16)}`;
      excluded.push(region);
    } else if (!((entry.attributes as number) & PAGE_ATTR_EADD)) {
      region.excluded_reason = "signer layout does not EADD this reserved page range";
      excluded.push(region);
    } else {
      if (!perms) throw new WorksetError(`committed REG region ${name} has no R/W/X permission`);
      included.push(region);
    }
  }
  return [included, excluded];
}

export function effectsForPermissions(perms: number, label: string): string[] {
  const effects: string[] = [];
  if (perms & SI_FLAG_X) effects.push("X");
  if (perms & SI_FLAG_R) effects.push("R");
  if (perms & SI_FLAG_W) effects.push("W");
  if (!effects.length) throw new WorksetError(`REG page has no usable permission: ${label}`);
  if (effects.includes("X") && effects.includes("W"))
    throw new WorksetError(`REG page is both executable and writable: ${label}`);
  if (effects.includes("W") && !effects.includes("R"))
    throw new WorksetError(`W template requires a readable/writable REG page: ${label}`);
  return effects;
}

const sha256Hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");

export function makeLayout(profile: ElfFile, signed: ElfFile, capacityQ: number): Record<string, unknown> {
  elfLoadEquivalence(profile, signed);
  const metadata = parseSignedMetadata(signed);
  const [pretouchSection, pretouchSegment] = locatePretouchSegment(profile, capacityQ);
  if (pretouchSection) {
    const signedPosts = signed.loads.filter(
      (s) => s.vaddr === pretouchSegment!.vaddr && s.filesz === pretouchSegment!.filesz &&
             s.memsz === pretouchSegment!.memsz && s.flags === pretouchSegment!.flags && s.align === pretouchSegment!.align
    );
    if (signedPosts.length !== 1)
      throw new WorksetError("signed ELF does not preserve the Profile post RX PT_LOAD geometry");
  }
  const postIndex = pretouchSegment ? pretouchSegment.index : null;
  const ordinary = profile.loads.filter((s) => s.index !== postIndex);
  if (!ordinary.length) throw new WorksetError("no ordinary PT_LOAD segments");
  const ordinaryLoadEnd = Math.max(...ordinary.map((s) => s.vaddr + s.memsz));
  const expectedPostStart = alignUp(ordinaryLoadEnd);
  if (pretouchSegment && pretouchSegment.vaddr !== expectedPostStart)
    throw new WorksetError("post PT_LOAD start differs from page-aligned ordinary_load_end");
  const regions: Record<string, unknown>[] = [];
  const excluded: Record<string, unknown>[] = [];
  for (const segment of ordinary) {
    if (segment.memsz === 0) continue;
    if (segment.vaddr + segment.memsz > (metadata.enclave_size as number))
      throw new WorksetError("PT_LOAD exceeds signed enclave_size");
    const start = alignDown(segment.vaddr), end = alignUp(segment.vaddr + segment.memsz);
    const perms = (segment.flags & PF_R ? SI_FLAG_R : 0) | (segment.flags & PF_W ? SI_FLAG_W : 0) | (segment.flags & PF_X ? SI_FLAG_X : 0);
    effectsForPermissions(perms, `PT_LOAD[${segment.index}]`);
    regions.push({ kind: "PT_LOAD", segment_index: segment.index, start_rva: start, end_rva: end, pages: (end - start) / PAGE, permissions: perms });
  }
  const [signer, omitted] = signerRegions(metadata);
  regions.push(...signer);
  excluded.push(...omitted);
  for (const special of omitted) {
    if (!String(special.excluded_reason ?? "").includes("TCS/SSA/guard")) continue;
    for (const region of regions) {
      if (Math.max(special.start_rva as number, region.start_rva as number) < Math.min(special.end_rva as number, region.end_rva as number))
        throw new WorksetError(`REG region ${region.name} overlaps excluded control range ${special.name}`);
    }
  }
  const ptPagePerms = new Map<number, number>();
  for (const segment of ordinary) {
    const perms = (segment.flags & PF_R ? SI_FLAG_R : 0) | (segment.flags & PF_W ? SI_FLAG_W : 0) | (segment.flags & PF_X ? SI_FLAG_X : 0);
    for (let page = alignDown(segment.vaddr); page < alignUp(segment.vaddr + segment.memsz); page += PAGE)
      ptPagePerms.set(page, (ptPagePerms.get(page) ?? 0) | perms);
  }
  const relroRanges: Record<string, unknown>[] = [];
  const relroPages = new Set<number>();
  for (const relro of profile.relro) {
    const protectedStart = alignDown(relro.vaddr);
    const protectedEnd = alignDown(relro.end!);
    if (protectedEnd > protectedStart) {
      for (let page = protectedStart; page < protectedEnd; page += PAGE) {
        const maxPerms = ptPagePerms.get(page) ?? 0;
        if ((maxPerms & (SI_FLAG_R | SI_FLAG_W)) !== (SI_FLAG_R | SI_FLAG_W) || maxPerms & SI_FLAG_X)
          throw new WorksetError(`PT_GNU_RELRO page 0x${page.toString(16)} is not within an R|W non-X PT_LOAD`);
        if (!regions.some((r) => (r.start_rva as number) <= page && page + PAGE <= (r.end_rva as number)))
          throw new WorksetError(`PT_GNU_RELRO page 0x${page.toString(16)} is absent from committed signer REG layout`);
        relroPages.add(page);
      }
    }
    relroRanges.push({ segment_index: relro.index, start_rva: relro.vaddr, end_rva: relro.end, protected_start_rva: protectedStart, protected_end_rva: protectedEnd });
  }
  const committedRegPages = new Set<number>();
  for (const region of regions) {
    for (let page = region.start_rva as number; page < (region.end_rva as number); page += PAGE) {
      if (!pretouchSegment || !(pretouchSegment.vaddr <= page && page < pretouchSegment.vaddr + pretouchSegment.memsz))
        committedRegPages.add(page);
    }
  }
  return {
    schema: "atfield-signer-layout-v1", page_size: PAGE,
    signed_elf: String(signed.path), signed_elf_sha256: sha256Hex(signed.data),
    profile_elf: String(profile.path), profile_elf_sha256: sha256Hex(profile.data),
    metadata_version: metadata.version, enclave_size: metadata.enclave_size,
    ssa_frame_pages: metadata.ssa_frame_pages,
    ordinary_load_end: ordinaryLoadEnd, pretouch_start: expectedPostStart,
    capacity_q: capacityQ, pretouch_segment: Boolean(pretouchSegment),
    regions, excluded_regions: excluded,
    relro_ranges: relroRanges, relro_pages: [...relroPages].sort((a, b) => a - b),
    all_committed_reg_pages: committedRegPages.size,
  };
}

const ANCHOR_RE = /^__atf_[cn]_[0-9a-f]+_[0-9a-f]+_[0-9a-f]+$/;
export function parseAnchorSymbols(profile: ElfFile): Map<number, Array<Record<string, unknown>>> {
  const anchors = new Map<number, Array<Record<string, unknown>>>();
  for (const symbol of profile.symbols()) {
    if (!ANCHOR_RE.test(symbol.name)) continue;
    const address = symbol.value;
    let offset: number;
    try { offset = profile.loadedOffset(address); } catch { continue; }
    if (profile.data[offset] !== 0xc3) continue;
    const containing = profile.loads.filter((s) => s.vaddr <= address && address < s.vaddr + s.memsz && s.flags & PF_X);
    if (containing.length !== 1) continue;
    const page = alignDown(address);
    const l = anchors.get(page) ?? [];
    l.push({ symbol: symbol.name, rva: address });
    anchors.set(page, l);
  }
  for (const values of anchors.values())
    values.sort((a, b) => (a.rva as number) - (b.rva as number) || String(a.symbol).localeCompare(String(b.symbol)));
  return anchors;
}

export function normalizedFields(fieldsFile: string): Array<Record<string, unknown>> {
  const payload = readJson(fieldsFile);
  if (payload.schema !== "atfield-fields-v1" || !Array.isArray(payload.fields))
    throw new WorksetError(`expected atfield-fields-v1 manifest: ${fieldsFile}`);
  const seen = new Set<bigint>();
  const result: Array<Record<string, unknown>> = [];
  for (const item of payload.fields as Record<string, unknown>[]) {
    if (item === null || typeof item !== "object" || Array.isArray(item))
      throw new WorksetError("each field manifest entry must be an object");
    const identity = parseU64(item.id, "Field id");
    if (identity === 0n || seen.has(identity))
      throw new WorksetError(`zero or duplicate Field id: ${JSON.stringify(item.id)}`);
    seen.add(identity);
    const order = item.order;
    if (!Array.isArray(order) || order.length !== 2)
      throw new WorksetError(`Field ${item.name} requires a two-element order key`);
    const normalized = { ...item };
    normalized._id_value = identity;
    normalized.id = `0x${identity.toString(16).padStart(16, "0")}`;
    normalized.order = [parseU64(order[0], "payloadOrdinal"), parseU64(order[1], "functionOrdinal")];
    result.push(normalized);
  }
  result.sort((a, b) => {
    const [a0, a1] = a.order as [bigint, bigint], [b0, b1] = b.order as [bigint, bigint];
    if (a0 !== b0) return a0 < b0 ? -1 : 1;
    if (a1 !== b1) return a1 < b1 ? -1 : 1;
    const ai = a._id_value as bigint, bi = b._id_value as bigint;
    return ai < bi ? -1 : ai > bi ? 1 : 0;
  });
  return result;
}

export function edlPublicEcalls(edlFile: string): string[] {
  let source: string;
  try { source = readFileSync(edlFile, "utf-8"); }
  catch (exc) { throw new WorksetError(`cannot read EDL ${edlFile}: ${exc}`); }
  source = source.replace(/\/\*.*?\*\//gs, "");
  source = source.replace(/\/\/[^\n]*/g, "");
  source = source.replace(/^\s*#.*$/gm, "");
  const trustedBlocks = [...source.matchAll(/\btrusted\s*\{/g)];
  if (trustedBlocks.length !== 1)
    throw new WorksetError(`EDL ${edlFile} must have exactly one simple trusted block; found ${trustedBlocks.length}`);
  const opening = trustedBlocks[0].index! + trustedBlocks[0][0].length - 1;
  let depth = 0, closing: number | null = null;
  for (let pos = opening; pos < source.length; pos++) {
    if (source[pos] === "{") depth++;
    else if (source[pos] === "}") {
      depth--;
      if (depth === 0) { closing = pos; break; }
    }
  }
  if (closing === null) throw new WorksetError(`EDL ${edlFile} has an unterminated trusted block`);
  const body = source.slice(opening + 1, closing);
  if (/\bfrom\b|\bimport\b/.test(body))
    throw new WorksetError(`EDL ${edlFile} has an import inside trusted; imported ECALL order is unsupported`);
  const outside = source.slice(0, opening) + source.slice(closing + 1);
  const importRe = /\bfrom\s+"([^"]+)"\s+import\s+([^;]+);/gs;
  const imports = [...outside.matchAll(importRe)];
  const residual = outside.replace(importRe, "");
  if (/\bfrom\b|\bimport\b/.test(residual))
    throw new WorksetError(`EDL ${edlFile} uses an unsupported import form; pass a simple EDL or generated _u.c mapping`);
  for (const imported of imports) {
    const sourceEdl = path.basename(imported[1]);
    if (!["sgx_tsgxssl.edl", "sgx_tstdc.edl"].includes(sourceEdl))
      throw new WorksetError(`EDL ${edlFile} imports ${sourceEdl}, whose ECALL-selector effect is not verified`);
  }
  const names: string[] = [];
  for (const match of body.matchAll(/\bpublic\b/g)) {
    const end = body.indexOf(";", match.index! + match[0].length);
    if (end < 0) throw new WorksetError(`EDL ${edlFile} has an unterminated public declaration`);
    const declaration = body.slice(match.index! + match[0].length, end).trim();
    const header = declaration.split("(", 1)[0];
    const name = /([A-Za-z_][A-Za-z_0-9]*)\s*$/.exec(header);
    if (!declaration.includes("(") || !name)
      throw new WorksetError(`EDL ${edlFile} has a complex public declaration near ${JSON.stringify(declaration.slice(0, 100))}`);
    names.push(name[1]);
  }
  if (!names.length) throw new WorksetError(`EDL ${edlFile} contains no public ECALL declarations`);
  if (names.length !== new Set(names).size) throw new WorksetError(`EDL ${edlFile} repeats a public ECALL name`);
  return names;
}

function readableFieldNames(field: Record<string, unknown>): Set<string> {
  const values = [field.name, field.demangled_name];
  const result = new Set<string>();
  for (const v of values) if (typeof v === "string" && v.trim()) result.add(v.trim());
  for (const value of [...result]) {
    const base = value.split("(", 1)[0].trim().split("::").pop()!.trim();
    if (base) result.add(base);
  }
  return result;
}

function resolveFieldFunction(fn: string, fields: Array<Record<string, unknown>>, selectorIndex: number): Record<string, unknown> {
  let exact = fields.filter((f) => fn === f.function || fn === f.linkage_name);
  exact = [...new Map(exact.map((f) => [f.id, f])).values()];
  if (exact.length === 1) return exact[0];
  if (exact.length > 1) throw new WorksetError(`selector ${selectorIndex} linkage symbol ${JSON.stringify(fn)} resolves to multiple Fields`);
  let readable = fields.filter((f) => readableFieldNames(f).has(fn));
  readable = [...new Map(readable.map((f) => [f.id, f])).values()];
  if (readable.length === 1) return readable[0];
  if (readable.length > 1) {
    const names = readable.map((f) => String(f.linkage_name ?? f.function ?? f.id)).join(", ");
    throw new WorksetError(`selector ${selectorIndex} readable function ${JSON.stringify(fn)} is ambiguous (${names}); use an exact linkage_name`);
  }
  throw new WorksetError(`selector ${selectorIndex} references unknown Field function/linkage ${JSON.stringify(fn)}`);
}

export function resolveSelectors(
  selectorFile: string | null,
  fields: Array<Record<string, unknown>>,
  edlFile: string | null,
): Array<Record<string, unknown>> {
  if (selectorFile === null) {
    if (edlFile !== null) throw new WorksetError("--edl requires --selectors so every public selector can be mapped");
    return [];
  }
  if (edlFile === null) throw new WorksetError("--selectors requires --edl to verify ECALL names and public order");
  const payload = readJson(selectorFile);
  if (payload.schema !== "atfield-selectors-v1" || !Array.isArray(payload.selectors))
    throw new WorksetError(`expected atfield-selectors-v1 manifest: ${selectorFile}`);
  const policy = payload.policy;
  if ("policy" in payload && policy !== "conservative-all-fields")
    throw new WorksetError(`unsupported selector policy ${JSON.stringify(policy)}: ${selectorFile}`);
  const conservativeAllFields = policy === "conservative-all-fields";
  const expectedNames = edlPublicEcalls(edlFile);
  const supplied = payload.selectors as Array<Record<string, unknown>>;
  if (supplied.length !== expectedNames.length)
    throw new WorksetError(`selector map has ${supplied.length} entries, EDL declares ${expectedNames.length} public ECALLs`);
  const expectedFieldIds: bigint[] = [];
  const canonicalFieldIds = new Map<bigint, string>();
  if (conservativeAllFields) {
    for (const field of fields) {
      const identity = parseU64(field.id, "Field id");
      if (identity === 0n || canonicalFieldIds.has(identity))
        throw new WorksetError(`zero or duplicate Field id in conservative-all-fields input: ${JSON.stringify(field.id)}`);
      expectedFieldIds.push(identity);
      canonicalFieldIds.set(identity, String(field.id));
    }
  }
  const resolved: Array<Record<string, unknown>> = [];
  for (let expectedIndex = 0; expectedIndex < supplied.length; expectedIndex++) {
    const selector = supplied[expectedIndex], expectedName = expectedNames[expectedIndex];
    if (selector === null || typeof selector !== "object" || Array.isArray(selector))
      throw new WorksetError("each selector entry must be an object");
    const index = parseU64(selector.ecall_index, "ecall_index");
    if (index !== BigInt(expectedIndex))
      throw new WorksetError(`selector index ${index} is out of EDL order; expected ${expectedIndex}`);
    const name = selector.name;
    if (name !== expectedName)
      throw new WorksetError(`selector ${index} name ${JSON.stringify(name)} differs from EDL public ECALL ${JSON.stringify(expectedName)}`);
    if (conservativeAllFields) {
      const keySet = new Set(Object.keys(selector));
      if (keySet.size !== 3 || !["ecall_index", "name", "reachable_fields"].every((k) => keySet.has(k)))
        throw new WorksetError(`selector ${index} under conservative-all-fields must contain only ecall_index, name, and reachable_fields`);
      const suppliedIds = selector.reachable_fields;
      if (!Array.isArray(suppliedIds))
        throw new WorksetError(`selector ${index} requires reachable_fields under conservative-all-fields`);
      const seenIds = new Set<bigint>();
      for (const fieldId of suppliedIds) {
        if (typeof fieldId !== "string" || !fieldId)
          throw new WorksetError(`selector ${index} reachable_fields entries must be nonempty Field ID strings`);
        const identity = parseU64(fieldId, "reachable Field ID");
        if (!canonicalFieldIds.has(identity))
          throw new WorksetError(`selector ${index} references unknown Field ID ${JSON.stringify(fieldId)}`);
        if (seenIds.has(identity))
          throw new WorksetError(`selector ${index} repeats reachable Field ID ${JSON.stringify(fieldId)}`);
        seenIds.add(identity);
      }
      if (seenIds.size !== expectedFieldIds.length || !expectedFieldIds.every((v) => seenIds.has(v))) {
        const missing = expectedFieldIds.filter((v) => !seenIds.has(v)).map((v) => canonicalFieldIds.get(v));
        throw new WorksetError(`selector ${index} conservative-all-fields must include every fields.json ID exactly once; missing ${JSON.stringify(missing)}`);
      }
      resolved.push({ ecall_index: Number(index), name, reachable_fields: expectedFieldIds.map((v) => canonicalFieldIds.get(v)), policy });
      continue;
    }
    const functions = selector.reachable_functions;
    if (!Array.isArray(functions))
      throw new WorksetError(`selector ${index} requires reachable_functions`);
    const ids: string[] = [];
    for (const fn of functions) {
      if (typeof fn !== "string" || !fn)
        throw new WorksetError(`selector ${index} reachable_functions entries must be nonempty strings`);
      ids.push(resolveFieldFunction(fn, fields, expectedIndex).id as string);
    }
    if (new Set(ids).size !== ids.length)
      throw new WorksetError(`selector ${index} repeats a reachable function/Field`);
    resolved.push({ ecall_index: Number(index), name, reachable_functions: functions, reachable_fields: ids });
  }
  return resolved;
}

export function produceWorkset(
  profile: ElfFile,
  layout: Record<string, unknown>,
  fieldsFile: string,
  selectorsFile: string | null,
  edlFile: string | null,
): Record<string, unknown> {
  const anchors = parseAnchorSymbols(profile);
  const pagePerms = new Map<number, number>();
  const pageOrigins = new Map<number, string[]>();
  const postStart = layout.pretouch_start as number;
  const postEnd = layout.pretouch_segment ? postStart + ((layout.capacity_q as number) ?? 0) : null;
  for (const region of layout.regions as Array<Record<string, unknown>>) {
    for (let page = region.start_rva as number; page < (region.end_rva as number); page += PAGE) {
      if (postEnd !== null && postStart <= page && page < postEnd) continue;
      pagePerms.set(page, (pagePerms.get(page) ?? 0) | (region.permissions as number));
      const l = pageOrigins.get(page) ?? [];
      l.push(region.kind === "signer" ? (region.name as string) : `PT_LOAD[${region.segment_index}]`);
      pageOrigins.set(page, l);
    }
  }
  if (!pagePerms.size) throw new WorksetError("signed layout produced no committed business REG pages");
  const pageRecords: Array<Record<string, unknown>> = [];
  const relroPages = new Set((layout.relro_pages as number[]) ?? []);
  for (const page of [...pagePerms.keys()].sort((a, b) => a - b)) {
    const maxPermissions = pagePerms.get(page)!;
    let permissions = maxPermissions;
    if (relroPages.has(page)) {
      if ((permissions & (SI_FLAG_R | SI_FLAG_W)) !== (SI_FLAG_R | SI_FLAG_W) || permissions & SI_FLAG_X)
        throw new WorksetError(`RELRO page 0x${page.toString(16)} lacks max R|W non-X permissions`);
      permissions &= ~SI_FLAG_W;
    }
    const effects = effectsForPermissions(permissions, `page 0x${page.toString(16)}`);
    const record: Record<string, unknown> = {
      page_rva: page, effects, active_permissions: permissions,
      max_permissions: maxPermissions, relro: relroPages.has(page),
      origins: [...new Set(pageOrigins.get(page))].sort(),
    };
    if (effects.includes("X")) {
      const choices = anchors.get(page) ?? [];
      if (!choices.length) throw new WorksetError(`X page 0x${page.toString(16)} lacks a final same-page C3 anchor symbol`);
      record.code_anchor = choices[0];
    }
    if (effects.includes("R") || effects.includes("W")) {
      record.data_anchor_rva = page;
      record.data_width = 1;
    }
    pageRecords.push(record);
  }
  const fields = normalizedFields(fieldsFile);
  if (!fields.length) throw new WorksetError("fields.json contains no Field entries");
  const selectors = resolveSelectors(selectorsFile, fields, edlFile);
  return {
    schema: "atfield-workset-v1", page_size: PAGE,
    layout, field_manifest: fieldsFile,
    field_manifest_sha256: sha256Hex(readFileSync(fieldsFile)),
    selector_manifest: selectorsFile ?? null,
    selector_manifest_sha256: selectorsFile ? sha256Hex(readFileSync(selectorsFile)) : null,
    edl_manifest: edlFile ?? null,
    edl_manifest_sha256: edlFile ? sha256Hex(readFileSync(edlFile)) : null,
    selectors,
    fields: fields.map((field) => ({
      id: field.id, name: field.name ?? field.function ?? field.id,
      function: field.function, order: field.order,
      stack_bytes: field.stack_bytes, pages: pageRecords,
    })),
  };
}
