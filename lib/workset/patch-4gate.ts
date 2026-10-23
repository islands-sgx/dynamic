// lib/workset/patch-4gate.ts
// Create layout-identical 4-gate diagnostic enclave ELF from a ProfileElf or
// FinalElf. Per-Field Gate A/B/C/D trampolines go in the last page
// (gate_helper_rva = post_start + capacity_q - 0x1000) of .atfield_pretouch
// without changing any PT_LOAD header, section size, or business symbol RVA.
// TypeScript implementation of the four-gate ELF layout patcher.

import { chmodSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { ElfFile, WorksetError, locatePretouchSegment, normalizedFields, writeJson, PAGE } from "./elf.ts";

const GATE_SHARED_VA = 0x700000000000n;
const SCRATCH_RAX_VA = 0x700000000100n;

function rel32(opcode: number, srcRva: number, dstRva: number): Buffer {
  const delta = dstRva - (srcRva + 5);
  if (delta < -2147483648 || delta >= 2147483648)
    throw new WorksetError(`rel32 out of range: 0x${srcRva.toString(16)} -> 0x${dstRva.toString(16)}`);
  const b = Buffer.alloc(5);
  b[0] = opcode;
  b.writeInt32LE(delta, 1);
  return b;
}

function emitSaveRegs(stageCode = 0): Buffer {
  const out: number[] = [];
  out.push(0x48, 0xa3);
  const q1 = Buffer.alloc(8); q1.writeBigUInt64LE(SCRATCH_RAX_VA);
  const q2 = Buffer.alloc(8); q2.writeBigUInt64LE(GATE_SHARED_VA);
  const u = Buffer.alloc(4); u.writeUInt32LE(stageCode);
  return Buffer.concat([
    Buffer.from(out), q1,
    Buffer.from([0x48, 0xb8]), q2,
    Buffer.from([0x48, 0x89, 0x88, 0x08, 0x01, 0x00, 0x00]),
    Buffer.from([0x48, 0x89, 0x90, 0x10, 0x01, 0x00, 0x00]),
    Buffer.from([0x48, 0x89, 0xc1]),
    Buffer.from([0x9f, 0x0f, 0x90, 0xc0]),
    Buffer.from([0x66, 0x89, 0x81, 0x18, 0x01, 0x00, 0x00]),
    Buffer.from([0x48, 0x89, 0xc8]),
    Buffer.from([0xc7, 0x40, 0x50]), u,
  ]);
}

function emitRestoreRegs(nextStageCode = 0): Buffer {
  const u = Buffer.alloc(4); u.writeUInt32LE(nextStageCode);
  const q = Buffer.alloc(8); q.writeBigUInt64LE(SCRATCH_RAX_VA);
  return Buffer.concat([
    Buffer.from([0xc7, 0x40, 0x50]), u,
    Buffer.from([0x48, 0x8b, 0x88, 0x08, 0x01, 0x00, 0x00]),
    Buffer.from([0x48, 0x8b, 0x90, 0x10, 0x01, 0x00, 0x00]),
    Buffer.from([0x66, 0x8b, 0x80, 0x18, 0x01, 0x00, 0x00]),
    Buffer.from([0x04, 0x7f, 0x9e]),
    Buffer.from([0x48, 0xa1]), q,
  ]);
}

function emitRdtscToOffset(disp8: number): Buffer {
  return Buffer.concat([
    Buffer.from([0x48, 0x89, 0xc1]),
    Buffer.from([0x0f, 0x31]),
    Buffer.from([0x48, 0xc1, 0xe2, 0x20]),
    Buffer.from([0x48, 0x09, 0xd0]),
    Buffer.from([0x48, 0x89, 0x41, disp8]),
    Buffer.from([0x48, 0x89, 0xc8]),
  ]);
}

function emitGateSpin(reqVal: number, ackVal: number): Buffer {
  const u = Buffer.alloc(4); u.writeUInt32LE(reqVal);
  return Buffer.concat([
    Buffer.from([0x0f, 0xae, 0xf0, 0x0f, 0xae, 0xe8]),
    Buffer.from([0xc7, 0x00]), u,
    Buffer.from([0xff, 0x40, 0x18]),
    Buffer.from([0x8b, 0x08]),
    Buffer.from([0x83, 0xf9, ackVal]),
    Buffer.from([0x74, 0x04]),
    Buffer.from([0xf3, 0x90]),
    Buffer.from([0xeb, 0xf2]),
    Buffer.from([0x0f, 0xae, 0xf0, 0x0f, 0xae, 0xe8]),
  ]);
}

export interface Patch4GateSummary {
  schema: string; input_elf: string; input_elf_sha256: string;
  output_elf: string; output_elf_sha256: string;
  gate_helper_page_rva: number; gate_bytes_used: number;
  fields: Array<Record<string, unknown>>;
  [k: string]: unknown;
}

export function patchElf4gate(
  inputElfPath: string,
  fieldsPath: string,
  capacityQ: number,
  outputElfPath: string,
  outputJsonPath: string,
): Patch4GateSummary {
  const elf = new ElfFile(inputElfPath);
  const [postSec, postSeg] = locatePretouchSegment(elf, capacityQ);
  if (!postSec || !postSeg) throw new WorksetError(`missing .atfield_pretouch in ${inputElfPath}`);

  const syms = new Map<string, number>();
  const symSize = new Map<string, number>();
  for (const s of elf.symbols()) {
    if (s.shndx === 0) continue;
    if (!syms.has(s.name)) { syms.set(s.name, s.value); symSize.set(s.name, s.size); }
  }
  // Python dict comp {s["name"]: s["value"]} keeps LAST occurrence per name;
  // symbols_named lookups below use first-defined for single names — replicate
  // Python exactly: build dict with last wins, and size via the same list scan.
  syms.clear();
  for (const s of elf.symbols()) if (s.shndx !== 0) syms.set(s.name, s.value);
  const fieldEnterRva = syms.get("field_enter")!;
  const fieldExitRva = syms.get("field_exit")!;
  const fields = normalizedFields(fieldsPath);

  const gatePageRva = postSec.addr + capacityQ - PAGE;
  const gatePageOff = postSec.offset + capacityQ - PAGE;

  const updated = Buffer.from(elf.data);
  const gateBufs: Buffer[] = [];
  const gateBufLen = () => gateBufs.reduce((a, b) => a + b.length, 0);
  const fieldGateInfo: Array<Record<string, unknown>> = [];

  for (let idx = 0; idx < fields.length; idx++) {
    const field = fields[idx];
    const fidStr = field.id as string;
    const contRva = syms.get(field.continuation_symbol as string)!;
    const markerRva = contRva - 5;
    const pretouchSym = field.pretouch_symbol as string;
    const pretouchRva = syms.get(pretouchSym)!;
    const pretouchSize = elf.symbols().find((s) => s.name === pretouchSym && s.shndx !== 0)!.size;
    if (pretouchRva + pretouchSize > gatePageRva)
      throw new WorksetError(`pretouch block for ${fidStr} overlaps gate helper page 0x${gatePageRva.toString(16)}`);

    const enterLbl = syms.get(field.field_enter_symbol as string)!;
    const exitLbl = syms.get(field.field_exit_symbol as string)!;

    let enterCallRva: number | null = null;
    for (let rva = enterLbl; rva < markerRva; rva++) {
      const off = elf.loadedOffset(rva, 5);
      if (updated[off] === 0xe8 && rva + 5 + updated.readInt32LE(off + 1) === fieldEnterRva) { enterCallRva = rva; break; }
    }
    if (enterCallRva === null) throw new WorksetError(`cannot find callq field_enter for ${fidStr}`);

    let exitCallRva: number | null = null;
    for (let rva = exitLbl; rva < exitLbl + 32; rva++) {
      const off = elf.loadedOffset(rva, 5);
      if (updated[off] === 0xe8 && rva + 5 + updated.readInt32LE(off + 1) === fieldExitRva) { exitCallRva = rva; break; }
    }
    if (exitCallRva === null) throw new WorksetError(`cannot find callq field_exit for ${fidStr}`);

    const pretouchJmpRva = pretouchRva + pretouchSize - 5;
    const pretouchJmpOff = elf.loadedOffset(pretouchJmpRva, 5);
    if (updated[pretouchJmpOff] !== 0xe9)
      throw new WorksetError(`expected E9 jmp at end of ${pretouchSym} (0x${pretouchJmpRva.toString(16)})`);

    const gateARva = gatePageRva + gateBufLen();
    const stubA: Buffer[] = [];
    stubA.push(emitSaveRegs(1));
    stubA.push(Buffer.from([0x48, 0x89, 0x78, 0x20]));
    stubA.push(Buffer.from([0x48, 0x89, 0x60, 0x10]));
    const spinA = emitGateSpin(10, 20);
    stubA.push(Buffer.from([0x83, 0x78, 0x04, 0x01]));
    stubA.push(Buffer.from([0x75, spinA.length]));
    stubA.push(spinA);
    stubA.push(emitRestoreRegs(1));
    stubA.push(rel32(0xe8, gateARva + stubA.reduce((a, b) => a + b.length, 0), fieldEnterRva));
    stubA.push(rel32(0xe9, gateARva + stubA.reduce((a, b) => a + b.length, 0), enterCallRva + 5));
    gateBufs.push(...stubA);

    const gateBRva = gatePageRva + gateBufLen();
    const stubB: Buffer[] = [];
    stubB.push(emitSaveRegs(2));
    stubB.push(Buffer.from([0x48, 0x89, 0x60, 0x10]));
    const spinB = Buffer.concat([emitGateSpin(30, 40), Buffer.from([0x48, 0x83, 0x78, 0x08, 0x01, 0x75, 0x07, 0x48, 0x8d, 0xa0, 0xf0, 0x0f, 0x00, 0x00])]);
    stubB.push(Buffer.from([0x83, 0x78, 0x04, 0x01]));
    stubB.push(Buffer.from([0x75, spinB.length]));
    stubB.push(spinB);
    stubB.push(emitRdtscToOffset(0x28));
    stubB.push(emitRestoreRegs(2));
    stubB.push(rel32(0xe9, gateBRva + stubB.reduce((a, b) => a + b.length, 0), pretouchRva));
    gateBufs.push(...stubB);

    const gateCRva = gatePageRva + gateBufLen();
    const stubC: Buffer[] = [];
    stubC.push(emitSaveRegs(3));
    stubC.push(emitRdtscToOffset(0x30));
    const spinC = Buffer.concat([Buffer.from([0x48, 0x83, 0x78, 0x08, 0x01, 0x75, 0x04, 0x48, 0x8b, 0x60, 0x10]), emitGateSpin(50, 60)]);
    stubC.push(Buffer.from([0x83, 0x78, 0x04, 0x01]));
    stubC.push(Buffer.from([0x75, spinC.length]));
    stubC.push(spinC);
    stubC.push(emitRdtscToOffset(0x38));
    stubC.push(emitRestoreRegs(3));
    stubC.push(rel32(0xe9, gateCRva + stubC.reduce((a, b) => a + b.length, 0), contRva));
    gateBufs.push(...stubC);

    const gateDRva = gatePageRva + gateBufLen();
    const stubD: Buffer[] = [];
    stubD.push(rel32(0xe8, gateDRva, fieldExitRva));
    stubD.push(emitSaveRegs(4));
    stubD.push(Buffer.from([0x48, 0x89, 0x60, 0x48]));
    stubD.push(emitRdtscToOffset(0x40));
    const spinD = emitGateSpin(70, 80);
    stubD.push(Buffer.from([0x83, 0x78, 0x04, 0x01]));
    stubD.push(Buffer.from([0x75, spinD.length]));
    stubD.push(spinD);
    stubD.push(emitRestoreRegs(4));
    stubD.push(rel32(0xe9, gateDRva + stubD.reduce((a, b) => a + b.length, 0), exitCallRva + 5));
    gateBufs.push(...stubD);

    const offEnter = elf.loadedOffset(enterCallRva, 5);
    rel32(0xe9, enterCallRva, gateARva).copy(updated, offEnter);
    const offMarker = elf.loadedOffset(markerRva, 5);
    rel32(0xe9, markerRva, gateBRva).copy(updated, offMarker);
    rel32(0xe9, pretouchJmpRva, gateCRva).copy(updated, pretouchJmpOff);
    const offExit = elf.loadedOffset(exitCallRva, 5);
    rel32(0xe9, exitCallRva, gateDRva).copy(updated, offExit);

    fieldGateInfo.push({
      field_id: fidStr, function: field.function,
      enter_call_rva: enterCallRva, marker_rva: markerRva,
      pretouch_rva: pretouchRva, pretouch_jmp_rva: pretouchJmpRva,
      exit_call_rva: exitCallRva,
      gate_a_rva: gateARva, gate_b_rva: gateBRva, gate_c_rva: gateCRva, gate_d_rva: gateDRva,
    });
  }

  let gateBuf = Buffer.concat(gateBufs);
  if (gateBuf.length > PAGE) throw new WorksetError(`gate_buf size ${gateBuf.length} exceeds 1 page (${PAGE})`);
  gateBuf = Buffer.concat([gateBuf, Buffer.alloc(PAGE - gateBuf.length, 0xcc)]);
  gateBuf.copy(updated, gatePageOff);

  writeFileSync(outputElfPath, updated);
  chmodSync(outputElfPath, 0o755);
  let used = gateBuf.length;
  while (used > 0 && gateBuf[used - 1] === 0xcc) used--;
  const summary: Patch4GateSummary = {
    schema: "atfield-4gate-patch-v1",
    input_elf: String(inputElfPath),
    input_elf_sha256: createHash("sha256").update(elf.data).digest("hex"),
    output_elf: String(outputElfPath),
    output_elf_sha256: createHash("sha256").update(updated).digest("hex"),
    gate_helper_page_rva: gatePageRva,
    gate_bytes_used: used,
    fields: fieldGateInfo,
  };
  writeJson(outputJsonPath, summary);
  return summary;
}
