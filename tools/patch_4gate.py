#!/usr/bin/env python3
"""Create layout-identical 4-gate diagnostic Enclave ELF from a ProfileElf or FinalElf.

Places per-Field Gate A / Gate B / Gate C / Gate D trampolines in the last page
(gate_helper_rva = post_start + capacity_q - 0x1000) of .atfield_pretouch without
changing any PT_LOAD header, section size, or business symbol RVA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/home/meandssh/islands-sgx/dynamic/vendor/implement/build/workset")
from workset import PAGE, ElfFile, locate_pretouch_segment, normalized_fields, write_json  # noqa: E402

GATE_SHARED_VA = 0x700000000000
SCRATCH_RAX_VA = 0x700000000100


def rel32(opcode: int, src_rva: int, dst_rva: int) -> bytes:
    delta = dst_rva - (src_rva + 5)
    if not -(1 << 31) <= delta < (1 << 31):
        raise ValueError(f"rel32 out of range: {src_rva:#x} -> {dst_rva:#x}")
    return bytes([opcode]) + struct.pack("<i", delta)


def emit_save_regs(stage_code: int = 0) -> bytes:
    # NOTE: mov instructions do NOT modify arithmetic flags (CF, PF, AF, ZF, SF, OF).
    # 1. Save %rax to 0x700000000100 (48 A3 <u64>)
    # 2. Load 0x700000000000 into %rax (48 B8 <u64>)
    # 3. Save %rcx -> 0x108(%rax), %rdx -> 0x110(%rax)
    # 4. Copy %rax -> %rcx (48 89 C1)
    # 5. lahf (9F) + seto %al (0F 90 C0) -> saves SF:ZF:AF:PF:CF in %ah and OF in %al
    # 6. movw %ax, 0x118(%rcx) (66 89 81 18 01 00 00)
    # 7. Restore %rax = %rcx (48 89 C8)
    # 8. Store current stage_code into 0x50(%rax) (C7 40 50 <u32>)
    out = bytearray()
    out += b"\x48\xa3" + struct.pack("<Q", SCRATCH_RAX_VA)
    out += b"\x48\xb8" + struct.pack("<Q", GATE_SHARED_VA)
    out += b"\x48\x89\x88\x08\x01\x00\x00"
    out += b"\x48\x89\x90\x10\x01\x00\x00"
    out += b"\x48\x89\xc1"
    out += b"\x9f\x0f\x90\xc0"
    out += b"\x66\x89\x81\x18\x01\x00\x00"
    out += b"\x48\x89\xc8"
    out += b"\xc7\x40\x50" + struct.pack("<I", stage_code)
    return bytes(out)


def emit_restore_regs(next_stage_code: int = 0) -> bytes:
    # 1. Store next_stage_code into 0x50(%rax) (C7 40 50 <u32>)
    # 2. Restore %rcx from 0x108(%rax), %rdx from 0x110(%rax)
    # 3. Load saved flags word from 0x118(%rax) into %ax (66 8B 80 18 01 00 00)
    # 4. addb $0x7f, %al (04 7F) -> restores OF!
    # 5. sahf (9E) -> restores SF, ZF, AF, PF, CF!
    # 6. movabsq 0x700000000100, %rax (48 A1 <u64>) -> mov does not alter flags!
    out = bytearray()
    out += b"\xc7\x40\x50" + struct.pack("<I", next_stage_code)
    out += b"\x48\x8b\x88\x08\x01\x00\x00"
    out += b"\x48\x8b\x90\x10\x01\x00\x00"
    out += b"\x66\x8b\x80\x18\x01\x00\x00"
    out += b"\x04\x7f\x9e"
    out += b"\x48\xa1" + struct.pack("<Q", SCRATCH_RAX_VA)
    return bytes(out)


def emit_rdtsc_to_offset(disp8: int) -> bytes:
    # rdtsc                         (0F 31)
    # shlq $32, %rdx                (48 C1 E2 20)
    # orq %rdx, %rax -- wait: %rax holds GATE_SHARED_VA!
    # Instead:
    # movq %rax, %rcx               (48 89 C1) -> %rcx = GATE_SHARED_VA
    # rdtsc                         (0F 31)
    # shlq $32, %rdx                (48 C1 E2 20)
    # orq %rdx, %rax                (48 09 D0)
    # movq %rax, disp8(%rcx)        (48 89 41 <disp8>)
    # movq %rcx, %rax               (48 89 C8) -> restore %rax = GATE_SHARED_VA
    return (
        b"\x48\x89\xc1"
        b"\x0f\x31"
        b"\x48\xc1\xe2\x20"
        b"\x48\x09\xd0"
        + bytes([0x48, 0x89, 0x41, disp8])
        + b"\x48\x89\xc8"
    )


def emit_gate_spin(req_val: int, ack_val: int) -> bytes:
    # Assumes %rax == GATE_SHARED_VA
    # mfence; lfence                (0F AE F0 0F AE E8)
    # movl $req_val, (%rax)         (C7 00 <u32>)
    # loop:
    # incl 0x18(%rax)               (FF 40 18)
    # movl (%rax), %ecx             (8B 08)
    # cmpl $ack_val, %ecx           (83 F9 <u8>)
    # je done                       (74 04)
    # pause                         (F3 90)
    # jmp loop                      (EB F3)
    # done:
    # mfence; lfence                (0F AE F0 0F AE E8)
    out = bytearray()
    out += b"\x0f\xae\xf0\x0f\xae\xe8"
    out += b"\xc7\x00" + struct.pack("<I", req_val)
    # loop body is 11 bytes: FF 40 18 (3) + 8B 08 (2) + 83 F9 ack (3) + 74 04 (2) + F3 90 (2) + EB F2 (2) -> total 14 bytes
    out += b"\xff\x40\x18"
    out += b"\x8b\x08"
    out += b"\x83\xf9" + bytes([ack_val])
    out += b"\x74\x04"
    out += b"\xf3\x90"
    out += b"\xeb\xf2"
    out += b"\x0f\xae\xf0\x0f\xae\xe8"
    return bytes(out)


def patch_elf_4gate(
    input_elf_path: Path,
    fields_path: Path,
    capacity_q: int,
    output_elf_path: Path,
    output_json_path: Path,
) -> dict:
    elf = ElfFile(input_elf_path)
    post_sec, post_seg = locate_pretouch_segment(elf, capacity_q)
    if not post_sec or not post_seg:
        raise RuntimeError(f"missing .atfield_pretouch in {input_elf_path}")

    syms = {s["name"]: s["value"] for s in elf.symbols() if s["shndx"] != 0}
    field_enter_rva = syms["field_enter"]
    field_exit_rva = syms["field_exit"]
    fields = normalized_fields(fields_path)

    gate_page_rva = post_sec["addr"] + capacity_q - PAGE
    gate_page_off = post_sec["offset"] + capacity_q - PAGE

    updated = bytearray(elf.data)
    cursor_rva = gate_page_rva
    gate_buf = bytearray()
    field_gate_info = []

    for idx, field in enumerate(fields):
        fid_str = field["id"]
        cont_rva = syms[field["continuation_symbol"]]
        marker_rva = cont_rva - 5
        pretouch_sym = field["pretouch_symbol"]
        pretouch_rva = syms[pretouch_sym]
        pretouch_size = next(
            s["size"] for s in elf.symbols() if s["name"] == pretouch_sym and s["shndx"] != 0
        )
        if pretouch_rva + pretouch_size > gate_page_rva:
            raise RuntimeError(
                f"pretouch block for {fid_str} overlaps gate helper page {gate_page_rva:#x}"
            )

        enter_lbl = syms[field["field_enter_symbol"]]
        exit_lbl = syms[field["field_exit_symbol"]]

        # Locate `callq field_enter` in [enter_lbl, marker_rva)
        enter_call_rva = None
        for rva in range(enter_lbl, marker_rva):
            off = elf.loaded_offset(rva, 5)
            if updated[off] == 0xE8 and rva + 5 + struct.unpack_from("<i", updated, off + 1)[0] == field_enter_rva:
                enter_call_rva = rva
                break
        if enter_call_rva is None:
            raise RuntimeError(f"cannot find callq field_enter for {fid_str}")

        # Locate `callq field_exit` in [exit_lbl, exit_lbl + 32)
        exit_call_rva = None
        for rva in range(exit_lbl, exit_lbl + 32):
            off = elf.loaded_offset(rva, 5)
            if updated[off] == 0xE8 and rva + 5 + struct.unpack_from("<i", updated, off + 1)[0] == field_exit_rva:
                exit_call_rva = rva
                break
        if exit_call_rva is None:
            raise RuntimeError(f"cannot find callq field_exit for {fid_str}")

        # Verify trailing jmp at end of __atfield_pretouch_<id>
        pretouch_jmp_rva = pretouch_rva + pretouch_size - 5
        pretouch_jmp_off = elf.loaded_offset(pretouch_jmp_rva, 5)
        if updated[pretouch_jmp_off] != 0xE9:
            raise RuntimeError(f"expected E9 jmp at end of {pretouch_sym} ({pretouch_jmp_rva:#x})")

        # 1. Emit __gate_A_B_field_<idx>:
        #    Replaces `callq field_enter` at enter_call_rva.
        #    Note: [enter_call_rva .. marker_rva] has `callq field_enter` (5B) followed immediately
        #    (or after a mov) by `jmp __atfield_pretouch_<id>` at marker_rva.
        #    Wait: for sgxwallet generate_ecdsa_key_field, enter_call=0x14909, marker=0x14915 (there is a 7-byte instruction between them!).
        #    So __gate_A_field_<idx> must jump back to `enter_call_rva + 5`, and `marker_rva` jumps to `__gate_B_field_<idx>`!
        gate_a_rva = gate_page_rva + len(gate_buf)
        stub_a = bytearray()
        stub_a += emit_save_regs(1)
        # Save active_field_id (%rdi) -> 0x20(%rax) and %rsp -> 0x10(%rax)
        stub_a += b"\x48\x89\x78\x20"  # movq %rdi, 0x20(%rax)
        stub_a += b"\x48\x89\x60\x10"  # movq %rsp, 0x10(%rax)
        # Check gate_enable == 1: cmpl $1, 4(%rax); jne skip_a
        spin_a = emit_gate_spin(10, 20)
        stub_a += b"\x83\x78\x04\x01"  # cmpl $1, 4(%rax)
        stub_a += b"\x75" + bytes([len(spin_a)])
        stub_a += spin_a
        stub_a += emit_restore_regs(1)
        # Call real field_enter from here:
        call_fe_src = gate_a_rva + len(stub_a)
        stub_a += rel32(0xE8, call_fe_src, field_enter_rva)
        # Jump back to enter_call_rva + 5
        jmp_back_a_src = gate_a_rva + len(stub_a)
        stub_a += rel32(0xE9, jmp_back_a_src, enter_call_rva + 5)
        gate_buf += stub_a

        # 2. Emit __gate_B_field_<idx> (jumped to by marker_rva):
        gate_b_rva = gate_page_rva + len(gate_buf)
        stub_b = bytearray()
        stub_b += emit_save_regs(2)
        # Record %rsp at Gate B -> 0x10(%rax)
        stub_b += b"\x48\x89\x60\x10"  # movq %rsp, 0x10(%rax)
        spin_b = bytearray(emit_gate_spin(30, 40))
        # Also if use_alt_rsp_in_s2 (0x8(%rax)) == 1: leaq 0xff0(%rax), %rsp
        # cmpq $1, 8(%rax) (48 83 78 08 01); jne +7 (75 07); leaq 0xff0(%rax), %rsp (48 8D A0 F0 0F 00 00)
        alt_rsp_b = b"\x48\x83\x78\x08\x01\x75\x07\x48\x8d\xa0\xf0\x0f\x00\x00"
        spin_b += alt_rsp_b
        stub_b += b"\x83\x78\x04\x01"  # cmpl $1, 4(%rax)
        stub_b += b"\x75" + bytes([len(spin_b)])
        stub_b += spin_b
        stub_b += emit_rdtsc_to_offset(0x28)  # tsc_s2_start
        stub_b += emit_restore_regs(2)
        jmp_pretouch_src = gate_b_rva + len(stub_b)
        stub_b += rel32(0xE9, jmp_pretouch_src, pretouch_rva)
        gate_buf += stub_b

        # 3. Emit __gate_C_field_<idx> (jumped to by end of __atfield_pretouch_<id>):
        gate_c_rva = gate_page_rva + len(gate_buf)
        stub_c = bytearray()
        stub_c += emit_save_regs(3)
        stub_c += emit_rdtsc_to_offset(0x30)  # tsc_s2_end
        # Restore %rsp if use_alt_rsp_in_s2 == 1:
        # cmpq $1, 8(%rax) (48 83 78 08 01); jne +4 (75 04); movq 0x10(%rax), %rsp (48 8B 60 10)
        restore_rsp_c = b"\x48\x83\x78\x08\x01\x75\x04\x48\x8b\x60\x10"
        spin_c = restore_rsp_c + emit_gate_spin(50, 60)
        stub_c += b"\x83\x78\x04\x01"  # cmpl $1, 4(%rax)
        stub_c += b"\x75" + bytes([len(spin_c)])
        stub_c += spin_c
        stub_c += emit_rdtsc_to_offset(0x38)  # tsc_s3_start
        stub_c += emit_restore_regs(3)
        jmp_cont_src = gate_c_rva + len(stub_c)
        stub_c += rel32(0xE9, jmp_cont_src, cont_rva)
        gate_buf += stub_c

        # 4. Emit __gate_D_field_<idx> (replaces `callq field_exit` at exit_call_rva):
        gate_d_rva = gate_page_rva + len(gate_buf)
        stub_d = bytearray()
        # First call real field_exit so closing CAS is part of S3!
        call_fx_src = gate_d_rva + len(stub_d)
        stub_d += rel32(0xE8, call_fx_src, field_exit_rva)
        stub_d += emit_save_regs(4)
        stub_d += b"\x48\x89\x60\x48"  # movq %rsp, 0x48(%rax) (gateD_rsp)
        stub_d += emit_rdtsc_to_offset(0x40)  # tsc_s3_end
        spin_d = emit_gate_spin(70, 80)
        stub_d += b"\x83\x78\x04\x01"  # cmpl $1, 4(%rax)
        stub_d += b"\x75" + bytes([len(spin_d)])
        stub_d += spin_d
        stub_d += emit_restore_regs(4)
        jmp_back_d_src = gate_d_rva + len(stub_d)
        stub_d += rel32(0xE9, jmp_back_d_src, exit_call_rva + 5)
        gate_buf += stub_d

        # Patch enter_call_rva: E8 -> E9 to gate_a_rva
        off_enter = elf.loaded_offset(enter_call_rva, 5)
        updated[off_enter : off_enter + 5] = rel32(0xE9, enter_call_rva, gate_a_rva)

        # Patch marker_rva: E9 to gate_b_rva
        off_marker = elf.loaded_offset(marker_rva, 5)
        updated[off_marker : off_marker + 5] = rel32(0xE9, marker_rva, gate_b_rva)

        # Patch pretouch_jmp_rva: E9 to gate_c_rva
        updated[pretouch_jmp_off : pretouch_jmp_off + 5] = rel32(0xE9, pretouch_jmp_rva, gate_c_rva)

        # Patch exit_call_rva: E8 -> E9 to gate_d_rva
        off_exit = elf.loaded_offset(exit_call_rva, 5)
        updated[off_exit : off_exit + 5] = rel32(0xE9, exit_call_rva, gate_d_rva)

        field_gate_info.append({
            "field_id": fid_str,
            "function": field["function"],
            "enter_call_rva": enter_call_rva,
            "marker_rva": marker_rva,
            "pretouch_rva": pretouch_rva,
            "pretouch_jmp_rva": pretouch_jmp_rva,
            "exit_call_rva": exit_call_rva,
            "gate_a_rva": gate_a_rva,
            "gate_b_rva": gate_b_rva,
            "gate_c_rva": gate_c_rva,
            "gate_d_rva": gate_d_rva,
        })

    if len(gate_buf) > PAGE:
        raise RuntimeError(f"gate_buf size {len(gate_buf)} exceeds 1 page ({PAGE})")

    gate_buf += b"\xcc" * (PAGE - len(gate_buf))
    updated[gate_page_off : gate_page_off + PAGE] = gate_buf

    output_elf_path.write_bytes(bytes(updated))
    output_elf_path.chmod(0o755)
    summary = {
        "schema": "atfield-4gate-patch-v1",
        "input_elf": str(input_elf_path),
        "input_elf_sha256": hashlib.sha256(elf.data).hexdigest(),
        "output_elf": str(output_elf_path),
        "output_elf_sha256": hashlib.sha256(updated).hexdigest(),
        "gate_helper_page_rva": gate_page_rva,
        "gate_bytes_used": len(gate_buf.rstrip(b"\xcc")),
        "fields": field_gate_info,
    }
    write_json(output_json_path, summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-elf", type=Path, required=True)
    parser.add_argument("--fields", type=Path, required=True)
    parser.add_argument("--capacity-q", type=int, required=True)
    parser.add_argument("--config-xml", type=Path, required=True)
    parser.add_argument("--sign-key", type=Path, default=Path("/home/meandssh/islands-sgx/sample/build/test-signing-key.pem"))
    parser.add_argument("--out-elf", type=Path, required=True)
    parser.add_argument("--out-signed-elf", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()

    summary = patch_elf_4gate(
        args.input_elf, args.fields, args.capacity_q, args.out_elf, args.out_json
    )
    sgx_sign = "/nix/store/2acwmnfcsz668csnyxn77brmllp7kx6s-sgx-sdk-2.29.100.1/bin/x64/sgx_sign"
    subprocess.run(
        [
            sgx_sign, "sign",
            "-key", str(args.sign_key),
            "-enclave", str(args.out_elf),
            "-out", str(args.out_signed_elf),
            "-config", str(args.config_xml),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    print(
        f"patched 4gate: {args.out_signed_elf.name} fields={len(summary["fields"])} "
        f"gate_helper_page={summary["gate_helper_page_rva"]:#x} bytes={summary["gate_bytes_used"]}"
    )


if __name__ == "__main__":
    main()
