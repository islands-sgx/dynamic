#!/usr/bin/env python3
import struct
import sys
from pathlib import Path

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_REL = 9

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

WRAPPER = b"\x0f\x1f\x80\xc3\x00\x00\x00"


def reloc_width(r_type: int) -> int:
    if r_type == 0:
        return 0
    if r_type in (14, 15):
        return 1
    if r_type in (12, 13):
        return 2
    if r_type in (1, 24, 25, 33):
        return 8
    return 4


def align_up(buf: bytearray, align: int) -> int:
    pad = (-len(buf)) & (align - 1)
    if pad:
        buf.extend(b"\x00" * pad)
    return len(buf)


def main() -> None:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: inject-native-anchors.py OBJECT PAYLOAD_ORDINAL\n")
        sys.exit(64)
    obj_path = sys.argv[1]
    payload_ordinal = int(sys.argv[2], 0)
    if not 0 <= payload_ordinal < (1 << 64):
        sys.exit("payload ordinal must fit uint64")

    data = Path(obj_path).read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type != 1 or e_machine != 62:
        return

    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    if e_shentsize != 64 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return

    sections = []
    for idx in range(e_shnum):
        off = e_shoff + idx * 64
        sections.append(list(struct.unpack_from("<IIQQQQIIQQ", data, off)))

    shstr_sec = sections[e_shstrndx]
    shstr_bytes = data[shstr_sec[4] : shstr_sec[4] + shstr_sec[5]]

    def sec_name(name_off: int) -> bytes:
        end = shstr_bytes.find(b"\x00", name_off)
        return shstr_bytes[name_off:end] if end != -1 else b""

    for s in sections:
        if sec_name(s[0]) == b".note.atfield.anchors":
            sys.exit("legacy ATField note in native object")

    covered = {}
    for s in sections:
        sh_type, sh_flags, _, sh_offset, sh_size, sh_link, sh_info, _, sh_entsize = s[1:]
        if sh_type not in (SHT_REL, SHT_RELA) or sh_info >= e_shnum:
            continue
        target = sections[sh_info]
        if (target[2] & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR):
            continue
        ent_size = sh_entsize or (24 if sh_type == SHT_RELA else 16)
        cov = covered.setdefault(sh_info, set())
        for pos in range(sh_offset, sh_offset + sh_size, ent_size):
            r_offset, r_info = struct.unpack_from("<QQ", data, pos)
            w = reloc_width(r_info & 0xFFFFFFFF)
            for b_off in range(r_offset, r_offset + w):
                cov.add(b_off)

    anchors = []
    anchor_ordinal = 0
    for shndx, s in enumerate(sections):
        sh_type, sh_flags, _, sh_offset, sh_size = s[1:6]
        if (
            sh_type != SHT_PROGBITS
            or (sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR)
            or sh_size == 0
        ):
            continue
        sec_bytes = data[sh_offset : sh_offset + sh_size]
        cov = covered.get(shndx, set())
        for i, b_val in enumerate(sec_bytes):
            if b_val != 0xC3 or i in cov:
                continue
            if (
                i >= 3
                and i + 4 <= len(sec_bytes)
                and sec_bytes[i - 3 : i + 4] == WRAPPER
                and all((k not in cov) for k in range(i - 3, i + 4))
            ):
                kind = 2
            else:
                kind = 1
            anchors.append((shndx, i, kind, anchor_ordinal))
            anchor_ordinal += 1

    symtab_idx = next((i for i, s in enumerate(sections) if s[1] == SHT_SYMTAB), None)
    if symtab_idx is None:
        if anchors:
            sys.exit("native anchors require a static symbol table")
        return
    symtab_sec = sections[symtab_idx]
    strtab_idx = symtab_sec[6]
    if strtab_idx >= e_shnum or sections[strtab_idx][1] != SHT_STRTAB:
        sys.exit("native symbol string table is missing")
    strtab_sec = sections[strtab_idx]
    strings = data[strtab_sec[4]:strtab_sec[4] + strtab_sec[5]]

    def anchor_name(kind: int, ordinal: int) -> bytes:
        category = "c" if kind == 2 else "n"
        return f"__atf_{category}_{payload_ordinal:x}_0_{ordinal:x}".encode("ascii")

    expected = {
        anchor_name(kind, ordinal): (shndx, offset)
        for shndx, offset, kind, ordinal in anchors
    }
    existing = {}
    for pos in range(symtab_sec[4], symtab_sec[4] + symtab_sec[5], 24):
        name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, pos)
        end = strings.find(b"\x00", name)
        symbol = strings[name:end]
        if symbol.startswith((b"__atfield_anchor_", b"__atfield_native_anchor_")):
            sys.exit("legacy ATField symbol in native object")
        if not symbol.startswith(b"__atf_"):
            continue
        if symbol in existing or info != 0x10 or other != 0x02 or size != 0:
            sys.exit("invalid native ATField anchor symbol")
        existing[symbol] = (shndx, value)
    if existing:
        if existing != expected:
            sys.exit("native ATField anchors differ from the complete expected set")
        return
    if not anchors:
        return

    new_symtab = bytearray(data[symtab_sec[4] : symtab_sec[4] + symtab_sec[5]])
    new_strtab = bytearray(data[strtab_sec[4] : strtab_sec[4] + strtab_sec[5]])
    if not new_strtab or new_strtab[-1] != 0:
        new_strtab.append(0)

    for shndx, offset, kind, a_ord in anchors:
        name_off = len(new_strtab)
        new_strtab.extend(anchor_name(kind, a_ord))
        new_strtab.append(0)
        new_symtab.extend(struct.pack("<IBBHQQ", name_off, 0x10, 0x02, shndx, offset, 0))

    out = bytearray(data)
    new_symtab_off = align_up(out, 8)
    out.extend(new_symtab)
    sections[symtab_idx][4] = new_symtab_off
    sections[symtab_idx][5] = len(new_symtab)

    new_strtab_off = align_up(out, 1)
    out.extend(new_strtab)
    sections[strtab_idx][4] = new_strtab_off
    sections[strtab_idx][5] = len(new_strtab)

    new_shoff = align_up(out, 8)
    for s in sections:
        out.extend(struct.pack("<IIQQQQIIQQ", *s))

    struct.pack_into("<Q", out, 40, new_shoff)
    Path(obj_path).write_bytes(out)


if __name__ == "__main__":
    main()
