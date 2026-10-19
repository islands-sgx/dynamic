#!/usr/bin/env python3
"""Extract and validate hidden ATField anchors from a linked x86-64 ProfileElf."""
import argparse
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

PAGE_SIZE = 4096
PT_LOAD, PF_X = 1, 1
SHT_SYMTAB, SHT_RELA, SHT_REL, SHT_DYNSYM, SHT_STRTAB = 2, 4, 9, 11, 3
SHF_EXECINSTR = 4
WRAPPER = bytes.fromhex("0f1f80c3000000")
ANCHOR_RE = re.compile(r"^__atf_([cn])_(0|[1-9a-f][0-9a-f]*)_(0|[1-9a-f][0-9a-f]*)_(0|[1-9a-f][0-9a-f]*)$")
WIDTH = {0:0,1:8,2:4,3:4,4:4,5:8,6:8,7:8,8:8,9:8,10:4,11:4,12:2,13:2,
         14:1,15:1,16:8,17:8,18:8,19:4,20:4,21:4,22:4,23:4,24:8,25:8,26:4,
         27:8,28:8,29:8,30:8,31:8,32:4,33:8,34:4,35:0,36:16,37:8,38:8,41:4,42:4}

class ElfError(ValueError):
    pass

@dataclass(frozen=True)
class AnchorFact:
    name: str
    category: str
    payload: int
    function: int
    ordinal: int
    rva: int
    page_rva: int
    file_offset: int
    section_index: int

def checked_slice(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ElfError(f"{label} lies outside the ELF file")
    return data[offset:offset + size]

def parse_elf(path):
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if data[4:7] != b"\x02\x01\x01":
        raise ElfError("expected ELF64 little-endian version 1")
    etype, machine = struct.unpack_from("<HH", data, 16)
    if machine != 62:
        raise ElfError(f"expected x86-64 ELF (e_machine=62), got {machine}")
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 54)
    if not shnum or shstrndx >= shnum or shentsize != 64:
        raise ElfError("unsupported or invalid ELF section table")
    checked_slice(data, shoff, shnum * shentsize, "section table")
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strings_sec = raw[shstrndx]
    names = checked_slice(data, strings_sec[4], strings_sec[5], "section-name table")
    sections = []
    for section in raw:
        noff = section[0]
        end = names.find(b"\0", noff) if noff < len(names) else -1
        if end < 0:
            raise ElfError("invalid section name")
        sections.append(section + (names[noff:end].decode("utf-8", "replace"),))
    programs = []
    if phnum:
        if phentsize != 56:
            raise ElfError("invalid ELF64 program-header size")
        checked_slice(data, phoff, phnum * phentsize, "program-header table")
        programs = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
                    for i in range(phnum)]
    return data, etype, sections, programs

def collect_symbols(data, sections):
    found = {}
    for si, sec in enumerate(sections):
        if sec[1] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        entsize = sec[9] or 24
        if entsize != 24 or sec[5] % entsize or sec[6] >= len(sections):
            raise ElfError(f"invalid symbol table at section {si}")
        st = sections[sec[6]]
        if st[1] != SHT_STRTAB:
            raise ElfError(f"symbol table {si} has invalid string table")
        strings = checked_slice(data, st[4], st[5], "symbol string table")
        symbols = checked_slice(data, sec[4], sec[5], "symbol table")
        for pos in range(0, len(symbols), 24):
            noff, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", symbols, pos)
            end = strings.find(b"\0", noff) if noff < len(strings) else -1
            if end < 0:
                raise ElfError(f"invalid symbol name in table {si}")
            name = strings[noff:end].decode("ascii", "strict")
            if not name.startswith(("__atf_c_", "__atf_n_")):
                continue
            match = ANCHOR_RE.fullmatch(name)
            if not match:
                raise ElfError(f"malformed anchor identity: {name}")
            cat, payload, function, ordinal = match.groups()
            if info & 0xF != 0 or info >> 4 not in (0, 1) or other & 3 != 2 or size != 0:
                raise ElfError(f"anchor must be a hidden zero-size NOTYPE symbol: {name}")
            if shndx == 0 or shndx >= len(sections):
                raise ElfError(f"anchor has no regular defining section: {name}")
            item = (cat, int(payload, 16), int(function, 16), int(ordinal, 16), value, shndx)
            if any(v >= 1 << 64 for v in item[1:4]):
                raise ElfError(f"anchor identity exceeds uint64: {name}")
            if name in found and found[name] != item:
                raise ElfError(f"conflicting definitions for {name}")
            found[name] = item
    return found

def file_offset_for_exec(data, programs, address):
    matches = []
    for p_type, flags, offset, vaddr, _, filesz, memsz, _ in programs:
        if p_type == PT_LOAD and flags & PF_X and vaddr <= address < vaddr + filesz:
            matches.append(offset + address - vaddr)
        elif p_type == PT_LOAD and flags & PF_X and vaddr <= address < vaddr + memsz:
            raise ElfError(f"anchor RVA 0x{address:x} lies in executable zero-fill")
    if len(matches) != 1:
        raise ElfError(f"anchor RVA 0x{address:x} maps to {len(matches)} executable file ranges")
    return matches[0]

def relocation_coverage(data, sections):
    covered = set()
    for sec in sections:
        if sec[1] not in (SHT_REL, SHT_RELA):
            continue
        entsize = sec[9] or (24 if sec[1] == SHT_RELA else 16)
        expected = 24 if sec[1] == SHT_RELA else 16
        if entsize != expected or sec[5] % entsize:
            raise ElfError("invalid relocation section")
        raw = checked_slice(data, sec[4], sec[5], "relocation section")
        for pos in range(0, len(raw), entsize):
            address, info = struct.unpack_from("<QQ", raw, pos)
            width = WIDTH.get(info & 0xFFFFFFFF)
            if width is None:
                covered.add(address)
            else:
                covered.update(range(address, address + width))
    return covered

def extract_anchor_facts(path, required_pages=()):
    """Return final C3 anchors with identity, RVA, executable mapping and page coverage."""
    data, etype, sections, programs = parse_elf(path)
    if etype not in (2, 3):
        raise ElfError(f"expected linked ET_EXEC or ET_DYN ProfileElf, got e_type={etype}")
    syms = collect_symbols(data, sections)
    covered = relocation_coverage(data, sections)
    facts = []
    for name, (cat, payload, function, ordinal, rva, shndx) in syms.items():
        if not sections[shndx][2] & SHF_EXECINSTR:
            raise ElfError(f"anchor section is not executable: {name}")
        offset = file_offset_for_exec(data, programs, rva)
        if offset >= len(data) or data[offset] != 0xC3:
            actual = data[offset] if offset < len(data) else None
            raise ElfError(f"final anchor byte is {actual!r}, expected 0xc3: {name}")
        if rva in covered:
            raise ElfError(f"anchor byte is covered by a final relocation: {name}")
        if cat == "c":
            if rva < 3 or checked_slice(data, offset - 3, 7, "constructed anchor wrapper") != WRAPPER:
                raise ElfError(f"constructed anchor does not match the fixed seven-byte wrapper: {name}")
            if any(address in covered for address in range(rva - 3, rva + 4)):
                raise ElfError(f"constructed anchor wrapper is covered by a final relocation: {name}")
        facts.append(AnchorFact(name, cat, payload, function, ordinal, rva,
                                rva & ~(PAGE_SIZE - 1), offset, shndx))
    facts.sort(key=lambda f: (f.rva, f.name))
    pages = {f.page_rva for f in facts}
    for page in required_pages:
        if page < 0 or page % PAGE_SIZE:
            raise ElfError(f"required page RVA must be nonnegative and page-aligned: {page}")
        if page not in pages:
            raise ElfError(f"required executable page 0x{page:x} has no validated C3 anchor")
    return facts

def validate_profile_elf(path, required_pages=()):
    """Validate final anchor bytes and optional required executable-page coverage."""
    return extract_anchor_facts(path, required_pages)

def fact_json(fact):
    row = asdict(fact)
    for key in ("payload", "function", "ordinal"):
        row[key] = f"0x{row[key]:x}"
    return row

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile_elf", help="linked ELF64 x86-64 ProfileElf")
    parser.add_argument("--require-page", action="append", default=[], metavar="RVA",
                        help="required page RVA (decimal or 0x-prefixed); may repeat")
    args = parser.parse_args()
    try:
        pages = [int(value, 0) for value in args.require_page]
        facts = validate_profile_elf(args.profile_elf, pages)
    except (OSError, ValueError, struct.error, UnicodeError) as exc:
        print(f"anchor_facts: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"format": "AnchorFacts-v1", "page_size": PAGE_SIZE,
                      "anchors": [fact_json(fact) for fact in facts]},
                     indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
