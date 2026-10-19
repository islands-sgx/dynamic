#!/usr/bin/env python3
"""Build FieldTargetPages from a signed SGX layout and frozen ELF inputs.

The producer uses ELF PT_LOAD p_memsz plus the signed .note.sgxmeta DIR_LAYOUT.
It never inspects process VMAs. All committed REG pages are conservatively added
for each Field; TCS, SSA, guard and uncommitted post-add reservations are omitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from pathlib import Path

PAGE = 4096
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_DYN = 3
EM_X86_64 = 62
PT_LOAD = 1
PT_GNU_RELRO = 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
SHT_SYMTAB, SHT_DYNSYM, SHT_NOTE = 2, 11, 7
MAGIC = 0x86A80294635D0E4C
GROUP_FLAG = 1 << 12
DIR_LAYOUT = 1
PAGE_ATTR_EADD = 1
SI_FLAG_R, SI_FLAG_W, SI_FLAG_X = 1, 2, 4
SI_FLAG_PT_MASK, SI_FLAG_TCS, SI_FLAG_REG = 0xFF << 8, 1 << 8, 2 << 8
LAYOUT_NAMES = {
    1: "HEAP_MIN", 2: "HEAP_INIT", 3: "HEAP_MAX", 4: "TCS", 5: "TD",
    6: "SSA", 7: "STACK_MAX", 8: "STACK_MIN", 10: "GUARD",
    11: "HEAP_DYN_MIN", 12: "HEAP_DYN_INIT", 13: "HEAP_DYN_MAX",
    14: "TCS_DYN", 15: "TD_DYN", 16: "SSA_DYN", 17: "STACK_DYN_MAX",
    18: "STACK_DYN_MIN", 20: "RSRV_MIN", 21: "RSRV_INIT", 22: "RSRV_MAX",
    23: "USER_REGION",
}
SPECIAL_IDS = {4, 6, 10, 14, 16}


class WorksetError(Exception):
    pass


def align_down(n: int, a: int = PAGE) -> int:
    return n & -a


def align_up(n: int, a: int = PAGE) -> int:
    return (n + a - 1) & -a


def write_json(path: str | Path, value: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_json(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise WorksetError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorksetError(f"JSON root must be an object: {path}")
    return value


def parse_u64(value: object, label: str) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError("boolean")
        if isinstance(value, int):
            result = value
        elif isinstance(value, str) and re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,16}|[0-9]+)", value):
            result = int(value, 0 if value.lower().startswith("0x") else 10)
        else:
            raise ValueError("not an integer or hexadecimal string")
    except ValueError as exc:
        raise WorksetError(f"{label} must be an unsigned 64-bit integer: {value!r}") from exc
    if not 0 <= result < (1 << 64):
        raise WorksetError(f"{label} is outside uint64: {value!r}")
    return result


def read_cstr(blob: bytes, at: int) -> str:
    if at < 0 or at >= len(blob):
        return ""
    end = blob.find(b"\0", at)
    if end < 0:
        end = len(blob)
    return blob[at:end].decode("utf-8", "replace")


class ElfFile:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        try:
            self.data = self.path.read_bytes()
        except OSError as exc:
            raise WorksetError(f"cannot read ELF {self.path}: {exc}") from exc
        if len(self.data) < 64 or self.data[:4] != b"\x7fELF":
            raise WorksetError(f"not an ELF file: {self.path}")
        ident = self.data[:16]
        if ident[4] != ELFCLASS64 or ident[5] != ELFDATA2LSB:
            raise WorksetError(f"expected little-endian ELF64: {self.path}")
        (self.etype, self.machine, _version, _entry, phoff, shoff, _flags,
         ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", self.data, 16)
        if self.machine != EM_X86_64 or self.etype != ET_DYN:
            raise WorksetError(f"expected x86-64 ET_DYN enclave ELF: {self.path}")
        if ehsize < 64 or phentsize < 56 or shentsize < 64 or phnum == 0 or shnum == 0:
            raise WorksetError(f"unsupported or incomplete ELF tables: {self.path}")
        if phoff + phentsize * phnum > len(self.data) or shoff + shentsize * shnum > len(self.data):
            raise WorksetError(f"ELF table exceeds file size: {self.path}")
        self.loads = []
        self.relro = []
        for index in range(phnum):
            base = phoff + index * phentsize
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", self.data, base)
            if p_type == PT_LOAD:
                if p_filesz > p_memsz or p_offset + p_filesz > len(self.data):
                    raise WorksetError(f"invalid PT_LOAD {index} in {self.path}")
                self.loads.append({"index": index, "offset": p_offset, "vaddr": p_vaddr,
                                   "filesz": p_filesz, "memsz": p_memsz,
                                   "flags": p_flags, "align": p_align})
            elif p_type == PT_GNU_RELRO:
                if p_memsz == 0:
                    raise WorksetError(f"empty PT_GNU_RELRO {index} in {self.path}")
                self.relro.append({"index": index, "vaddr": p_vaddr,
                                   "memsz": p_memsz, "end": p_vaddr + p_memsz})
        if not self.loads:
            raise WorksetError(f"ELF has no PT_LOAD segments: {self.path}")
        if shstrndx >= shnum:
            raise WorksetError(f"invalid section-name string table: {self.path}")
        raw_sections = []
        for index in range(shnum):
            base = shoff + index * shentsize
            name, stype, flags, addr, offset, size, link, info, addralign, entsize = struct.unpack_from("<IIQQQQIIQQ", self.data, base)
            if stype != 8 and offset + size > len(self.data):
                raise WorksetError(f"section {index} exceeds file size: {self.path}")
            raw_sections.append({"index": index, "nameoff": name, "type": stype, "flags": flags,
                                 "addr": addr, "offset": offset, "size": size, "link": link,
                                 "info": info, "align": addralign, "entsize": entsize})
        strings_section = raw_sections[shstrndx]
        strings = self.data[strings_section["offset"]:strings_section["offset"] + strings_section["size"]]
        self.sections = []
        for section in raw_sections:
            section = dict(section)
            section["name"] = read_cstr(strings, section["nameoff"])
            self.sections.append(section)
        self.by_name = {}
        for section in self.sections:
            if section["name"]:
                self.by_name.setdefault(section["name"], []).append(section)

    def section_data(self, section: dict) -> bytes:
        return self.data[section["offset"]:section["offset"] + section["size"]]

    def loaded_offset(self, address: int, width: int = 1) -> int:
        for segment in self.loads:
            lo, hi = segment["vaddr"], segment["vaddr"] + segment["filesz"]
            if lo <= address and address + width <= hi:
                return segment["offset"] + address - lo
        raise WorksetError(f"RVA {address:#x} is not file-backed by PT_LOAD in {self.path}")

    def note_descriptor(self) -> bytes:
        notes = self.by_name.get(".note.sgxmeta", [])
        if len(notes) != 1:
            raise WorksetError(f"expected one .note.sgxmeta section in {self.path}; found {len(notes)}")
        section = notes[0]
        if section["type"] != SHT_NOTE:
            raise WorksetError(f".note.sgxmeta is not SHT_NOTE in {self.path}")
        blob = self.section_data(section)
        offset = 0
        while offset + 12 <= len(blob):
            namesz, descsz, note_type = struct.unpack_from("<III", blob, offset)
            offset += 12
            name_end = offset + namesz
            if name_end > len(blob):
                break
            owner = blob[offset:name_end].rstrip(b"\0")
            # Intel's .note.sgxmeta stores its 13-byte owner immediately before
            # the descriptor, then pads the whole section at the end. Accept the
            # standard ELF note padding too, but only when the owner/type/magic match.
            starts = (name_end, offset + align_up(namesz, 4))
            if owner == b"sgx_metadata" and note_type == 1:
                for desc_start in starts:
                    desc_end = desc_start + descsz
                    if desc_end > len(blob):
                        continue
                    desc = blob[desc_start:desc_end]
                    if len(desc) >= 0x6000 and struct.unpack_from("<Q", desc, 0)[0] == MAGIC:
                        return desc[:0x6000]
            next_note = max(starts) + align_up(descsz, 4)
            if namesz == 0 and descsz == 0:
                break
            offset = next_note
        raise WorksetError(f"SGX metadata note not found in {self.path}")

    def symbols(self) -> list[dict]:
        result = []
        for section in self.sections:
            if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if section["link"] >= len(self.sections):
                raise WorksetError(f"symbol table has invalid string table in {self.path}")
            strings_section = self.sections[section["link"]]
            strings = self.data[strings_section["offset"]:strings_section["offset"] + strings_section["size"]]
            entsize = section["entsize"] or 24
            if entsize < 24 or section["size"] % entsize:
                raise WorksetError(f"invalid symbol table size in {self.path}")
            blob = self.section_data(section)
            for offset in range(0, len(blob), entsize):
                nameoff, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", blob, offset)
                name = read_cstr(strings, nameoff)
                if name:
                    result.append({"name": name, "value": value, "size": size,
                                   "info": info, "other": other, "shndx": shndx,
                                   "file_offset": section["offset"] + offset,
                                   "table_name": section["name"]})
        return result


def parse_signed_metadata(elf: ElfFile) -> dict:
    desc = elf.note_descriptor()
    (magic, version, metadata_size, _policy, ssa_frame_pages, _max_save_buffer,
     _misc, _tcs_min_pool, enclave_size) = struct.unpack_from("<QQIIIIIIQ", desc, 0)
    if magic != MAGIC:
        raise WorksetError(f"bad .note.sgxmeta magic in {elf.path}: {magic:#x}")
    if metadata_size < 0x750 or metadata_size > len(desc):
        raise WorksetError(f"invalid signer metadata_size {metadata_size} in {elf.path}")
    dirs_offset = 8 + 8 + 24 + 8 + 16 + 1808
    if dirs_offset + 32 > metadata_size:
        raise WorksetError("SGX metadata directory table exceeds metadata_size")
    directories = [struct.unpack_from("<II", desc, dirs_offset + i * 8) for i in range(4)]
    layout_offset, layout_size = directories[DIR_LAYOUT]
    if layout_size == 0 or layout_size % 32 or layout_offset + layout_size > metadata_size:
        raise WorksetError(f"invalid DIR_LAYOUT offset={layout_offset} size={layout_size}")
    entries = []
    for offset in range(layout_offset, layout_offset + layout_size, 32):
        entry_id = struct.unpack_from("<H", desc, offset)[0]
        if entry_id & GROUP_FLAG:
            group_id, entry_count, load_times, load_step = struct.unpack_from("<HHIQ", desc, offset)
            if entry_count > len(entries):
                raise WorksetError(f"layout group at {offset:#x} exceeds prior entry table")
            template = entries[-entry_count:] if entry_count else []
            for repetition in range(1, load_times + 1):
                for prior in template:
                    clone = dict(prior)
                    clone["rva"] += load_step * repetition
                    clone["name"] = f"{prior['name']}_group_{repetition}"
                    clone["group_id"] = group_id
                    entries.append(clone)
            continue
        identity, attributes, pages, rva, content_size, content_offset, si_flags = struct.unpack_from("<HHIQIIQ", desc, offset)
        entries.append({"id": identity, "name": LAYOUT_NAMES.get(identity, f"LAYOUT_{identity}"),
                        "attributes": attributes, "pages": pages, "rva": rva,
                        "content_size": content_size, "content_offset": content_offset,
                        "si_flags": si_flags})
    return {"version": version, "metadata_size": metadata_size,
            "ssa_frame_pages": ssa_frame_pages, "enclave_size": enclave_size,
            "layout_entries": entries}


def elf_load_equivalence(profile: ElfFile, signed: ElfFile) -> None:
    def identity(elf: ElfFile):
        return [(s["vaddr"], s["filesz"], s["memsz"], s["flags"], s["align"]) for s in elf.loads]
    if identity(profile) != identity(signed):
        raise WorksetError("Profile ELF and signed ELF PT_LOAD layout differs; use the matching signer output")


def locate_pretouch_segment(elf: ElfFile, capacity_q: int) -> tuple[dict | None, dict | None]:
    sections = elf.by_name.get(".atfield_pretouch", [])
    if len(sections) > 1:
        raise WorksetError("multiple .atfield_pretouch sections")
    if not sections:
        return None, None
    section = sections[0]
    if section["type"] != 1 or (section["flags"] & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR) or section["flags"] & SHF_WRITE:
        raise WorksetError(".atfield_pretouch must be allocated, executable and read-only")
    owners = [segment for segment in elf.loads if segment["vaddr"] <= section["addr"] and section["addr"] + section["size"] <= segment["vaddr"] + segment["memsz"]]
    if len(owners) != 1:
        raise WorksetError(".atfield_pretouch must belong to exactly one PT_LOAD")
    segment = owners[0]
    if segment["flags"] != (PF_R | PF_X) or segment["vaddr"] % PAGE or segment["align"] < PAGE or segment["filesz"] != segment["memsz"]:
        raise WorksetError("post PT_LOAD must be page-aligned RX with p_filesz == p_memsz")
    if capacity_q and segment["memsz"] != capacity_q:
        raise WorksetError(f"signed .atfield_pretouch size {segment['memsz']} differs from configured Q={capacity_q}")
    if segment["vaddr"] != align_up(max(s["vaddr"] + s["memsz"] for s in elf.loads if s is not segment)):
        raise WorksetError(".atfield_pretouch is not immediately after ordinary PT_LOAD memory")
    if segment is not max(elf.loads, key=lambda s: s["vaddr"]):
        raise WorksetError(".atfield_pretouch PT_LOAD is not the last load segment")
    if section["addr"] != segment["vaddr"] or section["size"] != segment["memsz"]:
        raise WorksetError(".atfield_pretouch output section must fill its dedicated PT_LOAD")
    return section, segment


def signer_regions(metadata: dict) -> tuple[list[dict], list[dict]]:
    included, excluded = [], []
    for entry in metadata["layout_entries"]:
        identity, name = entry["id"], entry["name"]
        start, pages = entry["rva"], entry["pages"]
        end = start + pages * PAGE
        if pages == 0:
            continue
        if start % PAGE or end > metadata["enclave_size"]:
            raise WorksetError(f"signer region {name} has invalid page range [{start:#x},{end:#x})")
        page_type = entry["si_flags"] & SI_FLAG_PT_MASK
        perms = entry["si_flags"] & 7
        region = {"kind": "signer", "name": name, "start_rva": start, "end_rva": end,
                  "pages": pages, "permissions": perms, "si_flags": entry["si_flags"],
                  "attributes": entry["attributes"], "layout_id": identity}
        if identity in SPECIAL_IDS or page_type == SI_FLAG_TCS:
            region["excluded_reason"] = "TCS/SSA/guard control region"
            excluded.append(region)
        elif page_type != SI_FLAG_REG:
            region["excluded_reason"] = f"non-REG SGX page type {page_type:#x}"
            excluded.append(region)
        elif not entry["attributes"] & PAGE_ATTR_EADD:
            region["excluded_reason"] = "signer layout does not EADD this reserved page range"
            excluded.append(region)
        else:
            if not perms:
                raise WorksetError(f"committed REG region {name} has no R/W/X permission")
            included.append(region)
    return included, excluded


def effects_for_permissions(perms: int, label: str) -> list[str]:
    effects = []
    if perms & SI_FLAG_X:
        effects.append("X")
    if perms & SI_FLAG_R:
        effects.append("R")
    if perms & SI_FLAG_W:
        effects.append("W")
    if not effects:
        raise WorksetError(f"REG page has no usable permission: {label}")
    if "X" in effects and "W" in effects:
        raise WorksetError(f"REG page is both executable and writable: {label}")
    if "W" in effects and "R" not in effects:
        raise WorksetError(f"W template requires a readable/writable REG page: {label}")
    return effects


def make_layout(profile: ElfFile, signed: ElfFile, capacity_q: int) -> dict:
    elf_load_equivalence(profile, signed)
    metadata = parse_signed_metadata(signed)
    pretouch_section, pretouch_segment = locate_pretouch_segment(profile, capacity_q)
    if pretouch_section:
        signed_section, signed_segment = locate_pretouch_segment(signed, capacity_q)
        if not signed_section or signed_segment["vaddr"] != pretouch_segment["vaddr"]:
            raise WorksetError("signed and Profile .atfield_pretouch layout differs")
    post_index = pretouch_segment["index"] if pretouch_segment else None
    ordinary = [s for s in profile.loads if s["index"] != post_index]
    if not ordinary:
        raise WorksetError("no ordinary PT_LOAD segments")
    ordinary_load_end = max(s["vaddr"] + s["memsz"] for s in ordinary)
    expected_post_start = align_up(ordinary_load_end)
    if pretouch_segment and pretouch_segment["vaddr"] != expected_post_start:
        raise WorksetError("post PT_LOAD start differs from page-aligned ordinary_load_end")
    regions = []
    excluded = []
    for segment in ordinary:
        if segment["memsz"] == 0:
            continue
        if segment["vaddr"] + segment["memsz"] > metadata["enclave_size"]:
            raise WorksetError("PT_LOAD exceeds signed enclave_size")
        start, end = align_down(segment["vaddr"]), align_up(segment["vaddr"] + segment["memsz"])
        perms = (SI_FLAG_R if segment["flags"] & PF_R else 0) | (SI_FLAG_W if segment["flags"] & PF_W else 0) | (SI_FLAG_X if segment["flags"] & PF_X else 0)
        effects_for_permissions(perms, f"PT_LOAD[{segment['index']}]")
        regions.append({"kind": "PT_LOAD", "segment_index": segment["index"],
                        "start_rva": start, "end_rva": end, "pages": (end - start) // PAGE,
                        "permissions": perms})
    signer, omitted = signer_regions(metadata)
    regions.extend(signer)
    excluded.extend(omitted)
    # A control range must never alias an ordinary committed region.
    for special in omitted:
        if "TCS/SSA/guard" not in special.get("excluded_reason", ""):
            continue
        for region in regions:
            if max(special["start_rva"], region["start_rva"]) < min(special["end_rva"], region["end_rva"]):
                raise WorksetError(f"REG region {region['name']} overlaps excluded control range {special['name']}")
    pt_page_permissions: dict[int, int] = {}
    for segment in ordinary:
        perms = (SI_FLAG_R if segment["flags"] & PF_R else 0) | (SI_FLAG_W if segment["flags"] & PF_W else 0) | (SI_FLAG_X if segment["flags"] & PF_X else 0)
        for page in range(align_down(segment["vaddr"]), align_up(segment["vaddr"] + segment["memsz"]), PAGE):
            pt_page_permissions[page] = pt_page_permissions.get(page, 0) | perms
    relro_ranges = []
    relro_pages = set()
    for relro in profile.relro:
        protected_start = align_down(relro["vaddr"])
        protected_end = align_down(relro["end"])
        if protected_end > protected_start:
            for page in range(protected_start, protected_end, PAGE):
                max_perms = pt_page_permissions.get(page, 0)
                if (max_perms & (SI_FLAG_R | SI_FLAG_W)) != (SI_FLAG_R | SI_FLAG_W) or max_perms & SI_FLAG_X:
                    raise WorksetError(f"PT_GNU_RELRO page {page:#x} is not within an R|W non-X PT_LOAD")
                if not any(region["start_rva"] <= page and page + PAGE <= region["end_rva"] for region in regions):
                    raise WorksetError(f"PT_GNU_RELRO page {page:#x} is absent from committed signer REG layout")
                relro_pages.add(page)
        relro_ranges.append({"segment_index": relro["index"], "start_rva": relro["vaddr"],
                             "end_rva": relro["end"], "protected_start_rva": protected_start,
                             "protected_end_rva": protected_end})
    return {"schema": "atfield-signer-layout-v1", "page_size": PAGE,
            "signed_elf": str(signed.path), "signed_elf_sha256": hashlib.sha256(signed.data).hexdigest(),
            "profile_elf": str(profile.path), "profile_elf_sha256": hashlib.sha256(profile.data).hexdigest(),
            "metadata_version": metadata["version"], "enclave_size": metadata["enclave_size"],
            "ssa_frame_pages": metadata["ssa_frame_pages"],
            "ordinary_load_end": ordinary_load_end, "pretouch_start": expected_post_start,
            "capacity_q": capacity_q, "pretouch_segment": bool(pretouch_segment),
            "regions": regions, "excluded_regions": excluded,
            "relro_ranges": relro_ranges, "relro_pages": sorted(relro_pages),
            "all_committed_reg_pages": len({page for region in regions for page in range(region["start_rva"], region["end_rva"], PAGE)})}


def parse_anchor_symbols(profile: ElfFile) -> dict[int, list[dict]]:
    anchors: dict[int, list[dict]] = {}
    pattern = re.compile(r"__atf_[cn]_[0-9a-f]+_[0-9a-f]+_[0-9a-f]+$")
    for symbol in profile.symbols():
        if not pattern.fullmatch(symbol["name"]):
            continue
        address = symbol["value"]
        try:
            offset = profile.loaded_offset(address)
        except WorksetError:
            continue
        if profile.data[offset] != 0xC3:
            continue
        containing = [seg for seg in profile.loads if seg["vaddr"] <= address < seg["vaddr"] + seg["memsz"] and seg["flags"] & PF_X]
        if len(containing) != 1:
            continue
        anchors.setdefault(align_down(address), []).append({"symbol": symbol["name"], "rva": address})
    for values in anchors.values():
        values.sort(key=lambda item: (item["rva"], item["symbol"]))
    return anchors


def normalized_fields(fields_file: str | Path) -> list[dict]:
    payload = read_json(fields_file)
    if payload.get("schema") != "atfield-fields-v1" or not isinstance(payload.get("fields"), list):
        raise WorksetError(f"expected atfield-fields-v1 manifest: {fields_file}")
    seen = set()
    result = []
    for item in payload["fields"]:
        if not isinstance(item, dict):
            raise WorksetError("each field manifest entry must be an object")
        identity = parse_u64(item.get("id"), "Field id")
        if identity == 0 or identity in seen:
            raise WorksetError(f"zero or duplicate Field id: {item.get('id')!r}")
        seen.add(identity)
        order = item.get("order")
        if not isinstance(order, list) or len(order) != 2:
            raise WorksetError(f"Field {item.get('name')} requires a two-element order key")
        normalized = dict(item)
        normalized["_id_value"] = identity
        normalized["id"] = f"0x{identity:016x}"
        normalized["order"] = [parse_u64(order[0], "payloadOrdinal"), parse_u64(order[1], "functionOrdinal")]
        result.append(normalized)
    result.sort(key=lambda item: (item["order"], item["_id_value"]))
    return result


def edl_public_ecalls(edl_file: str | Path) -> list[str]:
    try:
        source = Path(edl_file).read_text()
    except OSError as exc:
        raise WorksetError(f"cannot read EDL {edl_file}: {exc}") from exc
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"(?m)^\s*#.*$", "", source)
    trusted_blocks = list(re.finditer(r"\btrusted\s*\{", source))
    if len(trusted_blocks) != 1:
        raise WorksetError(f"EDL {edl_file} must have exactly one simple trusted block; found {len(trusted_blocks)}")
    opening = trusted_blocks[0].end() - 1
    depth, closing = 0, None
    for pos in range(opening, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                closing = pos
                break
    if closing is None:
        raise WorksetError(f"EDL {edl_file} has an unterminated trusted block")
    body = source[opening + 1:closing]
    if re.search(r"\bfrom\b|\bimport\b", body):
        raise WorksetError(f"EDL {edl_file} has an import inside trusted; imported ECALL order is unsupported")
    names = []
    for match in re.finditer(r"\bpublic\b", body):
        end = body.find(";", match.end())
        if end < 0:
            raise WorksetError(f"EDL {edl_file} has an unterminated public declaration")
        declaration = body[match.end():end].strip()
        header = declaration.split("(", 1)[0]
        name = re.search(r"([A-Za-z_][A-Za-z_0-9]*)\s*$", header)
        if "(" not in declaration or not name:
            raise WorksetError(f"EDL {edl_file} has a complex public declaration near {declaration[:100]!r}")
        names.append(name.group(1))
    if not names:
        raise WorksetError(f"EDL {edl_file} contains no public ECALL declarations")
    if len(names) != len(set(names)):
        raise WorksetError(f"EDL {edl_file} repeats a public ECALL name")
    return names


def readable_field_names(field: dict) -> set[str]:
    values = {field.get("name"), field.get("demangled_name")}
    result = {value.strip() for value in values if isinstance(value, str) and value.strip()}
    for value in list(result):
        base = value.split("(", 1)[0].strip().split("::")[-1].strip()
        if base:
            result.add(base)
    return result


def resolve_field_function(function: str, fields: list[dict], selector_index: int) -> dict:
    exact = []
    for field in fields:
        if function in (field.get("function"), field.get("linkage_name")):
            exact.append(field)
    exact = list({field["id"]: field for field in exact}.values())
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise WorksetError(f"selector {selector_index} linkage symbol {function!r} resolves to multiple Fields")
    readable = [field for field in fields if function in readable_field_names(field)]
    readable = list({field["id"]: field for field in readable}.values())
    if len(readable) == 1:
        return readable[0]
    if len(readable) > 1:
        names = ", ".join(field.get("linkage_name", field.get("function", field["id"])) for field in readable)
        raise WorksetError(f"selector {selector_index} readable function {function!r} is ambiguous ({names}); use an exact linkage_name")
    raise WorksetError(f"selector {selector_index} references unknown Field function/linkage {function!r}")


def resolve_selectors(selector_file: str | Path | None, fields: list[dict],
                      edl_file: str | Path | None) -> list[dict]:
    if selector_file is None:
        if edl_file is not None:
            raise WorksetError("--edl requires --selectors so every public selector can be mapped")
        return []
    if edl_file is None:
        raise WorksetError("--selectors requires --edl to verify ECALL names and public order")
    payload = read_json(selector_file)
    if payload.get("schema") != "atfield-selectors-v1" or not isinstance(payload.get("selectors"), list):
        raise WorksetError(f"expected atfield-selectors-v1 manifest: {selector_file}")
    expected_names = edl_public_ecalls(edl_file)
    supplied = payload["selectors"]
    if len(supplied) != len(expected_names):
        raise WorksetError(f"selector map has {len(supplied)} entries, EDL declares {len(expected_names)} public ECALLs")
    resolved = []
    for expected_index, (selector, expected_name) in enumerate(zip(supplied, expected_names)):
        if not isinstance(selector, dict):
            raise WorksetError("each selector entry must be an object")
        index = parse_u64(selector.get("ecall_index"), "ecall_index")
        if index != expected_index:
            raise WorksetError(f"selector index {index} is out of EDL order; expected {expected_index}")
        name = selector.get("name")
        functions = selector.get("reachable_functions")
        if name != expected_name:
            raise WorksetError(f"selector {index} name {name!r} differs from EDL public ECALL {expected_name!r}")
        if not isinstance(functions, list):
            raise WorksetError(f"selector {index} requires reachable_functions")
        ids = []
        for function in functions:
            if not isinstance(function, str) or not function:
                raise WorksetError(f"selector {index} reachable_functions entries must be nonempty strings")
            ids.append(resolve_field_function(function, fields, index)["id"])
        if len(set(ids)) != len(ids):
            raise WorksetError(f"selector {index} repeats a reachable function/Field")
        resolved.append({"ecall_index": index, "name": name,
                         "reachable_functions": functions, "reachable_fields": ids})
    return resolved


def produce_workset(profile: ElfFile, layout: dict, fields_file: str | Path,
                    selectors_file: str | Path | None, edl_file: str | Path | None) -> dict:
    anchors = parse_anchor_symbols(profile)
    page_permissions: dict[int, int] = {}
    page_origins: dict[int, list[str]] = {}
    for region in layout["regions"]:
        for page in range(region["start_rva"], region["end_rva"], PAGE):
            page_permissions[page] = page_permissions.get(page, 0) | region["permissions"]
            page_origins.setdefault(page, []).append(region["name"] if region["kind"] == "signer" else f"PT_LOAD[{region['segment_index']}]")
    if not page_permissions:
        raise WorksetError("signed layout produced no committed business REG pages")
    page_records = []
    relro_pages = set(layout.get("relro_pages", []))
    for page in sorted(page_permissions):
        max_permissions = page_permissions[page]
        permissions = max_permissions
        if page in relro_pages:
            if (permissions & (SI_FLAG_R | SI_FLAG_W)) != (SI_FLAG_R | SI_FLAG_W) or permissions & SI_FLAG_X:
                raise WorksetError(f"RELRO page {page:#x} lacks max R|W non-X permissions")
            permissions &= ~SI_FLAG_W
        effects = effects_for_permissions(permissions, f"page {page:#x}")
        record = {"page_rva": page, "effects": effects, "max_permissions": max_permissions,
                  "relro": page in relro_pages, "origins": sorted(set(page_origins[page]))}
        if "X" in effects:
            choices = anchors.get(page, [])
            if not choices:
                raise WorksetError(f"X page {page:#x} lacks a final same-page C3 anchor symbol")
            record["code_anchor"] = choices[0]
        if "R" in effects or "W" in effects:
            record["data_anchor_rva"] = page
            record["data_width"] = 1
        page_records.append(record)
    fields = normalized_fields(fields_file)
    if not fields:
        raise WorksetError("fields.json contains no Field entries")
    selectors = resolve_selectors(selectors_file, fields, edl_file)
    return {"schema": "atfield-workset-v1", "page_size": PAGE,
            "layout": layout, "field_manifest": str(fields_file),
            "selector_manifest": str(selectors_file) if selectors_file else None,
            "edl_manifest": str(edl_file) if edl_file else None,
            "selectors": selectors,
            "fields": [{"id": field["id"], "name": field.get("name", field.get("function", field["id"])),
                        "function": field.get("function"), "order": field["order"],
                        "stack_bytes": field.get("stack_bytes"), "pages": page_records}
                       for field in fields]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Produce full committed REG Field worksets from signed SGX metadata.")
    parser.add_argument("--profile-elf", required=True, help="unsigned Profile ELF with symbol table and finalized PT_LOADs")
    parser.add_argument("--signed-elf", required=True, help="matching signer output containing .note.sgxmeta")
    parser.add_argument("--fields", required=True, help="build/field/fields.json")
    parser.add_argument("--capacity-q", required=True, type=int, help="protect-configured post RX PT_LOAD capacity in bytes")
    parser.add_argument("--selectors", help="public selector map with reachable_functions names; IDs are resolved from fields.json")
    parser.add_argument("--edl", help="simple target EDL used to verify public ECALL indices and names; required with --selectors")
    parser.add_argument("--layout-out", help="write the extracted signer layout intermediate JSON")
    parser.add_argument("--layout", help="consume a previously extracted layout JSON instead of parsing the note again")
    parser.add_argument("--out", required=True, help="write atfield-workset-v1 JSON")
    args = parser.parse_args()
    try:
        if args.capacity_q <= 0 or args.capacity_q % PAGE:
            raise WorksetError("--capacity-q must be a positive multiple of 4096")
        profile = ElfFile(args.profile_elf)
        signed = ElfFile(args.signed_elf)
        if args.layout:
            layout = read_json(args.layout)
            if layout.get("schema") != "atfield-signer-layout-v1":
                raise WorksetError("--layout must be an atfield-signer-layout-v1 JSON")
            if layout.get("signed_elf_sha256") != hashlib.sha256(signed.data).hexdigest():
                raise WorksetError("--layout does not match --signed-elf identity")
            if layout.get("profile_elf_sha256") != hashlib.sha256(profile.data).hexdigest():
                raise WorksetError("--layout does not match --profile-elf identity")
            if layout.get("capacity_q") != args.capacity_q:
                raise WorksetError("--layout Q differs from --capacity-q")
        else:
            layout = make_layout(profile, signed, args.capacity_q)
        if args.layout_out:
            write_json(args.layout_out, layout)
        result = produce_workset(profile, layout, args.fields, args.selectors, args.edl)
        write_json(args.out, result)
        n = len(result["fields"][0]["pages"])
        print(f"workset: fields={len(result['fields'])} committed_REG_pages_per_field={n} "
              f"ordinary_load_end={layout['ordinary_load_end']:#x} post_start={layout['pretouch_start']:#x} "
              f"Q={layout['capacity_q']} excluded_layout_ranges={len(layout['excluded_regions'])}")
        print(f"wrote {args.out}")
        return 0
    except (WorksetError, OSError, struct.error) as exc:
        print(f"workset: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
