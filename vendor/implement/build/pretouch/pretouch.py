#!/usr/bin/env python3
"""Emit Profile/Final ELF post-load Field pretouch bytes and verify FinalElf."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "workset"))
from workset import (  # noqa: E402
    PAGE, PF_R, PF_W, PF_X, ElfFile, WorksetError, align_up,
    elf_load_equivalence, make_layout, normalized_fields, parse_signed_metadata,
    read_json, write_json,
)


def fail(message: str) -> None:
    raise WorksetError(message)


def unique_symbol(elf: ElfFile, name: str) -> dict:
    return elf.unique_symbol(name)


def fields_by_id(fields_path: str) -> list[dict]:
    return normalized_fields(fields_path)


def workset_by_id(workset: dict) -> dict[str, dict]:
    if workset.get("schema") != "atfield-workset-v1":
        fail("expected atfield-workset-v1")
    result = {}
    for field in workset.get("fields", []):
        identity = field.get("id")
        if not isinstance(identity, str) or identity in result:
            fail(f"invalid or duplicate workset Field id: {identity!r}")
        result[identity] = field
    return result


def field_pages(field: dict) -> list[dict]:
    pages = field.get("pages")
    if not isinstance(pages, list):
        fail(f"Field {field.get('id')} pages must be an array")
    ordered = sorted(pages, key=lambda p: p["page_rva"])
    prior = -1
    for page in ordered:
        rva = page.get("page_rva")
        effects = page.get("effects")
        if not isinstance(rva, int) or rva < 0 or rva % PAGE or rva <= prior:
            fail(f"Field {field.get('id')} has unaligned or duplicate page RVA {rva!r}")
        if not isinstance(effects, list) or not effects or any(e not in ("X", "R", "W") for e in effects):
            fail(f"Field {field.get('id')} page {rva:#x} has invalid effects")
        effects = list(dict.fromkeys(effects))
        if "X" in effects and "W" in effects:
            fail(f"Field {field.get('id')} page {rva:#x} is X+W")
        if "W" in effects and "R" not in effects:
            fail(f"Field {field.get('id')} page {rva:#x} W template needs R|W")
        page["effects"] = effects
        if "X" in effects:
            code = page.get("code_anchor")
            if not isinstance(code, dict) or not isinstance(code.get("symbol"), str) or code.get("rva", -1) // PAGE != rva // PAGE:
                fail(f"Field {field.get('id')} page {rva:#x} lacks same-page code_anchor")
        if "R" in effects or "W" in effects:
            target = page.get("data_anchor_rva")
            if not isinstance(target, int) or not (rva <= target < rva + PAGE):
                fail(f"Field {field.get('id')} page {rva:#x} lacks a same-page data anchor")
        prior = rva
    return ordered


def rel32(opcode: int, source_rva: int, target_rva: int) -> bytes:
    delta = target_rva - (source_rva + 5)
    if not -(1 << 31) <= delta < (1 << 31):
        fail(f"rel32 out of range: source={source_rva:#x} target={target_rva:#x}")
    return bytes([opcode]) + struct.pack("<i", delta)


def disp32(target_rva: int, next_rva: int, label: str) -> bytes:
    delta = target_rva - next_rva
    if not -(1 << 31) <= delta < (1 << 31):
        fail(f"disp32 out of range for {label}: target={target_rva:#x} next={next_rva:#x}")
    return struct.pack("<i", delta)


def generate_body(field: dict, facts: dict, start_rva: int, final_elf: ElfFile | None = None) -> tuple[bytes, list[dict]]:
    code = bytearray()
    target_records = []
    for page in field_pages(facts):
        page_start = start_rva + len(code)
        effects = page["effects"]
        if "X" in effects:
            anchor = page["code_anchor"]
            target = anchor["rva"]
            if final_elf:
                actual = unique_symbol(final_elf, anchor["symbol"]) ["value"]
                if actual != target:
                    fail(f"anchor RVA changed for {anchor['symbol']}: expected {target:#x}, found {actual:#x}")
                if final_elf.data[final_elf.loaded_offset(actual)] != 0xC3:
                    fail(f"anchor {anchor['symbol']} no longer contains C3")
            if target // PAGE != page["page_rva"] // PAGE:
                fail(f"X page {page['page_rva']:#x} anchor {target:#x} is on another page")
            code.extend(rel32(0xE8, start_rva + len(code), target))
        if "W" in effects:
            target = page["data_anchor_rva"]
            instr = start_rva + len(code)
            code.extend(b"\xf0\x80\x0d")
            code.extend(disp32(target, instr + 8, f"Field {field['id']} W page {page['page_rva']:#x}"))
            code.append(0)
        elif "R" in effects:
            target = page["data_anchor_rva"]
            instr = start_rva + len(code)
            code.extend(b"\x8a\x05")
            code.extend(disp32(target, instr + 6, f"Field {field['id']} R page {page['page_rva']:#x}"))
        target_records.append({"page_rva": page["page_rva"], "effects": effects,
                              "start_rva": page_start, "end_rva": start_rva + len(code)})
    code.extend(b"\x0f\xae\xe8")
    return bytes(code), target_records


def emit_assembly(workset_path: str | None, fields_path: str, mode: str,
                  capacity_q: int, output_path: str, output_json: str) -> None:
    fields = fields_by_id(fields_path)
    workset = read_json(workset_path) if workset_path else None
    if mode == "final" and workset is None:
        fail("Final pretouch emission requires signed Profile workset.json")
    facts_by_id = workset_by_id(workset) if workset else {}
    if workset and {f"0x{field['_id_value']:016x}" for field in fields} != set(facts_by_id):
        fail("fields.json and workset Field ID sets differ")
    if workset and workset.get("field_manifest_sha256") != hashlib.sha256(Path(fields_path).read_bytes()).hexdigest():
        fail("fields.json bytes differ from the frozen workset manifest")
    capacity = workset["layout"]["capacity_q"] if workset else capacity_q
    if capacity != capacity_q:
        fail("--capacity-q differs from frozen workset")
    if capacity <= 0 or capacity % PAGE:
        fail("Q must be a positive multiple of 4096")
    post_rva = workset["layout"]["pretouch_start"] if workset else None
    snippets = [".section .atfield_pretouch,\"ax\",@progbits", ".p2align 12"]
    blocks = []
    offset = 0
    for field in fields:
        identity = f"0x{field['_id_value']:016x}"
        facts = facts_by_id.get(identity)
        if mode == "final" and facts is None:
            fail(f"signed Profile workset lacks Field {identity}")
        symbol = field.get("pretouch_symbol")
        continuation = field.get("continuation_symbol")
        if not isinstance(symbol, str) or not isinstance(continuation, str):
            fail(f"Field {identity} lacks pretouch_symbol or continuation_symbol")
        begin = offset
        snippets.extend([f".globl {symbol}", f".hidden {symbol}", f".type {symbol},@function", f"{symbol}:"])
        if mode == "profile":
            snippets.extend([".byte 0xe9", f".long {continuation} - . - 4"])
            size = 5
        else:
            for page in field_pages(facts):
                effects = page["effects"]
                if "X" in effects:
                    code_symbol = page["code_anchor"]["symbol"]
                    snippets.extend([".byte 0xe8", f".long {code_symbol} - . - 4"])
                    offset += 5
                if "W" in effects:
                    target = page["data_anchor_rva"]
                    snippets.extend([".byte 0xf0,0x80,0x0d", f".long {target} - . - 5", ".byte 0x00"])
                    offset += 8
                elif "R" in effects:
                    target = page["data_anchor_rva"]
                    snippets.extend([".byte 0x8a,0x05", f".long {target} - . - 4"])
                    offset += 6
            snippets.append(".byte 0x0f,0xae,0xe8")
            offset += 3
            snippets.extend([".byte 0xe9", f".long {continuation} - . - 4"])
            offset += 5
            size = offset - begin
        if mode == "profile":
            offset += size
        snippets.append(f".size {symbol}, . - {symbol}")
        blocks.append({"field_id": identity, "symbol": symbol, "continuation_symbol": continuation,
                       "begin_offset": begin, "end_offset": offset, "size": size})
    if offset > capacity:
        fail(f"pretouch code needs {offset} bytes, configured Q={capacity}; increase Q and rebuild Profile")
    snippets.extend([f".fill {capacity - offset},1,0x90", ".section .note.GNU-stack,\"\",@progbits"])
    text = "\n".join(snippets) + "\n"
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    summary = {"schema": "atfield-pretouch-output-v1", "mode": mode,
               "workset_sha256": hashlib.sha256(Path(workset_path).read_bytes()).hexdigest() if workset_path else None,
               "fields_sha256": hashlib.sha256(Path(fields_path).read_bytes()).hexdigest(),
               "capacity_q": capacity, "pretouch_start": post_rva,
               "code_bytes": offset, "blocks": blocks, "assembly": str(target)}
    write_json(output_json, summary)
    print(f"pretouch emit: mode={mode} fields={len(blocks)} code_bytes={offset} Q={capacity}")
    print(f"wrote {output_path} and {output_json}")


def load_ranges(elf: ElfFile, exclude: dict | None = None) -> list[dict]:
    return [segment for segment in elf.loads if not exclude or segment["index"] != exclude["index"]]


def verify_load_bytes(profile: ElfFile, final: ElfFile, fields: list[dict], profile_post: dict, final_post: dict) -> None:
    profile_loads = load_ranges(profile, profile_post)
    final_loads = load_ranges(final, final_post)
    ident = lambda s: (s["vaddr"], s["filesz"], s["memsz"], s["flags"], s["align"])
    if [ident(s) for s in profile_loads] != [ident(s) for s in final_loads]:
        fail("Profile and Final ordinary PT_LOAD layouts differ")
    permitted: dict[int, set[int]] = {}
    for field in fields:
        continuation = unique_symbol(final, field["continuation_symbol"])["value"]
        profile_continuation = unique_symbol(profile, field["continuation_symbol"])["value"]
        if continuation != profile_continuation:
            fail(f"continuation RVA changed for {field['id']}")
        marker_rva = continuation - 5
        for elf, expected_target, label in (
                (profile, unique_symbol(profile, field["pretouch_symbol"])["value"], "Profile"),
                (final, unique_symbol(final, field["pretouch_symbol"])["value"], "Final")):
            fileoff = elf.loaded_offset(marker_rva, 5)
            if elf.data[fileoff] != 0xE9:
                fail(f"{label} marker at {marker_rva:#x} is not E9 rel32 for {field['id']}")
            actual = marker_rva + 5 + struct.unpack_from("<i", elf.data, fileoff + 1)[0]
            if actual != expected_target:
                fail(f"{label} marker for {field['id']} targets {actual:#x}, expected {expected_target:#x}")
            # Exactly the four-byte rel32 immediate is allowed to differ.
            segment = next(s for s in elf.loads if s["vaddr"] <= marker_rva < s["vaddr"] + s["memsz"])
            rel = marker_rva - segment["vaddr"]
            permitted.setdefault(segment["index"], set()).update(range(rel + 1, rel + 5))
    for left, right in zip(profile_loads, final_loads):
        a = profile.data[left["offset"]:left["offset"] + left["filesz"]]
        b = final.data[right["offset"]:right["offset"] + right["filesz"]]
        if len(a) != len(b):
            fail(f"ordinary segment file size changed at {left['vaddr']:#x}")
        allowed = permitted.get(left["index"], set())
        for offset, (x, y) in enumerate(zip(a, b)):
            if x != y and offset not in allowed:
                fail(f"ordinary load byte changed outside marker rel32 at RVA {left['vaddr'] + offset:#x}")


def verify_final(profile_path: str, signed_profile_path: str, final_path: str, signed_final_path: str,
                 workset_path: str, fields_path: str, capacity_q: int, output_json: str) -> None:
    profile, signed_profile = ElfFile(profile_path), ElfFile(signed_profile_path)
    final, signed_final = ElfFile(final_path), ElfFile(signed_final_path)
    elf_load_equivalence(profile, signed_profile)
    elf_load_equivalence(final, signed_final)
    workset = read_json(workset_path)
    facts_by_id = workset_by_id(workset)
    fields = fields_by_id(fields_path)
    if {f"0x{f['_id_value']:016x}" for f in fields} != set(facts_by_id):
        fail("fields.json and workset Field ID sets differ")
    fields_sha256 = hashlib.sha256(Path(fields_path).read_bytes()).hexdigest()
    if workset.get("field_manifest_sha256") != fields_sha256:
        fail("fields.json bytes differ from the frozen workset manifest")
    if workset["layout"].get("profile_elf_sha256") != hashlib.sha256(profile.data).hexdigest():
        fail("Profile ELF bytes differ from the workset input")
    if workset["layout"].get("signed_elf_sha256") != hashlib.sha256(signed_profile.data).hexdigest():
        fail("signed Profile ELF bytes differ from the workset input")
    for elf, label in ((profile, "Profile"), (final, "Final")):
        note = parse_signed_metadata(signed_profile if label == "Profile" else signed_final)
        if note["enclave_size"] != workset["layout"]["enclave_size"]:
            fail(f"{label} signer enclave_size differs from workset layout")
    from workset import locate_pretouch_segment
    profile_section, profile_post = locate_pretouch_segment(profile, capacity_q)
    final_section, final_post = locate_pretouch_segment(final, capacity_q)
    if not profile_section or not final_section:
        fail("Profile and Final must each contain .atfield_pretouch")
    ordinary_end = workset["layout"]["ordinary_load_end"]
    expected_start = align_up(ordinary_end)
    if profile_post["vaddr"] != expected_start or final_post["vaddr"] != expected_start:
        fail("Profile/Final post PT_LOAD start differs from frozen ordinary_load_end")
    if profile_section["size"] != capacity_q or final_section["size"] != capacity_q:
        fail("Profile/Final .atfield_pretouch does not fill Q")
    if profile_post["vaddr"] != final_post["vaddr"]:
        fail("Profile/Final post PT_LOAD address differs")
    profile_metadata = parse_signed_metadata(signed_profile)
    final_metadata = parse_signed_metadata(signed_final)
    if (profile_metadata["version"], profile_metadata["layout_entries"]) != (final_metadata["version"], final_metadata["layout_entries"]):
        fail("signer layout changed between Profile and Final")
    profile_layout = make_layout(profile, signed_profile, capacity_q)
    final_layout = make_layout(final, signed_final, capacity_q)
    frozen_keys = ("metadata_version", "ssa_frame_pages", "page_size", "enclave_size",
                   "ordinary_load_end", "pretouch_start", "capacity_q", "pretouch_segment", "regions",
                   "excluded_regions", "relro_ranges", "relro_pages")
    for key in frozen_keys:
        if profile_layout.get(key) != workset["layout"].get(key):
            fail(f"Profile layout differs from frozen workset at {key}")
        if final_layout.get(key) != workset["layout"].get(key):
            fail(f"Final layout differs from frozen workset at {key}")
    verify_load_bytes(profile, final, fields, profile_post, final_post)
    section_bytes = final.section_data(final_section)
    expected_offset = 0
    block_result = []
    for field in fields:
        identity = f"0x{field['_id_value']:016x}"
        facts = facts_by_id[identity]
        symbol = field.get("pretouch_symbol")
        if not isinstance(symbol, str):
            fail(f"Field {identity} lacks pretouch_symbol")
        actual_start = unique_symbol(final, symbol)["value"]
        wanted_start = final_section["addr"] + expected_offset
        if actual_start != wanted_start:
            fail(f"Field {identity} pretouch block is not contiguous at {wanted_start:#x}")
        expected, target_records = generate_body(field, facts, actual_start, final)
        continuation = unique_symbol(final, field["continuation_symbol"])["value"]
        expected += rel32(0xE9, actual_start + len(expected), continuation)
        expected_end = expected_offset + len(expected)
        if section_bytes[expected_offset:expected_end] != expected:
            fail(f"Final pretouch bytes differ from fixed X/R/W template for Field {identity}")
        continuation_after = unique_symbol(final, field["continuation_symbol"])["value"]
        body_symbol = unique_symbol(final, field["body_symbol"])
        body = body_symbol["value"]
        if continuation_after != unique_symbol(profile, field["continuation_symbol"])["value"]:
            fail(f"continuation moved for Field {identity}")
        if body == 0 or not any(seg["flags"] & PF_X and seg["vaddr"] <= body < seg["vaddr"] + seg["memsz"] for seg in load_ranges(final, final_post)):
            fail(f"body symbol is outside ordinary executable PT_LOADs for Field {identity}")
        marker_name = field.get("marker_symbol")
        if not isinstance(marker_name, str) or not marker_name:
            fail(f"Field {identity} lacks its manifest marker_symbol identifier")
        marker_rva = continuation - 5
        marker_off = final.loaded_offset(marker_rva, 5)
        if final.data[marker_off] != 0xE9:
            fail(f"marker identified by {marker_name} is not a five-byte E9 site for Field {identity}")
        marker_rva = continuation - 5
        marker_off = final.loaded_offset(marker_rva, 5)
        marker_target = marker_rva + 5 + struct.unpack_from("<i", final.data, marker_off + 1)[0]
        if marker_target != actual_start:
            fail(f"marker for Field {identity} does not jump to its unique post block")
        end_rva = actual_start + len(expected)
        block_result.append({"field_id": identity, "symbol": symbol,
                             "begin_rva": actual_start, "end_rva": end_rva,
                             "size": len(expected), "target_pages": target_records})
        expected_offset = expected_end
    if expected_offset > capacity_q:
        fail("generated Field blocks exceed Q")
    if any(byte != 0x90 for byte in section_bytes[expected_offset:]):
        fail("Final post PT_LOAD padding is not fixed 0x90 fill")
    result = {"schema": "atfield-pretouch-final-v1", "final_elf": str(final_path),
              "workset_sha256": hashlib.sha256(Path(workset_path).read_bytes()).hexdigest(),
              "fields_sha256": fields_sha256,
              "final_elf_sha256": hashlib.sha256(final.data).hexdigest(),
              "signed_final_elf": str(signed_final_path), "signed_final_elf_sha256": hashlib.sha256(signed_final.data).hexdigest(),
              "post_start": final_section["addr"], "capacity_q": capacity_q,
              "code_bytes": expected_offset, "blocks": block_result}
    write_json(output_json, result)
    print(f"pretouch verify: fields={len(block_result)} post={final_section['addr']:#x} code_bytes={expected_offset} Q={capacity_q}")
    print(f"wrote {output_json}")


def atomic_write_elf(path: str, data: bytes, mode: int) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        os.fchmod(fd, mode & 0o777)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def finalize_profile(profile_path: str, signed_profile_path: str, workset_path: str,
                     fields_path: str, capacity_q: int, output_path: str,
                     output_json: str) -> None:
    profile = ElfFile(profile_path)
    signed_profile = ElfFile(signed_profile_path)
    elf_load_equivalence(profile, signed_profile)
    if Path(profile_path).resolve() == Path(output_path).resolve():
        fail("Final output must have a separate path from Profile ELF")
    workset = read_json(workset_path)
    facts_by_id = workset_by_id(workset)
    fields = fields_by_id(fields_path)
    if {f"0x{field['_id_value']:016x}" for field in fields} != set(facts_by_id):
        fail("fields.json and workset Field ID sets differ")
    if workset.get("field_manifest_sha256") != hashlib.sha256(Path(fields_path).read_bytes()).hexdigest():
        fail("fields.json bytes differ from the frozen workset manifest")
    expected_layout = workset["layout"]
    if expected_layout.get("profile_elf_sha256") != hashlib.sha256(profile.data).hexdigest():
        fail("Profile ELF bytes differ from the frozen workset input")
    if expected_layout.get("signed_elf_sha256") != hashlib.sha256(signed_profile.data).hexdigest():
        fail("signed Profile ELF bytes differ from the frozen workset input")
    if expected_layout.get("capacity_q") != capacity_q:
        fail("--capacity-q differs from the frozen workset")
    actual_layout = make_layout(profile, signed_profile, capacity_q)
    for key in ("metadata_version", "ssa_frame_pages", "page_size", "enclave_size",
                "ordinary_load_end", "pretouch_start", "capacity_q", "pretouch_segment", "regions",
                "excluded_regions", "relro_ranges", "relro_pages"):
        if expected_layout.get(key) != actual_layout.get(key):
            fail(f"Profile signer layout differs from frozen workset at {key}")
    from workset import locate_pretouch_segment
    post_section, post_segment = locate_pretouch_segment(profile, capacity_q)
    if not post_section or not post_segment:
        fail("Profile must already contain the reserved .atfield_pretouch RX PT_LOAD")

    final_code = bytearray()
    blocks = []
    pending_symbols = []
    pending_markers = []
    for field in fields:
        identity = f"0x{field['_id_value']:016x}"
        facts = facts_by_id[identity]
        pretouch_symbol = field.get("pretouch_symbol")
        continuation_symbol = field.get("continuation_symbol")
        body_symbol = field.get("body_symbol")
        if not all(isinstance(value, str) and value for value in
                   (pretouch_symbol, continuation_symbol, body_symbol)):
            fail(f"Field {identity} lacks pretouch, continuation or body symbol")
        old_entry = unique_symbol(profile, pretouch_symbol)
        expected_old_entry = post_section["addr"] + 5 * len(blocks)
        if old_entry["value"] != expected_old_entry or old_entry["size"] != 5:
            fail(f"Profile stub for Field {identity} is not the expected contiguous five-byte jmp")
        continuation = unique_symbol(profile, continuation_symbol)["value"]
        unique_symbol(profile, body_symbol)
        marker_rva = continuation - 5
        marker_offset = profile.loaded_offset(marker_rva, 5)
        if profile.data[marker_offset] != 0xE9:
            fail(f"Profile marker for Field {identity} is not E9 rel32")
        old_target = marker_rva + 5 + struct.unpack_from("<i", profile.data, marker_offset + 1)[0]
        if old_target != old_entry["value"]:
            fail(f"Profile marker for Field {identity} does not target its stub")

        start_rva = post_section["addr"] + len(final_code)
        body, target_records = generate_body(field, facts, start_rva, profile)
        body += rel32(0xE9, start_rva + len(body), continuation)
        final_code.extend(body)
        end_rva = start_rva + len(body)
        definitions = [symbol for symbol in profile.symbols()
                       if symbol["name"] == pretouch_symbol and symbol["shndx"] != 0]
        if not definitions:
            fail(f"Profile has no symbol-table definition for {pretouch_symbol}")
        pending_symbols.append((pretouch_symbol, start_rva, len(body), definitions))
        pending_markers.append((identity, marker_offset, marker_rva, start_rva))
        blocks.append({"field_id": identity, "symbol": pretouch_symbol,
                       "begin_rva": start_rva, "end_rva": end_rva,
                       "size": len(body), "target_pages": target_records})

    if len(final_code) > capacity_q:
        fail(f"pretouch code needs {len(final_code)} bytes, configured Q={capacity_q}; rebuild Profile with larger Q")
    content = bytes(final_code) + b"\x90" * (capacity_q - len(final_code))
    updated = bytearray(profile.data)
    start = post_section["offset"]
    updated[start:start + capacity_q] = content
    for symbol_name, value, size, definitions in pending_symbols:
        seen_offsets = set()
        for symbol in definitions:
            file_offset = symbol["file_offset"]
            if file_offset in seen_offsets:
                continue
            seen_offsets.add(file_offset)
            struct.pack_into("<QQ", updated, file_offset + 8, value, size)
    for identity, marker_offset, marker_rva, target in pending_markers:
        updated[marker_offset + 1:marker_offset + 5] = disp32(target, marker_rva + 5, f"Field {identity} marker")

    atomic_write_elf(output_path, bytes(updated), profile.path.stat().st_mode)
    final = ElfFile(output_path)
    from workset import locate_pretouch_segment
    final_section, final_segment = locate_pretouch_segment(final, capacity_q)
    if not final_section or not final_segment:
        fail("generated Final lost its post RX PT_LOAD")
    if [(s["vaddr"], s["filesz"], s["memsz"], s["flags"], s["align"]) for s in final.loads] != [
            (s["vaddr"], s["filesz"], s["memsz"], s["flags"], s["align"]) for s in profile.loads]:
        fail("Finalization changed program-header load layout")
    verify_load_bytes(profile, final, fields, post_segment, final_segment)
    if final.section_data(final_section) != content:
        fail("generated post RX bytes failed immediate reread")
    for field, block in zip(fields, blocks):
        symbol = unique_symbol(final, block["symbol"])
        if (symbol["value"], symbol["size"]) != (block["begin_rva"], block["size"]):
            fail(f"Final symbol mismatch for Field {block['field_id']}")
    result = {"schema": "atfield-pretouch-finalized-v1", "profile_elf": str(profile_path),
              "workset_sha256": hashlib.sha256(Path(workset_path).read_bytes()).hexdigest(),
              "fields_sha256": hashlib.sha256(Path(fields_path).read_bytes()).hexdigest(),
              "profile_elf_sha256": hashlib.sha256(profile.data).hexdigest(),
              "final_elf": str(output_path), "final_elf_sha256": hashlib.sha256(final.data).hexdigest(),
              "post_start": final_section["addr"], "capacity_q": capacity_q,
              "code_bytes": len(final_code), "blocks": blocks}
    write_json(output_json, result)
    print(f"pretouch finalize: fields={len(blocks)} post={final_section['addr']:#x} code_bytes={len(final_code)} Q={capacity_q}")
    print(f"wrote {output_path} and {output_json}; sign Final ELF next")


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit or verify the shared per-Field post-RX pretouch blocks.")
    commands = parser.add_subparsers(dest="command", required=True)
    emit = commands.add_parser("emit", help="emit Profile stub or Final fixed-template assembly")
    emit.add_argument("--workset", help="required for Final mode; signed Profile workset.json")
    emit.add_argument("--fields", required=True)
    emit.add_argument("--mode", choices=("profile", "final"), required=True)
    emit.add_argument("--capacity-q", required=True, type=int)
    emit.add_argument("--out-asm", required=True)
    emit.add_argument("--out-json", required=True)
    finalize = commands.add_parser("finalize", help="fill Profile's reserved RX segment and patch marker rel32s in place")
    finalize.add_argument("--profile-elf", required=True)
    finalize.add_argument("--signed-profile-elf", required=True)
    finalize.add_argument("--workset", required=True)
    finalize.add_argument("--fields", required=True)
    finalize.add_argument("--capacity-q", required=True, type=int)
    finalize.add_argument("--out-elf", required=True)
    finalize.add_argument("--out-json", required=True)
    verify = commands.add_parser("verify", help="verify frozen loads, marker jumps, exact machine templates and signed layout")
    verify.add_argument("--profile-elf", required=True)
    verify.add_argument("--signed-profile-elf", required=True)
    verify.add_argument("--final-elf", required=True)
    verify.add_argument("--signed-final-elf", required=True)
    verify.add_argument("--workset", required=True)
    verify.add_argument("--fields", required=True)
    verify.add_argument("--capacity-q", required=True, type=int)
    verify.add_argument("--out-json", required=True)
    args = parser.parse_args()
    try:
        if args.command == "emit":
            emit_assembly(args.workset, args.fields, args.mode, args.capacity_q,
                          args.out_asm, args.out_json)
        elif args.command == "finalize":
            finalize_profile(args.profile_elf, args.signed_profile_elf, args.workset,
                             args.fields, args.capacity_q, args.out_elf, args.out_json)
        else:
            verify_final(args.profile_elf, args.signed_profile_elf, args.final_elf,
                         args.signed_final_elf, args.workset, args.fields,
                         args.capacity_q, args.out_json)
        return 0
    except (WorksetError, OSError, ValueError, struct.error) as exc:
        print(f"pretouch: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
