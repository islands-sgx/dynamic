#!/usr/bin/env python3
"""Build the fixed little-endian ReadyTable v3 for public ECALL selectors."""
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
    PAGE, ElfFile, WorksetError, make_layout, normalized_fields,
    parse_u64, read_json, write_json,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pretouch"))
from pretouch import unique_symbol  # noqa: E402

VERSION = 3


def fail(message: str) -> None:
    raise WorksetError(message)


def check_layout(expected: dict, actual: dict) -> None:
    keys = ("schema", "metadata_version", "ssa_frame_pages", "page_size", "enclave_size",
            "ordinary_load_end", "pretouch_start", "capacity_q", "pretouch_segment", "regions", "excluded_regions",
            "relro_ranges", "relro_pages")
    for key in keys:
        if expected.get(key) != actual.get(key):
            fail(f"final signer layout differs from frozen workset at {key}")


def read_selectors(workset: dict) -> list[dict]:
    selectors = workset.get("selectors")
    fields = {field.get("id") for field in workset.get("fields", [])}
    if not isinstance(selectors, list):
        fail("workset.json lacks resolved selector mappings; rerun workset.py --selectors")
    seen = set()
    result = []
    for item in selectors:
        if not isinstance(item, dict):
            fail("each selector must be an object")
        index = parse_u64(item.get("ecall_index"), "ecall_index")
        if index in seen:
            fail(f"duplicate public ecall_index {index}")
        seen.add(index)
        name = item.get("name")
        reachable = item.get("reachable_fields")
        if not isinstance(name, str) or not isinstance(reachable, list):
            fail(f"selector {index} requires name and resolved reachable_fields")
        ids = []
        for value in reachable:
            identity = parse_u64(value, "reachable Field id")
            key = f"0x{identity:016x}"
            if key not in fields:
                fail(f"selector {index} references unknown Field {key}")
            ids.append(key)
        if len(set(ids)) != len(ids):
            fail(f"selector {index} repeats a reachable Field")
        result.append({"ecall_index": index, "name": name, "reachable_fields": ids})
    result.sort(key=lambda x: x["ecall_index"])
    if not result:
        fail("workset selector mapping contains no public non-switchless ECALL selectors")
    return result

def write_bytes(path: str, data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
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


def build_ready(workset_path: str, fields_path: str,
                pretouch_path: str, final_path: str, signed_final_path: str,
                output_path: str, json_path: str) -> None:
    workset = read_json(workset_path)
    if workset.get("schema") != "atfield-workset-v1":
        fail("expected atfield-workset-v1")
    fields = normalized_fields(fields_path)
    if workset.get("field_manifest_sha256") != hashlib.sha256(Path(fields_path).read_bytes()).hexdigest():
        fail("fields.json bytes differ from the frozen workset manifest")
    workset_fields = {field["id"]: field for field in workset.get("fields", [])}
    field_order = [f"0x{field['_id_value']:016x}" for field in fields]
    if set(workset_fields) != set(field_order):
        fail("fields.json and workset Field ID sets differ")
    if list(workset_fields) != field_order:
        fail("fields.json order and workset order differ")

    pretouch = read_json(pretouch_path)
    if pretouch.get("schema") != "atfield-pretouch-final-v1":
        fail("expected the JSON emitted by pretouch.py verify")
    if pretouch.get("workset_sha256") != hashlib.sha256(Path(workset_path).read_bytes()).hexdigest():
        fail("workset bytes differ from the pretouch verification input")
    final = ElfFile(final_path)
    signed_final = ElfFile(signed_final_path)
    q = workset["layout"]["capacity_q"]
    if pretouch.get("capacity_q") != q or pretouch.get("final_elf_sha256") != hashlib.sha256(final.data).hexdigest():
        fail("pretouch verification facts do not match this Final ELF/workset")
    layout = make_layout(final, signed_final, q)
    check_layout(workset["layout"], layout)
    if pretouch.get("post_start") != layout["pretouch_start"]:
        fail("pretouch output start differs from the signed final layout")

    blocks = {item.get("field_id"): item for item in pretouch.get("blocks", [])}
    if set(blocks) != set(field_order):
        fail("verified pretouch blocks do not match the Field manifest")
    pretouch_pages: dict[str, set[int]] = {}
    for identity in field_order:
        block = blocks[identity]
        begin, end = block.get("begin_rva"), block.get("end_rva")
        field_meta = next(field for field in fields if f"0x{field['_id_value']:016x}" == identity)
        symbol = field_meta.get("pretouch_symbol")
        if not isinstance(begin, int) or not isinstance(end, int) or end <= begin:
            fail(f"invalid verified block range for Field {identity}")
        symbol_info = unique_symbol(final, symbol)
        if symbol_info["value"] != begin or symbol_info["size"] != end - begin:
            fail(f"verified block range differs from final symbol {symbol}")
        pages = set(range(begin // PAGE * PAGE, (end - 1) // PAGE * PAGE + PAGE, PAGE))
        if any(page >= layout["enclave_size"] for page in pages):
            fail(f"Field {identity} pretouch block exceeds enclave range")
        pretouch_pages[identity] = pages

    target_pages: dict[str, set[int]] = {}
    for identity, field in workset_fields.items():
        pages = set()
        for page in field.get("pages", []):
            rva, effects = page.get("page_rva"), page.get("effects")
            if not isinstance(rva, int) or rva % PAGE or rva >= layout["enclave_size"]:
                fail(f"Field {identity} has an invalid target page RVA")
            if not isinstance(effects, list) or not effects:
                fail(f"Field {identity} page {rva:#x} has no effects")
            pages.add(rva)
        target_pages[identity] = pages

    # Include the complete signer-generated REG stack in each reachable Field;
    # the full-business producer already includes it in FieldTargetPages.
    stack_pages = set()
    for region in layout["regions"]:
        if region.get("kind") == "signer" and region.get("name", "").startswith("STACK"):
            stack_pages.update(range(region["start_rva"], region["end_rva"], PAGE))

    selectors = read_selectors(workset)
    ready_entries = []
    all_page_rvas = []
    selector_json = []
    for selector in selectors:
        pages = set()
        for identity in selector["reachable_fields"]:
            pages.update(target_pages[identity])
            pages.update(stack_pages)
            pages.update(pretouch_pages[identity])
        ordered = sorted(pages)
        if any(page % PAGE or page >= layout["enclave_size"] for page in ordered):
            fail(f"selector {selector['ecall_index']} has an out-of-range page")
        first = len(all_page_rvas)
        all_page_rvas.extend(ordered)
        ready_entries.append((selector["ecall_index"], first, len(ordered)))
        selector_json.append({"ecall_index": selector["ecall_index"], "name": selector["name"],
                              "reachable_fields": selector["reachable_fields"],
                              "first_page": first, "page_count": len(ordered),
                              "page_rvas": ordered})

    table = bytearray(struct.pack("<QQQQ", VERSION, len(ready_entries), len(all_page_rvas), 0))
    for entry in ready_entries:
        table.extend(struct.pack("<QQQ", *entry))
    for page in all_page_rvas:
        table.extend(struct.pack("<Q", page))
    expected_size = 32 + 24 * len(ready_entries) + 8 * len(all_page_rvas)
    if len(table) != expected_size:
        fail("internal ReadyTable v3 byte-count mismatch")
    write_bytes(output_path, bytes(table))
    summary = {"schema": "atfield-ready-table-v3", "format_version": VERSION,
               "workset": str(workset_path), "workset_sha256": hashlib.sha256(Path(workset_path).read_bytes()).hexdigest(),
               "fields_sha256": hashlib.sha256(Path(fields_path).read_bytes()).hexdigest(),
               "final_elf": str(final_path), "final_elf_sha256": hashlib.sha256(final.data).hexdigest(),
               "signed_final_elf": str(signed_final_path), "signed_final_elf_sha256": hashlib.sha256(signed_final.data).hexdigest(),
               "table_path": str(output_path), "table_sha256": hashlib.sha256(table).hexdigest(),
               "table_bytes": len(table), "entry_count": len(ready_entries),
               "total_page_count": len(all_page_rvas), "selectors": selector_json}
    write_json(json_path, summary)
    counts = ", ".join(f"{item['ecall_index']}:{item['page_count']}" for item in selector_json)
    print(f"ReadyTable v3: selectors={len(ready_entries)} pages={len(all_page_rvas)} bytes={len(table)} [{counts}]")
    print(f"wrote {output_path} and {json_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge per-Field ready pages into ReadyTable v3.")
    parser.add_argument("--workset", required=True)
    parser.add_argument("--fields", required=True)
    parser.add_argument("--pretouch", required=True, help="JSON from pretouch.py verify")
    parser.add_argument("--final-elf", required=True, help="analysis Final ELF retaining symbols")
    parser.add_argument("--signed-final-elf", required=True, help="matching signed Final ELF with .note.sgxmeta")
    parser.add_argument("--out", required=True, help="raw ReadyTable v3 bytes")
    parser.add_argument("--out-json", required=True, help="layout-bound JSON summary")
    args = parser.parse_args()
    try:
        build_ready(args.workset, args.fields, args.pretouch,
                    args.final_elf, args.signed_final_elf, args.out, args.out_json)
        return 0
    except (WorksetError, OSError, ValueError, struct.error, StopIteration) as exc:
        print(f"readiness: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
