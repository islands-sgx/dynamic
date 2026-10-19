#!/usr/bin/env python3
"""Link a protect Profile ELF after filtering Fields removed by section GC."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

_IMPLEMENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_IMPLEMENT_ROOT / "build" / "workset"))
from workset import (  # noqa: E402
    ElfFile,
    PF_R,
    PF_W,
    PF_X,
    SHF_ALLOC,
    SHF_EXECINSTR,
    WorksetError,
)

SHT_PROGBITS = 1
BODY_PREFIX = "__atfield_body_"
CONTINUATION_PREFIX = "__atfield_after_marker_"


def link_arguments(arguments: list[str]) -> list[str]:
    expanded: list[str] = []
    for argument in arguments:
        if argument.startswith("@") and Path(argument[1:]).is_file():
            expanded.extend(link_arguments(shlex.split(Path(argument[1:]).read_text())))
        else:
            expanded.append(argument)
    return expanded


def link_output(arguments: list[str]) -> Path:
    for index, argument in enumerate(arguments):
        if argument == "-o" and index + 1 < len(arguments):
            return Path(arguments[index + 1]).resolve()
    raise ValueError("link command has no -o output")


def with_output(arguments: list[str], output: Path) -> list[str]:
    result = list(arguments)
    for index, argument in enumerate(result):
        if argument == "-o" and index + 1 < len(result):
            result[index + 1] = str(output)
            return result
    raise ValueError("link command has no replaceable -o output")


def symbol_definitions(elf: ElfFile, name: str) -> list[dict]:
    by_identity = {}
    for symbol in elf.symbols():
        if symbol["name"] == name and symbol["shndx"] not in (0, 0xFFF1, 0xFFF2):
            identity = (symbol["value"], symbol["size"], symbol["shndx"])
            by_identity[identity] = symbol
    return list(by_identity.values())


def verify_ax_field_symbol(elf: ElfFile, field: dict, name: str) -> dict | None:
    matches = symbol_definitions(elf, name)
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError(
            f"Field {field.get('id')} symbol {name} has {len(matches)} distinct definitions"
        )
    symbol = matches[0]
    sections = [section for section in elf.sections if section["index"] == symbol["shndx"]]
    if len(sections) != 1:
        raise ValueError(f"Field {field.get('id')} symbol {name} has invalid section index")
    section = sections[0]
    required_flags = SHF_ALLOC | SHF_EXECINSTR
    if section["type"] != SHT_PROGBITS or section["flags"] & required_flags != required_flags:
        raise ValueError(f"Field {field.get('id')} symbol {name} is not in an allocated AX PROGBITS section")
    if section["name"] == ".atfield_pretouch":
        raise ValueError(f"Field {field.get('id')} symbol {name} unexpectedly belongs to pretouch output")
    address = symbol["value"]
    if not section["addr"] <= address < section["addr"] + section["size"]:
        raise ValueError(f"Field {field.get('id')} symbol {name} falls outside its AX section")
    load_matches = [
        segment for segment in elf.loads
        if segment["vaddr"] <= address < segment["vaddr"] + segment["filesz"]
        and segment["flags"] & PF_X
        and segment["flags"] & PF_R
        and not segment["flags"] & PF_W
    ]
    if len(load_matches) != 1:
        raise ValueError(
            f"Field {field.get('id')} symbol {name} belongs to {len(load_matches)} ordinary RX PT_LOAD ranges"
        )
    return symbol


def live_fields(elf_path: Path, fields: list[dict]) -> list[dict]:
    elf = ElfFile(elf_path)
    if not any(section["type"] == 2 for section in elf.sections):
        raise ValueError(f"prepass ELF has no .symtab for Field liveness proof: {elf_path}")
    live = []
    for field in fields:
        body_name = field.get("body_symbol")
        continuation_name = field.get("continuation_symbol")
        if not isinstance(body_name, str) or not body_name.startswith(BODY_PREFIX):
            raise ValueError(f"Field {field.get('id')} has invalid body_symbol")
        if not isinstance(continuation_name, str) or not continuation_name.startswith(CONTINUATION_PREFIX):
            raise ValueError(f"Field {field.get('id')} has invalid continuation_symbol")

        body = verify_ax_field_symbol(elf, field, body_name)
        continuation = verify_ax_field_symbol(elf, field, continuation_name)
        if body is None and continuation is None:
            continue
        if body is None or continuation is None:
            raise ValueError(
                f"Field {field.get('id')} retained only one of body/continuation symbols after section GC"
            )
        if body["value"] != continuation["value"]:
            raise ValueError(
                f"Field {field.get('id')} body and continuation addresses differ: "
                f"{body['value']:#x} vs {continuation['value']:#x}"
            )
        live.append(field)

    expected = {field["body_symbol"] for field in live}
    observed = {
        symbol["name"] for symbol in elf.symbols()
        if symbol["name"].startswith(BODY_PREFIX) and symbol["shndx"] not in (0, 0xFFF1, 0xFFF2)
    }
    unknown = observed - expected
    if unknown:
        raise ValueError(
            f"linked ELF has Field body symbols missing from its manifests: {sorted(unknown)}"
        )
    return live


def replace_fields_manifest(source: Path, output: Path, fields: list[dict]) -> None:
    try:
        document = json.loads(source.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read merged Field manifest {source}: {error}") from error
    if document.get("schema") != "atfield-fields-v1" or not isinstance(document.get("fields"), list):
        raise ValueError(f"invalid merged Field manifest: {source}")
    live_ids = {field["id"] for field in fields}
    document["fields"] = [field for field in document["fields"] if field.get("id") in live_ids]
    if {field.get("id") for field in document["fields"]} != live_ids:
        raise ValueError("live Field selection did not match merged manifest IDs")
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n")
    temporary.replace(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field-tool", type=Path, required=True)
    parser.add_argument("--pretouch-tool", type=Path, required=True)
    parser.add_argument("--capacity-q", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--assembler", type=Path, required=True)
    parser.add_argument("--linker-script", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.capacity_q <= 0 or args.capacity_q % 4096:
        parser.error("a link command and page-aligned positive Q are required")

    expanded = link_arguments(command)
    objects = [
        Path(item) for item in expanded
        if item.endswith(".o") and Path(item).is_file()
    ]
    manifests = [Path(str(obj) + ".field.json") for obj in objects]
    if not objects or any(not path.is_file() for path in manifests):
        missing = [str(path) for path in manifests if not path.is_file()]
        raise ValueError(f"Field manifest missing for linked object(s): {missing or 'no objects'}")

    output = link_output(expanded)
    folder = output.parent
    folder.mkdir(parents=True, exist_ok=True)
    fields = folder / "fields.json"
    assembly = folder / "pretouch-profile.S"
    pretouch_object = folder / "pretouch-profile.o"
    profile_info = folder / "pretouch-profile.json"

    with tempfile.TemporaryDirectory(prefix=".atfield-profile-link-", dir=folder) as scratch:
        scratch_path = Path(scratch)
        merged_fields = scratch_path / "all-fields.json"
        prepass_elf = scratch_path / "prepass.so"
        subprocess.run([
            str(args.field_tool), "merge",
            *(part for manifest in manifests for part in ("--manifest", str(manifest))),
            "--out", str(merged_fields),
        ], check=True)
        try:
            document = json.loads(merged_fields.read_text())
            all_fields = document["fields"]
            if not isinstance(all_fields, list):
                raise ValueError("merged fields.json does not contain a Field array")
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError(f"cannot parse merged Field manifest: {error}") from error

        prepass_command = with_output(expanded, prepass_elf)
        prepass_command.extend(
            f"-Wl,--defsym={field['pretouch_symbol']}=0" for field in all_fields
        )
        subprocess.run(prepass_command, check=True)
        selected_fields = live_fields(prepass_elf, all_fields)
        replace_fields_manifest(merged_fields, fields, selected_fields)

        subprocess.run([
            sys.executable, str(args.pretouch_tool), "emit",
            "--mode", "profile", "--fields", str(fields),
            "--capacity-q", str(args.capacity_q),
            "--out-asm", str(assembly), "--out-json", str(profile_info),
        ], check=True)
        subprocess.run([
            str(args.assembler), "-c", "-x", "assembler-with-cpp",
            str(assembly), "-o", str(pretouch_object),
        ], check=True)
        subprocess.run(command + [
            str(pretouch_object), f"-Wl,-T,{args.linker_script}",
        ], check=True)

    final_fields = live_fields(output, selected_fields)
    if {field["id"] for field in final_fields} != {field["id"] for field in selected_fields}:
        raise ValueError("Field set changed between prepass and final Profile link")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, WorksetError, subprocess.CalledProcessError) as error:
        print(f"ATField Profile link failed: {error}", file=sys.stderr)
        sys.exit(1)
