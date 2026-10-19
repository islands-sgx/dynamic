#!/usr/bin/env python3
"""Link a protect Profile ELF after all Field object manifests exist."""

import argparse
from pathlib import Path
import shlex
import subprocess
import sys


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
    objects = [Path(item) for item in expanded if item.endswith(".o") and Path(item).is_file()]
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

    subprocess.run([str(args.field_tool), "merge",
                    *(part for manifest in manifests
                      for part in ("--manifest", str(manifest))),
                    "--out", str(fields)], check=True)
    subprocess.run([sys.executable, str(args.pretouch_tool), "emit",
                    "--mode", "profile", "--fields", str(fields),
                    "--capacity-q", str(args.capacity_q),
                    "--out-asm", str(assembly), "--out-json", str(profile_info)],
                   check=True)
    subprocess.run([str(args.assembler), "-c", "-x", "assembler-with-cpp",
                    str(assembly), "-o", str(pretouch_object)], check=True)
    subprocess.run(command + [str(pretouch_object),
                              f"-Wl,-T,{args.linker_script}"], check=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ATField Profile link failed: {error}", file=sys.stderr)
        sys.exit(1)
