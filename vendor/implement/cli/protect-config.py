#!/usr/bin/env python3
"""Derive a protect-only SGX signing XML from a sample's original XML."""

import argparse
from pathlib import Path
from xml.etree import ElementTree as ET


PAGE = 4096


def size(value: str) -> int:
    parsed = int(value, 0)
    if parsed <= 0 or parsed % PAGE:
        raise argparse.ArgumentTypeError("size must be a positive multiple of 4096")
    return parsed


def one(root: ET.Element, name: str) -> ET.Element:
    matches = root.findall(name)
    if len(matches) != 1:
        raise ValueError(f"expected one <{name}> in signing XML")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--heap", type=size, required=True)
    parser.add_argument("--stack", type=size, required=True)
    args = parser.parse_args()

    root = ET.parse(args.source).getroot()
    if root.tag != "EnclaveConfiguration":
        raise ValueError("expected <EnclaveConfiguration> root")
    if int(one(root, "TCSNum").text or "", 0) != 1:
        raise ValueError("protect currently requires one TCS")
    if int(one(root, "TCSPolicy").text or "", 0) != 0:
        raise ValueError("protect currently requires bound TCS policy")

    one(root, "HeapMaxSize").text = f"0x{args.heap:X}"
    one(root, "StackMinSize").text = f"0x{args.stack:X}"
    one(root, "StackMaxSize").text = f"0x{args.stack:X}"
    notify = root.findall("EnableAEXNotify")
    if len(notify) > 1:
        raise ValueError("duplicate <EnableAEXNotify>")
    if notify:
        notify[0].text = "1"
    else:
        debug = one(root, "DisableDebug")
        root.insert(list(root).index(debug), ET.Element("EnableAEXNotify"))
        one(root, "EnableAEXNotify").text = "1"

    ET.indent(root, space="  ")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    content = ET.tostring(root, encoding="unicode") + "\n"
    if args.output.exists() and args.output.read_text() == content:
        return
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_text(content)
    temporary.replace(args.output)


if __name__ == "__main__":
    main()
