#!/usr/bin/env python3
"""Verify vendored implement bytes against the pinned commit or recorded source digests."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "vendor" / "IMPLEMENT_UPSTREAM.json"


def run_git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def tracked_vendor_paths(root: Path) -> list[str]:
    return [
        item.decode()
        for item in run_git(root, "ls-files", "-z", "vendor/implement").split(b"\0")
        if item
    ]


def compare_manifest_bytes(root: Path, expected: dict[str, str], tracked_count: int) -> list[str]:
    tracked = tracked_vendor_paths(root)
    relatives = {
        Path(path).relative_to("vendor/implement").as_posix()
        for path in tracked
    }
    errors = []
    if len(tracked) != tracked_count:
        errors.append(f"tracked file count is {len(tracked)}, expected {tracked_count}")
    if relatives != set(expected):
        errors.append("tracked file set differs from the source manifest")
    for relative in sorted(relatives | set(expected)):
        path = root / "vendor" / "implement" / relative
        if not path.is_file():
            errors.append(f"missing vendor file: {relative}")
        elif relative not in expected:
            errors.append(f"unrecorded vendor file: {relative}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected[relative]:
            errors.append(f"source byte digest mismatch: {relative}")
    return errors


def compare_upstream_bytes(root: Path, upstream: Path, manifest: dict) -> list[str]:
    commit = manifest["commit"]
    run_git(upstream, "cat-file", "-e", f"{commit}^{{commit}}")
    tracked = tracked_vendor_paths(root)
    errors = []
    if len(tracked) != manifest["tracked_file_count"]:
        errors.append(f"tracked file count is {len(tracked)}, expected {manifest['tracked_file_count']}")
    for path in tracked:
        relative = Path(path).relative_to("vendor/implement").as_posix()
        upstream_bytes = run_git(upstream, "show", f"{commit}:{relative}")
        if (root / path).read_bytes() != upstream_bytes:
            errors.append(f"source byte mismatch: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("upstream_checkout", nargs="?", type=Path, help="canonical implement Git checkout")
    parser.add_argument("--manifest-only", action="store_true", help="verify vendored bytes against pinned SHA-256 values")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    try:
        if args.manifest_only:
            errors = compare_manifest_bytes(ROOT, manifest["files_sha256"], manifest["tracked_file_count"])
        elif args.upstream_checkout is not None:
            errors = compare_upstream_bytes(ROOT, args.upstream_checkout, manifest)
            if not errors:
                errors = compare_manifest_bytes(ROOT, manifest["files_sha256"], manifest["tracked_file_count"])
        else:
            parser.error("provide upstream_checkout or --manifest-only")
            return 2
    except (OSError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: cannot verify vendored source bytes: {exc}")
        return 2
    if errors:
        print("FAIL: vendored implement source parity check failed:")
        for error in errors:
            print(f"  {error}")
        return 1
    print(f"PASS: {manifest['tracked_file_count']} vendored files match implement@{manifest['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
