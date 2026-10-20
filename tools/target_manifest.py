#!/usr/bin/env python3
"""Single-source loader for sample-exported `target_manifest.json` and `scenarios.json`."""
from __future__ import annotations

import json
import os
from pathlib import Path

DYN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAMPLE_ROOT = Path(os.environ.get("ATFIELD_SAMPLE_ROOT", str(DYN_ROOT.parent / "sample")))


def load_target_manifest(target_or_path: str | Path, sample_root: Path = DEFAULT_SAMPLE_ROOT) -> dict:
    """Load `target_manifest.json` (and attach its `scenarios` dict from `scenarios_json`)
    given either a path to `target_manifest.json` or a sample target name.
    """
    p = Path(target_or_path)
    if p.is_file() and p.name.endswith(".json"):
        manifest_path = p.resolve()
    elif (DYN_ROOT / "targets" / str(target_or_path) / "target_manifest.json").is_file():
        manifest_path = (DYN_ROOT / "targets" / str(target_or_path) / "target_manifest.json").resolve()
    else:
        manifest_path = (sample_root / "build" / "real" / str(target_or_path) / "protect" / "target_manifest.json").resolve()
        if not manifest_path.is_file():
            raise FileNotFoundError(f"Cannot locate target_manifest.json for {target_or_path!r} at {manifest_path}")

    manifest = json.loads(manifest_path.read_text())
    manifest["manifest_path"] = str(manifest_path)
    sc_path = Path(manifest.get("scenarios_json", ""))
    if sc_path.is_file():
        manifest["scenarios"] = json.loads(sc_path.read_text())
    else:
        manifest["scenarios"] = {}
    return manifest


def discover_real_target_manifests(
    names_or_paths: list[str] | None = None,
    sample_root: Path = DEFAULT_SAMPLE_ROOT,
) -> list[dict]:
    """Discover all real target manifests from `sample/build/real/*/protect/target_manifest.json`
    (or load the explicitly specified target names / manifest paths).
    """
    if names_or_paths:
        return [load_target_manifest(x, sample_root=sample_root) for x in names_or_paths]
    found = sorted((sample_root / "build" / "real").glob("*/protect/target_manifest.json"))
    return [load_target_manifest(p, sample_root=sample_root) for p in found]
