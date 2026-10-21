#!/usr/bin/env python3
"""Load build metadata and dynamic-owned scenario/oracle configurations."""
from __future__ import annotations

import json
import os
from pathlib import Path

DYN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAMPLE_ROOT = Path(os.environ.get("ATFIELD_SAMPLE_ROOT", str(DYN_ROOT.parent / "sample")))
SCENARIO_SCHEMA = "atfield-dynamic-scenarios-v1"
FIXTURE_TARGET_NAMES = frozenset({"sqlite"})


def ensure_real_target_name(name: str) -> None:
    """Reject research fixtures at APIs that operate on real targets."""
    if name in FIXTURE_TARGET_NAMES:
        raise ValueError(f"{name!r} is a research fixture, not a real target")


def _read_dynamic_scenarios(target_name: str) -> dict:
    scenario_path = DYN_ROOT / "targets" / target_name / "scenarios.json"
    if not scenario_path.is_file():
        raise FileNotFoundError(
            f"Missing dynamic scenario/oracle for real target {target_name!r}: {scenario_path}"
        )
    scenarios = json.loads(scenario_path.read_text())
    if not isinstance(scenarios, dict):
        raise ValueError(f"Dynamic scenarios for {target_name!r} must be a JSON object: {scenario_path}")
    if scenarios.get("schema") != SCENARIO_SCHEMA:
        raise ValueError(
            f"Dynamic scenarios for {target_name!r} require schema {SCENARIO_SCHEMA!r}; "
            f"found {scenarios.get('schema')!r} in {scenario_path}"
        )
    if scenarios.get("name") != target_name:
        raise ValueError(
            f"Dynamic scenarios target name mismatch: manifest={target_name!r}, "
            f"scenarios={scenarios.get('name')!r} in {scenario_path}"
        )
    return scenarios


def load_target_manifest(target_or_path: str | Path, sample_root: Path = DEFAULT_SAMPLE_ROOT) -> dict:
    """Load build metadata and attach scenarios from `dynamic/targets/<name>/scenarios.json`.

    The sample-exported manifest remains the source for compiler-resolved artifact paths.
    Its legacy `scenarios_json` pointer is discarded; scenario/oracle data belongs to dynamic.
    """
    p = Path(target_or_path)
    if not p.is_file() and str(target_or_path) in FIXTURE_TARGET_NAMES:
        ensure_real_target_name(str(target_or_path))
    if p.is_file() and p.name.endswith(".json"):
        manifest_path = p.resolve()
    elif (DYN_ROOT / "targets" / str(target_or_path) / "target_manifest.json").is_file():
        manifest_path = (DYN_ROOT / "targets" / str(target_or_path) / "target_manifest.json").resolve()
    else:
        manifest_path = (sample_root / "build" / "real" / str(target_or_path) / "protect" / "target_manifest.json").resolve()
        if not manifest_path.is_file():
            raise FileNotFoundError(f"Cannot locate target_manifest.json for {target_or_path!r} at {manifest_path}")

    manifest = json.loads(manifest_path.read_text())
    target_name = str(manifest.get("name", ""))
    if not target_name:
        raise ValueError(f"Target manifest has no non-empty name: {manifest_path}")
    ensure_real_target_name(target_name)

    scenarios = _read_dynamic_scenarios(target_name)
    manifest.pop("scenarios_json", None)
    manifest.pop("scenarios", None)
    manifest["manifest_path"] = str(manifest_path)
    manifest["scenarios"] = scenarios
    return manifest


def discover_real_target_manifests(
    names_or_paths: list[str] | None = None,
    sample_root: Path = DEFAULT_SAMPLE_ROOT,
) -> list[dict]:
    """Discover real target build manifests, excluding targets classified as fixtures."""
    if names_or_paths:
        return [load_target_manifest(x, sample_root=sample_root) for x in names_or_paths]

    found = sorted((sample_root / "build" / "real").glob("*/protect/target_manifest.json"))
    manifests = []
    for manifest_path in found:
        target_name = str(json.loads(manifest_path.read_text()).get("name", ""))
        if target_name in FIXTURE_TARGET_NAMES:
            continue
        manifests.append(load_target_manifest(manifest_path, sample_root=sample_root))
    return manifests
