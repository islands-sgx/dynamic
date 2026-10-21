#!/usr/bin/env python3
"""Unit tests for challenge exploration and dynamic-owned scenario loading."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from generic_explorer import (  # noqa: E402
    AUDIT_OF_LEGACY_HEURISTICS,
    CHALLENGE_CASES,
    evaluate_challenge_suite,
    round_robin_schedule_interventions,
)
import target_manifest as target_manifest_module  # noqa: E402
import build_real_targets as build_real_targets_module  # noqa: E402


class TestExplorerChallengeSuite(unittest.TestCase):
    def test_audit_of_legacy_heuristics_complete(self) -> None:
        self.assertEqual(len(AUDIT_OF_LEGACY_HEURISTICS), 7)
        for item in AUDIT_OF_LEGACY_HEURISTICS:
            for key in (
                "heuristic",
                "problem_addressed",
                "information_used",
                "underlying_assumption",
                "failure_condition",
                "empirical_status_and_upgrade",
            ):
                self.assertTrue(item.get(key), f"Missing {key} in {item}")

    def test_round_robin_interleaves_operator_families(self) -> None:
        items = [
            {"family": "boundary", "id": 1},
            {"family": "boundary", "id": 2},
            {"family": "content", "id": 3},
            {"family": "joint", "id": 4},
            {"family": "alias", "id": 5},
        ]
        sched = round_robin_schedule_interventions(items)
        self.assertEqual([x["family"] for x in sched[:4]], ["boundary", "content", "joint", "alias"])

    def test_four_strategy_equal_budget_challenge_progression(self) -> None:
        res = evaluate_challenge_suite(budget_per_case=16)
        s0 = res["summary_by_strategy"]["S0"]
        s1 = res["summary_by_strategy"]["S1"]
        s2 = res["summary_by_strategy"]["S2"]
        s3 = res["summary_by_strategy"]["S3"]

        self.assertEqual(s0["challenges_solved"], 0)
        self.assertEqual(s1["challenges_solved"], 0)
        self.assertEqual(s2["challenges_solved"], 3)  # solves C3, C4, C6; misses stateful C1, C2, C5
        self.assertEqual(s3["challenges_solved"], 6)  # solves all 6 (C1..C6)
        self.assertEqual(s3["holdout_missed_effects"], 0)
        self.assertEqual(len(s3["witnesses"]), len(CHALLENGE_CASES))
        for w in s3["witnesses"]:
            self.assertTrue(w["replayed_confirmed"])


class TestDynamicScenarioOwnership(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.dynamic_root = root / "dynamic"
        self.sample_root = root / "sample"
        self.root_patch = patch.object(target_manifest_module, "DYN_ROOT", self.dynamic_root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def write_sample_manifest(self, name: str, *, scenarios_json: str | None = None) -> Path:
        path = self.sample_root / "build" / "real" / name / "protect" / "target_manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        manifest = {"schema": "atfield-target-manifest-v1", "name": name}
        if scenarios_json is not None:
            manifest["scenarios_json"] = scenarios_json
        path.write_text(json.dumps(manifest))
        return path

    def write_dynamic_scenarios(self, name: str, *, schema: str | None = None) -> Path:
        path = self.dynamic_root / "targets" / name / "scenarios.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema": schema or target_manifest_module.SCENARIO_SCHEMA,
            "name": name,
            "marker": "dynamic-oracle",
        }))
        return path

    def test_explicit_build_target_name_uses_current_sample_manifest(self) -> None:
        manifest_path = self.write_sample_manifest("ehsm")
        with patch.object(build_real_targets_module, "DEFAULT_SAMPLE_ROOT", self.sample_root):
            resolved = build_real_targets_module._prefer_current_sample_manifests(["ehsm"])

        self.assertEqual(resolved, [manifest_path])

    def test_explicit_build_does_not_fall_back_to_dynamic_snapshot(self) -> None:
        with patch.object(build_real_targets_module, "DEFAULT_SAMPLE_ROOT", self.sample_root):
            with self.assertRaisesRegex(FileNotFoundError, "current sample build metadata"):
                build_real_targets_module._prefer_current_sample_manifests(["ehsm"])

    def test_dynamic_scenario_overrides_legacy_sample_pointer(self) -> None:
        sample_scenarios = self.sample_root / "real" / "ehsm" / "scenarios.json"
        sample_scenarios.parent.mkdir(parents=True, exist_ok=True)
        sample_scenarios.write_text(json.dumps({"schema": "legacy", "name": "ehsm", "marker": "sample"}))
        manifest_path = self.write_sample_manifest("ehsm", scenarios_json=str(sample_scenarios))
        self.write_dynamic_scenarios("ehsm")

        loaded = target_manifest_module.load_target_manifest("ehsm", sample_root=self.sample_root)

        self.assertEqual(loaded["scenarios"]["marker"], "dynamic-oracle")
        self.assertNotIn("scenarios_json", loaded)
        self.assertEqual(loaded["manifest_path"], str(manifest_path))

    def test_dynamic_scenario_loads_when_sample_manifest_has_no_scenario_field(self) -> None:
        self.write_sample_manifest("ehsm")
        self.write_dynamic_scenarios("ehsm")

        loaded = target_manifest_module.load_target_manifest("ehsm", sample_root=self.sample_root)

        self.assertEqual(loaded["scenarios"]["marker"], "dynamic-oracle")

    def test_missing_dynamic_scenario_is_a_hard_error(self) -> None:
        self.write_sample_manifest("ehsm")

        with self.assertRaisesRegex(FileNotFoundError, "Missing dynamic scenario/oracle"):
            target_manifest_module.load_target_manifest("ehsm", sample_root=self.sample_root)

    def test_dynamic_scenario_schema_is_validated(self) -> None:
        self.write_sample_manifest("ehsm")
        self.write_dynamic_scenarios("ehsm", schema="atfield-sample-scenarios-v1")

        with self.assertRaisesRegex(ValueError, "atfield-dynamic-scenarios-v1"):
            target_manifest_module.load_target_manifest("ehsm", sample_root=self.sample_root)

    def test_default_discovery_skips_stale_sqlite_build_manifest(self) -> None:
        self.write_sample_manifest("ehsm")
        self.write_sample_manifest("sqlite")
        self.write_dynamic_scenarios("ehsm")

        found = target_manifest_module.discover_real_target_manifests(sample_root=self.sample_root)

        self.assertEqual([item["name"] for item in found], ["ehsm"])
        with self.assertRaisesRegex(ValueError, "research fixture"):
            target_manifest_module.discover_real_target_manifests(["sqlite"], sample_root=self.sample_root)

    def test_fixture_is_rejected_by_real_runner_and_report_cohort(self) -> None:
        from generate_report_tables import REAL_TARGETS
        from run_native_sgx import run_sample

        self.assertNotIn("sqlite", REAL_TARGETS)
        with self.assertRaisesRegex(ValueError, "research fixture"):
            run_sample("sqlite")

    def test_six_canonical_scenario_files_use_dynamic_schema_and_opt_hosts(self) -> None:
        names = ("ehsm", "ehsm-opt-1", "ehsm-opt-2", "qe3", "sgxwallet", "signal-cds")
        with patch.object(target_manifest_module, "DYN_ROOT", DYN_ROOT):
            for name in names:
                manifest_path = DYN_ROOT / "targets" / name / "target_manifest.json"
                loaded = target_manifest_module.load_target_manifest(manifest_path)
                self.assertEqual(loaded["scenarios"]["schema"], "atfield-dynamic-scenarios-v1")
                self.assertEqual(loaded["scenarios"]["name"], name)
                self.assertNotIn("scenarios_json", loaded)
                persisted = json.loads(manifest_path.read_text())
                self.assertNotIn("scenarios", persisted)
                self.assertNotIn("scenarios_json", persisted)
                self.assertNotIn("manifest_path", persisted)
                if name in {"ehsm-opt-1", "ehsm-opt-2"}:
                    self.assertIn(f"sample/real/{name}/host.cpp", loaded["scenarios"]["onboarding_metadata"]["host_entry"])


if __name__ == "__main__":
    unittest.main()
