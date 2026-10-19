#!/usr/bin/env python3
"""Unit tests for the 6-case general challenge suite (C1..C6) and 4-strategy equal-budget comparison."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from generic_explorer import (  # noqa: E402
    AUDIT_OF_LEGACY_HEURISTICS,
    CHALLENGE_CASES,
    evaluate_challenge_suite,
    round_robin_schedule_interventions,
)


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


if __name__ == "__main__":
    unittest.main()
