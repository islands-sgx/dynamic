#!/usr/bin/env python3
"""Offline negative & positive unit tests for tools/acceptance_validator.py."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from acceptance_validator import (  # noqa: E402
    validate_provenance_consistency,
    validate_run_result,
)


def make_valid_mock_run() -> dict:
    return {
        "sample": "mock",
        "returncode": 0,
        "timed_out": False,
        "measurement_invalid": False,
        "stdout": "Mock functional checks: PASS",
        "interpose_sha256": "aaaa1111",
        "records": [
            {
                "call_seq": 0,
                "ecall_index": 0,
                "sgx_status": 0,
                "ms_retval_i32": 0,
                "measurement_invalid": 0,
                "invalid_reason": "",
                "syscall_errors": 0,
                "ipi_flush_failures": 0,
                "fast_forwarded_prior": 0,
                "strict_non_ready_fault_count": 0,
                "fields": [
                    {
                        "field_id": "0x1111111111111111",
                        "ipi_aex_verified_mask": 7,
                        "heap_walk_truncated": 0,
                        "heap_pread_failures": 0,
                        "s3": [
                            {"rva": "0x1000", "ad": "A"},
                            {"rva": "0x2000", "ad": "D"},
                        ],
                    }
                ],
            }
        ],
    }


class TestAcceptanceValidator(unittest.TestCase):
    def test_00_valid_run_passes(self) -> None:
        run = make_valid_mock_run()
        ws = {"0x1111111111111111": {(0x1000, "A"), (0x2000, "A"), (0x2000, "D")}}
        v = validate_run_result(
            run,
            expected_min_records=1,
            expected_field_ids={"0x1111111111111111"},
            require_ipi_mask=7,
            closed_workset_effects=ws,
            require_zero_strict_faults=True,
        )
        self.assertEqual(v["status"], "PASS")
        self.assertEqual(v["reasons"], [])

    def test_01_empty_trace_rejected(self) -> None:
        run = make_valid_mock_run()
        run["records"] = []
        v = validate_run_result(run)
        self.assertEqual(v["status"], "INVALID")
        self.assertIn("EMPTY_TRACE", v["reasons"])

    def test_02_truncated_trace_rejected(self) -> None:
        run = make_valid_mock_run()
        v = validate_run_result(run, expected_min_records=5)
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("TRUNCATED_TRACE" in r for r in v["reasons"]))

    def test_03_sigill_crash_rejected(self) -> None:
        run = make_valid_mock_run()
        run["returncode"] = -4
        v = validate_run_result(run)
        self.assertEqual(v["status"], "FAIL")
        self.assertIn("SIGNAL_EXIT_-4", v["reasons"])

    def test_04_timeout_rejected(self) -> None:
        run = make_valid_mock_run()
        run["timed_out"] = True
        v = validate_run_result(run)
        self.assertEqual(v["status"], "TIMEOUT")
        self.assertIn("PROCESS_TIMED_OUT", v["reasons"])

    def test_05_missing_required_field_rejected(self) -> None:
        run = make_valid_mock_run()
        v = validate_run_result(run, expected_field_ids={"0x1111111111111111", "0x2222222222222222"})
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("MISSING_REQUIRED_FIELDS" in r for r in v["reasons"]))

    def test_06_missing_write_effect_D_rejected(self) -> None:
        run = make_valid_mock_run()
        ws = {"0x1111111111111111": {(0x1000, "A"), (0x2000, "A")}}
        v = validate_run_result(run, closed_workset_effects=ws)
        self.assertEqual(v["status"], "FAIL")
        self.assertIn("UNCOVERED_WRITE_EFFECT_D_ON_0x2000_IN_0x1111111111111111", v["reasons"])

    def test_07_invalid_measurement_or_heap_truncation_rejected(self) -> None:
        run = make_valid_mock_run()
        run["records"][0]["fields"][0]["heap_walk_truncated"] = 1
        v = validate_run_result(run)
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("HEAP_WALK_TRUNCATED" in r for r in v["reasons"]))

    def test_08_wrong_business_stdout_rejected(self) -> None:
        run = make_valid_mock_run()
        run["stdout"] = ""
        v = validate_run_result(run, expected_stdout_substr="PASS")
        self.assertEqual(v["status"], "FAIL")
        self.assertTrue(any("MISSING_BUSINESS_PASS_STDOUT" in r for r in v["reasons"]))

    def test_09_provenance_hash_mismatch_rejected(self) -> None:
        ledger = {
            "interpose_sha256": "0e5371aaaa",
            "runs": [{"run_id": "r1", "measurement_invalid": True}],
            "witnesses": [],
        }
        eval_runs = [{"interpose_sha256": "d6f00d4bbbb"}]
        v = validate_provenance_consistency(ledger, eval_runs)
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("INTERPOSE_HASH_MISMATCH" in r for r in v["reasons"]))
        self.assertTrue(any("LEDGER_RUN_INVALID" in r for r in v["reasons"]))


if __name__ == "__main__":
    unittest.main()
