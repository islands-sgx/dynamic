#!/usr/bin/env python3
"""Offline negative & positive unit tests for tools/acceptance_validator.py."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from acceptance_validator import (  # noqa: E402
    evaluate_regression_workflow_case,
    extract_valid_s3_effects,
    is_valid_measurement_run,
    validate_challenge_ground_truth_and_holdout,
    validate_diagnostic_4gate_run,
    validate_production_run_result,
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
                "tag": "schema_xor_p2_byte_45",
                "sgx_status": 0,
                "ms_retval_i32": 0,
                "elapsed_ns": 50000,
                "acquire_ns": 20000,
                "encl_body_ns": 15000,
                "release_ns": 15000,
                "readiness_installed": 1,
                "acquire_calls": 1,
                "acquire_rc": 0,
                "release_calls": 1,
                "release_rc": 0,
                "measurement_invalid": 0,
                "invalid_reason": "",
                "syscall_errors": 0,
                "ipi_flush_failures": 0,
                "fast_forwarded_prior": 0,
                "mutation_oob_rejected": 0,
                "strict_mode": 2,
                "strict_non_ready_fault_count": 0,
                "fields": [
                    {
                        "field_id": "0x1111111111111111",
                        "ipi_aex_verified_mask": 7,
                        "heap_walk_truncated": 0,
                        "heap_pread_failures": 0,
                        "s3_active_aex_count": 0,
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
            expected_tags={"schema_xor_p2_byte_45"},
            require_strict_mode=2,
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

    def test_10_strict_mode_disabled_rejected(self) -> None:
        run = make_valid_mock_run()
        run["records"][0]["strict_mode"] = 0
        v = validate_run_result(run, require_strict_mode=2, require_zero_strict_faults=True)
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("STRICT_MODE" in r for r in v["reasons"]))

    def test_11_missing_expected_mutation_tag_rejected(self) -> None:
        run = make_valid_mock_run()
        run["records"][0]["tag"] = "host_normal"
        v = validate_run_result(run, expected_tags={"schema_xor_p2_byte_45"})
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("MISSING_EXPECTED_INTERVENTION_TAGS" in r for r in v["reasons"]))

    def test_12_unknown_field_not_in_workset_rejected(self) -> None:
        run = make_valid_mock_run()
        ws = {"0x9999999999999999": {(0x1000, "A")}}
        v = validate_run_result(run, closed_workset_effects=ws)
        self.assertEqual(v["status"], "INVALID")
        self.assertIn("UNKNOWN_FIELD_NOT_IN_WORKSET:0x1111111111111111", v["reasons"])



    def test_13_prod_measurement_invalid_rejected(self) -> None:
        r = make_valid_mock_run()
        r["measurement_invalid"] = True
        v = validate_production_run_result(
            r,
            expected_stdout_substr="PASS",
            expected_ecall_seq=[0],
            ready_sel_set={0},
            require_readiness=True,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertIn("RUN_MEASUREMENT_INVALID_FLAG", v["reasons"])

    def test_14_prod_missing_readiness_or_acquire_rejected(self) -> None:
        r = make_valid_mock_run()
        r["records"][0]["readiness_installed"] = 0
        r["records"][0]["acquire_calls"] = 0
        v = validate_production_run_result(
            r,
            expected_stdout_substr="PASS",
            expected_ecall_seq=[0],
            ready_sel_set={0},
            require_readiness=True,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertIn("RECORD_0_READINESS_NOT_INSTALLED", v["reasons"])

    def test_15_prod_ecall_sequence_mismatch_rejected(self) -> None:
        r = make_valid_mock_run()
        v = validate_production_run_result(
            r,
            expected_stdout_substr="PASS",
            expected_ecall_seq=[0, 1],
            ready_sel_set={0},
            require_readiness=False,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("ECALL_SEQUENCE_MISMATCH" in x for x in v["reasons"]))



    def test_16_false_positive_not_pass_stdout_rejected(self) -> None:
        r = make_valid_mock_run()
        r["stdout"] = "Mock functional checks: NOT PASS"
        v = validate_run_result(r, expected_stdout_substr="PASS")
        self.assertEqual(v["status"], "FAIL")
        self.assertTrue(any("NEGATIVE_STDOUT_MARKER" in x for x in v["reasons"]))

    def test_17_nonzero_sgx_status_transport_error_rejected(self) -> None:
        r = make_valid_mock_run()
        r["records"][0]["sgx_status"] = 0x2001
        v = validate_production_run_result(
            r,
            expected_stdout_substr="PASS",
            expected_ecall_seq=[0],
            ready_sel_set={0},
            require_readiness=True,
        )
        self.assertEqual(v["status"], "FAIL")
        self.assertTrue(any("SGX_TRANSPORT_ERROR" in x for x in v["reasons"]))

    def test_18_missing_required_record_fields_rejected(self) -> None:
        r = make_valid_mock_run()
        del r["records"][0]["release_calls"]
        v = validate_production_run_result(
            r,
            expected_stdout_substr="PASS",
            expected_ecall_seq=[0],
            ready_sel_set={0},
            require_readiness=True,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("MISSING_PROD_KEYS" in x for x in v["reasons"]))

    def test_19_diagnostic_4gate_sequence_or_field_mismatch_rejected(self) -> None:
        r = make_valid_mock_run()
        r["records"][0]["fields"][0]["ipi_aex_verified_mask"] = 3
        v = validate_diagnostic_4gate_run(
            r,
            expected_field_ids={"0x1111111111111111"},
            expected_ecall_seq=[0],
            expected_field_call_seqs=set(),  # mismatch: record 0 entered a field!
            require_ipi_mask=3,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertIn("DIAG_FIELD_ENTERING_CALL_SEQS_MISMATCH", v["reasons"])


    def test_20_missing_s3_key_or_empty_s3_rejected(self) -> None:
        r = make_valid_mock_run()
        del r["records"][0]["fields"][0]["s3"]
        v = validate_run_result(
            r,
            expected_min_records=1,
            expected_field_ids={"0x1111111111111111"},
            require_ipi_mask=7,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("FIELD_MISSING_KEYS" in x for x in v["reasons"]))

        r_empty = make_valid_mock_run()
        r_empty["records"][0]["fields"][0]["s3"] = []
        v_empty = validate_run_result(
            r_empty,
            expected_min_records=1,
            expected_field_ids={"0x1111111111111111"},
            require_ipi_mask=7,
        )
        self.assertEqual(v_empty["status"], "INVALID")
        self.assertTrue(any("EMPTY_S3_OBSERVATION" in x for x in v_empty["reasons"]))

    def test_21_missing_s3_active_aex_count_rejected(self) -> None:
        r = make_valid_mock_run()
        r["records"][0]["fields"][0]["ipi_aex_verified_mask"] = 3
        del r["records"][0]["fields"][0]["s3_active_aex_count"]
        v = validate_diagnostic_4gate_run(
            r,
            expected_field_ids={"0x1111111111111111"},
            expected_ecall_seq=[0],
            expected_field_call_seqs={0},
            require_ipi_mask=3,
        )
        self.assertEqual(v["status"], "INVALID")
        self.assertTrue(any("MISSING_S3_ACTIVE_AEX_COUNT" in x for x in v["reasons"]))

    def test_22_all_observations_contaminated_rejected(self) -> None:
        r = make_valid_mock_run()
        r["records"][0]["fields"][0]["ipi_aex_verified_mask"] = 3
        r["records"][0]["fields"][0]["s3_active_aex_count"] = 2
        v = validate_diagnostic_4gate_run(
            r,
            expected_field_ids={"0x1111111111111111"},
            expected_ecall_seq=[0],
            expected_field_call_seqs={0},
            require_ipi_mask=3,
        )
        self.assertEqual(v["status"], "INCONCLUSIVE")
        self.assertIn("NO_CLEAN_OBSERVATIONS_ALL_CONTAMINATED", v["reasons"])

    def test_23_challenge_ground_truth_rejects_missing_symbol_wrong_field_and_missing_D(self) -> None:
        gt_syms = {f"C{i}": 0x30000 + i * 0x1000 for i in range(1, 9)}
        decl = {
            f"C{i}": {"field_function": "fn_a", "effects": ["A"] if i in (2, 4) else ["A", "D"]}
            for i in range(1, 9)
        }
        fmap = {"fn_a": "0xaaaa", "fn_b": "0xbbbb"}
        full_ho = {
            ("0xaaaa", gt_syms[f"C{i}"], eff)
            for i in range(1, 9)
            for eff in decl[f"C{i}"]["effects"]
        }
        ok, _, reasons = validate_challenge_ground_truth_and_holdout(gt_syms, decl, fmap, full_ho)
        self.assertTrue(ok, reasons)

        # 1. Missing C8 symbol
        gt_missing = dict(gt_syms)
        del gt_missing["C8"]
        ok1, _, r1 = validate_challenge_ground_truth_and_holdout(gt_missing, decl, fmap, full_ho)
        self.assertFalse(ok1)
        self.assertTrue(any("INCOMPLETE_CHALLENGE_SYMBOLS" in x for x in r1))

        # 2. Wrong Field ID (C1 observed in 0xbbbb instead of 0xaaaa)
        ho_wrong_fid = (full_ho - {("0xaaaa", gt_syms["C1"], "A"), ("0xaaaa", gt_syms["C1"], "D")}) | {
            ("0xbbbb", gt_syms["C1"], "A"),
            ("0xbbbb", gt_syms["C1"], "D"),
        }
        ok2, _, r2 = validate_challenge_ground_truth_and_holdout(gt_syms, decl, fmap, ho_wrong_fid)
        self.assertFalse(ok2)
        self.assertTrue(any("MISSING_DECLARED_GT_EFFECT_C1" in x for x in r2))

        # 3. Missing write effect D on C1 (only A observed)
        ho_no_d = full_ho - {("0xaaaa", gt_syms["C1"], "D")}
        ok3, _, r3 = validate_challenge_ground_truth_and_holdout(gt_syms, decl, fmap, ho_no_d)
        self.assertFalse(ok3)
        self.assertTrue(any("MISSING_DECLARED_GT_EFFECT_C1" in x for x in r3))


    def test_24_failed_setup_zero_fields_not_counted_as_zero_omission_workflow(self) -> None:
        """Regression test for predetermined workflow evaluation:
        When a workflow returns rc=2, stdout='FAIL: setup', and only an init record with 0 Field entries,
        `evaluate_regression_workflow_case` must mark `business_workflow_completed=False`,
        `workset_coverage_zero_omission=False` (omitted_pages_count=None), and
        `frozen_protected_enclave_completed=False` — NEVER counting it as a zero-omission workflow!
        """
        wsp = {"id": "broken_setup_case", "min_rec": 5}
        rw_cov = {
            "sample": "mock",
            "returncode": 2,
            "timed_out": False,
            "measurement_invalid": False,
            "stdout": "FAIL: setup",
            "ipi_mask": 7,
            "records": [
                {
                    "call_seq": 0,
                    "ecall_index": 0,
                    "tag": "host_normal",
                    "sgx_status": 0,
                    "measurement_invalid": 0,
                    "syscall_errors": 0,
                    "ipi_flush_failures": 0,
                    "fast_forwarded_prior": 0,
                    "mutation_oob_rejected": 0,
                    "strict_mode": 0,
                    "strict_non_ready_fault_count": 0,
                    "fields": [],
                }
            ],
        }
        res = evaluate_regression_workflow_case(
            wsp,
            rw_cov,
            None,
            expected_fids={"0x1111111111111111"},
            closed_target_effects_by_fid={"0x1111111111111111": {(0x1000, "A")}},
            ready_sel_set={0},
        )
        self.assertFalse(res["business_workflow_completed"])
        self.assertFalse(res["workset_coverage_zero_omission"])
        self.assertIsNone(res["omitted_pages_count"])
        self.assertFalse(res["frozen_protected_enclave_completed"])
        self.assertTrue(any("UNEXPECTED_RETURNCODE_2_EXPECTED_0" in x for x in res["business_reasons"]))
        self.assertTrue(any("NEGATIVE_STDOUT_MARKER" in x for x in res["business_reasons"]))
        self.assertTrue(any("TRUNCATED_TRACE" in x for x in res["business_reasons"]))
        self.assertTrue(any("MISSING_REQUIRED_FIELDS" in x for x in res["business_reasons"]))

    def test_25_is_valid_measurement_run_rejects_missing_aex_broken_ad_fast_forward_and_wrong_ipi(self) -> None:
        """Verify unified underlying check `is_valid_measurement_run` rejects:
        1) Missing `s3_active_aex_count`,
        2) Illegal `ad='BROKEN'` (and `extract_valid_s3_effects` raises ValueError),
        3) `fast_forwarded_prior > 0`,
        4) Mismatched `ipi_aex_verified_mask` (`4` vs `7`).
        """
        # 1. Missing s3_active_aex_count
        r1 = make_valid_mock_run()
        del r1["records"][0]["fields"][0]["s3_active_aex_count"]
        ok1, rs1 = is_valid_measurement_run(r1, require_ipi_mask=7)
        self.assertFalse(ok1)
        self.assertTrue(any("MISSING_S3_ACTIVE_AEX_COUNT" in x for x in rs1))

        # 2. Illegal ad='BROKEN'
        r2 = make_valid_mock_run()
        r2["records"][0]["fields"][0]["s3"][0]["ad"] = "BROKEN"
        ok2, rs2 = is_valid_measurement_run(r2, require_ipi_mask=7)
        self.assertFalse(ok2)
        self.assertTrue(any("MALFORMED_S3_ITEM" in x for x in rs2))
        with self.assertRaises(ValueError):
            extract_valid_s3_effects(r2["records"][0]["fields"][0])

        # 3. fast_forwarded_prior > 0
        r3 = make_valid_mock_run()
        r3["records"][0]["fast_forwarded_prior"] = 1
        ok3, rs3 = is_valid_measurement_run(r3, require_ipi_mask=7)
        self.assertFalse(ok3)
        self.assertIn("RECORD_0_FAST_FORWARD_SKIPPED", rs3)

        # 4. Mismatched ipi_aex_verified_mask (4 vs requested 7, and 7 vs requested 4)
        r4 = make_valid_mock_run()
        ok4_7, _ = is_valid_measurement_run(r4, require_ipi_mask=7)
        self.assertTrue(ok4_7)
        ok4_4, rs4 = is_valid_measurement_run(r4, require_ipi_mask=4)
        self.assertFalse(ok4_4)
        self.assertTrue(any("IPI_MASK_7_NE_4" in x for x in rs4))


if __name__ == "__main__":
    unittest.main()
