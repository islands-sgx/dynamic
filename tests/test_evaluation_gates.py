from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from tools import check_vendor_sync
from tools import evaluate_worksets as evaluation


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CallScheduleTests(unittest.TestCase):
    def test_signal_requests_are_additional_to_two_default_calls(self) -> None:
        self.assertEqual(evaluation.expected_host_call_count("signal-cds", []), 6)
        self.assertEqual(evaluation.expected_host_call_count("signal-cds", ["--requests", "6"]), 12)
        self.assertEqual(evaluation.expected_host_call_count("signal-cds", ["--requests", "0"]), 6)

    def test_signal_max_queries_suppresses_boundary_ecall(self) -> None:
        cases = (
            ([], 6),
            (["--requests", "4"], 10),
            (["--queries", "8192"], 7),
            (["--requests", "4", "--queries", "8192"], 9),
            (["--queries", "8192", "--requests", "4"], 9),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(
                    evaluation.expected_host_call_count("signal-cds", args),
                    expected,
                )

    def test_signal_explicit_schedule_catches_missing_default_calls(self) -> None:
        calls = evaluation.expected_host_call_count("signal-cds", ["--requests", "2"])
        result = {
            "mode": "dynamic_4gate",
            "host_sha256": evaluation.HOST_BINARY_SHA256["signal-cds"],
            "enclave_path": "/tmp/dynamic.4gate.aex0.signed.so",
            "enclave_sha256": "a" * 64,
            "returncode": 0,
            "timed_out": False,
            "measurement_invalid": False,
            "records": [
                {"tag": "host_normal", "call_seq": i, "sgx_status": 0}
                for i in range(calls - 2)
            ],
        }
        expected_artifacts = {
            "dynamic_4gate": {
                "valid": True,
                "path": result["enclave_path"],
                "sha256": result["enclave_sha256"],
            }
        }
        assessment = evaluation.assess_full_call_schedule(
            result, "signal-cds", ["--requests", "2"], run_artifacts=expected_artifacts
        )
        self.assertFalse(assessment["valid"])
        self.assertFalse(assessment["checks"]["host_call_count"])
        self.assertFalse(assessment["checks"]["host_call_sequence"])


class AEXNotifyTests(unittest.TestCase):
    def _valid_runs(self) -> tuple[dict, dict, dict]:
        aex0_event = {
            "page_rva": "0x1000",
            "encl_rip_rva": "0x1007",
            "access_kind": "X",
            "stage": "S3_BODY",
            "active_flag": 1,
        }
        aex0_schedule = {"valid": True, "returncode": 0}
        aex1_result = {
            "mode": "dynamic_final",
            "host_sha256": evaluation.HOST_BINARY_SHA256["qe3"],
            "enclave_path": "/tmp/dynamic.final.signed.so",
            "enclave_sha256": "b" * 64,
            "returncode": 1,
            "timed_out": False,
            "measurement_invalid": False,
            "records": [{
                "sgx_status": 0x1006,
                "fault_events": [{
                    **aex0_event,
                    "exitinfo": "0x0",
                }],
            }],
        }
        return aex0_event, aex0_schedule, aex1_result

    def test_same_fault_requires_same_instruction_and_expected_aex1_failure(self) -> None:
        aex0_event, aex0_schedule, aex1_result = self._valid_runs()
        artifacts = {
            "dynamic_final": {
                "valid": True,
                "path": aex1_result["enclave_path"],
                "sha256": aex1_result["enclave_sha256"],
            }
        }
        result = evaluation.assess_same_fault_aex_notify(
            aex0_event, aex0_schedule, aex1_result, "qe3", "0x1000", artifacts
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["verdict"], "PASS")

        aex1_result["records"][0]["fault_events"][0]["encl_rip_rva"] = "0x1008"
        result = evaluation.assess_same_fault_aex_notify(
            aex0_event, aex0_schedule, aex1_result, "qe3", "0x1000", artifacts
        )
        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["aex1_same_instruction"])

        aex1_result["records"][0]["fault_events"].insert(0, {
            "page_rva": "0x2000",
            "encl_rip_rva": "0x2001",
            "access_kind": "R",
            "stage": "S2_PRETOUCH",
            "active_flag": 1,
        })
        result = evaluation.assess_same_fault_aex_notify(
            aex0_event, aex0_schedule, aex1_result, "qe3", "0x1000", artifacts
        )
        self.assertFalse(result["checks"]["aex1_same_page"])

    def test_aggregate_calibration_cannot_pass_when_aex1_comparison_fails(self) -> None:
        controls = {
            key: {"fault_caught": True, "run_schedule": {"valid": True}}
            for key in ("X_code_page", "R_rodata_page", "W_data_page")
        }
        restored = {"valid": True}
        self.assertTrue(evaluation.calibration_gate_pass(controls, restored, 0, {"valid": True, "verdict": "PASS"}))
        self.assertFalse(evaluation.calibration_gate_pass(controls, restored, 0, {"valid": False, "verdict": "INVALID_OR_FAIL"}))


class ArtifactPreflightTests(unittest.TestCase):
    def _make_4gate_fixture(self, root: Path) -> tuple[Path, dict]:
        tdir = root / "targets" / "sample"
        tdir.mkdir(parents=True)
        input_elf = tdir / "enclave.dynamic.final.so"
        patched_elf = tdir / "enclave.dynamic.4gate.so"
        signed_elf = tdir / "enclave.dynamic.4gate.aex0.signed.so"
        input_elf.write_bytes(b"input elf")
        patched_elf.write_bytes(b"patched output")
        signed_elf.write_bytes(b"signed aex0")
        metadata = {
            "input_elf": str(input_elf),
            "input_elf_sha256": digest(input_elf.read_bytes()),
            "output_elf": str(patched_elf),
            "output_elf_sha256": digest(patched_elf.read_bytes()),
            "signed_output_elf": str(signed_elf),
            "signed_output_elf_sha256": digest(signed_elf.read_bytes()),
        }
        (tdir / "enclave.dynamic.4gate.json").write_text(json.dumps(metadata))
        return tdir, metadata

    def test_4gate_preflight_binds_patched_and_signed_outputs_to_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tdir, _ = self._make_4gate_fixture(Path(tmp))
            result = evaluation.validate_4gate_artifact(tdir, "dynamic", tdir / "enclave.dynamic.final.so")
            self.assertTrue(result["valid"])

            (tdir / "enclave.dynamic.4gate.so").write_bytes(b"tampered patched output")
            result = evaluation.validate_4gate_artifact(tdir, "dynamic", tdir / "enclave.dynamic.final.so")
            self.assertFalse(result["valid"])
            self.assertIn("output_elf_sha256", result["errors"])

    def test_run_binding_rejects_a_different_aex0_signed_elf(self) -> None:
        result = {
            "enclave_path": "/tmp/strict.aex0.signed.so",
            "enclave_sha256": "a" * 64,
        }
        expected = {"valid": True, "path": result["enclave_path"], "sha256": "b" * 64}
        self.assertFalse(evaluation.run_enclave_binding_valid(result, expected))

    def test_evaluation_preflight_invokes_source_byte_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker_dir = root / "tools"
            vendor_dir = root / "vendor" / "implement"
            checker_dir.mkdir()
            vendor_dir.mkdir(parents=True)
            checker_dir.joinpath("check_vendor_sync.py").write_text(Path(check_vendor_sync.__file__).read_text())
            source = vendor_dir / "tracked.py"
            source.write_bytes(b"pinned bytes")
            manifest = {
                "commit": "a3cf16bce12267c4323cabe2b571fdae9a203b01",
                "tracked_file_count": 1,
                "files_sha256": {"tracked.py": digest(b"pinned bytes")},
            }
            (root / "vendor" / "IMPLEMENT_UPSTREAM.json").write_text(json.dumps(manifest))
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "vendor/implement/tracked.py"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "tools/check_vendor_sync.py"], check=True)
            with mock.patch.object(evaluation, "DYN_ROOT", root):
                self.assertTrue(evaluation.validate_vendor_source()["valid"])
                source.write_bytes(b"modified bytes")
                result = evaluation.validate_vendor_source()
                self.assertFalse(result["valid"])
                self.assertIn("source byte digest mismatch", result["output"])

    def test_source_manifest_hash_check_detects_modified_vendor_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "vendor" / "implement" / "tracked.py"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"pinned bytes")
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "vendor/implement/tracked.py"], check=True)
            expected = {"tracked.py": digest(b"pinned bytes")}
            self.assertEqual(check_vendor_sync.compare_manifest_bytes(root, expected, 1), [])
            source.write_bytes(b"changed bytes")
            failures = check_vendor_sync.compare_manifest_bytes(root, expected, 1)
            self.assertTrue(any("source byte digest mismatch" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
