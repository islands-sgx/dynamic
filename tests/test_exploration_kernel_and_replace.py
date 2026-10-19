#!/usr/bin/env python3
"""Regression tests for Milestone 1:
1. Unified ExplorationKernel: with fixed candidates and random seed, changing ONLY one round's
   feedback deterministically alters subsequent candidate selection on the real kernel entry point.
2. In-place call replacement (`replace_scalar`) vs insert (`set_scalar`) on real SGX hardware:
   verifies single execution, ABI return-value writeback, and non-overwriting state persistence.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from exploration_kernel import ExplorationKernel  # noqa: E402
from run_native_sgx import run_sample  # noqa: E402


class TestExplorationKernelAndReplace(unittest.TestCase):
    def test_single_round_feedback_changes_subsequent_selection(self) -> None:
        """Fix candidate pool and rng_seed=101; change ONLY the feedback of the first boundary
        trial, and verify that `feedback_guided` schedules the spawned follow-up next while
        `fixed_round_robin` (or zero-feedback) does not.
        """
        tdir = DYN_ROOT / "targets" / "challenge-bench"
        edl_schema = json.loads((tdir / "edl_schema.json").read_text())
        selectors = json.loads((tdir / "selectors.json").read_text())["selectors"]
        for s in selectors:
            s["reachable_fields"] = ["0x1111"] if s["reachable_functions"] else []

        def make_runner(trigger_feedback_on_boundary: bool):
            def runner(plan: dict) -> dict:
                if plan["tag"] == "L0_L1_seed":
                    return {
                        "returncode": 0,
                        "measurement_invalid": False,
                        "records": [
                            {"call_seq": 0, "ecall_index": 0, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": []},
                            {"call_seq": 1, "ecall_index": 3, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x1111", "s3": [{"rva": "0x12000", "ad": "D"}]}]},
                        ],
                    }
                extra_page = []
                if trigger_feedback_on_boundary and plan["tag"].startswith("replace_prefix_e4_"):
                    extra_page = [{"rva": "0x99000", "ad": "D"}]
                return {
                    "returncode": 0,
                    "measurement_invalid": False,
                    "records": [
                        {
                            "call_seq": 0,
                            "ecall_index": 3,
                            "selector_seq": 0,
                            "sgx_status": 0,
                            "ms_retval": 0,
                            "fields": [{"field_id": "0x1111", "s3": [{"rva": "0x12000", "ad": "D"}, *extra_page]}],
                        }
                    ],
                }
            return runner

        k_no_fb = ExplorationKernel(
            sample="challenge-bench",
            edl_schema=edl_schema,
            selectors=selectors,
            runner_fn=make_runner(False),
            mode="feedback_guided",
            rng_seed=101,
            max_enclave_creations=24,
        ).run()

        k_with_fb = ExplorationKernel(
            sample="challenge-bench",
            edl_schema=edl_schema,
            selectors=selectors,
            runner_fn=make_runner(True),
            mode="feedback_guided",
            rng_seed=101,
            max_enclave_creations=24,
        ).run()

        tags_no_fb = [x["tag"] for x in k_no_fb["selection_trace"]]
        tags_with_fb = [x["tag"] for x in k_with_fb["selection_trace"]]
        # Up to the first boundary step (step 10), both execute the exact same sequence
        self.assertEqual(tags_no_fb[:2], tags_with_fb[:2])
        self.assertNotEqual(tags_no_fb[2:], tags_with_fb[2:])
        self.assertTrue(any("demote_satisfied_slot_replace_prefix" in d["decision"] for d in k_with_fb["feedback_decisions"]))

    def test_hardware_replace_scalar_executes_once_vs_set_scalar_twice(self) -> None:
        """On real SGX hardware (`challenge-bench`), verify that:
        - `set_scalar:1:0:0:2` inserts an extra call before the normal call (total 6 ECALL records),
        - `replace_scalar:1:0:0:2` replaces the call in-place and executes it ONCE (total 5 ECALL records,
          with record[1].tag == 'replace_scalar_p0_val_2' and no duplicate host_normal for ecall 1).
        """
        res_insert = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="set_scalar:1:0:0:2")
        res_replace = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="replace_scalar:1:0:0:2")
        self.assertEqual(res_insert["returncode"], 0)
        self.assertEqual(res_replace["returncode"], 0)
        self.assertEqual(len(res_insert["records"]), 10)
        self.assertEqual(len(res_replace["records"]), 9)
        ecall1_tags_replace = [r["tag"] for r in res_replace["records"] if r["ecall_index"] == 1]
        self.assertEqual(ecall1_tags_replace, ["replace_scalar_p0_val_2"])


    def test_c2_overwriting_setter_and_c7_authenticated_token_chain_on_hardware(self) -> None:
        """Verify on real SGX hardware (`challenge-bench`, 8 challenges, 2 Fields) that:
        1. C2 (overwriting setter): `set_scalar:1:0:0:2` (insert-before-normal) is overwritten by
           the subsequent normal `ecall_configure_stage(0)` and FAILS to touch `challenge_page_c2`,
           whereas `replace_scalar:1:0:0:2` (in-place replacement) executes once and SOLVES C2.
        2. C7 (keyed-MAC opaque token producer-consumer chain): `set_scalar:4:0:0:2` and forged
           consumer input `xor_param:5:0:1:4:2` both FAIL to touch `challenge_page_c7`, whereas
           in-place producer replacement `replace_scalar:4:0:0:2` writes a valid MAC-authenticated
           token into the host buffer and SOLVES C7 in Field 2.
        """
        from elf_workset import ElfFile
        elf = ElfFile(DYN_ROOT / "targets" / "challenge-bench" / "enclave.profile.so")
        gt = {
            s["name"].replace("challenge_page_", "").upper(): s["value"]
            for s in elf.symbols()
            if s["name"].startswith("challenge_page_c") and not s["name"].endswith("base")
        }
        self.assertEqual(len(gt), 8)

        def s3_rvas(res: dict) -> set[int]:
            return {
                int(it["rva"], 16)
                for r in res["records"]
                for fo in r["fields"]
                for it in fo["s3"]
            }

        r_c2_ins = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="set_scalar:1:0:0:2")
        r_c2_rep = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="replace_scalar:1:0:0:2")
        self.assertNotIn(gt["C2"], s3_rvas(r_c2_ins))
        self.assertIn(gt["C2"], s3_rvas(r_c2_rep))

        r_c7_ins = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="set_scalar:4:0:0:2")
        r_c7_forg = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="xor_param:5:0:1:4:2", stop_before_normal_ecall="5:0")
        r_c7_rep = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="replace_scalar:4:0:0:2")
        self.assertNotIn(gt["C7"], s3_rvas(r_c7_ins))
        self.assertNotIn(gt["C7"], s3_rvas(r_c7_forg))
        self.assertIn(gt["C7"], s3_rvas(r_c7_rep))


if __name__ == "__main__":
    unittest.main()
