#!/usr/bin/env python3
"""Regression tests for ExplorationKernel & In-Place Call Replacement:
1. Single-round feedback divergence on a REAL target (`ehsm`) execution entry point.
2. State-novelty without new pages or heap growth (`new_effects_count == 0`, `heap_grew == False`,
   `target_new_state_keys > 0`) spawns a follow-up joint probe and executes it next.
3. Multi-branch parameter slot (two distinct values on the same parameter slot unlocking two
   different pages) discovers BOTH branches via periodic `low_priority_queue` anti-starvation
   scheduling, and accounts all remaining low-priority candidates in `unexplored_frontier`.
4. Per-Field and per-sseq feedback isolation (same page RVA in Field B vs Field A is recognized
   as a new concrete Field effect; different `selector_seq` positions have distinct state keys).
5. In-place call replacement (`replace_scalar` / `replace_xor`) vs insert (`set_scalar`) on real
   SGX hardware, including duplicate-replacement rejection and SGX SDK AES-128-CMAC (`C7`).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from elf_workset import normalized_fields, resolve_selectors  # noqa: E402
from exploration_kernel import ExplorationKernel, extract_concrete_record_feedback  # noqa: E402
from run_native_sgx import run_sample  # noqa: E402


class TestExplorationKernelAndReplace(unittest.TestCase):
    def test_single_round_feedback_changes_subsequent_selection_on_real_target(self) -> None:
        """On the real `ehsm` target schema and selectors, fix `rng_seed=101` and change ONLY
        one round feedback; verify that subsequent candidate selection changes deterministically.
        """
        tdir = DYN_ROOT / "targets" / "ehsm"
        edl_schema = json.loads((tdir / "edl_schema.json").read_text())
        fields = normalized_fields(tdir / "fields.json")
        selectors = resolve_selectors(tdir / "selectors.json", fields, Path(edl_schema["edl_path"]))

        def make_runner(trigger_feedback: bool):
            def runner(plan: dict) -> dict:
                if plan["tag"] == "L0_L1_seed":
                    return {
                        "returncode": 0,
                        "measurement_invalid": False,
                        "records": [
                            {"call_seq": 0, "ecall_index": 0, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": []},
                            {"call_seq": 1, "ecall_index": 1, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x1111", "s3": [{"rva": "0x12000", "ad": "D"}]}]},
                            {"call_seq": 2, "ecall_index": 2, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x2222", "s3": [{"rva": "0x13000", "ad": "D"}]}]},
                            {"call_seq": 3, "ecall_index": 3, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x3333", "s3": [{"rva": "0x14000", "ad": "D"}]}]},
                            {"call_seq": 4, "ecall_index": 4, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x4444", "s3": [{"rva": "0x15000", "ad": "D"}]}]},
                        ],
                    }
                eidx = plan.get("ecall_index", 2)
                base_rva = {1: "0x12000", 2: "0x13000", 3: "0x14000", 4: "0x15000"}.get(eidx, "0x12000")
                fid = {1: "0x1111", 2: "0x2222", 3: "0x3333", 4: "0x4444"}.get(eidx, "0x1111")
                extra_page = []
                if trigger_feedback and plan["step_index"] == 1:
                    extra_page = [{"rva": "0x99000", "ad": "D"}]
                return {
                    "returncode": 0,
                    "measurement_invalid": False,
                    "records": [
                        {
                            "call_seq": 0,
                            "ecall_index": eidx,
                            "selector_seq": plan.get("selector_seq", 0),
                            "tag": plan.get("tag", "probe"),
                            "sgx_status": 0,
                            "ms_retval": 0,
                            "fields": [{"field_id": fid, "s3": [{"rva": base_rva, "ad": "D"}, *extra_page]}],
                        }
                    ],
                }

            step_counter = 0

            def wrapped(plan: dict) -> dict:
                nonlocal step_counter
                plan = dict(plan, step_index=step_counter)
                step_counter += 1
                return runner(plan)

            return wrapped

        k_no_fb = ExplorationKernel(
            sample="ehsm",
            edl_schema=edl_schema,
            selectors=selectors,
            runner_fn=make_runner(False),
            mode="feedback_guided",
            rng_seed=101,
            max_enclave_creations=16,
        ).run()

        k_with_fb = ExplorationKernel(
            sample="ehsm",
            edl_schema=edl_schema,
            selectors=selectors,
            runner_fn=make_runner(True),
            mode="feedback_guided",
            rng_seed=101,
            max_enclave_creations=16,
        ).run()

        tags_no_fb = [x["tag"] for x in k_no_fb["selection_trace"]]
        tags_with_fb = [x["tag"] for x in k_with_fb["selection_trace"]]
        self.assertEqual(tags_no_fb[:2], tags_with_fb[:2])
        self.assertNotEqual(tags_no_fb[2:], tags_with_fb[2:])

    def test_state_novelty_without_new_pages_spawns_followup(self) -> None:
        """Regression test for state novelty without new pages or heap growth:
        When a `boundary` scalar candidate touches NO new pages (`new_effects_count == 0`) and
        does NOT grow the heap (`heap_grew == False`), but produces a new valid `state_obs_key`
        (e.g. deeper stack bucket on the target Field call), `ExplorationKernel` must record
        `new_valid_state_key_without_new_pages` and immediately schedule `feedback_joint_...` next!
        """
        tdir = DYN_ROOT / "targets" / "challenge-bench"
        edl_schema = json.loads((tdir / "edl_schema.json").read_text())
        fields = normalized_fields(tdir / "fields.json")
        selectors = resolve_selectors(tdir / "selectors.json", fields, Path(edl_schema["edl_path"]))

        def runner(plan: dict) -> dict:
            if plan["tag"] == "L0_L1_seed":
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
                            "fields": [{
                                "field_id": "0x1111",
                                "gateB_rsp_rva": "0x40000",
                                "gateD_rsp_rva": "0x3f000",
                                "s3": [{"rva": "0x12000", "ad": "D"}],
                            }],
                        }
                    ],
                }
            is_boundary = (plan.get("family") == "boundary")
            rsp_d = "0x3c000" if is_boundary else "0x3f000"
            return {
                "returncode": 0,
                "measurement_invalid": False,
                "records": [
                    {
                        "call_seq": 0,
                        "ecall_index": plan.get("ecall_index", 3),
                        "selector_seq": plan.get("selector_seq", 0),
                        "tag": plan.get("tag", "probe"),
                        "sgx_status": 0,
                        "ms_retval": 0,
                        "fields": [{
                            "field_id": "0x1111",
                            "gateB_rsp_rva": "0x40000",
                            "gateD_rsp_rva": rsp_d,
                            "s3": [{"rva": "0x12000", "ad": "D"}],
                        }],
                    }
                ],
            }

        ksum = ExplorationKernel(
            sample="challenge-bench",
            edl_schema=edl_schema,
            selectors=selectors,
            runner_fn=runner,
            mode="feedback_guided",
            rng_seed=101,
            max_enclave_creations=18,
        ).run()

        reasons = [p["reason"] for p in ksum["productive_plans"]]
        self.assertIn("new_valid_state_key_without_new_pages", reasons)
        tags = [x["tag"] for x in ksum["selection_trace"]]
        self.assertTrue(any(t.startswith("feedback_joint_") for t in tags))

    def test_multi_branch_parameter_slot_discovers_both_branches_and_tracks_frontier(self) -> None:
        """Regression test for a parameter slot where TWO distinct values (`val=2` and `val=16`)
        on the SAME parameter (`ecall 1`, `param 0`) trigger TWO different branches (`0x81000`
        and `0x82000`). Verifies that reprioritizing after the first hit does NOT starve the
        second value (discovered via periodic `low_priority_queue` scheduling) and that
        `unexplored_frontier` accounts for all remaining low-priority candidates.
        """
        tdir = DYN_ROOT / "targets" / "challenge-bench"
        edl_schema = json.loads((tdir / "edl_schema.json").read_text())
        fields = normalized_fields(tdir / "fields.json")
        selectors = resolve_selectors(tdir / "selectors.json", fields, Path(edl_schema["edl_path"]))

        hit_branches: set[str] = set()

        def runner(plan: dict) -> dict:
            s3 = [{"rva": "0x12000", "ad": "D"}]
            if plan.get("family") == "replace_prefix" and plan.get("ecall_index") == 1:
                if plan.get("scalar_val") == 2:
                    s3.append({"rva": "0x81000", "ad": "D"})
                    hit_branches.add("branch_val_2")
                elif plan.get("scalar_val") == 16:
                    s3.append({"rva": "0x82000", "ad": "D"})
                    hit_branches.add("branch_val_16")
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
                        "fields": [{"field_id": "0x1111", "s3": s3}],
                    }
                ],
            }

        ksum = ExplorationKernel(
            sample="challenge-bench",
            edl_schema=edl_schema,
            selectors=selectors,
            runner_fn=runner,
            mode="feedback_guided",
            rng_seed=101,
            max_enclave_creations=45,
        ).run()

        self.assertEqual(hit_branches, {"branch_val_2", "branch_val_16"})
        uf = ksum["unexplored_frontier"]
        self.assertIn("remaining_low_priority_candidates", uf)
        self.assertEqual(
            uf["total_unexplored_candidates"],
            sum(uf["remaining_candidates_by_family"].values())
            + uf["remaining_low_priority_candidates"]
            + uf["remaining_followup_candidates"],
        )

    def test_per_field_and_per_sseq_feedback_isolation(self) -> None:
        """Verify that `extract_concrete_record_feedback` includes `selector_seq` and Field IDs
        in `state_obs_key` and tracks `(field_id, rva, effect)` tuples separately per Field.
        """
        r_sseq0 = {
            "ecall_index": 3,
            "selector_seq": 0,
            "sgx_status": 0,
            "ms_retval": 0,
            "fields": [{"field_id": "0xaaaa", "s3": [{"rva": "0x12000", "ad": "A"}]}],
        }
        r_sseq2 = {
            "ecall_index": 3,
            "selector_seq": 2,
            "sgx_status": 0,
            "ms_retval": 0,
            "fields": [{"field_id": "0xaaaa", "s3": [{"rva": "0x12000", "ad": "A"}]}],
        }
        r_other_field = {
            "ecall_index": 5,
            "selector_seq": 0,
            "sgx_status": 0,
            "ms_retval": 0,
            "fields": [{"field_id": "0xbbbb", "s3": [{"rva": "0x12000", "ad": "A"}]}],
        }
        fb0 = extract_concrete_record_feedback(r_sseq0)
        fb2 = extract_concrete_record_feedback(r_sseq2)
        fbb = extract_concrete_record_feedback(r_other_field)
        self.assertNotEqual(fb0["state_obs_key"], fb2["state_obs_key"])
        self.assertTrue(fb0["s3_field_effects"].isdisjoint(fbb["s3_field_effects"]))

    def test_hardware_replace_scalar_executes_once_and_rejects_duplicate_token(self) -> None:
        """On real SGX hardware (`challenge-bench`), verify that:
        - `set_scalar:1:0:0:2` inserts an extra call before the normal call (10 ECALL records),
        - `replace_scalar:1:0:0:2` replaces the call in-place and executes it ONCE (9 ECALL records),
        - Duplicate replacement tokens at the same call site (`replace_scalar:1:0:0:2;replace_scalar:1:0:0:4`)
          are rejected with `measurement_invalid=True` and still execute the ECALL only ONCE.
        """
        res_insert = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="set_scalar:1:0:0:2")
        res_replace = run_sample("challenge-bench", mode="profile_4gate", ipi_mask=7, intervention="replace_scalar:1:0:0:2")
        res_dup = run_sample(
            "challenge-bench",
            mode="profile_4gate",
            ipi_mask=7,
            intervention="replace_scalar:1:0:0:2;replace_scalar:1:0:0:4",
        )
        self.assertEqual(res_insert["returncode"], 0)
        self.assertEqual(res_replace["returncode"], 0)
        self.assertEqual(len(res_insert["records"]), 10)
        self.assertEqual(len(res_replace["records"]), 9)
        self.assertEqual([r["tag"] for r in res_replace["records"] if r["ecall_index"] == 1], ["replace_scalar_p0_val_2"])
        self.assertTrue(res_dup["measurement_invalid"])
        self.assertEqual([r["tag"] for r in res_dup["records"] if r["ecall_index"] == 1], ["replace_scalar_p0_val_2"])

    def test_c2_overwriting_setter_and_c7_sgx_sdk_cmac_token_chain_on_hardware(self) -> None:
        """Verify on real SGX hardware (`challenge-bench`, 8 challenges, 2 Fields) that:
        1. C2 (overwriting setter): `set_scalar:1:0:0:2` is overwritten by normal `ecall_configure_stage(0)`
           and FAILS to touch `challenge_page_c2`, whereas `replace_scalar:1:0:0:2` SOLVES C2.
        2. C7 (SGX SDK `sgx_rijndael128_cmac_msg` authenticated opaque token chain): `set_scalar:4:0:0:2`
           and forged consumer input `xor_param:5:0:1:4:2` both FAIL to touch `challenge_page_c7`,
           whereas in-place producer replacement `replace_scalar:4:0:0:2` SOLVES C7 in Field 2.
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
