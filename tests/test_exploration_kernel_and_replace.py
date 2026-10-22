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
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from elf_workset import WorksetError, normalized_fields, resolve_selectors  # noqa: E402
from exploration_kernel import ExplorationKernel, build_unified_candidate_queues, extract_concrete_record_feedback  # noqa: E402
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
                            {"call_seq": 1, "ecall_index": 1, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x1111", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x12000", "ad": "D"}]}]},
                            {"call_seq": 2, "ecall_index": 2, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x2222", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x13000", "ad": "D"}]}]},
                            {"call_seq": 3, "ecall_index": 3, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x3333", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x14000", "ad": "D"}]}]},
                            {"call_seq": 4, "ecall_index": 4, "selector_seq": 0, "sgx_status": 0, "ms_retval": 0, "fields": [{"field_id": "0x4444", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x15000", "ad": "D"}]}]},
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
                            "fields": [{"field_id": fid, "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": base_rva, "ad": "D"}, *extra_page]}],
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
                                "ipi_aex_verified_mask": 7,
                                "heap_walk_truncated": 0,
                                "heap_pread_failures": 0,
                                "s3_active_aex_count": 0,
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
                            "ipi_aex_verified_mask": 7,
                            "heap_walk_truncated": 0,
                            "heap_pread_failures": 0,
                            "s3_active_aex_count": 0,
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
                        "fields": [{"field_id": "0x1111", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": s3}],
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
            "fields": [{"field_id": "0xaaaa", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x12000", "ad": "A"}]}],
        }
        r_sseq2 = {
            "ecall_index": 3,
            "selector_seq": 2,
            "sgx_status": 0,
            "ms_retval": 0,
            "fields": [{"field_id": "0xaaaa", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x12000", "ad": "A"}]}],
        }
        r_other_field = {
            "ecall_index": 5,
            "selector_seq": 0,
            "sgx_status": 0,
            "ms_retval": 0,
            "fields": [{"field_id": "0xbbbb", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x12000", "ad": "A"}]}],
        }
        fb0 = extract_concrete_record_feedback(r_sseq0)
        fb2 = extract_concrete_record_feedback(r_sseq2)
        fbb = extract_concrete_record_feedback(r_other_field)
        self.assertNotEqual(fb0["state_obs_key"], fb2["state_obs_key"])
        self.assertTrue(fb0["s3_field_effects"].isdisjoint(fbb["s3_field_effects"]))

    @unittest.skipUnless(os.environ.get("ATFIELD_RUN_HARDWARE_TESTS") == "1", "requires explicit SGX hardware opt-in")
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

    @unittest.skipUnless(os.environ.get("ATFIELD_RUN_HARDWARE_TESTS") == "1", "requires explicit SGX hardware opt-in")
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


    def test_measurement_invalid_and_crashed_run_isolated_from_feedback_and_discovery(self) -> None:
        """Regression test for unified evidence admission:
        When a probe returns `measurement_invalid=True` and `returncode=-9` with a fake S3 page
        `0xdead000` (`ad=D`), `ExplorationKernel` must:
          - Charge the enclave creation and ECALL count (`enclave_creations`, `total_ecalls_executed`),
          - Increment `measurement_invalid_runs`,
          - NOT merge `0xdead000` into `confirmed_s3_pages` / `confirmed_s3_effects`,
          - NOT increment `valid_field_entering_ecalls` for the invalid run,
          - Record `measurement_invalid_ignored` in `feedback_decisions`.
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
                            "measurement_invalid": 0,
                            "syscall_errors": 0,
                            "ipi_flush_failures": 0,
                            "mutation_oob_rejected": 0,
                            "ms_retval": 0,
                            "fields": [{"field_id": "0x1111", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0x12000", "ad": "D"}]}],
                        }
                    ],
                }
            # Every subsequent probe crashes with rc=-9 and measurement_invalid=True while trying to inject 0xdead000
            return {
                "returncode": -9,
                "measurement_invalid": True,
                "records": [
                    {
                        "call_seq": 0,
                        "ecall_index": 3,
                        "selector_seq": 0,
                        "sgx_status": 0,
                        "measurement_invalid": 1,
                        "invalid_reason": "mock_crash",
                        "ms_retval": 0,
                        "fields": [{"field_id": "0x1111", "ipi_aex_verified_mask": 7, "heap_walk_truncated": 0, "heap_pread_failures": 0, "s3_active_aex_count": 0, "s3": [{"rva": "0xdead000", "ad": "D"}]}],
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
            max_enclave_creations=4,
        ).run()

        self.assertEqual(ksum["enclave_creations"], 4)
        self.assertEqual(ksum["measurement_invalid_runs"], 3)
        self.assertEqual(ksum["valid_field_entering_ecalls"], 1)  # Only the seed run!
        self.assertEqual(ksum["confirmed_s3_pages"], 1)  # Only 0x12000 from seed; 0xdead000 rejected!
        self.assertEqual(ksum["confirmed_s3_effects"], 2)
        self.assertEqual(len(ksum["productive_plans"]), 0)
        self.assertTrue(all(d["decision"].startswith("measurement_invalid_ignored:") for d in ksum["feedback_decisions"]))



    def test_04_replace_coupled_single_call_and_2step_plan_reuse(self) -> None:
        """Verify Stage 2A (coupled_struct_constraints -> replace_coupled) and Stage 2B
        (valid_prefix_corpus -> 2-step composed replay plan `P1;P2`) in ExplorationKernel.
        """
        tdir = DYN_ROOT / "targets" / "ehsm-opt-1"
        edl_schema_with_coupled = json.loads((tdir / "edl_schema.json").read_text())
        edl_schema_with_coupled["coupled_struct_constraints"] = [
            {
                "constraint_id": "test_coupled_producer",
                "ecall_index": 1,
                "selector_seq": 0,
                "coupled_ops": ["f:0:0:4:31", "f:0:40:4:80", "s:1:124"],
                "description": "Test coupled producer constraint",
            }
        ]
        fields = normalized_fields(tdir / "fields.json")
        selectors = resolve_selectors(tdir / "selectors.json", fields, Path(edl_schema_with_coupled["edl_path"]))
        queues, _ = build_unified_candidate_queues(
            edl_schema_with_coupled,
            selectors,
            [{"call_seq": 0, "ecall_index": 1, "selector_seq": 0, "fields": []}],
            rng_seed=101,
        )
        coupled_specs = [c["spec"] for c in queues["replace_prefix"] if c.get("subkind") == "coupled_multi_field_replacement"]
        self.assertIn("replace_coupled:1:0:f:0:0:4:31+f:0:40:4:80+s:1:124", coupled_specs)

        # Now run ExplorationKernel on a mock 2-Field stateful workflow where:
        # - Field 0 (ecall 1) is a scalable state-populating Field (`scale_bound_v2`)
        # - Field 1 (ecall 2) is a query Field whose mode=2 only touches page 0x99000 IF ecall 1 was scaled in the same enclave run!
        two_field_schema = {
            "sample": "mock_two_field",
            "ecalls": [
                {
                    "ecall_index": 1,
                    "name": "ecall_populate",
                    "has_retval": True,
                    "replay_supported": True,
                    "ms_layout": {"size": 24},
                    "params": [
                        {"name": "rows", "direction": "in", "is_pointer": True, "ms_offset": 8, "ms_size": 8, "elem_size": 4, "bound_kind": "count", "bound_ms_offset": 16, "bound_ms_size": 8, "param_replay_supported": True},
                        {"name": "count", "direction": "val", "is_pointer": False, "ms_offset": 16, "ms_size": 8, "elem_size": 8, "param_replay_supported": True},
                    ],
                },
                {
                    "ecall_index": 2,
                    "name": "ecall_query",
                    "has_retval": True,
                    "replay_supported": True,
                    "ms_layout": {"size": 16},
                    "params": [
                        {"name": "qmode", "direction": "val", "is_pointer": False, "ms_offset": 8, "ms_size": 4, "elem_size": 4, "param_replay_supported": True},
                    ],
                },
            ],
        }
        two_field_selectors = [
            {"ecall_index": 1, "name": "ecall_populate", "reachable_fields": ["0x1111"]},
            {"ecall_index": 2, "name": "ecall_query", "reachable_fields": ["0x2222"]},
        ]

        def mock_2field_runner(plan: dict) -> dict:
            spec = plan.get("spec", "")
            scaled = "scale_bound_v2:1:0:" in spec
            qmode2 = "replace_scalar:2:0:0:2" in spec
            f1_s3 = [{"rva": "0x10000", "ad": "A"}]
            if scaled:
                f1_s3.append({"rva": "0x20000", "ad": "D"})
            f2_s3 = [{"rva": "0x30000", "ad": "A"}]
            if scaled and qmode2:
                # Multi-step state dependency: only reached when BOTH scale on ecall 1 AND qmode=2 on ecall 2 run in the same instance!
                f2_s3.append({"rva": "0x99000", "ad": "D"})
            elif qmode2:
                f2_s3.append({"rva": "0x31000", "ad": "A"})
            return {
                "returncode": 0,
                "ipi_mask": 7,
                "records": [
                    {
                        "ecall_index": 1,
                        "selector_seq": 0,
                        "tag": "scale" if scaled else "host_normal",
                        "sgx_status": 0,
                        "ms_retval": 0,
                        "measurement_invalid": 0,
                        "syscall_errors": 0,
                        "ipi_flush_failures": 0,
                        "mutation_oob_rejected": 0,
                        "fast_forwarded_prior": 0,
                        "fields": [{
                            "field_id": "0x1111",
                            "ipi_aex_verified_mask": 7,
                            "s3_active_aex_count": 2,
                            "heap_lo_rva": "0x50000",
                            "heap_hi_rva": "0x58000" if scaled else "0x51000",
                            "s0": [{"rva": "0x1000", "ad": "A"}],
                            "s1": [],
                            "s2": [],
                            "s3": f1_s3,
                            "s3_pretouch_seg": [],
                            "heap_walk_truncated": 0,
                            "heap_pread_failures": 0,
                        }],
                    },
                    {
                        "ecall_index": 2,
                        "selector_seq": 0,
                        "tag": "replace_scalar_p0_val_2" if qmode2 else "host_normal",
                        "sgx_status": 0,
                        "ms_retval": 0,
                        "measurement_invalid": 0,
                        "syscall_errors": 0,
                        "ipi_flush_failures": 0,
                        "mutation_oob_rejected": 0,
                        "fast_forwarded_prior": 0,
                        "fields": [{
                            "field_id": "0x2222",
                            "ipi_aex_verified_mask": 7,
                            "s3_active_aex_count": 2,
                            "heap_lo_rva": "0x50000",
                            "heap_hi_rva": "0x58000" if (scaled and qmode2) else "0x51000",
                            "s0": [{"rva": "0x1000", "ad": "A"}],
                            "s1": [],
                            "s2": [],
                            "s3": f2_s3,
                            "s3_pretouch_seg": [],
                            "heap_walk_truncated": 0,
                            "heap_pread_failures": 0,
                        }],
                    },
                ],
            }

        kernel = ExplorationKernel(
            sample="mock_two_field",
            edl_schema=two_field_schema,
            selectors=two_field_selectors,
            runner_fn=mock_2field_runner,
            mode="feedback_guided",
            rng_seed=101,
        )
        summary = kernel.run()
        self.assertTrue(len(summary["valid_prefix_corpus"]) >= 1)
        self.assertIn(("0x2222", 0x99000, "D"), kernel.cumulative_s3_field_effects)


class TestConservativeAllFieldsSelectors(unittest.TestCase):
    FIELD_IDS = ["0x0000000000001111", "0x0000000000002222"]

    def resolve_payload(self, payload: dict, field_functions: tuple[str, str] = ("field_a", "field_b")) -> list[dict]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        edl_file = root / "sample.edl"
        edl_file.write_text(
            "enclave { trusted { public void ecall_a(); public void ecall_b(); }; };\n"
        )
        selector_file = root / "selectors.json"
        selector_file.write_text(json.dumps(payload))
        fields = [
            {"id": self.FIELD_IDS[0], "function": field_functions[0]},
            {"id": self.FIELD_IDS[1], "function": field_functions[1]},
        ]
        return resolve_selectors(selector_file, fields, edl_file)

    def policy_payload(self) -> dict:
        return {
            "schema": "atfield-selectors-v1",
            "policy": "conservative-all-fields",
            "selectors": [
                {"ecall_index": 0, "name": "ecall_a", "reachable_fields": list(reversed(self.FIELD_IDS))},
                {"ecall_index": 1, "name": "ecall_b", "reachable_fields": self.FIELD_IDS.copy()},
            ],
        }

    def test_policy_resolves_all_field_ids_and_marks_policy(self) -> None:
        resolved = self.resolve_payload(self.policy_payload(), field_functions=("same_name", "same_name"))

        for selector in resolved:
            self.assertEqual(selector["reachable_fields"], self.FIELD_IDS)
            self.assertEqual(selector["policy"], "conservative-all-fields")
            self.assertNotIn("reachable_functions", selector)

    def test_policy_rejects_missing_duplicate_unknown_ids_and_function_entries(self) -> None:
        invalid_payloads = []

        missing = self.policy_payload()
        missing["selectors"][0]["reachable_fields"] = self.FIELD_IDS[:1]
        invalid_payloads.append((missing, "every fields.json ID exactly once"))

        duplicate = self.policy_payload()
        duplicate["selectors"][0]["reachable_fields"] = [self.FIELD_IDS[0], self.FIELD_IDS[0]]
        invalid_payloads.append((duplicate, "repeats reachable Field ID"))

        unknown = self.policy_payload()
        unknown["selectors"][0]["reachable_fields"] = [self.FIELD_IDS[0], "0x0000000000003333"]
        invalid_payloads.append((unknown, "unknown Field ID"))

        function_names = self.policy_payload()
        function_names["selectors"][0]["reachable_functions"] = ["field_a", "field_b"]
        invalid_payloads.append((function_names, "must contain only"))

        for payload, message in invalid_payloads:
            with self.subTest(message=message):
                with self.assertRaisesRegex(WorksetError, message):
                    self.resolve_payload(payload)

    def test_hand_written_function_selectors_keep_legacy_resolution(self) -> None:
        payload = {
            "schema": "atfield-selectors-v1",
            "selectors": [
                {"ecall_index": 0, "name": "ecall_a", "reachable_functions": ["field_a"]},
                {"ecall_index": 1, "name": "ecall_b", "reachable_functions": ["field_b"]},
            ],
        }

        resolved = self.resolve_payload(payload)

        self.assertEqual([item["reachable_fields"] for item in resolved], [[self.FIELD_IDS[0]], [self.FIELD_IDS[1]]])
        self.assertEqual(resolved[0]["reachable_functions"], ["field_a"])
        self.assertNotIn("policy", resolved[0])


class TestImplementDynamicSelectorContract(unittest.TestCase):
    IMPLEMENT_ROOT = Path("/home/meandssh/islands-sgx/implement")
    SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")

    def test_current_implement_generator_output_is_consumed_by_dynamic(self) -> None:
        implement_entry = self.IMPLEMENT_ROOT / "build" / "workset" / "workset.ts"
        if not implement_entry.is_file():
            self.skipTest(f"current implement selector generator is unavailable: {implement_entry}")
        if shutil.which("nix") is None:
            self.skipTest("Nix is required to provide Bun from the sample flake's real protect devShell")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            edl_file = root / "enclave.edl"
            edl_file.write_text(
                "enclave { trusted { public void ecall_a(); public void ecall_b(); }; };\n"
            )
            fields_file = root / "fields.json"
            field_ids = ["0x0000000000001001", "0x0000000000002002"]
            fields_file.write_text(json.dumps({
                "schema": "atfield-fields-v1",
                "fields": [
                    {
                        "id": field_ids[0],
                        "name": "duplicate_field()",
                        "function": "duplicate_field",
                        "linkage_name": "_duplicate_field",
                        "order": ["1", "0"],
                    },
                    {
                        "id": field_ids[1],
                        "name": "duplicate_field()",
                        "function": "duplicate_field",
                        "linkage_name": "_duplicate_field",
                        "order": ["2", "0"],
                    },
                ],
            }))
            selectors_file = root / "selectors.json"
            js = f"""
import {{ buildConservativeSelectorManifest }} from {json.dumps(str(implement_entry))};
import {{ readFileSync, writeFileSync }} from "node:fs";
const fields = JSON.parse(readFileSync({json.dumps(str(fields_file))}, "utf8")).fields;
const manifest = buildConservativeSelectorManifest(fields, {json.dumps(str(edl_file))});
writeFileSync({json.dumps(str(selectors_file))}, JSON.stringify(manifest));
"""
            completed = subprocess.run(
                [
                    "nix", "develop", f"{self.SAMPLE_ROOT}#real-ehsm-protect",
                    "--command", "bun", "-e", js,
                ],
                cwd=self.SAMPLE_ROOT,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"implement selector generator failed:\n{completed.stdout}\n{completed.stderr}",
            )

            generated = json.loads(selectors_file.read_text())
            fields = normalized_fields(fields_file)
            expected_ids = [field["id"] for field in fields]
            self.assertEqual(generated["schema"], "atfield-selectors-v1")
            self.assertEqual(generated["policy"], "conservative-all-fields")
            self.assertEqual(len(generated["selectors"]), 2)
            self.assertTrue(all("reachable_functions" not in item for item in generated["selectors"]))
            for item in generated["selectors"]:
                ids = item["reachable_fields"]
                self.assertEqual(len(ids), len(expected_ids))
                self.assertEqual(set(ids), set(expected_ids))
            self.assertEqual(fields[0]["function"], fields[1]["function"])
            self.assertNotEqual(fields[0]["id"], fields[1]["id"])

            resolved = resolve_selectors(selectors_file, fields, edl_file)

            self.assertEqual([item["name"] for item in resolved], ["ecall_a", "ecall_b"])
            self.assertTrue(all(item["reachable_fields"] == expected_ids for item in resolved))
            self.assertTrue(all(item["policy"] == "conservative-all-fields" for item in resolved))
            self.assertTrue(all("reachable_functions" not in item for item in resolved))


if __name__ == "__main__":
    unittest.main()
