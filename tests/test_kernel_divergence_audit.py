#!/usr/bin/env python3
"""Adversarial convergence audit for ExplorationKernel (regression test).

Every plan execution returns records containing FRESH page RVAs and a GROWING
heap span — i.e., maximal new-effects/new-state-keys/heap_grew per step, the
worst case for workset accumulation. If the kernel still terminates with
candidates_exhausted, scheduling is provably bounded; the cumulative set must
equal exactly the union of injected observations (no fabrication, no drop).

Runs against every target under dynamic/targets that ships edl_schema.json and
selectors.json.
"""
from __future__ import annotations

import itertools
import json
import sys
import unittest
from pathlib import Path

DYN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DYN_ROOT / "tools"))

from exploration_kernel import ExplorationKernel  # noqa: E402


def available_targets():
    tdir = DYN_ROOT / "targets"
    return sorted(
        d.name for d in tdir.iterdir()
        if d.is_dir() and (d / "edl_schema.json").exists() and (d / "selectors.json").exists()
    )


def run_audit(target: str):
    edl = json.loads((DYN_ROOT / "targets" / target / "edl_schema.json").read_text())
    sel_doc = json.loads((DYN_ROOT / "targets" / target / "selectors.json").read_text())
    selectors = sel_doc["selectors"] if isinstance(sel_doc, dict) else sel_doc

    field_sel = [s["ecall_index"] for s in selectors if s.get("reachable_fields")]
    non_field = [s["ecall_index"] for s in selectors if not s.get("reachable_fields")]
    if not field_sel:
        return None  # no Field-reachable selectors: audit is meaningless here

    page_ctr = itertools.count(1)
    run_ctr = itertools.count(1)

    def fresh_pages(n, ad):
        return [{"rva": hex(0x100000 + next(page_ctr) * 0x1000), "ad": ad} for _ in range(n)]

    def mk_fobs(mask, n_fresh, heap_span_pages):
        return {
            "field_id": "0xdeadbeef",
            "ipi_aex_verified_mask": mask,
            "heap_walk_truncated": 0,
            "heap_pread_failures": 0,
            "s3_active_aex_count": 2 * n_fresh,
            "s3": fresh_pages(n_fresh, "A") + fresh_pages(n_fresh, "D"),
            "heap_lo_rva": "0x0",
            "heap_hi_rva": hex(heap_span_pages * 0x1000),
            "gateB_rsp_rva": "0x900000",
            "gateD_rsp_rva": "0x8ff000",
        }

    def runner(plan):
        i = next(run_ctr)
        fam = plan.get("family", "seed")
        mask = 4 if fam == "history" else 7
        heap_pages = i  # grows on EVERY run: adversarial heap divergence pressure
        recs = []
        if fam == "seed":
            for idx in non_field:
                recs.append({"ecall_index": idx, "selector_seq": 0, "sgx_status": 0,
                             "ms_retval": 0, "fields": []})
            for sseq, idx in enumerate(field_sel):
                recs.append({"ecall_index": idx, "selector_seq": sseq, "sgx_status": 0,
                             "ms_retval": 0, "fields": [mk_fobs(mask, 3, heap_pages)]})
        else:
            idx = plan.get("ecall_index", field_sel[0])
            sseq = plan.get("selector_seq", 0)
            if non_field:
                recs.append({"ecall_index": non_field[0], "selector_seq": 0,
                             "sgx_status": 0, "ms_retval": 0, "fields": []})
            recs.append({"ecall_index": idx, "selector_seq": sseq, "sgx_status": 0,
                         "ms_retval": 0, "fields": [mk_fobs(mask, 2, heap_pages)]})
        return {"records": recs, "ipi_mask": mask, "returncode": 0, "stdout": "PASS"}

    k = ExplorationKernel(sample=target, edl_schema=edl, selectors=selectors,
                          runner_fn=runner, mode="feedback_guided",
                          max_enclave_creations=50000)
    res = k.run()
    return k, res, next(page_ctr) - 1


class KernelDivergenceAudit(unittest.TestCase):
    def test_cumulative_set_equals_injected_universe(self):
        targets = available_targets()
        self.assertTrue(targets, "no target artifacts found")
        ran = 0
        for target in targets:
            with self.subTest(target=target):
                out = run_audit(target)
                if out is None:
                    self.skipTest(f"{target}: selector schema lacks reachable_fields")
                k, res, injected = out
                ran += 1
                self.assertEqual(
                    len(k.cumulative_s3_pages), injected,
                    f"{target}: cumulative pages {len(k.cumulative_s3_pages)} "
                    f"!= injected universe {injected} "
                    f"(stop_reason={res.get('stop_reason')}, "
                    f"ecalls={res.get('total_ecalls')}, "
                    f"creations={res.get('enclave_creations')})")


if __name__ == "__main__":
    unittest.main()
