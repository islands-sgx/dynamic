#!/usr/bin/env python3
"""Strict, Non-Bypassable Acceptance Validator for ATField-SGX Dynamic Runs and Worksets."""
from __future__ import annotations


def validate_run_result(
    run_res: dict,
    *,
    expected_returncode: int = 0,
    expected_stdout_substr: str = "PASS",
    expected_min_records: int = 1,
    expected_field_ids: set[str] | None = None,
    require_ipi_mask: int | None = None,
    closed_workset_effects: dict[str, set[tuple[int, str]]] | None = None,
    require_zero_strict_faults: bool = False,
) -> dict:
    """Return {'status': 'PASS'|'FAIL'|'INVALID'|'TIMEOUT', 'reasons': [...]}."""
    reasons: list[str] = []
    status = "PASS"

    def fail(code: str, kind: str = "FAIL") -> None:
        nonlocal status
        reasons.append(code)
        if status == "PASS":
            status = kind
        elif kind == "INVALID" and status != "TIMEOUT":
            status = "INVALID"

    if run_res.get("timed_out", False):
        fail("PROCESS_TIMED_OUT", "TIMEOUT")

    rc = run_res.get("returncode")
    if rc != expected_returncode:
        if rc is not None and rc < 0:
            fail(f"SIGNAL_EXIT_{rc}", "FAIL")
        else:
            fail(f"UNEXPECTED_RETURNCODE_{rc}_EXPECTED_{expected_returncode}", "FAIL")

    records = run_res.get("records") or []
    if len(records) == 0:
        fail("EMPTY_TRACE", "INVALID")
    elif len(records) < expected_min_records:
        fail(f"TRUNCATED_TRACE_{len(records)}_LT_{expected_min_records}", "INVALID")

    if expected_stdout_substr:
        stdout = run_res.get("stdout") or ""
        if expected_stdout_substr not in stdout:
            fail(f"MISSING_BUSINESS_PASS_STDOUT:{expected_stdout_substr}", "FAIL")

    if run_res.get("measurement_invalid", False):
        fail("RUN_MEASUREMENT_INVALID_FLAG", "INVALID")

    observed_fields: set[str] = set()
    total_strict_faults = 0

    for idx, rec in enumerate(records):
        if rec.get("measurement_invalid", 0) != 0:
            fail(f"RECORD_{idx}_MEASUREMENT_INVALID:{rec.get('invalid_reason', '')}", "INVALID")
        if rec.get("syscall_errors", 0) > 0:
            fail(f"RECORD_{idx}_SYSCALL_ERRORS_{rec.get('syscall_errors')}", "INVALID")
        if rec.get("ipi_flush_failures", 0) > 0:
            fail(f"RECORD_{idx}_IPI_FLUSH_FAILURES_{rec.get('ipi_flush_failures')}", "INVALID")
        if rec.get("fast_forwarded_prior", 0) > 0:
            fail(f"RECORD_{idx}_FAST_FORWARD_SKIPPED", "INVALID")
        if rec.get("mutation_oob_rejected", 0) > 0:
            fail(f"RECORD_{idx}_MUTATION_OOB_REJECTED", "INVALID")

        total_strict_faults += rec.get("strict_non_ready_fault_count", 0)

        for fobs in rec.get("fields", []):
            fid = fobs.get("field_id", "")
            observed_fields.add(fid)
            if fobs.get("heap_walk_truncated", 0) != 0:
                fail(f"RECORD_{idx}_FIELD_{fid}_HEAP_WALK_TRUNCATED", "INVALID")
            if fobs.get("heap_pread_failures", 0) != 0:
                fail(f"RECORD_{idx}_FIELD_{fid}_HEAP_PREAD_FAILURES", "INVALID")
            if require_ipi_mask is not None and fobs.get("ipi_aex_verified_mask") != require_ipi_mask:
                fail(
                    f"RECORD_{idx}_FIELD_{fid}_IPI_MASK_{fobs.get('ipi_aex_verified_mask')}_NE_{require_ipi_mask}",
                    "INVALID",
                )
            if closed_workset_effects is not None and fid in closed_workset_effects:
                allowed = closed_workset_effects[fid]
                for item in fobs.get("s3", []):
                    rva = int(item["rva"], 16)
                    ad = item["ad"]
                    if (rva, "A") not in allowed:
                        fail(f"UNCOVERED_PAGE_{hex(rva)}_IN_{fid}", "FAIL")
                    if ad == "D" and (rva, "D") not in allowed:
                        fail(f"UNCOVERED_WRITE_EFFECT_D_ON_{hex(rva)}_IN_{fid}", "FAIL")

    if expected_field_ids is not None:
        missing_fids = sorted(expected_field_ids - observed_fields)
        if missing_fids:
            fail(f"MISSING_REQUIRED_FIELDS:{','.join(missing_fids)}", "INVALID")

    if require_zero_strict_faults and total_strict_faults > 0:
        fail(f"STRICT_NON_READY_FAULTS_{total_strict_faults}", "FAIL")

    return {"status": status, "reasons": reasons}


def validate_provenance_consistency(ledger: dict, eval_runs: list[dict]) -> dict:
    """Verify that discovery ledger and evaluation runs share identical collector & profile ELF hashes
    and that no witness in the ledger came from an invalid measurement record.
    """
    reasons: list[str] = []
    status = "PASS"

    ledger_interpose = ledger.get("interpose_sha256", "")
    if not ledger_interpose:
        status = "INVALID"
        reasons.append("LEDGER_MISSING_INTERPOSE_SHA256")

    for r in ledger.get("runs", []):
        if r.get("measurement_invalid", False):
            status = "INVALID"
            reasons.append(f"LEDGER_RUN_INVALID:{r.get('run_id')}")

    for w in ledger.get("witnesses", []):
        if w.get("measurement_invalid", 0) != 0:
            status = "INVALID"
            reasons.append(f"WITNESS_FROM_INVALID_RECORD:{w.get('witness_id')}")

    for er in eval_runs:
        if ledger_interpose and er.get("interpose_sha256") != ledger_interpose:
            status = "INVALID"
            reasons.append(
                f"INTERPOSE_HASH_MISMATCH:ledger={ledger_interpose[:12]}_vs_eval={str(er.get('interpose_sha256'))[:12]}"
            )

    return {"status": status, "reasons": reasons}
