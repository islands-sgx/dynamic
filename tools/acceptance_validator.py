#!/usr/bin/env python3
"""Strict, Non-Bypassable Acceptance Validator for ATField-SGX Dynamic Runs and Worksets."""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path


def sha256_path(p: Path) -> str:
    if p.is_file():
        return hashlib.sha256(p.read_bytes()).hexdigest()
    gz = p.with_suffix(p.suffix + ".gz")
    if gz.is_file():
        with gzip.open(gz, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    return ""


def validate_run_result(
    run_res: dict,
    *,
    expected_returncode: int = 0,
    expected_stdout_substr: str = "PASS",
    expected_min_records: int = 1,
    expected_field_ids: set[str] | None = None,
    expected_tags: set[str] | None = None,
    require_strict_mode: int | None = None,
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
    observed_tags: set[str] = set()
    strict_enforced_records = 0
    total_strict_faults = 0

    for idx, rec in enumerate(records):
        observed_tags.add(rec.get("tag", ""))
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

        if require_strict_mode is not None:
            if rec.get("strict_mode") == require_strict_mode:
                strict_enforced_records += 1
            elif rec.get("fields"):
                fail(
                    f"RECORD_{idx}_STRICT_MODE_{rec.get('strict_mode')}_NE_{require_strict_mode}",
                    "INVALID",
                )

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
            if closed_workset_effects is not None:
                if fid not in closed_workset_effects:
                    fail(f"UNKNOWN_FIELD_NOT_IN_WORKSET:{fid}", "INVALID")
                else:
                    allowed = closed_workset_effects[fid]
                    for item in fobs.get("s3", []):
                        rva = int(item["rva"], 16)
                        ad = item["ad"]
                        if (rva, "A") not in allowed:
                            fail(f"UNCOVERED_PAGE_{hex(rva)}_IN_{fid}", "FAIL")
                        if ad == "D" and (rva, "D") not in allowed:
                            fail(f"UNCOVERED_WRITE_EFFECT_D_ON_{hex(rva)}_IN_{fid}", "FAIL")

    if require_strict_mode is not None and strict_enforced_records == 0:
        fail("STRICT_MODE_NEVER_ENFORCED_ON_ANY_FIELD_CALL", "INVALID")

    if expected_field_ids is not None:
        missing_fids = sorted(expected_field_ids - observed_fields)
        if missing_fids:
            fail(f"MISSING_REQUIRED_FIELDS:{','.join(missing_fids)}", "INVALID")

    if expected_tags is not None:
        missing_tags = sorted(expected_tags - observed_tags)
        if missing_tags:
            fail(f"MISSING_EXPECTED_INTERVENTION_TAGS:{','.join(missing_tags)}", "INVALID")

    if require_zero_strict_faults and total_strict_faults > 0:
        fail(f"STRICT_NON_READY_FAULTS_{total_strict_faults}", "FAIL")

    return {"status": status, "reasons": reasons}


def validate_provenance_consistency(
    ledger: dict,
    eval_runs: list[dict],
    target_dir: Path | None = None,
    variant: str = "dynamic_xr",
) -> dict:
    """Verify full artifact chain: collector hash, profile ELF hash, workset/final/ready hashes,
    and valid trace_sha256 for every discovery run and witness.
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
        if r.get("interpose_sha256") and r.get("interpose_sha256") != ledger_interpose:
            status = "INVALID"
            reasons.append(f"LEDGER_RUN_INTERPOSE_MISMATCH:{r.get('run_id')}")
        tpath = r.get("trace_jsonl")
        if tpath and target_dir is not None:
            disk_sha = sha256_path(Path(tpath))
            if not disk_sha or disk_sha != r.get("trace_sha256"):
                status = "INVALID"
                reasons.append(f"LEDGER_TRACE_SHA256_MISMATCH:{r.get('run_id')}")

    for w in ledger.get("witnesses", []):
        if w.get("measurement_invalid", 0) != 0:
            status = "INVALID"
            reasons.append(f"WITNESS_FROM_INVALID_RECORD:{w.get('witness_id')}")
        if w.get("interpose_sha256") != ledger_interpose:
            status = "INVALID"
            reasons.append(f"WITNESS_INTERPOSE_MISMATCH:{w.get('witness_id')}")

    for er in eval_runs:
        if ledger_interpose and er.get("interpose_sha256") != ledger_interpose:
            status = "INVALID"
            reasons.append(
                f"INTERPOSE_HASH_MISMATCH:ledger={ledger_interpose[:12]}_vs_eval={str(er.get('interpose_sha256'))[:12]}"
            )

    if target_dir is not None:
        prof_sha = sha256_path(target_dir / "enclave.profile.so")
        if prof_sha != ledger.get("profile_elf_sha256"):
            status = "INVALID"
            reasons.append("PROFILE_ELF_SHA256_MISMATCH")
        art = ledger.get("artifacts", {}).get(variant, {})
        if art:
            checks = [
                ("workset_sha256", target_dir / f"workset.{variant}.json"),
                ("final_elf_sha256", target_dir / f"enclave.{variant}.final.so"),
                ("signed_aex1_sha256", target_dir / f"enclave.{variant}.final.signed.so"),
                ("signed_aex0_sha256", target_dir / f"enclave.{variant}.final.aex0.signed.so"),
                ("gate_aex0_sha256", target_dir / f"enclave.{variant}.4gate.aex0.signed.so"),
                ("ready_bin_sha256", target_dir / f"enclave.{variant}.ready.bin"),
            ]
            for key, fpath in checks:
                if sha256_path(fpath) != art.get(key):
                    status = "INVALID"
                    reasons.append(f"ARTIFACT_HASH_MISMATCH:{key}")

    return {"status": status, "reasons": reasons}


def validate_production_run_result(
    run_res: dict,
    *,
    expected_stdout_substr: str,
    expected_ecall_seq: list[int],
    ready_sel_set: set[int] | None = None,
    require_readiness: bool = False,
) -> dict:
    """Strict non-bypassable validator for production benchmark runs (Raw, No-PreTouch, Group A/B/C)."""
    base = validate_run_result(
        run_res,
        expected_returncode=0,
        expected_stdout_substr=expected_stdout_substr,
        expected_min_records=len(expected_ecall_seq),
    )
    reasons = list(base["reasons"])
    status = base["status"]

    def fail(code: str, kind: str = "INVALID") -> None:
        nonlocal status
        reasons.append(code)
        if status == "PASS":
            status = kind
        elif kind == "INVALID" and status != "TIMEOUT":
            status = "INVALID"

    records = run_res.get("records") or []
    actual_seq = [r.get("ecall_index") for r in records]
    if actual_seq != expected_ecall_seq:
        fail(f"ECALL_SEQUENCE_MISMATCH:len={len(actual_seq)}_vs_{len(expected_ecall_seq)}", "INVALID")

    if require_readiness:
        if ready_sel_set is None:
            fail("MISSING_READY_SELECTOR_SET", "INVALID")
        else:
            for idx, r in enumerate(records):
                if r.get("readiness_installed", 0) != 1:
                    fail(f"RECORD_{idx}_READINESS_NOT_INSTALLED", "INVALID")
                sel = r.get("ecall_index")
                if sel in ready_sel_set:
                    if r.get("acquire_calls", 0) != 1 or r.get("acquire_rc", -1) != 0:
                        fail(f"RECORD_{idx}_ACQUIRE_MISSING_OR_FAILED:calls={r.get('acquire_calls')}_rc={r.get('acquire_rc')}", "INVALID")
                    if r.get("release_calls", 0) != 1 or r.get("release_rc", -1) != 0:
                        fail(f"RECORD_{idx}_RELEASE_MISSING_OR_FAILED:calls={r.get('release_calls')}_rc={r.get('release_rc')}", "INVALID")
                    if r.get("acquire_ns", 0) <= 0:
                        fail(f"RECORD_{idx}_ZERO_ACQUIRE_NS", "INVALID")
                else:
                    if r.get("acquire_calls", 0) != 0:
                        fail(f"RECORD_{idx}_UNEXPECTED_ACQUIRE_ON_EMPTY_SELECTOR_{sel}", "INVALID")

    return {"status": status, "reasons": reasons}
