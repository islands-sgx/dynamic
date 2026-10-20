#!/usr/bin/env python3
"""Strict, Non-Bypassable Acceptance Validator for ATField-SGX Dynamic Runs and Worksets."""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

REQUIRED_RECORD_KEYS = {
    "call_seq",
    "ecall_index",
    "tag",
    "sgx_status",
    "measurement_invalid",
    "syscall_errors",
    "ipi_flush_failures",
    "fast_forwarded_prior",
    "mutation_oob_rejected",
    "strict_mode",
    "strict_non_ready_fault_count",
    "fields",
}

REQUIRED_FOBS_KEYS = {
    "field_id",
    "ipi_aex_verified_mask",
    "heap_walk_truncated",
    "heap_pread_failures",
    "s3",
}

REQUIRED_PROD_RECORD_KEYS = REQUIRED_RECORD_KEYS | {
    "elapsed_ns",
    "acquire_ns",
    "encl_body_ns",
    "release_ns",
    "readiness_installed",
    "acquire_calls",
    "acquire_rc",
    "release_calls",
    "release_rc",
}

EXPECTED_CHALLENGE_KEYS = {"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}


def sha256_path(p: Path) -> str:
    if p.is_file():
        return hashlib.sha256(p.read_bytes()).hexdigest()
    gz = p.with_suffix(p.suffix + ".gz")
    if gz.is_file():
        with gzip.open(gz, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    return ""


def check_business_pass_stdout(stdout: str, expected_stdout_substr: str) -> tuple[bool, str]:
    """Verify stdout contains a genuine PASS line and no negative 'NOT PASS' / 'FAIL' markers."""
    if not expected_stdout_substr:
        return True, ""
    lines = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
    for ln in lines:
        up = ln.upper()
        if "NOT PASS" in up or "FAILED" in up or up.startswith("FAIL:") or up.startswith("ERROR:"):
            return False, f"NEGATIVE_STDOUT_MARKER:{ln}"
    if expected_stdout_substr == "PASS":
        for ln in lines:
            if ln == "PASS" or ln.endswith(": PASS") or ln.startswith("PASS:") or ln.endswith(" PASS"):
                return True, ""
        return False, "MISSING_BUSINESS_PASS_STDOUT:MISSING_EXACT_PASS_LINE"
    if expected_stdout_substr not in (stdout or ""):
        return False, f"MISSING_BUSINESS_PASS_STDOUT:{expected_stdout_substr}"
    return True, ""


def extract_valid_s3_effects(fobs: dict) -> set[tuple[int, str]]:
    """Extract `(rva, effect)` tuples from `fobs['s3']`, strictly rejecting any `ad` not in `('A', 'D')`."""
    s3_list = fobs.get("s3")
    if not isinstance(s3_list, list):
        raise ValueError("fobs['s3'] must be a list")
    effs: set[tuple[int, str]] = set()
    for item in s3_list:
        if not isinstance(item, dict) or "rva" not in item:
            raise ValueError(f"Malformed S3 item: {item!r}")
        ad = item.get("ad")
        if ad not in ("A", "D"):
            raise ValueError(f"Illegal S3 effect ad={ad!r} (must be 'A' or 'D')")
        rva = int(item["rva"], 16)
        effs.add((rva, "A"))
        if ad == "D":
            effs.add((rva, "D"))
    return effs


def validate_field_observation_dict(
    fobs: dict,
    *,
    rec_idx: int = 0,
    require_ipi_mask: int | None = None,
    require_nonempty_s3: bool = False,
    require_aex_counter: bool = True,
) -> list[str]:
    """Single authoritative validator for a Field observation dict (`fobs`)."""
    errs: list[str] = []
    if not isinstance(fobs, dict):
        return [f"RECORD_{rec_idx}_FIELD_NOT_DICT"]
    missing_fkeys = sorted(REQUIRED_FOBS_KEYS - set(fobs.keys()))
    if missing_fkeys:
        errs.append(f"RECORD_{rec_idx}_FIELD_MISSING_KEYS:{','.join(missing_fkeys)}")
        return errs
    fid = fobs.get("field_id", "")
    if not isinstance(fid, str) or not fid:
        errs.append(f"RECORD_{rec_idx}_FIELD_EMPTY_ID")
    s3_list = fobs.get("s3")
    if not isinstance(s3_list, list):
        errs.append(f"RECORD_{rec_idx}_FIELD_{fid}_S3_NOT_LIST")
        return errs
    if require_nonempty_s3 and len(s3_list) == 0:
        errs.append(f"RECORD_{rec_idx}_FIELD_{fid}_EMPTY_S3_OBSERVATION")
    for item in s3_list:
        if not isinstance(item, dict) or "rva" not in item or item.get("ad") not in ("A", "D"):
            errs.append(f"RECORD_{rec_idx}_FIELD_{fid}_MALFORMED_S3_ITEM:{item!r}")
            break
    if require_aex_counter:
        if "s3_active_aex_count" not in fobs or not isinstance(fobs.get("s3_active_aex_count"), int):
            errs.append(f"RECORD_{rec_idx}_FIELD_{fid}_MISSING_S3_ACTIVE_AEX_COUNT")
    if fobs.get("heap_walk_truncated", 0) != 0:
        errs.append(f"RECORD_{rec_idx}_FIELD_{fid}_HEAP_WALK_TRUNCATED")
    if fobs.get("heap_pread_failures", 0) != 0:
        errs.append(f"RECORD_{rec_idx}_FIELD_{fid}_HEAP_PREAD_FAILURES")
    if require_ipi_mask is not None and fobs.get("ipi_aex_verified_mask") != require_ipi_mask:
        errs.append(
            f"RECORD_{rec_idx}_FIELD_{fid}_IPI_MASK_{fobs.get('ipi_aex_verified_mask')}_NE_{require_ipi_mask}"
        )
    return errs


def is_valid_measurement_run(
    run_res: dict,
    *,
    allow_nonzero_rc: bool = False,
    require_ipi_mask: int | None = None,
    require_nonempty_s3: bool = True,
    require_aex_counter: bool = True,
) -> tuple[bool, list[str]]:
    """Unified underlying measurement admission gate shared across:
      - ExplorationKernel feedback & discovery
      - Reference hold-out & witness confirmation replay
      - Workset merging (`controller.py`)
      - Predetermined regression matrix evaluation
    Delegates Field validation directly to `validate_field_observation_dict` so missing
    `s3_active_aex_count`, illegal `ad="BROKEN"`, `fast_forwarded_prior > 0`, and mismatched
    `ipi_aex_verified_mask` (e.g. `4` for history vs `7` for normal profiling) are uniformly rejected.
    """
    reasons: list[str] = []
    if not isinstance(run_res, dict):
        return False, ["RUN_RESULT_NOT_DICT"]
    if run_res.get("timed_out", False):
        reasons.append("PROCESS_TIMED_OUT")
    rc = run_res.get("returncode", 0)
    if rc is None or rc < 0:
        reasons.append(f"SIGNAL_EXIT_{rc}")
    elif not allow_nonzero_rc and rc != 0:
        reasons.append(f"UNEXPECTED_RETURNCODE_{rc}")
    if run_res.get("measurement_invalid", False):
        reasons.append("RUN_MEASUREMENT_INVALID_FLAG")
    records = run_res.get("records")
    if not isinstance(records, list) or len(records) == 0:
        reasons.append("EMPTY_TRACE")
        return False, reasons

    eff_ipi_mask = require_ipi_mask if require_ipi_mask is not None else run_res.get("ipi_mask")

    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            reasons.append(f"RECORD_{idx}_NOT_DICT")
            continue
        if rec.get("sgx_status", 0) != 0:
            reasons.append(f"RECORD_{idx}_SGX_TRANSPORT_ERROR:{hex(rec.get('sgx_status', 0))}")
        if rec.get("measurement_invalid", 0) != 0:
            reasons.append(f"RECORD_{idx}_MEASUREMENT_INVALID:{rec.get('invalid_reason', '')}")
        if rec.get("syscall_errors", 0) > 0:
            reasons.append(f"RECORD_{idx}_SYSCALL_ERRORS_{rec.get('syscall_errors')}")
        if rec.get("ipi_flush_failures", 0) > 0:
            reasons.append(f"RECORD_{idx}_IPI_FLUSH_FAILURES_{rec.get('ipi_flush_failures')}")
        if rec.get("fast_forwarded_prior", 0) > 0:
            reasons.append(f"RECORD_{idx}_FAST_FORWARD_SKIPPED")
        if rec.get("mutation_oob_rejected", 0) > 0:
            reasons.append(f"RECORD_{idx}_MUTATION_OOB_REJECTED")
        fields_list = rec.get("fields")
        if not isinstance(fields_list, list):
            reasons.append(f"RECORD_{idx}_FIELDS_NOT_LIST")
            continue
        for fobs in fields_list:
            f_errs = validate_field_observation_dict(
                fobs,
                rec_idx=idx,
                require_ipi_mask=eff_ipi_mask,
                require_nonempty_s3=require_nonempty_s3,
                require_aex_counter=require_aex_counter,
            )
            reasons.extend(f_errs)

    return len(reasons) == 0, reasons


def validate_challenge_ground_truth_and_holdout(
    gt_syms: dict[str, int],
    declared_gt: dict[str, dict],
    fields_by_func: dict[str, str],
    holdout_field_effects: set[tuple[str, int, str]],
) -> tuple[bool, dict[str, set[tuple[str, int, str]]], list[str]]:
    """Verify that:
    1. All 8 challenge symbols `C1..C8` exist in the ELF (`gt_syms`);
    2. All 8 challenges `C1..C8` are declared in `declared_gt` with valid `field_function` and `effects`;
    3. Every declared `(field_id, rva, effect)` tuple is actually observed in `holdout_field_effects`.
    """
    reasons: list[str] = []
    if set(gt_syms.keys()) != EXPECTED_CHALLENGE_KEYS:
        missing = sorted(EXPECTED_CHALLENGE_KEYS - set(gt_syms.keys()))
        extra = sorted(set(gt_syms.keys()) - EXPECTED_CHALLENGE_KEYS)
        reasons.append(f"INCOMPLETE_CHALLENGE_SYMBOLS:missing={missing},extra={extra}")
        return False, {}, reasons

    if set(declared_gt.keys()) != EXPECTED_CHALLENGE_KEYS:
        reasons.append("INCOMPLETE_DECLARED_GROUND_TRUTH")
        return False, {}, reasons

    gt_required_effects: dict[str, set[tuple[str, int, str]]] = {}
    for cname in sorted(EXPECTED_CHALLENGE_KEYS):
        crva = gt_syms[cname]
        decl = declared_gt[cname]
        fn_name = decl.get("field_function", "")
        fid = fields_by_func.get(fn_name, "")
        eff_list = decl.get("effects", [])
        if not fid or not eff_list:
            reasons.append(f"INVALID_DECLARED_GT_FOR_{cname}:fn={fn_name}")
            continue
        req_set = {(fid, crva, eff) for eff in eff_list}
        gt_required_effects[cname] = req_set
        missing_effs = sorted(
            f"{f_id}:{hex(r)}:{e}"
            for f_id, r, e in (req_set - holdout_field_effects)
        )
        if missing_effs:
            reasons.append(f"MISSING_DECLARED_GT_EFFECT_{cname}:{','.join(missing_effs)}")

    return len(reasons) == 0, gt_required_effects, reasons


def validate_run_result(
    run_res: dict,
    *,
    expected_returncode: int | None = 0,
    expected_stdout_substr: str = "PASS",
    expected_min_records: int = 1,
    expected_field_ids: set[str] | None = None,
    expected_tags: set[str] | None = None,
    require_strict_mode: int | None = None,
    require_ipi_mask: int | None = None,
    closed_workset_effects: dict[str, set[tuple[int, str]]] | None = None,
    require_zero_strict_faults: bool = False,
    allow_nonzero_sgx_status: bool = False,
    require_nonempty_s3: bool | None = None,
    require_aex_counter: bool = True,
) -> dict:
    """Return {'status': 'PASS'|'FAIL'|'INVALID'|'TIMEOUT', 'reasons': [...]}."""
    reasons: list[str] = []
    status = "PASS"

    if require_nonempty_s3 is None:
        require_nonempty_s3 = (require_ipi_mask == 7 or closed_workset_effects is not None)

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
    if rc is None or rc < 0:
        fail(f"SIGNAL_EXIT_{rc}", "FAIL")
    elif expected_returncode is not None and rc != expected_returncode:
        fail(f"UNEXPECTED_RETURNCODE_{rc}_EXPECTED_{expected_returncode}", "FAIL")

    records = run_res.get("records") or []
    if len(records) == 0:
        fail("EMPTY_TRACE", "INVALID")
    elif len(records) < expected_min_records:
        fail(f"TRUNCATED_TRACE_{len(records)}_LT_{expected_min_records}", "INVALID")

    if expected_stdout_substr:
        ok_out, out_reason = check_business_pass_stdout(run_res.get("stdout") or "", expected_stdout_substr)
        if not ok_out:
            fail(out_reason, "FAIL")

    if run_res.get("measurement_invalid", False):
        fail("RUN_MEASUREMENT_INVALID_FLAG", "INVALID")

    observed_fields: set[str] = set()
    observed_tags: set[str] = set()
    strict_enforced_records = 0
    total_strict_faults = 0

    for idx, rec in enumerate(records):
        missing_keys = sorted(REQUIRED_RECORD_KEYS - set(rec.keys()))
        if missing_keys:
            fail(f"RECORD_{idx}_MISSING_KEYS:{','.join(missing_keys)}", "INVALID")
            continue

        observed_tags.add(rec.get("tag", ""))
        if not allow_nonzero_sgx_status and rec.get("sgx_status", 0) != 0:
            fail(f"RECORD_{idx}_SGX_TRANSPORT_ERROR:{hex(rec.get('sgx_status', 0))}", "FAIL")
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
            f_errs = validate_field_observation_dict(
                fobs,
                rec_idx=idx,
                require_ipi_mask=require_ipi_mask,
                require_nonempty_s3=require_nonempty_s3,
                require_aex_counter=require_aex_counter,
            )
            for fe in f_errs:
                fail(fe, "INVALID")
            if f_errs:
                continue
            fid = fobs.get("field_id", "")
            observed_fields.add(fid)
            if closed_workset_effects is not None:
                if fid not in closed_workset_effects:
                    fail(f"UNKNOWN_FIELD_NOT_IN_WORKSET:{fid}", "INVALID")
                else:
                    allowed = closed_workset_effects[fid]
                    for rva, eff in sorted(extract_valid_s3_effects(fobs)):
                        if (rva, eff) not in allowed:
                            if eff == "A":
                                fail(f"UNCOVERED_PAGE_{hex(rva)}_IN_{fid}", "FAIL")
                            else:
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


def evaluate_regression_workflow_case(
    wsp: dict,
    rw_cov: dict,
    rw_prod: dict | None,
    *,
    expected_fids: set[str],
    closed_target_effects_by_fid: dict[str, set[tuple[int, str]]],
    ready_sel_set: set[int],
) -> dict:
    """Evaluate one predetermined end-to-end regression workflow case and report FOUR separate
    verdicts (never conflating them into a single PASS, and never counting a failed/incomplete
    workflow with 0 Field entries as 'zero omissions'):
      1. `measurement_valid`: Underlying 4-Gate measurement validity (`is_valid_measurement_run` with `ipi_mask=7`);
      2. `business_workflow_completed`: Enforces `min_rec`, `expected_fids` (all target Fields entered),
         `expected_tags` (intervention actually applied), `expected_rc` (`0` unless business rejection is expected
         and verified), and `expected_stdout_substr` (`PASS`);
      3. `workset_coverage_zero_omission`: Requires `measurement_valid` AND `business_workflow_completed` AND
         `0` uncovered `(field_id, page_rva, effect)` tuples against the frozen `workset.dynamic_xr.json`;
      4. `frozen_protected_enclave_completed`: Requires the frozen production artifact (`dynamic_xr_final` with
         `AEX-Notify=1` and `ReadyTable v3`) to complete the identical workflow with exact ECALL sequence parity,
         verified `enclave_pages_acquire/release`, and matching return/stdout expectations.
    """
    allow_nz = bool(wsp.get("allow_nonzero_rc", False))
    exp_rc = None if allow_nz else wsp.get("expected_rc", 0)
    exp_stdout = wsp.get("expected_stdout_substr", "" if allow_nz else "PASS")
    exp_fids = set(wsp.get("expected_fids", expected_fids))
    exp_tags = set(wsp["expected_tags"]) if wsp.get("expected_tags") else None
    min_rec = int(wsp.get("min_rec", 1))

    meas_ok, meas_reasons = is_valid_measurement_run(
        rw_cov,
        allow_nonzero_rc=allow_nz,
        require_ipi_mask=7,
        require_nonempty_s3=True,
        require_aex_counter=True,
    )

    val_biz = validate_run_result(
        rw_cov,
        expected_returncode=exp_rc,
        expected_stdout_substr=exp_stdout,
        expected_min_records=min_rec,
        expected_field_ids=exp_fids,
        expected_tags=exp_tags,
        require_ipi_mask=7,
        require_nonempty_s3=True,
        require_aex_counter=True,
    )

    omitted_pages_wf: set[tuple[str, int]] = set()
    omitted_effects_wf: set[tuple[str, int, str]] = set()
    wf_fentries = 0
    if meas_ok:
        for rec in rw_cov.get("records", []):
            for fo in rec.get("fields", []):
                wf_fentries += 1
                fid = fo["field_id"]
                allowed = closed_target_effects_by_fid.get(fid, set())
                for rva, eff in extract_valid_s3_effects(fo):
                    if (rva, eff) not in allowed:
                        omitted_pages_wf.add((fid, rva))
                        omitted_effects_wf.add((fid, rva, eff))

    biz_ok = bool(meas_ok and val_biz["status"] == "PASS" and wf_fentries > 0 and len(exp_fids) > 0)
    cov_ok = bool(meas_ok and biz_ok and len(omitted_effects_wf) == 0)

    prod_ok = False
    prod_reasons: list[str] = []
    if rw_prod is not None and biz_ok:
        val_prod = validate_production_run_result(
            rw_prod,
            expected_returncode=exp_rc,
            expected_stdout_substr=exp_stdout,
            expected_ecall_seq=[r["ecall_index"] for r in rw_cov.get("records", [])],
            expected_tags=exp_tags,
            ready_sel_set=ready_sel_set,
            require_readiness=True,
        )
        prod_ok = (val_prod["status"] == "PASS")
        prod_reasons = val_prod["reasons"]
    else:
        prod_reasons = ["NOT_RUN_OR_BIZ_INCOMPLETE"]

    return {
        "workflow_id": wsp.get("id", ""),
        "ecalls": len(rw_cov.get("records", [])),
        "field_entries": wf_fentries,
        "measurement_valid": meas_ok,
        "measurement_reasons": meas_reasons,
        "business_workflow_completed": biz_ok,
        "business_reasons": val_biz["reasons"],
        "workset_coverage_zero_omission": cov_ok,
        "omitted_pages_count": len(omitted_pages_wf) if biz_ok else None,
        "omitted_effects_count": len(omitted_effects_wf) if biz_ok else None,
        "frozen_protected_enclave_completed": prod_ok,
        "protected_reasons": prod_reasons,
        "coverage_trace_sha256": rw_cov.get("trace_sha256", ""),
        "protected_trace_sha256": rw_prod.get("trace_sha256", "") if rw_prod else "",
    }


def validate_diagnostic_4gate_run(
    run_res: dict,
    *,
    expected_field_ids: set[str],
    expected_ecall_seq: list[int] | None = None,
    expected_field_call_seqs: set[int] | None = None,
    require_ipi_mask: int = 3,
    require_clean_observation_per_field: bool = False,
) -> dict:
    """Strict validator for 4-Gate diagnostic runs before their statistics or reference call_seq are used."""
    base = validate_run_result(
        run_res,
        expected_returncode=0,
        expected_stdout_substr="PASS",
        expected_min_records=len(expected_ecall_seq) if expected_ecall_seq else 1,
        expected_field_ids=expected_field_ids,
        require_ipi_mask=require_ipi_mask,
        require_nonempty_s3=(require_ipi_mask == 7),
        require_aex_counter=True,
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
    if expected_ecall_seq is not None:
        actual_seq = [r.get("ecall_index") for r in records]
        if actual_seq != expected_ecall_seq:
            fail(f"DIAG_ECALL_SEQUENCE_MISMATCH:len={len(actual_seq)}_vs_{len(expected_ecall_seq)}", "INVALID")

    if expected_field_call_seqs is not None:
        actual_fseqs = {r.get("call_seq") for r in records if r.get("fields")}
        if actual_fseqs != expected_field_call_seqs:
            fail("DIAG_FIELD_ENTERING_CALL_SEQS_MISMATCH", "INVALID")

    if status == "PASS" and expected_field_ids:
        clean_by_fid: dict[str, int] = {fid: 0 for fid in expected_field_ids}
        total_clean = 0
        for r in records:
            for fo in r.get("fields", []):
                fid = fo.get("field_id", "")
                if fo.get("s3_active_aex_count") == 0:
                    total_clean += 1
                    if fid in clean_by_fid:
                        clean_by_fid[fid] += 1
        if total_clean == 0:
            fail("NO_CLEAN_OBSERVATIONS_ALL_CONTAMINATED", "INCONCLUSIVE")
        elif require_clean_observation_per_field:
            for fid, cnt in sorted(clean_by_fid.items()):
                if cnt == 0:
                    fail(f"FIELD_{fid}_NO_CLEAN_OBSERVATIONS_ALL_CONTAMINATED", "INCONCLUSIVE")

    return {"status": status, "reasons": reasons}


def validate_production_run_result(
    run_res: dict,
    *,
    expected_returncode: int | None = 0,
    expected_stdout_substr: str = "PASS",
    expected_ecall_seq: list[int],
    expected_tags: set[str] | None = None,
    ready_sel_set: set[int] | None = None,
    require_readiness: bool = False,
) -> dict:
    """Strict non-bypassable validator for production benchmark runs (Raw, No-PreTouch, Group A/B/C)."""
    base = validate_run_result(
        run_res,
        expected_returncode=expected_returncode,
        expected_stdout_substr=expected_stdout_substr,
        expected_min_records=len(expected_ecall_seq),
        expected_tags=expected_tags,
        require_nonempty_s3=False,
        require_aex_counter=False,
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
    for idx, r in enumerate(records):
        missing_prod = sorted(REQUIRED_PROD_RECORD_KEYS - set(r.keys()))
        if missing_prod:
            fail(f"RECORD_{idx}_MISSING_PROD_KEYS:{','.join(missing_prod)}", "INVALID")

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
