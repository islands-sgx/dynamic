#!/usr/bin/env python3
"""Run an unmodified sample host binary under libatfield_native_sgx.so on real SGX hardware."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "/home/meandssh/islands-sgx/dynamic/tools")
from elf_workset import ElfFile, parse_signed_metadata, signer_regions  # noqa: E402

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")
INTERPOSE_SO = DYN_ROOT / "build" / "libatfield_native_sgx.so"
ATFIELD_HOST_BIN = Path("/nix/store/6vyb98yh62as89qwndd4drgh7baxcw54-atfield-implement-bundle/bin/atfield-host")
LD_LIB_PATH = (
    "/nix/store/hg41dqig0qxm7shyi0a0xkw29a14i3js-openssl-3.6.3/lib:"
    "/nix/store/j2kgllgds4w7na8zqv1msi0mpvpjxda8-gcc-15.2.0-lib/lib:"
    "/nix/store/a1fx7mb2366qs2i5bd9mci3nis495wcb-sgx-psw-2.29.100.1/lib64:"
    "/nix/store/a1fx7mb2366qs2i5bd9mci3nis495wcb-sgx-psw-2.29.100.1/lib"
)


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""


def make_layout_spec(sample: str, encl_path: Path | None = None) -> str:
    tdir = DYN_ROOT / "targets" / sample
    layout = json.loads((tdir / "signer_layout.json").read_text())
    elf = ElfFile(tdir / "enclave.profile.so")
    syms = {s["name"]: s["value"] for s in elf.symbols() if s["shndx"] != 0}
    gm_rva = syms.get("_gm_", syms.get("gm_", 0))
    active_rva = syms.get("__atfield_active", 0)

    inc_regions = [r for r in layout["regions"] if r.get("kind") == "signer"]
    excl_regions = layout["excluded_regions"]
    if encl_path is not None and encl_path.is_file():
        try:
            meta = parse_signed_metadata(ElfFile(encl_path))
            inc_regions, excl_regions = signer_regions(meta)
        except Exception:
            pass

    tcs_rva = 0
    ssa_rva = 0
    excl = []
    for r in excl_regions:
        if r["name"] == "TCS":
            tcs_rva = r["start_rva"]
        elif r["name"] == "SSA":
            ssa_rva = r["start_rva"]
        excl.append(f"{r['start_rva']:x}:{r['end_rva']:x}")

    stack_lo = stack_hi = 0
    for r in inc_regions:
        if r.get("name", "").startswith("STACK"):
            stack_lo, stack_hi = r["start_rva"], r["end_rva"]

    p_start = layout["pretouch_start"]
    p_end = p_start + layout["capacity_q"]
    gate_rva = p_end - 4096
    return (
        f"tcs={tcs_rva:x};ssa={ssa_rva:x};gm={gm_rva:x};active={active_rva:x};"
        f"pretouch={p_start:x}:{p_end:x};gate={gate_rva:x};stack={stack_lo:x}:{stack_hi:x};"
        f"excl={','.join(excl)}"
    )


def make_schema_spec(sample: str) -> str:
    tdir = DYN_ROOT / "targets" / sample
    sch = json.loads((tdir / "edl_schema.json").read_text())
    dir_map = {"val": 0, "in": 1, "out": 2, "inout": 3}
    bkind_map = {None: 0, "count": 1, "size": 2}
    tokens = []
    for ec in sch["ecalls"]:
        idx = ec["ecall_index"]
        ms = ec.get("ms_layout")
        ms_sz = ms["size"] if ms else 0
        has_ret = 1 if ec.get("has_retval") else 0
        ret_off = ec.get("retval_offset") or 0
        ret_sz = ec.get("retval_size") or 0
        rep_ok = 1 if ec.get("replay_supported", True) else 0
        params = ec.get("params", [])
        tokens.append(f"E:{idx}:{ms_sz}:{has_ret}:{ret_off}:{ret_sz}:{rep_ok}:{len(params)}")
        for pidx, p in enumerate(params):
            moff = p.get("ms_offset") or 0
            msz = p.get("ms_size") or 0
            esz = p.get("elem_size") or 1
            is_ptr = 1 if p.get("is_pointer") else 0
            pdepth = p.get("ptr_depth") or 0
            dcode = dir_map.get(p.get("direction", "val"), 0)
            is_str = 1 if p.get("is_string") else 0
            is_uc = 1 if p.get("is_user_check") else 0
            bk = bkind_map.get(p.get("bound_kind"), 0)
            boff = p.get("bound_ms_offset") if p.get("bound_ms_offset") is not None else -1
            bsz = p.get("bound_ms_size") or 0
            scnt = p.get("static_count") if p.get("static_count") is not None else -1
            prok = 1 if p.get("param_replay_supported", True) else 0
            tokens.append(
                f"P:{idx}:{pidx}:{moff}:{msz}:{esz}:{is_ptr}:{pdepth}:{dcode}:{is_str}:{is_uc}:{bk}:{boff}:{bsz}:{scnt}:{prok}"
            )
    return ";".join(tokens)


def resolve_enclave_path(tdir: Path, mode: str) -> tuple[Path, int]:
    mapping = {
        "profile_4gate": (tdir / "enclave.profile.4gate.aex0.signed.so", 1),
        "all_reg_4gate": (tdir / "enclave.all_reg.4gate.aex0.signed.so", 1),
        "dynamic_4gate": (tdir / "enclave.dynamic.4gate.aex0.signed.so", 1),
        "dynamic_xr_4gate": (tdir / "enclave.dynamic_xr.4gate.aex0.signed.so", 1),
        "raw_unprotected": (SAMPLE_ROOT / "build" / "real" / tdir.name / "raw" / "enclave.signed.so", 0),
        "profile_signed": (tdir / "enclave.profile.aex0.signed.so", 0),
        "all_reg_final": (tdir / "enclave.all_reg.final.signed.so", 0),
        "all_reg_final_aex0": (tdir / "enclave.all_reg.final.aex0.signed.so", 0),
        "dynamic_final": (tdir / "enclave.dynamic.final.signed.so", 0),
        "dynamic_final_aex0": (tdir / "enclave.dynamic.final.aex0.signed.so", 0),
        "dynamic_xr_final": (tdir / "enclave.dynamic_xr.final.signed.so", 0),
        "dynamic_xr_final_aex0": (tdir / "enclave.dynamic_xr.final.aex0.signed.so", 0),
        "sm4_seeded_xr_4gate": (tdir / "enclave.sm4_seeded_xr.4gate.aex0.signed.so", 1),
        "sm4_seeded_xr_final": (tdir / "enclave.sm4_seeded_xr.final.signed.so", 0),
        "sm4_seeded_xr_final_aex0": (tdir / "enclave.sm4_seeded_xr.final.aex0.signed.so", 0),
    }
    if mode not in mapping:
        raise ValueError(f"unknown mode: {mode}")
    return mapping[mode]


def run_sample(
    sample: str,
    mode: str = "profile_4gate",
    ipi_mask: int = 7,
    intervention: str = "",
    strict_ready_file: str = "",
    strict_mode: str = "",
    dump_dir: str = "",
    encl_cpu: int = 45,
    watch_cpu: int = 1,
    allow_fast_forward: int = 0,
    stop_after_call: int | None = None,
    stop_after_selector: str = "",
    stop_before_normal_ecall: str = "",
    host_args: list[str] | None = None,
    persist_prefix: Path | None = None,
    timeout_sec: int = 300,
) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    host_bin = (tdir / "host") if (tdir / "host").is_file() else (SAMPLE_ROOT / "build" / "real" / sample / "anchor" / "host")
    encl, use_4gate = resolve_enclave_path(tdir, mode)
    spec = make_layout_spec(sample, encl)
    schema_spec = make_schema_spec(sample)
    if strict_ready_file and not strict_mode:
        strict_mode = "ecall"

    ready_table_map = {
        "all_reg_final": tdir / "enclave.all_reg.ready.bin",
        "dynamic_xr_final": tdir / "enclave.dynamic_xr.ready.bin",
        "dynamic_final": tdir / "enclave.dynamic.ready.bin",
        "sm4_seeded_xr_final": tdir / "enclave.sm4_seeded_xr.ready.bin",
    }
    ready_bin = ready_table_map.get(mode)
    is_pure_prod = (
        use_4gate == 0
        and not strict_mode
        and not strict_ready_file
        and not intervention
        and not dump_dir
        and stop_after_call is None
        and not stop_after_selector
        and not stop_before_normal_ecall
        and mode in ("raw_unprotected", "profile_signed", "all_reg_final", "dynamic_xr_final", "dynamic_final", "sm4_seeded_xr_final")
    )

    with tempfile.TemporaryDirectory(prefix=f"atfield_run_{sample}_") as work_cwd:
        trace_file = Path(work_cwd) / "trace.jsonl"
        env_args = [
            f"LD_PRELOAD={INTERPOSE_SO}",
            f"LD_LIBRARY_PATH={LD_LIB_PATH}",
            f"ATFIELD_ENCLAVE_PATH={encl}",
            f"ATFIELD_LAYOUT_SPEC={spec}",
            f"ATFIELD_SCHEMA_SPEC={schema_spec}",
            f"ATFIELD_TRACE_OUT={trace_file}",
            f"ATFIELD_USE_4GATE={use_4gate}",
            f"ATFIELD_IPI_MASK={ipi_mask}",
            f"ATFIELD_ENCL_CPU={encl_cpu}",
            f"ATFIELD_WATCH_CPU={watch_cpu}",
            f"ATFIELD_ALLOW_FAST_FORWARD={allow_fast_forward}",
            f"ATFIELD_PURE_PROD={1 if is_pure_prod else 0}",
            f"ATFIELD_STOP_AFTER_CALL={'' if stop_after_call is None else stop_after_call}",
            f"ATFIELD_STOP_AFTER_SELECTOR={stop_after_selector}",
            f"ATFIELD_STOP_BEFORE_NORMAL_ECALL={stop_before_normal_ecall}",
            f"ATFIELD_INTERVENTION={intervention}",
            f"ATFIELD_STRICT_READY_FILE={strict_ready_file}",
            f"ATFIELD_STRICT_MODE={strict_mode}",
            f"ATFIELD_DUMP_DIR={dump_dir}",
        ]
        if ready_bin is not None and is_pure_prod:
            if not ready_bin.is_file():
                raise FileNotFoundError(f"Required ReadyTable missing for protected mode {mode}: {ready_bin}")
            env_args.append("ATFIELD_REQUIRE_READINESS=1")
            env_args.append(f"ATFIELD_READY_TABLE={ready_bin}")
        if is_pure_prod:
            cmd = [
                "sudo", "--", str(ATFIELD_HOST_BIN), "run", "--", "/usr/bin/env",
                *env_args, "setarch", "x86_64", "-R", str(host_bin), *(host_args or [])
            ]
        else:
            cmd = [
                "sudo", "env",
                *env_args, "setarch", "x86_64", "-R", str(host_bin), *(host_args or [])
            ]
        timed_out = False
        try:
            proc = subprocess.run(cmd, cwd=work_cwd, text=True, capture_output=True, timeout=timeout_sec)
            time.sleep(0.01)
            rc = proc.returncode
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = -9
            stdout = (exc.stdout or b"").decode("utf-8", errors="replace").strip() if isinstance(exc.stdout, bytes) else (exc.stdout or "").strip()
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace").strip() if isinstance(exc.stderr, bytes) else (exc.stderr or "").strip()

        records = []
        trace_sha256 = ""
        if trace_file.is_file():
            trace_sha256 = sha256_file(trace_file)
            for line in trace_file.read_text().splitlines():
                if line.strip():
                    records.append(json.loads(line))
            if persist_prefix is not None:
                persist_prefix.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(trace_file, persist_prefix.with_suffix(".jsonl"))

        any_invalid = any(r.get("measurement_invalid", 0) != 0 for r in records)
        schema_file = tdir / "edl_schema.json"
        result = {
            "sample": sample,
            "mode": mode,
            "enclave_path": str(encl),
            "enclave_sha256": sha256_file(encl),
            "host_path": str(host_bin),
            "host_sha256": sha256_file(host_bin),
            "interpose_sha256": sha256_file(INTERPOSE_SO),
            "schema_sha256": sha256_file(schema_file) if schema_file.is_file() else "",
            "ready_table_path": str(ready_bin) if (ready_bin and is_pure_prod) else "",
            "ready_table_sha256": sha256_file(ready_bin) if (ready_bin and is_pure_prod and ready_bin.is_file()) else "",
            "trace_jsonl": str(persist_prefix.with_suffix(".jsonl")) if persist_prefix is not None else "",
            "trace_sha256": trace_sha256,
            "command": cmd,
            "ipi_mask": ipi_mask,
            "intervention": intervention,
            "strict_mode": strict_mode,
            "strict_ready_file": strict_ready_file,
            "allow_fast_forward": allow_fast_forward,
            "stop_after_call": stop_after_call,
            "stop_after_selector": stop_after_selector,
            "stop_before_normal_ecall": stop_before_normal_ecall,
            "host_args": host_args or [],
            "timed_out": timed_out,
            "measurement_invalid": any_invalid,
            "returncode": rc,
            "stdout": stdout,
            "stderr": stderr,
            "records": records,
        }
        if persist_prefix is not None:
            meta = {k: v for k, v in result.items() if k != "records"}
            meta["record_count"] = len(records)
            persist_prefix.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        return result


if __name__ == "__main__":
    sample = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "profile_4gate"
    ipi = int(sys.argv[3]) if len(sys.argv) > 3 else (7 if "profile" in mode else 3)
    interv = sys.argv[4] if len(sys.argv) > 4 else ""
    res = run_sample(sample, mode=mode, ipi_mask=ipi, intervention=interv)
    print(f"rc={res['returncode']} invalid={res['measurement_invalid']} stdout={res['stdout']} records={len(res['records'])}")
