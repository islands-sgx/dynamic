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
from pathlib import Path

sys.path.insert(0, "/home/meandssh/islands-sgx/dynamic/vendor/implement/build/workset")
from workset import ElfFile  # noqa: E402

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")
INTERPOSE_SO = DYN_ROOT / "build" / "libatfield_native_sgx.so"
LD_LIB_PATH = (
    "/nix/store/hg41dqig0qxm7shyi0a0xkw29a14i3js-openssl-3.6.3/lib:"
    "/nix/store/j2kgllgds4w7na8zqv1msi0mpvpjxda8-gcc-15.2.0-lib/lib:"
    "/nix/store/idzqgxj50m3zd5h39yh5gij3iddzii3a-sgx-psw-2.29.100.1/lib64:"
    "/nix/store/idzqgxj50m3zd5h39yh5gij3iddzii3a-sgx-psw-2.29.100.1/lib"
)


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""


def make_layout_spec(sample: str) -> str:
    tdir = DYN_ROOT / "targets" / sample
    layout = json.loads((tdir / "signer_layout.json").read_text())
    elf = ElfFile(tdir / "enclave.profile.so")
    syms = {s["name"]: s["value"] for s in elf.symbols() if s["shndx"] != 0}
    gm_rva = syms.get("_gm_", syms.get("gm_", 0))
    active_rva = syms.get("__atfield_active", 0)

    tcs_rva = 0
    ssa_rva = 0
    excl = []
    for r in layout["excluded_regions"]:
        if r["name"] == "TCS":
            tcs_rva = r["start_rva"]
        elif r["name"] == "SSA":
            ssa_rva = r["start_rva"]
        excl.append(f"{r['start_rva']:x}:{r['end_rva']:x}")

    stack_lo = stack_hi = 0
    for r in layout["regions"]:
        if r.get("kind") == "signer" and r.get("name", "").startswith("STACK"):
            stack_lo, stack_hi = r["start_rva"], r["end_rva"]

    p_start = layout["pretouch_start"]
    p_end = p_start + layout["capacity_q"]
    gate_rva = p_end - 4096
    return (
        f"tcs={tcs_rva:x};ssa={ssa_rva:x};gm={gm_rva:x};active={active_rva:x};"
        f"pretouch={p_start:x}:{p_end:x};gate={gate_rva:x};stack={stack_lo:x}:{stack_hi:x};"
        f"excl={','.join(excl)}"
    )


def resolve_enclave_path(tdir: Path, mode: str) -> tuple[Path, int]:
    mapping = {
        "profile_4gate": (tdir / "enclave.profile.4gate.aex0.signed.so", 1),
        "all_reg_4gate": (tdir / "enclave.all_reg.4gate.aex0.signed.so", 1),
        "dynamic_4gate": (tdir / "enclave.dynamic.4gate.aex0.signed.so", 1),
        "dynamic_xr_4gate": (tdir / "enclave.dynamic_xr.4gate.aex0.signed.so", 1),
        "profile_signed": (tdir / "enclave.profile.signed.so", 0),
        "all_reg_final": (tdir / "enclave.all_reg.final.signed.so", 0),
        "all_reg_final_aex0": (tdir / "enclave.all_reg.final.aex0.signed.so", 0),
        "dynamic_final": (tdir / "enclave.dynamic.final.signed.so", 0),
        "dynamic_final_aex0": (tdir / "enclave.dynamic.final.aex0.signed.so", 0),
        "dynamic_xr_final": (tdir / "enclave.dynamic_xr.final.signed.so", 0),
        "dynamic_xr_final_aex0": (tdir / "enclave.dynamic_xr.final.aex0.signed.so", 0),
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
    host_args: list[str] | None = None,
    persist_prefix: Path | None = None,
    timeout_sec: int = 300,
) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    host_bin = SAMPLE_ROOT / "build" / "real" / sample / "anchor" / "host"
    encl, use_4gate = resolve_enclave_path(tdir, mode)
    spec = make_layout_spec(sample)
    if strict_ready_file and not strict_mode:
        strict_mode = "ecall"

    with tempfile.TemporaryDirectory(prefix=f"atfield_run_{sample}_") as work_cwd:
        trace_file = Path(work_cwd) / "trace.jsonl"
        cmd = [
            "sudo",
            "env",
            f"LD_PRELOAD={INTERPOSE_SO}",
            f"LD_LIBRARY_PATH={LD_LIB_PATH}",
            f"ATFIELD_ENCLAVE_PATH={encl}",
            f"ATFIELD_LAYOUT_SPEC={spec}",
            f"ATFIELD_TRACE_OUT={trace_file}",
            f"ATFIELD_USE_4GATE={use_4gate}",
            f"ATFIELD_IPI_MASK={ipi_mask}",
            f"ATFIELD_ENCL_CPU={encl_cpu}",
            f"ATFIELD_WATCH_CPU={watch_cpu}",
            f"ATFIELD_ALLOW_FAST_FORWARD={allow_fast_forward}",
            f"ATFIELD_STOP_AFTER_CALL={'' if stop_after_call is None else stop_after_call}",
            f"ATFIELD_INTERVENTION={intervention}",
            f"ATFIELD_STRICT_READY_FILE={strict_ready_file}",
            f"ATFIELD_STRICT_MODE={strict_mode}",
            f"ATFIELD_DUMP_DIR={dump_dir}",
            "setarch",
            "x86_64",
            "-R",
            str(host_bin),
            *(host_args or []),
        ]
        timed_out = False
        try:
            proc = subprocess.run(cmd, cwd=work_cwd, text=True, capture_output=True, timeout=timeout_sec)
            rc = proc.returncode
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = -9
            stdout = (exc.stdout or b"").decode("utf-8", errors="replace").strip() if isinstance(exc.stdout, bytes) else (exc.stdout or "").strip()
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace").strip() if isinstance(exc.stderr, bytes) else (exc.stderr or "").strip()

        records = []
        if trace_file.is_file():
            for line in trace_file.read_text().splitlines():
                if line.strip():
                    records.append(json.loads(line))
            if persist_prefix is not None:
                persist_prefix.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(trace_file, persist_prefix.with_suffix(".jsonl"))

        any_invalid = any(r.get("measurement_invalid", 0) != 0 for r in records)
        result = {
            "sample": sample,
            "mode": mode,
            "enclave_path": str(encl),
            "enclave_sha256": sha256_file(encl),
            "host_path": str(host_bin),
            "host_sha256": sha256_file(host_bin),
            "interpose_sha256": sha256_file(INTERPOSE_SO),
            "command": cmd,
            "ipi_mask": ipi_mask,
            "intervention": intervention,
            "strict_mode": strict_mode,
            "strict_ready_file": strict_ready_file,
            "allow_fast_forward": allow_fast_forward,
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


def main() -> None:
    sample = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "profile_4gate"
    ipi = int(sys.argv[3]) if len(sys.argv) > 3 else (7 if "profile" in mode else 3)
    interv = sys.argv[4] if len(sys.argv) > 4 else ""
    res = run_sample(sample, mode=mode, ipi_mask=ipi, intervention=interv)
    print(
        f"returncode={res['returncode']} timed_out={res['timed_out']} "
        f"invalid={res['measurement_invalid']} stdout={res['stdout']} records={len(res['records'])}"
    )
    for r in res["records"]:
        f_summaries = [
            {
                "field_id": f["field_id"],
                "s0": len(f["s0"]),
                "s1": len(f["s1"]),
                "s2": len(f["s2"]),
                "s3": len(f["s3"]),
                "ipi_ok": f["ipi_aex_verified_mask"],
                "s3_aex": f["s3_active_aex_count"],
                "tsc_s2": f["tsc_s2"],
                "tsc_s3": f["tsc_s3"],
            }
            for f in r["fields"]
        ]
        print(
            f"  seq={r['call_seq']} ecall={r['ecall_index']} tag={r['tag']} "
            f"st={r['sgx_status']} ret={r['ms_retval_i32']} aex={r['total_aex_count']} "
            f"ipi_aex={r['gate_ipi_aex_count']} inv={r['measurement_invalid']} "
            f"faults={r['strict_non_ready_fault_count']} fields={f_summaries}"
        )


if __name__ == "__main__":
    main()
