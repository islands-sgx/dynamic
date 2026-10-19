#!/usr/bin/env python3
"""Run an unmodified sample host binary under libatfield_native_sgx.so on real SGX hardware."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/home/meandssh/islands-sgx/dynamic/vendor/implement/build/workset")
from workset import ElfFile  # noqa: E402

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")
INTERPOSE_SO = DYN_ROOT / "build" / "libatfield_native_sgx.so"


def make_layout_spec(sample: str) -> str:
    tdir = DYN_ROOT / "targets" / sample
    layout = json.loads((tdir / "signer_layout.json").read_text())
    elf = ElfFile(tdir / "enclave.profile.so")
    syms = {s["name"]: s["value"] for s in elf.symbols() if s["shndx"] != 0}
    gm_rva = syms.get("_gm_", syms.get("gm_", 0))

    tcs_rva = 0
    excl = []
    for r in layout["excluded_regions"]:
        if r["name"] == "TCS":
            tcs_rva = r["start_rva"]
        excl.append(f"{r['start_rva']:x}:{r['end_rva']:x}")

    stack_lo = stack_hi = 0
    for r in layout["regions"]:
        if r.get("kind") == "signer" and r.get("name", "").startswith("STACK"):
            stack_lo, stack_hi = r["start_rva"], r["end_rva"]

    p_start = layout["pretouch_start"]
    p_end = p_start + layout["capacity_q"]
    gate_rva = p_end - 4096
    return (
        f"tcs={tcs_rva:x};gm={gm_rva:x};pretouch={p_start:x}:{p_end:x};"
        f"gate={gate_rva:x};stack={stack_lo:x}:{stack_hi:x};excl={','.join(excl)}"
    )


def run_sample(
    sample: str,
    mode: str = "profile_4gate",
    ipi_mask: int = 7,
    intervention: str = "",
    strict_ready_file: str = "",
    dump_dir: str = "",
    encl_cpu: int = 45,
    watch_cpu: int = 1,
) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    host_bin = SAMPLE_ROOT / "build" / "real" / sample / "anchor" / "host"
    if mode == "profile_4gate":
        encl = tdir / "enclave.profile.4gate.aex0.signed.so"
        use_4gate = 1
    elif mode == "all_reg_4gate":
        encl = tdir / "enclave.all_reg.4gate.aex0.signed.so"
        use_4gate = 1
    elif mode == "dynamic_4gate":
        encl = tdir / "enclave.dynamic.4gate.aex0.signed.so"
        use_4gate = 1
    elif mode == "all_reg_final":
        encl = tdir / "enclave.all_reg.final.signed.so"
        use_4gate = 0
    elif mode == "dynamic_final":
        encl = tdir / "enclave.dynamic.final.signed.so"
        use_4gate = 0
    elif mode == "dynamic_final_aex0":
        encl = tdir / "enclave.dynamic.final.aex0.signed.so"
        use_4gate = 0
    else:
        raise ValueError(f"unknown mode: {mode}")

    spec = make_layout_spec(sample)
    with tempfile.TemporaryDirectory(prefix=f"atfield_run_{sample}_") as work_cwd:
        trace_file = Path(work_cwd) / "trace.jsonl"
        cmd = [
            "sudo",
            "env",
            f"LD_PRELOAD={INTERPOSE_SO}",
            "LD_LIBRARY_PATH=/nix/store/hg41dqig0qxm7shyi0a0xkw29a14i3js-openssl-3.6.3/lib:/nix/store/j2kgllgds4w7na8zqv1msi0mpvpjxda8-gcc-15.2.0-lib/lib:/nix/store/idzqgxj50m3zd5h39yh5gij3iddzii3a-sgx-psw-2.29.100.1/lib64:/nix/store/idzqgxj50m3zd5h39yh5gij3iddzii3a-sgx-psw-2.29.100.1/lib",
            f"ATFIELD_ENCLAVE_PATH={encl}",
            f"ATFIELD_LAYOUT_SPEC={spec}",
            f"ATFIELD_TRACE_OUT={trace_file}",
            f"ATFIELD_USE_4GATE={use_4gate}",
            f"ATFIELD_IPI_MASK={ipi_mask}",
            f"ATFIELD_ENCL_CPU={encl_cpu}",
            f"ATFIELD_WATCH_CPU={watch_cpu}",
            f"ATFIELD_INTERVENTION={intervention}",
            f"ATFIELD_STRICT_READY_FILE={strict_ready_file}",
            f"ATFIELD_DUMP_DIR={dump_dir}",
            "setarch",
            "x86_64",
            "-R",
            str(host_bin),
        ]
        proc = subprocess.run(cmd, cwd=work_cwd, text=True, capture_output=True, timeout=180)
        records = []
        if trace_file.is_file():
            for line in trace_file.read_text().splitlines():
                if line.strip():
                    records.append(json.loads(line))
        return {
            "sample": sample,
            "mode": mode,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "records": records,
        }


def main() -> None:
    sample = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "profile_4gate"
    ipi = int(sys.argv[3]) if len(sys.argv) > 3 else (7 if "profile" in mode else 3)
    interv = sys.argv[4] if len(sys.argv) > 4 else ""
    res = run_sample(sample, mode=mode, ipi_mask=ipi, intervention=interv)
    print(f"returncode={res['returncode']} stdout={res['stdout']} records={len(res['records'])}")
    for r in res["records"]:
        f_summaries = [
            {
                "field_id": f["field_id"],
                "s0": len(f["s0"]),
                "s1": len(f["s1"]),
                "s2": len(f["s2"]),
                "s3": len(f["s3"]),
                "tsc_s2": f["tsc_s2"],
                "tsc_s3": f["tsc_s3"],
                "chunks": f["live_chunks"],
            }
            for f in r["fields"]
        ]
        print(
            f"  call_seq={r['call_seq']} ecall={r['ecall_index']} tag={r['tag']} "
            f"st={r['sgx_status']} ret={r['ms_retval_i32']} ecall_ad={len(r['ecall_ad'])} fields={f_summaries}"
        )


if __name__ == "__main__":
    main()
