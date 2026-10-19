#!/usr/bin/env python3
"""Parse EDL and edger8r *_u.c bridges to emit compiler-exact ms_*_t marshaling schemas."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")
SGX_SDK_INC = "/nix/store/2acwmnfcsz668csnyxn77brmllp7kx6s-sgx-sdk-2.29.100.1/include"

SAMPLES = {
    "qe3": {
        "edl": SAMPLE_ROOT / "real/qe3/qe3_enclave.edl",
        "u_c": SAMPLE_ROOT / "build/real/qe3/anchor/real/qe3/qe3_enclave_edl_untrusted/qe3_enclave_u.c",
        "u_dir": SAMPLE_ROOT / "build/real/qe3/anchor/real/qe3/qe3_enclave_edl_untrusted",
        "inc": [
            f"-I{SGX_SDK_INC}",
            f"-I{SAMPLE_ROOT}/real/qe3",
            "-I/nix/store/xikv7y5qjigjav7l8mjpv7ryrm230jwl-qe3-7ed37274294c5dc47bda4cec601bb727be2875e0/ae/dep/inc/internal",
            "-I/nix/store/xikv7y5qjigjav7l8mjpv7ryrm230jwl-qe3-7ed37274294c5dc47bda4cec601bb727be2875e0/QuoteGeneration/quote_wrapper/common/inc",
            "-I/nix/store/xikv7y5qjigjav7l8mjpv7ryrm230jwl-qe3-7ed37274294c5dc47bda4cec601bb727be2875e0/QuoteGeneration/common/inc/internal",
        ],
    },
    "signal-cds": {
        "edl": SAMPLE_ROOT / "real/signal-cds/sabd_enclave.edl",
        "u_c": SAMPLE_ROOT / "build/real/signal-cds/anchor/real/signal-cds/signal_cds_enclave_edl_untrusted/sabd_enclave_u.c",
        "u_dir": SAMPLE_ROOT / "build/real/signal-cds/anchor/real/signal-cds/signal_cds_enclave_edl_untrusted",
        "inc": [
            f"-I{SGX_SDK_INC}",
            f"-I{SAMPLE_ROOT}/real/signal-cds",
            "-I/nix/store/g0p9ac9flpwhzpgvwhscsd155fninvaa-signal-cds-69d33cfd8634fc3b1eb74b71e94cde77abe1a1c6-clang/enclave/include",
        ],
    },
    "sgxwallet": {
        "edl": SAMPLE_ROOT / "real/sgxwallet/secure_enclave.edl",
        "u_c": SAMPLE_ROOT / "build/real/sgxwallet/anchor/real/sgxwallet/sgxwallet_enclave_edl_untrusted/secure_enclave_u.c",
        "u_dir": SAMPLE_ROOT / "build/real/sgxwallet/anchor/real/sgxwallet/sgxwallet_enclave_edl_untrusted",
        "inc": [
            f"-I{SGX_SDK_INC}",
            f"-I{SAMPLE_ROOT}/real/sgxwallet",
            "-I/nix/store/gxn26m1yw7cp50myszbf50vhf1q725ls-sgxwallet-c24ad2580570064ce3dbc0a8a16122f67b081b32-clang/secure_enclave",
        ],
    },
    "ehsm": {
        "edl": SAMPLE_ROOT / "real/ehsm/enclave_hsm.edl",
        "u_c": SAMPLE_ROOT / "build/real/ehsm/anchor/real/ehsm/ehsm_enclave_edl_untrusted/enclave_hsm_u.c",
        "u_dir": SAMPLE_ROOT / "build/real/ehsm/anchor/real/ehsm/ehsm_enclave_edl_untrusted",
        "inc": [
            f"-I{SGX_SDK_INC}",
            f"-I{SAMPLE_ROOT}/real/ehsm",
            "-I/nix/store/my840mbl3rj7gv78bmhbxxi48yznjfvp-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-clang/include",
            "-I/nix/store/my840mbl3rj7gv78bmhbxxi48yznjfvp-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-clang/core/Enclave",
        ],
    },
}


def parse_edl_ecalls(edl_text: str) -> list[dict]:
    clean = re.sub(r"/\*.*?\*/", "", edl_text, flags=re.S)
    clean = re.sub(r"//[^\n]*", "", clean)
    ecalls = []
    idx = 0
    for m in re.finditer(r"\bpublic\s+([^;(]+?)\s+(\w+)\s*\(([^)]*)\)\s*;", clean, re.S):
        ret_type = " ".join(m.group(1).split())
        name = m.group(2).strip()
        raw_params = m.group(3).strip()
        params = []
        if raw_params and raw_params != "void":
            parts = re.split(r",(?![^\[]*\])", raw_params)
            for p in parts:
                p = " ".join(p.strip().split())
                if not p:
                    continue
                attr_m = re.match(r"^\[([^\]]+)\]\s*(.+)$", p)
                attrs = [a.strip() for a in attr_m.group(1).split(",")] if attr_m else []
                decl = attr_m.group(2) if attr_m else p
                nm_m = re.search(r"(\w+)\s*(?:\[\s*\d*\s*\])?$", decl)
                pname = nm_m.group(1) if nm_m else f"arg{len(params)}"
                params.append({
                    "name": pname,
                    "decl": decl,
                    "attributes": attrs,
                    "is_pointer": ("*" in decl) or ("[" in decl),
                })
        ecalls.append({
            "ecall_index": idx,
            "name": name,
            "return_type": ret_type,
            "params": params,
        })
        idx += 1
    return ecalls


def introspect_u_c(sample: str, cfg: dict, ecalls: list[dict]) -> list[dict]:
    u_c_text = cfg["u_c"].read_text()
    ms_structs: dict[str, list[str]] = {}
    for m in re.finditer(r"typedef\s+struct\s+(ms_\w+_t)\s*\{([^}]*)\}\s*\1\s*;", u_c_text, re.S):
        st_name = m.group(1)
        body = m.group(2)
        fields = []
        for line in body.splitlines():
            line = line.strip().rstrip(";")
            if not line:
                continue
            fm = re.search(r"(\w+)$", line)
            if fm:
                fields.append(fm.group(1))
        ms_structs[st_name] = fields

    c_lines = [
        "#include <stdio.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        f'#include "{cfg["u_c"].name}"',
        "int main(void) {",
        '  printf("{\\n");',
    ]
    items = []
    for ec in ecalls:
        st_name = f"ms_{ec['name']}_t"
        if st_name in ms_structs:
            items.append((ec["name"], st_name, ms_structs[st_name]))
    for idx, (ec_name, st_name, flds) in enumerate(items):
        comma = "," if idx + 1 < len(items) else ""
        c_lines.append(f'  printf("  \\"{ec_name}\\": {{\\"struct\\": \\"{st_name}\\", \\"size\\": %zu, \\"fields\\": {{", sizeof({st_name}));')
        for f_idx, f in enumerate(flds):
            f_comma = "," if f_idx + 1 < len(flds) else ""
            c_lines.append(
                f'  printf("\\"{f}\\": {{\\"offset\\": %zu, \\"size\\": %zu}}{f_comma}", '
                f"offsetof({st_name}, {f}), sizeof((({st_name} *)0)->{f}));"
            )
        c_lines.append(f'  printf("}}}}{comma}\\n");')
    c_lines.append('  printf("}\\n");')
    c_lines.append("  return 0;")
    c_lines.append("}")

    with tempfile.TemporaryDirectory() as td:
        c_file = Path(td) / "introspect.c"
        bin_file = Path(td) / "introspect"
        c_file.write_text("\n".join(c_lines) + "\n")
        # Define dummy sgx_ecall / sgx_ocall so we don't even need libsgx_urts.so at link time
        wrapper = Path(td) / "stubs.c"
        wrapper.write_text(
            "int sgx_ecall(unsigned long e, int i, const void *o, void *m){(void)e;(void)i;(void)o;(void)m;return 0;}\n"
            "int sgx_ecall_switchless(unsigned long e, int i, const void *o, void *m){(void)e;(void)i;(void)o;(void)m;return 0;}\n"
            "int sgx_ocall(unsigned int i, void *m){(void)i;(void)m;return 0;}\n"
        )
        # Stub out any OCALL host implementations referenced in *_u.c ocall table
        ocall_names = re.findall(r"\(void\*\)(\w+),\s*$", u_c_text, re.M)
        for oc in set(ocall_names):
            with wrapper.open("a") as wf:
                wf.write(f"void {oc}(void){{}}\n")
        subprocess.run(
            ["gcc", "-O0", "-w", "-Wl,--unresolved-symbols=ignore-all", f"-I{cfg['u_dir']}", *cfg["inc"], str(c_file), str(wrapper), "-o", str(bin_file)],
            check=True,
        )
        out = subprocess.check_output([str(bin_file)], text=True)
        layout_map = json.loads(out)

    for ec in ecalls:
        ec["ms_layout"] = layout_map.get(ec["name"])
    return ecalls



def enrich_schema_bindings(ecalls: list[dict]) -> list[dict]:
    TYPE_SIZES = {
        "uint64_t": 8, "int64_t": 8, "size_t": 8, "unsigned long": 8, "long": 8,
        "uint32_t": 4, "int32_t": 4, "int": 4, "unsigned int": 4,
        "uint16_t": 2, "int16_t": 2, "short": 2,
        "uint8_t": 1, "int8_t": 1, "char": 1, "unsigned char": 1, "void": 1,
    }
    for ec in ecalls:
        ms = ec.get("ms_layout")
        if not ms:
            continue
        flds = ms["fields"]
        for param in ec["params"]:
            ms_name = f"ms_{param['name']}"
            if ms_name in flds:
                param["ms_offset"] = flds[ms_name]["offset"]
                param["ms_size"] = flds[ms_name]["size"]
            attrs = param.get("attributes", [])
            direction = "in" if any(a == "in" or a.startswith("in=") for a in attrs) else ("out" if any(a == "out" for a in attrs) else "val")
            if any(a == "in" for a in attrs) and any(a == "out" for a in attrs):
                direction = "inout"
            param["direction"] = direction
            param["is_string"] = any(a == "string" for a in attrs)
            # Determine base element size for pointer
            base_decl = re.sub(r"\bconst\b", "", param["decl"]).replace("*", "").strip()
            base_type = " ".join(base_decl.split()[:-1])
            param["elem_size"] = TYPE_SIZES.get(base_type, 1)
            for a in attrs:
                m_cnt = re.match(r"^(count|size)\s*=\s*(\w+)$", a)
                if m_cnt:
                    kind, ref_name = m_cnt.group(1), m_cnt.group(2)
                    ref_ms = f"ms_{ref_name}"
                    param["bound_kind"] = kind
                    param["bound_param"] = ref_name
                    if ref_ms in flds:
                        param["bound_ms_offset"] = flds[ref_ms]["offset"]
                        param["bound_ms_size"] = flds[ref_ms]["size"]
    return ecalls


def main() -> None:
    summary = {}
    for sample, cfg in SAMPLES.items():
        ecalls = parse_edl_ecalls(cfg["edl"].read_text())
        ecalls = enrich_schema_bindings(introspect_u_c(sample, cfg, ecalls))
        out_path = DYN_ROOT / "targets" / sample / "edl_schema.json"
        payload = {
            "schema": "atfield-edl-schema-v1",
            "sample": sample,
            "edl_path": str(cfg["edl"]),
            "untrusted_bridge_c": str(cfg["u_c"]),
            "ecalls": ecalls,
        }
        out_path.write_text(json.dumps(payload, indent=2) + "\n")
        summary[sample] = [
            {
                "index": e["ecall_index"],
                "name": e["name"],
                "ms_size": e["ms_layout"]["size"] if e["ms_layout"] else 0,
                "fields": list(e["ms_layout"]["fields"].keys()) if e["ms_layout"] else [],
            }
            for e in ecalls
        ]
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
