#!/usr/bin/env python3
"""Compiler-exact EDL parser & ms_*_t ABI/bound reflection generator."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")
SGX_SDK_INC = "/nix/store/w9361i2a8728720ll02ypv9nbbfzw5pj-sgx-sdk-2.29.100.1/include"

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
    "ehsm-opt-1": {
        "edl": SAMPLE_ROOT / "real/ehsm-opt-1/enclave_hsm.edl",
        "u_c": SAMPLE_ROOT / "build/real/ehsm-opt-1/anchor/real/ehsm-opt-1/ehsm_opt_1_enclave_edl_untrusted/enclave_hsm_u.c",
        "u_dir": SAMPLE_ROOT / "build/real/ehsm-opt-1/anchor/real/ehsm-opt-1/ehsm_opt_1_enclave_edl_untrusted",
        "inc": [
            f"-I{SGX_SDK_INC}",
            f"-I{SAMPLE_ROOT}/real/ehsm-opt-1",
            "-I/nix/store/zd3wnkf5a9rl27ai52kr6ws9k2k80228-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-1-clang/include",
            "-I/nix/store/zd3wnkf5a9rl27ai52kr6ws9k2k80228-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-1-clang/core/Enclave",
        ],
    },
    "ehsm-opt-2": {
        "edl": SAMPLE_ROOT / "real/ehsm-opt-2/enclave_hsm.edl",
        "u_c": SAMPLE_ROOT / "build/real/ehsm-opt-2/anchor/real/ehsm-opt-2/ehsm_opt_2_enclave_edl_untrusted/enclave_hsm_u.c",
        "u_dir": SAMPLE_ROOT / "build/real/ehsm-opt-2/anchor/real/ehsm-opt-2/ehsm_opt_2_enclave_edl_untrusted",
        "inc": [
            f"-I{SGX_SDK_INC}",
            f"-I{SAMPLE_ROOT}/real/ehsm-opt-2",
            "-I/nix/store/bz93f9hr99lpgdyr032qrsfxyi6zj6qj-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-2-clang/include",
            "-I/nix/store/bz93f9hr99lpgdyr032qrsfxyi6zj6qj-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-2-clang/core/Enclave",
        ],
    },
}
for _cdir in sorted((DYN_ROOT / "challenges").glob("challenge-*")):
    _cfg_f = _cdir / "challenge_config.json"
    if _cfg_f.is_file():
        _ccfg = json.loads(_cfg_f.read_text())
        _stem = _ccfg["edl_stem"]
        SAMPLES[_cdir.name] = {
            "edl": _cdir / _ccfg["edl"],
            "u_c": DYN_ROOT / "targets" / _cdir.name / "edl_gen" / f"{_stem}_u.c",
            "u_dir": DYN_ROOT / "targets" / _cdir.name / "edl_gen",
            "inc": [f"-I{SGX_SDK_INC}"],
        }


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def parse_edl_trusted(edl_path: Path) -> list[dict]:
    raw = strip_comments(edl_path.read_text())
    m = re.search(r"\btrusted\s*\{(.*?)\}", raw, flags=re.S)
    if not m:
        raise ValueError(f"no trusted block in {edl_path}")
    body = m.group(1)
    ecalls = []
    idx = 0
    for stmt in body.split(";"):
        stmt = " ".join(stmt.strip().split())
        if not stmt.startswith("public "):
            continue
        rest = stmt[len("public "):].strip()
        fm = re.match(r"^(.*?)(\w+)\s*\((.*)\)$", rest)
        if not fm:
            continue
        ret_type = fm.group(1).strip()
        fn_name = fm.group(2).strip()
        args_str = fm.group(3).strip()
        params = []
        if args_str and args_str != "void":
            parts = []
            cur = []
            depth = 0
            for ch in args_str:
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                if ch == "," and depth == 0:
                    parts.append("".join(cur).strip())
                    cur = []
                else:
                    cur.append(ch)
            if cur:
                parts.append("".join(cur).strip())
            for p in parts:
                attrs = []
                am = re.match(r"^\[(.*?)\]\s*(.*)$", p)
                if am:
                    attrs = [a.strip() for a in am.group(1).split(",") if a.strip()]
                    decl = am.group(2).strip()
                else:
                    decl = p
                pm = re.match(r"^(.*?)(\w+)$", decl)
                if not pm:
                    continue
                ptype = pm.group(1).strip()
                pname = pm.group(2).strip()
                ptr_depth = ptype.count("*")
                params.append({
                    "name": pname,
                    "type": ptype,
                    "attributes": attrs,
                    "is_pointer": ptr_depth > 0,
                    "ptr_depth": ptr_depth,
                    "decl": decl,
                })
        ecalls.append({
            "ecall_index": idx,
            "name": fn_name,
            "return_type": ret_type,
            "params": params,
        })
        idx += 1
    return ecalls


def introspect_u_c(sample: str, cfg: dict, ecalls: list[dict]) -> list[dict]:
    u_c_text = cfg["u_c"].read_text()
    structs = {}
    for sm in re.finditer(r"typedef\s+struct\s+ms_(\w+)_t\s*\{(.*?)\}\s*ms_\1_t\s*;", u_c_text, flags=re.S):
        fn = sm.group(1)
        sbody = sm.group(2)
        fields = []
        for line in sbody.splitlines():
            line = line.strip().rstrip(";")
            if not line:
                continue
            lm = re.match(r"^(.*?)(\w+)$", line)
            if lm:
                fields.append((lm.group(1).strip(), lm.group(2).strip()))
        structs[fn] = fields

    c_lines = [
        "#include <stdio.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        *[f"#ifndef {m.group(1)}\n#define {m.group(1)} {m.group(2)}\n#endif" for m in re.finditer(r"^\s*#\s*define\s+(\w+)\s+([0-9xXa-fA-F]+)", cfg["edl"].read_text(), flags=re.M)],
        f'#include "{cfg["u_c"]}"',
        "sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index, const void *ocall_table, void *ms) { (void)eid; (void)index; (void)ocall_table; (void)ms; return SGX_SUCCESS; }",
        "sgx_status_t sgx_ocall(const unsigned int index, void *ms) { (void)index; (void)ms; return SGX_SUCCESS; }",
        "void *sgx_ocalloc(size_t size) { (void)size; return 0; }",
        "void sgx_ocfree(void) {}",
        "void ocall_print_string(const char *str) { (void)str; }",
        "uint64_t oc_realloc(void *optr, size_t osz, size_t nsz) { (void)optr; (void)osz; (void)nsz; return 0; }",
        "void oc_free(void *optr, size_t sz) { (void)optr; (void)sz; }",
        "int main(void) {",
        '  printf("{\\n");',
    ]
    items = [e for e in ecalls if e["name"] in structs]
    for i, e in enumerate(items):
        fn = e["name"]
        sname = f"ms_{fn}_t"
        flds = structs[fn]
        fld_names = {fname for _, fname in flds}
        c_lines.append(f'  printf("  \\"{fn}\\": {{\\"size\\": %zu, \\"fields\\": {{\\n", sizeof({sname}));')
        for j, (ftype, fname) in enumerate(flds):
            comma = "," if j + 1 < len(flds) else ""
            is_void_ptr = ("void" in ftype and "*" in ftype)
            deref_expr = "1UL" if is_void_ptr else f"sizeof(*((({sname} *)0)->{fname}))" if "*" in ftype else f"sizeof((({sname} *)0)->{fname})"
            c_lines.append(
                f'  printf("    \\"{fname}\\": {{\\"offset\\": %zu, \\"size\\": %zu, \\"elem_size\\": %zu, \\"type\\": \\"{ftype}\\"}}{comma}\\n", '
                f"offsetof({sname}, {fname}), sizeof((({sname} *)0)->{fname}), (size_t)({deref_expr}));"
            )
        c_lines.append('  printf("  }, \\"param_consts\\": {\\n");')
        const_exprs = []
        for pm in e["params"]:
            for attr in pm.get("attributes", []):
                mc = re.match(r"^(count|size)\s*=\s*(\w+)$", attr)
                if mc and f"ms_{mc.group(2)}" not in fld_names:
                    const_exprs.append((pm["name"], mc.group(1), mc.group(2)))
        for j, (pname, bkind, expr) in enumerate(const_exprs):
            comma = "," if j + 1 < len(const_exprs) else ""
            c_lines.append(
                f'  printf("    \\"{pname}\\": {{\\"kind\\": \\"{bkind}\\", \\"value\\": %zu}}{comma}\\n", (size_t)({expr}));'
            )
        c_lines.append('  printf("  }\\n");')
        end_comma = "," if i + 1 < len(items) else ""
        c_lines.append(f'  printf("  }}{end_comma}\\n");')
    c_lines.append('  printf("}\\n");')
    c_lines.append("  return 0;")
    c_lines.append("}")

    with tempfile.TemporaryDirectory() as td:
        c_file = Path(td) / "probe.c"
        bin_file = Path(td) / "probe"
        c_file.write_text("\n".join(c_lines))
        cmd = ["gcc", "-O0", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", f"-I{cfg['u_dir']}", *cfg["inc"], str(c_file), "-o", str(bin_file)]
        subprocess.run(cmd, check=True)
        out = subprocess.check_output([str(bin_file)], text=True)
        layout_map = json.loads(out)

    for e in ecalls:
        ms = layout_map.get(e["name"])
        e["ms_layout"] = ms
        if not ms:
            e["has_retval"] = False
            e["retval_offset"] = None
            e["retval_size"] = 0
            e["replay_supported"] = True
            continue
        flds = ms["fields"]
        pconsts = ms.get("param_consts", {})
        if "ms_retval" in flds and e["return_type"] != "void":
            e["has_retval"] = True
            e["retval_offset"] = flds["ms_retval"]["offset"]
            e["retval_size"] = flds["ms_retval"]["size"]
        else:
            e["has_retval"] = False
            e["retval_offset"] = None
            e["retval_size"] = 0

        replay_ok = True
        for param in e["params"]:
            ms_name = f"ms_{param['name']}"
            if ms_name in flds:
                param["ms_offset"] = flds[ms_name]["offset"]
                param["ms_size"] = flds[ms_name]["size"]
                param["elem_size"] = flds[ms_name]["elem_size"]
            attrs = param.get("attributes", [])
            has_in = any(a == "in" or a.startswith("in=") for a in attrs)
            has_out = any(a == "out" or a.startswith("out=") for a in attrs)
            param["direction"] = "inout" if (has_in and has_out) else ("in" if has_in else ("out" if has_out else "val"))
            param["is_string"] = any(a == "string" for a in attrs)
            param["is_user_check"] = any(a == "user_check" for a in attrs)
            param["bound_kind"] = None
            param["bound_param"] = None
            param["bound_ms_offset"] = None
            param["bound_ms_size"] = None
            param["static_count"] = None

            has_unsupported_bound_expr = False
            if param["is_pointer"]:
                for a in attrs:
                    if a.startswith(("count", "size")):
                        mc = re.match(r"^(count|size)\s*=\s*(\w+)$", a)
                        if not mc:
                            has_unsupported_bound_expr = True
                            continue
                        kind, ref = mc.group(1), mc.group(2)
                        ref_ms = f"ms_{ref}"
                        param["bound_kind"] = kind
                        param["bound_param"] = ref
                        if ref_ms in flds:
                            param["bound_ms_offset"] = flds[ref_ms]["offset"]
                            param["bound_ms_size"] = flds[ref_ms]["size"]
                        elif param["name"] in pconsts:
                            param["static_count"] = pconsts[param["name"]]["value"]
                        else:
                            has_unsupported_bound_expr = True
                if not has_unsupported_bound_expr and param["bound_kind"] is None and not param["is_string"] and not param["is_user_check"]:
                    if param["ptr_depth"] == 1 and "void" not in param["type"]:
                        param["bound_kind"] = "count"
                        param["static_count"] = 1
                if has_unsupported_bound_expr:
                    param["param_replay_supported"] = False
                    replay_ok = False
                if param["is_user_check"] or param["ptr_depth"] > 1:
                    param["param_replay_supported"] = False
                    replay_ok = False
                elif not param["is_string"] and param["bound_ms_offset"] is None and param["static_count"] is None:
                    param["param_replay_supported"] = False
                    replay_ok = False
                else:
                    param["param_replay_supported"] = True
            else:
                param["param_replay_supported"] = True
            # Compute static_byte_len when static_count is known
            if param["is_pointer"] and param["static_count"] is not None:
                if param["bound_kind"] == "size":
                    param["static_byte_len"] = param["static_count"]
                else:
                    param["static_byte_len"] = param["static_count"] * param.get("elem_size", 1)
            else:
                param["static_byte_len"] = None
        e["replay_supported"] = replay_ok
    return ecalls


def main() -> None:
    summary = {}
    for sample, cfg in SAMPLES.items():
        ecalls = parse_edl_trusted(cfg["edl"])
        ecalls = introspect_u_c(sample, cfg, ecalls)
        out_dir = DYN_ROOT / "targets" / sample
        out_dir.mkdir(parents=True, exist_ok=True)
        schema_path = out_dir / "edl_schema.json"
        payload = {
            "sample": sample,
            "edl_path": str(cfg["edl"]),
            "u_c_path": str(cfg["u_c"]),
            "ecalls": ecalls,
        }
        schema_path.write_text(json.dumps(payload, indent=2) + "\n")
        summary[sample] = [
            {
                "index": e["ecall_index"],
                "name": e["name"],
                "return_type": e["return_type"],
                "has_retval": e["has_retval"],
                "replay_supported": e["replay_supported"],
                "ms_size": e["ms_layout"]["size"] if e["ms_layout"] else 0,
                "params": [
                    (
                        p["name"],
                        p["direction"],
                        f"off={p.get('ms_offset')}",
                        f"elem_sz={p.get('elem_size')}",
                        f"static_b={p.get('static_byte_len')}",
                        f"bound={p.get('bound_kind')}:{p.get('bound_ms_offset')}:{p.get('bound_ms_size')}",
                        f"str={p.get('is_string')}",
                    )
                    for p in e["params"]
                ],
            }
            for e in ecalls
        ]
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
