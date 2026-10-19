#!/usr/bin/env python3
"""Build frozen ProfileElf, signed ProfileElf (AEX1 and AEX0), fields.json, and all-REG baseline workset for the 4 real samples."""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
SAMPLE_ROOT = Path("/home/meandssh/islands-sgx/sample")
VENDOR_IMPL = DYN_ROOT / "vendor" / "implement"
COMPILE_WRAPPER = VENDOR_IMPL / "build" / "codegen" / "compile-ir-object.sh"
FIELD_TOOL = VENDOR_IMPL / "build" / "field" / ".build-host" / "atfield-field"
PRETOUCH_TOOL = VENDOR_IMPL / "build" / "pretouch" / "pretouch.py"
POST_LD = VENDOR_IMPL / "build" / "pretouch" / "post-rx-segment.ld"
PROFILE_LINK = VENDOR_IMPL / "cli" / "profile-link.py"
PROTECT_CONFIG = VENDOR_IMPL / "cli" / "protect-config.py"
WORKSET_TOOL = VENDOR_IMPL / "build" / "workset" / "workset.py"
READINESS_TOOL = VENDOR_IMPL / "build" / "readiness" / "readiness.py"

LLC_BIN = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llc"
OBJCOPY_BIN = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llvm-objcopy"
SGX_SDK_ROOT = "/nix/store/2acwmnfcsz668csnyxn77brmllp7kx6s-sgx-sdk-2.29.100.1"
SGX_SIGN = f"{SGX_SDK_ROOT}/bin/x64/sgx_sign"
SIGN_KEY = str(SAMPLE_ROOT / "build" / "test-signing-key.pem")

TARGETS = {
    "qe3": {
        "edl": "qe3_enclave.edl",
        "heap": 0x100000,
        "stack": 0x40000,
        "capacity_q": 12288,
        "upstream_pkg": "qe3-7ed37274294c5dc47bda4cec601bb727be2875e0",
        "upstream_root": "/nix/store/xikv7y5qjigjav7l8mjpv7ryrm230jwl-qe3-7ed37274294c5dc47bda4cec601bb727be2875e0",
        "extra_includes": [f"-I{SGX_SDK_ROOT}/include"],
        "selectors": [
            {"ecall_index": 0, "name": "ecall_get_attestation_key", "reachable_functions": ["_ZL31get_att_key_based_from_seal_keyP20_sgx_ec256_private_tP19_sgx_ec256_public_tPK13_sgx_key_id_t"]}
        ],
    },
    "signal-cds": {
        "edl": "sabd_enclave.edl",
        "heap": 0x400000,
        "stack": 0x40000,
        "capacity_q": 16384,
        "upstream_pkg": "signal-cds-69d33cfd8634fc3b1eb74b71e94cde77abe1a1c6-clang",
        "upstream_root": "/nix/store/g0p9ac9flpwhzpgvwhscsd155fninvaa-signal-cds-69d33cfd8634fc3b1eb74b71e94cde77abe1a1c6-clang",
        "extra_includes": [f"-I{SGX_SDK_ROOT}/include"],
        "selectors": [
            {"ecall_index": 0, "name": "ecall_lookup_hash", "reachable_functions": ["sabd_lookup_hash"]}
        ],
    },
    "sgxwallet": {
        "edl": "secure_enclave.edl",
        "heap": 0x400000,
        "stack": 0x40000,
        "capacity_q": 90112,
        "upstream_pkg": "sgxwallet-c24ad2580570064ce3dbc0a8a16122f67b081b32-clang",
        "upstream_root": "/nix/store/gxn26m1yw7cp50myszbf50vhf1q725ls-sgxwallet-c24ad2580570064ce3dbc0a8a16122f67b081b32-clang",
        "extra_includes": [
            f"-I{SGX_SDK_ROOT}/include",
            "-I/nix/store/bg8yg7k0d4fndd7ixsm0plhygmg3fpg7-intel-sgx-gmp-anchor-6.1.2/include",
            "-I/nix/store/x9rxgc1hlz73qz8nxy7sdj3b8yb954wf-mcl-sgx-anchor-3.03/include",
        ],
        "selectors": [
            {"ecall_index": 0, "name": "trustedEnclaveInit", "reachable_functions": []},
            {"ecall_index": 1, "name": "trustedEnclaveClear", "reachable_functions": []},
            {"ecall_index": 2, "name": "trustedGenerateSEK", "reachable_functions": ["generate_sek_field"]},
            {"ecall_index": 3, "name": "trustedSetSEK", "reachable_functions": ["set_sek_field"]},
            {"ecall_index": 4, "name": "trustedGenerateEcdsaKey", "reachable_functions": ["generate_ecdsa_key_field"]},
            {"ecall_index": 5, "name": "trustedGetPublicEcdsaKey", "reachable_functions": ["get_public_ecdsa_key_field"]},
            {"ecall_index": 6, "name": "trustedEcdsaSign", "reachable_functions": ["ecdsa_sign_field"]},
        ],
    },
    "ehsm": {
        "edl": "enclave_hsm.edl",
        "heap": 0x400000,
        "stack": 0x40000,
        "capacity_q": 94208,
        "upstream_pkg": "ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-clang",
        "upstream_root": "/nix/store/my840mbl3rj7gv78bmhbxxi48yznjfvp-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-clang",
        "extra_includes": [
            f"-I{SGX_SDK_ROOT}/include",
            "-I/nix/store/nfd9a0lbz3vjh19g3nw03vpsp1qkgki7-intel-sgx-ssl-anchor-3.0_Rev5.4/include",
        ],
        "selectors": [
            {"ecall_index": 0, "name": "enclave_get_domain_key_from_local", "reachable_functions": []},
            {"ecall_index": 1, "name": "enclave_create_key", "reachable_functions": ["_Z19ehsm_create_aes_keyP14ehsm_keyblob_t"]},
            {"ecall_index": 2, "name": "enclave_encrypt", "reachable_functions": ["_Z20ehsm_aes_gcm_encryptP11ehsm_data_tP14ehsm_keyblob_tS0_S0_"]},
            {"ecall_index": 3, "name": "enclave_decrypt", "reachable_functions": ["_Z20ehsm_aes_gcm_decryptP11ehsm_data_tP14ehsm_keyblob_tS0_S0_"]},
            {"ecall_index": 4, "name": "enclave_generate_datakey", "reachable_functions": ["_ZL21ehsm_generate_datakeyP14ehsm_keyblob_tP11ehsm_data_tS2_S2_"]},
        ],
    },
}


def parse_ninja_link(ninja_path: Path) -> tuple[str, list[str], list[str]]:
    text = ninja_path.read_text()
    m = re.search(
        r"^build enclave\.so:\s+(\S+)\s+([^|\n]+).*?\n((?:  .*\n)+)",
        text,
        re.MULTILINE,
    )
    if not m:
        raise RuntimeError(f"cannot find build enclave.so in {ninja_path}")
    rule = m.group(1)
    rel_objs = shlex.split(m.group(2))
    body = m.group(3)
    flags_m = re.search(r"^\s*LINK_FLAGS\s*=\s*(.+)$", body, re.MULTILINE)
    libs_m = re.search(r"^\s*LINK_LIBRARIES\s*=\s*(.+)$", body, re.MULTILINE)
    flags = shlex.split(flags_m.group(1)) if flags_m else []
    clean_flags = []
    skip = False
    for i, f in enumerate(flags):
        if skip:
            skip = False
            continue
        if f == "-Xlinker" and i + 1 < len(flags) and flags[i + 1].startswith("--dependency-file="):
            skip = True
            continue
        if f.startswith("--dependency-file="):
            continue
        clean_flags.append(f)
    libs = shlex.split(libs_m.group(1)) if libs_m else []
    compiler = "/nix/store/fys2jh0y4iisx69yf73b3z8k048cqx95-llvm-atfield-llc-wrapper-22.1.8/bin/" + (
        "c++" if "CXX" in rule else "cc"
    )
    return compiler, rel_objs, clean_flags + libs


def build_target(name: str) -> dict:
    cfg = TARGETS[name]
    anchor_dir = SAMPLE_ROOT / "build" / "real" / name / "anchor"
    out_dir = DYN_ROOT / "targets" / name
    obj_dir = out_dir / "obj"
    out_dir.mkdir(parents=True, exist_ok=True)
    obj_dir.mkdir(parents=True, exist_ok=True)

    cc_db = json.loads((anchor_dir / "compile_commands.json").read_text())
    compiler_link, rel_objs, link_tail = parse_ninja_link(anchor_dir / "build.ninja")

    env = os.environ.copy()
    env.update({
        "ATFIELD_ANCHOR_PREPARATION": "1",
        "ATFIELD_FIELD_BOUNDARY": "1",
        "ATFIELD_IMPLEMENT_ROOT": str(VENDOR_IMPL),
        "ATFIELD_PAYLOAD_NAMESPACE": f"real/{name}",
        "ATFIELD_SOURCE_ROOT": str(SAMPLE_ROOT / "real" / name),
        "ATFIELD_LLC": LLC_BIN,
        "ATFIELD_FIELD_TOOL": str(FIELD_TOOL),
        "ATFIELD_UPSTREAM_SOURCE_ROOT": cfg["upstream_root"],
        "ATFIELD_UPSTREAM_PACKAGE": cfg["upstream_pkg"],
    })

    obj_map: dict[str, Path] = {}
    for entry in cc_db:
        out_abs = Path(entry["output"])
        rel = out_abs.relative_to(anchor_dir)
        if ".dir/host" in str(rel) or "/host.dir/" in str(rel):
            continue
        target_obj = obj_dir / rel.name
        cmd = shlex.split(entry["command"])
        new_cmd = [str(COMPILE_WRAPPER), cmd[0], *cfg["extra_includes"]]
        skip = False
        for i in range(1, len(cmd)):
            if skip:
                skip = False
                continue
            if cmd[i] == "-o":
                new_cmd.extend(["-o", str(target_obj)])
                skip = True
            else:
                new_cmd.append(cmd[i])
        subprocess.run(new_cmd, cwd=entry["directory"], env=env, check=True)
        obj_map[str(rel)] = target_obj

    ordered_objs = [str(obj_map[r]) for r in rel_objs]
    profile_elf = out_dir / "enclave.profile.so"
    link_cmd = [
        sys.executable,
        str(PROFILE_LINK),
        "--field-tool", str(FIELD_TOOL),
        "--pretouch-tool", str(PRETOUCH_TOOL),
        "--capacity-q", str(cfg["capacity_q"]),
        "--assembler", "/nix/store/fys2jh0y4iisx69yf73b3z8k048cqx95-llvm-atfield-llc-wrapper-22.1.8/bin/cc",
        "--linker-script", str(POST_LD),
        "--",
        compiler_link,
        *ordered_objs,
        *link_tail,
        "-o", str(profile_elf),
    ]
    subprocess.run(link_cmd, cwd=out_dir, check=True)

    orig_xml = SAMPLE_ROOT / "real" / name / "Enclave.config.xml"
    protect_xml = out_dir / "Enclave.protect.config.xml"
    aex0_xml = out_dir / "Enclave.aex0.config.xml"
    subprocess.run([
        sys.executable, str(PROTECT_CONFIG),
        str(orig_xml), str(protect_xml),
        "--heap", hex(cfg["heap"]), "--stack", hex(cfg["stack"]),
    ], check=True)
    aex0_text = protect_xml.read_text().replace("<EnableAEXNotify>1</EnableAEXNotify>", "<EnableAEXNotify>0</EnableAEXNotify>")
    aex0_xml.write_text(aex0_text)

    signed_profile = out_dir / "enclave.profile.signed.so"
    signed_profile_aex0 = out_dir / "enclave.profile.aex0.signed.so"
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(profile_elf), "-out", str(signed_profile),
        "-config", str(protect_xml),
    ], check=True)
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(profile_elf), "-out", str(signed_profile_aex0),
        "-config", str(aex0_xml),
    ], check=True)

    selectors_json = out_dir / "selectors.json"
    selectors_json.write_text(json.dumps({
        "schema": "atfield-selectors-v1",
        "selectors": cfg["selectors"],
    }, indent=2) + "\n")

    workset_all_reg = out_dir / "workset.all_reg.json"
    layout_json = out_dir / "signer_layout.json"
    subprocess.run([
        sys.executable, str(WORKSET_TOOL),
        "--profile-elf", str(profile_elf),
        "--signed-elf", str(signed_profile),
        "--fields", str(out_dir / "fields.json"),
        "--selectors", str(selectors_json),
        "--edl", str(SAMPLE_ROOT / "real" / name / cfg["edl"]),
        "--capacity-q", str(cfg["capacity_q"]),
        "--layout-out", str(layout_json),
        "--out", str(workset_all_reg),
    ], check=True)

    final_all_reg_elf = out_dir / "enclave.all_reg.final.so"
    final_all_reg_json = out_dir / "pretouch.all_reg.finalized.json"
    verify_all_reg_json = out_dir / "pretouch.all_reg.verified.json"
    signed_final_all_reg = out_dir / "enclave.all_reg.final.signed.so"
    signed_final_all_reg_aex0 = out_dir / "enclave.all_reg.final.aex0.signed.so"
    ready_all_reg_bin = out_dir / "enclave.all_reg.ready.bin"
    ready_all_reg_json = out_dir / "enclave.all_reg.ready.json"

    subprocess.run([
        sys.executable, str(PRETOUCH_TOOL), "finalize",
        "--profile-elf", str(profile_elf),
        "--signed-profile-elf", str(signed_profile),
        "--workset", str(workset_all_reg),
        "--fields", str(out_dir / "fields.json"),
        "--capacity-q", str(cfg["capacity_q"]),
        "--out-elf", str(final_all_reg_elf),
        "--out-json", str(final_all_reg_json),
    ], check=True)
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(final_all_reg_elf), "-out", str(signed_final_all_reg),
        "-config", str(protect_xml),
    ], check=True)
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(final_all_reg_elf), "-out", str(signed_final_all_reg_aex0),
        "-config", str(aex0_xml),
    ], check=True)
    subprocess.run([
        sys.executable, str(PRETOUCH_TOOL), "verify",
        "--profile-elf", str(profile_elf),
        "--signed-profile-elf", str(signed_profile),
        "--final-elf", str(final_all_reg_elf),
        "--signed-final-elf", str(signed_final_all_reg),
        "--workset", str(workset_all_reg),
        "--fields", str(out_dir / "fields.json"),
        "--capacity-q", str(cfg["capacity_q"]),
        "--out-json", str(verify_all_reg_json),
    ], check=True)
    subprocess.run([
        sys.executable, str(READINESS_TOOL),
        "--workset", str(workset_all_reg),
        "--fields", str(out_dir / "fields.json"),
        "--pretouch", str(verify_all_reg_json),
        "--final-elf", str(final_all_reg_elf),
        "--signed-final-elf", str(signed_final_all_reg),
        "--out", str(ready_all_reg_bin),
        "--out-json", str(ready_all_reg_json),
    ], check=True)

    fields_data = json.loads((out_dir / "fields.json").read_text())
    ver_data = json.loads(verify_all_reg_json.read_text())
    ws_data = json.loads(workset_all_reg.read_text())
    return {
        "sample": name,
        "field_count": len(fields_data["fields"]),
        "fields": [f["function"] for f in fields_data["fields"]],
        "all_reg_pages_per_field": len(ws_data["fields"][0]["pages"]),
        "all_reg_pretouch_code_bytes": ver_data["code_bytes"],
        "capacity_q": cfg["capacity_q"],
    }


def main() -> None:
    names = sys.argv[1:] or list(TARGETS.keys())
    summaries = []
    for name in names:
        print(f"=== Building {name} ===", flush=True)
        summaries.append(build_target(name))
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
