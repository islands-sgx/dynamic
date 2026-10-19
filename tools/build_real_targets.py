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
IMPL_BUNDLE = Path("/nix/store/6vyb98yh62as89qwndd4drgh7baxcw54-atfield-implement-bundle")
VENDOR_IMPL = IMPL_BUNDLE
COMPILE_WRAPPER = IMPL_BUNDLE / "build" / "codegen" / "compile-ir-object.ts"
FIELD_TOOL = IMPL_BUNDLE / "bin" / "atfield-field"
PRETOUCH_TOOL = IMPL_BUNDLE / "build" / "pretouch" / "pretouch.ts"
POST_LD = IMPL_BUNDLE / "build" / "pretouch" / "post-rx-segment.ld"
PROFILE_LINK = IMPL_BUNDLE / "cli" / "profile-link.ts"
PROTECT_CONFIG = IMPL_BUNDLE / "cli" / "protect-config.ts"
WORKSET_TOOL = IMPL_BUNDLE / "build" / "workset" / "workset.ts"
READINESS_TOOL = IMPL_BUNDLE / "build" / "readiness" / "readiness.ts"

LLC_BIN = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llc"
OBJCOPY_BIN = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llvm-objcopy"
SGX_SDK_ROOT = "/nix/store/w9361i2a8728720ll02ypv9nbbfzw5pj-sgx-sdk-2.29.100.1"
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
    "ehsm-opt-1": {
        "edl": "enclave_hsm.edl",
        "heap": 0x400000,
        "stack": 0x40000,
        "capacity_q": 94208,
        "upstream_pkg": "ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-1-clang",
        "upstream_root": "/nix/store/zd3wnkf5a9rl27ai52kr6ws9k2k80228-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-1-clang",
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
    "ehsm-opt-2": {
        "edl": "enclave_hsm.edl",
        "heap": 0x400000,
        "stack": 0x40000,
        "capacity_q": 94208,
        "upstream_pkg": "ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-2-clang",
        "upstream_root": "/nix/store/bz93f9hr99lpgdyr032qrsfxyi6zj6qj-ehsm-d87fb4884a32b9ecaecb5e7d45a25482344f21b3-opt-2-clang",
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
        str(PROTECT_CONFIG),
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
        str(WORKSET_TOOL),
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
        str(PRETOUCH_TOOL), "finalize",
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
        str(PRETOUCH_TOOL), "verify",
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
        str(READINESS_TOOL),
        "--workset", str(workset_all_reg),
        "--fields", str(out_dir / "fields.json"),
        "--pretouch", str(verify_all_reg_json),
        "--final-elf", str(final_all_reg_elf),
        "--signed-final-elf", str(signed_final_all_reg),
        "--out", str(ready_all_reg_bin),
        "--out-json", str(ready_all_reg_json),
    ], check=True)

    for prefix, in_elf in (("profile", profile_elf), ("all_reg", final_all_reg_elf)):
        subprocess.run([
            sys.executable, str(DYN_ROOT / "tools" / "patch_4gate.py"),
            "--input-elf", str(in_elf),
            "--fields", str(out_dir / "fields.json"),
            "--capacity-q", str(cfg["capacity_q"]),
            "--config-xml", str(aex0_xml),
            "--out-elf", str(out_dir / f"enclave.{prefix}.4gate.so"),
            "--out-signed-elf", str(out_dir / f"enclave.{prefix}.4gate.aex0.signed.so"),
            "--out-json", str(out_dir / f"enclave.{prefix}.4gate.json"),
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



def load_challenge_targets() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for cdir in sorted((DYN_ROOT / "challenges").glob("challenge-*")):
        cfg_file = cdir / "challenge_config.json"
        if cfg_file.is_file():
            cfg = json.loads(cfg_file.read_text())
            cfg["src_dir"] = cdir
            out[cdir.name] = cfg
    return out


CHALLENGE_TARGETS = load_challenge_targets()


def build_challenge_target(name: str) -> dict:
    cfg = load_challenge_targets()[name]
    src_dir = cfg["src_dir"]
    out_dir = DYN_ROOT / "targets" / name
    obj_dir = out_dir / "obj"
    edl_dir = out_dir / "edl_gen"
    out_dir.mkdir(parents=True, exist_ok=True)
    obj_dir.mkdir(parents=True, exist_ok=True)
    edl_dir.mkdir(parents=True, exist_ok=True)

    edl_file = src_dir / cfg["edl"]
    stem = cfg["edl_stem"]
    subprocess.run([
        f"{SGX_SDK_ROOT}/bin/x64/sgx_edger8r",
        "--trusted", str(edl_file),
        "--trusted-dir", str(edl_dir),
        "--untrusted", str(edl_file),
        "--untrusted-dir", str(edl_dir),
        "--search-path", f"{SGX_SDK_ROOT}/include",
    ], check=True)

    cc_bin = "/nix/store/fys2jh0y4iisx69yf73b3z8k048cqx95-llvm-atfield-llc-wrapper-22.1.8/bin/cc"
    psw_lib = "/nix/store/a1fx7mb2366qs2i5bd9mci3nis495wcb-sgx-psw-2.29.100.1/lib64"
    tlib_dir = "/nix/store/swyss2hhip1fciv6fn5y3iza6rr0dkps-sgx-trusted-libs-anchor-2.29.100.1/lib"

    env = os.environ.copy()
    env.update({
        "ATFIELD_ANCHOR_PREPARATION": "1",
        "ATFIELD_FIELD_BOUNDARY": "1",
        "ATFIELD_IMPLEMENT_ROOT": str(VENDOR_IMPL),
        "ATFIELD_PAYLOAD_NAMESPACE": f"challenges/{name}",
        "ATFIELD_SOURCE_ROOT": str(src_dir),
        "ATFIELD_LLC": LLC_BIN,
        "ATFIELD_FIELD_TOOL": str(FIELD_TOOL),
        "ATFIELD_UPSTREAM_SOURCE_ROOT": str(src_dir),
        "ATFIELD_UPSTREAM_PACKAGE": name,
    })

    common_t_flags = [
        "-m64", "-O2", "-fPIC", "-nostdinc",
        f"-I{edl_dir}",
        f"-I{src_dir}",
        f"-I{SGX_SDK_ROOT}/include",
        f"-I{SGX_SDK_ROOT}/include/tlibc",
    ]
    t_obj = obj_dir / f"{stem}_t.o"
    e_obj = obj_dir / "enclave.o"
    subprocess.run([str(COMPILE_WRAPPER), cc_bin, *common_t_flags, "-c", str(edl_dir / f"{stem}_t.c"), "-o", str(t_obj)], env=env, check=True)
    subprocess.run([str(COMPILE_WRAPPER), cc_bin, *common_t_flags, "-c", str(src_dir / "enclave.c"), "-o", str(e_obj)], env=env, check=True)

    profile_elf = out_dir / "enclave.profile.so"
    link_tail = [
        "-fuse-ld=/nix/store/fv53kz6bwf3bkpj4qini6cfq5njl4xvn-lld-22.1.8/bin/ld.lld",
        "-Wl,-z,relro,-z,now,-z,noexecstack",
        "-Wl,--fatal-warnings", "-Wl,--as-needed", "-Wl,--no-undefined", "-Wl,--no-undefined-version",
        "-nostdlib", "-nodefaultlibs", "-nostartfiles",
        "-Wl,-Bstatic", "-Wl,-Bsymbolic", "-Wl,-pie,-eenclave_entry",
        "-Wl,--export-dynamic", "-Wl,--defsym,__ImageBase=0", "-Wl,--gc-sections",
        f"-Wl,--version-script={SAMPLE_ROOT / 'cmake' / 'Enclave.lds'}",
        "-Wl,--whole-archive", f"{tlib_dir}/libsgx_trts.a", "-Wl,--no-whole-archive",
        "-Wl,--start-group",
        f"{tlib_dir}/libsgx_tstdc.a",
        f"{tlib_dir}/libsgx_tcxx.a",
        f"{tlib_dir}/libsgx_tcrypto.a",
        f"{tlib_dir}/libsgx_tservice.a",
        "-Wl,--end-group",
    ]
    subprocess.run([
        str(PROFILE_LINK),
        "--field-tool", str(FIELD_TOOL),
        "--pretouch-tool", str(PRETOUCH_TOOL),
        "--capacity-q", str(cfg["capacity_q"]),
        "--assembler", cc_bin,
        "--linker-script", str(POST_LD),
        "--",
        cc_bin,
        str(t_obj), str(e_obj),
        *link_tail,
        "-o", str(profile_elf),
    ], cwd=out_dir, check=True)

    # Build untrusted host binary into out_dir / "host"
    host_bin = out_dir / "host"
    subprocess.run([
        cc_bin, "-m64", "-O2", "-fPIC",
        f'-DENCLAVE_PATH="{out_dir / "enclave.profile.aex0.signed.so"}"',
        f"-I{edl_dir}", f"-I{SGX_SDK_ROOT}/include",
        str(src_dir / "host.c"), str(edl_dir / f"{stem}_u.c"),
        f"-L{psw_lib}", "-lsgx_urts", "-lpthread", "-ldl",
        "-o", str(host_bin),
    ], check=True)

    base_xml = SAMPLE_ROOT / "real" / "signal-cds" / "Enclave.config.xml" 
    protect_xml = out_dir / "Enclave.protect.config.xml"
    aex0_xml = out_dir / "Enclave.aex0.config.xml"
    subprocess.run([
        str(PROTECT_CONFIG), str(base_xml), str(protect_xml),
        "--heap", hex(cfg["heap"]), "--stack", hex(cfg["stack"]),
    ], check=True)
    aex0_xml.write_text(protect_xml.read_text().replace("<EnableAEXNotify>1</EnableAEXNotify>", "<EnableAEXNotify>0</EnableAEXNotify>"))

    signed_profile = out_dir / "enclave.profile.signed.so"
    signed_profile_aex0 = out_dir / "enclave.profile.aex0.signed.so"
    subprocess.run([SGX_SIGN, "sign", "-key", SIGN_KEY, "-enclave", str(profile_elf), "-out", str(signed_profile), "-config", str(protect_xml)], check=True)
    subprocess.run([SGX_SIGN, "sign", "-key", SIGN_KEY, "-enclave", str(profile_elf), "-out", str(signed_profile_aex0), "-config", str(aex0_xml)], check=True)

    selectors_json = out_dir / "selectors.json"
    selectors_json.write_text(json.dumps({"schema": "atfield-selectors-v1", "selectors": cfg["selectors"]}, indent=2) + "\n")

    workset_all_reg = out_dir / "workset.all_reg.json"
    layout_json = out_dir / "signer_layout.json"
    subprocess.run([
        str(WORKSET_TOOL),
        "--profile-elf", str(profile_elf),
        "--signed-elf", str(signed_profile),
        "--fields", str(out_dir / "fields.json"),
        "--selectors", str(selectors_json),
        "--edl", str(edl_file),
        "--capacity-q", str(cfg["capacity_q"]),
        "--out", str(workset_all_reg),
        "--layout-out", str(layout_json),
    ], check=True)

    final_all_reg_elf = out_dir / "enclave.all_reg.final.so"
    final_all_reg_json = out_dir / "pretouch.all_reg.finalized.json"
    verify_all_reg_json = out_dir / "pretouch.all_reg.verified.json"
    signed_final_all_reg = out_dir / "enclave.all_reg.final.signed.so"
    signed_final_all_reg_aex0 = out_dir / "enclave.all_reg.final.aex0.signed.so"
    ready_all_reg_bin = out_dir / "enclave.all_reg.ready.bin"
    ready_all_reg_json = out_dir / "enclave.all_reg.ready.json"

    subprocess.run([
        str(PRETOUCH_TOOL), "finalize",
        "--profile-elf", str(profile_elf),
        "--signed-profile-elf", str(signed_profile),
        "--workset", str(workset_all_reg),
        "--fields", str(out_dir / "fields.json"),
        "--capacity-q", str(cfg["capacity_q"]),
        "--out-elf", str(final_all_reg_elf),
        "--out-json", str(final_all_reg_json),
    ], check=True)
    subprocess.run([SGX_SIGN, "sign", "-key", SIGN_KEY, "-enclave", str(final_all_reg_elf), "-out", str(signed_final_all_reg), "-config", str(protect_xml)], check=True)
    subprocess.run([SGX_SIGN, "sign", "-key", SIGN_KEY, "-enclave", str(final_all_reg_elf), "-out", str(signed_final_all_reg_aex0), "-config", str(aex0_xml)], check=True)
    subprocess.run([
        str(PRETOUCH_TOOL), "verify",
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
        str(READINESS_TOOL),
        "--workset", str(workset_all_reg),
        "--fields", str(out_dir / "fields.json"),
        "--pretouch", str(verify_all_reg_json),
        "--final-elf", str(final_all_reg_elf),
        "--signed-final-elf", str(signed_final_all_reg),
        "--out", str(ready_all_reg_bin),
        "--out-json", str(ready_all_reg_json),
    ], check=True)
    for prefix, in_elf in (("profile", profile_elf), ("all_reg", final_all_reg_elf)):
        subprocess.run([
            sys.executable, str(DYN_ROOT / "tools" / "patch_4gate.py"),
            "--input-elf", str(in_elf),
            "--fields", str(out_dir / "fields.json"),
            "--capacity-q", str(cfg["capacity_q"]),
            "--config-xml", str(aex0_xml),
            "--out-elf", str(out_dir / f"enclave.{prefix}.4gate.so"),
            "--out-signed-elf", str(out_dir / f"enclave.{prefix}.4gate.aex0.signed.so"),
            "--out-json", str(out_dir / f"enclave.{prefix}.4gate.json"),
        ], check=True)

    ws_data = json.loads(workset_all_reg.read_text())
    return {
        "sample": name,
        "field_count": len(ws_data["fields"]),
        "all_reg_pages_per_field": len(ws_data["fields"][0]["pages"]),
    }


def main() -> None:
    names = sys.argv[1:] or (list(TARGETS.keys()) + list(load_challenge_targets().keys()))
    summaries = []
    for name in names:
        print(f"=== Building {name} ===", flush=True)
        if name in load_challenge_targets():
            summaries.append(build_challenge_target(name))
        else:
            summaries.append(build_target(name))
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
