#!/usr/bin/env python3
"""Prepare dynamic artifacts from sample build metadata and dynamic-owned scenarios."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

DYN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DYN_ROOT / "tools"))
from elf_workset import ElfFile, parse_signed_metadata, write_json  # noqa: E402
from patch_4gate import patch_elf_4gate  # noqa: E402
from target_manifest import DEFAULT_SAMPLE_ROOT, discover_real_target_manifests  # noqa: E402


def prepare_target_from_manifest(manifest: dict) -> dict:
    name = manifest["name"]
    out_dir = DYN_ROOT / "targets" / name
    scenario_path = out_dir / "scenarios.json"
    if not scenario_path.is_file():
        raise FileNotFoundError(f"Missing dynamic-owned scenarios for {name}: {scenario_path}")
    local_scenarios = json.loads(scenario_path.read_text())
    if local_scenarios != manifest.get("scenarios"):
        raise ValueError(f"Loaded scenario/oracle differs from dynamic source {scenario_path}")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Persist build metadata only; scenarios.json remains dynamic's canonical source.
    persisted_manifest = {
        key: value for key, value in manifest.items()
        if key not in {"manifest_path", "scenarios", "scenarios_json"}
    }
    write_json(out_dir / "target_manifest.json", persisted_manifest)

    # Copy authoritative artifacts already built by `sample` (`ATFIELD_MODE=protect`)
    copy_pairs = [
        ("profile_elf", "enclave.profile.so"),
        ("profile_signed_elf", "enclave.profile.signed.so"),
        ("fields_json", "fields.json"),
        ("selectors_json", "selectors.json"),
        ("protect_config_xml", "Enclave.protect.config.xml"),
        ("all_reg_workset_json", "workset.all_reg.json"),
        ("all_reg_final_elf", "enclave.all_reg.final.so"),
        ("all_reg_signed_elf", "enclave.all_reg.final.signed.so"),
        ("all_reg_unstripped_signed_elf", "enclave.all_reg.final.signed.unstripped.so"),
        ("all_reg_pretouch_finalized_json", "pretouch.all_reg.finalized.json"),
        ("all_reg_pretouch_verified_json", "pretouch.all_reg.verified.json"),
        ("all_reg_ready_bin", "enclave.all_reg.ready.bin"),
        ("all_reg_ready_json", "enclave.all_reg.ready.json"),
    ]
    for src_key, dst_name in copy_pairs:
        src_p = Path(manifest[src_key])
        if not src_p.is_file():
            raise FileNotFoundError(f"Missing sample artifact {src_key}={src_p} for {name}")
        shutil.copy2(src_p, out_dir / dst_name)

    protect_xml = out_dir / "Enclave.protect.config.xml"
    aex0_xml = out_dir / "Enclave.aex0.config.xml"
    aex0_xml.write_text(
        protect_xml.read_text().replace("<EnableAEXNotify>1</EnableAEXNotify>", "<EnableAEXNotify>0</EnableAEXNotify>")
    )

    sgx_sign = manifest["sgx_sign"]
    sign_key = manifest["signing_key_path"]
    objcopy_bin = manifest["objcopy"]
    impl_root = Path(manifest["implement_root"])
    pretouch_tool = str(impl_root / "build" / "pretouch" / "pretouch.ts")
    readiness_tool = str(impl_root / "build" / "readiness" / "readiness.ts")
    capacity_q = int(manifest["protect_q"])

    profile_elf = out_dir / "enclave.profile.so"
    signed_profile = out_dir / "enclave.profile.signed.so"
    signed_profile_aex0 = out_dir / "enclave.profile.aex0.signed.so"
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(profile_elf), "-out", str(signed_profile_aex0), "-config", str(aex0_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    fields_file = out_dir / "fields.json"
    profile_4gate_elf = out_dir / "enclave.profile.4gate.so"
    profile_4gate_signed_aex0 = out_dir / "enclave.profile.4gate.aex0.signed.so"
    patch_elf_4gate(profile_elf, fields_file, capacity_q, profile_4gate_elf, out_dir / "enclave.profile.4gate.json")
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(profile_4gate_elf), "-out", str(profile_4gate_signed_aex0), "-config", str(aex0_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    all_reg_final = out_dir / "enclave.all_reg.final.so"
    all_reg_signed_aex0 = out_dir / "enclave.all_reg.final.aex0.signed.so"
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(all_reg_final), "-out", str(all_reg_signed_aex0), "-config", str(aex0_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    all_reg_4gate_elf = out_dir / "enclave.all_reg.4gate.so"
    all_reg_4gate_signed_aex0 = out_dir / "enclave.all_reg.4gate.aex0.signed.so"
    patch_elf_4gate(all_reg_final, fields_file, capacity_q, all_reg_4gate_elf, out_dir / "enclave.all_reg.4gate.json")
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(all_reg_4gate_elf), "-out", str(all_reg_4gate_signed_aex0), "-config", str(aex0_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    # Also build Group A (all_reg_xr: All-REG with RX pages kept as XR)
    ws_all_reg = json.loads((out_dir / "workset.all_reg.json").read_text())
    ws_all_reg_xr = json.loads(json.dumps(ws_all_reg))
    for f in ws_all_reg_xr.get("fields", []):
        for pg in f.get("pages", []):
            if (pg.get("max_permissions", 0) & 5) == 5 and "R" not in pg.get("effects", []):
                pg["effects"] = ["X", "R"]
    ws_xr_file = out_dir / "workset.all_reg_xr.json"
    write_json(ws_xr_file, ws_all_reg_xr)

    xr_final = out_dir / "enclave.all_reg_xr.final.so"
    xr_finalized = out_dir / "pretouch.all_reg_xr.finalized.json"
    xr_verified = out_dir / "pretouch.all_reg_xr.verified.json"
    xr_signed_unstripped = out_dir / "enclave.all_reg_xr.final.signed.unstripped.so"
    xr_signed_aex1 = out_dir / "enclave.all_reg_xr.final.signed.so"
    xr_signed_aex0 = out_dir / "enclave.all_reg_xr.final.aex0.signed.so"
    xr_ready_bin = out_dir / "enclave.all_reg_xr.ready.bin"
    xr_ready_json = out_dir / "enclave.all_reg_xr.ready.json"

    subprocess.run(
        [
            pretouch_tool, "finalize",
            "--profile-elf", str(profile_elf),
            "--signed-profile-elf", str(signed_profile),
            "--workset", str(ws_xr_file),
            "--fields", str(fields_file),
            "--capacity-q", str(capacity_q),
            "--out-elf", str(xr_final),
            "--out-json", str(xr_finalized),
        ],
        check=True,
    )
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(xr_final), "-out", str(xr_signed_unstripped), "-config", str(protect_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(xr_final), "-out", str(xr_signed_aex0), "-config", str(aex0_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [objcopy_bin, "--strip-all", "--keep-section=.note.sgxmeta", str(xr_signed_unstripped), str(xr_signed_aex1)],
        check=True,
    )
    subprocess.run(
        [
            pretouch_tool, "verify",
            "--profile-elf", str(profile_elf),
            "--signed-profile-elf", str(signed_profile),
            "--final-elf", str(xr_final),
            "--signed-final-elf", str(xr_signed_aex1),
            "--workset", str(ws_xr_file),
            "--fields", str(fields_file),
            "--capacity-q", str(capacity_q),
            "--out-json", str(xr_verified),
        ],
        check=True,
    )
    subprocess.run(
        [
            readiness_tool,
            "--workset", str(ws_xr_file),
            "--fields", str(fields_file),
            "--pretouch", str(xr_verified),
            "--final-elf", str(xr_final),
            "--signed-final-elf", str(xr_signed_aex1),
            "--out", str(xr_ready_bin),
            "--out-json", str(xr_ready_json),
        ],
        check=True,
    )
    xr_4gate_elf = out_dir / "enclave.all_reg_xr.4gate.so"
    xr_4gate_signed_aex0 = out_dir / "enclave.all_reg_xr.4gate.aex0.signed.so"
    patch_elf_4gate(xr_final, fields_file, capacity_q, xr_4gate_elf, out_dir / "enclave.all_reg_xr.4gate.json")
    subprocess.run(
        [sgx_sign, "sign", "-key", sign_key, "-enclave", str(xr_4gate_elf), "-out", str(xr_4gate_signed_aex0), "-config", str(aex0_xml)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    # signer_layout.json is ws_all_reg["layout"]
    write_json(out_dir / "signer_layout.json", ws_all_reg["layout"])
    return {
        "name": name,
        "fields": len(ws_all_reg["fields"]),
        "all_reg_pages": len(ws_all_reg["fields"][0]["pages"]),
        "post_start": hex(ws_all_reg["layout"]["pretouch_start"]),
        "capacity_q": ws_all_reg["layout"]["capacity_q"],
    }


def _prefer_current_sample_manifests(requests: list[str]) -> list[str | Path]:
    """Resolve target names to current sample build manifests, never old dynamic snapshots."""
    resolved: list[str | Path] = []
    for request in requests:
        if Path(request).is_file():
            resolved.append(request)
            continue
        sample_manifest = (
            DEFAULT_SAMPLE_ROOT / "build" / "real" / request / "protect" / "target_manifest.json"
        )
        if not sample_manifest.is_file():
            raise FileNotFoundError(
                f"Cannot rebuild {request!r} without current sample build metadata: {sample_manifest}"
            )
        resolved.append(sample_manifest)
    return resolved


def main() -> None:
    manifests = discover_real_target_manifests(_prefer_current_sample_manifests(sys.argv[1:]))
    summary = {}
    for m in manifests:
        name = m["name"]
        print(f"=== Preparing {name} from {m['manifest_path']} ===", flush=True)
        summary[name] = prepare_target_from_manifest(m)
        print(f"Prepared {name}: {summary[name]}", flush=True)


if __name__ == "__main__":
    main()
