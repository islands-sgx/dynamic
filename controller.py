#!/usr/bin/env python3
"""ATField-SGX Dynamic Workset Explorer, 4-Layer Attribution Ledger, and Heuristic Assist Builder."""
from __future__ import annotations

import bisect
import json
import re
import subprocess
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
IMPL_BUNDLE = Path("/nix/store/6vyb98yh62as89qwndd4drgh7baxcw54-atfield-implement-bundle")
sys.path.insert(0, str(DYN_ROOT / "tools"))

from elf_workset import (  # noqa: E402
    PAGE,
    SI_FLAG_W,
    ElfFile,
    align_down,
    align_up,
    effects_for_permissions,
    normalized_fields,
    parse_anchor_symbols,
    resolve_selectors,
    write_json,
)
from generic_explorer import (  # noqa: E402
    AUDIT_OF_LEGACY_HEURISTICS,
    build_scale_bound_v2_spec,
    evaluate_challenge_suite,
    generate_schema_mutations_for_ecall,
    get_scalable_bound_offsets,
    round_robin_schedule_interventions,
    run_real_hardware_challenge_ablation,
    structural_behavior_signature,
)
from run_native_sgx import INTERPOSE_SO, run_sample, sha256_file  # noqa: E402

LLVM_OBJDUMP = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llvm-objdump"
SGX_SIGN = "/nix/store/w9361i2a8728720ll02ypv9nbbfzw5pj-sgx-sdk-2.29.100.1/bin/x64/sgx_sign"
SIGN_KEY = "/home/meandssh/islands-sgx/sample/build/test-signing-key.pem"
PRETOUCH_TOOL = IMPL_BUNDLE / "build" / "pretouch" / "pretouch.ts"
READINESS_TOOL = IMPL_BUNDLE / "build" / "readiness" / "readiness.ts"
PATCH_4GATE_TOOL = DYN_ROOT / "tools" / "patch_4gate.py"


def parse_disasm_graph(elf_path: Path, elf: ElfFile) -> dict:
    syms = [
        s for s in elf.symbols()
        if s["shndx"] != 0 and (s["info"] & 0xF) == 2 and s["value"] > 0
    ]
    syms.sort(key=lambda s: (s["value"], -s["size"]))
    func_starts = []
    func_by_start = {}
    for s in syms:
        if s["value"] not in func_by_start:
            func_starts.append(s["value"])
            func_by_start[s["value"]] = {
                "name": s["name"],
                "start": s["value"],
                "end": s["value"] + max(s["size"], 1),
                "callees": set(),
                "rip_refs": set(),
                "indirect_branches": [],
            }

    def owner_func(rva: int) -> int | None:
        idx = bisect.bisect_right(func_starts, rva) - 1
        if idx < 0:
            return None
        fstart = func_starts[idx]
        finfo = func_by_start[fstart]
        if rva < finfo["end"] + 64:
            return fstart
        return None

    txt = subprocess.check_output(
        [LLVM_OBJDUMP, "-d", "--no-show-raw-insn", str(elf_path)],
        text=True,
    )
    for line in txt.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s+(.*)$", line)
        if not m:
            continue
        insn_rva = int(m.group(1), 16)
        mnemonic = m.group(2)
        ops = m.group(3)
        fstart = owner_func(insn_rva)
        if fstart is None:
            continue
        finfo = func_by_start[fstart]
        if mnemonic.startswith(("call", "jmp", "j")):
            if "*" in ops:
                finfo["indirect_branches"].append({"insn_rva": hex(insn_rva), "mnemonic": mnemonic, "ops": ops.strip()})
            else:
                tm = re.search(r"\b0x([0-9a-f]+)\s*<", ops)
                if tm:
                    target = int(tm.group(1), 16)
                    t_owner = owner_func(target)
                    if t_owner is not None:
                        finfo["callees"].add(t_owner)
        else:
            rm = re.search(r"#\s*0x([0-9a-f]+)", ops)
            if rm:
                ref_rva = int(rm.group(1), 16)
                finfo["rip_refs"].add(ref_rva)

    return {"func_starts": func_starts, "func_by_start": func_by_start}


def build_committed_page_map(layout: dict) -> dict[int, dict]:
    page_permissions: dict[int, int] = {}
    page_origins: dict[int, list[str]] = {}
    for region in layout["regions"]:
        for page in range(region["start_rva"], region["end_rva"], PAGE):
            page_permissions[page] = page_permissions.get(page, 0) | region["permissions"]
            origin = region["name"] if region["kind"] == "signer" else f"PT_LOAD[{region['segment_index']}]"
            page_origins.setdefault(page, []).append(origin)
    relro_pages = set(layout.get("relro_pages", []))
    out: dict[int, dict] = {}
    for page in sorted(page_permissions):
        max_perm = page_permissions[page]
        perm = max_perm & ~SI_FLAG_W if page in relro_pages else max_perm
        effects = effects_for_permissions(perm, f"page {page:#x}")
        out[page] = {
            "page_rva": page,
            "effects": effects,
            "max_permissions": max_perm,
            "relro": page in relro_pages,
            "origins": sorted(set(page_origins[page])),
        }
    return out


def emit_and_sign_variant(
    tdir: Path,
    variant_name: str,
    workset_path: Path,
    cap_q: int,
) -> dict:
    final_elf = tdir / f"enclave.{variant_name}.final.so"
    final_json = tdir / f"pretouch.{variant_name}.finalized.json"
    verify_json = tdir / f"pretouch.{variant_name}.verified.json"
    signed_aex1 = tdir / f"enclave.{variant_name}.final.signed.so"
    signed_aex0 = tdir / f"enclave.{variant_name}.final.aex0.signed.so"
    ready_bin = tdir / f"enclave.{variant_name}.ready.bin"
    ready_json = tdir / f"enclave.{variant_name}.ready.json"
    gate_elf = tdir / f"enclave.{variant_name}.4gate.so"
    gate_signed = tdir / f"enclave.{variant_name}.4gate.aex0.signed.so"
    gate_json = tdir / f"enclave.{variant_name}.4gate.json"

    subprocess.run([
        str(PRETOUCH_TOOL), "finalize",
        "--profile-elf", str(tdir / "enclave.profile.so"),
        "--signed-profile-elf", str(tdir / "enclave.profile.signed.so"),
        "--workset", str(workset_path),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--out-elf", str(final_elf),
        "--out-json", str(final_json),
    ], check=True)
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(final_elf), "-out", str(signed_aex1),
        "-config", str(tdir / "Enclave.protect.config.xml"),
    ], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(final_elf), "-out", str(signed_aex0),
        "-config", str(tdir / "Enclave.aex0.config.xml"),
    ], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([
        str(PRETOUCH_TOOL), "verify",
        "--profile-elf", str(tdir / "enclave.profile.so"),
        "--signed-profile-elf", str(tdir / "enclave.profile.signed.so"),
        "--final-elf", str(final_elf),
        "--signed-final-elf", str(signed_aex1),
        "--workset", str(workset_path),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--out-json", str(verify_json),
    ], check=True)
    subprocess.run([
        str(READINESS_TOOL),
        "--workset", str(workset_path),
        "--fields", str(tdir / "fields.json"),
        "--pretouch", str(verify_json),
        "--final-elf", str(final_elf),
        "--signed-final-elf", str(signed_aex1),
        "--out", str(ready_bin),
        "--out-json", str(ready_json),
    ], check=True)
    subprocess.run([
        sys.executable, str(PATCH_4GATE_TOOL),
        "--input-elf", str(final_elf),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--config-xml", str(tdir / "Enclave.aex0.config.xml"),
        "--out-elf", str(gate_elf),
        "--out-signed-elf", str(gate_signed),
        "--out-json", str(gate_json),
    ], check=True)
    return {
        "variant": variant_name,
        "workset_sha256": sha256_file(workset_path),
        "final_elf_sha256": sha256_file(final_elf),
        "signed_aex1_sha256": sha256_file(signed_aex1),
        "signed_aex0_sha256": sha256_file(signed_aex0),
        "gate_aex0_sha256": sha256_file(gate_signed),
        "ready_bin_sha256": sha256_file(ready_bin),
    }


def explore_and_close_sample(sample: str) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    wdir = DYN_ROOT / "witnesses" / sample
    dump_dir = wdir / "dumps"
    raw_trace_dir = DYN_ROOT / "experiments" / "raw_traces" / sample
    wdir.mkdir(parents=True, exist_ok=True)
    dump_dir.mkdir(parents=True, exist_ok=True)
    raw_trace_dir.mkdir(parents=True, exist_ok=True)

    profile_elf = ElfFile(tdir / "enclave.profile.so")
    layout = json.loads((tdir / "signer_layout.json").read_text())
    fields = normalized_fields(tdir / "fields.json")
    edl_schema = json.loads((tdir / "edl_schema.json").read_text())
    edl_path = Path(edl_schema["edl_path"])
    selectors = resolve_selectors(tdir / "selectors.json", fields, edl_path)
    committed_map = build_committed_page_map(layout)
    anchors = parse_anchor_symbols(profile_elf)

    stack_pages = sorted(p for p, info in committed_map.items() if any(o.startswith("STACK") for o in info["origins"]))
    heap_pages = sorted(p for p, info in committed_map.items() if any(o.startswith("HEAP") for o in info["origins"]))
    td_pages = sorted(p for p, info in committed_map.items() if any(o.startswith("TD") for o in info["origins"]))

    field_ids = [f"0x{f['_id_value']:016x}" for f in fields]
    interpose_hash = sha256_file(INTERPOSE_SO)

    layer_sets: dict[str, dict[str, set[tuple[int, str]]]] = {
        "layer0_first_call": {fid: set() for fid in field_ids},
        "layer1_full_host": {fid: set() for fid in field_ids},
        "layer2_generic_schema": {fid: set() for fid in field_ids},
        "layer3_domain_assist": {fid: set() for fid in field_ids},
    }
    layer2_seed_only: dict[str, set[tuple[int, str]]] = {fid: set() for fid in field_ids}
    cumulative_effects: dict[str, set[tuple[int, str]]] = {fid: set() for fid in field_ids}
    dyn_obs_pages: dict[str, dict[int, str]] = {fid: {} for fid in field_ids}
    dyn_bridge_pages: dict[str, set[int]] = {fid: set() for fid in field_ids}
    dyn_chunks: dict[str, list[tuple[int, int]]] = {fid: [] for fid in field_ids}
    dyn_rsps: dict[str, list[int]] = {fid: [] for fid in field_ids}
    heap_truncated_runs = 0
    heap_pread_fail_runs = 0

    field_call_stats = {
        fid: {
            "field_entries": 0,
            "transport_ok_entries": 0,
            "abi_zero_return_entries": 0,
            "abi_nonzero_return_entries": 0,
            "abi_void_return_entries": 0,
            "transport_error_entries": 0,
        }
        for fid in field_ids
    }
    ecall_stats: dict[int, dict] = {}
    witness_ledger = []
    run_summaries = []
    feedback_trace = []

    def ingest_run(plan: dict, res: dict, is_baseline_host: bool = False, is_seed_isolated: bool = False) -> int:
        nonlocal heap_truncated_runs, heap_pread_fail_runs
        if res["interpose_sha256"] != interpose_hash:
            raise RuntimeError(f"Interpose hash changed during exploration of {sample}")
        if res["measurement_invalid"]:
            raise RuntimeError(f"Discovery run {plan['run_id']} on {sample} has measurement_invalid=True")
        if res["returncode"] != 0 and not plan.get("allow_nonzero_rc", False):
            raise RuntimeError(f"Discovery run {plan['run_id']} on {sample} exited with rc={res['returncode']}")

        run_new_effects = 0
        for rec in res["records"]:
            if rec.get("measurement_invalid", 0) != 0:
                raise RuntimeError(f"Invalid record in {plan['run_id']}: {rec.get('invalid_reason')}")
            ec_idx = rec["ecall_index"]
            est = ecall_stats.setdefault(ec_idx, {
                "ecall_invocations": 0,
                "field_entering_calls": 0,
                "outer_non_field_calls": 0,
                "abi_return_type": rec.get("abi_return_type", "scalar"),
                "abi_zero_return_calls": 0,
                "abi_nonzero_return_calls": 0,
                "abi_void_calls": 0,
                "out_status_zero_calls": 0,
                "out_status_nonzero_calls": 0,
                "transport_error_calls": 0,
            })
            est["ecall_invocations"] += 1
            if rec["fields"]:
                est["field_entering_calls"] += 1
            else:
                est["outer_non_field_calls"] += 1
            if rec["sgx_status"] != 0:
                est["transport_error_calls"] += 1
            elif rec.get("abi_return_type") == "void":
                est["abi_void_calls"] += 1
                if rec.get("has_out_status_i32"):
                    if rec.get("out_status_i32") == 0:
                        est["out_status_zero_calls"] += 1
                    else:
                        est["out_status_nonzero_calls"] += 1
            elif rec.get("ms_retval") == 0:
                est["abi_zero_return_calls"] += 1
            else:
                est["abi_nonzero_return_calls"] += 1

            for fobs in rec["fields"]:
                fid = fobs["field_id"]
                if fid not in dyn_obs_pages:
                    continue
                fstat = field_call_stats[fid]
                fstat["field_entries"] += 1
                if rec["sgx_status"] != 0:
                    fstat["transport_error_entries"] += 1
                else:
                    fstat["transport_ok_entries"] += 1
                    if rec.get("abi_return_type") == "void":
                        fstat["abi_void_return_entries"] += 1
                    elif rec.get("ms_retval") == 0:
                        fstat["abi_zero_return_entries"] += 1
                    else:
                        fstat["abi_nonzero_return_entries"] += 1

                if fobs.get("heap_walk_truncated", 0):
                    heap_truncated_runs += 1
                if fobs.get("heap_pread_failures", 0):
                    heap_pread_fail_runs += 1

                for item in fobs["s0"] + fobs["s1"] + rec.get("ecall_ad", []):
                    rva = int(item["rva"], 16)
                    if rva in committed_map:
                        dyn_bridge_pages[fid].add(rva)

                is_first_entry = len(layer_sets["layer0_first_call"][fid]) == 0
                eff_pairs_this_call: set[tuple[int, str]] = set()
                for item in fobs["s3"]:
                    rva = int(item["rva"], 16)
                    ad = item["ad"]
                    if rva not in committed_map:
                        continue
                    eff_pairs_this_call.add((rva, "A"))
                    if ad == "D":
                        eff_pairs_this_call.add((rva, "D"))

                if is_baseline_host:
                    if is_first_entry:
                        layer_sets["layer0_first_call"][fid].update(eff_pairs_this_call)
                    layer_sets["layer1_full_host"][fid].update(eff_pairs_this_call)
                else:
                    layer_sets[plan["layer"]][fid].update(eff_pairs_this_call)
                    if is_seed_isolated:
                        layer2_seed_only[fid].update(eff_pairs_this_call)

                newly_discovered_effects = []
                for rva, eff in sorted(eff_pairs_this_call):
                    if (rva, eff) not in cumulative_effects[fid]:
                        had_a_before = (rva, "A") in cumulative_effects[fid]
                        cumulative_effects[fid].add((rva, eff))
                        newly_discovered_effects.append({
                            "rva": hex(rva),
                            "effect": eff,
                            "upgrade_from_A_to_D": bool(eff == "D" and had_a_before),
                        })
                        run_new_effects += 1
                    prev_ad = dyn_obs_pages[fid].get(rva)
                    if prev_ad is None or (prev_ad == "A" and eff == "D"):
                        dyn_obs_pages[fid][rva] = eff

                for lo_s, hi_s in fobs.get("chunks", []):
                    dyn_chunks[fid].append((int(lo_s, 16), int(hi_s, 16)))
                for rk in ("gateB_rsp_rva", "gateD_rsp_rva"):
                    rv = int(fobs.get(rk, "0x0"), 16)
                    if rv > 0:
                        dyn_rsps[fid].append(rv)

                if newly_discovered_effects:
                    actual_layer = "layer0_first_call" if (is_baseline_host and is_first_entry) else plan["layer"]
                    witness_ledger.append({
                        "witness_id": f"{sample}_{plan['run_id']}_seq{rec['call_seq']}_{fid[-6:]}",
                        "layer": actual_layer,
                        "run_id": plan["run_id"],
                        "subkind": plan["subkind"],
                        "trace_file": str((raw_trace_dir / plan["run_id"]).with_suffix(".jsonl")),
                        "trace_sha256": res["trace_sha256"],
                        "enclave_sha256": res["enclave_sha256"],
                        "interpose_sha256": res["interpose_sha256"],
                        "measurement_invalid": rec.get("measurement_invalid", 0),
                        "returncode": res["returncode"],
                        "call_seq": rec["call_seq"],
                        "ecall_index": rec["ecall_index"],
                        "selector_seq": rec["selector_seq"],
                        "tag": rec["tag"],
                        "intervention": plan["intervention"],
                        "field_id": fid,
                        "new_effects": newly_discovered_effects,
                        "total_field_obs_pages": len(dyn_obs_pages[fid]),
                        "total_field_obs_effects": len(cumulative_effects[fid]),
                        "tsc_s3": fobs["tsc_s3"],
                    })

        run_summaries.append({
            "run_id": plan["run_id"],
            "layer": plan["layer"],
            "subkind": plan["subkind"],
            "description": plan["desc"],
            "trace_jsonl": str((raw_trace_dir / plan["run_id"]).with_suffix(".jsonl")),
            "trace_sha256": res["trace_sha256"],
            "interpose_sha256": res["interpose_sha256"],
            "returncode": res["returncode"],
            "records_collected": len(res["records"]),
            "measurement_invalid": res["measurement_invalid"],
            "new_page_effects_discovered": run_new_effects,
        })
        return run_new_effects

    # Step A: Layer 0 + Layer 1 (Unmodified full host workflow, all calls measured, 0 skipped)
    p0 = {
        "run_id": "layer0_and_layer1_unmodified_host",
        "layer": "layer1_full_host",
        "subkind": "unmodified_host_full_trace",
        "intervention": "",
        "desc": "Unmodified host binary full execution (first entry per Field = Layer 0; full run = Layer 1)",
    }
    res0 = run_sample(
        sample,
        mode="profile_4gate",
        ipi_mask=7,
        allow_fast_forward=0,
        dump_dir=str(dump_dir),
        persist_prefix=raw_trace_dir / p0["run_id"],
    )
    ingest_run(p0, res0, is_baseline_host=True, is_seed_isolated=False)

    # Identify from the L1 seed trace the first selector_seq of each ECALL that actually enters a Field
    ecalls_by_idx = {e["ecall_index"]: e for e in edl_schema["ecalls"]}
    field_selectors = [s["ecall_index"] for s in selectors if s["reachable_fields"]]
    non_field_selectors = [s["ecall_index"] for s in selectors if not s["reachable_fields"]]

    first_field_sseq_by_ecall = {}
    for rec in res0["records"]:
        if rec["fields"] and rec["ecall_index"] not in first_field_sseq_by_ecall:
            first_field_sseq_by_ecall[rec["ecall_index"]] = rec["selector_seq"]

    # Step B: Layer 2 Closed-Loop Feedback Scale Expansion (on executable prefix + first Field-entering sseq)
    for idx in field_selectors:
        ec = ecalls_by_idx.get(idx)
        if not ec or get_scalable_bound_offsets(ec) is None:
            continue
        target_sseq = first_field_sseq_by_ecall.get(idx, 0)
        scale = 64
        seen_scale_effects: set[tuple[int, str]] = set()
        max_heap_span = 0
        stagnant_rounds = 0
        consecutive_rejections = 0
        while scale <= 262144:
            q_scale = min(scale, 1024)
            specs = [
                build_scale_bound_v2_spec(ec, scale, q_scale, mode=m, selector_seq=target_sseq)
                for m in ((0, 1, 2) if scale <= 4096 else (0,))
            ]
            spec_str = ";".join(s for s in specs if s)
            plan = {
                "run_id": f"layer2_feedback_scale_ecall{idx}_n{scale}",
                "layer": "layer2_generic_schema",
                "subkind": "feedback_scale_expansion",
                "intervention": spec_str,
                "desc": f"Closed-loop feedback scale step n={scale} on {ec['name']} (stop_after_selector={idx}:{target_sseq})",
            }
            res_sc = run_sample(
                sample,
                mode="profile_4gate",
                ipi_mask=7,
                intervention=spec_str,
                stop_after_selector=f"{idx}:{target_sseq}",
                allow_fast_forward=0,
                persist_prefix=raw_trace_dir / plan["run_id"],
            )
            ingest_run(plan, res_sc, is_baseline_host=False, is_seed_isolated=True)

            step_effs: set[tuple[int, str]] = set()
            step_heap_span = 0
            any_valid_return = False
            for rec in res_sc["records"]:
                if rec["tag"].startswith("schema_scale_"):
                    if rec["sgx_status"] == 0 and (rec.get("abi_return_type") == "void" or rec.get("ms_retval") == 0):
                        any_valid_return = True
                    for fobs in rec["fields"]:
                        h_span = int(fobs.get("heap_hi_rva", "0x0"), 16) - int(fobs.get("heap_lo_rva", "0x0"), 16)
                        if h_span > step_heap_span:
                            step_heap_span = h_span
                        for item in fobs["s3"]:
                            rva = int(item["rva"], 16)
                            step_effs.add((rva, "A"))
                            if item["ad"] == "D":
                                step_effs.add((rva, "D"))

            new_sc_effs = len(step_effs - seen_scale_effects)
            heap_grew = step_heap_span > max_heap_span
            seen_scale_effects |= step_effs
            if step_heap_span > max_heap_span:
                max_heap_span = step_heap_span

            if not any_valid_return:
                consecutive_rejections += 1
                decision = "stop_enclave_rejected_scale" if (consecutive_rejections >= 2 or scale >= 262144) else "continue_past_rejected_scale"
                feedback_trace.append({
                    "ecall_index": idx, "scale": scale, "valid_return": False,
                    "new_effects": new_sc_effs, "heap_span": step_heap_span,
                    "decision": decision,
                })
                if decision == "stop_enclave_rejected_scale":
                    break
                scale *= 4
                continue

            consecutive_rejections = 0
            if new_sc_effs == 0 and not heap_grew:
                stagnant_rounds += 1
            else:
                stagnant_rounds = 0

            if stagnant_rounds >= 2:
                decision = "stop_stagnant_2_rounds"
            elif scale >= 262144:
                decision = "stop_budget_cap_reached"
            else:
                decision = "expand_4x"
            feedback_trace.append({
                "ecall_index": idx, "scale": scale, "valid_return": True,
                "new_effects": new_sc_effs, "heap_span": step_heap_span,
                "decision": decision,
            })
            if decision != "expand_4x":
                break
            scale *= 4

    # Step C: Layer 2 Feedback-Guided Multi-Position & Prefix-Continuation Exploration
    # Collect up to 2 distinct Field-entering selector_seq positions per ECALL (retaining later positions
    # even when their L1 page set coincided with sseq=0)
    field_positions_by_ecall: dict[int, list[int]] = {}
    for rec in res0["records"]:
        if rec["fields"]:
            s_list = field_positions_by_ecall.setdefault(rec["ecall_index"], [])
            if rec["selector_seq"] not in s_list and len(s_list) < 2:
                s_list.append(rec["selector_seq"])

    seen_struct_sigs: set[tuple] = {structural_behavior_signature(r) for r in res0["records"]}
    family_credits: dict[str, float] = {"boundary": 1.0, "joint": 1.0, "alias": 1.0, "content": 0.8}

    for idx in field_selectors:
        ec = ecalls_by_idx.get(idx)
        if not ec:
            continue
        sseq_list = field_positions_by_ecall.get(idx, [0])
        for pos_rank, target_sseq in enumerate(sseq_list):
            raw_muts = generate_schema_mutations_for_ecall(ec, selector_seq=target_sseq, strategy="S3")
            # For secondary positions (pos_rank > 0), allocate reserved budget to control-scalar boundaries, joint, and alias
            if pos_rank > 0:
                raw_muts = [m for m in raw_muts if m.get("family") in ("boundary", "joint", "alias") and m.get("is_control_scalar", True)][:6]
            muts = round_robin_schedule_interventions(raw_muts)
            for m_i, m in enumerate(muts):
                fam = m.get("family", "content")
                plan = {
                    "run_id": f"layer2_isolated_mut_ecall{idx}_s{target_sseq}_m{m_i}_{m['tag']}",
                    "layer": "layer2_generic_schema",
                    "subkind": "isolated_single_mutation_replay",
                    "intervention": m["spec"],
                    "allow_nonzero_rc": False,
                    "desc": f"Feedback-scheduled mutation ({fam}, credit={family_credits.get(fam, 1.0):.2f}): {m['desc']} at sseq={target_sseq}",
                }
                res_m = run_sample(
                    sample,
                    mode="profile_4gate",
                    ipi_mask=7,
                    intervention=m["spec"],
                    stop_before_normal_ecall=f"{idx}:{target_sseq}",
                    allow_fast_forward=0,
                    persist_prefix=raw_trace_dir / plan["run_id"],
                )
                gained = ingest_run(plan, res_m, is_baseline_host=False, is_seed_isolated=True)
                new_sig = any(structural_behavior_signature(r) not in seen_struct_sigs for r in res_m["records"])
                for r in res_m["records"]:
                    seen_struct_sigs.add(structural_behavior_signature(r))
                if gained > 0 or new_sig:
                    family_credits[fam] = family_credits.get(fam, 1.0) + (2.0 * gained if gained > 0 else 0.5)
                    feedback_trace.append({
                        "ecall_index": idx,
                        "selector_seq": target_sseq,
                        "family": fam,
                        "tag": m["tag"],
                        "new_effects": gained,
                        "new_structural_sig": new_sig,
                        "updated_credit": round(family_credits[fam], 2),
                    })

    # Step D: Layer 2 Prefix Setup Continuation & Cold-State Replay across non-Field setup selectors
    for nf_idx in non_field_selectors:
        nf_ec = ecalls_by_idx.get(nf_idx)
        if nf_ec:
            for pidx, p in enumerate(nf_ec.get("params", [])):
                if not p.get("is_pointer"):
                    for val in (1, 2, 16):
                        plan = {
                            "run_id": f"layer2_prefix_setup_ecall{nf_idx}_p{pidx}_val{val}",
                            "layer": "layer2_generic_schema",
                            "subkind": "prefix_setup_continuation",
                            "intervention": f"set_scalar:{nf_idx}:0:{pidx}:{val}",
                            "allow_nonzero_rc": True,
                            "desc": f"Mutate setup call {nf_ec['name']}.{p['name']}={val} and continue host workflow into Field calls",
                        }
                        res_ps = run_sample(
                            sample,
                            mode="profile_4gate",
                            ipi_mask=7,
                            intervention=plan["intervention"],
                            allow_fast_forward=0,
                            persist_prefix=raw_trace_dir / plan["run_id"],
                        )
                        ingest_run(plan, res_ps, is_baseline_host=False, is_seed_isolated=True)

    if non_field_selectors and len(field_selectors) > 1:
        trig_idx = non_field_selectors[0]
        for idx in field_selectors:
            ec = ecalls_by_idx.get(idx)
            if not ec or not ec.get("replay_supported", True):
                continue
            cap_seq = first_field_sseq_by_ecall.get(idx, 0)
            plan = {
                "run_id": f"layer2_cold_state_replay_ecall{idx}_cap{cap_seq}",
                "layer": "layer2_generic_schema",
                "subkind": "cold_enclave_state_replay",
                "intervention": f"typed_state_probe:{idx}:{cap_seq}:{trig_idx}:1",
                "allow_nonzero_rc": False,
                "desc": f"Schema-typed cold enclave state replay of {ec['name']} (cap_seq={cap_seq} -> after ecall {trig_idx} sseq=1)",
            }
            res_sr = run_sample(
                sample,
                mode="profile_4gate",
                ipi_mask=7,
                intervention=plan["intervention"],
                allow_fast_forward=0,
                persist_prefix=raw_trace_dir / plan["run_id"],
            )
            ingest_run(plan, res_sr, is_baseline_host=False, is_seed_isolated=True)

    # Step E: Layer 2 Multi-Selector Quadrupling History Depth Scan
    # Reserves history budget (depth=16) for all Field-bearing selectors, plus full 16->64->256->1024 on primary steady-state selector
    for idx in field_selectors:
        ec = ecalls_by_idx.get(idx)
        if not ec or not ec.get("replay_supported", True):
            continue
        target_sseq = first_field_sseq_by_ecall.get(idx, 0)
        depths = (16, 64, 256, 1024) if idx == field_selectors[-1] else (16,)
        for depth in depths:
            plan = {
                "run_id": f"layer2_quadrupling_history_n{depth}_ecall{idx}",
                "layer": "layer2_generic_schema",
                "subkind": "quadrupling_history_scan",
                "intervention": f"repeat:{idx}:{target_sseq}:{depth}",
                "allow_nonzero_rc": True,
                "desc": f"Quadrupling history scan (4x progression, depth={depth}, 0 skipped) on {ec['name']}",
            }
            res_h = run_sample(
                sample,
                mode="profile_4gate",
                ipi_mask=4,
                intervention=plan["intervention"],
                stop_after_selector=f"{idx}:{target_sseq}",
                allow_fast_forward=0,
                persist_prefix=raw_trace_dir / plan["run_id"],
            )
            ingest_run(plan, res_h, is_baseline_host=False, is_seed_isolated=True)
            if res_h["returncode"] != 0:
                feedback_trace.append({
                    "ecall_index": idx,
                    "history_depth": depth,
                    "decision": f"stop_selector_non_repeatable_rc_{res_h['returncode']}",
                })
                break
            tscs = [f["tsc_s3"] for r in res_h["records"] for f in r["fields"] if r["tag"].startswith("generic_repeat_")]
            if tscs:
                med_tsc = sorted(tscs)[len(tscs) // 2]
                max_tsc = max(tscs)
                feedback_trace.append({
                    "ecall_index": idx, "history_depth": depth,
                    "median_tsc_s3": med_tsc, "max_tsc_s3": max_tsc,
                    "regime_jump_ratio": round(max_tsc / max(med_tsc, 1), 2),
                })


    # Static ELF inspection & heuristic assist
    syms = profile_elf.symbols()
    objects = [
        s for s in syms
        if s["shndx"] != 0 and (s["info"] & 0xF) == 1 and 0 < s["size"] < 0x1000000 and s["name"] != "meta_reserve"
    ]
    gm_sym = next((s for s in syms if s["name"] in ("_gm_", "gm_") and s["value"] > 0), None)
    disasm = parse_disasm_graph(tdir / "enclave.profile.so", profile_elf)
    func_by_start = disasm["func_by_start"]
    func_by_name = {v["name"]: k for k, v in func_by_start.items()}
    PRUNE_FUNCS = {"abort", "__stack_chk_fail", "field_exit", "exit", "_Exit"}

    rx_data_pages = set()
    for obj in objects:
        for pg in range(align_down(obj["value"]), align_up(obj["value"] + max(obj["size"], 1)), PAGE):
            rx_data_pages.add(pg)
    for finfo in func_by_start.values():
        for ref_rva in finfo["rip_refs"]:
            rx_data_pages.add(align_down(ref_rva))

    closed_fields_xr = []
    closed_fields_refined = []
    closure_breakdown = {}

    for field in fields:
        fid = f"0x{field['_id_value']:016x}"
        obs_pages = set(dyn_obs_pages[fid].keys())
        bridge_pages = set(dyn_bridge_pages[fid])
        p_set = set(obs_pages) | set(bridge_pages)

        reach_code_added = set()
        reach_data_added = set()
        exact_rip_refs = set()
        indirect_branches_found = []
        pruned_callees_found = []
        entry_fn = field["function"]
        if entry_fn in func_by_name:
            queue = [(func_by_name[entry_fn], 0)]
            visited_fn = {func_by_name[entry_fn]}
            while queue:
                fstart, depth = queue.pop(0)
                finfo = func_by_start[fstart]
                indirect_branches_found.extend(finfo["indirect_branches"])
                for pg in range(align_down(finfo["start"]), align_up(finfo["end"]), PAGE):
                    if pg in committed_map and pg not in p_set:
                        p_set.add(pg)
                        reach_code_added.add(pg)
                for ref_rva in finfo["rip_refs"]:
                    exact_rip_refs.add(ref_rva)
                    pg = align_down(ref_rva)
                    if pg in committed_map and pg not in p_set:
                        p_set.add(pg)
                        reach_data_added.add(pg)
                if depth < 4:
                    for callee in finfo["callees"]:
                        cname = func_by_start[callee]["name"]
                        if cname in PRUNE_FUNCS:
                            pruned_callees_found.append(cname)
                            continue
                        if callee not in visited_fn:
                            visited_fn.add(callee)
                            queue.append((callee, depth + 1))

        obj_added = set()
        for obj in objects:
            olo = obj["value"]
            ohi = obj["value"] + max(obj["size"], 1)
            lo = align_down(olo)
            hi = align_up(ohi)
            span = list(range(lo, hi, PAGE))
            has_exact_rip_ref = any(olo <= r < ohi for r in exact_rip_refs)
            check_span = span[1:-1] if len(span) >= 4 else span
            has_obs_hit = any(p in obs_pages for p in check_span)
            if has_exact_rip_ref or has_obs_hit:
                for p in span:
                    if p in committed_map and p not in p_set:
                        p_set.add(p)
                        obj_added.add(p)

        heap_added = set()
        if gm_sym:
            for p in range(align_down(gm_sym["value"]), align_up(gm_sym["value"] + max(gm_sym["size"], 64)), PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    heap_added.add(p)
        for clo, chi in set(dyn_chunks[fid]):
            span = list(range(align_down(max(0, clo - 16)), align_up(chi + 16), PAGE))
            if any(p in obs_pages for p in span):
                for p in span:
                    if p in committed_map and p not in p_set:
                        p_set.add(p)
                        heap_added.add(p)
        touched_heap = [p for p in obs_pages if p in heap_pages]
        if touched_heap:
            max_hp = max(touched_heap)
            for p in range(max(min(heap_pages), max_hp - PAGE), min(max_hp + 3 * PAGE, max(heap_pages) + PAGE), PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    heap_added.add(p)

        stack_added = set()
        if stack_pages:
            stack_hi_pg = max(stack_pages)
            min_rsp_pg = align_down(min(dyn_rsps[fid])) if dyn_rsps[fid] else (stack_hi_pg - 4 * PAGE)
            stack_lo_pg = max(min(stack_pages), min_rsp_pg - 4 * PAGE)
            for p in range(stack_lo_pg, stack_hi_pg + PAGE, PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    stack_added.add(p)
        for p in td_pages:
            if p in committed_map and p not in p_set:
                p_set.add(p)
                stack_added.add(p)

        records_xr = []
        records_refined = []
        for page in sorted(p_set):
            base_rec = committed_map[page]
            eff_xr = list(base_rec["effects"])
            eff_ref = list(base_rec["effects"])
            if "X" in eff_ref and "W" not in eff_ref and page not in rx_data_pages:
                eff_ref = ["X"]

            for target_list, effs in ((records_xr, eff_xr), (records_refined, eff_ref)):
                rec = {
                    "page_rva": page,
                    "effects": effs,
                    "max_permissions": base_rec["max_permissions"],
                    "relro": base_rec["relro"],
                    "origins": base_rec["origins"],
                }
                if "X" in effs:
                    choices = anchors.get(page, [])
                    if not choices:
                        raise RuntimeError(f"X page {page:#x} lacks a same-page C3 anchor")
                    rec["code_anchor"] = choices[0]
                if "R" in effs or "W" in effs:
                    rec["data_anchor_rva"] = page
                    rec["data_width"] = 1
                target_list.append(rec)

        for target_fields, recs in ((closed_fields_xr, records_xr), (closed_fields_refined, records_refined)):
            target_fields.append({
                "id": field["id"],
                "name": field.get("name", field.get("function", field["id"])),
                "function": field.get("function"),
                "order": field["order"],
                "stack_bytes": field.get("stack_bytes"),
                "pages": recs,
            })

        l0_eff = layer_sets["layer0_first_call"][fid]
        l1_eff = layer_sets["layer1_full_host"][fid]
        l2_eff = layer_sets["layer2_generic_schema"][fid]
        l2_seed_eff = layer2_seed_only[fid] | l0_eff
        l3_eff = layer_sets["layer3_domain_assist"][fid]

        l0_pg = {p for p, _ in l0_eff}
        l1_pg = {p for p, _ in l1_eff}
        l2_pg = {p for p, _ in l2_eff}
        l2_seed_pg = {p for p, _ in l2_seed_eff}
        l3_pg = {p for p, _ in l3_eff}

        closure_breakdown[fid] = {
            "function": field["function"],
            "call_statistics": field_call_stats[fid],
            "four_layer_attribution": {
                "layer0_first_field_call": {
                    "pages": len(l0_pg),
                    "page_effects": len(l0_eff),
                },
                "layer1_full_existing_host": {
                    "pages": len(l1_pg),
                    "page_effects": len(l1_eff),
                    "added_pages_over_layer0": len(l1_pg - l0_pg),
                    "added_effects_over_layer0": len(l1_eff - l0_eff),
                },
                "layer2_generic_schema_explorer": {
                    "seed_isolated_pages": len(l2_seed_pg),
                    "seed_isolated_added_pages_over_layer0": len(l2_seed_pg - l0_pg),
                    "added_pages_beyond_full_host_layer1": len(l2_pg - l1_pg),
                    "added_effects_beyond_full_host_layer1": len(l2_eff - l1_eff),
                    "cumulative_pages_after_layer2": len(l1_pg | l2_pg),
                    "cumulative_effects_after_layer2": len(l1_eff | l2_eff),
                },
                "layer3_domain_assisted": {
                    "added_pages_beyond_layer2": len(l3_pg - (l1_pg | l2_pg)),
                    "added_effects_beyond_layer2": len(l3_eff - (l1_eff | l2_eff)),
                    "cumulative_pages_after_layer3": len(obs_pages),
                    "cumulative_effects_after_layer3": len(cumulative_effects[fid]),
                },
            },
            "raw_single_run_pages": len(l0_pg),
            "dynamic_explored_obs_pages": len(obs_pages),
            "dynamic_explored_obs_effects": len(cumulative_effects[fid]),
            "s0_s1_epilogue_bridge_pages": len(bridge_pages - obs_pages),
            "heuristic_assist_breakdown": {
                "direct_call_depth4_code_added": len(reach_code_added),
                "direct_call_rip_data_added": len(reach_data_added),
                "stt_object_span_added": len(obj_added),
                "dlmalloc_heap_and_frontier_added": len(heap_added),
                "stack_margin_and_td_added": len(stack_added),
                "unresolved_indirect_branch_sites_in_subgraph": len(indirect_branches_found),
                "pruned_noreturn_callees": sorted(set(pruned_callees_found)),
                "heap_walk_truncated_runs": heap_truncated_runs,
                "heap_pread_failure_runs": heap_pread_fail_runs,
                "heuristic_parameters": {
                    "direct_call_max_depth": 4,
                    "heap_top_frontier_pages": 2,
                    "stack_below_min_rsp_margin_pages": 4,
                },
            },
            "final_field_target_pages": len(records_xr),
            "rx_pages_kept_xr_in_group_b": sum(1 for r in records_xr if "X" in r["effects"] and "R" in r["effects"]),
            "rx_pages_refined_to_x_in_group_c": sum(1 for r in records_refined if r["effects"] == ["X"]),
            "all_business_reg_pages": len(committed_map),
            "reduction_vs_all_reg_pct": round(100.0 * (1.0 - len(records_xr) / len(committed_map)), 2),
        }

    cap_q = layout["capacity_q"]
    artifacts = {}
    for variant_name, f_list in (("dynamic_xr", closed_fields_xr), ("dynamic", closed_fields_refined)):
        w_path = tdir / f"workset.{variant_name}.json"
        write_json(w_path, {
            "schema": "atfield-workset-v1",
            "page_size": PAGE,
            "layout": layout,
            "field_manifest": str(tdir / "fields.json"),
            "field_manifest_sha256": sha256_file(tdir / "fields.json"),
            "selector_manifest": str(tdir / "selectors.json"),
            "selector_manifest_sha256": sha256_file(tdir / "selectors.json"),
            "edl_manifest": str(edl_path),
            "edl_manifest_sha256": sha256_file(edl_path),
            "selectors": selectors,
            "fields": f_list,
        })
        artifacts[variant_name] = emit_and_sign_variant(tdir, variant_name, w_path, cap_q)

    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(tdir / "enclave.all_reg.final.so"),
        "-out", str(tdir / "enclave.all_reg.final.aex0.signed.so"),
        "-config", str(tdir / "Enclave.aex0.config.xml"),
    ], check=True, stdout=subprocess.DEVNULL)

    ledger_out = {
        "schema": "atfield-witness-ledger-v3",
        "sample": sample,
        "interpose_sha256": interpose_hash,
        "profile_elf_sha256": sha256_file(tdir / "enclave.profile.so"),
        "artifacts": artifacts,
        "feedback_trace": feedback_trace,
        "ecall_statistics": ecall_stats,
        "runs": run_summaries,
        "closure_breakdown": closure_breakdown,
        "witnesses": witness_ledger,
    }
    write_json(wdir / "witness_ledger.json", ledger_out)
    return ledger_out


def main() -> None:
    samples = sys.argv[1:] or ["qe3", "signal-cds", "sgxwallet", "ehsm", "ehsm-opt-1", "ehsm-opt-2"]
    hw_challenge_res = run_real_hardware_challenge_ablation(max_enclave_budget=48)
    challenge_payload = {
        "audit_of_legacy_heuristics": AUDIT_OF_LEGACY_HEURISTICS,
        "equal_enclave_budget": 48,
        "real_hardware_challenge_enclaves": hw_challenge_res,
    }
    write_json(DYN_ROOT / "experiments" / "strategy_comparison.json", challenge_payload)
    for s in samples:
        print(f"=== Exploring & building Group B/C variants for {s} ===", flush=True)
        res = explore_and_close_sample(s)
        for fid, cb in res["closure_breakdown"].items():
            fl = cb["four_layer_attribution"]
            print(
                f"  {cb['function']}: L0={fl['layer0_first_field_call']['pages']}p "
                f"L1={fl['layer1_full_existing_host']['pages']}p "
                f"L2_seed={fl['layer2_generic_schema_explorer']['seed_isolated_pages']}p "
                f"L2_over_L1=+{fl['layer2_generic_schema_explorer']['added_pages_beyond_full_host_layer1']}p/"
                f"+{fl['layer2_generic_schema_explorer']['added_effects_beyond_full_host_layer1']}e "
                f"L3=+{fl['layer3_domain_assisted']['added_pages_beyond_layer2']}p/"
                f"+{fl['layer3_domain_assisted']['added_effects_beyond_layer2']}e "
                f"-> Final={cb['final_field_target_pages']}p"
            )


if __name__ == "__main__":
    main()
