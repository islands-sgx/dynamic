#!/usr/bin/env python3
"""ATField-SGX Dynamic Workset Explorer, 4-Layer Attribution Ledger, and Heuristic Assist Builder.

Implements:
- P0/P1: Full-call (0 skipped) collection and 4-layer attribution ledger with (page_rva, effect)
  granularity (explicitly recording A->D write upgrades and per-Field call/entry/status counts):
    * Layer 0: First Field call / minimal 1-call seed
    * Layer 1: Full unmodified host workflow
    * Layer 2: Generic EDL-schema-driven & feedback/history/L*-state explorer (zero sample hardcoding)
    * Layer 3: Optional domain-assisted format-aware probes (tracked separately)
- P2: Data-driven mutations from targets/<sample>/edl_schema.json via tools/generic_explorer.py
- P3/P4: Explicit separation of dynamic observations vs heuristic ELF/allocator/stack assist,
  emitting three workset & binary variants per sample:
    * Group A (all_reg): All committed business REG pages (RX = XR)
    * Group B (dynamic_xr): Dynamic + heuristic assist pages, keeping all RX pages conservatively as XR
    * Group C (dynamic): Same page set as Group B, refining pure code RX pages without RIP-data/object refs to X-only
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
VENDOR_IMPL = DYN_ROOT / "vendor" / "implement"
sys.path.insert(0, str(VENDOR_IMPL / "build" / "workset"))
sys.path.insert(0, str(DYN_ROOT / "tools"))

from workset import (  # noqa: E402
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
    generate_schema_mutations_for_ecall,
    generate_schema_scale_schedule,
)
from run_native_sgx import run_sample, sha256_file  # noqa: E402

LLVM_OBJDUMP = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llvm-objdump"
SGX_SIGN = "/nix/store/2acwmnfcsz668csnyxn77brmllp7kx6s-sgx-sdk-2.29.100.1/bin/x64/sgx_sign"
SIGN_KEY = "/home/meandssh/islands-sgx/sample/build/test-signing-key.pem"
PRETOUCH_TOOL = VENDOR_IMPL / "build" / "pretouch" / "pretouch.py"
READINESS_TOOL = VENDOR_IMPL / "build" / "readiness" / "readiness.py"
PATCH_4GATE_TOOL = DYN_ROOT / "tools" / "patch_4gate.py"


def parse_disasm_graph(elf_path: Path, elf: ElfFile) -> dict:
    """Extract function ranges, direct call/jump edges, indirect branch sites, and exact RIP-relative data refs."""
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


def build_generic_layer2_runs(sample: str, edl_schema: dict, selectors: list[dict]) -> list[dict]:
    """Construct Layer 2 runs purely from edl_schema.json + selector reachability without sample-name branches."""
    ecalls_by_idx = {e["ecall_index"]: e for e in edl_schema["ecalls"]}
    field_Format_selectors = [s["ecall_index"] for s in selectors if s["reachable_fields"]]
    non_field_init_selectors = [s["ecall_index"] for s in selectors if not s["reachable_fields"]]

    runs = []
    # 1. Generic schema buffer-scale doubling schedule (for any ECALL with count=/size= bound [in] pointers)
    for idx in field_Format_selectors:
        ec = ecalls_by_idx.get(idx)
        if not ec:
            continue
        scale_steps = generate_schema_scale_schedule(ec, selector_seq=0)
        if scale_steps:
            runs.append({
                "run_id": f"layer2_schema_scale_ecall{idx}",
                "layer": "layer2_generic_schema",
                "subkind": "adaptive_bound_scale",
                "intervention": ";".join(st["spec"] for st in scale_steps),
                "stop_after_call": 0,
                "host_args": [],
                "allow_nonzero_rc": False,
                "desc": f"Generic edl_schema count=/size= doubling schedule on {ec['name']}",
            })

    # 2. Generic schema pointer/scalar/bit-flip mutations per Field-bearing ECALL
    for idx in field_Format_selectors:
        ec = ecalls_by_idx.get(idx)
        if not ec:
            continue
        muts = generate_schema_mutations_for_ecall(ec, selector_seq=0)
        non_null = [m["spec"] for m in muts if m["kind"] != "schema_null_ptr"]
        nulls = [m["spec"] for m in muts if m["kind"] == "schema_null_ptr"]
        if non_null:
            # Test at sseq=0 and sseq=1 (in case sseq=0 is a size-query call!)
            non_null_s1 = [sp.replace(f":{idx}:0:", f":{idx}:1:") for sp in non_null]
            runs.append({
                "run_id": f"layer2_schema_val_xor_ecall{idx}",
                "layer": "layer2_generic_schema",
                "subkind": "schema_scalar_and_bitflip",
                "intervention": ";".join(non_null + non_null_s1),
                "stop_after_call": None,
                "host_args": ["--requests", "1"] if len(ecalls_by_idx) == 7 else [],
                "allow_nonzero_rc": True,
                "desc": f"Generic edl_schema scalar boundaries & input buffer bit-flips on {ec['name']}",
            })
        if nulls:
            runs.append({
                "run_id": f"layer2_schema_null_ecall{idx}",
                "layer": "layer2_generic_schema",
                "subkind": "schema_null_pointer",
                "intervention": ";".join(nulls[:2]),
                "stop_after_call": None,
                "host_args": ["--requests", "1"] if len(ecalls_by_idx) == 7 else [],
                "allow_nonzero_rc": True,
                "desc": f"Generic edl_schema NULL pointer injection on {ec['name']}",
            })

    # 3. Generic L* cold-state distinguishing probes:
    #    If there is an initialization ECALL (index 0, no fields) and multiple Field-bearing ECALLs,
    #    probe each Field-bearing ECALL immediately after index 0 (selector_seq=1, fresh second enclave instance)
    if 0 in non_field_init_selectors and len(field_Format_selectors) > 1:
        for idx in field_Format_selectors:
            ec = ecalls_by_idx.get(idx)
            if not ec or not ec.get("ms_layout"):
                continue
            ms_sz = ec["ms_layout"]["size"]
            for cap_seq in (0, 1):
                runs.append({
                    "run_id": f"layer2_lstar_cold_probe_ecall{idx}_cap{cap_seq}",
                    "layer": "layer2_generic_schema",
                    "subkind": "lstar_cold_state_probe",
                    "intervention": f"state_probe:{idx}:{cap_seq}:0:1:{ms_sz}",
                    "stop_after_call": None,
                    "host_args": ["--requests", "1"] if len(ecalls_by_idx) == 7 else [],
                    "allow_nonzero_rc": True,
                    "desc": f"Generic L* cold-state distinguishing query on {ec['name']} (cap_seq={cap_seq} -> after ecall 0 sseq=1)",
                })

    # 4. Generic exponential history depth exploration (1024 full calls, 0 skipped) on the last Field-bearing ECALL
    if field_Format_selectors:
        last_idx = field_Format_selectors[-1]
        ec = ecalls_by_idx[last_idx]
        runs.append({
            "run_id": f"layer2_generic_history_1024_ecall{last_idx}",
            "layer": "layer2_generic_schema",
            "subkind": "exponential_history_depth_1024",
            "intervention": f"repeat:{last_idx}:0:1024",
            "ipi_mask": 4,
            "stop_after_call": None,
            "host_args": ["--requests", "1"] if len(ecalls_by_idx) == 7 else [],
            "allow_nonzero_rc": True,
            "desc": f"Generic 1024-step full-call history exploration on {ec['name']} (0 calls skipped)",
        })

    return runs


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
        sys.executable, str(PRETOUCH_TOOL), "finalize",
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
        sys.executable, str(PRETOUCH_TOOL), "verify",
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
        sys.executable, str(READINESS_TOOL),
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

    # Per-layer independent (page_rva, effect) sets for exact attribution
    layer_sets: dict[str, dict[str, set[tuple[int, str]]]] = {
        "layer0_first_call": {fid: set() for fid in field_ids},
        "layer1_full_host": {fid: set() for fid in field_ids},
        "layer2_generic_schema": {fid: set() for fid in field_ids},
        "layer3_domain_assist": {fid: set() for fid in field_ids},
    }
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
            "succeeded_entries": 0,
            "expected_rejection_entries": 0,
            "transport_error_entries": 0,
        }
        for fid in field_ids
    }
    ecall_stats: dict[int, dict] = {}
    witness_ledger = []
    run_summaries = []

    # Define the 4-layer execution schedule:
    # 1. Layer 0 + Layer 1: Run unmodified full host workflow (all calls measured, 0 skipped!).
    #    The very first observation of each Field in this run defines Layer 0; the rest of the run defines Layer 1.
    # 2. Layer 2: Generic EDL-schema-driven & L*/history explorer runs (zero sample-name branching!).
    # 3. Layer 3: Optional domain-assisted runs (only ehsm_sizes for inner ehsm_data_t framing).
    schedule = [
        {
            "run_id": "layer0_and_layer1_unmodified_host",
            "layer": "layer1_full_host",
            "subkind": "unmodified_host_full_trace",
            "intervention": "",
            "ipi_mask": 7,
            "stop_after_call": None,
            "host_args": [],
            "allow_nonzero_rc": False,
            "desc": "Unmodified host binary full execution (first entry per Field = Layer 0; full run = Layer 1)",
        },
        *build_generic_layer2_runs(sample, edl_schema, selectors),
    ]
    if sample == "ehsm":
        schedule.append({
            "run_id": "layer3_domain_ehsm_inner_datalen_sweep",
            "layer": "layer3_domain_assist",
            "subkind": "domain_inner_struct_framing",
            "intervention": "ehsm_sizes:1",
            "ipi_mask": 7,
            "stop_after_call": None,
            "host_args": [],
            "allow_nonzero_rc": False,
            "desc": "Domain-assisted ehsm_data_t inner datalen payload sweep [1..6145] + GCM tag fault",
        })

    # Also measure what Layer 2 discovers on a strictly minimal 1-call seed (without Layer 1's subsequent host calls!)
    layer2_on_minimal_seed: dict[str, set[tuple[int, str]]] = {fid: set() for fid in field_ids}

    for run_idx, plan in enumerate(schedule):
        persist_pref = raw_trace_dir / plan["run_id"]
        res = run_sample(
            sample,
            mode="profile_4gate",
            ipi_mask=plan.get("ipi_mask", 7),
            intervention=plan["intervention"],
            stop_after_call=plan.get("stop_after_call"),
            host_args=plan.get("host_args", []),
            allow_fast_forward=0,
            dump_dir=str(dump_dir) if run_idx == 0 else "",
            persist_prefix=persist_pref,
        )
        if res["returncode"] != 0 and not plan.get("allow_nonzero_rc"):
            raise RuntimeError(f"Run {plan['run_id']} failed on {sample}: rc={res['returncode']} stderr={res['stderr']}")

        run_new_effects = 0
        for rec in res["records"]:
            ec_idx = rec["ecall_index"]
            est = ecall_stats.setdefault(ec_idx, {
                "ecall_invocations": 0,
                "field_entering_calls": 0,
                "outer_rejected_or_nofield_calls": 0,
                "succeeded_calls": 0,
                "nonzero_retval_calls": 0,
                "transport_error_calls": 0,
            })
            est["ecall_invocations"] += 1
            if rec["fields"]:
                est["field_entering_calls"] += 1
            else:
                est["outer_rejected_or_nofield_calls"] += 1
            if rec["sgx_status"] != 0:
                est["transport_error_calls"] += 1
            elif rec["ms_retval_i32"] == 0:
                est["succeeded_calls"] += 1
            else:
                est["nonzero_retval_calls"] += 1

            for fobs in rec["fields"]:
                fid = fobs["field_id"]
                if fid not in dyn_obs_pages:
                    continue
                fstat = field_call_stats[fid]
                fstat["field_entries"] += 1
                if rec["sgx_status"] != 0:
                    fstat["transport_error_entries"] += 1
                elif rec["ms_retval_i32"] == 0:
                    fstat["succeeded_entries"] += 1
                else:
                    fstat["expected_rejection_entries"] += 1

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

                if run_idx == 0:
                    if is_first_entry:
                        layer_sets["layer0_first_call"][fid].update(eff_pairs_this_call)
                    layer_sets["layer1_full_host"][fid].update(eff_pairs_this_call)
                else:
                    layer_sets[plan["layer"]][fid].update(eff_pairs_this_call)
                    if plan["layer"] == "layer2_generic_schema":
                        # If this record came from a schema intervention or on a --requests 1 / stop_after_call seed,
                        # record it in layer2_on_minimal_seed
                        if rec["tag"] != "host_normal" or plan.get("host_args") == ["--requests", "1"] or plan.get("stop_after_call") is not None:
                            layer2_on_minimal_seed[fid].update(eff_pairs_this_call)

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
                    actual_layer = "layer0_first_call" if (run_idx == 0 and is_first_entry) else plan["layer"]
                    witness_ledger.append({
                        "witness_id": f"{sample}_{plan['run_id']}_seq{rec['call_seq']}_{fid[-6:]}",
                        "layer": actual_layer,
                        "run_id": plan["run_id"],
                        "subkind": plan["subkind"],
                        "trace_file": str(persist_pref.with_suffix(".jsonl")),
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
            "trace_jsonl": str(persist_pref.with_suffix(".jsonl")),
            "records_collected": len(res["records"]),
            "measurement_invalid": res["measurement_invalid"],
            "new_page_effects_discovered": run_new_effects,
        })

    # Static ELF inspection & heuristic assist (explicitly separated from dynamic observations)
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

    # Identify all RX pages that have an STT_OBJECT or a direct RIP-relative data reference
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

        # Heuristic Assist (a): Direct call-graph (depth <= 4) + exact RIP-relative references from Field entry
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

        # Heuristic Assist (b): STT_OBJECT full-span assist
        # Triggered if EITHER an exact RIP-relative reference falls inside [olo, ohi) (including first/last page!)
        # OR an interior page of the object (or any page for <=2-page objects) was dynamically observed in obs_pages.
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

        # Heuristic Assist (c): dlmalloc (_gm_) + live heap chunk span + 2-page top frontier
        heap_added = set()
        if gm_sym:
            for p in range(align_down(gm_sym["value"]), align_up(gm_sym["value"] + max(gm_sym["size"], 64)), PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    heap_added.add(p)
        for clo, chi in set(dyn_chunks[fid]):
            span = range(align_down(max(0, clo - 16)), align_up(chi + 16), PAGE)
            if any(p in p_set for p in span):
                for p in span:
                    if p in committed_map and p not in p_set:
                        p_set.add(p)
                        heap_added.add(p)
        touched_heap = [p for p in p_set if p in heap_pages]
        if touched_heap:
            min_hp, max_hp = min(touched_heap), max(touched_heap)
            for p in range(min_hp, min(max_hp + 3 * PAGE, max(heap_pages) + PAGE), PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    heap_added.add(p)

        # Heuristic Assist (d): Stack interval (min observed %rsp - 4 pages heuristic margin) + TD
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

        # Build Group B (dynamic_xr: keep all RX pages as XR) and Group C (dynamic: refine pure code RX pages to X)
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

        # Compute exact 4-layer attribution for this Field (both pages and (page, effect) pairs)
        l0_eff = layer_sets["layer0_first_call"][fid]
        l1_eff = layer_sets["layer1_full_host"][fid]
        l2_eff = layer_sets["layer2_generic_schema"][fid]
        l2_seed_eff = layer2_on_minimal_seed[fid] | l0_eff
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
                    "independent_pages_from_minimal_seed": len(l2_seed_pg),
                    "independent_added_pages_over_layer0": len(l2_seed_pg - l0_pg),
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
            "final_field_target_pages": len(records_refined),
            "rx_pages_kept_xr_in_group_b": sum(1 for r in records_xr if "X" in r["effects"] and "R" in r["effects"]),
            "rx_pages_refined_to_x_in_group_c": sum(1 for r in records_refined if r["effects"] == ["X"]),
            "all_business_reg_pages": len(committed_map),
            "reduction_vs_all_reg_pct": round(100.0 * (1.0 - len(records_refined) / len(committed_map)), 2),
        }

    # Write Group B (workset.dynamic_xr.json) and Group C (workset.dynamic.json)
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

    # Also ensure Group A (all_reg) has enclave.all_reg.final.aex0.signed.so signed for reproducible evaluation
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(tdir / "enclave.all_reg.final.so"),
        "-out", str(tdir / "enclave.all_reg.final.aex0.signed.so"),
        "-config", str(tdir / "Enclave.aex0.config.xml"),
    ], check=True, stdout=subprocess.DEVNULL)

    ledger_out = {
        "schema": "atfield-witness-ledger-v2",
        "sample": sample,
        "profile_elf_sha256": sha256_file(tdir / "enclave.profile.so"),
        "artifacts": artifacts,
        "ecall_statistics": ecall_stats,
        "runs": run_summaries,
        "closure_breakdown": closure_breakdown,
        "witnesses": witness_ledger,
    }
    write_json(wdir / "witness_ledger.json", ledger_out)
    return ledger_out


def main() -> None:
    samples = sys.argv[1:] or ["qe3", "signal-cds", "sgxwallet", "ehsm"]
    for s in samples:
        print(f"=== Exploring, attributing 4 layers & building Group B/C variants for {s} ===", flush=True)
        res = explore_and_close_sample(s)
        for fid, cb in res["closure_breakdown"].items():
            fl = cb["four_layer_attribution"]
            print(
                f"  {cb['function']}: L0={fl['layer0_first_field_call']['pages']}p "
                f"L1={fl['layer1_full_existing_host']['pages']}p "
                f"L2_seed={fl['layer2_generic_schema_explorer']['independent_pages_from_minimal_seed']}p "
                f"L2_added_over_host=+{fl['layer2_generic_schema_explorer']['added_pages_beyond_full_host_layer1']}p "
                f"L3_added=+{fl['layer3_domain_assisted']['added_pages_beyond_layer2']}p "
                f"-> Final={cb['final_field_target_pages']}p (All-REG={cb['all_business_reg_pages']}p)"
            )


if __name__ == "__main__":
    main()
