#!/usr/bin/env python3
"""ATField-SGX Dynamic Workset Explorer & Conservative Closure Controller.

Implements:
1. Multi-stage real-SGX dynamic exploration via libatfield_native_sgx.so:
   - Stage 0: Zero-intervention record/replay of the unmodified host workflow
   - Stage 1: EDL-typed parameter/scale/content/error-path interventions
   - Stage 2: General history repetition & state-distinguishing queries (e.g. sgxwallet sigCounter)
   - Stage 3: Cross-instance persistence & reload workflows
2. Witness ledger archiving (witnesses/<sample>/witness_ledger.json):
   - Every discovered (field_id, page_rva, ad) is tied to a reproducible witness
3. Conservative closure (workset-acquisition.md §4.2):
   - STT_OBJECT full-span closure
   - dlmalloc (_gm_) active heap chunk + header/metadata span closure
   - Stack interval closure from Gate-B/Gate-D %rsp + .stack_sizes frame bounds
   - Direct call/branch & RIP-relative constant reachability closure from Field entry
   - Same-page C3 code anchor & data anchor attachment producing schema-compatible
     atfield-workset-v1 JSON (targets/<sample>/workset.dynamic.json)
4. Finalization & 4-Gate / Strict Readiness (PTE=0) Hardware Verification:
   - Emits enclave.dynamic.final.signed.so, enclave.dynamic.4gate.aex0.signed.so,
     and enclave.dynamic.ready.bin (ReadyTable v3)
   - Compares Raw-Single-Run vs Dynamic+Closure vs All-Committed-REG Baseline
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
VENDOR_IMPL = DYN_ROOT / "vendor" / "implement"
sys.path.insert(0, str(VENDOR_IMPL / "build" / "workset"))
sys.path.insert(0, str(DYN_ROOT / "tools"))

from workset import (  # noqa: E402
    PAGE,
    PF_X,
    SI_FLAG_R,
    SI_FLAG_W,
    SI_FLAG_X,
    ElfFile,
    align_down,
    align_up,
    effects_for_permissions,
    normalized_fields,
    parse_anchor_symbols,
    resolve_selectors,
    write_json,
)
from run_native_sgx import run_sample  # noqa: E402

LLVM_OBJDUMP = "/nix/store/grw38wxqcn2k8bp9gm9b9h28ds3jgb9y-llvm-atfield-llc-22.1.8/bin/llvm-objdump"
SGX_SIGN = "/nix/store/2acwmnfcsz668csnyxn77brmllp7kx6s-sgx-sdk-2.29.100.1/bin/x64/sgx_sign"
SIGN_KEY = "/home/meandssh/islands-sgx/sample/build/test-signing-key.pem"
PRETOUCH_TOOL = VENDOR_IMPL / "build" / "pretouch" / "pretouch.py"
READINESS_TOOL = VENDOR_IMPL / "build" / "readiness" / "readiness.py"
PATCH_4GATE_TOOL = DYN_ROOT / "tools" / "patch_4gate.py"


EXPLORATION_PLANS = {
    "qe3": [
        {"stage": "stage0_baseline", "intervention": "", "desc": "Unmodified host workflow (3 key derivations + public checks)"},
        {
            "stage": "stage1_keyid_mutations",
            "intervention": "xor_buf:0:0:8:0:255;xor_buf:0:0:8:15:170;xor_buf:0:0:8:31:85",
            "desc": "Mutate key_id bytes [0, 15, 31] to exercise distinct EGETKEY->CMAC->secp256r1 scalar paths",
        },
        {
            "stage": "stage1_error_paths",
            "intervention": "null_ptr:0:0:8;null_ptr:0:0:16",
            "desc": "Inject NULL key_id and NULL public_key pointers",
        },
    ],
    "signal-cds": [
        {"stage": "stage0_baseline", "intervention": "", "desc": "Unmodified host workflow (empty, small, dup, 262144-record scale)"},
        {
            "stage": "stage1_scales_and_collisions",
            "intervention": "signal_scales:0",
            "desc": "Scale & collision sweep: (16,16), (128,64), (512,128) all-hit, (1024,256) all-miss, (2048,512) hash-bucket dups, (4096,1024)",
        },
    ],
    "sgxwallet": [
        {
            "stage": "stage0_history_and_persistence",
            "intervention": "",
            "desc": "Full host workflow: GenerateSEK, GenerateEcdsaKey, GetPublicEcdsaKey, 1001x EcdsaSign (crossing sigCounter==1000 self_check_ecdsa!), bad key, bad hex, Enclave recreate + SetSEK + Sign",
        },
        {
            "stage": "stage1_base_and_error_mutations",
            "intervention": "set_u32:6:0:72:10;set_u32:6:0:72:99;set_u32:5:0:24:8;xor_buf:5:0:16:0:255",
            "desc": "Mutate EcdsaSign base=10 (decimal conversion branch) & base=99 (invalid base error), GetPublicEcdsaKey bad dec_len=8 & corrupted key",
        },
        {
            "stage": "stage2_setsek_corrupt_unseal",
            "intervention": "xor_buf:3:0:16:60:255",
            "allow_nonzero_rc": True,
            "desc": "Corrupt sealed SEK MAC tag in SetSEK (triggers sgx_unseal_data 0x3001 error branch inside set_sek_field)",
        },
    ],
    "ehsm": [
        {
            "stage": "stage0_baseline",
            "intervention": "",
            "desc": "Unmodified host workflow: domain key init, create_key (size query + alloc), encrypt/decrypt roundtrips, generate_datakey, tampered MAC tag, wrong keyusage, len=1, len=6144, len=0/6145 rejections, enclave reload from domain-key.sealed",
        },
        {
            "stage": "stage1_payload_sizes_and_tag_faults",
            "intervention": "ehsm_sizes:1",
            "desc": "Coupled encrypt->decrypt sweep across payload sizes [1, 15, 16, 17, 64, 256, 1024, 4096, 6144, 6145] + corrupted GCM tag on len=1024",
        },
    ],
}


def parse_disasm_graph(elf_path: Path, elf: ElfFile) -> dict:
    """Extract function ranges, direct call/jump edges, and RIP-relative memory references per function."""
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
            }

    import bisect

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
            tm = re.search(r"\b0x([0-9a-f]+)\s*<", ops)
            if tm:
                target = int(tm.group(1), 16)
                t_owner = owner_func(target)
                if t_owner is not None:
                    finfo["callees"].add(t_owner)
        # RIP-relative memory reference comment: `# 0x<hex>` (on non-call/non-jump instructions)
        if not mnemonic.startswith(("call", "jmp", "j")):
            rm = re.search(r"#\s*0x([0-9a-f]+)", ops)
            if rm:
                ref_rva = int(rm.group(1), 16)
                finfo["rip_refs"].add(ref_rva)

    return {"func_starts": func_starts, "func_by_start": func_by_start}


def build_committed_page_map(layout: dict) -> dict[int, dict]:
    """Return {page_rva: {'max_permissions': int, 'permissions': int, 'relro': bool, 'origins': list[str]}}."""
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


def explore_and_close_sample(sample: str) -> dict:
    tdir = DYN_ROOT / "targets" / sample
    wdir = DYN_ROOT / "witnesses" / sample
    dump_dir = wdir / "dumps"
    wdir.mkdir(parents=True, exist_ok=True)
    dump_dir.mkdir(parents=True, exist_ok=True)

    profile_elf = ElfFile(tdir / "enclave.profile.so")
    layout = json.loads((tdir / "signer_layout.json").read_text())
    fields = normalized_fields(tdir / "fields.json")
    edl_path = Path(json.loads((tdir / "edl_schema.json").read_text())["edl_path"])
    selectors = resolve_selectors(tdir / "selectors.json", fields, edl_path)
    committed_map = build_committed_page_map(layout)
    anchors = parse_anchor_symbols(profile_elf)

    # Identify stack and heap regions
    stack_pages = sorted(
        p for p, info in committed_map.items()
        if any(o.startswith("STACK") for o in info["origins"])
    )
    heap_pages = sorted(
        p for p, info in committed_map.items()
        if any(o.startswith("HEAP") for o in info["origins"])
    )
    td_pages = sorted(
        p for p, info in committed_map.items()
        if any(o.startswith("TD") for o in info["origins"])
    )

    # Per-field tracking
    field_ids = [f"0x{f['_id_value']:016x}" for f in fields]
    raw_first_obs: dict[str, set[int]] = {fid: set() for fid in field_ids}
    dyn_obs_pages: dict[str, dict[int, str]] = {fid: {} for fid in field_ids}
    dyn_chunks: dict[str, list[tuple[int, int]]] = {fid: [] for fid in field_ids}
    dyn_rsps: dict[str, list[int]] = {fid: [] for fid in field_ids}
    dyn_s1_pages: dict[str, set[int]] = {fid: set() for fid in field_ids}
    witness_ledger = []
    stage_curve = []

    plans = EXPLORATION_PLANS[sample]
    for p_idx, plan in enumerate(plans):
        res = run_sample(
            sample,
            mode="profile_4gate",
            ipi_mask=7,
            intervention=plan["intervention"],
            dump_dir=str(dump_dir) if p_idx == 0 else "",
        )
        if res["returncode"] != 0 and not plan.get("allow_nonzero_rc"):
            raise RuntimeError(f"Exploration stage {plan['stage']} failed on {sample}: {res['stderr']}")

        stage_new_pages = 0
        for rec in res["records"]:
            for fobs in rec["fields"]:
                fid = fobs["field_id"]
                if fid not in dyn_obs_pages:
                    continue
                s3_list = fobs["s3"]
                if not raw_first_obs[fid] and s3_list:
                    raw_first_obs[fid] = {
                        int(item["rva"], 16) for item in s3_list
                        if int(item["rva"], 16) in committed_map
                    }
                for item in fobs["s0"] + fobs["s1"] + rec.get("ecall_ad", []):
                    rva = int(item["rva"], 16)
                    if rva in committed_map:
                        dyn_s1_pages[fid].add(rva)
                newly_added_in_call = []
                for item in s3_list:
                    rva = int(item["rva"], 16)
                    ad = item["ad"]
                    if rva not in committed_map:
                        continue
                    prev = dyn_obs_pages[fid].get(rva)
                    if prev is None:
                        dyn_obs_pages[fid][rva] = ad
                        newly_added_in_call.append({"rva": hex(rva), "ad": ad})
                        stage_new_pages += 1
                    elif prev == "A" and ad == "D":
                        dyn_obs_pages[fid][rva] = "D"
                for lo_s, hi_s in fobs.get("chunks", []):
                    dyn_chunks[fid].append((int(lo_s, 16), int(hi_s, 16)))
                for rk in ("gateB_rsp_rva", "gateD_rsp_rva"):
                    rv = int(fobs.get(rk, "0x0"), 16)
                    if rv > 0:
                        dyn_rsps[fid].append(rv)
                if newly_added_in_call:
                    witness_ledger.append({
                        "witness_id": f"{sample}_{plan['stage']}_seq{rec['call_seq']}_{fid[-6:]}",
                        "stage": plan["stage"],
                        "call_seq": rec["call_seq"],
                        "ecall_index": rec["ecall_index"],
                        "selector_seq": rec["selector_seq"],
                        "tag": rec["tag"],
                        "intervention": plan["intervention"],
                        "field_id": fid,
                        "new_pages": newly_added_in_call,
                        "total_field_obs_pages": len(dyn_obs_pages[fid]),
                        "tsc_s3": fobs["tsc_s3"],
                    })

        stage_curve.append({
            "stage": plan["stage"],
            "description": plan["desc"],
            "records_collected": len(res["records"]),
            "new_pages_discovered": stage_new_pages,
            "per_field_obs_counts": {fid: len(dyn_obs_pages[fid]) for fid in field_ids},
        })

    # Parse static ELF objects and call graph for §4.2 conservative closure
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

    closed_fields_workset = []
    closure_breakdown = {}

    for field in fields:
        fid = f"0x{field['_id_value']:016x}"
        p_set = set(dyn_obs_pages[fid].keys()) | set(dyn_s1_pages[fid])
        n_obs = len(dyn_obs_pages[fid])
        n_raw_first = len(raw_first_obs[fid])

        # Closure (a): Direct call-graph + RIP-relative constant reachability from Field entry
        reach_code_added = set()
        reach_data_added = set()
        entry_fn = field["function"]
        if entry_fn in func_by_name:
            queue = [(func_by_name[entry_fn], 0)]
            visited_fn = {func_by_name[entry_fn]}
            while queue:
                fstart, depth = queue.pop(0)
                finfo = func_by_start[fstart]
                for pg in range(align_down(finfo["start"]), align_up(finfo["end"]), PAGE):
                    if pg in committed_map and pg not in p_set:
                        p_set.add(pg)
                        reach_code_added.add(pg)
                for ref_rva in finfo["rip_refs"]:
                    pg = align_down(ref_rva)
                    if pg in committed_map and pg not in p_set:
                        p_set.add(pg)
                        reach_data_added.add(pg)
                if depth < 4:
                    for callee in finfo["callees"]:
                        cname = func_by_start[callee]["name"]
                        if cname in PRUNE_FUNCS or callee in visited_fn:
                            continue
                        visited_fn.add(callee)
                        queue.append((callee, depth + 1))

        # Closure (b): STT_OBJECT full-span closure (seeded from observed + RIP-referenced pages, avoiding boundary-page false chaining)
        obj_added = set()
        seed_for_obj = set(dyn_obs_pages[fid].keys()) | reach_data_added
        for obj in objects:
            olo = obj["value"]
            ohi = obj["value"] + max(obj["size"], 1)
            # If object > 2 pages, require either an interior page hit or exact RIP reference
            lo = align_down(olo)
            hi = align_up(ohi)
            span = list(range(lo, hi, PAGE))
            check_span = span[1:-1] if len(span) >= 4 else span
            if any(p in seed_for_obj for p in check_span):
                for p in span:
                    if p in committed_map and p not in p_set:
                        p_set.add(p)
                        obj_added.add(p)

        # Closure (c): dlmalloc (_gm_) + live heap chunk span closure
        heap_added = set()
        if gm_sym:
            gm_lo = align_down(gm_sym["value"])
            gm_hi = align_up(gm_sym["value"] + max(gm_sym["size"], 64))
            for p in range(gm_lo, gm_hi, PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    heap_added.add(p)
        for clo, chi in set(dyn_chunks[fid]):
            span_lo = align_down(max(0, clo - 16))
            span_hi = align_up(chi + 16)
            span = range(span_lo, span_hi, PAGE)
            if any(p in p_set for p in span):
                for p in span:
                    if p in committed_map and p not in p_set:
                        p_set.add(p)
                        heap_added.add(p)
        # Also include a 2-page frontier above the highest touched heap page for brk/top growth
        touched_heap = [p for p in p_set if p in heap_pages]
        if touched_heap:
            min_hp, max_hp = min(touched_heap), max(touched_heap)
            for p in range(min_hp, min(max_hp + 3 * PAGE, max(heap_pages) + PAGE), PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    heap_added.add(p)

        # Closure (d): Stack interval closure + TD closure
        stack_added = set()
        if stack_pages:
            stack_hi_pg = max(stack_pages)
            min_rsp_pg = align_down(min(dyn_rsps[fid])) if dyn_rsps[fid] else (stack_hi_pg - 4 * PAGE)
            # Add 4-page safety margin below minimum observed %rsp
            stack_lo_pg = max(min(stack_pages), min_rsp_pg - 4 * PAGE)
            for p in range(stack_lo_pg, stack_hi_pg + PAGE, PAGE):
                if p in committed_map and p not in p_set:
                    p_set.add(p)
                    stack_added.add(p)
        for p in td_pages:
            if p in committed_map and p not in p_set:
                p_set.add(p)
                stack_added.add(p)

        # Identify RX pages with embedded data (STT_OBJECT or RIP-relative data reference)
        rx_data_pages = set(reach_data_added)
        for obj in objects:
            for pg in range(align_down(obj["value"]), align_up(obj["value"] + max(obj["size"], 1)), PAGE):
                rx_data_pages.add(pg)
        for finfo in func_by_start.values():
            for ref_rva in finfo["rip_refs"]:
                rx_data_pages.add(align_down(ref_rva))

        # Build sorted page records matching atfield-workset-v1 schema
        page_records = []
        for page in sorted(p_set):
            base_rec = committed_map[page]
            effects = list(base_rec["effects"])
            if "X" in effects and "W" not in effects and page not in rx_data_pages:
                effects = ["X"]
            rec = {
                "page_rva": page,
                "effects": effects,
                "max_permissions": base_rec["max_permissions"],
                "relro": base_rec["relro"],
                "origins": base_rec["origins"],
            }
            if "X" in effects:
                choices = anchors.get(page, [])
                if not choices:
                    raise RuntimeError(f"X page {page:#x} lacks a same-page C3 anchor")
                rec["code_anchor"] = choices[0]
            if "R" in effects or "W" in effects:
                rec["data_anchor_rva"] = page
                rec["data_width"] = 1
            page_records.append(rec)

        closed_fields_workset.append({
            "id": field["id"],
            "name": field.get("name", field.get("function", field["id"])),
            "function": field.get("function"),
            "order": field["order"],
            "stack_bytes": field.get("stack_bytes"),
            "pages": page_records,
        })
        closure_breakdown[fid] = {
            "function": field["function"],
            "raw_single_run_pages": n_raw_first,
            "dynamic_explored_obs_pages": n_obs,
            "s1_boundary_pages": len(dyn_s1_pages[fid]),
            "closure_reach_code_added": len(reach_code_added),
            "closure_reach_data_added": len(reach_data_added),
            "closure_stt_object_added": len(obj_added),
            "closure_dlmalloc_heap_added": len(heap_added),
            "closure_stack_td_added": len(stack_added),
            "final_field_target_pages": len(page_records),
            "all_business_reg_pages": len(committed_map),
            "reduction_vs_all_reg_pct": round(100.0 * (1.0 - len(page_records) / len(committed_map)), 2),
        }

    # Write workset.dynamic.json (100% compatible with pretouch.py and readiness.py!)
    workset_dyn_path = tdir / "workset.dynamic.json"
    workset_payload = {
        "schema": "atfield-workset-v1",
        "page_size": PAGE,
        "layout": layout,
        "field_manifest": str(tdir / "fields.json"),
        "selector_manifest": str(tdir / "selectors.json"),
        "edl_manifest": str(edl_path),
        "selectors": selectors,
        "fields": closed_fields_workset,
    }
    write_json(workset_dyn_path, workset_payload)

    # Finalize, sign, verify, and build ReadyTable v3 + 4-gate image for dynamic workset
    cap_q = layout["capacity_q"]
    final_dyn_elf = tdir / "enclave.dynamic.final.so"
    final_dyn_json = tdir / "pretouch.dynamic.finalized.json"
    verify_dyn_json = tdir / "pretouch.dynamic.verified.json"
    signed_final_dyn = tdir / "enclave.dynamic.final.signed.so"
    ready_dyn_bin = tdir / "enclave.dynamic.ready.bin"
    ready_dyn_json = tdir / "enclave.dynamic.ready.json"

    subprocess.run([
        sys.executable, str(PRETOUCH_TOOL), "finalize",
        "--profile-elf", str(tdir / "enclave.profile.so"),
        "--signed-profile-elf", str(tdir / "enclave.profile.signed.so"),
        "--workset", str(workset_dyn_path),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--out-elf", str(final_dyn_elf),
        "--out-json", str(final_dyn_json),
    ], check=True)
    subprocess.run([
        SGX_SIGN, "sign", "-key", SIGN_KEY,
        "-enclave", str(final_dyn_elf), "-out", str(signed_final_dyn),
        "-config", str(tdir / "Enclave.protect.config.xml"),
    ], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([
        sys.executable, str(PRETOUCH_TOOL), "verify",
        "--profile-elf", str(tdir / "enclave.profile.so"),
        "--signed-profile-elf", str(tdir / "enclave.profile.signed.so"),
        "--final-elf", str(final_dyn_elf),
        "--signed-final-elf", str(signed_final_dyn),
        "--workset", str(workset_dyn_path),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--out-json", str(verify_dyn_json),
    ], check=True)
    subprocess.run([
        sys.executable, str(READINESS_TOOL),
        "--workset", str(workset_dyn_path),
        "--fields", str(tdir / "fields.json"),
        "--pretouch", str(verify_dyn_json),
        "--final-elf", str(final_dyn_elf),
        "--signed-final-elf", str(signed_final_dyn),
        "--out", str(ready_dyn_bin),
        "--out-json", str(ready_dyn_json),
    ], check=True)
    subprocess.run([
        sys.executable, str(PATCH_4GATE_TOOL),
        "--input-elf", str(final_dyn_elf),
        "--fields", str(tdir / "fields.json"),
        "--capacity-q", str(cap_q),
        "--config-xml", str(tdir / "Enclave.aex0.config.xml"),
        "--out-elf", str(tdir / "enclave.dynamic.4gate.so"),
        "--out-signed-elf", str(tdir / "enclave.dynamic.4gate.aex0.signed.so"),
        "--out-json", str(tdir / "enclave.dynamic.4gate.json"),
    ], check=True)

    # Save witness ledger
    ledger_out = {
        "schema": "atfield-witness-ledger-v1",
        "sample": sample,
        "stages": stage_curve,
        "closure_breakdown": closure_breakdown,
        "witnesses": witness_ledger,
    }
    write_json(wdir / "witness_ledger.json", ledger_out)
    return ledger_out


def main() -> None:
    samples = sys.argv[1:] or ["qe3", "signal-cds", "sgxwallet", "ehsm"]
    results = {}
    for s in samples:
        print(f"=== Exploring & closing {s} ===", flush=True)
        results[s] = explore_and_close_sample(s)
        print(json.dumps(results[s]["closure_breakdown"], indent=2), flush=True)


if __name__ == "__main__":
    main()
