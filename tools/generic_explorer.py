#!/usr/bin/env python3
"""Generic EDL-Schema-Driven & Page/Effect-Feedback Dynamic Workset Explorer (Layer 2).

Zero sample-name branching: derives all buffer scaling, pointer/scalar/content mutations,
and exponential history schedules purely from targets/<sample>/edl_schema.json and
real-SGX (page_rva, effect) feedback.
"""
from __future__ import annotations

import json
from pathlib import Path


def generate_schema_mutations_for_ecall(ecall: dict, selector_seq: int = 0) -> list[dict]:
    """Generate generic pointer, scalar, and bit-flip interventions from edl_schema.json."""
    idx = ecall["ecall_index"]
    ms = ecall.get("ms_layout")
    if not ms:
        return []
    interventions = []
    for p in ecall.get("params", []):
        off = p.get("ms_offset")
        if off is None:
            continue
        pname = p["name"]
        direction = p.get("direction", "val")
        if p.get("is_pointer"):
            if direction in ("in", "inout"):
                # 1. Generic bit-flip at byte offsets 0, 15, 31, 60 of input buffer
                for byte_idx, mask in [(0, 255), (15, 170), (31, 85), (60, 255)]:
                    interventions.append({
                        "kind": "schema_xor_buf",
                        "spec": f"xor_buf:{idx}:{selector_seq}:{off}:{byte_idx}:{mask}",
                        "desc": f"Generic bit-flip on {ecall['name']}.{pname}[{byte_idx}] ^= 0x{mask:02x}",
                        "allow_nonzero_rc": True,
                    })
                # 2. Generic NULL pointer injection
                interventions.append({
                    "kind": "schema_null_ptr",
                    "spec": f"null_ptr:{idx}:{selector_seq}:{off}",
                    "desc": f"Generic NULL pointer injection on {ecall['name']}.{pname}",
                    "allow_nonzero_rc": True,
                })
        else:
            # Scalar parameter: test generic boundary values
            ms_sz = p.get("ms_size", 4)
            op = "set_u64" if ms_sz == 8 else "set_u32"
            for val in (0, 2, 8, 10, 16, 99):
                interventions.append({
                    "kind": "schema_scalar_boundary",
                    "spec": f"{op}:{idx}:{selector_seq}:{off}:{val}",
                    "desc": f"Generic scalar boundary {ecall['name']}.{pname} = {val}",
                    "allow_nonzero_rc": True,
                })
    return interventions


def generate_schema_scale_schedule(ecall: dict, selector_seq: int = 0) -> list[dict]:
    """If an ECALL has [in] pointers bound to count=/size= scalars in edl_schema.json,
    generate an adaptive doubling scale schedule using the generic scale_bound primitive.
    """
    idx = ecall["ecall_index"]
    ms = ecall.get("ms_layout")
    if not ms:
        return []
    ms_sz = ms["size"]
    params = ecall.get("params", [])
    in_bound = [
        p for p in params
        if p.get("is_pointer") and p.get("direction") == "in"
        and p.get("bound_kind") in ("count", "size")
        and p.get("bound_ms_offset") is not None
    ]
    if not in_bound:
        return []

    primary = in_bound[0]
    secondary_in = in_bound[1] if len(in_bound) > 1 else None
    out_bound = [
        p for p in params
        if p.get("is_pointer") and p.get("direction") in ("out", "inout")
        and p.get("bound_kind") in ("count", "size")
    ]
    secondary_out = out_bound[0] if out_bound else None

    cnt1_off = primary["bound_ms_offset"]
    cnt1_sz = primary["bound_ms_size"]
    ptr1_off = primary["ms_offset"]
    elem1_sz = primary.get("elem_size", 1)

    cnt2_off = secondary_in["bound_ms_offset"] if secondary_in else 0
    cnt2_sz = secondary_in["bound_ms_size"] if secondary_in else 0
    ptr2_off = secondary_in["ms_offset"] if secondary_in else 0
    elem2_sz = secondary_in.get("elem_size", 0) if secondary_in else 0

    out2_off = secondary_out["ms_offset"] if secondary_out else 0
    out2_elem_sz = secondary_out.get("elem_size", 0) if secondary_out else 0

    steps = []
    # Exponential doubling from 64 to 262144
    for scale in (64, 256, 1024, 4096, 16384, 65536, 262144):
        q_scale = min(scale, 1024) if elem2_sz > 0 else 0
        modes = (0, 1, 2) if scale <= 4096 else (0,)
        for mode in modes:
            spec = (
                f"scale_bound:{idx}:{selector_seq}:{ms_sz}:"
                f"{cnt1_off}:{cnt1_sz}:{scale}:{ptr1_off}:{elem1_sz}:{mode}:"
                f"{cnt2_off}:{cnt2_sz}:{q_scale}:{ptr2_off}:{elem2_sz}:{out2_off}:{out2_elem_sz}"
            )
            steps.append({
                "scale": scale,
                "mode": mode,
                "spec": spec,
                "desc": (
                    f"Generic schema scale_bound on {ecall['name']}.{primary['name']} "
                    f"({primary['bound_kind']}={scale}, elem_sz={elem1_sz}, mode={mode})"
                ),
            })
    return steps
