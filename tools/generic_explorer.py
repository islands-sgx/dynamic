#!/usr/bin/env python3
"""Schema-Typed & Feedback-Driven Dynamic Workset Explorer (Layer 2).

All parameter offsets, element widths, static/dynamic bounds, and ABI return types
are derived strictly from targets/<sample>/edl_schema.json.
"""
from __future__ import annotations


def generate_schema_mutations_for_ecall(ecall: dict, selector_seq: int = 0) -> list[dict]:
    """Generate strictly bounds-safe pointer, scalar, and bit-flip interventions from edl_schema.json."""
    idx = ecall["ecall_index"]
    ms = ecall.get("ms_layout")
    if not ms or not ecall.get("replay_supported", True):
        return []
    interventions = []
    for pidx, p in enumerate(ecall.get("params", [])):
        if p.get("ms_offset") is None or not p.get("param_replay_supported", True):
            continue
        pname = p["name"]
        direction = p.get("direction", "val")
        if p.get("is_pointer"):
            if direction in ("in", "inout"):
                static_b = p.get("static_byte_len")
                is_str = p.get("is_string", False)
                if static_b is not None:
                    cands = [b for b in (0, 15, 60) if b < static_b]
                elif is_str:
                    cands = [0]
                else:
                    cands = [0, 15]
                for byte_idx in cands:
                    mask = 0xFF if byte_idx in (0, 60) else 0xAA
                    interventions.append({
                        "kind": "schema_xor_param",
                        "param_index": pidx,
                        "tag": f"schema_xor_p{pidx}_byte_{byte_idx}",
                        "spec": f"xor_param:{idx}:{selector_seq}:{pidx}:{byte_idx}:{mask}",
                        "desc": f"Bounded schema XOR on {ecall['name']}.{pname}[{byte_idx}] ^= 0x{mask:02x}",
                    })
        else:
            for val in (0, 2, 99):
                interventions.append({
                    "kind": "schema_scalar_boundary",
                    "param_index": pidx,
                    "tag": f"schema_scalar_p{pidx}_val_{val}",
                    "spec": f"set_scalar:{idx}:{selector_seq}:{pidx}:{val}",
                    "desc": f"Typed scalar boundary (with dependent buffer rebind) {ecall['name']}.{pname} = {val}",
                })
    return interventions


def get_scalable_bound_offsets(ecall: dict) -> tuple[int, int] | None:
    """Return (primary_cnt_ms_offset, secondary_cnt_ms_offset) if ecall has [in] pointers
    with dynamic count=/size= bindings, else None.
    """
    if not ecall.get("ms_layout") or not ecall.get("replay_supported", True):
        return None
    params = ecall.get("params", [])
    in_bound = [
        p for p in params
        if p.get("is_pointer") and p.get("direction") == "in"
        and p.get("bound_kind") in ("count", "size")
        and p.get("bound_ms_offset") is not None
    ]
    if not in_bound:
        return None
    cnt1_off = in_bound[0]["bound_ms_offset"]
    cnt2_off = -1
    for p in in_bound[1:]:
        if p["bound_ms_offset"] != cnt1_off:
            cnt2_off = p["bound_ms_offset"]
            break
    return (cnt1_off, cnt2_off)


def build_scale_bound_v2_spec(
    ecall: dict,
    scale1: int,
    scale2: int = 0,
    mode: int = 0,
    selector_seq: int = 0,
) -> str | None:
    offs = get_scalable_bound_offsets(ecall)
    if offs is None:
        return None
    cnt1_off, cnt2_off = offs
    return f"scale_bound_v2:{ecall['ecall_index']}:{selector_seq}:{mode}:{cnt1_off}:{scale1}:{cnt2_off}:{scale2}"
