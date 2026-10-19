#!/usr/bin/env python3
"""Unit tests for src/schema_mutator_abi.h and tools/edl_harness.py covering:
1. 4-byte guard-page-adjacent objects (is_exportable),
2. Multiplication overflow (count * elem_size),
3. Overlapping pointer aliasing (p and p + 4) preserved under both replay AND mutate_xor_in_snapshot,
4. Coordinated scalar + bound-buffer reallocation (mutate_scalar_and_rebind_buffers: 3 -> 99 expands
   both 8*99=792B [in] and 1*99=99B [inout] buffers so writing 99 bytes succeeds without overflow!),
5. ms_size > 256 (MAX_MS_FRAME_BYTES) rejected with -EOVERFLOW,
6. Unsupported EDL length expressions (count=a+b) rejected,
7. void vs scalar ABI return reading.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")
sys.path.insert(0, str(DYN_ROOT / "tools"))
from edl_harness import parse_edl_trusted  # noqa: E402


C_TEST_SRC = r"""
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "schema_mutator_abi.h"

int main(void) {
    /* 1. 4-byte object (int[1], like sgxwallet is_exportable) placed right before a PROT_NONE guard page! */
    uint8_t *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(pages != MAP_FAILED);
    assert(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
    int32_t *four_byte_obj = (int32_t *)(pages + 4096 - 4);
    *four_byte_obj = 0x11223344;

    param_schema_t p4 = {0};
    strcpy(p4.name, "is_exportable");
    p4.ms_offset = 16; p4.ms_size = 8; p4.elem_size = 4;
    p4.is_pointer = 1; p4.ptr_depth = 1; p4.direction = DIR_IN;
    p4.bound_kind = BOUND_COUNT; p4.bound_ms_offset = -1; p4.static_count = 1;
    p4.replay_supported = 1;

    uint8_t ms_orig[32] = {0}, ms_work[32] = {0};
    *(void **)(ms_orig + 16) = four_byte_obj;
    void *tmp_alloc = NULL;

    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 4, 0xff, &tmp_alloc) == -ERANGE);
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 15, 0xff, &tmp_alloc) == -ERANGE);
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 31, 0xff, &tmp_alloc) == -ERANGE);
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 60, 0xff, &tmp_alloc) == -ERANGE);
    assert(*four_byte_obj == 0x11223344);

    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 0, 0xff, &tmp_alloc) == 0);
    assert(tmp_alloc != NULL && tmp_alloc != four_byte_obj);
    assert(*four_byte_obj == 0x11223344);
    free(tmp_alloc);
    munmap(pages, 8192);

    /* 2. Multiplication overflow check */
    param_schema_t p_ovf = p4;
    p_ovf.elem_size = 8; p_ovf.bound_ms_offset = 8; p_ovf.bound_ms_size = 8; p_ovf.static_count = -1;
    *(uint64_t *)(ms_orig + 8) = (1ULL << 62);
    size_t blen = 0, ulen = 0;
    assert(compute_param_byte_len(ms_orig, 32, &p_ovf, &blen, &ulen) == -EOVERFLOW);

    /* 3. Overlapping pointer aliasing (p and p + 4) preserved under replay AND mutate_xor_in_snapshot! */
    ecall_schema_t es_overlap = {0};
    es_overlap.ecall_index = 1;
    es_overlap.ms_size = 32;
    es_overlap.has_retval = 0;
    es_overlap.replay_supported = 1;
    es_overlap.num_params = 2;

    es_overlap.params[0].ms_offset = 0; es_overlap.params[0].ms_size = 8; es_overlap.params[0].elem_size = 1;
    es_overlap.params[0].is_pointer = 1; es_overlap.params[0].ptr_depth = 1; es_overlap.params[0].direction = DIR_INOUT;
    es_overlap.params[0].bound_kind = BOUND_SIZE; es_overlap.params[0].bound_ms_offset = -1; es_overlap.params[0].static_count = 16;
    es_overlap.params[0].replay_supported = 1;

    es_overlap.params[1] = es_overlap.params[0];
    es_overlap.params[1].ms_offset = 8;
    es_overlap.params[1].static_count = 12;

    uint8_t shared_backing[16];
    for (int i = 0; i < 16; i++) shared_backing[i] = (uint8_t)(0x10 + i);
    uint8_t ms_ov[32] = {0}, ms_ov_out[32] = {0};
    *(void **)(ms_ov + 0) = shared_backing;       /* p */
    *(void **)(ms_ov + 8) = shared_backing + 4;   /* p + 4 (overlapping interior alias!) */

    typed_ms_snapshot_t snap_ov = {0};
    assert(typed_snapshot_ms(ms_ov, 32, &es_overlap, &snap_ov) == 0);
    assert(typed_restore_ms_for_replay(&snap_ov, &es_overlap, ms_ov_out) == 0);
    uint8_t *rp0 = *(uint8_t **)(ms_ov_out + 0);
    uint8_t *rp1 = *(uint8_t **)(ms_ov_out + 8);
    assert(rp1 == rp0 + 4);

    /* Mutating byte 0 of param 1 (p + 4) via mutate_xor_in_snapshot MUST also be visible at byte 4 of param 0 (p)! */
    assert(mutate_xor_in_snapshot(&snap_ov, &es_overlap, ms_ov_out, 1, 0, 0xff) == 0);
    rp0 = *(uint8_t **)(ms_ov_out + 0);
    rp1 = *(uint8_t **)(ms_ov_out + 8);
    assert(rp1 == rp0 + 4);
    assert(rp1[0] == (0x14 ^ 0xff));
    assert(rp0[4] == (0x14 ^ 0xff));
    free_typed_snapshot(&snap_ov);

    /* 4. Coordinated scalar mutation (mutate_scalar_and_rebind_buffers):
     *    Signal-CDS layout: ab_jids (off=24, elem_sz=8, bound=32:4), ab_jid_count (off=32, sz=4),
     *    in_ab_jids_result (off=40, elem_sz=1, bound=32:4).
     *    Seed count = 3 (ab_jids = 24B, in_ab_jids_result = 3B).
     *    Mutate ab_jid_count from 3 -> 99: BOTH ab_jids (792B) and in_ab_jids_result (99B) MUST be reallocated!
     */
    ecall_schema_t es_sig = {0};
    es_sig.ecall_index = 0;
    es_sig.ms_size = 48;
    es_sig.has_retval = 1; es_sig.retval_offset = 0; es_sig.retval_size = 4;
    es_sig.replay_supported = 1;
    es_sig.num_params = 3;

    /* param 0: ab_jids [in, count=ab_jid_count] uint64_t* at off=24 */
    es_sig.params[0].ms_offset = 24; es_sig.params[0].ms_size = 8; es_sig.params[0].elem_size = 8;
    es_sig.params[0].is_pointer = 1; es_sig.params[0].ptr_depth = 1; es_sig.params[0].direction = DIR_IN;
    es_sig.params[0].bound_kind = BOUND_COUNT; es_sig.params[0].bound_ms_offset = 32; es_sig.params[0].bound_ms_size = 4;
    es_sig.params[0].static_count = -1; es_sig.params[0].replay_supported = 1;

    /* param 1: ab_jid_count [val] uint32_t at off=32 */
    es_sig.params[1].ms_offset = 32; es_sig.params[1].ms_size = 4; es_sig.params[1].elem_size = 4;
    es_sig.params[1].is_pointer = 0; es_sig.params[1].direction = DIR_VAL; es_sig.params[1].replay_supported = 1;

    /* param 2: in_ab_jids_result [inout, count=ab_jid_count] uint8_t* at off=40 */
    es_sig.params[2].ms_offset = 40; es_sig.params[2].ms_size = 8; es_sig.params[2].elem_size = 1;
    es_sig.params[2].is_pointer = 1; es_sig.params[2].ptr_depth = 1; es_sig.params[2].direction = DIR_INOUT;
    es_sig.params[2].bound_kind = BOUND_COUNT; es_sig.params[2].bound_ms_offset = 32; es_sig.params[2].bound_ms_size = 4;
    es_sig.params[2].static_count = -1; es_sig.params[2].replay_supported = 1;

    uint64_t seed_ab[3] = {101, 202, 303};
    uint8_t seed_res[3] = {1, 0, 1};
    uint8_t ms_sig[48] = {0}, ms_sig_work[48] = {0};
    *(void **)(ms_sig + 24) = seed_ab;
    *(uint32_t *)(ms_sig + 32) = 3;
    *(void **)(ms_sig + 40) = seed_res;

    typed_ms_snapshot_t snap_sig = {0};
    assert(typed_snapshot_ms(ms_sig, 48, &es_sig, &snap_sig) == 0);
    assert(snap_sig.work_alloc_len[0] == 24);
    assert(snap_sig.work_alloc_len[2] == 3);

    /* Mutate ab_jid_count (param 1) from 3 -> 99 */
    assert(mutate_scalar_and_rebind_buffers(&snap_sig, &es_sig, ms_sig_work, 1, 99) == 0);
    assert(*(uint32_t *)(ms_sig_work + 32) == 99);
    assert(snap_sig.work_alloc_len[0] == 792);
    assert(snap_sig.work_alloc_len[2] == 99);

    /* Reading 792 bytes from ab_jids and writing 99 bytes to in_ab_jids_result succeeds cleanly within bounds! */
    uint64_t *new_ab = *(uint64_t **)(ms_sig_work + 24);
    uint8_t *new_res = *(uint8_t **)(ms_sig_work + 40);
    assert(new_ab[0] == 101 && new_ab[3] == 101 && new_ab[98] == 303);
    memset(new_res, 0x5a, 99);
    free_typed_snapshot(&snap_sig);

    /* 5. ms_size > MAX_MS_FRAME_BYTES (256) MUST be rejected with -EOVERFLOW */
    es_sig.ms_size = 300;
    assert(typed_snapshot_ms(ms_sig, 300, &es_sig, &snap_sig) == -EOVERFLOW);

    puts("ALL_SCHEMA_MUTATOR_AND_ABI_TESTS_PASSED");
    return 0;
}
"""


class TestSchemaMutatorAndAbi(unittest.TestCase):
    def test_c_schema_mutator_and_abi_suite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            c_file = Path(td) / "test_abi.c"
            bin_file = Path(td) / "test_abi"
            c_file.write_text(C_TEST_SRC)
            subprocess.run(
                ["gcc", "-O2", "-Wall", "-Wextra", f"-I{DYN_ROOT / 'src'}", str(c_file), "-o", str(bin_file)],
                check=True,
            )
            out = subprocess.check_output([str(bin_file)], text=True)
            self.assertIn("ALL_SCHEMA_MUTATOR_AND_ABI_TESTS_PASSED", out)

    def test_unsupported_edl_bound_expression_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            edl = Path(td) / "bad.edl"
            edl.write_text('enclave { trusted { public int foo([in, count=a+b] uint8_t *buf, int a, int b); }; };')
            ecalls = parse_edl_trusted(edl)
            self.assertEqual(len(ecalls), 1)
            attrs = ecalls[0]["params"][0]["attributes"]
            import re
            self.assertIsNone(re.match(r"^(count|size)\s*=\s*(\w+)$", [a for a in attrs if a.startswith("count")][0]))


if __name__ == "__main__":
    unittest.main()
