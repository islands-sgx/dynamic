#!/usr/bin/env python3
"""Unit tests for src/schema_mutator_abi.h covering 4B objects, cross-page objects, aliasing,
short integers, zero length, inout restoration, unsupported user_check, and void vs scalar ABI reading.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

DYN_ROOT = Path("/home/meandssh/islands-sgx/dynamic")


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
    p4.ms_offset = 16;
    p4.ms_size = 8;
    p4.elem_size = 4;
    p4.is_pointer = 1;
    p4.ptr_depth = 1;
    p4.direction = DIR_IN;
    p4.bound_kind = BOUND_COUNT;
    p4.bound_ms_offset = -1;
    p4.static_count = 1;
    p4.replay_supported = 1;

    uint8_t ms_orig[32] = {0}, ms_work[32] = {0};
    *(void **)(ms_orig + 16) = four_byte_obj;
    void *tmp_alloc = NULL;

    /* Offsets >= 4 (e.g., 4, 15, 31, 60) MUST be rejected with -ERANGE without touching the guard page! */
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 4, 0xff, &tmp_alloc) == -ERANGE);
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 15, 0xff, &tmp_alloc) == -ERANGE);
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 31, 0xff, &tmp_alloc) == -ERANGE);
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 60, 0xff, &tmp_alloc) == -ERANGE);
    assert(*four_byte_obj == 0x11223344);

    /* Offset 0..3 succeeds on a cloned buffer and leaves original 4B object untouched */
    assert(mutate_xor_bounded(ms_work, ms_orig, 32, &p4, 0, 0xff, &tmp_alloc) == 0);
    assert(tmp_alloc != NULL && tmp_alloc != four_byte_obj);
    assert(*four_byte_obj == 0x11223344);
    assert(*(int32_t *)tmp_alloc == (int32_t)(0x11223344 ^ 0xff));
    free(tmp_alloc);
    munmap(pages, 8192);

    /* 2. Multiplication overflow check (count * elem_size) */
    param_schema_t p_ovf = p4;
    p_ovf.elem_size = 8;
    p_ovf.bound_ms_offset = 8;
    p_ovf.bound_ms_size = 8;
    p_ovf.static_count = -1;
    *(uint64_t *)(ms_orig + 8) = (1ULL << 62);
    size_t blen = 0, ulen = 0;
    assert(compute_param_byte_len(ms_orig, 32, &p_ovf, &blen, &ulen) == -EOVERFLOW);

    /* 3. Cross-page object (6000 bytes), short integer count (uint16_t), zero-length, aliased pointers, and inout restoration */
    ecall_schema_t es = {0};
    es.ecall_index = 2;
    es.ms_size = 48;
    es.has_retval = 0; /* void ECALL like sgxwallet! */
    es.replay_supported = 1;
    es.num_params = 4;

    /* param 0: errStatus [out] int* at offset 0 (pointer at offset 0 in a void ECALL!) */
    es.params[0].ms_offset = 0; es.params[0].ms_size = 8; es.params[0].elem_size = 4;
    es.params[0].is_pointer = 1; es.params[0].ptr_depth = 1; es.params[0].direction = DIR_OUT;
    es.params[0].bound_kind = BOUND_COUNT; es.params[0].bound_ms_offset = -1; es.params[0].static_count = 1;
    es.params[0].replay_supported = 1;

    /* param 1: cross-page [inout] buffer bound to uint16_t count at offset 8 */
    es.params[1].ms_offset = 16; es.params[1].ms_size = 8; es.params[1].elem_size = 2;
    es.params[1].is_pointer = 1; es.params[1].ptr_depth = 1; es.params[1].direction = DIR_INOUT;
    es.params[1].bound_kind = BOUND_COUNT; es.params[1].bound_ms_offset = 8; es.params[1].bound_ms_size = 2;
    es.params[1].static_count = -1; es.params[1].replay_supported = 1;

    /* param 2: uint16_t count scalar at offset 8 */
    es.params[2].ms_offset = 8; es.params[2].ms_size = 2; es.params[2].elem_size = 2;
    es.params[2].is_pointer = 0; es.params[2].direction = DIR_VAL; es.params[2].replay_supported = 1;

    /* param 3: aliased pointer pointing to the SAME buffer as param 1! */
    es.params[3] = es.params[1];
    es.params[3].ms_offset = 24;

    int32_t err_status_slot = 0x77777777;
    uint8_t *cross_page_buf = (uint8_t *)calloc(3000, 2); /* 6000 bytes (> 1 page) */
    for (int i = 0; i < 6000; i++) cross_page_buf[i] = (uint8_t)(i & 0xff);

    uint8_t ms_frame[48] = {0};
    *(void **)(ms_frame + 0) = &err_status_slot;
    *(uint16_t *)(ms_frame + 8) = 3000; /* 3000 * 2 = 6000 bytes */
    *(void **)(ms_frame + 16) = cross_page_buf;
    *(void **)(ms_frame + 24) = cross_page_buf; /* aliased! */

    /* ABI check on void ECALL: must NOT read offset 0 pointer low bits as retval! */
    abi_outcome_t abi = {0};
    assert(read_ecall_abi_outcome(ms_frame, 48, &es, &abi) == 0);
    assert(abi.has_retval == 0 && abi.retval_i64 == 0);

    /* Snapshot and replay check */
    typed_ms_snapshot_t snap = {0};
    assert(typed_snapshot_ms(ms_frame, 48, &es, &snap) == 0);
    uint8_t ms_replay[48] = {0};
    assert(typed_restore_ms_for_replay(&snap, &es, ms_replay) == 0);
    uint8_t *rep_p1 = *(uint8_t **)(ms_replay + 16);
    uint8_t *rep_p3 = *(uint8_t **)(ms_replay + 24);
    assert(rep_p1 != NULL && rep_p1 != cross_page_buf);
    /* Aliasing preserved: rep_p1 and rep_p3 point to the exact same cloned buffer! */
    assert(rep_p1 == rep_p3);
    assert(memcmp(rep_p1, cross_page_buf, 6000) == 0);

    /* Modify inout buffer during replay #1, then restore for replay #2 and verify pristine contents */
    memset(rep_p1, 0xaa, 6000);
    assert(typed_restore_ms_for_replay(&snap, &es, ms_replay) == 0);
    assert(memcmp(rep_p1, cross_page_buf, 6000) == 0);
    free_typed_snapshot(&snap);

    /* Zero-length buffer check (count = 0) */
    *(uint16_t *)(ms_frame + 8) = 0;
    assert(typed_snapshot_ms(ms_frame, 48, &es, &snap) == 0);
    assert(snap.byte_lens[1] == 0);
    assert(mutate_xor_bounded(ms_replay, ms_frame, 48, &es.params[1], 0, 0xff, &tmp_alloc) == -ERANGE);
    free_typed_snapshot(&snap);

    /* Unsupported user_check parameter MUST be rejected with -ENOTSUP */
    es.params[1].is_user_check = 1;
    assert(typed_snapshot_ms(ms_frame, 48, &es, &snap) == -ENOTSUP);

    free(cross_page_buf);
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


if __name__ == "__main__":
    unittest.main()
