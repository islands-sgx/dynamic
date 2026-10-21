# Native collector trace contract

## Canonical JSONL: `atfield-canonical-trace-v1`

One runner invocation writes UTF-8 JSONL: one `run_start`, zero or more `ecall`, then one `run_end`. Every record has `schema`, `record_type`, `run_id`, `layout_epoch`, and `instance_generation`; use null on `run_start` before the first successful create, then the assigned generation on ECALL records and the final generation on `run_end`. A consumer marks the run `complete` only if start/end exist once, every line parses, `ecall.call_seq` is contiguous, the process exits without timeout, and no required measurement is invalid. Otherwise mark `incomplete`, retain records and reasons, and exclude the run from complete measurements. Per-field required gates are mode-declared; a missing required gate makes that field incomplete.

- `run_start`: `schema="atfield-canonical-trace-v1"`, sample/mode, run ID, start time, and minimum bundle identity: SHA-256 for selected enclave, host, interposer, schema/manifest, plus their artifact paths or immutable IDs.
- `ecall`: unique run-wide `call_seq` for every measured record; `instance_generation`; `ecall_index` (selector ordinal); `selector_seq` (zero-based invocation count for that index in the generation); tag; elapsed time; SGX transport status; validity and reasons; page effects; application result; diagnostics.
- `run_end`: process return code, timeout, ECALL record count, `completion`, `incomplete_reasons`. The runner `.meta.json` stores full trace SHA-256, stdout/stderr or artifact paths, and the same completion decision. Do not put a hash of the whole JSONL inside itself.

`call_seq` advances for every emitted measurement, including nested replay/intervention records. `selector_seq` belongs to the originating host ECALL and is inherited by nested records; the records still get distinct `call_seq` and tags. This preserves both global record order and selector identity.

## Evidence and semantics

- `fields[]` carries `field_id`, named gate intervals `s0..s3`, interval durations, and `page_effects`. Boundaries follow host-gate snapshots: S0 at gate 10, S1 at 30, S2 at 50, S3 at 70. Each snapshot is followed by A/D clear except final S3. Encode each page as `{rva, a: bool, d: bool}`; keep A and D independently (D can coexist with A), state page size and set completeness. `ecall_ad` is only the post-call aggregate. A/D page effects are the primary access evidence.
- `aex` is a diagnostic object with count and optional `fault_events`. AEX first-touch/healed-PTE observations are debug evidence only; they cannot establish page access, field completeness, or a business result. The AEP hook sees only some strict-retracted pages and can miss accesses.
- `layout_epoch` is a stable fingerprint of effective signer/excluded ranges, TCS/SSA, stack, pretouch/gate RVAs, page size, and selected enclave SHA-256. A changed fingerprint is a new epoch; sample name alone does not identify layout.
- `instance_generation` increments on each successful enclave creation. Scope selector sequence to generation; this prevents joining reused enclave IDs/RVAs across destroy/create.
- Preserve separate `sgx_status`, ABI return type/value, and `out_status_i32`. Use `business_result: {status, value, source}` only when an application-specific adapter defines the meaning; otherwise set status to `unknown`. SGX success is transport status, not business success.

## Minimal implementation points

1. `src/native_sgx_interpose.c:34-36`: trace currently opens in append mode. Use a fresh per-run file; check open/write/flush failures and JSON-escape every string.
2. `src/native_sgx_interpose.c:311-398,427-503`: allocate record `call_seq` at measured-call entry; add schema, run/layout/generation IDs, explicit A/D booleans, result and diagnostics; mark missing required gates and collector failures incomplete.
3. `src/native_sgx_interpose.c:517-579`: current `call_seq` and `selector_seq` advance only in the outer wrapper; nested measurements reuse both. Keep origin `selector_seq`, add a separate record sequence per emitted measurement.
4. `src/interpose_state.h:157-159` stores process counters only. Add generation and layout fingerprint there; assign generation at successful create/destroy boundaries `src/native_sgx_interpose.c:7-48,652-658`.
5. Four-gate page snapshots are collected at `src/interpose_4gate_aep.h:410-462`; AEX first-touch/debug observations at `src/interpose_4gate_aep.h:53-114`. Serialize them as distinct evidence.
6. `tools/run_native_sgx.py:35-74,180-202`: compute/pass run ID and effective layout epoch; include bundle digests. `tools/run_native_sgx.py:218-277`: after process exit, append `run_end`, validate JSONL/sequence/completion, and persist full trace hash plus stdout/stderr and completion in `.meta.json`.
