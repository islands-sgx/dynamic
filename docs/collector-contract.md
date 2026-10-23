# Canonical trace and workset contract

## Current flow

The current pipeline starts with a Profile bundle produced by the pinned implement build:

1. lib/bundle/profile-bundle.ts validates the Profile manifest, artifact paths, and SHA-256 identities.
2. cli/run.ts calls lib/runner/canonical-runner.ts to run the selected host. The runner binds the trace to the bundle and records process completion, stdout/stderr, and artifact digests.
3. The native interposer in src/native_sgx_interpose.c collects gate observations using the vendored SGX-Step collector under vendor/sgxstep/.
4. cli/atfield-workset.ts checks canonical traces against the same Profile bundle and lib/workset/build.ts creates the per-Field workset. It rejects duplicate run IDs and preserves Field, page, and effect identity.
5. The implement build runs pretouch verify as a build-time ELF/workset identity check, then readiness.ts emits the ReadyTable. Formal Final v2 hardware acceptance freezes all artifacts with cli/freeze-final-v2-target.ts and runs cli/run.ts in verify-pretouch mode with c-preserve-tlb gate mode and the native collector; its verdict evaluates raw S3 page effects across four gates.

cli/explore.ts also provides online candidate exploration and validated corpus collection over the Profile and trace contract. The historical Python controller, evaluator, harness, scenario/oracle build path, and SQLite research fixture were retired from this checkout; the exact source, artifacts, and frozen tables remain at tag archive/python-acquisition-0446fc3. Current README examples describe the Bun path and make no claim that historical tables were recomputed.

## Canonical JSONL: atfield-canonical-trace-v1

A run contains one run_start, zero or more ecall records, then one run_end. Every record carries the schema, record type, run ID, layout epoch, and instance generation. A consumer accepts a run as complete only when its boundaries are present once, every line parses, ECALL call sequences are contiguous, the process exits without timeout, and all required measurements are valid. Otherwise it records an incomplete result and the reasons.

- run_start binds sample and mode, run ID, start time, and Profile artifact identities.
- ecall records use a run-wide call_seq, instance_generation, selector ordinal and invocation sequence, tag, elapsed time, SGX transport status, measurement validity, page effects, application result, and diagnostics.
- run_end records process status, timeout, ECALL count, completion, and incomplete reasons. Persist the full trace digest and process output in run metadata. Do not include the digest of the entire JSONL inside the JSONL itself.

call_seq advances for every emitted measurement, including nested replay/intervention records. selector_seq belongs to the originating host ECALL and is inherited by nested records. Distinct record sequences preserve both global ordering and selector identity.

## Evidence and semantics

- fields[] carries a field_id, named gate intervals s0..s3, interval durations, and page_effects. Boundaries follow the host-gate snapshots: S0 at gate 10, S1 at 30, S2 at 50, S3 at 70. Each snapshot is followed by A/D clear except final S3. Encode each page as {rva, a: bool, d: bool} and retain A and D independently.
- aex is diagnostic evidence. AEP first-touch and healed-PTE observations cannot establish page access, Field completeness, or business success; the AEP hook can miss accesses.
- layout_epoch fingerprints effective signer/excluded ranges, TCS/SSA, stack, pretouch/gate RVAs, page size, and selected enclave digest. A changed fingerprint is a new epoch.
- instance_generation increments on successful enclave creation. Scope selector sequence to a generation so reused enclave IDs/RVAs cannot be joined across destroy/create.
- Preserve SGX transport status, ABI return value, and application status separately. SGX success alone does not establish business success.
- Final-v2 acceptance judges the raw S3_BODY.page_effects set. It does not subtract S2 observations or optional Gate C diagnostics.

## Code map

- Profile identity: lib/bundle/profile-bundle.ts
- Host execution and trace artifacts: cli/run.ts, lib/runner/canonical-runner.ts
- Trace parsing and bundle binding: lib/workset/trace.ts
- Workset aggregation: cli/atfield-workset.ts, lib/workset/build.ts
- Native measurement: src/native_sgx_interpose.c, src/interpose_4gate_aep.h, vendor/sgxstep/
- Historical source and frozen tables: tag archive/python-acquisition-0446fc3
