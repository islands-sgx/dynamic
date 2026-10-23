# ATField-SGX dynamic trace and Field workset

This checkout owns the current Bun/TypeScript trace and workset tools, online candidate explorer, and native SGX measurement collector. The canonical pipeline starts from an implement Profile bundle and produces a bundle-bound trace, a per-Field workset, and a formal Final v2 hardware verdict.

The reported historical study came from the retired Python acquisition chain and its companion test-only hidden evaluator. Their source, tracked fixtures, frozen tables, and checked-in evaluation JSON remain at tag archive/python-acquisition-0446fc3 (commit 0446fc3f49c0b5eb17bc1db97368a76480531a6c); raw per-run traces are not included in that tag. This checkout does not rerun or recompute those historical results. Retrieve the archived tables with:

```bash
git show archive/python-acquisition-0446fc3:README.md
git show archive/python-acquisition-0446fc3:experiments/SUMMARY_TABLES.md
```

## Current workflow

1. The pinned implement build produces and verifies the Profile bundle.
2. cli/run.ts runs a host through the native collector and stores canonical JSONL trace artifacts bound to that bundle.
3. cli/atfield-workset.ts validates traces against the same bundle and produces the FieldTargetPages workset.
4. The implement build runs pretouch verify as a build-time ELF/workset identity check, then readiness.ts emits the ReadyTable. This step is separate from formal hardware acceptance.
5. Freeze a full Final v2 artifact identity for the current Profile bundle and generated Final with cli/freeze-final-v2-target.ts. Re-freeze after any sample path or layout migration, then run cli/run.ts in verify-pretouch mode with c-preserve-tlb gate mode and the native collector. Formal acceptance checks the raw S3 page-effect set across all four gates.

Online candidate exploration and corpus validation remain available through cli/explore.ts. The native interposer and vendored SGX-Step collector provide the canonical observations.

## Example with the current yescrypt Profile bundle

The sample tree now places this workload under bench/micro. Rebuild the
current protect target first; it produces the Profile bundle at the new path
below. A Final v2 target frozen before the sample migration is stale, so
regenerate and freeze a new target from this bundle before formal
verify-pretouch. On TDX, cli/run.ts and cli/explore.ts need root access to
/dev/sgx-step and /dev/mem; run those hardware commands with sudo -E.

```bash
# From the sample checkout, rebuild the migrated protect target
(cd ../sample && nix develop --no-write-lock-file .#bench-micro-yescrypt-kdf-rw-protect --command just build bench/micro yescrypt-kdf-rw protect)

SAMPLE_SHELL='../sample#bench-micro-yescrypt-kdf-rw-protect'
PROFILE_BUNDLE=../sample/build/bench/micro/yescrypt-kdf-rw/protect/profile-bundle.json
COLLECTOR=build/libatfield_native_sgx.so
RUN_DIR=../sample/build/bench/micro/yescrypt-kdf-rw/protect/profile-traces

# Build the native collector and vendored SGX-Step page-table helper
mkdir -p build
nix develop --no-write-lock-file "$SAMPLE_SHELL" --command cc -std=gnu11 -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 -fPIC -shared -Isrc -Ivendor/sgxstep src/native_sgx_interpose.c src/interpose_mutation.c vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c vendor/sgxstep/libsgxstep/debug.c -pthread -lcrypto -ldl -Wl,-z,defs -o "$COLLECTOR"

sudo -E nix develop --no-write-lock-file "$SAMPLE_SHELL" --command bun cli/run.ts --bundle "$PROFILE_BUNDLE" --collector "$COLLECTOR" --mode profile --sample yescrypt-kdf-rw --artifact-dir "$RUN_DIR" -- --self-test
# Set TRACE to the JSONL path reported by the profile command.
nix develop --no-write-lock-file "$SAMPLE_SHELL" --command bun cli/atfield-workset.ts --bundle "$PROFILE_BUNDLE" --trace "$TRACE" --out "$RUN_DIR/workset.json"

# Show the inputs for freezing a new Final v2 target from the migrated build
nix develop --no-write-lock-file "$SAMPLE_SHELL" --command bun cli/freeze-final-v2-target.ts --help

# Optional online exploration over the same current bundle
sudo -E nix develop --no-write-lock-file "$SAMPLE_SHELL" --command bun cli/explore.ts --bundle "$PROFILE_BUNDLE" --corpus "$RUN_DIR/corpus" --role main --collector "$COLLECTOR" -- --self-test

# Formal verification after freezing a fresh Final v2 target
sudo -E nix develop --no-write-lock-file "$SAMPLE_SHELL" --command bun cli/run.ts --bundle "$PROFILE_BUNDLE" --final-v2-target "${FINAL_V2_TARGET:?set to the newly frozen target manifest}" --mode verify-pretouch --gate-mode c-preserve-tlb --collector "$COLLECTOR" --artifact-dir "$RUN_DIR/final-v2-recheck" -- --self-test
```

Set FINAL_V2_TARGET to the manifest emitted by a fresh freeze command before
running formal verification.
