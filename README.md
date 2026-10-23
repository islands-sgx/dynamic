# ATField-SGX dynamic trace and Field workset

This checkout owns the current Bun/TypeScript trace and workset tools, online candidate explorer, and native SGX measurement collector. The canonical pipeline starts from an implement Profile bundle and produces a bundle-bound trace, a per-Field workset, and a formal Final v2 hardware verdict.

The reported historical study was collected by the retired Python controller and SGX-Step evaluation chain. Its exact source, SQLite research fixture, frozen tables, and evidence remain at tag archive/python-acquisition-0446fc3 (commit 0446fc3f49c0b5eb17bc1db97368a76480531a6c). This checkout does not rerun or recompute those historical results. Retrieve the archived tables with:

```bash
git show archive/python-acquisition-0446fc3:README.md
git show archive/python-acquisition-0446fc3:experiments/SUMMARY_TABLES.md
```

## Current workflow

1. The pinned implement build produces and verifies the Profile bundle.
2. cli/run.ts runs a host through the native collector and stores canonical JSONL trace artifacts bound to that bundle.
3. cli/atfield-workset.ts validates traces against the same bundle and produces the FieldTargetPages workset.
4. The implement build runs pretouch verify as a build-time ELF/workset identity check, then readiness.ts emits the ReadyTable. This step is separate from formal hardware acceptance.
5. Freeze the full Final v2 artifact identity with cli/freeze-final-v2-target.ts. Then run cli/run.ts in verify-pretouch mode with c-preserve-tlb gate mode and the native collector. Formal acceptance checks the raw S3 page-effect set across all four gates.

Online candidate exploration and corpus validation remain available through cli/explore.ts. The native interposer and vendored SGX-Step collector provide the canonical observations.

## Example with the pinned yescrypt Profile bundle

These commands use the published sample flake shell and the pinned bundle already built under sample/build. On TDX, cli/run.ts and cli/explore.ts need root access to /dev/sgx-step and /dev/mem, so run those hardware commands with sudo -E. Set TRACE to the trace JSONL path reported by the first command before building the workset.

```bash
# Build the native collector and vendored SGX-Step page-table helper
mkdir -p build
nix develop ../sample#bench-yescrypt-kdf-rw-protect --command cc -std=gnu11 -O2 -Wno-unused-result -DLIBSGXSTEP_SILENT=1 -fPIC -shared -Isrc -Ivendor/sgxstep src/native_sgx_interpose.c src/interpose_mutation.c vendor/sgxstep/libsgxstep/pt.c vendor/sgxstep/libsgxstep/file.c vendor/sgxstep/libsgxstep/debug.c -pthread -lcrypto -ldl -Wl,-z,defs -o build/libatfield_native_sgx.so

PROFILE_BUNDLE=../sample/build/bench/yescrypt-kdf-rw/protect.reprofile-20261023-pinned/profile-bundle.json
COLLECTOR=build/libatfield_native_sgx.so
RUN_DIR=../sample/build/bench/yescrypt-kdf-rw/protect.reprofile-20261023-pinned/profile-traces
sudo -E nix develop ../sample#bench-yescrypt-kdf-rw-protect --command bun cli/run.ts --bundle "$PROFILE_BUNDLE" --collector "$COLLECTOR" --mode profile --sample yescrypt-kdf-rw --artifact-dir "$RUN_DIR" -- --self-test
nix develop ../sample#bench-yescrypt-kdf-rw-protect --command bun cli/atfield-workset.ts --bundle "$PROFILE_BUNDLE" --trace "$TRACE" --out "$RUN_DIR/workset.json"

# Show all required inputs for freezing a fresh Final v2 target
nix develop ../sample#bench-yescrypt-kdf-rw-protect --command bun cli/freeze-final-v2-target.ts --help

# Run the pinned Final v2 target through four-gate C-preserve-TLB verification
FINAL_DIR=../sample/build/bench/yescrypt-kdf-rw/protect.reprofile-20261023-pinned
sudo -E nix develop ../sample#bench-yescrypt-kdf-rw-protect --command bun cli/run.ts --bundle "$PROFILE_BUNDLE" --final-v2-target "$FINAL_DIR/final-v2-run-target.json" --mode verify-pretouch --gate-mode c-preserve-tlb --collector "$COLLECTOR" --artifact-dir "$FINAL_DIR/final-v2-recheck" -- --self-test

# Optional online exploration over the same yescrypt bundle
sudo -E nix develop ../sample#bench-yescrypt-kdf-rw-protect --command bun cli/explore.ts --bundle "$PROFILE_BUNDLE" --corpus "$RUN_DIR/corpus" --role main --collector "$COLLECTOR" -- --self-test
```
