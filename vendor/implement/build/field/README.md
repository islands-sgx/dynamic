# Field IDs and boundary transformation

atfield-field consumes optimized LLVM IR after ordinary optimization. It converts each annotate("atfield.field.v1") function into a normal ABI field_enter(uint64_t) call, a call marker, a shared normal-close/field_exit(uint64_t) path, and reserved symbols consumed by the assembly stage. The MC-based assembly transformer recognizes the call marker as a structured x86 instruction and emits a same-size direct jump to the later pretouch block. It retains the original call/return ABI effects in LLVM IR until register allocation is complete.

## Per-object interface

The compile wrapper knows the stable payload ordinal and output object path. It writes the transformed IR and a sidecar manifest beside that object:

    atfield-field ir \
      --payload-ordinal "$payloadOrdinal" \
      --input "$optimizedIR" \
      --output "$boundaryIR" \
      --manifest "$outputFile.field.json"

    # Run pinned llc on boundaryIR with -filetype=asm.
    atfield-field asm \
      --manifest "$outputFile.field.json" \
      --input "$llcAssembly" \
      --output "$outputFile"

The ir command writes an empty manifest for a translation unit without Fields. The wrapper can leave its ordinary object path unchanged for an empty manifest. This gives the link launcher one deterministic sidecar path per linked object without directory scans.

The link launcher passes the manifests for the exact linked object list, in any response-file expansion order, to:

    atfield-field merge \
      --manifest object1.o.field.json \
      --manifest object2.o.field.json \
      --out fields.json

Merge sorts by (payloadOrdinal, functionOrdinal) and rejects duplicate IDs and duplicate order keys. It reads only the explicitly supplied manifests.

## ID and manifest rules

A Field ID is FNV-1a 64 over the 16 little-endian bytes of payloadOrdinal followed by functionOrdinal, using the standard FNV-1a 64 offset basis and prime. A zero result maps to one. The linker-side merge checks collisions across all object manifests and stops the build if any occur. The transform also checks for an in-payload collision. The C++ ABI uses the uint64 value; JSON stores IDs and payload ordinals as canonical 0x plus 16 lowercase hex digits so JavaScript parsers preserve them. Symbol suffixes use the canonical unsigned decimal ID expected by the MC transformer.

Each field includes its readable name/demangled_name, exact function/linkage_name, explicit payload/function order, marker, continuation, body, pretouch, enter, close, and exit symbols. A stack annotation may provide a positive stack_bytes; when the sample's plain ATFIELD has no stack bound, the value is JSON null, leaving the whole committed normal REG stack for workset analysis. selectors starts as an empty array; selector reachability is supplied separately by sample integration.

name and demangled_name use LLVM's Itanium demangler. function and linkage_name are the exact symbol name in the IR/ELF. A selector may use a readable name only when it identifies one Field in the linked artifact; an ambiguous name must be specified by linkage name.
