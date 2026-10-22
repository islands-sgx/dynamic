import { expect, test } from "bun:test";
import { proveColdFirstFieldTransfer } from "../../lib/explorer/cold-proof.ts";
import type { CallCaptureDocument, CallCaptureEvent } from "../../lib/explorer/contract.ts";

const digest = "a7".repeat(32);
const address = "0x7abc000";

function trace(records: Array<Record<string, unknown>>): string {
  const common = {
    schema: "atfield-canonical-trace-v1",
    run_id: "run-cold-proof-fixture",
    layout_epoch: "epoch-fixture",
    bundle_manifest_sha256: "b1".repeat(32),
  };
  const calls = records.map((record, callSeq) => ({
    ...common,
    record_type: "ecall",
    call_seq: callSeq,
    instance_generation: record.generation,
    selector_ordinal: record.selectorOrdinal,
    selector_seq: record.selectorSeq,
    measurement_valid: true,
    measurement_invalid_reasons: [],
    fields: record.fields,
  }));
  return [
    JSON.stringify({ ...common, record_type: "run_start", instance_generation: null }),
    ...calls.map((record) => JSON.stringify(record)),
    JSON.stringify({
      ...common,
      record_type: "run_end",
      instance_generation: calls.at(-1)?.instance_generation ?? null,
      record_count: calls.length,
      completion: "complete",
      termination: "exited",
      process_return_code: 0,
      timeout: false,
      incomplete_reasons: [],
    }),
  ].join("\n") + "\n";
}

function event(
  generation: number,
  callSeq: number,
  selectorOrdinal: number,
  selectorSeq: number,
  input: CallCaptureEvent["bufferInputs"] = [],
  output: CallCaptureEvent["bufferOutputs"] = [],
): CallCaptureEvent {
  return {
    generation,
    callSeq,
    selectorOrdinal,
    selectorSeq,
    transportStatus: 0,
    scalarInputs: [],
    bufferInputs: input,
    bufferOutputs: output,
    retval: null,
    scalarOutputs: [],
    mutation: null,
  };
}

function output(sha: string | undefined = digest, storageAddress = address) {
  return {
    paramIndex: 2,
    direction: "out" as const,
    isString: false,
    elementSize: 1,
    byteLength: 1024,
    fnv1a64: "0x0000000000000000",
    prefixHex: "deed",
    ...(sha ? { sha256: sha } : {}),
    storageAddress,
  };
}

function input(sha: string | undefined = digest, storageAddress = address, direction: "in" | "inout" = "in") {
  return {
    paramIndex: 2,
    direction,
    isString: false,
    elementSize: 1,
    byteLength: 1024,
    fnv1a64: "0x0000000000000000",
    prefixHex: "deed",
    ...(sha ? { sha256: sha } : {}),
    storageAddress,
  };
}

function capture(events: CallCaptureEvent[]): CallCaptureDocument {
  return {
    bundleManifestSha256: "b1".repeat(32),
    marshalLayoutSha256: "c2".repeat(32),
    runId: "run-cold-proof-fixture",
    events,
    end: {
      processReturnCode: 0,
      termination: "exited",
      timedOut: false,
      complete: true,
      ecallCount: events.length,
      targetMatchCount: 0,
      mutationAppliedCount: 0,
      incompleteReasons: [],
    },
  };
}

function validTrace() {
  return trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 1, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]);
}

test("proves a wallet-like object consumed by the fresh generation first measured Field", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 1, 0),
    event(2, 2, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, validTrace());
  expect(result.status).toBe("proved");
  expect(result.opportunityCount).toBe(1);
  expect(result.provenTransfers).toHaveLength(1);
  expect(result.provenTransfers[0]).toMatchObject({
    source: { generation: 1, callSeq: 0, selectorOrdinal: 4, selectorSeq: 0, paramIndex: 2 },
    consumer: { generation: 2, callSeq: 2, selectorOrdinal: 7, selectorSeq: 0, paramIndex: 2 },
    sha256: digest,
    byteLength: 1024,
    elementSize: 1,
    storageAddress: address,
    scope: "same_process_fresh_enclave",
    crossProcessPortabilityProven: false,
  });
});

test("uses full-buffer SHA-256 even when the retained prefix is shorter than the object", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("proved");
  expect(result.provenTransfers[0]?.byteLength).toBe(1024);
});

test("reports a same-address opportunity without claiming a transfer when full digests differ", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output("b8".repeat(32))]),
    event(2, 1, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("absent");
  expect(result.opportunityCount).toBe(1);
  expect(result.provenTransfers).toHaveLength(0);
  expect(result.reason).toContain("full SHA-256");
});

test("rejects ambiguous latest writers at the same prior-generation call position", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output(), { ...output(), paramIndex: 3 }]),
    event(2, 1, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("absent");
  expect(result.opportunityCount).toBe(1);
  expect(result.generations[0]?.reason).toContain("ambiguous");
});

test("rejects invalid canonical trace and reports a generation with no measured Field", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 1, 0),
  ]);
  const valid = trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 1, selectorSeq: 0, fields: [] },
  ]);
  const noField = proveColdFirstFieldTransfer(document, valid);
  expect(noField.status).toBe("absent");
  expect(noField.reason).toContain("measured Field entry");

  const malformed = valid.replace('"call_seq":1', '"call_seq":3');
  const invalid = proveColdFirstFieldTransfer(document, malformed);
  expect(invalid.status).toBe("invalid");
  expect(invalid.reason).toContain("invalid ECALL record");
});

test("uses the latest matching writer across all prior enclave generations", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 3, 0),
    event(3, 2, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 3, selectorSeq: 0, fields: [] },
    { generation: 3, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("proved");
  expect(result.provenTransfers[0]?.source.generation).toBe(1);
  expect(result.provenTransfers[0]?.consumer.generation).toBe(3);
});

test("a newer prior-generation write supersedes an older matching digest", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 3, 0, [], [output("b8".repeat(32))]),
    event(3, 2, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 3, selectorSeq: 0, fields: [] },
    { generation: 3, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("absent");
  expect(result.opportunityCount).toBe(1);
  expect(result.provenTransfers).toHaveLength(0);
  expect(result.reason).toContain("full SHA-256");
});

test("rejects a same-address initialization write before the fresh generation first Field", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 3, 0, [], [output()]),
    event(2, 2, 7, 0, [input()]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 3, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("absent");
  expect(result.opportunityCount).toBe(1);
  expect(result.provenTransfers).toHaveLength(0);
  expect(result.reason).toContain("intervening same-generation output");
});

test("does not count inout destination buffers as prior-generation input objects", () => {
  const document = capture([
    event(1, 0, 4, 0, [], [output()]),
    event(2, 1, 7, 0, [input(digest, address, "inout")]),
  ]);
  const result = proveColdFirstFieldTransfer(document, trace([
    { generation: 1, selectorOrdinal: 4, selectorSeq: 0, fields: [] },
    { generation: 2, selectorOrdinal: 7, selectorSeq: 0, fields: [{ field_id: "fixture-field" }] },
  ]));
  expect(result.status).toBe("absent");
  expect(result.opportunityCount).toBe(0);
  expect(result.provenTransfers).toHaveLength(0);
  expect(result.reason).toContain("no same-address, same-shape");
});
