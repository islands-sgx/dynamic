import { expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { readLifecycleCost } from "../../lib/explorer/lifecycle.ts";

test("lifecycle costs include earlier generations and a call interrupted before capture", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "lifecycle-cost-"));
  try {
    const filename = path.join(directory, "lifecycle.jsonl");
    const record = (event: string, generation: number, callSeq: number, selectorOrdinal = 0) =>
      ({ event, generation, callSeq, selectorOrdinal, selectorSeq: 0 });
    writeFileSync(filename, [record("enclave_created", 1, 0, -1), record("ecall_enter", 1, 0),
      record("ecall_return", 1, 0), record("enclave_created", 2, 0, -1),
      record("ecall_enter", 2, 1), record("ecall_return", 2, 1),
      record("ecall_enter", 2, 2, 1)].map((item) => JSON.stringify(item)).join("\n") + "\n");
    expect(readLifecycleCost(filename, { targetGeneration: 2, execMode: 1, selectorOrdinal: 1,
      selectorSeq: 0, paramIndex: 0, widthBytes: 4, signedness: "unsigned",
      expectedBits: "0x00000000", replacementBits: "0x00000001" })).toEqual({
      realEcalls: 3, enclaveInstances: 2, prefixReplays: 2, interruptedEcalls: 1,
    });
    writeFileSync(filename, JSON.stringify(record("ecall_return", 1, 0)) + "\n");
    expect(() => readLifecycleCost(filename)).toThrow(/no entry/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
