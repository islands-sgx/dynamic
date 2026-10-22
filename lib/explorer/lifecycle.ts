import { existsSync, readFileSync } from "node:fs";
import { parseStrictJson } from "../bundle/profile-bundle.ts";
import type { ScalarMutationRule } from "./contract.ts";

export interface LifecycleCost {
  readonly realEcalls: number;
  readonly enclaveInstances: number;
  readonly prefixReplays: number;
  readonly interruptedEcalls: number;
}

export function readLifecycleCost(filename: string, mutation?: ScalarMutationRule): LifecycleCost | undefined {
  if (!existsSync(filename)) return undefined;
  const pending = new Set<string>();
  const generations = new Set<number>();
  const entered = new Set<string>();
  let realEcalls = 0;
  let prefixReplays = 0;
  let targetReached = false;
  for (const line of readFileSync(filename, "utf8").trimEnd().split("\n")) {
    const record = parseStrictJson(line, "lifecycle journal");
    if (record === null || typeof record !== "object" || Array.isArray(record)) {
      throw new TypeError("lifecycle journal record must be an object");
    }
    if (!("event" in record) || !("generation" in record) || !("callSeq" in record) ||
        !("selectorOrdinal" in record) || !("selectorSeq" in record)) {
      throw new TypeError("lifecycle journal record is missing call identity");
    }
    const { event, generation, callSeq, selectorOrdinal, selectorSeq } = record;
    if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1 ||
        typeof callSeq !== "number" || !Number.isSafeInteger(callSeq) || callSeq < 0 ||
        typeof selectorOrdinal !== "number" || !Number.isSafeInteger(selectorOrdinal) ||
        typeof selectorSeq !== "number" || !Number.isSafeInteger(selectorSeq) || selectorSeq < 0) {
      throw new TypeError("lifecycle journal has invalid call identity");
    }
    const key = generation + ":" + callSeq;
    if (event === "enclave_created") {
      if (generations.has(generation)) throw new TypeError("duplicate enclave creation in lifecycle journal");
      generations.add(generation);
    } else if (event === "ecall_enter") {
      if (!generations.has(generation) || entered.has(key)) throw new TypeError("invalid ECALL entry in lifecycle journal");
      entered.add(key);
      pending.add(key);
      realEcalls++;
      const target = mutation && generation === (mutation.targetGeneration ?? 1) &&
        selectorOrdinal === mutation.selectorOrdinal && selectorSeq === mutation.selectorSeq;
      if (target) targetReached = true;
      if (mutation && (mutation.execMode ?? 0) >= 1 && !targetReached) prefixReplays++;
    } else if (event === "ecall_return") {
      if (!pending.delete(key)) throw new TypeError("ECALL return has no entry in lifecycle journal");
    } else {
      throw new TypeError("unknown lifecycle event");
    }
  }
  return { realEcalls, enclaveInstances: generations.size, prefixReplays, interruptedEcalls: pending.size };
}
