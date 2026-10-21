import { describe, expect, test } from "bun:test";
import { generateScalarReplacementCandidates } from "./index.ts";

function siteId(number: number): string {
  return "irsite_" + number.toString(16).padStart(32, "0");
}

const location = { file: "src/wallet.c", line: 19, column: 7 };
const facts = [
  {
    schema: "atfield-ir-facts-v1",
    translation_unit: "objects/wallet.o",
    module_id: "irtu_00000000000000000000000000000001",
    source: { input_file: "src/wallet.c", ir_filename: "objects/wallet.ll" },
    complete: true,
    definitions: [
      { symbol: "wallet check", linkage: "external", source_file: "src/wallet.c", line: 17 },
      { symbol: "local helper", linkage: "internal", source_file: "src/wallet.c" },
      { symbol: "empty function", linkage: "external", source_file: "src/wallet.c" },
    ],
    direct_calls: [
      {
        caller: "wallet check",
        callee: "verify signature",
        site_id: siteId(90),
        source: location,
      },
    ],
    unknown_indirect: [
      {
        caller: "wallet check",
        site_id: siteId(91),
        reason: "callee-is-ssa-value",
        source: location,
      },
    ],
    guidance_sites: [
      {
        site_id: siteId(1),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 0,
        source: location,
        kind: "urem",
        width_bits: 32,
        signedness: "unsigned",
        divisor: { operand: 1, status: "constant", value: "1000" },
      },
      {
        site_id: siteId(2),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 1,
        source: { file: "src/wallet.c" },
        kind: "srem",
        width_bits: 32,
        signedness: "signed",
        divisor: { operand: 1, status: "constant", value: "-10" },
      },
      {
        site_id: siteId(3),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 2,
        source: { file: "src/wallet.c", line: 20, column: 9 },
        kind: "icmp",
        predicate: "eq",
        width_bits: 32,
        signedness: "signless",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%remainder" },
          { operand: 1, status: "constant", value: "731" },
        ],
      },
      {
        site_id: siteId(4),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 3,
        source: location,
        kind: "icmp",
        predicate: "eq",
        width_bits: 32,
        signedness: "signless",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%value" },
          { operand: 1, status: "constant", value: "31" },
        ],
      },
      {
        site_id: siteId(5),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 4,
        source: location,
        kind: "icmp",
        predicate: "slt",
        width_bits: 8,
        signedness: "signed",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%small" },
          { operand: 1, status: "constant", value: "-128" },
        ],
      },
      {
        site_id: siteId(6),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 5,
        source: location,
        kind: "icmp",
        predicate: "uge",
        width_bits: 8,
        signedness: "unsigned",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%small_unsigned" },
          { operand: 1, status: "constant", value: "255" },
        ],
      },
      {
        site_id: siteId(9),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 7,
        source: location,
        kind: "icmp",
        predicate: "eq",
        width_bits: 32,
        signedness: "signless",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%value" },
          { operand: 1, status: "constant", value: "4294967295" },
        ],
      },
      {
        site_id: siteId(7),
        function: "wallet check",
        function_linkage: "external",
        block_ordinal: 0,
        instruction_ordinal: 6,
        source: location,
        kind: "switch",
        width_bits: 32,
        selector: { operand: 0, status: "dynamic", value_ref: "%value" },
        default_target: "default",
        cases: [
          { value: "31", status: "constant", target: "case31" },
          { value: "32", status: "constant", target: "case thirty two" },
        ],
      },
      {
        site_id: siteId(8),
        function: "local helper",
        function_linkage: "internal",
        block_ordinal: 0,
        instruction_ordinal: 0,
        source: { file: "src/wallet.c" },
        kind: "icmp",
        predicate: "eq",
        width_bits: 8,
        signedness: "signless",
        operands: [
          { operand: 0, status: "dynamic", value_ref: "%helper_arg" },
          { operand: 1, status: "constant", value: "127" },
        ],
      },
    ],
  },
];

const reachability = [
  {
    ordinal: 0,
    name: "wallet",
    entry_symbol: "wallet check",
    visibility: "public",
    private: false,
    switchless: false,
    reachable_fields: [],
    reachable_functions: ["wallet check"],
    unknown_indirect: false,
    unknown_external: false,
    function_closure_complete: true,
    reachability: "static-may-reach",
    evidence: {},
  },
  {
    ordinal: 1,
    name: "unknown-indirect-selector",
    reachable_functions: ["unrelated function"],
    unknown_indirect: true,
    unknown_external: false,
    function_closure_complete: true,
  },
  {
    ordinal: 2,
    name: "empty-selector",
    reachable_functions: ["empty function"],
    unknown_indirect: false,
    unknown_external: false,
    function_closure_complete: true,
  },
  {
    ordinal: 3,
    name: "unknown-external-selector",
    reachable_functions: ["empty function"],
    unknown_indirect: false,
    unknown_external: true,
    function_closure_complete: true,
  },
  {
    ordinal: 4,
    name: "incomplete-function-closure-selector",
    reachable_functions: ["empty function"],
    unknown_indirect: false,
    unknown_external: false,
    function_closure_complete: false,
    evidence: {
      unknown_indirect_calls: [],
      unknown_external_calls: [],
    },
  },
];

const scalarParams = [
  { ordinal: 0, param_index: 0, width_bits: 32, signedness: "unsigned" },
  { ordinal: 0, param_index: 1, width_bits: 8, signedness: "signed" },
  { ordinal: 0, param_index: 2, width_bits: 8, signedness: "unsigned" },
  { ordinal: 1, param_index: 0, width_bits: 32, signedness: "unsigned" },
  { ordinal: 2, param_index: 0, width_bits: 8, signedness: "unsigned" },
  { ordinal: 3, param_index: 0, width_bits: 8, signedness: "unsigned" },
  { ordinal: 4, param_index: 0, width_bits: 8, signedness: "unsigned" },
];

function generate(params = scalarParams, options = {}) {
  return generateScalarReplacementCandidates(facts, reachability, params, options);
}

function candidateFor(
  candidates: ReturnType<typeof generate>,
  ordinal: number,
  paramIndex: number,
  value: string,
) {
  return candidates.find((item) =>
    item.selector_ordinal === ordinal && item.param_index === paramIndex && item.value === value,
  );
}

describe("static scalar replacement guidance", () => {
  test("strictly accepts the extractor's atfield-ir-facts-v1 JSON shape", () => {
    expect(() => generate()).not.toThrow();

    const wrongSchema = structuredClone(facts) as unknown as Array<Record<string, unknown>>;
    wrongSchema[0].schema = "atfield-explore-guidance-v1";
    expect(() => generateScalarReplacementCandidates(wrongSchema, reachability, scalarParams))
      .toThrow("schema");

  });

  test("generates wallet-style icmp neighborhoods around the static comparison constant", () => {
    const candidates = generate();
    for (const value of ["730", "731", "732"]) {
      expect(candidateFor(candidates, 0, 0, value)).toBeDefined();
    }
    expect(candidateFor(candidates, 0, 0, "731")?.evidence_site_ids).toContain(siteId(3));
  });

  test("generates switch case neighborhoods and merges duplicate evidence", () => {
    const candidates = generate();
    for (const value of ["30", "31", "32", "33"]) {
      expect(candidateFor(candidates, 0, 0, value)).toBeDefined();
    }
    const thirtyOne = candidateFor(candidates, 0, 0, "31");
    expect(thirtyOne?.evidence_site_ids).toEqual([siteId(2), siteId(4), siteId(7)].sort());
    expect(candidates.filter((item) =>
      item.selector_ordinal === 0 && item.param_index === 0 && item.value === "31",
    )).toHaveLength(1);
  });

  test("generates urem and srem divisor and multiple boundaries", () => {
    const candidates = generate();
    for (const value of ["0", "1", "999", "1000", "1001", "1999", "2000", "2001", "2999", "3000", "3001"]) {
      expect(candidateFor(candidates, 0, 0, value)).toBeDefined();
    }
    for (const value of ["-31", "-30", "-29", "-21", "-20", "-19", "-11", "-10", "-9", "0", "1", "19", "20", "21", "29", "30", "31"]) {
      expect(candidateFor(candidates, 0, 1, value)).toBeDefined();
    }
    expect(candidateFor(candidates, 0, 0, "1000")?.evidence_site_ids).toContain(siteId(1));
    expect(candidateFor(candidates, 0, 1, "-10")?.evidence_site_ids).toContain(siteId(2));
  });

  test("respects scalar signedness and width, including signless bit-pattern comparisons", () => {
    const candidates = generate();
    expect(candidateFor(candidates, 0, 1, "-128")).toBeDefined();
    expect(candidateFor(candidates, 0, 1, "-127")).toBeDefined();
    expect(candidateFor(candidates, 0, 1, "-129")).toBeUndefined();
    expect(candidateFor(candidates, 0, 2, "254")).toBeDefined();
    expect(candidateFor(candidates, 0, 2, "255")).toBeDefined();
    expect(candidateFor(candidates, 0, 2, "256")).toBeUndefined();

    const unsignedBits = [
      { ordinal: 0, param_index: 3, width_bits: 32, signedness: "unsigned" },
    ];
    const signedBits = [
      { ordinal: 0, param_index: 4, width_bits: 32, signedness: "signed" },
    ];
    const unsigned = generate(unsignedBits);
    const signed = generate(signedBits);
    expect(candidateFor(unsigned, 0, 3, "4294967295")).toBeDefined();
    expect(candidateFor(signed, 0, 4, "-1")).toBeDefined();
  });

  test("filters by reachable functions and includes all facts for unknown call flags", () => {
    const candidates = generate();
    expect(candidateFor(candidates, 0, 0, "127")).toBeUndefined();

    const unknownIndirect = candidateFor(candidates, 1, 0, "127");
    expect(unknownIndirect?.evidence_site_ids).toContain(siteId(8));

    const unknownExternal = candidateFor(candidates, 3, 0, "127");
    expect(unknownExternal?.evidence_site_ids).toContain(siteId(8));
  });

  test("uses all facts when function closure is incomplete despite empty unknown-call arrays", () => {
    const candidates = generate();
    const incompleteClosure = candidateFor(candidates, 4, 0, "127");
    expect(incompleteClosure?.evidence_site_ids).toContain(siteId(8));
  });

  test("uses generic scalar boundaries only when no fitting IR candidates exist", () => {
    const candidates = generate();
    const fallback = candidates.filter((item) => item.selector_ordinal === 2 && item.param_index === 0);
    expect(fallback.length).toBeGreaterThan(0);
    expect(fallback.map((item) => item.value)).toContain("0");
    expect(fallback.map((item) => item.value)).toContain("255");
    expect(fallback.every((item) => item.evidence_site_ids.length === 0)).toBe(true);
  });

  test("deduplicates, sorts deterministically, and enforces the output budget", () => {
    const all = generate();
    const limited = generate(scalarParams, { budget: 2 });
    expect(limited).toEqual(all.slice(0, 2));
    expect(generate(scalarParams, { budget: 0 })).toEqual([]);
  });

  test("returns only scalar replacements and accepts no buffer mapping fields", () => {
    const candidates = generate();
    expect(candidates.length).toBeGreaterThan(0);
    expect(Object.keys(candidates[0]).sort()).toEqual([
      "evidence_site_ids", "param_index", "priority", "selector_ordinal", "value",
    ]);

    const mappedParams = [{ ...scalarParams[0], offset: 4 }];
    expect(() => generateScalarReplacementCandidates(facts, reachability, mappedParams))
      .toThrow("offset is unsupported");
  });
});

