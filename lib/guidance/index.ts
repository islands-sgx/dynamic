export const IR_FACTS_SCHEMA = "atfield-ir-facts-v1" as const;

type IRStatus = "constant" | "dynamic" | "unknown";
type IRSignedness = "signed" | "unsigned" | "signless";

interface SourceLocation {
  file: string;
  line?: number;
  column?: number;
}

interface IntegerOperand {
  operand: 0 | 1;
  status: IRStatus;
  value?: string;
  value_ref?: string;
}

interface SiteBase {
  site_id: string;
  function: string;
  function_linkage: string;
  block_ordinal: number;
  instruction_ordinal: number;
  source: SourceLocation;
}

interface IcmpSite extends SiteBase {
  kind: "icmp";
  predicate: string;
  width_bits: number | null;
  vector_lanes?: number | null;
  signedness: IRSignedness;
  operands: [IntegerOperand, IntegerOperand];
}

interface SwitchSite extends SiteBase {
  kind: "switch";
  width_bits: number | null;
  selector: IntegerOperand;
  default_target?: string;
  cases: Array<{ value?: string; status: "constant" | "unknown"; target?: string }>;
}

interface RemainderSite extends SiteBase {
  kind: "urem" | "srem";
  width_bits: number | null;
  vector_lanes?: number | null;
  signedness: "signed" | "unsigned";
  divisor: IntegerOperand;
}

type GuidanceSite = IcmpSite | SwitchSite | RemainderSite;

interface IRFactsV1 {
  schema: typeof IR_FACTS_SCHEMA;
  translation_unit: string;
  module_id: string;
  source: { input_file: string; ir_filename: string };
  complete: boolean;
  definitions: Array<{ symbol: string; linkage: string; source_file: string; line?: number }>;
  direct_calls: Array<{ caller: string; callee: string; site_id: string; source: SourceLocation }>;
  unknown_indirect: Array<{ caller: string; site_id: string; reason: string; source: SourceLocation }>;
  guidance_sites: GuidanceSite[];
}

export interface SelectorReachability {
  ordinal: number;
  reachable_functions: string[];
  unknown_indirect: boolean;
  unknown_external: boolean;
  function_closure_complete: boolean;
}

export interface ScalarParameter {
  ordinal: number;
  param_index: number;
  width_bits: number;
  signedness: "signed" | "unsigned";
}

export interface ScalarReplacementCandidate {
  selector_ordinal: number;
  param_index: number;
  /** Canonical decimal text preserves full-width 64-bit and wider scalar values. */
  value: string;
  priority: number;
  evidence_site_ids: string[];
}

export interface CandidateOptions {
  /** Maximum number of candidates across all selectors and scalar parameters. Defaults to 256. */
  budget?: number;
}

const MAX_WIDTH_BITS = 256;
const DEFAULT_BUDGET = 256;
const GENERIC_VALUES = [
  "0", "1", "-1", "2", "3", "7", "8", "15", "16", "31", "32",
  "63", "64", "127", "128", "255", "256", "65535", "65536", "-2",
];

function fail(message: string): never {
  throw new TypeError(message);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!isObject(value)) fail(label + " must be an object");
  return value;
}

function keys(
  value: Record<string, unknown>,
  required: string[],
  optional: string[],
  label: string,
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail(label + "." + key + " is required");
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(label + "." + key + " is unsupported");
  }
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(label + " must be a nonempty string without NUL");
  }
  return value;
}

function integer(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    fail(label + " must be a safe integer at least " + minimum);
  }
  return value;
}

function canonicalInteger(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^-?(0|[1-9][0-9]*)$/.test(value)) {
    fail(label + " must be a canonical decimal integer");
  }
  return BigInt(value);
}

function validateSource(value: unknown, label: string): SourceLocation {
  const source = object(value, label);
  keys(source, ["file"], ["line", "column"], label);
  string(source.file, label + ".file");
  if (source.line !== undefined) integer(source.line, label + ".line");
  if (source.column !== undefined) integer(source.column, label + ".column");
  return value as SourceLocation;
}

function validateSiteId(value: unknown, label: string, seen: Set<string>): string {
  if (typeof value !== "string" || !/^irsite_[0-9a-f]{32}$/.test(value)) {
    fail(label + " must be a stable irsite identifier");
  }
  if (seen.has(value)) fail(label + " is duplicated");
  seen.add(value);
  return value;
}

const LINKAGES = new Set([
  "private", "internal", "available_externally", "linkonce", "weak", "common", "appending",
  "extern_weak", "linkonce_odr", "weak_odr", "external",
]);

function validateLinkage(value: unknown, label: string): string {
  if (typeof value !== "string" || !LINKAGES.has(value)) fail(label + " is not a supported LLVM linkage");
  return value;
}

function validateOperand(value: unknown, expected: 0 | 1, label: string): IntegerOperand {
  const operand = object(value, label);
  keys(operand, ["operand", "status"], ["value", "value_ref"], label);
  if (operand.operand !== expected) fail(label + ".operand must be " + expected);
  if (operand.status === "constant") {
    keys(operand, ["operand", "status", "value"], [], label);
    canonicalInteger(operand.value, label + ".value");
    return value as IntegerOperand;
  }
  if (operand.status === "dynamic") {
    keys(operand, ["operand", "status", "value_ref"], [], label);
    const reference = string(operand.value_ref, label + ".value_ref");
    if (!/^[@%].+/.test(reference)) fail(label + ".value_ref must name an LLVM value");
    return value as IntegerOperand;
  }
  if (operand.status === "unknown") {
    keys(operand, ["operand", "status"], [], label);
    return value as IntegerOperand;
  }
  return fail(label + ".status must be constant, dynamic, or unknown");
}

function validateWidth(value: unknown, label: string): number | null {
  if (value === null) return null;
  const width = integer(value, label, 1);
  if (width > MAX_WIDTH_BITS) fail(label + " exceeds supported width " + MAX_WIDTH_BITS);
  return width;
}

function validateSiteBase(
  site: Record<string, unknown>,
  label: string,
  definitions: Map<string, string>,
  seen: Set<string>,
): SiteBase {
  const siteId = validateSiteId(site.site_id, label + ".site_id", seen);
  const functionName = string(site.function, label + ".function");
  if (!definitions.has(functionName)) fail(label + ".function is not a local definition");
  const linkage = validateLinkage(site.function_linkage, label + ".function_linkage");
  if (definitions.get(functionName) !== linkage) fail(label + ".function_linkage disagrees with its definition");
  integer(site.block_ordinal, label + ".block_ordinal");
  integer(site.instruction_ordinal, label + ".instruction_ordinal");
  const source = validateSource(site.source, label + ".source");
  return {
    site_id: siteId,
    function: functionName,
    function_linkage: linkage,
    block_ordinal: site.block_ordinal as number,
    instruction_ordinal: site.instruction_ordinal as number,
    source,
  };
}

function validateSite(value: unknown, index: number, definitions: Map<string, string>, seen: Set<string>): GuidanceSite {
  const label = "guidance_sites[" + index + "]";
  const site = object(value, label);
  const baseKeys = [
    "site_id", "function", "function_linkage", "block_ordinal", "instruction_ordinal", "source", "kind",
  ];

  if (site.kind === "icmp") {
    keys(site, [...baseKeys, "predicate", "width_bits", "signedness", "operands"], ["vector_lanes"], label);
    const base = validateSiteBase(site, label, definitions, seen);
    const predicates = new Set(["eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle"]);
    if (typeof site.predicate !== "string" || !predicates.has(site.predicate)) fail(label + ".predicate is unsupported");
    const expected: IRSignedness = site.predicate.startsWith("s") ? "signed" : site.predicate.startsWith("u") ? "unsigned" : "signless";
    if (site.signedness !== expected) fail(label + ".signedness disagrees with predicate");
    const width = validateWidth(site.width_bits, label + ".width_bits");
    if (site.vector_lanes !== undefined && site.vector_lanes !== null) integer(site.vector_lanes, label + ".vector_lanes", 1);
    if (!Array.isArray(site.operands) || site.operands.length !== 2) fail(label + ".operands must contain two operands");
    return {
      ...base,
      kind: "icmp",
      predicate: site.predicate,
      width_bits: width,
      ...(site.vector_lanes === undefined ? {} : { vector_lanes: site.vector_lanes as number | null }),
      signedness: expected,
      operands: [
        validateOperand(site.operands[0], 0, label + ".operands[0]"),
        validateOperand(site.operands[1], 1, label + ".operands[1]"),
      ],
    };
  }

  if (site.kind === "switch") {
    keys(site, [...baseKeys, "width_bits", "selector", "cases"], ["default_target"], label);
    const base = validateSiteBase(site, label, definitions, seen);
    const width = validateWidth(site.width_bits, label + ".width_bits");
    const selector = validateOperand(site.selector, 0, label + ".selector");
    if (site.default_target !== undefined) string(site.default_target, label + ".default_target");
    if (!Array.isArray(site.cases)) fail(label + ".cases must be an array");
    const cases = site.cases.map((item, caseIndex) => {
      const caseLabel = label + ".cases[" + caseIndex + "]";
      const switchCase = object(item, caseLabel);
      if (switchCase.status === "constant") {
        keys(switchCase, ["status", "value"], ["target"], caseLabel);
        canonicalInteger(switchCase.value, caseLabel + ".value");
      } else if (switchCase.status === "unknown") {
        keys(switchCase, ["status"], ["target"], caseLabel);
      } else {
        fail(caseLabel + ".status must be constant or unknown");
      }
      if (switchCase.target !== undefined) string(switchCase.target, caseLabel + ".target");
      return switchCase as { value?: string; status: "constant" | "unknown"; target?: string };
    });
    return {
      ...base,
      kind: "switch",
      width_bits: width,
      selector,
      ...(site.default_target === undefined ? {} : { default_target: site.default_target as string }),
      cases,
    };
  }

  if (site.kind === "urem" || site.kind === "srem") {
    keys(site, [...baseKeys, "width_bits", "signedness", "divisor"], ["vector_lanes"], label);
    const base = validateSiteBase(site, label, definitions, seen);
    const width = validateWidth(site.width_bits, label + ".width_bits");
    if (site.vector_lanes !== undefined && site.vector_lanes !== null) integer(site.vector_lanes, label + ".vector_lanes", 1);
    const expected = site.kind === "srem" ? "signed" : "unsigned";
    if (site.signedness !== expected) fail(label + ".signedness disagrees with operation");
    return {
      ...base,
      kind: site.kind,
      width_bits: width,
      ...(site.vector_lanes === undefined ? {} : { vector_lanes: site.vector_lanes as number | null }),
      signedness: expected,
      divisor: validateOperand(site.divisor, 1, label + ".divisor"),
    };
  }

  return fail(label + ".kind is unsupported");
}

function validateFacts(value: unknown, index: number, seenSiteIds: Set<string>): IRFactsV1 {
  const label = "ir_facts[" + index + "]";
  const facts = object(value, label);
  keys(facts, [
    "schema", "translation_unit", "module_id", "source", "complete",
    "definitions", "direct_calls", "unknown_indirect", "guidance_sites",
  ], [], label);
  if (facts.schema !== IR_FACTS_SCHEMA) fail(label + ".schema must be " + IR_FACTS_SCHEMA);
  string(facts.translation_unit, label + ".translation_unit");
  if (typeof facts.module_id !== "string" || !/^irtu_[0-9a-f]{32}$/.test(facts.module_id)) {
    fail(label + ".module_id must be a stable irtu identifier");
  }
  const source = object(facts.source, label + ".source");
  keys(source, ["input_file", "ir_filename"], [], label + ".source");
  string(source.input_file, label + ".source.input_file");
  string(source.ir_filename, label + ".source.ir_filename");
  if (typeof facts.complete !== "boolean") fail(label + ".complete must be boolean");
  if (!Array.isArray(facts.definitions)) fail(label + ".definitions must be an array");
  if (!Array.isArray(facts.direct_calls)) fail(label + ".direct_calls must be an array");
  if (!Array.isArray(facts.unknown_indirect)) fail(label + ".unknown_indirect must be an array");
  if (!Array.isArray(facts.guidance_sites)) fail(label + ".guidance_sites must be an array");

  const definitions = new Map<string, string>();
  const parsedDefinitions = facts.definitions.map((item, definitionIndex) => {
    const definitionLabel = label + ".definitions[" + definitionIndex + "]";
    const definition = object(item, definitionLabel);
    keys(definition, ["symbol", "linkage", "source_file"], ["line"], definitionLabel);
    const symbol = string(definition.symbol, definitionLabel + ".symbol");
    const linkage = validateLinkage(definition.linkage, definitionLabel + ".linkage");
    const sourceFile = string(definition.source_file, definitionLabel + ".source_file");
    if (definition.line !== undefined) integer(definition.line, definitionLabel + ".line");
    if (definitions.has(symbol)) fail(definitionLabel + ".symbol is duplicated");
    definitions.set(symbol, linkage);
    return {
      symbol,
      linkage,
      source_file: sourceFile,
      ...(definition.line === undefined ? {} : { line: definition.line as number }),
    };
  });

  const validateCall = (item: unknown, callIndex: number, indirect: boolean) => {
    const callLabel = label + (indirect ? ".unknown_indirect[" : ".direct_calls[") + callIndex + "]";
    const call = object(item, callLabel);
    if (indirect) {
      keys(call, ["caller", "site_id", "reason", "source"], ["unresolved_symbol"], callLabel);
      if (call.unresolved_symbol !== undefined && call.unresolved_symbol !== null) string(call.unresolved_symbol, callLabel + ".unresolved_symbol");
    } else {
      keys(call, ["caller", "callee", "site_id", "source"], [], callLabel);
    }
    const caller = string(call.caller, callLabel + ".caller");
    if (!definitions.has(caller)) fail(callLabel + ".caller is not a local definition");
    const siteId = validateSiteId(call.site_id, callLabel + ".site_id", seenSiteIds);
    if (indirect) string(call.reason, callLabel + ".reason");
    else string(call.callee, callLabel + ".callee");
    const callSource = validateSource(call.source, callLabel + ".source");
    return indirect
      ? { caller, site_id: siteId, reason: call.reason as string, source: callSource }
      : { caller, callee: call.callee as string, site_id: siteId, source: callSource };
  };

  const directCalls = facts.direct_calls.map((item, callIndex) => validateCall(item, callIndex, false)) as IRFactsV1["direct_calls"];
  const unknownIndirect = facts.unknown_indirect.map((item, callIndex) => validateCall(item, callIndex, true)) as IRFactsV1["unknown_indirect"];
  const sites = facts.guidance_sites.map((item, siteIndex) => validateSite(item, siteIndex, definitions, seenSiteIds));

  return {
    schema: IR_FACTS_SCHEMA,
    translation_unit: facts.translation_unit as string,
    module_id: facts.module_id,
    source: { input_file: source.input_file as string, ir_filename: source.ir_filename as string },
    complete: facts.complete,
    definitions: parsedDefinitions,
    direct_calls: directCalls,
    unknown_indirect: unknownIndirect,
    guidance_sites: sites,
  };
}

function parseFactsInput(value: unknown): IRFactsV1[] {
  if (!Array.isArray(value)) fail("ir_facts must be an array of atfield-ir-facts-v1 objects");
  const seenSiteIds = new Set<string>();
  return value.map((facts, index) => validateFacts(facts, index, seenSiteIds));
}

function parseReachability(value: unknown): SelectorReachability[] {
  if (!Array.isArray(value)) fail("reachability must be an array of selector records");
  const seenOrdinals = new Set<number>();
  return value.map((item, index) => {
    const label = "reachability[" + index + "]";
    const selector = object(item, label);
    for (const required of ["ordinal", "reachable_functions", "unknown_indirect", "unknown_external", "function_closure_complete"]) {
      if (!Object.prototype.hasOwnProperty.call(selector, required)) fail(label + "." + required + " is required");
    }
    const ordinal = integer(selector.ordinal, label + ".ordinal");
    if (seenOrdinals.has(ordinal)) fail(label + ".ordinal is duplicated");
    seenOrdinals.add(ordinal);
    if (!Array.isArray(selector.reachable_functions)) fail(label + ".reachable_functions must be an array");
    const functions = selector.reachable_functions.map((name, nameIndex) =>
      string(name, label + ".reachable_functions[" + nameIndex + "]"),
    );
    if (new Set(functions).size !== functions.length) fail(label + ".reachable_functions contains duplicates");
    if (typeof selector.unknown_indirect !== "boolean") fail(label + ".unknown_indirect must be boolean");
    if (typeof selector.unknown_external !== "boolean") fail(label + ".unknown_external must be boolean");
    if (typeof selector.function_closure_complete !== "boolean") fail(label + ".function_closure_complete must be boolean");
    return {
      ordinal,
      reachable_functions: functions,
      unknown_indirect: selector.unknown_indirect,
      unknown_external: selector.unknown_external,
      function_closure_complete: selector.function_closure_complete,
    };
  });
}

function parseScalarParameters(value: unknown): ScalarParameter[] {
  if (!Array.isArray(value)) fail("scalar_params must be an array");
  const seen = new Set<string>();
  return value.map((item, index) => {
    const label = "scalar_params[" + index + "]";
    const parameter = object(item, label);
    keys(parameter, ["ordinal", "param_index", "width_bits", "signedness"], [], label);
    const ordinal = integer(parameter.ordinal, label + ".ordinal");
    const paramIndex = integer(parameter.param_index, label + ".param_index");
    const width = integer(parameter.width_bits, label + ".width_bits", 1);
    if (width > MAX_WIDTH_BITS) fail(label + ".width_bits exceeds supported width " + MAX_WIDTH_BITS);
    if (parameter.signedness !== "signed" && parameter.signedness !== "unsigned") {
      fail(label + ".signedness must be signed or unsigned");
    }
    const key = ordinal + ":" + paramIndex;
    if (seen.has(key)) fail(label + " duplicates a selector parameter");
    seen.add(key);
    return {
      ordinal,
      param_index: paramIndex,
      width_bits: width,
      signedness: parameter.signedness,
    };
  });
}

function scalarRange(parameter: ScalarParameter): [bigint, bigint] {
  const edge = 1n << BigInt(parameter.width_bits - (parameter.signedness === "signed" ? 1 : 0));
  return parameter.signedness === "signed" ? [-edge, edge - 1n] : [0n, edge - 1n];
}

function factRange(site: GuidanceSite): [bigint, bigint] | undefined {
  const width = site.width_bits;
  if (width === null) return undefined;
  if ("vector_lanes" in site && site.vector_lanes !== undefined && site.vector_lanes !== null && site.vector_lanes !== 1) return undefined;
  let signed: boolean;
  if (site.kind === "icmp") {
    signed = site.predicate.startsWith("s");
    if (!signed && !site.predicate.startsWith("u")) {
      const half = 1n << BigInt(width - 1);
      return [-half, (1n << BigInt(width)) - 1n];
    }
  } else {
    signed = site.kind === "srem";
  }
  if (signed) {
    const edge = 1n << BigInt(width - 1);
    return [-edge, edge - 1n];
  }
  return [0n, (1n << BigInt(width)) - 1n];
}

function scalarRepresentation(value: bigint, site: GuidanceSite, parameter: ScalarParameter): bigint {
  const width = site.width_bits;
  if (width === null || (site.kind !== "switch" && site.kind !== "icmp")) return value;
  const signless = site.kind === "switch" || site.predicate === "eq" || site.predicate === "ne";
  if (!signless) return value;
  const modulus = 1n << BigInt(width);
  let bits = value % modulus;
  if (bits < 0n) bits += modulus;
  if (parameter.signedness === "signed" && bits >= (modulus >> 1n)) return bits - modulus;
  return bits;
}

function addInRange(output: Map<string, { value: bigint; priority: number; evidence: Set<string> }>,
  value: bigint, site: GuidanceSite, priority: number, parameter: ScalarParameter): void {
  const sourceRange = factRange(site);
  if (!sourceRange || value < sourceRange[0] || value > sourceRange[1]) return;
  const represented = scalarRepresentation(value, site, parameter);
  const targetRange = scalarRange(parameter);
  if (represented < targetRange[0] || represented > targetRange[1]) return;
  const key = represented.toString();
  let candidate = output.get(key);
  if (!candidate) {
    candidate = { value: represented, priority, evidence: new Set<string>() };
    output.set(key, candidate);
  }
  if (priority > candidate.priority) candidate.priority = priority;
  candidate.evidence.add(site.site_id);
}

function siteCandidates(site: GuidanceSite, parameter: ScalarParameter) {
  const output = new Map<string, { value: bigint; priority: number; evidence: Set<string> }>();
  const range = factRange(site);
  if (!range) return output;

  if (site.kind === "icmp") {
    const constants = site.operands
      .filter((operand) => operand.status === "constant" && operand.value !== undefined)
      .map((operand) => canonicalInteger(operand.value, "IR comparison constant"));
    if (constants.length !== 1) return output;
    const threshold = constants[0];
    for (let delta = -1; delta <= 1; delta++) {
      const value = threshold + BigInt(delta);
      addInRange(output, value, site, delta === 0 ? 1000 : 970, parameter);
    }
    return output;
  }

  if (site.kind === "switch") {
    for (const switchCase of site.cases) {
      if (switchCase.status !== "constant" || switchCase.value === undefined) continue;
      const threshold = canonicalInteger(switchCase.value, "IR switch case");
      for (let delta = -1; delta <= 1; delta++) {
        const value = threshold + BigInt(delta);
        addInRange(output, value, site, delta === 0 ? 900 : 880, parameter);
      }
    }
    return output;
  }

  if (site.divisor.status !== "constant" || site.divisor.value === undefined) return output;
  const divisor = canonicalInteger(site.divisor.value, "IR remainder divisor");
  const seeds = new Map<string, { value: bigint; priority: number }>();
  const addSeed = (value: bigint, priority: number) => {
    const key = value.toString();
    const prior = seeds.get(key);
    if (!prior || priority > prior.priority) seeds.set(key, { value, priority });
  };
  for (const value of [0n, 1n, divisor - 1n, divisor, divisor + 1n]) addSeed(value, 850);

  if (divisor !== 0n) {
    if (site.kind === "urem") {
      const unsignedDivisor = divisor;
      if (unsignedDivisor > 0n) {
        for (const multiple of [2n, 3n]) {
          const center = unsignedDivisor * multiple;
          for (const delta of [-1n, 0n, 1n]) addSeed(center + delta, 820);
        }
      }
    } else {
      const magnitude = divisor < 0n ? -divisor : divisor;
      for (const sign of [-1n, 1n]) {
        for (const multiple of [2n, 3n]) {
          const center = sign * magnitude * multiple;
          for (const delta of [-1n, 0n, 1n]) addSeed(center + delta, 820);
        }
      }
    }
  }

  for (const seed of seeds.values()) addInRange(output, seed.value, site, seed.priority, parameter);
  return output;
}

function fallbackValues(parameter: ScalarParameter): bigint[] {
  const [minimum, maximum] = scalarRange(parameter);
  const values = new Set<string>([minimum.toString(), maximum.toString()]);
  for (const value of GENERIC_VALUES) {
    const parsed = BigInt(value);
    if (parsed >= minimum && parsed <= maximum) values.add(parsed.toString());
  }
  return [...values].map((value) => BigInt(value));
}

/**
 * Build deterministic scalar replacements from bundle facts, selector reachability, and scalar ABI layout.
 * This API accepts no buffer offsets or source mappings; facts can only produce scalar parameter values.
 */
export function generateScalarReplacementCandidates(
  irFactsInput: unknown,
  reachabilityInput: unknown,
  scalarParamsInput: unknown,
  options: CandidateOptions = {},
): ScalarReplacementCandidate[] {
  const facts = parseFactsInput(irFactsInput);
  const reachability = parseReachability(reachabilityInput);
  const scalarParams = parseScalarParameters(scalarParamsInput);
  const optionRecord = object(options, "options");
  keys(optionRecord, [], ["budget"], "options");
  const budget = optionRecord.budget === undefined ? DEFAULT_BUDGET : integer(optionRecord.budget, "options.budget");
  const reachabilityByOrdinal = new Map(reachability.map((selector) => [selector.ordinal, selector]));
  for (const parameter of scalarParams) {
    if (!reachabilityByOrdinal.has(parameter.ordinal)) {
      fail("missing reachability record for selector ordinal " + parameter.ordinal);
    }
  }

  const allSites = facts.flatMap((unit) => unit.guidance_sites);
  const output = new Map<string, {
    selector_ordinal: number;
    param_index: number;
    value: string;
    priority: number;
    evidence_site_ids: Set<string>;
  }>();

  for (const parameter of scalarParams) {
    const selector = reachabilityByOrdinal.get(parameter.ordinal)!;
    const conservative =
      selector.unknown_indirect || selector.unknown_external || !selector.function_closure_complete;
    const reachable = new Set(selector.reachable_functions);
    const sites = allSites.filter((site) => conservative || reachable.has(site.function));
    const siteCandidatesByValue = new Map<string, { value: bigint; priority: number; evidence: Set<string> }>();
    for (const site of sites) {
      for (const candidate of siteCandidates(site, parameter).values()) {
        const key = candidate.value.toString();
        let previous = siteCandidatesByValue.get(key);
        if (!previous) {
          previous = { value: candidate.value, priority: candidate.priority, evidence: new Set<string>() };
          siteCandidatesByValue.set(key, previous);
        }
        if (candidate.priority > previous.priority) previous.priority = candidate.priority;
        for (const id of candidate.evidence) previous.evidence.add(id);
      }
    }

    const candidates = siteCandidatesByValue.size > 0
      ? [...siteCandidatesByValue.values()].map((item) => ({
        value: item.value,
        priority: item.priority,
        evidence: [...item.evidence].sort(),
      }))
      : fallbackValues(parameter).map((value, index) => ({
        value,
        priority: 100 - index,
        evidence: [] as string[],
      }));

    for (const candidate of candidates) {
      const key = parameter.ordinal + ":" + parameter.param_index + ":" + candidate.value.toString();
      output.set(key, {
        selector_ordinal: parameter.ordinal,
        param_index: parameter.param_index,
        value: candidate.value.toString(),
        priority: candidate.priority,
        evidence_site_ids: new Set(candidate.evidence),
      });
    }
  }

  return [...output.values()]
    .map((candidate) => ({
      selector_ordinal: candidate.selector_ordinal,
      param_index: candidate.param_index,
      value: candidate.value,
      priority: candidate.priority,
      evidence_site_ids: [...candidate.evidence_site_ids].sort(),
    }))
    .sort((left, right) =>
      right.priority - left.priority ||
      left.selector_ordinal - right.selector_ordinal ||
      left.param_index - right.param_index ||
      (BigInt(left.value) < BigInt(right.value) ? -1 : BigInt(left.value) > BigInt(right.value) ? 1 : 0) ||
      left.evidence_site_ids.join(",").localeCompare(right.evidence_site_ids.join(",")),
    )
    .slice(0, budget);
}

