export type ExecutionOutcome = "success" | "failure" | "timeout" | "aex" | "incomplete";

export interface ProjectRef {
  projectId: string;
  familyId: string;
}

export interface WorksetEntry {
  fieldId: string;
  selectorId: string;
  pages: readonly string[];
}

export interface CandidateWorkset extends ProjectRef {
  entries: readonly WorksetEntry[];
}

export interface OracleObservation {
  fieldId: string;
  pages: readonly string[];
}

export interface OracleTrace extends ProjectRef {
  selectorId: string;
  outcome: ExecutionOutcome;
  /** Required for business-failure traces. */
  expected?: boolean;
  /** Required for business-failure traces; false means the measurement is unusable. */
  validMeasurement?: boolean;
  observations: readonly OracleObservation[];
}

export interface SupportedFieldSelector {
  projectId: string;
  fieldId: string;
  selectorId: string;
}

export interface HiddenEvaluationInput {
  developmentProjects: readonly ProjectRef[];
  hiddenProjects: readonly ProjectRef[];
  candidateWorksets: readonly CandidateWorkset[];
  withheldOracleTraces: readonly OracleTrace[];
  support: readonly SupportedFieldSelector[];
}

export interface HiddenEvaluationSummary {
  projectFamilies: number;
  projectVariants: number;
  fieldSelectorPairs: number;
  executions: number;
  outcomes: Record<ExecutionOutcome, number>;
  invalidExecutions: number;
  pairsWithoutValidObservation: number;
  missedPages: number;
  extraPages: number;
  missedPairs: number;
  extraPairs: number;
  executionsWithMisses: number;
}

export interface HiddenEvaluationResult {
  schema: "atfield-hidden-evaluation-v1";
  decision: "PASS" | "FAIL";
  summary: HiddenEvaluationSummary;
}

const OUTCOMES: readonly ExecutionOutcome[] = ["success", "failure", "timeout", "aex", "incomplete"];
const EHSM_VARIANT = /^ehsm(?:-?opt-?[12])?$/;

function canonicalFamily(familyId: string): string {
  const normalized = familyId.trim().toLowerCase().replace(/_/g, "-");
  return EHSM_VARIANT.test(normalized) ? "ehsm" : normalized;
}

function familyKey(project: ProjectRef): string {
  const declared = canonicalFamily(project.familyId);
  const projectIdentity = canonicalFamily(project.projectId);
  // The three eHSM configurations are one lineage even when a caller gives
  // them separate display family IDs.
  return declared === "ehsm" || projectIdentity === "ehsm" ? "ehsm" : declared;
}

function requireNonEmpty(value: string, label: string): void {
  if (!value.trim()) throw new Error(`${label} must be non-empty`);
}

function pairKey(projectId: string, fieldId: string, selectorId: string): string {
  return JSON.stringify([projectId, fieldId, selectorId]);
}

function executionKey(projectId: string, selectorId: string): string {
  return JSON.stringify([projectId, selectorId]);
}

function validateProjectSplit(
  developmentProjects: readonly ProjectRef[],
  hiddenProjects: readonly ProjectRef[],
): Map<string, ProjectRef> {
  const allIds = new Set<string>();
  const devFamilies = new Set<string>();
  for (const project of developmentProjects) {
    requireNonEmpty(project.projectId, "projectId");
    requireNonEmpty(project.familyId, "familyId");
    if (allIds.has(project.projectId)) throw new Error(`duplicate projectId: ${project.projectId}`);
    allIds.add(project.projectId);
    devFamilies.add(familyKey(project));
  }

  const hiddenById = new Map<string, ProjectRef>();
  for (const project of hiddenProjects) {
    requireNonEmpty(project.projectId, "projectId");
    requireNonEmpty(project.familyId, "familyId");
    if (allIds.has(project.projectId)) throw new Error(`projectId appears in multiple splits: ${project.projectId}`);
    allIds.add(project.projectId);
    const families = [familyKey(project)];
    for (const family of families) {
      if (devFamilies.has(family)) throw new Error(`project family leaks across dev/hidden split: ${family}`);
    }
    hiddenById.set(project.projectId, project);
  }
  if (hiddenProjects.length === 0) throw new Error("hiddenProjects must contain at least one project");
  return hiddenById;
}

function assertHiddenProject(
  ref: { projectId: string; familyId?: string },
  hiddenById: Map<string, ProjectRef>,
  source: string,
): void {
  const expected = hiddenById.get(ref.projectId);
  if (!expected) throw new Error(`${source} references a project outside the hidden split`);
  if (ref.familyId !== undefined && familyKey(expected) !== familyKey(ref as ProjectRef)) {
    throw new Error(`${source} project family does not match hidden manifest`);
  }
}

function pageSet(values: readonly string[]): Set<string> {
  const result = new Set<string>();
  for (const value of values) {
    if (!/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) {
      throw new Error("page RVA must use canonical lowercase 0x hexadecimal notation");
    }
    if (BigInt(value) % 4096n !== 0n) throw new Error("page RVA must be 4096-byte aligned");
    result.add(value);
  }
  return result;
}

function isValidMeasurement(trace: OracleTrace): boolean {
  if (trace.outcome === "success") return trace.validMeasurement !== false;
  if (trace.outcome === "failure") return trace.expected === true && trace.validMeasurement === true;
  return false;
}

/**
 * Evaluates a candidate against withheld traces. The return value contains only
 * aggregate metrics; it never contains project, Field, selector, page, or trace IDs.
 */
export function evaluateHiddenWorkset(input: HiddenEvaluationInput): HiddenEvaluationResult {
  const hiddenById = validateProjectSplit(input.developmentProjects, input.hiddenProjects);
  const supportedPairs = new Set<string>();
  const supportedExecutions = new Set<string>();
  for (const supported of input.support) {
    assertHiddenProject(supported, hiddenById, "support range");
    requireNonEmpty(supported.fieldId, "fieldId");
    requireNonEmpty(supported.selectorId, "selectorId");
    const key = pairKey(supported.projectId, supported.fieldId, supported.selectorId);
    if (supportedPairs.has(key)) throw new Error("duplicate support Field/selector entry");
    supportedPairs.add(key);
    supportedExecutions.add(executionKey(supported.projectId, supported.selectorId));
  }
  if (supportedPairs.size === 0) throw new Error("support range must contain at least one Field/selector pair");

  const candidatesByPair = new Map<string, Set<string>>();
  const candidateProjects = new Set<string>();
  for (const workset of input.candidateWorksets) {
    assertHiddenProject(workset, hiddenById, "candidate workset");
    if (candidateProjects.has(workset.projectId)) throw new Error("duplicate candidate workset for hidden project");
    candidateProjects.add(workset.projectId);
    for (const entry of workset.entries) {
      requireNonEmpty(entry.fieldId, "fieldId");
      requireNonEmpty(entry.selectorId, "selectorId");
      const key = pairKey(workset.projectId, entry.fieldId, entry.selectorId);
      if (!supportedPairs.has(key)) throw new Error("candidate contains a Field/selector pair outside support range");
      if (candidatesByPair.has(key)) throw new Error("duplicate candidate Field/selector entry");
      candidatesByPair.set(key, pageSet(entry.pages));
    }
  }

  for (const key of supportedPairs) {
    if (!candidatesByPair.has(key)) {
      throw new Error("candidate is missing an explicit supported Field/selector entry");
    }
  }

  const requiredByPair = new Map<string, Set<string>>();
  const validObservationPairs = new Set<string>();
  const outcomes: Record<ExecutionOutcome, number> = {
    success: 0,
    failure: 0,
    timeout: 0,
    aex: 0,
    incomplete: 0,
  };
  let executions = 0;
  let invalidExecutions = 0;
  let executionsWithMisses = 0;

  for (const trace of input.withheldOracleTraces) {
    assertHiddenProject(trace, hiddenById, "oracle trace");
    requireNonEmpty(trace.selectorId, "selectorId");
    if (!OUTCOMES.includes(trace.outcome)) throw new Error("unknown oracle execution outcome");
    if (trace.outcome === "failure" &&
      (typeof trace.expected !== "boolean" || typeof trace.validMeasurement !== "boolean")) {
      throw new Error("business-failure traces require expected and validMeasurement booleans");
    }
    if (!supportedExecutions.has(executionKey(trace.projectId, trace.selectorId))) continue;

    // Every supported execution remains in the denominator, independent of outcome.
    executions += 1;
    outcomes[trace.outcome] += 1;
    const measurementValid = isValidMeasurement(trace);
    if (!measurementValid) {
      invalidExecutions += 1;
      continue;
    }

    const observedFields = new Set<string>();
    let traceMisses = false;
    for (const observation of trace.observations) {
      requireNonEmpty(observation.fieldId, "fieldId");
      if (observedFields.has(observation.fieldId)) throw new Error("duplicate Field observation in one trace");
      observedFields.add(observation.fieldId);
      const key = pairKey(trace.projectId, observation.fieldId, trace.selectorId);
      if (!supportedPairs.has(key)) continue;
      const observedPages = pageSet(observation.pages);
      const required = requiredByPair.get(key) ?? new Set<string>();
      const candidate = candidatesByPair.get(key) ?? new Set<string>();
      for (const page of observedPages) {
        required.add(page);
        if (!candidate.has(page)) traceMisses = true;
      }
      if (measurementValid) validObservationPairs.add(key);
      requiredByPair.set(key, required);
    }
    if (traceMisses) executionsWithMisses += 1;
  }

  let missedPages = 0;
  let extraPages = 0;
  let missedPairs = 0;
  let extraPairs = 0;
  let pairsWithoutValidObservation = 0;
  for (const key of supportedPairs) {
    const observed = requiredByPair.get(key) ?? new Set<string>();
    const candidate = candidatesByPair.get(key) ?? new Set<string>();
    if (!validObservationPairs.has(key)) pairsWithoutValidObservation += 1;

    let pairMisses = 0;
    let pairExtras = 0;
    for (const page of observed) if (!candidate.has(page)) pairMisses += 1;
    if (validObservationPairs.has(key)) {
      for (const page of candidate) if (!observed.has(page)) pairExtras += 1;
    }
    missedPages += pairMisses;
    extraPages += pairExtras;
    if (pairMisses > 0) missedPairs += 1;
    if (pairExtras > 0) extraPairs += 1;
  }

  const summary: HiddenEvaluationSummary = {
    projectFamilies: new Set([...hiddenById.values()].map(familyKey)).size,
    projectVariants: hiddenById.size,
    fieldSelectorPairs: supportedPairs.size,
    executions,
    outcomes,
    invalidExecutions,
    pairsWithoutValidObservation,
    missedPages,
    extraPages,
    missedPairs,
    extraPairs,
    executionsWithMisses,
  };
  const passes = invalidExecutions === 0 &&
    pairsWithoutValidObservation === 0 &&
    missedPages === 0 &&
    executionsWithMisses === 0;
  return {
    schema: "atfield-hidden-evaluation-v1",
    decision: passes ? "PASS" : "FAIL",
    summary,
  };
}
