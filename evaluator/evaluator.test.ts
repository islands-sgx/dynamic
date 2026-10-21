import { describe, expect, test } from "bun:test";
import { evaluateHiddenWorkset, type HiddenEvaluationInput, type ProjectRef } from "./index";

const hidden: ProjectRef = { projectId: "vault-a", familyId: "vault-family" };

function fixture(overrides: Partial<HiddenEvaluationInput> = {}): HiddenEvaluationInput {
  return {
    developmentProjects: [{ projectId: "dev-a", familyId: "dev-family" }],
    hiddenProjects: [hidden],
    candidateWorksets: [{
      ...hidden,
      entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000", "0x2000"] }],
    }],
    withheldOracleTraces: [{
      ...hidden,
      selectorId: "ecall-1",
      outcome: "success",
      observations: [{ fieldId: "field-a", pages: ["0x1000", "0x2000"] }],
    }],
    support: [{ projectId: hidden.projectId, fieldId: "field-a", selectorId: "ecall-1" }],
    ...overrides,
  };
}

describe("hidden workset evaluator", () => {
  test("fails on one omitted page in a supported execution", () => {
    const input = fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000"] }],
      }],
    });
    const result = evaluateHiddenWorkset(input);
    expect(result.decision).toBe("FAIL");
    expect(result.summary.missedPages).toBe(1);
    expect(result.summary.executionsWithMisses).toBe(1);
    expect(result.summary.executions).toBe(1);
  });

  test("counts candidate-only pages while returning aggregate output", () => {
    const result = evaluateHiddenWorkset(fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000", "0x2000", "0x3000"] }],
      }],
    }));
    expect(result.decision).toBe("PASS");
    expect(result.summary.extraPages).toBe(1);
    expect(result.summary.extraPairs).toBe(1);
    expect(JSON.stringify(result)).not.toContain("field-a");
  });

  test("tracks two Fields separately when one ECALL selector reaches both", () => {
    const result = evaluateHiddenWorkset(fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [
          { fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000"] },
          { fieldId: "field-b", selectorId: "ecall-1", pages: ["0x3000"] },
        ],
      }],
      withheldOracleTraces: [{
        ...hidden,
        selectorId: "ecall-1",
        outcome: "success",
        observations: [
          { fieldId: "field-a", pages: ["0x1000"] },
          { fieldId: "field-b", pages: ["0x3000"] },
        ],
      }],
      support: [
        { projectId: hidden.projectId, fieldId: "field-a", selectorId: "ecall-1" },
        { projectId: hidden.projectId, fieldId: "field-b", selectorId: "ecall-1" },
      ],
    }));
    expect(result.decision).toBe("PASS");
    expect(result.summary.fieldSelectorPairs).toBe(2);
    expect(result.summary.missedPages).toBe(0);
  });

  test("keeps failure, timeout, AEX, and incomplete traces in the denominator", () => {
    const outcomes = ["failure", "timeout", "aex", "incomplete"] as const;
    const result = evaluateHiddenWorkset(fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000"] }],
      }],
      withheldOracleTraces: outcomes.map(outcome => ({
        ...hidden,
        selectorId: "ecall-1",
        outcome,
        ...(outcome === "failure" ? { expected: true, validMeasurement: true } : {}),
        observations: [{
          fieldId: "field-a",
          pages: outcome === "failure" ? ["0x1000", "0x2000"] : ["0x1000"],
        }],
      })),
    }));
    expect(result.summary.executions).toBe(4);
    expect(result.summary.outcomes).toEqual({ success: 0, failure: 1, timeout: 1, aex: 1, incomplete: 1 });
    expect(result.decision).toBe("FAIL");
    expect(result.summary.missedPages).toBe(1);
    expect(result.summary.executionsWithMisses).toBe(1);
  });

  test("does not merge partial observations from invalid executions", () => {
    const result = evaluateHiddenWorkset(fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000"] }],
      }],
      withheldOracleTraces: [
        {
          ...hidden,
          selectorId: "ecall-1",
          outcome: "success",
          observations: [{ fieldId: "field-a", pages: ["0x1000"] }],
        },
        {
          ...hidden,
          selectorId: "ecall-1",
          outcome: "aex",
          observations: [{ fieldId: "field-a", pages: ["0x2000"] }],
        },
      ],
    }));
    expect(result.decision).toBe("FAIL");
    expect(result.summary.executions).toBe(2);
    expect(result.summary.invalidExecutions).toBe(1);
    expect(result.summary.missedPages).toBe(0);
    expect(result.summary.executionsWithMisses).toBe(0);
  });

  test("requires a candidate entry even when the expected page set is empty", () => {
    expect(() => evaluateHiddenWorkset(fixture({
      candidateWorksets: [],
      withheldOracleTraces: [],
    }))).toThrow("missing an explicit supported Field/selector entry");

    const result = evaluateHiddenWorkset(fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: [] }],
      }],
      withheldOracleTraces: [{
        ...hidden,
        selectorId: "ecall-1",
        outcome: "success",
        observations: [{ fieldId: "field-a", pages: [] }],
      }],
    }));
    expect(result.decision).toBe("PASS");
    expect(result.summary.missedPages).toBe(0);
    expect(result.summary.extraPages).toBe(0);
  });

  test("accepts an expected business error only when its measurement is complete", () => {
    const result = evaluateHiddenWorkset(fixture({
      withheldOracleTraces: [{
        ...hidden,
        selectorId: "ecall-1",
        outcome: "failure",
        expected: true,
        validMeasurement: true,
        observations: [{ fieldId: "field-a", pages: ["0x1000", "0x2000"] }],
      }],
    }));
    expect(result.decision).toBe("PASS");
    expect(result.summary.executions).toBe(1);
    expect(result.summary.invalidExecutions).toBe(0);
  });

  test("rejects unexpected or incomplete business-failure measurements", () => {
    for (const metadata of [
      { expected: false, validMeasurement: true },
      { expected: true, validMeasurement: false },
    ]) {
      const result = evaluateHiddenWorkset(fixture({
        withheldOracleTraces: [{
          ...hidden,
          selectorId: "ecall-1",
          outcome: "failure",
          ...metadata,
          observations: [{ fieldId: "field-a", pages: ["0x1000"] }],
        }],
      }));
      expect(result.decision).toBe("FAIL");
      expect(result.summary.invalidExecutions).toBe(1);
    }
  });

  test("fails when a supported pair has no complete valid oracle observation", () => {
    const result = evaluateHiddenWorkset(fixture({ withheldOracleTraces: [] }));
    expect(result.decision).toBe("FAIL");
    expect(result.summary.executions).toBe(0);
    expect(result.summary.pairsWithoutValidObservation).toBe(1);
  });

  test("rejects candidate pairs outside support and duplicate support pairs", () => {
    expect(() => evaluateHiddenWorkset(fixture({
      candidateWorksets: [{
        ...hidden,
        entries: [
          { fieldId: "field-a", selectorId: "ecall-1", pages: ["0x1000"] },
          { fieldId: "outside-field", selectorId: "ecall-1", pages: ["0x2000"] },
        ],
      }],
    }))).toThrow("outside support range");

    expect(() => evaluateHiddenWorkset(fixture({
      support: [
        { projectId: hidden.projectId, fieldId: "field-a", selectorId: "ecall-1" },
        { projectId: hidden.projectId, fieldId: "field-a", selectorId: "ecall-1" },
      ],
    }))).toThrow("duplicate support");
  });

  test("rejects noncanonical or unaligned page RVAs", () => {
    for (const page of ["0X1000", "0xA000", "0x01000", "0x1001"]) {
      expect(() => evaluateHiddenWorkset(fixture({
        candidateWorksets: [{
          ...hidden,
          entries: [{ fieldId: "field-a", selectorId: "ecall-1", pages: [page] }],
        }],
      }))).toThrow();
    }
  });

  test("rejects a project family shared by development and hidden splits", () => {
    expect(() => evaluateHiddenWorkset(fixture({
      developmentProjects: [{ projectId: "vault-dev-config", familyId: "Vault-Family" }],
    }))).toThrow("project family leaks across dev/hidden split");
  });

  test("counts three eHSM configurations as one hidden project family", () => {
    const configs: ProjectRef[] = [
      { projectId: "ehsm", familyId: "legacy-config" },
      { projectId: "ehsm-opt-1", familyId: "optimized-config-a" },
      { projectId: "ehsm-opt-2", familyId: "optimized-config-b" },
    ];
    const result = evaluateHiddenWorkset({
      developmentProjects: [{ projectId: "dev-independent", familyId: "dev-independent" }],
      hiddenProjects: configs,
      candidateWorksets: configs.map(project => ({
        ...project,
        entries: [{ fieldId: "f", selectorId: "s", pages: ["0x1000"] }],
      })),
      withheldOracleTraces: configs.map(project => ({
        ...project,
        selectorId: "s",
        outcome: "success",
        observations: [{ fieldId: "f", pages: ["0x1000"] }],
      })),
      support: configs.map(project => ({ projectId: project.projectId, fieldId: "f", selectorId: "s" })),
    });
    expect(result.decision).toBe("PASS");
    expect(result.summary.projectVariants).toBe(3);
    expect(result.summary.projectFamilies).toBe(1);
    expect(JSON.stringify(result)).not.toContain("ehsm");
  });
});
