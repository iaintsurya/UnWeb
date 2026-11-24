import { describe, expect, it } from "vitest";
import { repositoryReportToSarif } from "./sarif";
import type { RepositoryReport } from "../types";

function report(overrides: Partial<RepositoryReport> = {}): RepositoryReport {
  return {
    repository: "sample-project", scanner_version: "0.2.0",
    findings: [{
      id: "python-dynamic-evaluation", category: "unsafe-code", title: "Dynamic evaluation",
      severity: "high", confidence: "medium", path: "src/app.py", line: 12,
      validation_state: "suspected", evidence: "eval(user_input)",
      recommendation: "Avoid evaluating untrusted input.",
    }],
    dependency_inventory: [], dependency_count: 0, dependency_inventory_truncated: false,
    files_scanned: 1, bytes_scanned: 100, skipped_files: 0, truncated: false,
    limitations: [], ...overrides,
  };
}

describe("repositoryReportToSarif", () => {
  it("emits SARIF 2.1.0 with stable rules and source locations", () => {
    const result = repositoryReportToSarif(report());
    expect(result.version).toBe("2.1.0");
    expect(result.runs[0].tool.driver.name).toBe("UnWeb");
    expect(result.runs[0].tool.driver.rules[0].id).toBe("python-dynamic-evaluation");
    expect(result.runs[0].results[0]).toMatchObject({
      ruleId: "python-dynamic-evaluation", level: "error",
      locations: [{ physicalLocation: {
        artifactLocation: { uri: "src/app.py" }, region: { startLine: 12 },
      } }],
      properties: { validationState: "suspected", confidence: "medium" },
    });
  });

  it("maps low and informational severities to SARIF note", () => {
    const low = report({ findings: [{ ...report().findings[0], severity: "low" }] });
    expect(repositoryReportToSarif(low).runs[0].results[0].level).toBe("note");
  });

  it("uses structured finding fingerprints and normalises relative paths", () => {
    const base = report();
    const structured = {
      finding_id: "unw_abc123", check_id: "python-dynamic-evaluation",
      source: "repository" as const, target: "sample-project",
      location: { kind: "file" as const, path: "./src/app.py", line: 12 },
      title: "Dynamic evaluation", category: "unsafe-code", severity: "high" as const,
      confidence: "medium" as const, validation_state: "suspected" as const,
      evidence: "eval(user_input)", impact: null, preconditions: [],
      remediation: "Avoid evaluating untrusted input.", scanner_version: "0.2.0", scope_id: null,
    };
    const result = repositoryReportToSarif({ ...base, security_findings: [structured] });
    expect(result.runs[0].results[0].partialFingerprints.unwebFindingId).toBe("unw_abc123");
    expect(result.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("src/app.py");
  });

  it("omits malformed source locations", () => {
    const noLocation = { ...report().findings[0], path: "", line: 0 };
    const result = repositoryReportToSarif(report({ findings: [noLocation] }));
    expect(result.runs[0].results[0].locations).toBeUndefined();
  });
});
