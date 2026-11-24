import type { RepositoryReport, CommonSecurityFinding } from "../types";

const severityToLevel: Record<string, "error" | "warning" | "note" | "none"> = {
  critical: "error", high: "error", medium: "warning", low: "note", info: "note",
};

function safeSourcePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
}

/** Convert heuristic source indicators to SARIF 2.1.0 for code-scanning tools. */
export function repositoryReportToSarif(report: RepositoryReport) {
  const findings: CommonSecurityFinding[] = report.security_findings?.length
    ? report.security_findings
    : report.findings.map((finding) => ({
        finding_id: `legacy-${finding.id}-${finding.path}-${finding.line}`,
        check_id: finding.id, source: "repository" as const, target: report.repository,
        location: { kind: "file" as const, path: finding.path, line: finding.line },
        title: finding.title, category: finding.category, severity: finding.severity,
        confidence: finding.confidence, validation_state: finding.validation_state,
        evidence: finding.evidence, impact: null, preconditions: [],
        remediation: finding.recommendation, scanner_version: report.scanner_version,
        scope_id: null,
      }));

  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; help: { text: string } }>();
  for (const finding of findings) {
    if (!rules.has(finding.check_id)) {
      rules.set(finding.check_id, {
        id: finding.check_id, name: finding.title,
        shortDescription: { text: finding.title },
        help: { text: finding.remediation || "Review the source evidence and application context." },
      });
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "UnWeb", semanticVersion: report.scanner_version,
        informationUri: "https://github.com/iaintsurya/UnWeb", rules: [...rules.values()],
      } },
      automationDetails: { id: `unweb/${report.source?.commit_sha || report.repository}` },
      results: findings.map((finding) => {
        const path = finding.location.kind === "file" ? safeSourcePath(finding.location.path) : "";
        const line = finding.location.kind === "file" ? finding.location.line : undefined;
        return {
          ruleId: finding.check_id,
          level: severityToLevel[finding.severity] || "note",
          message: { text: [
            finding.evidence,
            finding.remediation ? `Recommended remediation: ${finding.remediation}` : "",
            `Validation state: ${finding.validation_state}; confidence: ${finding.confidence}.`,
            "This is a heuristic source indicator, not a confirmed exploitable vulnerability.",
          ].filter(Boolean).join("\n\n") },
          ...(path ? { locations: [{ physicalLocation: {
            artifactLocation: { uri: path },
            ...(typeof line === "number" && Number.isInteger(line) && line > 0 ? { region: { startLine: line } } : {}),
          } }] } : {}),
          partialFingerprints: { unwebFindingId: finding.finding_id },
          properties: {
            category: finding.category, confidence: finding.confidence,
            validationState: finding.validation_state, source: finding.source,
            target: finding.target, scannerVersion: finding.scanner_version,
          },
        };
      }),
      properties: {
        repository: report.source?.full_name || report.repository,
        commitSha: report.source?.commit_sha || null,
        findingsAreHeuristic: true,
        reportTruncated: report.truncated,
        dependencyInventoryTruncated: report.dependency_inventory_truncated,
      },
    }],
  };
}
