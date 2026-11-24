import { describe, expect, it } from "vitest";
import type { RepositoryReport, ScanResult } from "../types";
import { correlateWebsiteAndRepository } from "./correlation";

function websiteScan(
  pages: string[],
  scriptRoutes: Array<{
    url: string;
    method?: string;
    line: number;
    dynamic?: boolean;
  }> = [],
): ScanResult {
  return {
    pages: pages.map((url) => ({ url })) as ScanResult["pages"],
    js_analysis: scriptRoutes.length
      ? [{
          url: "https://example.test/assets/app.js",
          route_references: scriptRoutes.map((route) => ({
            url: route.url,
            method: route.method,
            line: route.line,
            dynamic_template_prefix: route.dynamic ?? false,
          })),
        }]
      : [],
  } as unknown as ScanResult;
}

function repository(routes: Array<{
  method: string;
  path: string;
  source_path?: string;
  line?: number;
}>): RepositoryReport {
  return {
    repository: "owner/project",
    route_inventory: routes.map((route) => ({
      method: route.method,
      path: route.path,
      source_path: route.source_path ?? "src/routes.ts",
      line: route.line ?? 1,
      syntax: "test",
    })),
    route_inventory_truncated: false,
  } as unknown as RepositoryReport;
}

describe("correlateWebsiteAndRepository", () => {
  it("matches exact crawled paths and reports evidence location", () => {
    const result = correlateWebsiteAndRepository(
      websiteScan(["https://example.test/api/health?debug=1"]),
      repository([{ method: "GET", path: "/api/health" }]),
    );

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].websitePath).toBe("/api/health");
    expect(result.matches[0].matchKind).toBe("exact");
    expect(result.matches[0].confidence).toBe("medium");
    expect(result.matches[0].repositoryRoute.source_path).toBe("src/routes.ts");
  });

  it("matches parameterised repository paths without overstating confidence", () => {
    const result = correlateWebsiteAndRepository(
      websiteScan(["https://example.test/api/users/42"]),
      repository([{ method: "GET", path: "/api/users/{userId}" }]),
    );

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].matchKind).toBe("parameterised");
    expect(result.matches[0].confidence).toBe("low");
  });

  it("does not match conflicting known HTTP methods", () => {
    const result = correlateWebsiteAndRepository(
      websiteScan([], [{ url: "/api/users", method: "POST", line: 12 }]),
      repository([{ method: "GET", path: "/api/users" }]),
    );

    expect(result.matches).toHaveLength(0);
    expect(result.unmatchedWebsitePaths).toContain("/api/users");
    expect(result.unmatchedRepositoryRoutes).toHaveLength(1);
  });

  it("keeps JavaScript route references with unknown methods at low confidence", () => {
    const result = correlateWebsiteAndRepository(
      websiteScan([], [{ url: "/api/orders", line: 8 }]),
      repository([{ method: "POST", path: "/api/orders" }]),
    );

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].websiteEvidence).toBe("javascript-reference");
    expect(result.matches[0].websiteMethod).toBeNull();
    expect(result.matches[0].confidence).toBe("low");
  });

  it("treats dynamic template prefixes as low-confidence overlaps", () => {
    const result = correlateWebsiteAndRepository(
      websiteScan([], [{ url: "/api/users/", method: "GET", line: 20, dynamic: true }]),
      repository([{ method: "GET", path: "/api/users" }]),
    );

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].confidence).toBe("low");
  });

  it("handles absent route inventory and preserves truncation notes", () => {
    const result = correlateWebsiteAndRepository(
      websiteScan(["https://example.test/"]),
      { repository: "owner/project" } as RepositoryReport,
    );

    expect(result.matches).toHaveLength(0);
    expect(result.unmatchedWebsitePaths).toContain("/");
    expect(result.repositoryRouteCount).toBe(0);
    expect(result.notes.some((note) => note.includes("not proof"))).toBe(true);
  });
});
