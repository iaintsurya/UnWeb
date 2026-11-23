import type { RepositoryReport, RepositoryRoute, ScanResult } from "../types";

export type RouteMatch = {
  websitePath: string;
  websiteMethod: string | null;
  websiteEvidence: "crawled-page" | "javascript-reference";
  websiteSource: string;
  websiteLine?: number;
  repositoryRoute: RepositoryRoute;
  matchKind: "exact" | "parameterised";
  confidence: "medium" | "low";
  explanation: string;
};

export type RouteCorrelationReport = {
  websitePageCount: number;
  websiteScriptRouteCount: number;
  repositoryRouteCount: number;
  matches: RouteMatch[];
  unmatchedWebsitePaths: string[];
  unmatchedRepositoryRoutes: RepositoryRoute[];
  truncated: boolean;
  notes: string[];
};

type WebsiteCandidate = {
  path: string;
  method: string | null;
  evidence: "crawled-page" | "javascript-reference";
  source: string;
  line?: number;
  dynamic: boolean;
};

function cleanPath(value: string): string | null {
  let path = value.trim();
  if (!path || path.length > 2048) return null;
  try {
    if (/^https?:\/\//i.test(path)) path = new URL(path).pathname;
  } catch {
    return null;
  }
  path = path.split(/[?#]/, 1)[0];
  if (!path.startsWith("/") || path.includes("\\") || /[\u0000-\u001f]/.test(path)) return null;
  if (path.length > 1) path = path.replace(/\/+$/, "");
  return path || "/";
}

function isParameter(segment: string): boolean {
  return (
    /^:[A-Za-z_][\w-]*$/.test(segment) ||
    /^\{[^/{}]+\}$/.test(segment) ||
    /^<[^/<>]+>$/.test(segment) ||
    segment === "*"
  );
}

function comparePaths(
  websitePath: string,
  repositoryPath: string,
): "exact" | "parameterised" | null {
  const website = cleanPath(websitePath);
  const route = cleanPath(repositoryPath);
  if (!website || !route) return null;
  if (website === route) return "exact";

  const websiteSegments = website.split("/").filter(Boolean);
  const routeSegments = route.split("/").filter(Boolean);
  if (websiteSegments.length !== routeSegments.length) return null;

  let usedParameter = false;
  for (let index = 0; index < websiteSegments.length; index += 1) {
    if (websiteSegments[index] === routeSegments[index]) continue;
    if (isParameter(routeSegments[index])) {
      usedParameter = true;
      continue;
    }
    return null;
  }
  return usedParameter ? "parameterised" : null;
}

function methodCompatible(observed: string | null, declared: string): boolean {
  if (!observed) return true;
  const normalized = observed.toUpperCase();
  const routeMethod = declared.toUpperCase();
  return routeMethod === "ANY" || routeMethod === normalized;
}

function websiteCandidates(scan: ScanResult): WebsiteCandidate[] {
  const candidates: WebsiteCandidate[] = [];
  for (const page of scan.pages) {
    const path = cleanPath(page.url);
    if (path) {
      candidates.push({
        path,
        method: "GET",
        evidence: "crawled-page",
        source: page.url,
        dynamic: false,
      });
    }
  }

  for (const script of scan.js_analysis) {
    for (const reference of script.route_references ?? []) {
      const path = cleanPath(reference.url);
      if (!path) continue;
      candidates.push({
        path,
        method: reference.method?.toUpperCase() ?? null,
        evidence: "javascript-reference",
        source: script.url,
        line: reference.line,
        dynamic: reference.dynamic_template_prefix,
      });
    }
  }

  const unique = new Map<string, WebsiteCandidate>();
  for (const candidate of candidates) {
    const key = [
      candidate.path,
      candidate.method ?? "?",
      candidate.evidence,
      candidate.source,
      candidate.line ?? "",
      candidate.dynamic ? "dynamic" : "literal",
    ].join("|");
    if (!unique.has(key)) unique.set(key, candidate);
  }
  return [...unique.values()];
}

export function correlateWebsiteAndRepository(
  scan: ScanResult,
  repository: RepositoryReport,
): RouteCorrelationReport {
  const candidates = websiteCandidates(scan);
  const routes = repository.route_inventory ?? [];
  const matches: RouteMatch[] = [];
  const matchedWebsitePaths = new Set<string>();
  const matchedRepositoryRoutes = new Set<string>();
  const seen = new Set<string>();
  const maxMatches = 1_000;

  for (const candidate of candidates) {
    for (const route of routes) {
      if (!methodCompatible(candidate.method, route.method)) continue;
      const matchKind = comparePaths(candidate.path, route.path);
      if (!matchKind) continue;

      const routeKey = route.method + "|" + route.path + "|" + route.source_path + "|" + route.line;
      const matchKey = [
        candidate.path,
        candidate.method ?? "?",
        candidate.evidence,
        candidate.source,
        candidate.line ?? "",
        routeKey,
      ].join("|");
      if (seen.has(matchKey)) continue;
      seen.add(matchKey);
      matchedWebsitePaths.add(candidate.path);
      matchedRepositoryRoutes.add(routeKey);

      const confidence =
        matchKind === "exact" && candidate.method !== null && !candidate.dynamic
          ? "medium"
          : "low";
      const explanation =
        matchKind === "exact"
          ? candidate.method
            ? "The observed " + candidate.method + " path exactly matches a literal repository route."
            : "The observed JavaScript route path exactly matches a repository route; its HTTP method was not established."
          : "The observed path is compatible with a parameterised repository route.";
      matches.push({
        websitePath: candidate.path,
        websiteMethod: candidate.method,
        websiteEvidence: candidate.evidence,
        websiteSource: candidate.source,
        ...(candidate.line ? { websiteLine: candidate.line } : {}),
        repositoryRoute: route,
        matchKind,
        confidence,
        explanation,
      });
      if (matches.length >= maxMatches) break;
    }
    if (matches.length >= maxMatches) break;
  }

  const unmatchedWebsitePaths = [
    ...new Set(candidates.map((candidate) => candidate.path)),
  ].filter((path) => !matchedWebsitePaths.has(path));

  const unmatchedRepositoryRoutes = routes.filter(
    (route) =>
      !matchedRepositoryRoutes.has(
        route.method + "|" + route.path + "|" + route.source_path + "|" + route.line,
      ),
  );

  return {
    websitePageCount: scan.pages.length,
    websiteScriptRouteCount: scan.js_analysis.reduce(
      (count, script) => count + (script.route_references?.length ?? 0),
      0,
    ),
    repositoryRouteCount: routes.length,
    matches,
    unmatchedWebsitePaths,
    unmatchedRepositoryRoutes,
    truncated:
      Boolean(repository.route_inventory_truncated) || matches.length >= maxMatches,
    notes: [
      "A path overlap is a reconnaissance clue, not proof that the website and repository are the same deployed version or application.",
      "A match does not establish reachability, authentication requirements, authorisation correctness, or exploitability.",
      "Website page paths were fetched with GET; JavaScript route methods are only included when the lexical analyser inferred one.",
      "Dynamic routes, router composition, middleware, reverse-proxy rewrites, and runtime route registration are not resolved.",
      "Unmatched entries are not evidence that a route is absent or inaccessible.",
    ],
  };
}
