import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { BrowserEvidence } from "./App";
import type { BrowserRenderResult } from "./types";

const result: BrowserRenderResult = {
  engine: "playwright-chromium",
  target_url: "https://example.com/app",
  final_url: "https://example.com/app",
  navigation_status: 200,
  navigation_error_type: null,
  title: "Example",
  dom: {
    title: "Example",
    description: "Example description",
    headings: [{ level: 1, text: "Welcome" }],
    links: [{ text: "Docs", url: "https://example.com/docs" }],
    images: [{ url: "https://example.com/logo.png", alt: "Logo", width: 120, height: 40 }],
    stylesheetLinks: ["https://example.com/app.css"],
    scriptLinks: ["https://example.com/app.js"],
    landmarks: { main: 1, navigation: 1, header: 1, footer: 1 },
    styles: {},
    classSamples: ["hero"],
    document: { width: 1280, height: 900, viewportWidth: 1280, viewportHeight: 720, characterCount: 4200 },
  },
  network: {
    request_count: 2,
    blocked_request_count: 1,
    requests: [{ url: "https://example.com/app", method: "GET", resource_type: "document" }],
    responses: [{ url: "https://example.com/app", status: 200, content_type: "text/html", content_length_declared: 512 }],
    failed_requests: [],
    declared_response_bytes: 512,
    websockets: [],
    proxy_connections: 1,
    proxy_denials: 0,
  },
  browser_errors: { console_error_count: 0, page_error_count: 0 },
  limitations: ["Unauthenticated single render."],
};

describe("BrowserEvidence", () => {
  it("renders the DOM and bounded network evidence in a readable report", () => {
    const markup = renderToStaticMarkup(<BrowserEvidence result={result} />);
    expect(markup).toContain("Welcome");
    expect(markup).toContain("GET");
    expect(markup).toContain("Docs");
    expect(markup).toContain("app.css");
    expect(markup).toContain("Unauthenticated single render.");
  });

  it("handles missing DOM extraction without crashing", () => {
    const markup = renderToStaticMarkup(<BrowserEvidence result={{ ...result, dom: null }} />);
    expect(markup).toContain("No headings captured.");
    expect(markup).toContain("No same-origin links captured.");
  });
});
