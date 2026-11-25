import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import App from "./App";

describe("App initial state", () => {
  it("renders an empty workspace before a scan exists", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const markup = renderToStaticMarkup(<App />);

    expect(markup).toContain("No target selected");
    expect(markup).toContain("Start with a URL above");
    expect(markup).toContain("READY FOR ANALYSIS");

    vi.unstubAllGlobals();
  });
});
