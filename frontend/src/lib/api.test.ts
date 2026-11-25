import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequest, resolveApiUrl } from "./api";

describe("apiRequest", () => {
  it("does not duplicate an already-resolved API base URL", () => {
    expect(resolveApiUrl("https://api.example.com/api/scans", "https://api.example.com")).toBe(
      "https://api.example.com/api/scans",
    );
    expect(resolveApiUrl("/api/scans", "https://api.example.com")).toBe(
      "https://api.example.com/api/scans",
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns parsed JSON for successful responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ status: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(apiRequest<{ status: string }>("/api/health")).resolves.toEqual({
      status: "ok",
    });
  });

  it("uses the structured FastAPI error message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: { message: "Target rejected." } }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(apiRequest("/api/scans")).rejects.toThrow("Target rejected.");
  });

  it("falls back to the HTTP status when the response body is not JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not-json", { status: 502 })),
    );

    await expect(apiRequest("/api/scans")).rejects.toThrow("Request failed (502).");
  });
});
