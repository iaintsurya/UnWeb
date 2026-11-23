import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import SitemapGraph from "./SitemapGraph";
import type { Page } from "./types";

const pages: Page[] = [
  {
    url: "https://example.com/",
    title: "Home",
    status_code: 200,
    links: ["https://example.com/"],
    scripts: [],
    stylesheets: [],
    images: [],
    metadata: {},
  },
];

describe("SitemapGraph", () => {
  it("renders a self-referencing link without invalid SVG coordinates", () => {
    const markup = renderToStaticMarkup(
      <SitemapGraph
        pages={pages}
        edges={[{ source: "https://example.com/", target: "https://example.com/" }]}
      />,
    );

    expect(markup).toContain("ENTRY PAGE");
    expect(markup).toContain("Observed page relationships");
    expect(markup).not.toMatch(/NaN|Infinity|undefined/);
  });

  it("renders no graph when there are no scanned pages", () => {
    expect(renderToStaticMarkup(<SitemapGraph pages={[]} edges={[]} />)).toBe("");
  });
});
