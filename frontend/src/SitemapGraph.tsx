import type { Page, PageEdge } from "./types";

type Props = {
  pages: Page[];
  edges: PageEdge[];
};

const COLUMN_WIDTH = 228;
const ROW_HEIGHT = 124;
const NODE_WIDTH = 192;
const NODE_HEIGHT = 66;

function pageLabel(page: Page): string {
  try {
    const path = new URL(page.url).pathname || "/";
    return path.length > 25 ? `${path.slice(0, 22)}…` : path;
  } catch {
    return page.url.slice(0, 25);
  }
}

export default function SitemapGraph({ pages, edges }: Props) {
  if (pages.length === 0) return null;

  const positions = new Map(
    pages.map((page, index) => [
      page.url,
      {
        x: 24 + (index % 3) * COLUMN_WIDTH,
        y: 24 + Math.floor(index / 3) * ROW_HEIGHT,
      },
    ]),
  );
  const rows = Math.ceil(pages.length / 3);
  const width = 3 * COLUMN_WIDTH + 24;
  const height = rows * ROW_HEIGHT + 12;

  return (
    <div className="sitemap-graph-wrap">
      <div className="sitemap-graph-heading">
        <b>Page relationship map</b>
        <span>{edges.length} observed links · {pages.length} pages</span>
      </div>
      <div className="sitemap-graph-scroll">
        <svg
          className="sitemap-graph"
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label="Directed graph of observed links between scanned pages"
        >
          <title>Observed page relationships</title>
          <defs>
            <marker
              id="sitemap-arrow"
              markerWidth="7"
              markerHeight="7"
              refX="6"
              refY="3.5"
              orient="auto"
            >
              <path d="M0 0 L7 3.5 L0 7 Z" fill="#a87939" />
            </marker>
          </defs>

          {edges.map((edge, index) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            if (!source || !target) return null;

            const sx = source.x + NODE_WIDTH / 2;
            const sy = source.y + NODE_HEIGHT / 2;
            const tx = target.x + NODE_WIDTH / 2;
            const ty = target.y + NODE_HEIGHT / 2;
            const curve = Math.max(24, Math.abs(ty - sy) * 0.28);
            const direction = ty >= sy ? 1 : -1;
            return (
              <path
                key={`${edge.source}-${edge.target}-${index}`}
                d={`M ${sx} ${sy} C ${sx} ${sy + curve * direction}, ${tx} ${ty - curve * direction}, ${tx} ${ty}`}
                className="sitemap-edge"
                markerEnd="url(#sitemap-arrow)"
              />
            );
          })}

          {pages.map((page, index) => {
            const point = positions.get(page.url);
            if (!point) return null;
            const isRoot = index === 0;
            return (
              <g
                key={page.url}
                transform={`translate(${point.x} ${point.y})`}
                className={`sitemap-node ${isRoot ? "root" : ""}`}
              >
                <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="7" />
                <text x="12" y="19" className="sitemap-node-index">
                  {isRoot ? "ENTRY PAGE" : `PAGE ${String(index + 1).padStart(2, "0")}`}
                </text>
                <text x="12" y="39" className="sitemap-node-title">
                  {pageLabel(page)}
                </text>
                <text x={NODE_WIDTH - 12} y="19" textAnchor="end" className="sitemap-node-status">
                  {page.status_code ?? "—"}
                </text>
                <title>{page.title || page.url}</title>
              </g>
            );
          })}
        </svg>
      </div>
      <p className="sitemap-graph-caption">
        Arrows show links found in fetched HTML. They do not imply user navigation or prove a full site map.
      </p>
    </div>
  );
}
