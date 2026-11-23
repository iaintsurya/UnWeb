import html
import json
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Tag

MAX_BLOCKS = 100
MAX_TEXT_LENGTH = 500
MAX_NAV_LINKS = 24
MAX_IMAGES = 24

CSS = """:root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
  color: #202a34;
  background: #f5f6f4;
}
* { box-sizing: border-box; }
body { margin: 0; }
.page { max-width: 1120px; margin: 0 auto; padding: 40px clamp(18px, 5vw, 64px) 64px; }
.site-header { padding: 22px 0 28px; border-bottom: 1px solid #dfe4e1; }
.site-label { margin: 0 0 12px; color: #8d672d; font: 600 10px ui-monospace, monospace; letter-spacing: .13em; }
h1 { max-width: 850px; margin: 0; font-size: clamp(2rem, 5vw, 4.5rem); line-height: 1.02; letter-spacing: -.055em; }
.description { max-width: 720px; color: #697580; font-size: 15px; line-height: 1.7; }
.site-nav { display: flex; gap: 8px; flex-wrap: wrap; margin: 20px 0 34px; }
.site-nav a { padding: 7px 10px; border: 1px solid #dce2de; border-radius: 4px; background: #fff; color: #485562; font-size: 12px; text-decoration: none; }
.content { display: grid; gap: 18px; }
.block { min-width: 0; }
.block h2, .block h3 { margin: 10px 0; letter-spacing: -.025em; }
.block h2 { font-size: clamp(1.35rem, 3vw, 2rem); }
.block h3 { font-size: 1.2rem; }
.block p, .block blockquote { max-width: 780px; color: #54616d; font-size: 14px; line-height: 1.85; }
.block blockquote { margin: 10px 0; padding: 10px 18px; border-left: 3px solid #bd9455; background: #f0eee8; }
.block ul, .block ol { padding-left: 22px; color: #54616d; line-height: 1.85; }
.block img { display: block; max-width: 100%; height: auto; border-radius: 7px; }
.site-footer { margin-top: 48px; padding-top: 18px; border-top: 1px solid #dfe4e1; color: #8b959c; font: 10px ui-monospace, monospace; }
@media (max-width: 600px) { .page { padding-top: 24px; } .site-nav { gap: 6px; } }
"""

def _absolute_http_url(base_url: str, raw_url: object) -> str | None:
    if not isinstance(raw_url, str):
        return None
    raw_url = raw_url.strip()
    if not raw_url or len(raw_url) > 2048:
        return None
    try:
        absolute = urljoin(base_url, raw_url)
        parts = urlsplit(absolute)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        return absolute
    except ValueError:
        return None


def _text(element: Tag, limit: int = MAX_TEXT_LENGTH) -> str:
    value = " ".join(element.get_text(" ", strip=True).split())
    return value[:limit]


def _collect_blocks(body: Tag, base_url: str) -> list[dict[str, object]]:
    blocks: list[dict[str, object]] = []
    for element in body.find_all(["h1", "h2", "h3", "p", "ul", "ol", "blockquote", "img"]):
        if any(parent.name in {"li", "ul", "ol", "blockquote"} for parent in element.parents if isinstance(parent, Tag) and parent is not body):
            continue

        if element.name in {"h1", "h2", "h3"}:
            text = _text(element, 220)
            if text:
                blocks.append({
                    "type": "heading",
                    "level": int(element.name[1]),
                    "text": text,
                })
        elif element.name == "p":
            text = _text(element)
            if text:
                blocks.append({"type": "paragraph", "text": text})
        elif element.name in {"ul", "ol"}:
            items = [_text(item, 240) for item in element.find_all("li", recursive=False)]
            items = [item for item in items if item][:30]
            if items:
                blocks.append({
                    "type": "list",
                    "ordered": element.name == "ol",
                    "items": items,
                })
        elif element.name == "blockquote":
            text = _text(element)
            if text:
                blocks.append({"type": "quote", "text": text})
        elif element.name == "img":
            src = _absolute_http_url(base_url, element.get("src"))
            if src and len([item for item in blocks if item["type"] == "image"]) < MAX_IMAGES:
                blocks.append({
                    "type": "image",
                    "src": src,
                    "alt": str(element.get("alt") or "")[:180],
                })

        if len(blocks) >= MAX_BLOCKS:
            break
    return blocks


def _collect_navigation(body: Tag, base_url: str) -> list[dict[str, str]]:
    navigation = []
    seen = set()
    for anchor in body.find_all("a", href=True):
        href = _absolute_http_url(base_url, anchor.get("href"))
        label = _text(anchor, 100)
        if not href or not label or href in seen:
            continue
        seen.add(href)
        navigation.append({"label": label, "href": href})
        if len(navigation) >= MAX_NAV_LINKS:
            break
    return navigation


def _render_preview_block(block: dict[str, object]) -> str:
    kind = block["type"]
    if kind == "heading":
        level = int(block["level"])
        tag = "h1" if level == 1 else "h2" if level == 2 else "h3"
        return f'<section class="block"><{tag}>{html.escape(str(block["text"]))}</{tag}></section>'
    if kind == "paragraph":
        return f'<section class="block"><p>{html.escape(str(block["text"]))}</p></section>'
    if kind == "quote":
        return f'<section class="block"><blockquote>{html.escape(str(block["text"]))}</blockquote></section>'
    if kind == "list":
        tag = "ol" if block["ordered"] else "ul"
        items = "".join(f"<li>{html.escape(str(item))}</li>" for item in block["items"])
        return f'<section class="block"><{tag}>{items}</{tag}></section>'
    if kind == "image":
        src = html.escape(str(block["src"]), quote=True)
        alt = html.escape(str(block["alt"]), quote=True)
        return f'<section class="block"><img src="{src}" alt="{alt}" loading="lazy" referrerpolicy="no-referrer"></section>'
    return ""


def make_reconstruction(base_url: str, html_source: str) -> dict[str, str]:
    """Generate an editable, data-driven React starter plus a script-free preview.

    This is a structural reconstruction from delivered HTML evidence, not a
    copy of the original CSS, JavaScript, backend, or application behavior.
    """
    soup = BeautifulSoup(html_source, "html.parser")

    # Retain only content that can be represented safely by this generator.
    for tag in soup(["script", "style", "noscript", "iframe", "object", "embed", "form", "template", "svg", "canvas"]):
        tag.decompose()
    for tag in soup.find_all(True):
        for attribute in list(tag.attrs):
            if attribute.lower().startswith("on") or attribute.lower() in {"srcdoc", "style", "srcset"}:
                del tag.attrs[attribute]

    title = _text(soup.title, 220) if soup.title else ""
    if not title:
        first_heading = soup.find("h1")
        title = _text(first_heading, 220) if first_heading else "Reconstructed page"

    description = ""
    description_tag = soup.find("meta", attrs={"name": "description"})
    if description_tag and description_tag.get("content"):
        description = str(description_tag.get("content"))[:400]

    body = soup.body or soup
    blocks = _collect_blocks(body, base_url)
    navigation = _collect_navigation(body, base_url)

    blocks_json = json.dumps(blocks, ensure_ascii=False, indent=2)
    navigation_json = json.dumps(navigation, ensure_ascii=False, indent=2)
    title_json = json.dumps(title, ensure_ascii=True)
    description_json = json.dumps(description, ensure_ascii=True)
    base_url_json = json.dumps(base_url, ensure_ascii=True)

    component = f'''import React from "react";
import "./reconstructed.css";

// Generated from fetched public HTML evidence; this is not original source.
type ContentBlock =
  | {{ type: "heading"; level: 1 | 2 | 3; text: string }}
  | {{ type: "paragraph" | "quote"; text: string }}
  | {{ type: "list"; ordered: boolean; items: string[] }}
  | {{ type: "image"; src: string; alt: string }};

type NavigationLink = {{ label: string; href: string }};

const sourceUrl = {base_url_json};
const pageTitle = {title_json};
const description = {description_json};
const navigation: NavigationLink[] = {navigation_json};
const blocks: ContentBlock[] = {blocks_json};

function ContentItem({{ block }}: {{ block: ContentBlock }}) {{
  if (block.type === "heading") {{
    const Heading = block.level === 1 ? "h2" : block.level === 2 ? "h3" : "h4";
    return <Heading>{{block.text}}</Heading>;
  }}
  if (block.type === "paragraph") return <p>{{block.text}}</p>;
  if (block.type === "quote") return <blockquote>{{block.text}}</blockquote>;
  if (block.type === "image") {{
    return <img src={{block.src}} alt={{block.alt}} loading="lazy" referrerPolicy="no-referrer" />;
  }}
  const List = block.ordered ? "ol" : "ul";
  return <List>{{block.items.map((item, index) => <li key={{index}}>{{item}}</li>)}}</List>;
}}

export default function ReconstructedPage() {{
  return (
    <main className="page">
      <header className="site-header">
        <p className="site-label">UNWEB · GENERATED STARTER</p>
        <h1>{{pageTitle}}</h1>
        {{description && <p className="description">{{description}}</p>}}
        {{navigation.length > 0 && (
          <nav className="site-nav" aria-label="Observed page links">
            {{navigation.map((link) => (
              <a key={{link.href}} href={{link.href}}>{{link.label}}</a>
            ))}}
          </nav>
        )}}
      </header>
      <section className="content">
        {{blocks.map((block, index) => (
          <article className="block" key={{index}}>
            <ContentItem block={{block}} />
          </article>
        ))}}
        {{blocks.length === 0 && <p>No safe text or media blocks were extracted.</p>}}
      </section>
      <footer className="site-footer">
        Reconstructed from observed HTML at {{sourceUrl}} · Review before publishing
      </footer>
    </main>
  );
}}
'''

    preview_navigation = "".join(
        f'<a href="{html.escape(item["href"], quote=True)}">{html.escape(item["label"])}</a>'
        for item in navigation
    )
    preview_blocks = "".join(_render_preview_block(block) for block in blocks)
    preview_html = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main class="page">
<header class="site-header">
<p class="site-label">UNWEB · GENERATED PREVIEW</p>
<h1>{html.escape(title)}</h1>
{f'<p class="description">{html.escape(description)}</p>' if description else ''}
{f'<nav class="site-nav" aria-label="Observed page links">{preview_navigation}</nav>' if navigation else ''}
</header>
<section class="content">
{preview_blocks or '<p>No safe text or media blocks were extracted.</p>'}
</section>
<footer class="site-footer">Reconstructed from observed HTML at {html.escape(base_url)} · Review before publishing</footer>
</main>
</body>
</html>'''

    manifest = {
        "source_url": base_url,
        "generator": "UnWeb structural HTML reconstruction",
        "counts": {
            "content_blocks": len(blocks),
            "navigation_links": len(navigation),
            "images": sum(1 for block in blocks if block["type"] == "image"),
        },
        "limitations": [
            "Original CSS, layout rules, JavaScript, backend behavior, and authenticated content are not recovered.",
            "The preview is a script-free rendering of extracted headings, paragraphs, lists, quotes, images, and links.",
            "External image URLs may still make requests to their original hosts when the preview is opened.",
        ],
    }

    readme = f"""# Reconstructed starter

Source page: {base_url}

## Files

- \`App.tsx\` — editable React component with structured content blocks
- \`reconstructed.css\` — starter styling
- \`preview.html\` — script-free static preview generated from extracted content
- \`reconstruction-manifest.json\` — source and extraction counts

## Run

Copy the files into a React + TypeScript project, install React, and import \`App.tsx\`.

This is a structural reconstruction of publicly delivered HTML. It does not recover original source code, stylesheets, JavaScript, server logic, or authenticated content. Review all text, links, and image rights before publishing.
"""

    return {
        "App.tsx": component,
        "reconstructed.css": CSS,
        "preview.html": preview_html,
        "reconstruction-manifest.json": json.dumps(manifest, ensure_ascii=False, indent=2),
        "README.md": readme,
    }
