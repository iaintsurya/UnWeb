from app.rebuild import make_reconstruction


def test_reconstruction_preserves_structured_content_and_safe_navigation():
    source = """
    <!doctype html>
    <html>
      <head>
        <title>Research home</title>
        <meta name="description" content="A short introduction">
        <script>alert("not copied")</script>
      </head>
      <body>
        <nav>
          <a href="/about">About us</a>
          <a href="javascript:alert(1)">Unsafe link</a>
        </nav>
        <h1>Welcome</h1>
        <p>Intro paragraph.</p>
        <h2>What we do</h2>
        <ul><li>First item</li><li>Second item</li></ul>
        <blockquote>Quoted evidence.</blockquote>
        <img src="/media/hero.png" alt="Research lab">
      </body>
    </html>
    """
    result = make_reconstruction("https://example.com/", source)

    component = result["App.tsx"]
    preview = result["preview.html"]
    manifest = result["reconstruction-manifest.json"]

    assert 'type: "list"' in component
    assert 'type: "image"' in component
    assert "About us" in component
    assert "javascript:alert" not in component
    assert "alert(" not in component
    assert "Intro paragraph." in preview
    assert "<li>First item</li>" in preview
    assert 'src="https://example.com/media/hero.png"' in preview
    assert "Unsafe link" not in preview
    assert "<script" not in preview.lower()
    assert '"content_blocks": 6' in manifest
    assert '"navigation_links": 1' in manifest


def test_reconstruction_escapes_untrusted_text_and_attributes():
    source = """
    <html><head><title>&lt;/h1&gt;&lt;script&gt;bad()&lt;/script&gt;</title></head>
    <body>
      <h1 onclick="bad()">Hello &lt;img src=x onerror=bad()&gt;</h1>
      <a href="data:text/html,bad()">bad link</a>
      <img src="javascript:bad()" onerror="bad()" alt='" onload="bad()'>
      <p style="background:url(javascript:bad())">Safe text</p>
    </body></html>
    """
    result = make_reconstruction("https://example.com/", source)

    preview = result["preview.html"]
    component = result["App.tsx"]

    assert "<script>bad()</script>" not in preview
    assert "onerror=" not in preview
    assert "onload=" not in preview
    assert "javascript:bad()" not in preview
    assert "data:text/html" not in preview
    assert "&lt;script&gt;" in preview
    assert "onclick" not in component
    assert "style=" not in component


def test_reconstruction_has_empty_state_and_documentation():
    result = make_reconstruction("https://example.com/", "<html><body></body></html>")

    assert "No safe text or media blocks were extracted." in result["App.tsx"]
    assert "No safe text or media blocks were extracted." in result["preview.html"]
    assert "preview.html" in result["README.md"]
    assert "original source" in result["README.md"]
