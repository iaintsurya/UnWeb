from app.engines import analyze_javascript


def test_routes_ignore_comments_and_retain_source_evidence():
    body = '''// fetch("/api/commented-out")
/*
axios.post("/api/also-commented")
*/
fetch("/api/users");
axios.post('/api/auth/login');
const config = { path: "/admin/settings" };
'''
    result = analyze_javascript("https://example.com/app.js", body)

    assert result["routes"] == ["/api/users", "/api/auth/login", "/admin/settings"]
    refs = result["route_references"]
    assert refs[0]["line"] == 5
    assert refs[0]["confidence"] == "high"
    assert refs[0]["context"] == "network-call-or-url-field"
    assert refs[1]["method"] == "POST"
    assert refs[2]["confidence"] == "high"
    assert all("evidence" in item for item in refs)


def test_dynamic_template_route_is_reported_as_a_prefix():
    body = 'const url = `/api/items/${itemId}`; fetch(url);'
    result = analyze_javascript("https://example.com/app.js", body)

    assert result["routes"] == ["/api/items/"]
    assert result["route_references"][0]["dynamic_template_prefix"] is True


def test_route_like_strings_are_clues_with_lower_confidence():
    result = analyze_javascript(
        "https://example.com/app.js",
        'const docsPath = "/api/documentation";',
    )

    assert result["routes"] == ["/api/documentation"]
    assert result["route_references"][0]["confidence"] == "medium"
    assert result["route_references"][0]["context"] == "route-like-string"


def test_library_evidence_and_source_maps_are_returned_with_locations():
    body = '''import React from "react";
import { createApp } from "vue";
const x = 1;
//# sourceMappingURL=app.js.map
'''
    result = analyze_javascript("https://example.com/app.js", body)

    assert "React" in result["possible_libraries"]
    assert "Vue" in result["possible_libraries"]
    assert {item["name"] for item in result["library_evidence"]} >= {"React", "Vue"}
    assert result["source_mapping_url_reference"] is True
    assert result["source_map_references"][0] == {
        "reference": "app.js.map",
        "line": 4,
    }


def test_js_analysis_reports_basic_size_and_limitations():
    body = "const x = 1;\nconst y = 2;"
    result = analyze_javascript("https://example.com/app.js", body)

    assert result["bytes_analyzed"] == len(body.encode("utf-8"))
    assert result["line_count"] == 2
    assert "Not AST analysis" in result["limitations"]


def test_library_markers_in_comments_are_ignored():
    body = """// React.createElement
/* createApp({}); @angular/core */
const actual = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
"""
    result = analyze_javascript("https://example.com/app.js", body)

    assert result["possible_libraries"] == ["React"]
    assert result["library_evidence"][0]["line"] == 3
