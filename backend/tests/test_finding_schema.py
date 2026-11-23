from types import SimpleNamespace

from app.finding_schema import (
    repository_security_findings,
    website_security_findings,
)


def test_website_findings_are_marked_observed_not_validated():
    finding = SimpleNamespace(
        id="missing-content-security-policy",
        title="Content Security Policy not detected",
        severity="low",
        confidence="high",
        evidence="The inspected response did not include the header.",
        recommendation="Evaluate a suitable policy.",
    )

    [record] = website_security_findings(
        [finding],
        "https://example.test/",
        scanner_version="0.2.0",
        observed_at="2026-11-23T12:00:00+00:00",
    )

    assert record["source"] == "website"
    assert record["validation_state"] == "observed"
    assert record["severity"] == "low"
    assert record["confidence"] == "high"
    assert record["location"] == {
        "kind": "url",
        "value": "https://example.test/",
    }
    assert record["impact"] is None
    assert record["preconditions"] == []
    assert record["observed_at"] == "2026-11-23T12:00:00+00:00"


def test_repository_findings_remain_suspected_with_file_location():
    finding = SimpleNamespace(
        id="python-dynamic-evaluation",
        category="injection",
        title="Python dynamic evaluation call observed",
        severity="medium",
        confidence="low",
        path="src/handler.py",
        line=42,
        validation_state="suspected",
        evidence="eval(user_supplied_value)",
        recommendation="Avoid evaluating data as code.",
    )

    [record] = repository_security_findings(
        [finding],
        "owner/project",
        scanner_version="0.2.0",
    )

    assert record["source"] == "repository"
    assert record["validation_state"] == "suspected"
    assert record["target"] == "owner/project"
    assert record["location"] == {
        "kind": "file",
        "path": "src/handler.py",
        "line": 42,
    }
    # Risk and confidence are independent dimensions.
    assert record["severity"] == "medium"
    assert record["confidence"] == "low"


def test_finding_ids_are_stable_for_the_same_check_and_location():
    first = SimpleNamespace(
        id="python-dynamic-evaluation",
        category="injection",
        title="Dynamic evaluation found",
        severity="medium",
        confidence="medium",
        path="src/app.py",
        line=10,
        validation_state="suspected",
        evidence="eval(value)",
        recommendation="Use a safe parser.",
    )
    second = SimpleNamespace(
        id="python-dynamic-evaluation",
        category="injection",
        title="Dynamic evaluation found",
        severity="high",
        confidence="low",
        path="src/app.py",
        line=10,
        validation_state="suspected",
        evidence="eval(other_value)",
        recommendation="Use a constrained parser.",
    )

    first_record = repository_security_findings(
        [first], "owner/project", scanner_version="0.2.0"
    )[0]
    second_record = repository_security_findings(
        [second], "owner/project", scanner_version="0.3.0"
    )[0]

    assert first_record["finding_id"] == second_record["finding_id"]


def test_invalid_legacy_values_are_safely_normalised():
    finding = SimpleNamespace(
        id="unknown-check",
        category="test",
        title="Test",
        severity="catastrophic",
        confidence="certain",
        path="config/app.yml",
        line=0,
        validation_state="exploited",
        evidence="A pattern was observed.",
        recommendation="Review the configuration.",
    )

    [record] = repository_security_findings(
        [finding], "repo", scanner_version="0.2.0"
    )

    assert record["severity"] == "info"
    assert record["confidence"] == "low"
    assert record["validation_state"] == "suspected"
    assert record["location"] == {"kind": "file", "path": "config/app.yml"}
