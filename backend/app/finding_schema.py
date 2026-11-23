"""Common evidence record adapters for website and repository findings.

The normalised record is an evidence container, not a declaration that a
suspected condition is exploitable. Severity and confidence remain separate.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

VALIDATION_STATES = {
    "observed",
    "suspected",
    "validated",
    "inconclusive",
    "not_observed",
    "not_tested",
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
CONFIDENCE_LEVELS = {"low", "medium", "high"}


def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _stable_finding_id(
    source: str,
    check_id: str,
    target: str,
    location: dict[str, Any],
) -> str:
    identity = json.dumps(
        {
            "source": source,
            "check_id": check_id,
            "target": target,
            "location": location,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "unw_" + hashlib.sha256(identity).hexdigest()[:24]


def _normalise_common(
    *,
    source: str,
    check_id: str,
    target: str,
    location: dict[str, Any],
    title: str,
    category: str,
    severity: str,
    confidence: str,
    validation_state: str,
    evidence: str,
    remediation: str,
    scanner_version: str,
    observed_at: str | None = None,
) -> dict[str, Any]:
    safe_severity = severity if severity in SEVERITIES else "info"
    safe_confidence = confidence if confidence in CONFIDENCE_LEVELS else "low"
    safe_validation = (
        validation_state if validation_state in VALIDATION_STATES else "inconclusive"
    )
    result: dict[str, Any] = {
        "finding_id": _stable_finding_id(source, check_id, target, location),
        "check_id": check_id,
        "source": source,
        "target": target,
        "location": location,
        "title": title,
        "category": category,
        "severity": safe_severity,
        "confidence": safe_confidence,
        "validation_state": safe_validation,
        "evidence": evidence,
        "impact": None,
        "preconditions": [],
        "remediation": remediation,
        "scanner_version": scanner_version,
        "scope_id": None,
    }
    if observed_at:
        result["observed_at"] = observed_at
    return result


def website_security_findings(
    findings: list[Any],
    target: str,
    *,
    scanner_version: str,
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    """Convert passive website observations into common evidence records."""
    records = []
    for item in findings:
        check_id = str(_get(item, "id", "unknown-check"))
        title = str(_get(item, "title", "Untitled website observation"))
        category = str(_get(item, "category", "security-configuration"))
        if category == "security-configuration":
            if check_id.startswith("cookie-"):
                category = "session-management"
            elif "transport" in check_id or "https" in check_id or "hsts" in check_id:
                category = "transport-security"
            else:
                category = "security-headers"
        location = {"kind": "url", "value": target}
        records.append(
            _normalise_common(
                source="website",
                check_id=check_id,
                target=target,
                location=location,
                title=title,
                category=category,
                severity=str(_get(item, "severity", "info")),
                confidence=str(_get(item, "confidence", "low")),
                # These checks observe response configuration; they do not
                # validate exploitability or application-level impact.
                validation_state="observed",
                evidence=str(_get(item, "evidence", "")),
                remediation=str(_get(item, "recommendation", "")),
                scanner_version=scanner_version,
                observed_at=observed_at,
            )
        )
    return records


def repository_security_findings(
    findings: list[Any],
    repository: str,
    *,
    scanner_version: str,
) -> list[dict[str, Any]]:
    """Convert static source indicators into common suspected evidence records."""
    records = []
    for item in findings:
        check_id = str(_get(item, "id", "unknown-check"))
        path = str(_get(item, "path", ""))
        line = _get(item, "line")
        location: dict[str, Any] = {"kind": "file", "path": path}
        if isinstance(line, int) and line > 0:
            location["line"] = line
        validation_state = str(_get(item, "validation_state", "suspected"))
        if validation_state not in VALIDATION_STATES:
            validation_state = "suspected"
        records.append(
            _normalise_common(
                source="repository",
                check_id=check_id,
                target=repository,
                location=location,
                title=str(_get(item, "title", "Untitled repository indicator")),
                category=str(_get(item, "category", "source-analysis")),
                severity=str(_get(item, "severity", "info")),
                confidence=str(_get(item, "confidence", "low")),
                validation_state=validation_state,
                evidence=str(_get(item, "evidence", "")),
                remediation=str(_get(item, "recommendation", "")),
                scanner_version=scanner_version,
            )
        )
    return records
