"""Bounded, read-only dependency advisory lookup through the OSV API.

This module accepts package coordinates only; it never executes package code,
downloads dependencies, or follows caller-supplied URLs.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES = 100
MAX_RESPONSE_BYTES = 2_000_000
MAX_ADVISORIES_PER_PACKAGE = 20
TIMEOUT = httpx.Timeout(10.0, connect=4.0)

ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "crates.io": "crates.io",
}


class AdvisoryLookupError(RuntimeError):
    pass


def _normalise_package(item: dict[str, Any]) -> dict[str, str]:
    ecosystem = str(item.get("ecosystem", "")).strip().lower()
    osv_ecosystem = ECOSYSTEMS.get(ecosystem)
    name = str(item.get("name", "")).strip()
    version = str(item.get("version", "")).strip()
    if not osv_ecosystem:
        raise ValueError(f"Unsupported dependency ecosystem: {ecosystem or 'empty'}.")
    if not name or len(name) > 255 or any(ord(char) < 32 for char in name):
        raise ValueError("Dependency names must contain 1–255 printable characters.")
    if not version or len(version) > 100 or any(ord(char) < 32 for char in version):
        raise ValueError("Resolved dependency versions must contain 1–100 printable characters.")
    return {"name": name, "version": version, "ecosystem": osv_ecosystem}


def _safe_advisory(vulnerability: dict[str, Any]) -> dict[str, Any] | None:
    advisory_id = vulnerability.get("id")
    if not isinstance(advisory_id, str) or not advisory_id or len(advisory_id) > 100:
        return None
    aliases = vulnerability.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []
    references = vulnerability.get("references", [])
    if not isinstance(references, list):
        references = []
    safe_references = []
    for reference in references[:10]:
        if isinstance(reference, dict):
            url = reference.get("url")
            if isinstance(url, str) and url.startswith("https://") and len(url) <= 2048:
                safe_references.append(url)
    summary = vulnerability.get("summary")
    return {
        "id": advisory_id,
        "summary": summary[:500] if isinstance(summary, str) else "",
        "aliases": [alias[:100] for alias in aliases[:10] if isinstance(alias, str)],
        "modified": vulnerability.get("modified") if isinstance(vulnerability.get("modified"), str) else None,
        "published": vulnerability.get("published") if isinstance(vulnerability.get("published"), str) else None,
        "references": safe_references,
    }


async def query_advisories(
    packages: list[dict[str, Any]],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Return OSV matches for at most 100 exact, lockfile-resolved package versions."""
    if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_PACKAGES:
        raise ValueError(f"Submit between 1 and {MAX_PACKAGES} resolved dependencies.")

    normalised = [_normalise_package(item) for item in packages]
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in normalised:
        key = (item["ecosystem"], item["name"], item["version"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    payload = {
        "queries": [
            {"package": {"name": item["name"], "ecosystem": item["ecosystem"]}, "version": item["version"]}
            for item in unique
        ]
    }
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        try:
            async with client.stream("POST", OSV_QUERY_BATCH_URL, json=payload) as response:
                if response.status_code != 200:
                    raise AdvisoryLookupError(f"OSV returned HTTP {response.status_code}.")
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise AdvisoryLookupError("OSV response exceeded the 2 MB safety limit.")
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise AdvisoryLookupError("OSV advisory lookup timed out.") from exc
        except httpx.HTTPError as exc:
            raise AdvisoryLookupError("OSV advisory service could not be reached.") from exc

    try:
        data = json.loads(b"".join(chunks))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AdvisoryLookupError("OSV returned invalid JSON.") from exc
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(unique):
        raise AdvisoryLookupError("OSV returned an unexpected batch response.")

    output = []
    total_matches = 0
    for package, result in zip(unique, results):
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else []
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
        advisories = []
        for vulnerability in vulnerabilities[:MAX_ADVISORIES_PER_PACKAGE]:
            if isinstance(vulnerability, dict):
                safe = _safe_advisory(vulnerability)
                if safe:
                    advisories.append(safe)
        total_matches += len(advisories)
        output.append({
            "package": package["name"],
            "ecosystem": package["ecosystem"],
            "version": package["version"],
            "advisories": advisories,
            "advisory_count": len(advisories),
            "truncated": len(vulnerabilities) > MAX_ADVISORIES_PER_PACKAGE,
        })

    return {
        "provider": "OSV",
        "packages_checked": len(output),
        "packages_with_advisories": sum(1 for item in output if item["advisory_count"]),
        "advisory_matches": total_matches,
        "results": output,
        "limitations": [
            "Only exact resolved package versions are queried; unresolved manifest constraints are not assessed.",
            "An empty result means OSV returned no matching advisory, not that the package is secure.",
            "Advisory data may be incomplete, delayed, disputed, or ecosystem-specific; review upstream records.",
        ],
    }
