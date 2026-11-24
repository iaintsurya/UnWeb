import httpx
import pytest

from app.dependency_advisories import AdvisoryLookupError, query_advisories


@pytest.mark.anyio
async def test_query_advisories_maps_ecosystem_and_redacts_unneeded_fields():
    def handler(request):
        import json
        payload = json.loads(request.content)
        assert payload["queries"] == [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}
        ]
        return httpx.Response(200, json={"results": [{"vulns": [{
            "id": "GHSA-test-1234",
            "summary": "A test advisory",
            "details": "Long upstream details are intentionally not copied.",
            "aliases": ["CVE-2026-12345"],
            "modified": "2026-11-01T00:00:00Z",
            "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
        }]}]})

    result = await query_advisories(
        [{"name": "requests", "ecosystem": "python", "version": "2.31.0"}],
        transport=httpx.MockTransport(handler),
    )
    assert result["packages_checked"] == 1
    assert result["packages_with_advisories"] == 1
    advisory = result["results"][0]["advisories"][0]
    assert advisory["id"] == "GHSA-test-1234"
    assert "details" not in advisory


@pytest.mark.anyio
async def test_query_advisories_deduplicates_identical_packages():
    def handler(request):
        import json
        assert len(json.loads(request.content)["queries"]) == 1
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    result = await query_advisories(
        [
            {"name": "lodash", "ecosystem": "npm", "version": "4.17.21"},
            {"name": "lodash", "ecosystem": "npm", "version": "4.17.21"},
        ],
        transport=httpx.MockTransport(handler),
    )
    assert result["packages_checked"] == 1
    assert result["advisory_matches"] == 0


@pytest.mark.anyio
async def test_query_advisories_rejects_unresolved_or_unsupported_packages():
    with pytest.raises(ValueError):
        await query_advisories([{"name": "left-pad", "ecosystem": "npm", "version": ""}])
    with pytest.raises(ValueError):
        await query_advisories([{"name": "thing", "ecosystem": "unknown", "version": "1.0"}])


@pytest.mark.anyio
async def test_query_advisories_rejects_oversized_batch():
    packages = [{"name": "pkg", "ecosystem": "npm", "version": "1.0"}] * 101
    with pytest.raises(ValueError):
        await query_advisories(packages)


@pytest.mark.anyio
async def test_query_advisories_handles_provider_failure():
    def handler(request):
        return httpx.Response(503, text="unavailable")

    with pytest.raises(AdvisoryLookupError):
        await query_advisories(
            [{"name": "pkg", "ecosystem": "npm", "version": "1.0"}],
            transport=httpx.MockTransport(handler),
        )


@pytest.mark.anyio
async def test_query_advisories_rejects_oversized_provider_response():
    def handler(request):
        return httpx.Response(200, content=b" " * 2_000_001)

    with pytest.raises(AdvisoryLookupError, match="2 MB"):
        await query_advisories(
            [{"name": "pkg", "ecosystem": "npm", "version": "1.0"}],
            transport=httpx.MockTransport(handler),
        )
