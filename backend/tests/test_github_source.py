import asyncio

import httpx
import pytest

from app import github_source


COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"


def test_parse_github_repository_url_accepts_canonical_https_and_git_suffix():
    assert github_source.parse_github_repository_url(
        "https://github.com/owner-name/sample_repo.git"
    ) == ("owner-name", "sample_repo")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "https://github.com.evil.test/owner/repo",
        "https://user:pass@github.com/owner/repo",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo?download=1",
        "https://codeload.github.com/owner/repo",
        "https://github.com/owner/repo/../../other",
    ],
)
def test_parse_github_repository_url_rejects_noncanonical_urls(url):
    with pytest.raises(github_source.GitHubSourceError):
        github_source.parse_github_repository_url(url)


@pytest.mark.parametrize("ref", ["../main", "/main", "main/", "main//dev", "main\\\\dev", "a..b", "branch@{1}"])
def test_validate_github_ref_rejects_unsafe_or_ambiguous_refs(ref):
    with pytest.raises(github_source.GitHubSourceError):
        github_source.validate_github_ref(ref)


def test_fetch_github_archive_resolves_default_branch_and_pins_commit(tmp_path, monkeypatch):
    archive_bytes = b"fake-zip-content"
    requested = []

    def handler(request):
        requested.append(str(request.url))
        if request.url.host == "api.github.com" and request.url.path == "/repos/owner/repo":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.host == "api.github.com" and request.url.path == "/repos/owner/repo/commits/main":
            return httpx.Response(200, json={"sha": COMMIT_SHA})
        if request.url.host == "api.github.com" and request.url.path == f"/repos/owner/repo/zipball/{COMMIT_SHA}":
            return httpx.Response(
                302,
                headers={"location": f"https://codeload.github.com/owner/repo/legacy.zip/{COMMIT_SHA}"},
            )
        if request.url.host == "codeload.github.com":
            return httpx.Response(200, content=archive_bytes)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        github_source.httpx,
        "AsyncClient",
        lambda *args, **kwargs: original_client(*args, transport=transport, **kwargs),
    )
    destination = tmp_path / "repository.zip"
    result = asyncio.run(github_source.fetch_github_repository_archive(
        "https://github.com/owner/repo", None, destination
    ))

    assert destination.read_bytes() == archive_bytes
    assert result["full_name"] == "owner/repo"
    assert result["requested_ref"] == "main"
    assert result["default_branch"] == "main"
    assert result["commit_sha"] == COMMIT_SHA
    assert result["archive_bytes"] == len(archive_bytes)
    assert any(COMMIT_SHA in url for url in requested)


def test_fetch_github_archive_rejects_same_repo_redirect_to_different_commit(tmp_path, monkeypatch):
    other_commit = "f" * 40

    def handler(request):
        if request.url.path == "/repos/owner/repo/commits/main":
            return httpx.Response(200, json={"sha": COMMIT_SHA})
        if request.url.path == f"/repos/owner/repo/zipball/{COMMIT_SHA}":
            return httpx.Response(
                302,
                headers={
                    "location": f"https://codeload.github.com/owner/repo/legacy.zip/{other_commit}"
                },
            )
        if request.url.host == "codeload.github.com":
            return httpx.Response(200, content=b"not-a-real-but-nonempty-archive")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        github_source.httpx,
        "AsyncClient",
        lambda *args, **kwargs: original_client(*args, transport=transport, **kwargs),
    )
    with pytest.raises(github_source.GitHubSourceError) as error:
        asyncio.run(github_source.fetch_github_repository_archive(
            "https://github.com/owner/repo", "main", tmp_path / "repository.zip"
        ))
    assert error.value.code == "github_archive_redirect_rejected"


def test_fetch_github_archive_rejects_redirect_to_unapproved_host(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/repos/owner/repo/commits/main":
            return httpx.Response(200, json={"sha": COMMIT_SHA})
        if request.url.path == f"/repos/owner/repo/zipball/{COMMIT_SHA}":
            return httpx.Response(302, headers={"location": "https://attacker.example/archive.zip"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        github_source.httpx,
        "AsyncClient",
        lambda *args, **kwargs: original_client(*args, transport=transport, **kwargs),
    )
    with pytest.raises(github_source.GitHubSourceError) as error:
        asyncio.run(github_source.fetch_github_repository_archive(
            "https://github.com/owner/repo", "main", tmp_path / "repository.zip"
        ))
    assert error.value.code == "github_archive_redirect_rejected"


def test_fetch_github_archive_enforces_streamed_size_limit(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == f"/repos/owner/repo/commits/main":
            return httpx.Response(200, json={"sha": COMMIT_SHA})
        if request.url.path == f"/repos/owner/repo/zipball/{COMMIT_SHA}":
            return httpx.Response(
                302,
                headers={"location": f"https://codeload.github.com/owner/repo/legacy.zip/{COMMIT_SHA}"},
            )
        if request.url.host == "codeload.github.com":
            return httpx.Response(
                200,
                headers={"content-length": str(github_source.MAX_GITHUB_ARCHIVE_BYTES + 1)},
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        github_source.httpx,
        "AsyncClient",
        lambda *args, **kwargs: original_client(*args, transport=transport, **kwargs),
    )
    with pytest.raises(github_source.GitHubSourceError) as error:
        asyncio.run(github_source.fetch_github_repository_archive(
            "https://github.com/owner/repo", "main", tmp_path / "repository.zip"
        ))
    assert error.value.code == "github_archive_too_large"


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com//owner/repo",
        "https://github.com/owner//repo",
        "https://github.com/owner/repo//",
    ],
)
def test_parse_github_repository_url_rejects_duplicate_path_separators(url):
    with pytest.raises(github_source.GitHubSourceError):
        github_source.parse_github_repository_url(url)


def test_parse_github_repository_url_accepts_one_trailing_slash():
    assert github_source.parse_github_repository_url(
        "https://github.com/owner/repo/"
    ) == ("owner", "repo")


@pytest.mark.parametrize("metadata_body", ["not-json", "[]", "null"])
def test_fetch_github_archive_rejects_invalid_repository_metadata(
    tmp_path, monkeypatch, metadata_body
):
    def handler(request):
        return httpx.Response(200, text=metadata_body)

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        github_source.httpx,
        "AsyncClient",
        lambda *args, **kwargs: original_client(*args, transport=transport, **kwargs),
    )
    with pytest.raises(github_source.GitHubSourceError) as error:
        asyncio.run(github_source.fetch_github_repository_archive(
            "https://github.com/owner/repo", None, tmp_path / "repository.zip"
        ))
    assert error.value.code == "github_metadata_invalid"
