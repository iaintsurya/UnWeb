"""Bounded public GitHub repository source ingestion.

Only canonical public GitHub repositories are accepted. The selected ref is
resolved to an immutable commit SHA before downloading its source archive.
No GitHub credentials are accepted or stored by this preview integration.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

MAX_GITHUB_ARCHIVE_BYTES = 50_000_000
GITHUB_API = "https://api.github.com"
GITHUB_ARCHIVE_HOST = "codeload.github.com"
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


class GitHubSourceError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def parse_github_repository_url(repository_url: str) -> tuple[str, str]:
    """Accept only https://github.com/{owner}/{repo}[.git] repository URLs."""
    try:
        parsed = urlsplit(repository_url.strip())
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        # Reject duplicate separators instead of normalizing ambiguous paths.
        path = parsed.path[:-1] if parsed.path.endswith("/") else parsed.path
        if "//" in path or not path.startswith("/"):
            raise ValueError
        segments = path[1:].split("/")
        if len(segments) != 2 or any(not part for part in segments):
            raise ValueError
        owner, repository = segments
        if repository.endswith(".git"):
            repository = repository[:-4]
        if not OWNER_RE.fullmatch(owner) or not REPO_RE.fullmatch(repository):
            raise ValueError
        if repository in {".", ".."}:
            raise ValueError
        return owner, repository
    except (ValueError, UnicodeError) as exc:
        raise GitHubSourceError(
            "invalid_github_repository_url",
            "Use a canonical HTTPS GitHub repository URL such as https://github.com/owner/repository.",
        ) from exc


def validate_github_ref(ref: str | None) -> str | None:
    if ref is None:
        return None
    candidate = ref.strip()
    if (
        not REF_RE.fullmatch(candidate)
        or candidate.startswith("/")
        or candidate.endswith("/")
        or "//" in candidate
        or "\\\\" in candidate
        or ".." in candidate
        or "@{" in candidate
        or any(part in {"", "."} for part in candidate.split("/"))
    ):
        raise GitHubSourceError(
            "invalid_github_ref",
            "The Git reference contains unsupported characters or path components.",
        )
    return candidate


def _api_error(response: httpx.Response) -> GitHubSourceError:
    if response.status_code == 404:
        return GitHubSourceError(
            "github_repository_not_found",
            "The repository or ref was not found. Private repositories are not supported by this preview.",
            404,
        )
    if response.status_code in (403, 429):
        return GitHubSourceError(
            "github_rate_limited",
            "GitHub rate-limited the request. Try again later.",
            429,
        )
    return GitHubSourceError(
        "github_request_failed",
        "GitHub could not provide the requested repository metadata or source archive.",
        502,
    )


async def fetch_github_repository_archive(
    repository_url: str,
    ref: str | None,
    destination: str | Path,
) -> dict[str, object]:
    """Resolve a public repository ref and stream its pinned ZIP archive to disk."""
    owner, repository = parse_github_repository_url(repository_url)
    selected_ref = validate_github_ref(ref)
    repository_path = f"/repos/{owner}/{repository}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "UnWeb-authorised-security-assessment",
    }
    timeout = httpx.Timeout(connect=8.0, read=20.0, write=10.0, pool=5.0)
    limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
        trust_env=False,
        headers=headers,
    ) as client:
        default_branch: str | None = None
        if selected_ref is None:
            metadata_response = await client.get(f"{GITHUB_API}{repository_path}")
            if metadata_response.status_code != 200:
                raise _api_error(metadata_response)
            try:
                metadata = metadata_response.json()
            except ValueError as exc:
                raise GitHubSourceError(
                    "github_metadata_invalid",
                    "GitHub returned invalid repository metadata.",
                    502,
                ) from exc
            if not isinstance(metadata, dict):
                raise GitHubSourceError(
                    "github_metadata_invalid",
                    "GitHub returned invalid repository metadata.",
                    502,
                )
            default_branch = metadata.get("default_branch")
            if not isinstance(default_branch, str):
                raise GitHubSourceError(
                    "github_metadata_invalid",
                    "GitHub did not return a usable default branch.",
                    502,
                )
            selected_ref = validate_github_ref(default_branch)

        encoded_ref = quote(selected_ref or "", safe="")
        commit_response = await client.get(
            f"{GITHUB_API}{repository_path}/commits/{encoded_ref}"
        )
        if commit_response.status_code != 200:
            raise _api_error(commit_response)
        try:
            commit_data = commit_response.json()
        except ValueError as exc:
            raise GitHubSourceError(
                "github_commit_identity_invalid",
                "GitHub returned invalid commit metadata.",
                502,
            ) from exc
        commit = commit_data.get("sha") if isinstance(commit_data, dict) else None
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            raise GitHubSourceError(
                "github_commit_identity_invalid",
                "GitHub did not return a valid immutable commit SHA.",
                502,
            )

        archive_response = await client.get(
            f"{GITHUB_API}{repository_path}/zipball/{commit}"
        )
        if archive_response.status_code != 302:
            raise _api_error(archive_response)
        location = archive_response.headers.get("location", "")
        parsed_location = urlsplit(location)
        expected_prefix = f"/{owner}/{repository}/"
        if (
            parsed_location.scheme != "https"
            or parsed_location.hostname != GITHUB_ARCHIVE_HOST
            or parsed_location.port not in (None, 443)
            or parsed_location.username is not None
            or parsed_location.password is not None
            or not parsed_location.path.startswith(expected_prefix)
        ):
            raise GitHubSourceError(
                "github_archive_redirect_rejected",
                "GitHub returned an archive redirect outside the approved archive host.",
                502,
            )

        total_bytes = 0
        archive_headers = {"User-Agent": "UnWeb-authorised-security-assessment"}
        async with client.stream(
            "GET", location, headers=archive_headers, follow_redirects=False
        ) as archive_response:
            if archive_response.status_code != 200:
                raise _api_error(archive_response)
            content_length = archive_response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > MAX_GITHUB_ARCHIVE_BYTES:
                        raise GitHubSourceError(
                            "github_archive_too_large",
                            "GitHub source archives are limited to 50 MB.",
                            413,
                        )
                except ValueError as exc:
                    raise GitHubSourceError(
                        "github_archive_invalid_length",
                        "GitHub returned an invalid archive size.",
                        502,
                    ) from exc
            with Path(destination).open("wb") as output:
                async for chunk in archive_response.aiter_bytes(64 * 1024):
                    total_bytes += len(chunk)
                    if total_bytes > MAX_GITHUB_ARCHIVE_BYTES:
                        raise GitHubSourceError(
                            "github_archive_too_large",
                            "GitHub source archives are limited to 50 MB.",
                            413,
                        )
                    output.write(chunk)

    if total_bytes == 0:
        raise GitHubSourceError(
            "github_archive_empty",
            "GitHub returned an empty source archive.",
            502,
        )
    return {
        "provider": "github",
        "full_name": f"{owner}/{repository}",
        "requested_ref": selected_ref,
        "default_branch": default_branch,
        "commit_sha": commit.lower(),
        "archive_bytes": total_bytes,
    }
