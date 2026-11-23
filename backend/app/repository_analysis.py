"""Bounded, read-only static checks for a local repository checkout.

No repository code is executed, no dependencies are installed, and no network
requests are made. Results are heuristic indicators, not validated findings.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000
MAX_FILES = 1_500
MAX_FINDINGS = 500
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
    "node_modules", "vendor", "dist", "build", "coverage", ".next",
    ".nuxt", ".terraform", "target", "pods", ".idea", ".pytest_cache",
}
SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".c", ".h", ".cc",
    ".cpp", ".hpp", ".rs", ".swift", ".sh", ".bash", ".ps1",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".properties", ".gradle", ".tf", ".sql",
}
SPECIAL_FILENAMES = {
    "dockerfile", "makefile", "procfile", "requirements.txt",
    "pipfile", "gemfile", "go.mod", "cargo.toml", "pom.xml",
}
SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)\b(?P<key>password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["'](?P<value>[^"'\r\n]{8,})["']"""
)
TOKEN_PATTERNS = (
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
PLACEHOLDERS = {
    "changeme", "change-me", "replace-me", "your-secret-here",
    "your_api_key", "your-api-key", "example", "sample", "dummy",
    "placeholder", "redacted", "none", "null", "false", "true",
    "test", "testing", "xxx", "xxxx",
}


@dataclass(frozen=True)
class RepositoryFinding:
    id: str
    category: str
    title: str
    severity: str
    confidence: str
    path: str
    line: int
    validation_state: str
    evidence: str
    recommendation: str


@dataclass
class RepositoryReport:
    repository: str
    scanner_version: str
    findings: list[RepositoryFinding]
    files_scanned: int
    bytes_scanned: int
    skipped_files: int
    truncated: bool
    limitations: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "scanner_version": self.scanner_version,
            "findings": [asdict(item) for item in self.findings],
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "skipped_files": self.skipped_files,
            "truncated": self.truncated,
            "limitations": self.limitations,
        }


def _is_candidate(path: Path) -> bool:
    name = path.name.lower()
    return (
        name == ".env"
        or name.startswith(".env.")
        or name.endswith(".env")
        or name in SPECIAL_FILENAMES
        or path.suffix.lower() in SOURCE_EXTENSIONS
    )


def _iter_candidate_files(root: Path) -> Iterator[Path]:
    """Yield regular candidate files without following symlinks."""
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.lower())
        except OSError:
            continue
        subdirectories: list[Path] = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() not in SKIP_DIRS:
                        subdirectories.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    candidate = Path(entry.path)
                    if _is_candidate(candidate):
                        yield candidate
            except OSError:
                continue
        pending.extend(reversed(subdirectories))


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in PLACEHOLDERS:
        return True
    if normalized.startswith(("$" + "{", "{{", "os.getenv(", "getenv(", "process.env.")):
        return True
    return bool(re.fullmatch(r"<[^>]+>", normalized))


def _redact_evidence(line: str) -> str:
    """Strip common credential-shaped values before evidence is returned."""
    safe = SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('key')}=[REDACTED]", line
    )
    safe = re.sub(
        r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]{8,}",
        r"\1[REDACTED]",
        safe,
    )
    for _, pattern in TOKEN_PATTERNS:
        safe = pattern.sub("[REDACTED_TOKEN]", safe)
    return safe.strip()[:220]


def _finding(
    rule_id: str, category: str, title: str, severity: str, confidence: str,
    relative_path: str, line_number: int, evidence: str, recommendation: str,
) -> RepositoryFinding:
    return RepositoryFinding(
        id=rule_id, category=category, title=title, severity=severity,
        confidence=confidence, path=relative_path, line=line_number,
        validation_state="suspected", evidence=evidence,
        recommendation=recommendation,
    )


def _analyse_line(
    path: Path, relative_path: str, line_number: int, line: str
) -> list[RepositoryFinding]:
    findings: list[RepositoryFinding] = []
    suffix = path.suffix.lower()
    safe_line = _redact_evidence(line)

    secret_match = SECRET_ASSIGNMENT.search(line)
    if secret_match and not _is_placeholder(secret_match.group("value")):
        findings.append(_finding(
            "possible-hardcoded-secret", "secrets",
            "Possible hard-coded credential or secret", "high", "medium",
            relative_path, line_number,
            "A credential-like assignment was found; its value has been redacted.",
            "Move the value to a secret manager or runtime environment variable, rotate it if committed, and review repository history.",
        ))

    for rule_id, pattern in TOKEN_PATTERNS:
        if pattern.search(line):
            findings.append(_finding(
                rule_id, "secrets", "Possible provider access token in source",
                "high", "high", relative_path, line_number,
                "A provider-token-shaped string was detected; the token value has been redacted.",
                "Revoke and rotate the token, remove it from the working tree and repository history, and use a managed secret.",
            ))
            break

    if PRIVATE_KEY.search(line):
        findings.append(_finding(
            "private-key-material", "secrets", "Private-key material marker found",
            "high", "high", relative_path, line_number,
            "A private-key PEM marker was found; key material is not included in this report.",
            "Remove the private key from source control, rotate the associated credential, and store keys in a protected secret store.",
        ))

    if suffix not in {".py", ".pyi"} and re.search(r"\bverify\s*=\s*False\b", line, re.I):
        findings.append(_finding(
            "tls-certificate-verification-disabled", "transport-security",
            "TLS certificate verification is disabled", "medium", "high",
            relative_path, line_number, safe_line,
            "Enable certificate verification and configure a trusted CA bundle instead of disabling TLS validation.",
        ))

    if re.search(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]", line):
        findings.append(_finding(
            "node-tls-verification-disabled", "transport-security",
            "Node.js TLS certificate verification is disabled", "high", "high",
            relative_path, line_number, safe_line,
            "Remove this override and restore normal TLS certificate validation.",
        ))

    if (
        re.search(r"\ballow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", line, re.I)
        or re.search(r"access-control-allow-origin\s*[:=]\s*['\"]\*['\"]", line, re.I)
    ):
        findings.append(_finding(
            "cors-wildcard-origin", "security-misconfiguration",
            "Wildcard CORS origin configuration observed", "low", "medium",
            relative_path, line_number, safe_line,
            "Restrict cross-origin access to required trusted origins. Review credential handling and browser access requirements.",
        ))

    return findings



def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _analyse_python_ast(
    source: str, relative_path: str
) -> list[RepositoryFinding]:
    """Inspect Python syntax trees without importing or executing repository code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines = source.splitlines()
    findings: list[RepositoryFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = _dotted_name(node.func)
        line_number = getattr(node, "lineno", 1)
        source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
        evidence = _redact_evidence(source_line)

        if function in {"eval", "exec"}:
            findings.append(_finding(
                "python-dynamic-evaluation", "injection",
                "Python dynamic evaluation call observed", "medium", "medium",
                relative_path, line_number, evidence,
                "Avoid evaluating data as code. Use a constrained parser or explicit operation mapping.",
            ))
        elif function in {
            "subprocess.run", "subprocess.Popen", "subprocess.call",
            "subprocess.check_call", "subprocess.check_output",
        }:
            shell_enabled = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_enabled:
                findings.append(_finding(
                    "python-subprocess-shell-true", "command-execution",
                    "Subprocess is invoked with shell=True", "medium", "medium",
                    relative_path, line_number, evidence,
                    "Prefer an argument list with shell=False. Never concatenate untrusted input into a shell command.",
                ))
        elif function == "os.system":
            findings.append(_finding(
                "python-os-system", "command-execution",
                "os.system command execution call observed", "medium", "low",
                relative_path, line_number, evidence,
                "Prefer subprocess with an argument list and shell=False; validate and constrain command arguments.",
            ))
        elif function == "yaml.load":
            has_safe_loader = any(
                keyword.arg == "Loader"
                and _dotted_name(keyword.value).endswith("SafeLoader")
                for keyword in node.keywords
            )
            if not has_safe_loader:
                findings.append(_finding(
                    "python-yaml-load", "unsafe-deserialization",
                    "YAML load call without SafeLoader", "medium", "medium",
                    relative_path, line_number, evidence,
                    "Use yaml.safe_load for untrusted YAML, or pass yaml.SafeLoader explicitly.",
                ))
        elif function in {"pickle.load", "pickle.loads"}:
            findings.append(_finding(
                "python-pickle-load", "unsafe-deserialization",
                "Python pickle deserialization call observed", "high", "medium",
                relative_path, line_number, evidence,
                "Do not unpickle untrusted or attacker-controlled data. Prefer a non-executable serialization format.",
            ))

        if any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        ):
            findings.append(_finding(
                "tls-certificate-verification-disabled", "transport-security",
                "TLS certificate verification is disabled", "medium", "high",
                relative_path, line_number, evidence,
                "Enable certificate verification and configure a trusted CA bundle instead of disabling TLS validation.",
            ))

    return findings


def analyse_repository(
    repository_path: str | Path, *, max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> RepositoryReport:
    """Analyse a local checkout within strict file and byte budgets."""
    if max_files < 1 or max_total_bytes < 1 or max_file_bytes < 1:
        raise ValueError("Repository scan limits must be positive.")

    supplied_root = Path(repository_path).expanduser()
    if supplied_root.is_symlink():
        raise ValueError("Repository root must not be a symbolic link.")
    try:
        root = supplied_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Repository path does not exist or cannot be accessed.") from exc
    if not root.is_dir():
        raise ValueError("Repository path must be a directory.")

    findings: list[RepositoryFinding] = []
    seen: set[tuple[str, str, int]] = set()
    files_scanned = bytes_scanned = skipped_files = 0
    truncated = False

    for path in _iter_candidate_files(root):
        if files_scanned >= max_files or bytes_scanned >= max_total_bytes:
            truncated = True
            break
        try:
            if path.is_symlink():
                skipped_files += 1
                continue
            resolved = path.resolve(strict=True)
            if root not in resolved.parents:
                skipped_files += 1
                continue
            size = path.stat().st_size
            remaining = max_total_bytes - bytes_scanned
            if size > max_file_bytes or size > remaining:
                skipped_files += 1
                continue
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
        except OSError:
            skipped_files += 1
            continue

        if len(raw) > max_file_bytes or b"\x00" in raw:
            skipped_files += 1
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            skipped_files += 1
            continue

        files_scanned += 1
        bytes_scanned += len(raw)
        relative_path = path.relative_to(root).as_posix()
        file_findings: list[RepositoryFinding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            file_findings.extend(_analyse_line(path, relative_path, line_number, line))
        if path.suffix.lower() in {".py", ".pyi"}:
            file_findings.extend(_analyse_python_ast(content, relative_path))
        for item in file_findings:
            key = (item.id, item.path, item.line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
            if len(findings) >= MAX_FINDINGS:
                break
        if len(findings) >= MAX_FINDINGS:
            truncated = True
            break

    return RepositoryReport(
        repository=root.name, scanner_version="0.1.0", findings=findings,
        files_scanned=files_scanned, bytes_scanned=bytes_scanned,
        skipped_files=skipped_files, truncated=truncated,
        limitations=[
            "Python dangerous-call checks use AST; cross-language/configuration checks are lexical and line-based. No control-flow, data-flow, or reachability analysis is performed.",
            "Findings are suspected indicators, not validated vulnerabilities.",
            "No repository code is executed and no network requests are made.",
            "Dependencies are not installed and dependency advisories are not queried.",
            "Coverage is limited to supported source/configuration types and bounded scan budgets.",
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run bounded, read-only UnWeb checks on a local repository checkout."
    )
    parser.add_argument("repository", help="Path to a local repository checkout")
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL_BYTES)
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    args = parser.parse_args()
    try:
        report = analyse_repository(
            args.repository, max_files=args.max_files,
            max_total_bytes=args.max_total_bytes, max_file_bytes=args.max_file_bytes,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
