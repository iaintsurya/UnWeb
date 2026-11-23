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
import stat
import tempfile
import zipfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from .finding_schema import repository_security_findings
from typing import Iterator

MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000
MAX_FILES = 1_500
MAX_FINDINGS = 500
MAX_DEPENDENCY_RECORDS = 5_000
MAX_ARCHIVE_BYTES = 50_000_000
MAX_ARCHIVE_ENTRIES = 6_000
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
    "pipfile", "gemfile", "go.mod", "cargo.toml", "cargo.lock", "pom.xml",
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


@dataclass(frozen=True)
class DependencyRecord:
    name: str
    ecosystem: str
    source_path: str
    source_type: str
    version_constraint: str | None = None
    resolved_version: str | None = None
    dependency_group: str = "runtime"


@dataclass
class RepositoryReport:
    repository: str
    scanner_version: str
    findings: list[RepositoryFinding]
    dependency_inventory: list[DependencyRecord]
    files_scanned: int
    bytes_scanned: int
    skipped_files: int
    truncated: bool
    limitations: list[str]
    dependency_inventory_truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "scanner_version": self.scanner_version,
            "findings": [asdict(item) for item in self.findings],
            "security_findings": repository_security_findings(
                self.findings, self.repository, scanner_version=self.scanner_version
            ),
            "dependency_inventory": [asdict(item) for item in self.dependency_inventory],
            "dependency_count": len(self.dependency_inventory),
            "dependency_inventory_truncated": self.dependency_inventory_truncated,
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
        or (name.startswith("requirements") and name.endswith((".txt", ".in")))
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
    except (SyntaxError, RecursionError, ValueError):
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



def _dependency_from_requirement(
    requirement: str, ecosystem: str, source_path: str, group: str
) -> DependencyRecord | None:
    value = requirement.strip()
    if not value or value.startswith(("#", "-", "git+", "http:", "https:")):
        return None
    value = value.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$", value)
    if not match:
        return None
    name = match.group(1)
    constraint = match.group(2).strip() or None
    return DependencyRecord(
        name=name, ecosystem=ecosystem, source_path=source_path,
        source_type="manifest", version_constraint=constraint,
        dependency_group=group,
    )


def _extract_dependencies(
    path: Path, content: str, relative_path: str, *, max_records: int = MAX_DEPENDENCY_RECORDS
) -> list[DependencyRecord]:
    """Parse common dependency manifests/lockfiles using only stdlib parsers."""
    name = path.name.lower()
    records: list[DependencyRecord] = []

    if name == "package.json":
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError, RecursionError):
            return []
        if not isinstance(data, dict):
            return []
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            section = data.get(group, {})
            if not isinstance(section, dict):
                continue
            for package_name, constraint in section.items():
                if isinstance(package_name, str) and isinstance(constraint, str):
                    records.append(DependencyRecord(
                        name=package_name, ecosystem="npm",
                        source_path=relative_path, source_type="manifest",
                        version_constraint=constraint,
                        dependency_group=group,
                    ))

    elif name == "package-lock.json":
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError, RecursionError):
            return []
        if not isinstance(data, dict):
            return []
        packages = data.get("packages", {})
        if isinstance(packages, dict) and packages:
            for package_path, package in packages.items():
                if not package_path or not isinstance(package, dict):
                    continue
                if not package_path.startswith("node_modules/"):
                    continue
                package_name = package_path.rsplit("node_modules/", 1)[-1]
                if isinstance(package.get("name"), str):
                    package_name = package["name"]
                version = package.get("version")
                records.append(DependencyRecord(
                    name=package_name, ecosystem="npm",
                    source_path=relative_path, source_type="lockfile",
                    resolved_version=version if isinstance(version, str) else None,
                    dependency_group="locked",
                ))
        else:
            # npm lockfile v1 stores dependencies as a nested tree. Walk it
            # iteratively: repository-controlled nesting must not consume the
            # Python call stack.
            pending = [data.get("dependencies", {})]
            while pending and len(records) <= max_records:
                tree = pending.pop()
                if not isinstance(tree, dict):
                    continue
                for package_name, package in tree.items():
                    if not isinstance(package, dict):
                        continue
                    version = package.get("version")
                    records.append(DependencyRecord(
                        name=str(package_name), ecosystem="npm",
                        source_path=relative_path, source_type="lockfile",
                        resolved_version=version if isinstance(version, str) else None,
                        dependency_group="locked",
                    ))
                    children = package.get("dependencies", {})
                    if isinstance(children, dict):
                        pending.append(children)
                    if len(records) > max_records:
                        break

    elif name == "pyproject.toml":
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError, RecursionError):
            return []
        project = data.get("project", {})
        if isinstance(project, dict):
            for requirement in project.get("dependencies", []):
                if isinstance(requirement, str):
                    item = _dependency_from_requirement(
                        requirement, "pypi", relative_path, "runtime"
                    )
                    if item:
                        records.append(item)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group, requirements in optional.items():
                    if isinstance(requirements, list):
                        for requirement in requirements:
                            if isinstance(requirement, str):
                                item = _dependency_from_requirement(
                                    requirement, "pypi", relative_path, str(group)
                                )
                                if item:
                                    records.append(item)
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool", {}), dict) else {}
        if isinstance(poetry, dict):
            for group in ("dependencies", "dev-dependencies"):
                section = poetry.get(group, {})
                if isinstance(section, dict):
                    for package_name, constraint in section.items():
                        if package_name.lower() == "python":
                            continue
                        version = constraint if isinstance(constraint, str) else (
                            constraint.get("version") if isinstance(constraint, dict) else None
                        )
                        records.append(DependencyRecord(
                            name=package_name, ecosystem="pypi",
                            source_path=relative_path, source_type="manifest",
                            version_constraint=version if isinstance(version, str) else None,
                            dependency_group="development" if group == "dev-dependencies" else "runtime",
                        ))

    elif name.startswith("requirements") and name.endswith((".txt", ".in")):
        for line in content.splitlines():
            item = _dependency_from_requirement(
                line, "pypi", relative_path, "runtime"
            )
            if item:
                records.append(item)

    elif name == "cargo.toml":
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError, RecursionError):
            return []
        groups = ("dependencies", "dev-dependencies", "build-dependencies")
        sections = [(group, data.get(group, {})) for group in groups]
        target = data.get("target", {})
        if isinstance(target, dict):
            for target_section in target.values():
                if isinstance(target_section, dict):
                    sections.extend((group, target_section.get(group, {})) for group in groups)
        for group, section in sections:
            if isinstance(section, dict):
                for package_name, constraint in section.items():
                    version = constraint if isinstance(constraint, str) else (
                        constraint.get("version") if isinstance(constraint, dict) else None
                    )
                    records.append(DependencyRecord(
                        name=package_name, ecosystem="cargo",
                        source_path=relative_path, source_type="manifest",
                        version_constraint=version if isinstance(version, str) else None,
                        dependency_group=group,
                    ))

    elif name == "cargo.lock":
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError, RecursionError):
            return []
        for package in data.get("package", []):
            if isinstance(package, dict) and isinstance(package.get("name"), str):
                version = package.get("version")
                records.append(DependencyRecord(
                    name=package["name"], ecosystem="cargo",
                    source_path=relative_path, source_type="lockfile",
                    resolved_version=version if isinstance(version, str) else None,
                    dependency_group="locked",
                ))

    elif name == "go.mod":
        in_require_block = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and stripped == ")":
                in_require_block = False
                continue
            if stripped.startswith("require "):
                parts = stripped.split()
                if len(parts) >= 3:
                    records.append(DependencyRecord(
                        name=parts[1], ecosystem="go",
                        source_path=relative_path, source_type="manifest",
                        version_constraint=parts[2],
                    ))
                continue
            if in_require_block and stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2:
                    records.append(DependencyRecord(
                        name=parts[0], ecosystem="go",
                        source_path=relative_path, source_type="manifest",
                        version_constraint=parts[1],
                    ))
    # One extra record is a sentinel so the caller can report truncation.
    return records[: max_records + 1]



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
    dependency_inventory: list[DependencyRecord] = []
    dependency_inventory_truncated = False
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
        remaining_dependencies = MAX_DEPENDENCY_RECORDS - len(dependency_inventory)
        if not dependency_inventory_truncated:
            extracted_dependencies = _extract_dependencies(
                path, content, relative_path,
                max_records=max(0, remaining_dependencies),
            )
            if len(extracted_dependencies) > remaining_dependencies:
                dependency_inventory.extend(extracted_dependencies[:remaining_dependencies])
                dependency_inventory_truncated = True
            else:
                dependency_inventory.extend(extracted_dependencies)
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
        repository=root.name, scanner_version="0.2.0", findings=findings,
        dependency_inventory=dependency_inventory,
        files_scanned=files_scanned, bytes_scanned=bytes_scanned,
        skipped_files=skipped_files, truncated=truncated or dependency_inventory_truncated,
        limitations=[
            "Python dangerous-call checks use AST; cross-language/configuration checks are lexical and line-based. No control-flow, data-flow, or reachability analysis is performed.",
            "Findings are suspected indicators, not validated vulnerabilities.",
            "No repository code is executed and no network requests are made.",
            "Dependency manifests and lockfiles are inventoried, but no advisory database is queried and no vulnerable-version conclusion is made.",
            "Coverage is limited to supported source/configuration types and bounded scan budgets.",
            "Dependency inventory is capped at 5,000 records; the report marks when additional records may have been omitted.",
        ],
        dependency_inventory_truncated=dependency_inventory_truncated,
    )



def analyse_repository_archive(
    archive_path: str | Path, *,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
) -> RepositoryReport:
    """Safely inspect a repository ZIP without executing or networking."""
    archive = Path(archive_path).expanduser()
    if archive.is_symlink():
        raise ValueError("Archive must not be a symbolic link.")
    try:
        archive_stat = archive.stat()
    except OSError as exc:
        raise ValueError("Archive does not exist or cannot be accessed.") from exc
    if not stat.S_ISREG(archive_stat.st_mode):
        raise ValueError("Archive path must be a regular file.")
    if archive_stat.st_size > max_archive_bytes:
        raise ValueError("Archive exceeds the compressed input size limit.")
    if max_files < 1 or max_total_bytes < 1 or max_file_bytes < 1 or max_archive_bytes < 1:
        raise ValueError("Repository scan limits must be positive.")

    try:
        zipped = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("Input is not a valid ZIP archive.") from exc

    skipped = 0
    accepted = 0
    actual_bytes = 0
    truncated = False
    seen_paths: set[str] = set()

    with zipped, tempfile.TemporaryDirectory(prefix="unweb-repo-") as temporary:
        root = Path(temporary).resolve()
        infos = zipped.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("Archive contains too many entries.")

        for info in infos:
            if info.is_dir():
                continue
            raw_name = info.filename
            # ZIP paths use forward slashes. Reject ambiguous Windows separators,
            # absolute paths, drive prefixes, traversal and NUL bytes.
            if (
                not raw_name
                or "\x00" in raw_name
                or "\\" in raw_name
                or raw_name.startswith("/")
                or re.match(r"^[A-Za-z]:", raw_name)
            ):
                skipped += 1
                continue
            parts = Path(raw_name).parts
            if any(part in {"", ".", ".."} for part in parts):
                skipped += 1
                continue
            normalized = "/".join(parts)
            if normalized in seen_paths:
                skipped += 1
                continue
            seen_paths.add(normalized)

            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK or (mode not in {0, stat.S_IFREG}):
                skipped += 1
                continue

            relative = Path(*parts)
            if not _is_candidate(relative):
                continue
            if accepted >= max_files or actual_bytes >= max_total_bytes:
                truncated = True
                break
            if info.file_size > max_file_bytes or info.file_size > max_total_bytes - actual_bytes:
                skipped += 1
                truncated = True
                continue

            target = (root / relative).resolve()
            if root not in target.parents:
                skipped += 1
                continue

            try:
                with zipped.open(info, "r") as source:
                    content = source.read(max_file_bytes + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                skipped += 1
                continue
            if len(content) > max_file_bytes or len(content) != info.file_size or b"\x00" in content:
                skipped += 1
                continue
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            # We created the temporary parent tree ourselves and reject paths
            # that resolve outside it; files are created exclusively.
            try:
                with target.open("xb") as destination:
                    destination.write(content)
            except OSError:
                skipped += 1
                continue
            accepted += 1
            actual_bytes += len(content)

        report = analyse_repository(
            root,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_file_bytes=max_file_bytes,
        )
        report.repository = archive.stem
        report.skipped_files += skipped
        report.truncated = report.truncated or truncated
        return report



def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run bounded, read-only UnWeb checks on a local repository checkout."
    )
    parser.add_argument("repository", help="Path to a local repository checkout")
    parser.add_argument("--archive", action="store_true", help="Treat input as a bounded ZIP archive")
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL_BYTES)
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    args = parser.parse_args()
    try:
        analyser = analyse_repository_archive if args.archive else analyse_repository
        report = analyser(
            args.repository, max_files=args.max_files,
            max_total_bytes=args.max_total_bytes, max_file_bytes=args.max_file_bytes,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
