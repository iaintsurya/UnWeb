from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.repository_analysis import analyse_repository, main


def write_file(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_detects_security_indicators_without_exposing_secret_values(tmp_path):
    write_file(
        tmp_path,
        "src/settings.py",
        '\n'.join([
            'API_KEY = "genuinely-secret-value-123"',
            'requests.get(endpoint, verify=False)',
            'subprocess.run(command, shell=True)',
            'eval(user_input)',
            'yaml.load(untrusted_document)',
            'pickle.loads(untrusted_blob)',
            'os.system(command)',
        ]),
    )
    report = analyse_repository(tmp_path)
    ids = {item.id for item in report.findings}
    assert {
        "possible-hardcoded-secret",
        "tls-certificate-verification-disabled",
        "python-subprocess-shell-true",
        "python-dynamic-evaluation",
        "python-yaml-load",
        "python-pickle-load",
        "python-os-system",
    } <= ids
    rendered = json.dumps(report.to_dict())
    assert "genuinely-secret-value-123" not in rendered
    assert "value has been redacted" in rendered


def test_detects_provider_tokens_and_private_key_marker_without_values(tmp_path):
    token = "ghp_" + "A" * 36
    write_file(
        tmp_path,
        "config/credentials.env",
        "GITHUB_TOKEN=" + token + "\n"
        "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n",
    )
    report = analyse_repository(tmp_path)
    ids = {item.id for item in report.findings}
    assert "github-token" in ids
    assert "private-key-material" in ids
    rendered = json.dumps(report.to_dict())
    assert token not in rendered
    assert "BEGIN RSA PRIVATE KEY" not in rendered


def test_placeholder_values_are_not_reported_as_hardcoded_secrets(tmp_path):
    write_file(tmp_path, ".env.example", 'API_KEY="your_api_key"\nPASSWORD="change-me"\n')
    report = analyse_repository(tmp_path)
    assert not any(item.id == "possible-hardcoded-secret" for item in report.findings)


def test_skips_dependency_build_and_vcs_directories(tmp_path):
    write_file(tmp_path, "src/app.py", "eval(value)\n")
    write_file(tmp_path, "node_modules/vendor/bad.py", "eval(value)\n")
    write_file(tmp_path, ".git/hooks/pre-commit", "eval(value)\n")
    write_file(tmp_path, "dist/generated.py", "eval(value)\n")
    report = analyse_repository(tmp_path)
    assert report.files_scanned == 1
    assert len(report.findings) == 1
    assert report.findings[0].path == "src/app.py"


def test_ignores_symlinked_files_and_directories(tmp_path):
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    write_file(root, "src/app.py", "eval(value)\n")
    write_file(outside, "secret.py", 'API_KEY="outside-secret-value"\n')
    try:
        (root / "linked.py").symlink_to(outside / "secret.py")
        (root / "linked_dir").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks are not available on this platform")
    report = analyse_repository(root)
    assert report.files_scanned == 1
    assert not any(item.path.startswith("linked") for item in report.findings)


def test_file_and_total_byte_budgets_are_enforced(tmp_path):
    write_file(tmp_path, "one.py", "eval(x)\n")
    write_file(tmp_path, "two.py", "eval(y)\n")
    write_file(tmp_path, "large.py", "x" * 200)
    report = analyse_repository(tmp_path, max_files=1, max_total_bytes=100, max_file_bytes=100)
    assert report.files_scanned <= 1
    assert report.bytes_scanned <= 100
    assert report.truncated


def test_rejects_invalid_roots_and_limits(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        analyse_repository(tmp_path / "missing")
    with pytest.raises(ValueError, match="positive"):
        analyse_repository(tmp_path, max_files=0)
    file_path = write_file(tmp_path, "file.txt", "not a repository")
    with pytest.raises(ValueError, match="directory"):
        analyse_repository(file_path)


def test_cli_emits_json_report(tmp_path, monkeypatch, capsys):
    write_file(tmp_path, "app.py", "eval(value)\n")
    monkeypatch.setattr("sys.argv", ["unweb-repository-analysis", str(tmp_path)])
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["repository"] == tmp_path.name
    assert result["findings"][0]["validation_state"] == "suspected"
    assert result["files_scanned"] == 1


def test_detects_node_tls_and_wildcard_cors_configuration(tmp_path):
    write_file(
        tmp_path,
        "config/security.js",
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'
        'allow_origins = ["*"]\n',
    )
    report = analyse_repository(tmp_path)
    ids = {item.id for item in report.findings}
    assert "node-tls-verification-disabled" in ids
    assert "cors-wildcard-origin" in ids


def test_respects_symlink_repository_root_rejection(tmp_path):
    root = tmp_path / "actual"
    root.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks are not available on this platform")
    with pytest.raises(ValueError, match="symbolic link"):
        analyse_repository(alias)
