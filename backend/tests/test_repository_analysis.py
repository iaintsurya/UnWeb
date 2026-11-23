from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from app.repository_analysis import analyse_repository, analyse_repository_archive, main


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



def test_python_ast_handles_multiline_calls_and_ignores_comments(tmp_path):
    write_file(
        tmp_path,
        "src/multiline.py",
        "\n".join([
            "# eval(comment_only)",
            "# os.system(command)",
            "# requests.get(url, verify=False)",
            "subprocess.run(",
            "    command,",
            "    shell=True,",
            ")",
            "requests.get(",
            "    endpoint,",
            "    verify=False,",
            ")",
            "yaml.load(",
            "    untrusted_document,",
            ")",
            "yaml.load(data, Loader=yaml.SafeLoader)",
        ]),
    )
    report = analyse_repository(tmp_path)
    findings = [item for item in report.findings if item.path == "src/multiline.py"]
    ids = {item.id for item in findings}
    assert "python-subprocess-shell-true" in ids
    assert "tls-certificate-verification-disabled" in ids
    assert "python-yaml-load" in ids
    assert not any(item.line < 4 for item in findings)
    assert len([item for item in findings if item.id == "python-yaml-load"]) == 1



def test_inventories_npm_manifest_and_lockfile_without_claiming_vulnerabilities(tmp_path):
    write_file(
        tmp_path,
        "package.json",
        json.dumps({
            "dependencies": {"react": "^18.2.0", "@scope/pkg": "~2.1.0"},
            "devDependencies": {"vitest": "^5.0.0"},
        }),
    )
    write_file(
        tmp_path,
        "package-lock.json",
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "fixture"},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/@scope/pkg": {"version": "2.1.4"},
            },
        }),
    )
    report = analyse_repository(tmp_path)
    inventory = report.to_dict()["dependency_inventory"]
    react = [item for item in inventory if item["name"] == "react"]
    assert {item["source_type"] for item in react} == {"manifest", "lockfile"}
    assert any(item["resolved_version"] == "18.3.1" for item in react)
    assert any(item["version_constraint"] == "^18.2.0" for item in react)
    assert any(item["name"] == "vitest" and item["dependency_group"] == "devDependencies" for item in inventory)
    assert report.scanner_version == "0.2.0"
    assert not any("vulnerable" in item["title"].lower() for item in report.findings)


def test_inventories_python_requirements_and_pyproject_dependencies(tmp_path):
    write_file(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = ["fastapi>=0.100", "httpx==0.28.1"]\n'
        '[project.optional-dependencies]\ntest = ["pytest>=8"]\n',
    )
    write_file(
        tmp_path,
        "requirements-dev.txt",
        "ruff==0.8.0\nrequests>=2.31\n# a comment\n",
    )
    report = analyse_repository(tmp_path)
    inventory = report.to_dict()["dependency_inventory"]
    fastapi = next(item for item in inventory if item["name"] == "fastapi")
    assert fastapi["ecosystem"] == "pypi"
    assert fastapi["version_constraint"] == ">=0.100"
    assert any(item["name"] == "pytest" and item["dependency_group"] == "test" for item in inventory)
    assert any(item["name"] == "ruff" and item["version_constraint"] == "==0.8.0" for item in inventory)
    assert any(item["name"] == "requests" and item["version_constraint"] == ">=2.31" for item in inventory)


def test_inventories_cargo_and_go_manifests_and_lockfiles(tmp_path):
    write_file(
        tmp_path,
        "Cargo.toml",
        '[dependencies]\nserde = "1.0"\n'
        '[dev-dependencies]\npretty_assertions = "1"\n',
    )
    write_file(
        tmp_path,
        "Cargo.lock",
        'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.210"\n',
    )
    write_file(
        tmp_path,
        "go.mod",
        'module example.com/app\n\ngo 1.23\nrequire (\n'
        '  github.com/pkg/errors v0.9.1\n  golang.org/x/text v0.3.0\n)\n',
    )
    report = analyse_repository(tmp_path)
    inventory = report.to_dict()["dependency_inventory"]
    assert any(item["name"] == "serde" and item["source_type"] == "manifest" for item in inventory)
    assert any(item["name"] == "serde" and item["resolved_version"] == "1.0.210" for item in inventory)
    assert any(item["name"] == "pretty_assertions" and item["dependency_group"] == "dev-dependencies" for item in inventory)
    assert any(item["name"] == "github.com/pkg/errors" and item["version_constraint"] == "v0.9.1" for item in inventory)



def test_scans_safe_repository_zip_and_redacts_secrets(tmp_path):
    archive = tmp_path / "sample-repository.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("sample-repository/src/app.py", 'API_KEY="archive-secret-value-123"\neval(user_input)\n')
        zipped.writestr("sample-repository/package.json", json.dumps({
            "dependencies": {"express": "^4.18.0"}
        }))
    report = analyse_repository_archive(archive)
    ids = {item.id for item in report.findings}
    assert "possible-hardcoded-secret" in ids
    assert "python-dynamic-evaluation" in ids
    assert any(item.name == "express" for item in report.dependency_inventory)
    rendered = json.dumps(report.to_dict())
    assert "archive-secret-value-123" not in rendered
    assert report.repository == "sample-repository"


def test_zip_scanner_rejects_path_traversal_and_skips_symlink_entries(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../outside.py", 'API_KEY="must-not-be-read"\n')
        zipped.writestr("repo/src/app.py", "eval(user_input)\n")
        link = zipfile.ZipInfo("repo/linked.py")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zipped.writestr(link, "../outside.py")
    report = analyse_repository_archive(archive)
    assert any(item.id == "python-dynamic-evaluation" for item in report.findings)
    assert not any(item.id == "possible-hardcoded-secret" for item in report.findings)
    assert report.skipped_files >= 2
    assert not (tmp_path / "outside.py").exists()


def test_zip_scanner_enforces_archive_and_entry_budgets(tmp_path):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("repo/large.py", "x" * 100)
        zipped.writestr("repo/small.py", "eval(x)\n")
    report = analyse_repository_archive(
        archive,
        max_file_bytes=50,
        max_total_bytes=80,
    )
    assert report.bytes_scanned <= 80
    assert report.skipped_files >= 1
    assert report.truncated


def test_zip_scanner_rejects_invalid_and_oversized_archives(tmp_path):
    invalid = tmp_path / "not-a-zip.zip"
    invalid.write_text("not a zip", encoding="utf-8")
    with pytest.raises(ValueError, match="valid ZIP"):
        analyse_repository_archive(invalid)
    valid = tmp_path / "valid.zip"
    with zipfile.ZipFile(valid, "w") as zipped:
        zipped.writestr("repo/app.py", "eval(x)\n")
    with pytest.raises(ValueError, match="compressed input size"):
        analyse_repository_archive(valid, max_archive_bytes=1)


def test_cli_accepts_zip_archive_mode(tmp_path, monkeypatch, capsys):
    archive = tmp_path / "cli-repo.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("cli-repo/app.py", "eval(user_input)\n")
    monkeypatch.setattr(
        "sys.argv",
        ["unweb-repository-analysis", str(archive), "--archive"],
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["repository"] == "cli-repo"
    assert result["findings"][0]["id"] == "python-dynamic-evaluation"



def test_inventories_legacy_npm_v1_lockfile_nested_dependencies(tmp_path):
    write_file(
        tmp_path,
        "package-lock.json",
        json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "left-pad": {
                    "version": "1.3.0",
                    "dependencies": {
                        "repeat-string": {"version": "1.6.1"}
                    },
                }
            },
        }),
    )
    inventory = analyse_repository(tmp_path).to_dict()["dependency_inventory"]
    assert any(item["name"] == "left-pad" and item["resolved_version"] == "1.3.0" for item in inventory)
    assert any(item["name"] == "repeat-string" and item["resolved_version"] == "1.6.1" for item in inventory)


def test_zip_scanner_rejects_absolute_and_windows_style_paths(tmp_path):
    archive = tmp_path / "path-cases.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("/absolute.py", "eval(absolute)\n")
        zipped.writestr("C:/drive.py", "eval(drive)\n")
        zipped.writestr(r"repo\..\windows.py", "eval(windows)\n")
        zipped.writestr("repo/safe.py", "eval(safe)\n")
    report = analyse_repository_archive(archive)
    assert len([item for item in report.findings if item.id == "python-dynamic-evaluation"]) == 1
    assert report.findings[0].path.endswith("safe.py")
    assert report.skipped_files >= 3


def test_npm_v1_lockfile_nested_dependencies_are_walked_without_recursion(tmp_path):
    nested = {}
    cursor = nested
    for index in range(600):
        name = f"nested-{index}"
        child = {"version": "1.0.0", "dependencies": {}}
        cursor[name] = child
        cursor = child["dependencies"]
    write_file(
        tmp_path,
        "package-lock.json",
        json.dumps({"lockfileVersion": 1, "dependencies": nested}),
    )
    report = analyse_repository(tmp_path)
    assert len(report.dependency_inventory) == 600
    assert report.dependency_inventory_truncated is False


def test_dependency_inventory_is_capped_and_reported_as_truncated(tmp_path):
    dependencies = {f"package-{index}": "^1.0.0" for index in range(5_100)}
    write_file(tmp_path, "package.json", json.dumps({"dependencies": dependencies}))
    report = analyse_repository(tmp_path)
    assert len(report.dependency_inventory) == 5_000
    assert report.dependency_inventory_truncated is True
    assert report.truncated is True
    assert report.to_dict()["dependency_inventory_truncated"] is True


def test_malformed_or_wrong_shape_dependency_files_do_not_abort_scan(tmp_path):
    write_file(tmp_path, "package.json", json.dumps(["not", "an", "object"]))
    write_file(tmp_path, "package-lock.json", json.dumps(["also", "not", "an", "object"]))
    write_file(tmp_path, "src/app.py", "eval(user_input)\\n")
    report = analyse_repository(tmp_path)
    assert report.files_scanned == 3
    assert any(item.id == "python-dynamic-evaluation" for item in report.findings)


def test_deeply_nested_malformed_lockfile_is_skipped_without_aborting_scan(tmp_path):
    nested = "[" * 1_200 + "0" + "]" * 1_200
    write_file(tmp_path, "package-lock.json", nested)
    write_file(tmp_path, "src/app.py", "eval(user_input)\\n")
    report = analyse_repository(tmp_path)
    assert any(item.id == "python-dynamic-evaluation" for item in report.findings)
