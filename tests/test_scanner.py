import subprocess
from pathlib import Path
import pytest
from keyhound.scanner import scan_lines, scan_file, Finding
from keyhound.git import is_git_repo, scan_git_history


# --- scan_lines ---

def test_scan_lines_finds_aws_key():
    findings = scan_lines(["export AWS_KEY=AKIAIOSFODNN7EXAMPLE"])
    assert any(f.kind == "AWS Access Key ID" for f in findings)


def test_scan_lines_finds_github_pat():
    findings = scan_lines([f"token = ghp_{'a' * 36}"])
    assert any("GitHub PAT" in f.kind for f in findings)


def test_scan_lines_redacts_value():
    findings = scan_lines(["export AWS_KEY=AKIAIOSFODNN7EXAMPLE"])
    aws = next(f for f in findings if f.kind == "AWS Access Key ID")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.value
    assert "****" in aws.value
    assert aws.value.startswith("AKIA")


def test_scan_lines_correct_line_number():
    findings = scan_lines(["nothing here", "AKIAIOSFODNN7EXAMPLE is here"])
    aws = next(f for f in findings if f.kind == "AWS Access Key ID")
    assert aws.line_number == 2


def test_scan_lines_clean_file():
    findings = scan_lines(["def hello():", "    return 'world'"], no_entropy=True)
    assert findings == []


def test_scan_lines_attaches_commit():
    findings = scan_lines(["ghp_" + "b" * 36], commit="abc123def456")
    assert findings[0].commit == "abc123def456"


def test_scan_lines_entropy_medium_severity():
    findings = scan_lines(["token = p8yKxH2mNqLvRs7TwBjAeF3dCzYo1Ug"])
    entropy_finds = [f for f in findings if f.kind == "High Entropy String"]
    assert all(f.severity == "medium" for f in entropy_finds)


# --- scan_file ---

def test_scan_file_skips_binary_extension(tmp_path):
    f = tmp_path / "image.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert scan_file(f) == []


def test_scan_file_finds_secret(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_file(f, no_entropy=True)
    assert any(f.kind == "AWS Access Key ID" for f in findings)


def test_scan_file_returns_empty_for_clean_file(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("x = 1\ny = 2\n")
    findings = scan_file(f, no_entropy=True)
    assert findings == []


# --- git integration ---

def test_not_a_git_repo(tmp_path):
    assert not is_git_repo(tmp_path)


def test_scan_git_history_non_repo(tmp_path):
    assert scan_git_history(tmp_path) == []


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, capture_output=True)


def test_scan_git_history_finds_secret(tmp_path):
    _init_git_repo(tmp_path)
    secret_file = tmp_path / "config.py"
    secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add config"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    findings = scan_git_history(tmp_path, no_entropy=True)
    assert any(f.kind == "AWS Access Key ID" for f in findings)


def test_scan_git_history_attaches_commit_hash(tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "secrets.env").write_text("ghp_" + "z" * 36 + "\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "oops"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    findings = scan_git_history(tmp_path, no_entropy=True)
    pat_finds = [f for f in findings if "GitHub" in f.kind]
    assert pat_finds
    assert all(len(f.commit) == 40 for f in pat_finds)  # full SHA
