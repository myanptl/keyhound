from __future__ import annotations

import subprocess
from pathlib import Path

from keyhound.scanner import scan_lines, Finding


def _run(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def is_git_repo(path: Path) -> bool:
    out = _run(["git", "rev-parse", "--is-inside-work-tree"], path)
    return out.strip() == "true"


def get_commits(path: Path, max_commits: int = 100) -> list[str]:
    out = _run(["git", "log", "--all", "--format=%H", f"-{max_commits}"], path)
    return [h for h in out.strip().splitlines() if h]


def scan_commit(path: Path, commit: str, no_entropy: bool = False) -> list[Finding]:
    diff = _run(["git", "show", "--no-color", "--unified=0", commit], path)
    findings: list[Finding] = []
    current_file = f"<git:{commit[:8]}>"
    lines_buffer: list[str] = []

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            if lines_buffer:
                findings.extend(
                    scan_lines(lines_buffer, filename=current_file, no_entropy=no_entropy, commit=commit)
                )
            current_file = line.split(" b/", 1)[-1] if " b/" in line else line
            lines_buffer = []
        elif line.startswith("+") and not line.startswith("+++"):
            lines_buffer.append(line[1:])

    if lines_buffer:
        findings.extend(
            scan_lines(lines_buffer, filename=current_file, no_entropy=no_entropy, commit=commit)
        )

    return findings


def scan_git_history(
    path: Path,
    max_commits: int = 100,
    no_entropy: bool = False,
) -> list[Finding]:
    if not is_git_repo(path):
        return []
    commits = get_commits(path, max_commits)
    findings: list[Finding] = []
    for commit in commits:
        findings.extend(scan_commit(path, commit, no_entropy=no_entropy))
    return findings
