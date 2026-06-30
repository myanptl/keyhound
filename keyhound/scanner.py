from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from keyhound.entropy import high_entropy_tokens
from keyhound.patterns import PATTERNS

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".mp4", ".mp3", ".wav", ".mov", ".avi",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".class", ".o", ".so", ".dylib", ".dll",
    ".lock",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".tox",
}


@dataclass
class Finding:
    file: str
    line_number: int
    kind: str
    value: str          # redacted
    severity: str
    commit: str | None = None


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * min(len(value) - 4, 20)


def scan_lines(
    lines: list[str],
    filename: str = "<input>",
    no_entropy: bool = False,
    commit: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for lineno, line in enumerate(lines, start=1):
        for pat in PATTERNS:
            m = pat.regex.search(line)
            if not m:
                continue
            secret = m.group(pat.group)
            findings.append(Finding(
                file=filename,
                line_number=lineno,
                kind=pat.name,
                value=_redact(secret),
                severity=pat.severity,
                commit=commit,
            ))

        if no_entropy:
            continue

        for token in high_entropy_tokens(line):
            first4 = token[:4]
            already = any(
                f.line_number == lineno and f.value[:4] == first4
                for f in findings
            )
            if not already:
                findings.append(Finding(
                    file=filename,
                    line_number=lineno,
                    kind="High Entropy String",
                    value=_redact(token),
                    severity="medium",
                    commit=commit,
                ))

    return findings


def scan_file(path: Path, no_entropy: bool = False) -> list[Finding]:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except (PermissionError, OSError):
        return []
    return scan_lines(lines, filename=str(path), no_entropy=no_entropy)


def scan_directory(
    root: Path,
    no_entropy: bool = False,
) -> Iterator[tuple[Path, list[Finding]]]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            findings = scan_file(path, no_entropy=no_entropy)
            yield path, findings
