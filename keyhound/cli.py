from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from keyhound import __version__
from keyhound.git import scan_git_history
from keyhound.scanner import Finding, scan_directory, scan_file

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
_RESET = "\033[0m"


def _color(text: str, severity: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(severity, '')}{text}{_RESET}"


def _format_text(f: Finding, use_color: bool) -> str:
    label = _color(f"[{f.severity.upper()}]", f.severity, use_color)
    location = f"{f.file}:{f.line_number}"
    if f.commit:
        location += f" (commit {f.commit[:8]})"
    return f"{label} {location} — {f.kind}\n  Match: {f.value}"


def _print_text(findings: list[Finding], use_color: bool) -> None:
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
        print(_format_text(f, use_color))
        print()


def _print_json(findings: list[Finding]) -> None:
    print(json.dumps(
        [
            {
                "file": f.file,
                "line": f.line_number,
                "kind": f.kind,
                "severity": f.severity,
                "value": f.value,
                "commit": f.commit,
            }
            for f in findings
        ],
        indent=2,
    ))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keyhound",
        description="Dependency-free Python CLI secret scanner.",
    )
    p.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    p.add_argument("--git", action="store_true", help="Also scan git history")
    p.add_argument("--max-commits", type=int, default=100, metavar="N",
                   help="Max commits to scan in git history (default: 100)")
    p.add_argument("--no-entropy", action="store_true", help="Skip high-entropy string detection")
    p.add_argument("--severity", choices=["high", "medium", "low"], default="low",
                   help="Minimum severity to report (default: low)")
    p.add_argument("--output", choices=["text", "json"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--version", action="version", version=f"keyhound {__version__}")
    return p


def _filter(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]


def main() -> None:
    args = _build_parser().parse_args()
    target = Path(args.path).resolve()

    if not target.exists():
        print(f"keyhound: path not found: {target}", file=sys.stderr)
        sys.exit(2)

    findings: list[Finding] = []
    file_count = 0

    if target.is_file():
        findings.extend(scan_file(target, no_entropy=args.no_entropy))
        file_count = 1
    else:
        for _, file_findings in scan_directory(target, no_entropy=args.no_entropy):
            findings.extend(file_findings)
            file_count += 1

    if args.git:
        git_root = target if target.is_dir() else target.parent
        findings.extend(
            scan_git_history(git_root, max_commits=args.max_commits, no_entropy=args.no_entropy)
        )

    findings = _filter(findings, args.severity)
    use_color = not args.no_color and sys.stdout.isatty()

    if args.output == "json":
        _print_json(findings)
    else:
        if findings:
            _print_text(findings, use_color)
            n = len(findings)
            print(f"Found {n} secret{'s' if n != 1 else ''} in {file_count} file{'s' if file_count != 1 else ''}.")
        else:
            print(f"No secrets found in {file_count} file{'s' if file_count != 1 else ''}.")

    sys.exit(1 if findings else 0)
