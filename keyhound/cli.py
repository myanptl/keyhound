from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from keyhound import __version__
from keyhound.git import scan_git_history
from keyhound.patterns import PATTERNS
from keyhound.scanner import Finding, scan_directory, scan_file

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_SEVERITY_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
_GREEN = "\033[92m"
_CYAN = "\033[96m"

_EXAMPLES = """\
examples:
  keyhound                      scan the current directory
  keyhound ./src                scan a specific path
  keyhound --git                also scan the last 100 commits
  keyhound --severity high      only report high-severity findings
  keyhound --output json        machine-readable output for CI
  keyhound -q                   findings only, no banner or progress

exit codes:
  0  clean    1  findings    2  error
"""


class _Style:
    """ANSI styling that collapses to plain text when color is off."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap(_BOLD, text)

    def dim(self, text: str) -> str:
        return self._wrap(_DIM, text)

    def green(self, text: str) -> str:
        return self._wrap(_GREEN, text)

    def cyan(self, text: str) -> str:
        return self._wrap(_CYAN, text)

    def severity(self, sev: str, text: str) -> str:
        return self._wrap(_SEVERITY_COLORS.get(sev, ""), text)


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


def _print_banner(style: _Style, target: Path, args: argparse.Namespace) -> None:
    parts = [
        f"{len(PATTERNS)} patterns",
        "entropy off" if args.no_entropy else "entropy on",
        f"git history (last {args.max_commits})" if args.git else "git history off",
    ]
    print(style.bold(f"keyhound v{__version__}"))
    print(f"{style.dim('target:')} {target}  {style.dim('·  ' + '  ·  '.join(parts))}")
    print()


def _print_findings(findings: list[Finding], style: _Style) -> None:
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for file, file_findings in sorted(by_file.items()):
        print(style.bold(file))
        ordered = sorted(file_findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.line_number))
        for f in ordered:
            label = style.severity(f.severity, f"{f.severity.upper():<7}")
            line = style.dim(f"L{f.line_number:<6}")
            commit = style.dim(f"  (commit {f.commit[:8]})") if f.commit else ""
            print(f"  {label} {line} {f.kind:<28} {style.dim(f.value)}{commit}")
        print()


def _print_summary(
    findings: list[Finding], file_count: int, elapsed: float, style: _Style,
) -> None:
    print(style.dim("─" * 44))
    if not findings:
        files = f"{file_count} file{'s' if file_count != 1 else ''}"
        print(f"  {style.green('✓ clean')} — no secrets in {files} {style.dim(f'({elapsed:.2f}s)')}")
        return
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    n = len(findings)
    files = f"{file_count} file{'s' if file_count != 1 else ''}"
    label = f"{n} finding" + ("s" if n != 1 else "")
    print(f"  {style.bold(label)} in {files} {style.dim(f'({elapsed:.2f}s)')}")
    chips = "  ·  ".join(
        style.severity(sev, f"{sev} {counts[sev]}") for sev in ("high", "medium", "low") if counts[sev]
    )
    print(f"  {chips}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keyhound",
        description="Dependency-free secret scanner: 25 credential patterns, "
                    "entropy detection, and full git-history scanning.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Findings only — no banner, progress, or summary")
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

    # Respect the NO_COLOR convention (https://no-color.org) alongside --no-color.
    use_color = (
        not args.no_color
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
    )
    style = _Style(use_color)
    show_chrome = args.output == "text" and not args.quiet
    show_progress = show_chrome and sys.stderr.isatty()

    if show_chrome:
        _print_banner(style, target, args)

    started = time.monotonic()
    findings: list[Finding] = []
    file_count = 0

    if target.is_file():
        findings.extend(scan_file(target, no_entropy=args.no_entropy))
        file_count = 1
    else:
        for _, file_findings in scan_directory(target, no_entropy=args.no_entropy):
            findings.extend(file_findings)
            file_count += 1
            if show_progress and file_count % 20 == 0:
                sys.stderr.write(f"\r  scanning… {file_count} files")
                sys.stderr.flush()

    if args.git:
        if show_progress:
            sys.stderr.write(f"\r  scanning… git history ({args.max_commits} commits)")
            sys.stderr.flush()
        git_root = target if target.is_dir() else target.parent
        findings.extend(
            scan_git_history(git_root, max_commits=args.max_commits, no_entropy=args.no_entropy)
        )

    if show_progress:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    elapsed = time.monotonic() - started
    findings = _filter(findings, args.severity)

    if args.output == "json":
        _print_json(findings)
    else:
        if findings:
            _print_findings(findings, style)
        if show_chrome:
            _print_summary(findings, file_count, elapsed, style)
        elif not findings and not args.quiet:
            print(f"No secrets found in {file_count} file{'s' if file_count != 1 else ''}.")

    sys.exit(1 if findings else 0)
