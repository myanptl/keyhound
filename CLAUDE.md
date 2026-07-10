# KeyHound — Claude Code Config

Dependency-free Python CLI secret scanner (~25 detection patterns). Plan-B/security.

## Stack
- Python 3.9+, **zero runtime dependencies** (stdlib only) — this is a core constraint.
- Packaging: `pyproject.toml` (setuptools). CLI entry: `keyhound.cli:main`.
- Tests: **pytest** (dev extra: `pip install -e ".[dev]"`).

## Layout
- `keyhound/` — package (patterns, scanner, `cli.py`)
- `tests/` — pytest specs
- `pyproject.toml`, `setup.py`

## Commands
```bash
pip install -e ".[dev]"   # install with dev deps
keyhound <path>           # run the scanner
pytest                    # run tests
python -m keyhound.cli    # run without install
```

## Conventions
- **Never add a runtime dependency** — stdlib only. It's the project's selling point.
- Each detection pattern needs tests: a true positive AND a true negative (avoid false-positive noise).
- Guard against ReDoS — no catastrophic backtracking in secret regexes.
- Consider entropy checks to cut false positives on high-entropy-looking-but-safe strings.
- This tool scans for secrets — never print full secret values in output; mask them.

## Deploy / Release
GitHub source (push to `main`). PyPI-ready via `python -m build` + `twine upload` when publishing.

## Tooling available
- MCP `context7` (global) — Python stdlib / packaging docs.
- Project agent `pattern-reviewer` — audit detection regexes for false pos/neg.
- Global agent: `python-reviewer`.
