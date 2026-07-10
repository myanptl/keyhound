# keyhound

[![tests](https://github.com/myanptl/keyhound/actions/workflows/tests.yml/badge.svg)](https://github.com/myanptl/keyhound/actions/workflows/tests.yml)
[![python >= 3.10](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#)

A dependency-free Python CLI that scans codebases — and full git history — for leaked API keys and secrets.

Built after I found a live leaked key in one of my own projects during a security audit. Pure Python standard library, zero dependencies, one file to run.

## Why

Most secret scanners need a runtime, a config file, or a cloud account. keyhound is a single `pip install` with **no dependencies** — drop it into any repo or CI pipeline and it just works.

## Features

- **25 credential patterns** — AWS, GitHub (PAT / OAuth / Actions / refresh), Google, Stripe, Slack, SendGrid, OpenAI, Anthropic, Twilio, JWT, npm, PyPI, and RSA / EC / OpenSSH / PGP private keys
- **High-entropy detection** — catches secrets that don't match a known pattern
- **Scans full git history** — finds keys that were committed and later deleted
- **Redacted output** — findings are masked so secrets aren't re-exposed in logs
- **CI-ready exit codes** — `0` clean, `1` findings, `2` error
- **Severity filtering** and **JSON output** for automation
- **Zero dependencies** — Python 3.9+ standard library only

## Install

```bash
pip install .
# or, isolated:
pipx install .
```

## Usage

```bash
# scan the current directory
keyhound

# scan a specific path
keyhound ./src

# also scan git history (last 100 commits by default)
keyhound --git

# only show high-severity findings, as JSON
keyhound --severity high --output json

# findings only — no banner, progress, or summary (good for pipes)
keyhound -q
```

### Example output

```text
keyhound v0.1.0
target: ./demo  ·  25 patterns  ·  entropy on  ·  git history off

demo/config.py
  HIGH    L1      AWS Secret Access Key        abcd********************
  HIGH    L2      Stripe Secret Key            sk_t********************
  MEDIUM  L3      Generic Password             hunt**********

demo/token.txt
  HIGH    L1      GitHub PAT (classic)         ghp_********************

────────────────────────────────────────────
  4 findings in 2 files (0.02s)
  high 3  ·  medium 1
```

Findings are grouped by file, sorted by severity, and always redacted. A live
progress counter shows on stderr for large scans. Color respects both
`--no-color` and the [`NO_COLOR`](https://no-color.org) convention.

### Options

| Flag | Description |
|------|-------------|
| `path` | File or directory to scan (default: `.`) |
| `--git` | Also scan git history |
| `--max-commits N` | How many commits to scan (default: 100) |
| `--no-entropy` | Skip high-entropy string detection |
| `--severity {high,medium,low}` | Minimum severity to report (default: `low`) |
| `--output {text,json}` | Output format (default: `text`) |
| `--no-color` | Disable colored output (also respects `NO_COLOR`) |
| `-q`, `--quiet` | Findings only — no banner, progress, or summary |
| `--version` | Print version |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No secrets found |
| `1` | Secrets found |
| `2` | Error |

Use in CI to fail a build when a secret is committed:

```bash
keyhound --severity medium || exit 1
```

Or as a GitHub Actions step:

```yaml
- name: Scan for leaked secrets
  run: |
    pip install .
    keyhound --severity medium --no-color
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
