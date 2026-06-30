import re
from typing import NamedTuple


class Pattern(NamedTuple):
    name: str
    regex: re.Pattern
    severity: str  # "high" | "medium" | "low"
    group: int = 0  # capture group for the secret value; 0 = full match


PATTERNS: tuple[Pattern, ...] = (
    Pattern("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    Pattern(
        "AWS Secret Access Key",
        re.compile(
            r"(?i)(?:aws.{0,30}secret|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        "high",
        group=1,
    ),
    Pattern("GitHub PAT (classic)", re.compile(r"ghp_[a-zA-Z0-9]{36}"), "high"),
    Pattern("GitHub OAuth Token", re.compile(r"gho_[a-zA-Z0-9]{36}"), "high"),
    Pattern("GitHub Actions Token", re.compile(r"ghs_[a-zA-Z0-9]{36}"), "high"),
    Pattern("GitHub Refresh Token", re.compile(r"ghr_[a-zA-Z0-9]{36}"), "high"),
    Pattern("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high"),
    Pattern("Stripe Secret Key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"), "high"),
    Pattern("Stripe Publishable Key", re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,}"), "medium"),
    Pattern(
        "SendGrid API Key",
        re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
        "high",
    ),
    Pattern("Slack Bot Token", re.compile(r"xoxb-[0-9]+-[0-9]+-[0-9a-zA-Z]+"), "high"),
    Pattern("Slack User Token", re.compile(r"xoxp-[0-9]+-[0-9]+-[0-9]+-[0-9a-f]+"), "high"),
    Pattern(
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+"),
        "high",
    ),
    Pattern("RSA Private Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "high"),
    Pattern("EC Private Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----"), "high"),
    Pattern("OpenSSH Private Key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "high"),
    Pattern("PGP Private Key Block", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "high"),
    Pattern("OpenAI API Key", re.compile(r"sk-(?:proj-)?[a-zA-Z0-9]{48,}"), "high"),
    Pattern(
        "Anthropic API Key",
        re.compile(r"sk-ant-(?:api\d{2}-)?[a-zA-Z0-9\-_]{90,}"),
        "high",
    ),
    Pattern("Twilio Account SID", re.compile(r"AC[a-f0-9]{32}"), "medium"),
    Pattern(
        "JWT Token",
        re.compile(r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]{10,}"),
        "medium",
    ),
    Pattern("npm Token", re.compile(r"npm_[a-zA-Z0-9]{36}"), "high"),
    Pattern("PyPI API Token", re.compile(r"pypi-[a-zA-Z0-9\-_]{40,}"), "high"),
    Pattern(
        "Generic Password",
        re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']?(?!.*\$\{)([^\s\"'<>]{8,})[\"']?"
        ),
        "medium",
        group=1,
    ),
    Pattern(
        "Generic API Key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)"
            r"\s*[=:]\s*[\"']?([a-zA-Z0-9\-_./+]{16,})[\"']?"
        ),
        "medium",
        group=1,
    ),
)
