import pytest
from keyhound.patterns import PATTERNS


def _match(name: str, text: str) -> bool:
    pat = next((p for p in PATTERNS if p.name == name), None)
    assert pat is not None, f"Pattern '{name}' not found"
    return bool(pat.regex.search(text))


def test_aws_access_key_matches():
    assert _match("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE")


def test_aws_access_key_no_match_short():
    assert not _match("AWS Access Key ID", "AKIA12345")


def test_github_pat_matches():
    assert _match("GitHub PAT (classic)", "ghp_" + "a" * 36)


def test_github_pat_no_match_wrong_prefix():
    assert not _match("GitHub PAT (classic)", "ghx_" + "a" * 36)


def test_github_oauth_matches():
    assert _match("GitHub OAuth Token", "gho_" + "a" * 36)


def test_github_actions_matches():
    assert _match("GitHub Actions Token", "ghs_" + "a" * 36)


def test_google_api_key_matches():
    assert _match("Google API Key", "AIza" + "x" * 35)


def test_google_api_key_no_match_short():
    assert not _match("Google API Key", "AIza" + "x" * 10)


def test_stripe_secret_live_matches():
    assert _match("Stripe Secret Key", "sk_live_" + "a" * 24)


def test_stripe_secret_test_matches():
    assert _match("Stripe Secret Key", "sk_test_" + "a" * 24)


def test_stripe_publishable_matches():
    assert _match("Stripe Publishable Key", "pk_live_" + "a" * 24)


def test_sendgrid_matches():
    assert _match("SendGrid API Key", "SG." + "a" * 22 + "." + "b" * 43)


def test_slack_bot_token_matches():
    assert _match("Slack Bot Token", "xoxb-123456789012-123456789012-abcdefghijklmnop")


def test_slack_webhook_matches():
    assert _match(
        "Slack Webhook URL",
        "https://hooks.slack.com/services/TABCDEF12/BABCDEF12/abc123XYZ",
    )


def test_rsa_private_key_matches():
    assert _match("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----")


def test_openssh_private_key_matches():
    assert _match("OpenSSH Private Key", "-----BEGIN OPENSSH PRIVATE KEY-----")


def test_pgp_private_key_matches():
    assert _match("PGP Private Key Block", "-----BEGIN PGP PRIVATE KEY BLOCK-----")


def test_jwt_matches():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert _match("JWT Token", jwt)


def test_npm_token_matches():
    assert _match("npm Token", "npm_" + "a" * 36)


def test_pypi_token_matches():
    assert _match("PyPI API Token", "pypi-" + "a" * 40)


def test_generic_api_key_equals():
    assert _match("Generic API Key", "api_key=supersecretvalue123456")


def test_generic_api_key_quoted():
    assert _match("Generic API Key", 'API_KEY = "my-secret-token-12345678"')


def test_generic_password_equals():
    assert _match("Generic Password", "password=mysecretpassword")


def test_generic_password_quoted():
    assert _match("Generic Password", 'PASSWORD = "hunter2abcdef"')


def test_pattern_count():
    assert len(PATTERNS) >= 15, "Should detect at least 15 credential types"
