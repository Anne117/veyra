"""Tests for secret detection rules."""

from pathlib import Path

from veyra.rules.secrets import (
    detect_anthropic_key,
    detect_aws_key,
    detect_generic_key,
    detect_github_token,
    detect_openai_key,
    detect_password,
    detect_private_key,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _read(path: str) -> str:
    return (FIXTURES / path).read_text(encoding="utf-8")


def test_openai_key_detected():
    f = detect_openai_key('api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"
    assert f.rule_id == "AS-001"


def test_anthropic_key_detected():
    f = detect_anthropic_key('k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"


def test_github_token_detected():
    f = detect_github_token('t = "ghp_abcdefghijklmnopqrstuvwxyz123456"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"


def test_aws_key_detected():
    f = detect_aws_key('k = "AKIAIOSFODNN7EXAMPLE"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"


def test_generic_key_detected():
    f = detect_generic_key("API_KEY = 'supersecretvalue123'", "x.py", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_password_detected():
    f = detect_password('password = "hunter2secret"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_private_key_detected():
    f = detect_private_key("-----BEGIN RSA PRIVATE KEY-----", "x.pem", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"


def test_secret_redacted():
    """Evidence must never contain the full secret."""
    f = detect_openai_key('api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"', "x.py", 1)
    assert f is not None
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" not in f.evidence
    assert "sk-proj-" in f.evidence


def test_false_positive_placeholders_not_detected():
    """Placeholder/example values should not be flagged."""
    content = _read("false_positives/config.py")
    for line in content.splitlines():
        assert detect_openai_key(line, "x.py", 1) is None
        assert detect_anthropic_key(line, "x.py", 1) is None
        assert detect_github_token(line, "x.py", 1) is None
        assert detect_aws_key(line, "x.py", 1) is None
        assert detect_password(line, "x.py", 1) is None


def test_short_value_not_detected():
    assert detect_generic_key('key = "abc"', "x.py", 1) is None


def test_env_lookup_is_not_a_hardcoded_secret():
    # Reading a credential from the environment is the remediation this rule
    # recommends; the accessor must not be mistaken for the secret value.
    assert detect_generic_key('API_KEY = os.environ["OPENAI_API_KEY"]', "x.py", 1) is None
    assert detect_generic_key('OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")', "x.py", 1) is None
    assert detect_generic_key('GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")', "x.go", 1) is None


def test_dotted_config_lookup_is_not_a_hardcoded_secret():
    assert detect_generic_key("DB_PASSWORD = settings.DATABASE_PASSWORD", "x.py", 1) is None
    assert detect_generic_key("API_KEY: process.env.OPENAI_API_KEY", "x.js", 1) is None


def test_literal_value_after_reference_exemption_still_flagged():
    for line in (
        "API_KEY = 'supersecretvalue123'",
        "API_KEY = literalvalue98765",
        "TOKEN=abcdef1234567890abcd",
    ):
        f = detect_generic_key(line, "x.py", 1)
        assert f is not None, line
        assert f.severity.value == "HIGH"


def test_masked_key_examples_are_not_hardcoded_secrets():
    # Setup docs render credentials as masks; there is no secret inside `****`.
    for line in (
        'OPENAI_API_KEY: "sk-proj-********"',
        'OPENAI_API_KEY="sk-proj-********abcdef"',
        'API_KEY = "abcdefghijklmnop*"',
    ):
        assert detect_generic_key(line, "setup.md", 1) is None, line


def test_mask_exemption_does_not_hide_real_keys():
    # The mask exemption must not weaken provider-pattern detection.
    f = detect_openai_key('key = "sk-proj-abcdefghijklmnop1234"', "x.py", 1)
    assert f is not None and f.severity.value == "CRITICAL"
    f = detect_generic_key('API_KEY = "sk-proj-abcdefghijklmnop1234"', "x.py", 1)
    assert f is not None and f.severity.value == "HIGH"
    assert detect_generic_key("TOKEN=ghp_1234567890abcdefghij", "x.py", 1) is not None


def test_masked_password_is_not_a_hardcoded_secret():
    assert detect_password('password = "********"', "x.py", 1) is None
    assert detect_password('password = "hunter2secret"', "x.py", 1) is not None
