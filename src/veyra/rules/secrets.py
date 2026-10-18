"""Secret / credential detection rules.

Detects obvious hardcoded secrets and credentials. Matched secrets are
redacted in the evidence field so full secrets never appear in reports.
"""

from __future__ import annotations

import re

from veyra.models import Finding, Severity
from veyra.rules import register

# --- Redaction helpers -----------------------------------------------------

# Keep the first N chars of a secret, redact the rest.
def _redact(secret: str, keep: int = 8) -> str:
    if len(secret) <= keep:
        return "*" * len(secret)
    return secret[:keep] + "*" * (len(secret) - keep)


# Common placeholder values that should not be treated as real secrets.
PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "your_password",
    "your_password_here",
    "your_api_key",
    "your_api_key_here",
    "your_token",
    "your_token_here",
    "example",
    "example_token",
    "example_key",
    "password",
    "secret",
    "placeholder",
    "xxxx",
    "xxxxx",
    "xxxxxx",
    "xxxxxxx",
    "xxxxxxxx",
    "redacted",
    "none",
    "null",
    "true",
    "false",
}


# Runtime references rather than literals: `API_KEY = os.environ["API_KEY"]`,
# `TOKEN = process.env.TOKEN`, `PASSWORD = settings.DB_PASSWORD`. Reading a
# credential from the environment is the remediation this rule recommends, so
# treating the accessor as the secret value inverts the finding. Matching stops
# at the first `(` (the regex value class has no parens), so `os.getenv(...)`
# and `os.Getenv(...)` are seen as `os.getenv` / `os.Getenv`.
REFERENCE_ROOTS = {
    "os",
    "process",
    "settings",
    "config",
    "secrets",
    "secret",
    "env",
    "getenv",
    "system",
}


_MASK_CHARS = set("*…•.-_ ")


def _is_mask_placeholder(value: str) -> bool:
    """True when the captured value is a redaction mask, not a credential.

    Setup docs render keys as ``********`` or ``sk-...****``; a value built only
    from mask and decoration characters carries no secret material.
    """
    if not any(ch in value for ch in "*…"):
        return False
    return all(ch in _MASK_CHARS for ch in value)


def _followed_by_mask(content: str, end: int) -> bool:
    """True when the captured value is cut short by a mask (``sk-proj-****``).

    ``GENERIC_KEY`` stops at the first character outside the key charset, so a
    masked example yields only the prefix of a key-looking token. A real secret
    is never immediately followed by asterisks, so this is a mask, not a key.
    """
    return end < len(content) and content[end] in "*…"


def _is_runtime_reference(value: str) -> bool:
    """True when the captured value names a lookup, not a hardcoded secret."""
    root = value.split(".", 1)[0].lower()
    if root in REFERENCE_ROOTS:
        return True
    return value.lower() in REFERENCE_ROOTS


# --- Patterns --------------------------------------------------------------

# OpenAI-style keys: sk-... (sk-proj-, sk-svcacct-, sk-)
OPENAI_KEY = re.compile(r"\b(sk-(?:proj|svcacct)?-[A-Za-z0-9_\-]{20,})\b")

# Anthropic-style keys: sk-ant-...
ANTHROPIC_KEY = re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b")

# GitHub tokens: ghp_ / gho_ / github_pat_
GITHUB_TOKEN = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")

# AWS access key id
AWS_ACCESS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

# Generic API keys: <name>_KEY / <name>_TOKEN / api_key = "..."
GENERIC_KEY = re.compile(
    r"\b((?:[A-Za-z0-9_]{2,}_)?(?:API_?KEY|TOKEN|SECRET|PASSWORD))\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?"
)

# Private key blocks
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")

# Password in config
PASSWORD = re.compile(
    r"\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
    re.IGNORECASE,
)


@register
def detect_openai_key(content: str, file_path: str, line: int) -> "Finding | None":
    m = OPENAI_KEY.search(content)
    if not m:
        return None
    return Finding(
        rule_id="AS-001",
        severity=Severity.CRITICAL,
        title="Hardcoded secret",
        description="OpenAI-style API key detected in source.",
        file=file_path,
        line=line,
        evidence=f"API credential detected: {_redact(m.group(1))}",
        remediation="Remove the key and load it from an environment variable or a secrets manager.",
    )


@register
def detect_anthropic_key(content: str, file_path: str, line: int) -> "Finding | None":
    m = ANTHROPIC_KEY.search(content)
    if not m:
        return None
    return Finding(
        rule_id="AS-001",
        severity=Severity.CRITICAL,
        title="Hardcoded secret",
        description="Anthropic-style API key detected in source.",
        file=file_path,
        line=line,
        evidence=f"API credential detected: {_redact(m.group(1))}",
        remediation="Remove the key and load it from an environment variable or a secrets manager.",
    )


@register
def detect_github_token(content: str, file_path: str, line: int) -> "Finding | None":
    m = GITHUB_TOKEN.search(content)
    if not m:
        return None
    return Finding(
        rule_id="AS-001",
        severity=Severity.CRITICAL,
        title="Hardcoded secret",
        description="GitHub token detected in source.",
        file=file_path,
        line=line,
        evidence=f"API credential detected: {_redact(m.group(1))}",
        remediation="Remove the token and use a GitHub App or environment variable.",
    )


@register
def detect_aws_key(content: str, file_path: str, line: int) -> "Finding | None":
    m = AWS_ACCESS_KEY.search(content)
    if not m:
        return None
    return Finding(
        rule_id="AS-001",
        severity=Severity.CRITICAL,
        title="Hardcoded secret",
        description="AWS access key ID detected in source.",
        file=file_path,
        line=line,
        evidence=f"API credential detected: {_redact(m.group(1))}",
        remediation="Remove the key and use IAM roles or environment variables.",
    )


@register
def detect_generic_key(content: str, file_path: str, line: int) -> "Finding | None":
    m = GENERIC_KEY.search(content)
    if not m:
        return None
    name, value = m.group(1), m.group(2)
    if value.lower() in PLACEHOLDER_VALUES:
        return None
    if _is_mask_placeholder(value) or _followed_by_mask(content, m.end(2)):
        return None
    if _is_runtime_reference(value):
        return None
    return Finding(
        rule_id="AS-001",
        severity=Severity.HIGH,
        title="Hardcoded secret",
        description=f"Generic credential '{name}' detected in configuration.",
        file=file_path,
        line=line,
        evidence=f"Credential detected: {_redact(value)}",
        remediation="Remove the credential and load it from an environment variable or a secrets manager.",
    )


@register
def detect_private_key(content: str, file_path: str, line: int) -> "Finding | None":
    if PRIVATE_KEY.search(content):
        return Finding(
            rule_id="AS-001",
            severity=Severity.CRITICAL,
            title="Hardcoded secret",
            description="Private key material detected in source.",
            file=file_path,
            line=line,
            evidence="Private key block detected (content redacted)",
            remediation="Remove the private key and load it from a secure keystore.",
        )
    return None


@register
def detect_password(content: str, file_path: str, line: int) -> "Finding | None":
    m = PASSWORD.search(content)
    if not m:
        return None
    if m.group(2).lower() in PLACEHOLDER_VALUES:
        return None
    if _is_mask_placeholder(m.group(2)):
        return None
    return Finding(
        rule_id="AS-001",
        severity=Severity.HIGH,
        title="Hardcoded secret",
        description="Password embedded in configuration.",
        file=file_path,
        line=line,
        evidence=f"Password detected: {_redact(m.group(2))}",
        remediation="Remove the password and use a secrets manager or environment variable.",
    )
