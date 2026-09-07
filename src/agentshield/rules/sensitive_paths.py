"""Sensitive credential file access detection (AS-006).

Detects an actual READ/ACCESS operation against sensitive credential paths
and files (.env, ~/.aws, ~/.ssh, credential/secret/private-key files).

The rule requires evidence of an access/read operation — it does NOT flag a
sensitive path merely because it is mentioned. Negated/benign statements
("never read ~/.aws/credentials", "do not expose .env") are not flagged.

This is a pure static-analysis rule: it never executes commands and never
accesses the filesystem or network.
"""

from __future__ import annotations

import re

from agentshield.models import Finding, Severity
from agentshield.rules import register

# --- Sensitive path patterns ----------------------------------------------

# Sensitive credential-bearing paths/files.
SENSITIVE_PATH = re.compile(
    r"(?:\.env\b|\.aws(?:/|\\|\\b)|\.ssh(?:/|\\|\\b)|credentials?|secret(?:s)?\s+file|private\s+key|id_rsa|id_ed25519|\.pem\b|\.key\b)",
    re.IGNORECASE,
)

# Access/read verbs that indicate an actual read operation.
ACCESS_VERB = re.compile(
    r"\b(?:read|cat|open|load|access|get|print|display|show|dump|view|fetch|extract|include|report)\b",
    re.IGNORECASE,
)

# Generic config-file access (NOT sensitive by itself).
CONFIG_ACCESS = re.compile(
    r"\b(?:read|open|load|access|get|inspect|update|modify|edit)\b[^\n]*\b(?:config(?:uration)?(?:\s+file)?|configuration)\b",
    re.IGNORECASE,
)

# Explicit credential extraction terms.
CREDENTIAL_EXTRACTION = re.compile(
    r"\b(?:password|passwd|token|secret|credential|api\s*key|access\s*key|private\s*key)\b",
    re.IGNORECASE,
)

# Negation patterns: "never read", "do not expose", "don't access", etc.
# Reuse the same negation semantics as the prompt-injection rule.
NEGATION = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|should\s+not|shall\s+not|avoid|refrain\s+from|without|protect|secure|store|commit)\b",
    re.IGNORECASE,
)


@register
def detect_sensitive_path_access(content: str, file_path: str, line: int) -> "Finding | None":
    """Detect a read/access operation against a sensitive credential path.

    Two signals:
    1. A read/access of a known sensitive path (.env, ~/.aws, ~/.ssh, etc.).
    2. A generic config-file access combined with explicit credential
       extraction (password/token/secret/credential/API key).
    """
    # If the access verb is negated (e.g. "never read ~/.aws/credentials",
    # "do not expose .env"), it is NOT an actual access operation.
    if NEGATION.search(content):
        return None

    # Signal 1: known sensitive path + access verb.
    if SENSITIVE_PATH.search(content) and ACCESS_VERB.search(content):
        return Finding(
            rule_id="AS-006",
            severity=Severity.HIGH,
            title="Sensitive credential file access",
            description="A read/access operation against a sensitive credential file or path was detected.",
            file=file_path,
            line=line,
            evidence="Access to sensitive credential path",
            remediation="Avoid reading credential files; use a secrets manager or scoped credentials.",
        )

    # Signal 2: generic config-file access combined with credential extraction.
    if CONFIG_ACCESS.search(content) and CREDENTIAL_EXTRACTION.search(content):
        return Finding(
            rule_id="AS-006",
            severity=Severity.HIGH,
            title="Sensitive credential file access",
            description="A configuration file is being accessed in order to obtain credentials.",
            file=file_path,
            line=line,
            evidence="Config file access combined with credential extraction",
            remediation="Avoid extracting credentials from config files; use a secrets manager or scoped credentials.",
        )

    return None
