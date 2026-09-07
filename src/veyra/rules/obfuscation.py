"""Obfuscation detection (AS-007).

Detects encoded content that, once decoded, participates in a confirmed
execution or fetch/execution context.

IMPORTANT: decoding alone is NEVER a security signal. A finding is only raised
when the decoded content is combined with a dangerous context:
  - EXECUTION: decoded content is a shell command piped/passed to bash/sh
  - FETCH/EXECUTION: decoded content is a remote URL that is fetched/executed

This is a FILE rule: it inspects the full file text, extracts base64/ROT13
strings, decodes them deterministically, and checks for dangerous context.

The rule never executes code and never makes network requests.
"""

from __future__ import annotations

import base64
import codecs
import re
from typing import List, Optional

from veyra.models import Finding, Severity
from veyra.rules import register_file_rule

# --- Encoding extraction ---------------------------------------------------

# Base64-looking tokens: long alphanumeric strings with optional +/ and = padding.
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# ROT13 is only decoded when explicitly indicated.
ROT13_INDICATOR = re.compile(r"\brot13\b", re.IGNORECASE)

# --- Dangerous decoded content ---------------------------------------------

# Decoded content that is a destructive/executable shell command.
DANGEROUS_COMMAND = re.compile(
    r"\b(?:rm\s+-rf|rm\s+-fr|shutdown|reboot|mkfs|dd\s+if=|chmod\s+777|curl\s+[^|]*\|\s*(?:ba)?sh|wget\s+[^|]*\|\s*(?:ba)?sh)\b",
    re.IGNORECASE,
)

# Decoded content that is a remote script URL.
REMOTE_SCRIPT_URL = re.compile(
    r"https?://[^\s'\"]+\.(?:sh|bash|exe|msi|bat|ps1|jar|bin)(?:[?/]|$)",
    re.IGNORECASE,
)

# --- Dangerous context ------------------------------------------------------

# Execution context: decoded content is piped/passed to a shell.
EXECUTION_CONTEXT = re.compile(
    r"\|\s*(?:ba)?sh\b|\|\s*bash\b|\b(?:run|execute|exec|eval)\b",
    re.IGNORECASE,
)

# Fetch/execute context: surrounding text indicates fetching and executing.
FETCH_CONTEXT = re.compile(
    r"\b(?:fetch|download|retrieve|get|run|execute)\b[^\n]*\b(?:content|url|script|payload)\b",
    re.IGNORECASE,
)


def _decode_base64(token: str) -> Optional[str]:
    """Decode a base64 token. Returns None if not valid base64."""
    try:
        # Add padding if needed.
        padded = token + "=" * (-len(token) % 4)
        raw = base64.b64decode(padded, validate=True)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_rot13(token: str) -> str:
    return codecs.decode(token, "rot13")


def _line_for(text: str, needle: str) -> Optional[int]:
    """Best-effort line number for a needle within the raw text."""
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return None


def _mk(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    file_path: str,
    evidence: str,
    remediation: str,
    text: str,
    needle: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        file=file_path,
        line=_line_for(text, needle),
        evidence=evidence,
        remediation=remediation,
    )


@register_file_rule
def scan_obfuscation(text: str, file_path: str) -> List[Finding]:
    """Analyze a file for encoded content that is executed or fetched.

    Decoding alone is never a finding. A finding is only raised when the
    decoded content is dangerous AND combined with an execution or fetch
    context.
    """
    findings: List[Finding] = []

    # --- Base64 ---
    for m in BASE64_TOKEN.finditer(text):
        token = m.group(0)
        decoded = _decode_base64(token)
        if decoded is None:
            continue  # not valid base64 — ignore

        # Execution context: decoded shell command + pipe-to-shell.
        if DANGEROUS_COMMAND.search(decoded) and EXECUTION_CONTEXT.search(text):
            findings.append(
                _mk(
                    "AS-007",
                    Severity.CRITICAL,
                    "Encoded content executed",
                    "Base64-encoded content decodes to a dangerous shell command that is piped to a shell.",
                    file_path,
                    f"Base64 payload decodes to a shell command (method: Base64)",
                    "Do not decode and execute encoded content; review the payload.",
                    text,
                    token,
                )
            )
            continue

        # Fetch/execute context: decoded remote script URL + fetch intent.
        if REMOTE_SCRIPT_URL.search(decoded) and FETCH_CONTEXT.search(text):
            findings.append(
                _mk(
                    "AS-007",
                    Severity.HIGH,
                    "Encoded content fetched and executed",
                    "Base64-encoded content decodes to a remote script URL that is fetched.",
                    file_path,
                    f"Base64 payload decodes to a remote script URL (method: Base64)",
                    "Do not fetch and execute encoded remote content.",
                    text,
                    token,
                )
            )

    # --- ROT13 (only when explicitly indicated) ---
    if ROT13_INDICATOR.search(text):
        for m in BASE64_TOKEN.finditer(text):
            token = m.group(0)
            decoded = _decode_rot13(token)
            if DANGEROUS_COMMAND.search(decoded) and EXECUTION_CONTEXT.search(text):
                findings.append(
                    _mk(
                        "AS-007",
                        Severity.CRITICAL,
                        "Encoded content executed",
                        "ROT13-encoded content decodes to a dangerous shell command that is executed.",
                        file_path,
                        f"ROT13 payload decodes to a shell command (method: ROT13)",
                        "Do not decode and execute encoded content; review the payload.",
                        text,
                        token,
                    )
                )

    return findings
