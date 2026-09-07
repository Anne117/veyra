"""Suspicious URL detection rules.

Extracts URLs and flags suspicious patterns: raw IPs, shorteners,
executable/download URLs, and URLs followed by shell execution.
Does not classify a domain as malicious purely because it is unfamiliar.
"""

from __future__ import annotations

import re

from veyra.models import Finding, Severity
from veyra.rules import register

# --- URL extraction --------------------------------------------------------

URL_RE = re.compile(r"https?://[^\s'\"<>]+")

# --- Suspicious patterns ---------------------------------------------------

RAW_IP = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?[/\s'\"]")

SHORTENERS = re.compile(
    r"https?://(?:bit\.ly|t\.co|tinyurl\.com|is\.gd|buff\.ly|goo\.gl|ow\.ly|rb\.gy|shorturl\.at|s\.link)\b",
    re.IGNORECASE,
)

EXECUTABLE_DOWNLOAD = re.compile(
    r"https?://[^\s'\"<>]+\.(?:exe|msi|sh|bat|ps1|dmg|pkg|apk|jar|bin)(?:[?/]|$)",
    re.IGNORECASE,
)

URL_PIPE_SHELL = re.compile(
    r"https?://[^\s'\"<>]+\s*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)


@register
def detect_raw_ip(content: str, file_path: str, line: int) -> "Finding | None":
    if RAW_IP.search(content):
        return Finding(
            rule_id="AS-005",
            severity=Severity.MEDIUM,
            title="Suspicious URL",
            description="URL uses a raw IP address instead of a domain name.",
            file=file_path,
            line=line,
            evidence="Raw IP address in URL",
            remediation="Use a named domain and verify the endpoint is legitimate.",
        )
    return None


@register
def detect_shortener(content: str, file_path: str, line: int) -> "Finding | None":
    if SHORTENERS.search(content):
        return Finding(
            rule_id="AS-005",
            severity=Severity.LOW,
            title="Suspicious URL",
            description="URL shortener detected; the final destination is hidden.",
            file=file_path,
            line=line,
            evidence="URL shortener detected",
            remediation="Expand the shortener and verify the destination.",
        )
    return None


@register
def detect_executable_download(content: str, file_path: str, line: int) -> "Finding | None":
    if EXECUTABLE_DOWNLOAD.search(content):
        return Finding(
            rule_id="AS-005",
            severity=Severity.MEDIUM,
            title="Suspicious URL",
            description="URL points to an executable or script download.",
            file=file_path,
            line=line,
            evidence="Executable/download URL",
            remediation="Verify the download source and integrity before use.",
        )
    return None


@register
def detect_url_pipe_shell(content: str, file_path: str, line: int) -> "Finding | None":
    if URL_PIPE_SHELL.search(content):
        return Finding(
            rule_id="AS-005",
            severity=Severity.CRITICAL,
            title="Suspicious URL",
            description="URL is piped directly into a shell, executing remote content.",
            file=file_path,
            line=line,
            evidence="URL piped into shell",
            remediation="Do not pipe remote content into a shell.",
        )
    return None
