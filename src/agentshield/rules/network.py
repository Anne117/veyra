"""Network access detection rules.

Flags external downloads and network calls. Higher severity for
download-and-execute patterns and suspicious external domains.
"""

from __future__ import annotations

import re

from agentshield.models import Finding, Severity
from agentshield.rules import register

# --- HTTP client usage -----------------------------------------------------

HTTP_CLIENT = re.compile(
    r"\b(?:requests|urllib|httpx|aiohttp|fetch|axios|got|node-fetch)\b"
)

# --- Download-and-execute --------------------------------------------------

DOWNLOAD_EXECUTE = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|requests\.get|urllib\.request|fetch|axios)\b[^\n]*(?:\|\s*(?:ba)?sh|\.exec|os\.system|subprocess)"
)

# --- Raw IP in URL ---------------------------------------------------------

RAW_IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?[/\s'\"]")

# --- URL shorteners --------------------------------------------------------

SHORTENERS = re.compile(
    r"https?://(?:bit\.ly|t\.co|tinyurl\.com|is\.gd|buff\.ly|goo\.gl|ow\.ly|rb\.gy|shorturl\.at|s\.link)\b",
    re.IGNORECASE,
)


@register
def detect_http_client(content: str, file_path: str, line: int) -> "Finding | None":
    if HTTP_CLIENT.search(content):
        return Finding(
            rule_id="AS-003",
            severity=Severity.MEDIUM,
            title="External network access",
            description="HTTP client usage detected; the skill may make network requests.",
            file=file_path,
            line=line,
            evidence="HTTP client call",
            remediation="Ensure network access is intentional and the target is trusted.",
        )
    return None


@register
def detect_download_execute(content: str, file_path: str, line: int) -> "Finding | None":
    if DOWNLOAD_EXECUTE.search(content):
        return Finding(
            rule_id="AS-003",
            severity=Severity.HIGH,
            title="Download and execute",
            description="Remote content is downloaded and executed.",
            file=file_path,
            line=line,
            evidence="Download-and-execute pattern",
            remediation="Do not download and execute remote content.",
        )
    return None


@register
def detect_raw_ip_url(content: str, file_path: str, line: int) -> "Finding | None":
    if RAW_IP_URL.search(content):
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
