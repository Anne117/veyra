"""Network access detection rules.

Flags external downloads and network calls. Higher severity for
download-and-execute patterns and suspicious external domains.

``AS-005`` (raw-IP URLs and URL shorteners) is implemented in
``suspicious_urls.py``. This module re-exports those detectors under their
historical names so existing imports keep working; it must not register a
second copy, or every hit is emitted twice in scan results.
"""

from __future__ import annotations

import re

from veyra.models import Finding, Severity
from veyra.rules import register
from veyra.rules.suspicious_urls import (  # noqa: F401  (public re-export)
    detect_raw_ip as detect_raw_ip_url,
    detect_shortener,
)

__all__ = [
    "detect_http_client",
    "detect_download_execute",
    "detect_raw_ip_url",
    "detect_shortener",
]

# --- HTTP client usage -----------------------------------------------------

# A client name alone is not network access: "the next fetch is unconditional"
# and "requests that share a transport" are English prose, and ``urllib.parse``
# is a URL parser with no network capability. The signal is a client used as
# code (a call or a construction), a dependency declaration, or a real urllib
# network entry point.
#
# A *reference* to a client symbol makes no request either: ``httpx.Response``
# in a type annotation, ``except httpx.HTTPError``, ``cast(httpx.Client, x)``,
# and prose like "an ``httpx.Client`` whose lifetime is tied to ...". Those
# lines used to fire AS-003 MEDIUM once per annotation; the file-level claim is
# already carried by its ``import`` line, so the per-line repeat is noise
# (field probe 2026-10-20: 33 of 119 AS-003 MEDIUM in ``agent/`` were
# annotation/exception/prose references, no request possible on the line).
# Client used as code: a call or a construction, i.e. the symbol chain is
# followed by an argument list.
_HTTP_CALL_HEAD = r"\b(?:requests|httpx|aiohttp)(?:\.[A-Za-z_]\w*)*\s*\("
# Dependency declaration: the symbol is available to the file, nothing more.
_HTTP_DECLARATION = (
    r"|\b(?:import|from)\s+(?:requests|httpx|aiohttp|node-fetch)\b"
    r"|\bfrom\s+urllib\s+import\s+request\b"
    r"|\brequire\s*\(\s*['\"](?:axios|node-fetch|got)['\"]"
    r"|\bimport\s+got\s+from\b"
)
# Remaining call forms. No space before "(" here: "fetch (see below)" is prose,
# and a bare "got (" is ordinary English.
_HTTP_CALL_TAIL = (
    r"|\baxios\s*(?:\.[A-Za-z_]*\s*)?\("
    # ``fetch`` is the *global* in JS/undici only. A definition (``def`` or
    # ``function`` before the name), a method call (``source.fetch``), and
    # prose in backticks name no global request function; the global spelled
    # out on ``window`` still counts. Field probe 2026-10-20: 9 of the 86
    # AS-003 MEDIUM in ``agent/`` were bare-name collisions of this kind.
    r"|(?<![.\w`])(?<!def )(?<!function )fetch\("
    r"|\bwindow\.fetch\("
    r"|\bnode-fetch\("
    r"|\bgot\.[A-Za-z_]+\s*\("
    # urllib: ``urllib.parse`` / ``urllib.error`` make no requests.
    r"|\burllib\.request\b|\burlopen\b"
)
HTTP_CLIENT = re.compile(_HTTP_CALL_HEAD + _HTTP_DECLARATION + _HTTP_CALL_TAIL)
# The same branches, partitioned: a line that only *declares* a client states
# availability, a line that *calls* one states use. ``collapse_http_claims``
# needs the distinction; the detector itself still matches either.
HTTP_CALL = re.compile(_HTTP_CALL_HEAD + _HTTP_CALL_TAIL)
HTTP_DECLARATION = re.compile(_HTTP_DECLARATION.lstrip("|"))

# A request issued through a client *object* is invisible to the branches
# above, because they all name a library: ``async with session.post(url)`` and
# ``resp = await self._http_client.post(webhook, json=payload)`` name neither
# ``requests`` nor ``httpx``. The object form can only be recognised by naming
# convention, so it is restricted to receivers that declare a transport -- a
# name containing ``http`` (``http``, ``https``, ``_http_client``, ``_httpx``,
# ``http_session``) or a plain ``session`` / ``_session`` / ``self._session``.
# ``draftsBySession.delete(key)`` is a Map keyed by session id, not a request,
# so a bare ``session`` tail is not enough.
#
# Verbs are HTTP-only. ``get`` is deliberately absent: ``_HTTP_CALL_ERRORS.get(
# code, ...)`` and ``session.get("cwd")`` are dictionary reads -- 691
# ``<name>.get(`` lines in the field probe, and a verb alone does not separate
# a lookup from a request. The cost is that ``session.get(url)`` stays
# unreported (field probe 2026-10-20: 44 ``session.*`` call lines, of which 1
# is a JSON-RPC session over stdio -- ``session.post(method, params, cb)`` in
# ``ui-tui/scripts/profile-tui.mjs`` -- recorded as residual, not fixed here).
HTTP_OBJECT_CALL = re.compile(
    r"(?i)\b\w*https?\w*\.(?:post|put|patch|delete|head|options|request)\s*\("
    r"|\b(?:[A-Za-z_]\w*\.)?_?session\.(?:post|put|patch|delete|head|options|request)\s*\("
)


def _is_mention(line: str, start: int) -> bool:
    """True when ``line[start]`` sits inside a quoted or backticked mention.

    A docstring that describes the call (``await self._http_session.post(...)``)
    and a test that asserts on source text are talking *about* a request, not
    making one. Double-backtick RST spans are handled by treating anything
    between the first and last backtick of a line as a mention.
    """
    backticks = [m.start() for m in re.finditer(r"`", line)]
    if len(backticks) >= 2 and backticks[0] < start < backticks[-1]:
        return True
    for span in re.finditer(r'"[^"]*"', line):
        if span.start() <= start < span.end():
            return True
    return False


def collapse_http_claims(findings):
    """Drop an import-line claim when the same file also calls the client.

    A client *import* states that the client is available; a ``requests.get``
    on a URL states that it is used. Both fire AS-003 MEDIUM, so a file that does both
    reported one fact twice -- once on a line that cannot make a request. The
    call names the request line, so it is the claim that survives; the import is
    dropped only for a file that has a call claim, and an import-only file keeps
    its finding because nothing supersedes it.

    Field probe 2026-10-20 on the agent tree: 218 files import AND call, which
    was 357 of 2001 AS-003 MEDIUM -- every one a per-file duplicate. Files that
    only import (87) are untouched.
    """
    def _is_http_medium(f):
        return f.rule_id == "AS-003" and f.severity is Severity.MEDIUM

    def _calls(f):
        return bool(HTTP_CALL.search(f.matched_text or ""))

    def _declares_only(f):
        text = f.matched_text or ""
        return bool(HTTP_DECLARATION.search(text)) and not _calls(f)

    calling = {f.file for f in findings if _is_http_medium(f) and _calls(f)}
    if not calling:
        return findings
    return [f for f in findings
            if not (_is_http_medium(f) and f.file in calling and _declares_only(f))]


# --- Download-and-execute --------------------------------------------------

DOWNLOAD_EXECUTE = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|requests\.get|urllib\.request|fetch|axios)\b[^\n]*(?:\|\s*(?:ba)?sh|\.exec|os\.system|subprocess)"
)


@register
def detect_http_client(content: str, file_path: str, line: int) -> "Finding | None":
    matched = HTTP_CLIENT.search(content)
    if matched is None:
        candidate = HTTP_OBJECT_CALL.search(content)
        matched = (
            candidate
            if candidate is not None and not _is_mention(content, candidate.start())
            else None
        )
    if matched is not None:
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
