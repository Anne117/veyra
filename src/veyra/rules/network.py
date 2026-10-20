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
from typing import List

from veyra.models import Finding, Severity
from veyra.rules import register, register_file_rule
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

# ``get`` is not HTTP-only, so ``X.get(...)`` is a request only when the file
# *proves* what ``X`` is: a name assigned from ``requests.Session()`` or
# ``httpx.Client()`` in the same file, either as ``X = <ctor>(...)`` (annotation
# allowed) or bound by ``with <ctor>(...) as X:`` -- including a construction
# whose arguments span lines. A name that no such statement binds stays quiet,
# which is what keeps ``_HTTP_CALL_ERRORS.get(code, ...)``,
# ``session.get("cwd")`` and ``draftsBySession.delete(key)`` unreported: none of
# them can be a session this file created. Being file-scoped, this cannot leak
# across files (a sibling's ``client = httpx.Client()`` proves nothing here).
SESSION_CTOR = r"(?:requests\.Session|httpx\.Client)"
SESSION_ASSIGN = re.compile(
    rf"(?m)^[ \t]*(?P<name>(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)"
    rf"[ \t]*(?::[^=\n]+)?=[ \t]*{SESSION_CTOR}[ \t]*\("
)
SESSION_WITH_AS = re.compile(
    rf"\bwith\b[^\n:]*?{SESSION_CTOR}[ \t]*\((?:[^()]|\([^()]*\))*\)"
    rf"[ \t]*as[ \t]+(?P<name>[A-Za-z_]\w*)",
    re.S,
)
# Any ``<receiver>.get(`` on a line. Only a *proven* receiver ever becomes a
# finding, so inside a finding this says "this line issued a request".
SESSION_GET = re.compile(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.get[ \t]*\(")


def session_client_names(text: str) -> List[str]:
    """Names this file bound to a ``requests.Session`` / ``httpx.Client``.

    Sorted and de-duplicated so iteration (and therefore finding order) is
    deterministic.
    """
    names = {m.group("name") for m in SESSION_ASSIGN.finditer(text)}
    names |= {m.group("name") for m in SESSION_WITH_AS.finditer(text)}
    return sorted(names)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


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


def _live_match(pattern, line: str):
    """Return the first match of ``pattern`` that is not a quoted mention.

    The declaration branch had no mention guard, so a docstring quoting an
    import (``The module wraps ``import requests`` for callers``) and a rule
    catalogue entry (``"env_exfil_fetch", "critical", ..., "fetch() call ...")``)
    fired AS-003 MEDIUM on a line that cannot make a request. The object-call
    branch has skipped mentions since it was added; this makes the library
    branch agree. A line whose only matches are mentions makes no claim.
    """
    for m in pattern.finditer(line):
        if not _is_mention(line, m.start()):
            return m
    return None


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
        # A quoted call is a mention, not use: it supersedes nothing, so the
        # import keeps its claim (same guard as the detector).
        text = f.matched_text or ""
        if _live_match(HTTP_CALL, text) is not None:
            return True
        # A proven session ``get`` (see ``SESSION_ASSIGN``) is a call as well:
        # it names the request line, so the file's import is the duplicate.
        return _live_match(SESSION_GET, text) is not None

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
    matched = _live_match(HTTP_CLIENT, content)
    if matched is None:
        matched = _live_match(HTTP_OBJECT_CALL, content)
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


@register_file_rule
def detect_session_get(text: str, file_path: str) -> List[Finding]:
    """``X.get(...)`` where ``X`` is a session this file created.

    The line rule cannot decide this: a bare ``session.get("cwd")`` is a
    dictionary read. The file can, because the assignment is in it. The
    finding is attached to the request line rather than to the construction,
    so a chain or a graph edge points at the statement that makes the request.
    """
    findings: List[Finding] = []
    for name in session_client_names(text):
        pattern = re.compile(rf"\b{re.escape(name)}\.get[ \t]*\(")
        for m in pattern.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            if _is_mention(line, m.start() - line_start):
                continue
            findings.append(
                Finding(
                    rule_id="AS-003",
                    severity=Severity.MEDIUM,
                    title="External network access",
                    description=(
                        "HTTP client usage detected; the skill may make network requests."
                    ),
                    file=file_path,
                    line=_line_at(text, m.start()),
                    evidence="HTTP client call",
                    remediation=(
                        "Ensure network access is intentional and the target is trusted."
                    ),
                    matched_text=line.strip(),
                )
            )
    return findings


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
