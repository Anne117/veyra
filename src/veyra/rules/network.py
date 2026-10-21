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
#
# A configuration object is not a client. ``httpx.Timeout``, ``httpx.Limits``,
# ``httpx.URL``, ``httpx.Proxy``, ``httpx.Headers``, ``httpx.Cookies``,
# ``httpx.Auth`` (and its ``BasicAuth``/``DigestAuth``/``NetRCAuth`` values)
# and ``aiohttp.ClientTimeout`` are value objects built to be
# passed *into* a client; none of them opens a connection, and a line whose
# only HTTP symbol is one of these makes no request. Field probe 2026-10-21 on
# the slice (agent/tools/skills/hermes_cli): 16 of 334 AS-003 MEDIUM were such
# constructors alone on a line (``timeout = httpx.Timeout(...)``), and no file
# relied on one as its only claim -- the client construction or the request
# line in the same file still reports. A client construction on the same line
# (``httpx.Client(timeout=httpx.Timeout(...))``) is matched at the client
# symbol, so nothing is lost there.
_HTTP_CONFIG_CTOR = (
    r"(?:Timeout|Limits|URL|Proxy|Headers|Cookies|Auth|BasicAuth|DigestAuth"
    r"|NetRCAuth|ClientTimeout)"
)
# An import binds names. ``from httpx import Timeout`` binds a value object: a
# timeout holds a number pair, a ``Limits`` holds pool sizes, ``HTTPError`` is
# an exception class, ``ClientState`` an enum. None of them can send a byte, so
# a line whose only network symbol is one of these states no request
# capability. The list is deliberately closed: every name here is a value,
# exception, enum or record in the libraries' public (or semi-public) surface,
# and a client-bearing import (``from httpx import Client``) stays a claim even
# when it shares a line with one of them.
_HTTP_NON_CLIENT_SYMBOL = frozenset({
    # value objects -- the config constructors excluded from the call branch
    "Timeout", "Limits", "URL", "Proxy", "Headers", "Cookies", "Auth",
    "BasicAuth", "DigestAuth", "NetRCAuth", "ClientTimeout", "QueryParams",
    # exceptions and state: raised, caught or assigned, never sent
    "HTTPError", "HTTPStatusError", "RequestError", "TransportError",
    "TimeoutException", "ConnectError", "ConnectTimeout", "ReadTimeout",
    "WriteTimeout", "PoolTimeout", "CloseError", "ClientState",
    # records and responses: built or read, not a transport
    "Request", "Response", "Transport", "BaseTransport", "MockTransport",
})
# ``from requests import a, b as c`` -- the imported names, aliases stripped.
_FROM_LIB_IMPORT = re.compile(
    # a dotted submodule carries the same symbols: ``httpx._client.ClientState``
    r"\bfrom\s+(?:requests|httpx|aiohttp)(?:\.[A-Za-z_]\w*)*\s+import\s+\(?([^)\n#]*)"
)
_IMPORT_ALIAS = re.compile(r"\s+as\s+\w+")

_HTTP_CALL_HEAD = (
    r"\b(?:requests|httpx|aiohttp)"
    rf"(?:\.(?!{_HTTP_CONFIG_CTOR}\b)[A-Za-z_]\w*)*\s*\("
)
# Dependency declaration: the symbol is available to the file, nothing more.
_HTTP_DECLARATION = (
    r"|\b(?:import|from)\s+(?:requests|httpx|aiohttp|node-fetch)\b"
    r"|\bfrom\s+urllib\s+import\s+request\b"
    # ``import urllib.request`` binds the same module as ``from urllib import
    # request``; it was missing here, so the line matched only the call
    # alternative below and could never be recognised as a declaration.
    r"|\b(?:import|from)\s+urllib\.request\b"
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
    # urllib: ``urllib.parse`` / ``urllib.error`` make no requests. Neither
    # does ``urllib.request.Request``: it is the request *record* -- URL,
    # method, headers, body -- that ``urlopen`` sends, and building one opens
    # nothing. The request line is the ``urlopen``/``urlretrieve`` one (or the
    # opener built to send it), and the import line carries the file-level
    # claim only while no request line does (``collapse_http_claims``). Field
    # probe 2026-10-21 on the slice
    # (agent/tools/skills/hermes_cli): 52 of 318 AS-003 MEDIUM were such
    # records (49 constructions + 3 annotations) in 38 files, and no file had
    # one as its only claim -- each reports the ``urlopen`` line that sends
    # it. A line naming both keeps its finding at the ``urlopen`` match.
    # ``urlretrieve`` was absent here while ``urlopen`` was present, so a file
    # that imported the symbol (``from urllib.request import urlretrieve``) and
    # called it by the bare name had no request line at all: the only claim was
    # the import. Field probe 2026-10-21 on the slice
    # (agent/tools/skills/hermes_cli): ``hermes_cli/update_cmd_zip.py:278,283``.
    # The ``(`` keeps a name reference (``opener=urlretrieve``) out, exactly as
    # the record branch keeps ``urllib.request.Request`` out.
    #
    # The ``urllib.request`` module is a namespace, not an entry point, and the
    # module alternative is gone. It matched the bare ``urllib.request`` token,
    # so every reference to the module's *machinery* became an AS-003 MEDIUM
    # claim: a handler class in a base list (``class H(urllib.request.BaseHandler)``),
    # the opener registry (``getattr(urllib.request, "_opener", None)``), a
    # handler constructed for an opener (``urllib.request.HTTPSHandler(...)``)
    # and ``build_opener`` itself, which builds an opener object and sends
    # nothing. A handler is consulted during a send; it does not perform one.
    # Field probe 2026-10-21 on the slice (agent/tools/skills/hermes_cli): seven
    # such lines, all in ``hermes_cli/urllib_security.py`` -- the module that
    # wraps ``urlopen`` with a credential-safe redirect handler. Its real send
    # line is ``opener.open(request, timeout=timeout)``, which the scanner does
    # not see (recorded as residual: proving an opener object, a recall change).
    # None of the seven could make a request, and the file keeps its file-level
    # claim at ``import urllib.request``, the same trade the record branch and
    # the local-configuration helpers make.
    #
    # Nothing is lost for the entry points: ``urlopen`` (``urllib.request.urlopen``,
    # ``urlopen``, ``opener=urllib.request.urlopen``) is matched by its own bare
    # name below, and ``urlretrieve`` by its bare call form, with or without the
    # module prefix. The earlier exclusions (``Request``, ``proxy_bypass*``,
    # ``url2pathname``, ``pathname2url``) were the first four names of this same
    # class; the branch is removed rather than narrowed, because every name that
    # can send a byte is already spelled by another alternative.
    r"|\burlopen\b|\burlretrieve\s*\("
    r"|\burlopen\b|\burlretrieve\s*\("
)
HTTP_CLIENT = re.compile(_HTTP_CALL_HEAD + _HTTP_DECLARATION + _HTTP_CALL_TAIL)
# The same branches, partitioned: a line that only *declares* a client states
# availability, a line that *calls* one states use. ``collapse_http_claims``
# needs the distinction; the detector itself still matches either.
HTTP_CALL = re.compile(_HTTP_CALL_HEAD + _HTTP_CALL_TAIL)
HTTP_DECLARATION = re.compile(_HTTP_DECLARATION.lstrip("|"))

# An import statement binds a name; the symbols spelled inside it are declared,
# not called. ``import urllib.request`` matches the ``urllib.request`` call
# alternative and ``from urllib.request import urlopen`` matches ``urlopen``, so
# without this span every such declaration counted as the call that supersedes
# it -- and the import claim was never collapsed, in exactly the files whose
# request line was two lines below.
_IMPORT_STATEMENT = re.compile(r"(?m)^[ \t]*(?:import|from)\b[^;\n]*")


def _in_import_statement(text: str, offset: int) -> bool:
    """True when ``offset`` sits inside an import statement on its line."""
    return any(m.start() <= offset < m.end() for m in _IMPORT_STATEMENT.finditer(text))

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

# A client *construction* allocates a transport; it opens nothing. ``with
# httpx.Client(timeout=5) as client:`` builds a session object, and the line
# that sends is the ``client.get(...)``/``client.post(...)`` inside the block.
# The construction is therefore an availability statement -- the same kind of
# fact as an ``import`` -- not a request line. It is dropped for a file that
# also reports a request line, and kept (once, first by line number) for a file
# whose only claim it is: there the block's verb may be a ``post`` on a
# receiver this scanner does not prove, and the construction is the only
# pointer to it. Field probe 2026-10-21 on the slice
# (agent/tools/skills/hermes_cli): 46 of 195 AS-003 MEDIUM were constructions in
# 29 files; 18 of them sat in files that report a request line anyway, and 19
# files relied on the construction as their only claim (11 of those call a
# verb on the bound name -- mostly ``client.post``, which the object branch
# excludes by naming convention).
CLIENT_CONSTRUCTION = re.compile(
    rf"\b(?:{SESSION_CTOR}|httpx\.AsyncClient|aiohttp\.ClientSession)[ \t]*\("
)


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


def _imports_no_client(line: str, match) -> bool:
    """True when the matched declaration imports only non-client symbols.

    ``from httpx import Timeout`` makes the timeout class available; it makes no
    request possible, because a timeout value is not a transport, and the file
    that only names it never opened a socket through it. Field probe 2026-10-21
    on the slice (agent/tools/skills/hermes_cli): three such lines were the only
    AS-003 claim of their file -- ``agent/anthropic_adapter.py:307``
    (``Timeout``), ``agent/auxiliary_client.py:5399`` (``ClientState``),
    ``tools/mcp_oauth_provider.py:87`` (``HTTPError``). An import that binds any
    other name (``from httpx import Client``, ``from requests import Session``)
    stays a declaration, and a comma list keeps its claim if one name is a
    client.
    """
    stmt = _FROM_LIB_IMPORT.match(line, match.start())
    if stmt is None:
        return False
    names = {_IMPORT_ALIAS.sub("", n).strip() for n in stmt.group(1).split(",")}
    names.discard("")
    return bool(names) and names <= _HTTP_NON_CLIENT_SYMBOL


def _live_match(pattern, line: str, reject=None):
    """Return the first match of ``pattern`` that is not a quoted mention.

    The declaration branch had no mention guard, so a docstring quoting an
    import (``The module wraps ``import requests`` for callers``) and a rule
    catalogue entry (``"env_exfil_fetch", "critical", ..., "fetch() call ...")``)
    fired AS-003 MEDIUM on a line that cannot make a request. The object-call
    branch has skipped mentions since it was added; this makes the library
    branch agree. A line whose only matches are mentions makes no claim.

    ``reject`` lets a caller drop specific matches (a declaration that imports
    only value objects and exceptions); the search then continues, so a file
    that also imports a real client still reports that line.
    """
    for m in pattern.finditer(line):
        if _is_mention(line, m.start()):
            continue
        if reject is not None and reject(line, m):
            continue
        return m
    return None


def collapse_http_claims(findings):
    """Drop an import-line claim when the same file also calls the client.

    A client *import* states that the client is available; a ``requests.get``
    on a URL states that it is used. Both fire AS-003 MEDIUM, so a file that does both
    reported one fact twice -- once on a line that cannot make a request. The
    call names the request line, so it is the claim that survives; the import is
    dropped for a file that has a call claim. A file with no call claims one
    fact once: the first declaration by line number survives, later ones are
    the same availability statement repeated.

    Field probe 2026-10-20 on the agent tree: 218 files import AND call, which
    was 357 of 2001 AS-003 MEDIUM -- every one a per-file duplicate.

    Field probe 2026-10-21 on the slice (agent/tools/skills/hermes_cli): 27
    declaration claims in 22 import-only files, five of them repeats
    (`process_bootstrap.py` 3, `chat_completion_helpers.py` 3,
    `mcp_oauth_provider.py` 2), so one file reported one fact up to three times.

    A client *construction* is the same kind of fact as an import: ``with
    httpx.Client(...) as client:`` allocates a transport and opens nothing, so
    it is dropped for a file that reports a request line and kept as the single
    availability claim of a file that has none (see ``CLIENT_CONSTRUCTION``).

    A call-pattern match inside an import statement is the declaration itself:
    the branches are peers, so importing the urllib request module also matches
    the module's own call alternative, and importing its entry point by name
    matches the bare name. Without that guard the declaration superseded
    itself, and the urllib import claim survived in every file that made a
    request -- 46 of them on the 2026-10-21 slice, in 45 files (see
    ``docs/rule-precision-audit.md``).
    """
    def _is_http_medium(f):
        return f.rule_id == "AS-003" and f.severity is Severity.MEDIUM

    def _calls(f):
        # A quoted call is a mention, not use: it supersedes nothing, so the
        # import keeps its claim (same guard as the detector).
        text = f.matched_text or ""
        for m in HTTP_CALL.finditer(text):
            if _is_mention(text, m.start()):
                continue
            # A match inside an import statement is the declaration itself
            # (``import urllib.request``), not a call that supersedes it.
            if _in_import_statement(text, m.start()):
                continue
            return True
        # A proven session ``get`` (see ``SESSION_ASSIGN``) is a call as well:
        # it names the request line, so the file's import is the duplicate.
        return _live_match(SESSION_GET, text) is not None

    def _declares_only(f):
        text = f.matched_text or ""
        return bool(HTTP_DECLARATION.search(text)) and not _calls(f)

    def _construction(f):
        """A construction line, not a request line (mention-guarded)."""
        text = f.matched_text or ""
        if not _is_http_medium(f):
            return False
        return _live_match(CLIENT_CONSTRUCTION, text) is not None

    # A file that reports any non-construction claim reports its request line:
    # the construction above it is the same fact on a line that opens nothing.
    # A declaration states availability too: only a call claim names a request.
    requesting = {
        f.file
        for f in findings
        if _is_http_medium(f)
        and not _construction(f)
        and not _declares_only(f)
    }

    first_construction = {}
    for f in findings:
        if not _construction(f) or f.file in requesting:
            continue
        line = f.line or 0
        if f.file not in first_construction or line < first_construction[f.file]:
            first_construction[f.file] = line

    def _superseded_construction(f):
        return _construction(f) and f.file in requesting

    def _duplicate_construction(f):
        # One availability statement per file, as for declarations.
        if not (_construction(f) and f.file not in requesting):
            return False
        return (f.line or 0) != first_construction[f.file]

    calling = {f.file for f in findings if _is_http_medium(f) and _calls(f)}
    # One declaration per file. A file that imports a client in three places
    # and never calls it states its availability once; the other two lines are
    # the same fact, not two more facts (``agent/process_bootstrap.py`` imports
    # ``urllib.request`` once and ``httpx`` twice). The surviving line is the
    # first by number so the report points at the top-most import. Only
    # declaration-only files are touched: a call claim always wins.
    first_declaration = {}
    for f in findings:
        if not (_is_http_medium(f) and _declares_only(f)):
            continue
        if f.file in calling:
            continue
        line = f.line or 0
        if f.file not in first_declaration or line < first_declaration[f.file]:
            first_declaration[f.file] = line

    def _duplicate_declaration(f):
        if not (_is_http_medium(f) and f.file not in calling and _declares_only(f)):
            return False
        return (f.line or 0) != first_declaration[f.file]

    return [f for f in findings
            if not (_is_http_medium(f) and f.file in calling and _declares_only(f))
            and not _duplicate_declaration(f)
            and not _superseded_construction(f)
            and not _duplicate_construction(f)]


# --- Download-and-execute --------------------------------------------------

DOWNLOAD_EXECUTE = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|requests\.get|urllib\.request|fetch|axios)\b[^\n]*(?:\|\s*(?:ba)?sh|\.exec|os\.system|subprocess)"
)


@register
def detect_http_client(content: str, file_path: str, line: int) -> "Finding | None":
    matched = _live_match(HTTP_CLIENT, content, reject=_imports_no_client)
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
