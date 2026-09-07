"""Tests for MITRE ATT&CK metadata."""

import json
from pathlib import Path

from agentshield.mitre import mitre_for
from agentshield.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def _ids(result):
    return [f.mitre for f in result.findings]


def test_as001_contains_t1552():
    result = scan_path(str(FIXTURES / "secrets"))
    for f in result.findings:
        if f.rule_id == "AS-001":
            assert any(m["id"] == "T1552.001" for m in f.mitre)


def test_as002_contains_t1059():
    result = scan_path(str(FIXTURES / "mixed"))
    for f in result.findings:
        if f.rule_id == "AS-002":
            assert any(m["id"] == "T1059" for m in f.mitre)


def test_as002_unix_shell_contains_t1059_004():
    """curl|bash / eval findings should also map to T1059.004."""
    result = scan_path(str(FIXTURES / "malicious"))
    for f in result.findings:
        if f.rule_id == "AS-002" and "curl | bash" in f.evidence:
            assert any(m["id"] == "T1059.004" for m in f.mitre)


def test_as_chain_002_contains_t1105():
    result = scan_path(str(FIXTURES / "malicious"))
    for f in result.findings:
        if f.rule_id == "AS-CHAIN-002":
            assert any(m["id"] == "T1105" for m in f.mitre)


def test_as_mcp_006_contains_t1552():
    result = scan_path(str(FIXTURES / "mcp" / "secrets"))
    for f in result.findings:
        if f.rule_id == "AS-MCP-006":
            assert any(m["id"] == "T1552.001" for m in f.mitre)


def test_no_public_mitre_for_unmapped_rules():
    """Findings without an approved mapping must have no public MITRE metadata."""
    result = scan_path(str(FIXTURES / "mcp" / "http_server"))
    for f in result.findings:
        if f.rule_id in ("AS-MCP-001", "AS-MCP-002"):
            assert f.mitre == []


def test_medium_confidence_not_exposed():
    """Medium-confidence mappings (T1041, T1071.001, T1027, T1083) must not appear."""
    result = scan_path(str(FIXTURES / "malicious"))
    exposed = set()
    for f in result.findings:
        for m in f.mitre:
            exposed.add(m["id"])
    assert "T1041" not in exposed
    assert "T1071.001" not in exposed
    assert "T1027" not in exposed
    assert "T1083" not in exposed


def test_json_serialization_preserves_mitre():
    import io
    from contextlib import redirect_stdout

    from agentshield.cli import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(FIXTURES / "secrets"), "--format", "json"])
    data = json.loads(buf.getvalue())
    for f in data["findings"]:
        if f["rule_id"] == "AS-001":
            assert "mitre" in f
            assert any(m["id"] == "T1552.001" for m in f["mitre"])


def test_json_no_empty_mitre():
    """Findings without a mapping should not emit an empty 'mitre' key."""
    import io
    from contextlib import redirect_stdout

    from agentshield.cli import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(FIXTURES / "mcp" / "http_server"), "--format", "json"])
    data = json.loads(buf.getvalue())
    for f in data["findings"]:
        if f["rule_id"] in ("AS-MCP-001", "AS-MCP-002"):
            assert "mitre" not in f


def test_sarif_remains_valid_and_contains_mitre():
    import io
    from contextlib import redirect_stdout

    from agentshield.cli import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(FIXTURES / "secrets"), "--format", "sarif"])
    doc = json.loads(buf.getvalue())
    assert doc["version"] == "2.1.0"
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    as001 = [r for r in rules if r["id"] == "AS-001"]
    assert as001
    assert "properties" in as001[0]
    assert any(m["id"] == "T1552.001" for m in as001[0]["properties"]["mitre"])


def test_suppression_preserves_mitre():
    """Suppressed findings must retain their MITRE metadata."""
    from agentshield.suppress import apply_suppression, load_config

    repo = FIXTURES / "repo"
    result = scan_path(str(repo))
    cfg = load_config(str(repo))
    result.findings = apply_suppression(result.findings, cfg)
    for f in result.findings:
        if f.suppressed and f.rule_id == "AS-MCP-006":
            assert any(m["id"] == "T1552.001" for m in f.mitre)


def test_terminal_shows_mitre():
    import io
    from contextlib import redirect_stdout

    from agentshield.cli import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(FIXTURES / "secrets")])
    out = buf.getvalue()
    assert "MITRE ATT&CK: T1552.001 — Credentials In Files" in out
