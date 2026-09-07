"""Tests for SARIF 2.1.0 output."""

import json
from pathlib import Path

from veyra.cli import main
from veyra.models import Finding, ScanResult, Severity
from veyra.reporters.sarif import render_sarif
from veyra.scanner import scan_path
from veyra.suppress import apply_suppression, load_config

FIXTURES = Path(__file__).parent / "fixtures"
REPO = FIXTURES / "repo"


def _result(findings):
    return ScanResult(target="test", findings=findings)


def _parse_sarif(text: str) -> dict:
    return json.loads(text)


def test_sarif_version_and_schema():
    doc = _parse_sarif(render_sarif(_result([])))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"


def test_sarif_empty_findings():
    doc = _parse_sarif(render_sarif(_result([])))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["name"] == "Veyra"


def test_sarif_clean_scan():
    result = scan_path(str(FIXTURES / "clean"))
    doc = _parse_sarif(render_sarif(result))
    assert doc["runs"][0]["results"] == []


def test_sarif_high_finding():
    f = Finding(
        rule_id="AS-002",
        severity=Severity.HIGH,
        title="Command execution",
        description="os.system call",
        file="scripts/main.py",
        line=10,
        evidence="os.system",
        remediation="Use subprocess with a list.",
    )
    doc = _parse_sarif(render_sarif(_result([f])))
    run = doc["runs"][0]
    result = run["results"][0]
    assert result["ruleId"] == "AS-002"
    assert result["level"] == "error"
    assert result["message"]["text"] == "Command execution"
    # file + line mapping
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "scripts/main.py"
    assert loc["region"]["startLine"] == 10
    # rule metadata
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "AS-002"
    assert rule["name"] == "AS-002"
    assert rule["shortDescription"]["text"] == "Command execution"
    assert rule["fullDescription"]["text"] == "os.system call"
    assert rule["help"]["text"] == "Use subprocess with a list."


def test_sarif_critical_finding():
    f = Finding(
        rule_id="AS-001",
        severity=Severity.CRITICAL,
        title="Hardcoded secret",
        description="API key",
        file="config.py",
        line=1,
        evidence="sk-proj-xxxx",
        remediation="Remove the key.",
    )
    doc = _parse_sarif(render_sarif(_result([f])))
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_sarif_medium_maps_to_warning():
    f = Finding(rule_id="AS-MCP-001", severity=Severity.MEDIUM, title="Remote", description="d", file="x", evidence="e")
    doc = _parse_sarif(render_sarif(_result([f])))
    assert doc["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_mcp_finding():
    result = scan_path(str(FIXTURES / "mcp" / "http_server"))
    doc = _parse_sarif(render_sarif(result))
    results = doc["runs"][0]["results"]
    assert any(r["ruleId"] == "AS-MCP-001" for r in results)
    assert any(r["ruleId"] == "AS-MCP-002" for r in results)


def test_sarif_multiple_findings_dedup_rules():
    f1 = Finding(rule_id="AS-001", severity=Severity.HIGH, title="a", description="d", file="x", evidence="e")
    f2 = Finding(rule_id="AS-001", severity=Severity.HIGH, title="a", description="d", file="y", evidence="e")
    f3 = Finding(rule_id="AS-002", severity=Severity.MEDIUM, title="b", description="d", file="z", evidence="e")
    doc = _parse_sarif(render_sarif(_result([f1, f2, f3])))
    run = doc["runs"][0]
    assert len(run["results"]) == 3
    # rules deduplicated by rule_id
    assert len(run["tool"]["driver"]["rules"]) == 2
    # artifacts deduplicated by file
    assert len(run["artifacts"]) == 3


def test_sarif_suppressed_finding():
    f = Finding(
        rule_id="AS-MCP-003",
        severity=Severity.MEDIUM,
        title="Local command",
        description="MCP server 'filesystem' launches a command.",
        file=".mcp.json",
        evidence="Command: npx",
        remediation="Review.",
    )
    f.suppressed = True
    f.suppression_reason = "MCP server 'filesystem' ignored"
    doc = _parse_sarif(render_sarif(_result([f])))
    result = doc["runs"][0]["results"][0]
    # suppression preserved, not silently dropped
    assert "suppressions" in result
    assert result["suppressions"][0]["kind"] == "external"
    assert "filesystem" in result["suppressions"][0]["justification"]


def test_sarif_secret_redacted():
    result = scan_path(str(FIXTURES / "secrets"))
    doc = _parse_sarif(render_sarif(result))
    text = json.dumps(doc)
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" not in text
    assert "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890" not in text
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text


def test_sarif_repo_with_suppression():
    result = scan_path(str(REPO))
    cfg = load_config(str(REPO))
    result.findings = apply_suppression(result.findings, cfg)
    doc = _parse_sarif(render_sarif(result))
    results = doc["runs"][0]["results"]
    suppressed = [r for r in results if "suppressions" in r]
    active = [r for r in results if "suppressions" not in r]
    assert len(suppressed) > 0
    assert len(active) > 0
    # active findings include the malicious SKILL.md
    assert any("SKILL.md" in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in active)


def test_sarif_cli_output(capsys):
    rc = main(["scan", str(FIXTURES / "mcp" / "http_server"), "--format", "sarif"])
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"
    assert rc == 1  # HIGH finding (AS-MCP-002)


def test_sarif_exit_code_critical():
    rc = main(["scan", str(FIXTURES / "malicious"), "--format", "sarif"])
    assert rc == 2


def test_json_output_unchanged():
    """JSON output must remain unchanged (no SARIF fields leaked in)."""
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(FIXTURES / "malicious"), "--format", "json"])
    data = json.loads(buf.getvalue())
    assert "version" not in data
    assert "$schema" not in data
    assert "runs" not in data
    assert "findings" in data
    assert "score" in data
