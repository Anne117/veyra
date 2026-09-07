"""Tests for the suppression / allowlist system."""

import json
from pathlib import Path

from agentshield.cli import main
from agentshield.models import Finding, Severity
from agentshield.scanner import scan_path
from agentshield.suppress import (
    SuppressionConfig,
    apply_suppression,
    load_config,
)

FIXTURES = Path(__file__).parent / "fixtures"
REPO = FIXTURES / "repo"


def _finding(rule_id="AS-001", severity=Severity.HIGH, description="", evidence=""):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="t",
        description=description,
        file="x",
        evidence=evidence,
        remediation="r",
    )


def test_suppress_by_rule_id():
    f = _finding(rule_id="AS-MCP-010")
    out = apply_suppression([f], SuppressionConfig(rules=["AS-MCP-010"]))
    assert out[0].suppressed is True
    assert "AS-MCP-010" in out[0].suppression_reason


def test_suppress_by_server_name():
    f = _finding(rule_id="AS-MCP-003", description="MCP server 'filesystem' launches a local command.")
    out = apply_suppression([f], SuppressionConfig(servers=["filesystem"]))
    assert out[0].suppressed is True
    assert "filesystem" in out[0].suppression_reason


def test_suppress_by_domain():
    f = _finding(rule_id="AS-MCP-001", evidence="Remote endpoint: https://trusted.example.com/mcp")
    out = apply_suppression([f], SuppressionConfig(domains=["trusted.example.com"]))
    assert out[0].suppressed is True
    assert "domain" in out[0].suppression_reason


def test_suppress_by_domain_subdomain():
    f = _finding(rule_id="AS-MCP-001", evidence="Remote endpoint: https://sub.trusted.example.com/mcp")
    out = apply_suppression([f], SuppressionConfig(domains=["trusted.example.com"]))
    assert out[0].suppressed is True


def test_no_suppression_when_empty_config():
    f = _finding()
    out = apply_suppression([f], SuppressionConfig())
    assert out[0].suppressed is False


def test_suppression_does_not_affect_unrelated():
    """A finding not matching any ignore rule must remain active."""
    f1 = _finding(rule_id="AS-001", severity=Severity.CRITICAL, evidence="sk-proj-xxxx")
    f2 = _finding(rule_id="AS-MCP-003", description="MCP server 'other' launches a command.")
    out = apply_suppression([f1, f2], SuppressionConfig(servers=["filesystem"], rules=["AS-MCP-010"]))
    assert out[0].suppressed is False
    assert out[1].suppressed is False


def test_suppression_does_not_suppress_different_server():
    f = _finding(rule_id="AS-MCP-003", description="MCP server 'other' launches a command.")
    out = apply_suppression([f], SuppressionConfig(servers=["filesystem"]))
    assert out[0].suppressed is False


def test_suppression_does_not_suppress_different_domain():
    f = _finding(rule_id="AS-MCP-001", evidence="Remote endpoint: https://evil.example.com/mcp")
    out = apply_suppression([f], SuppressionConfig(domains=["trusted.example.com"]))
    assert out[0].suppressed is False


def test_suppressed_findings_excluded_from_score():
    f = _finding(rule_id="AS-MCP-003", severity=Severity.MEDIUM, description="MCP server 'filesystem' ...")
    out = apply_suppression([f], SuppressionConfig(servers=["filesystem"]))
    from agentshield.models import ScanResult

    result = ScanResult(target="x", findings=out)
    assert result.score == 0
    assert result.summary()["suppressed"] == 1


def test_load_config_from_repo():
    cfg = load_config(str(REPO))
    assert "dangerous" in cfg.servers
    assert "trusted.example.com" in cfg.domains
    assert "AS-MCP-010" in cfg.rules


def test_load_config_missing_returns_empty():
    cfg = load_config(str(FIXTURES / "clean"))
    assert cfg.is_empty()


def test_repo_scan_with_suppression():
    """Scanning the repo with its .agentshield.toml should suppress the
    dangerous MCP server but keep the malicious SKILL.md findings."""
    result = scan_path(str(REPO))
    cfg = load_config(str(REPO))
    result.findings = apply_suppression(result.findings, cfg)

    # The dangerous MCP server findings are suppressed.
    suppressed = [f for f in result.findings if f.suppressed]
    assert any("dangerous" in f.suppression_reason for f in suppressed)

    # The malicious SKILL.md findings remain active.
    active = [f for f in result.findings if not f.suppressed]
    assert any("SKILL.md" in f.file for f in active)
    assert any(f.severity == Severity.CRITICAL for f in active)


def test_repo_cli_exit_code_still_fails():
    """Even with suppression, the malicious SKILL.md keeps the repo failing."""
    rc = main(["scan", str(REPO), "--format", "json"])
    assert rc == 2


def test_repo_json_contains_suppression():
    import io
    import sys
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["scan", str(REPO), "--format", "json"])
    data = json.loads(buf.getvalue())
    assert data["summary"]["suppressed"] > 0
    assert any(f["suppressed"] for f in data["findings"])
    assert rc == 2


def test_terminal_shows_suppressed():
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(REPO)])
    out = buf.getvalue()
    assert "[SUPPRESSED]" in out
    assert "Suppressed:" in out
