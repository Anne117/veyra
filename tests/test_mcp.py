"""Tests for MCP configuration security rules."""

import json
from pathlib import Path

from veyra.rules.mcp import scan_mcp_config

FIXTURES = Path(__file__).parent / "fixtures" / "mcp"


def _scan(fixture: str) -> list:
    path = FIXTURES / fixture
    if path.is_dir():
        # find the config file inside
        for f in path.rglob("*"):
            if f.suffix in {".json", ".yaml", ".yml"}:
                return scan_mcp_config(f.read_text(encoding="utf-8"), str(f))
        return []
    return scan_mcp_config(path.read_text(encoding="utf-8"), str(path))


def _ids(findings) -> set:
    return {f.rule_id for f in findings}


def test_clean_mcp_no_findings():
    findings = _scan("clean")
    assert findings == []


def test_safe_local_server():
    findings = _scan("safe_local")
    # local command execution is MEDIUM, not a false positive
    assert any(f.rule_id == "AS-MCP-003" for f in findings)
    assert not any(f.rule_id == "AS-MCP-001" for f in findings)  # not remote


def test_remote_https_server():
    findings = _scan("remote_https")
    assert any(f.rule_id == "AS-MCP-001" for f in findings)  # remote
    assert not any(f.rule_id == "AS-MCP-002" for f in findings)  # https, not http


def test_http_server():
    findings = _scan("http_server")
    assert any(f.rule_id == "AS-MCP-001" for f in findings)
    assert any(f.rule_id == "AS-MCP-002" for f in findings)  # http without https


def test_npx_server():
    findings = _scan("npx_server")
    assert any(f.rule_id == "AS-MCP-004" for f in findings)  # dynamic package exec


def test_secrets_server():
    findings = _scan("secrets")
    assert any(f.rule_id == "AS-MCP-005" for f in findings)  # env vars passed
    assert any(f.rule_id == "AS-MCP-006" for f in findings)  # secret-like env vars


def test_broad_fs():
    findings = _scan("broad_fs")
    assert any(f.rule_id == "AS-MCP-007" for f in findings)  # broad fs access
    assert any(f.rule_id == "AS-MCP-008" for f in findings)  # suspicious args


def test_mixed_risk():
    findings = _scan("mixed")
    ids = _ids(findings)
    assert "AS-MCP-001" in ids  # remote
    assert "AS-MCP-002" in ids  # http
    assert "AS-MCP-003" in ids  # local command
    assert "AS-MCP-004" in ids  # npx
    assert "AS-MCP-005" in ids  # env vars
    assert "AS-MCP-006" in ids  # secret env
    assert "AS-MCP-007" in ids  # broad fs
    assert "AS-MCP-008" in ids  # suspicious args


def test_remote_not_labeled_malicious():
    """A remote HTTPS server should be MEDIUM, not CRITICAL."""
    findings = _scan("remote_https")
    remote = [f for f in findings if f.rule_id == "AS-MCP-001"]
    assert remote
    assert remote[0].severity.value == "MEDIUM"


def test_secret_redacted_in_mcp():
    """MCP findings must not leak the full secret value."""
    findings = _scan("secrets")
    for f in findings:
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" not in f.evidence
        assert "hunter2secret" not in f.evidence


def test_non_mcp_json_not_scanned():
    """A generic JSON file that is not MCP config should produce no MCP findings."""
    text = json.dumps({"name": "app", "version": "1.0"})
    findings = scan_mcp_config(text, "package.json")
    assert findings == []


def test_yaml_mcp_config():
    """YAML MCP config should be parsed."""
    yaml_text = """
mcpServers:
  local:
    command: python
    args: ["-m", "server"]
"""
    findings = scan_mcp_config(yaml_text, "mcp_servers.yaml")
    assert any(f.rule_id == "AS-MCP-003" for f in findings)


def test_missing_trust_info():
    """A server with no command/url/type should get AS-MCP-010."""
    text = json.dumps({"mcpServers": {"mystery": {}}})
    findings = scan_mcp_config(text, ".mcp.json")
    assert any(f.rule_id == "AS-MCP-010" for f in findings)


def test_finding_fields_present():
    """Every MCP finding must have all required fields."""
    findings = _scan("mixed")
    assert findings
    for f in findings:
        assert f.rule_id
        assert f.severity.value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert f.title
        assert f.description
        assert f.file
        assert f.evidence
        assert f.remediation
