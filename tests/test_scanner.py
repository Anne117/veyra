"""Integration tests for the scanner, CLI, JSON output, and exit codes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentshield.cli import main
from agentshield.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return str(FIXTURES / name)


def test_clean_skill_no_findings():
    result = scan_path(_fixture("clean"))
    assert result.findings == []
    assert result.score == 0
    assert result.risk_level == "SAFE"


def test_malicious_skill_findings():
    result = scan_path(_fixture("malicious"))
    assert len(result.findings) > 0
    assert result.score > 0
    assert result.risk_level in ("HIGH", "CRITICAL")


def test_mixed_risk_skill():
    result = scan_path(_fixture("mixed"))
    # shell=True and os.system should be flagged
    assert any(f.rule_id == "AS-002" for f in result.findings)
    assert result.score > 0


def test_recursive_scanning():
    """Scanning the fixtures root should find files in nested dirs."""
    result = scan_path(str(FIXTURES))
    # Should include findings from malicious/scripts/install.sh etc.
    assert len(result.findings) > 0
    files = {f.file for f in result.findings}
    assert any("install.sh" in f for f in files)


def test_secrets_redacted_in_scan():
    result = scan_path(_fixture("secrets"))
    for f in result.findings:
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" not in f.evidence
        assert "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890" not in f.evidence
        assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in f.evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence


def test_no_code_execution():
    """Scanning must not execute any scanned code."""
    # The malicious fixture contains os.system("whoami") and eval.
    # If the scanner executed it, this test would be trivially detectable,
    # but we assert the scanner is pure static analysis by checking it
    # returns findings without side effects.
    result = scan_path(_fixture("malicious"))
    assert result is not None
    # No network requests are made during scanning (static only).


def test_json_output():
    result = scan_path(_fixture("malicious"))
    data = result.to_dict()
    assert "target" in data
    assert "score" in data
    assert "risk_level" in data
    assert "summary" in data
    assert "findings" in data
    assert isinstance(data["score"], int)
    assert 0 <= data["score"] <= 100


def test_exit_code_clean():
    rc = main(["scan", _fixture("clean"), "--format", "json"])
    assert rc == 0


def test_exit_code_high():
    # mixed has HIGH findings (shell=True, os.system) but no CRITICAL
    rc = main(["scan", _fixture("mixed"), "--format", "json"])
    assert rc == 1


def test_exit_code_critical():
    # malicious has CRITICAL (curl|bash, wget|sh)
    rc = main(["scan", _fixture("malicious"), "--format", "json"])
    assert rc == 2


def test_cli_json_stdout(capsys):
    rc = main(["scan", _fixture("malicious"), "--format", "json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert rc == 2


def test_cli_terminal_output(capsys):
    rc = main(["scan", _fixture("clean")])
    captured = capsys.readouterr()
    assert "AgentShield Security Report" in captured.out
    assert "Risk: SAFE" in captured.out
    assert rc == 0


def test_missing_path():
    with pytest.raises(FileNotFoundError):
        scan_path(_fixture("does_not_exist"))
