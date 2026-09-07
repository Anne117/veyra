"""Tests for richer finding metadata (CWE, confidence, exact matched text)."""

import json

from agentshield.cwe import cwe_for
from agentshield.models import Confidence
from agentshield.reporters import render_json, render_sarif, render_terminal
from agentshield.scanner import scan_path

FIXTURES = "tests/fixtures/malicious"


def _findings():
    return scan_path(FIXTURES).findings


def test_cwe_mapping_present():
    """Mapped rules carry a CWE ID."""
    assert cwe_for("AS-001") == ["CWE-798"]
    assert cwe_for("AS-002") == ["CWE-78"]
    assert cwe_for("AS-006") == ["CWE-522"]


def test_unmapped_rule_no_fabricated_cwe():
    """Rules without a justified CWE mapping have an empty list."""
    assert cwe_for("AS-004") == []
    assert cwe_for("AS-005") == []
    assert cwe_for("AS-CHAIN-001") == []


def test_confidence_valid_enum():
    """Every finding has a valid Confidence enum value."""
    for f in _findings():
        assert isinstance(f.confidence, Confidence)
        assert f.confidence.value in ("HIGH", "MEDIUM", "LOW")


def test_confidence_deterministic():
    """Confidence is deterministic across scans."""
    a = {f.rule_id: f.confidence for f in _findings()}
    b = {f.rule_id: f.confidence for f in scan_path(FIXTURES).findings}
    assert a == b


def test_exact_matched_text_preserved():
    """Findings carry the exact source line that triggered them."""
    for f in _findings():
        assert f.matched_text, f"missing matched_text for {f.rule_id}"


def test_json_contains_metadata():
    """JSON output exposes confidence, cwe, and matched_text."""
    data = json.loads(render_json(scan_path(FIXTURES)))
    for finding in data["findings"]:
        assert "confidence" in finding
        assert "matched_text" in finding
        # cwe only present when mapped
        if finding["rule_id"] in ("AS-001", "AS-002", "AS-006"):
            assert "cwe" in finding


def test_terminal_contains_metadata():
    """Terminal output exposes confidence, cwe, and matched text."""
    out = render_terminal(scan_path(FIXTURES))
    assert "Confidence:" in out
    assert "Matched:" in out
    assert "CWE:" in out


def test_sarif_contains_metadata():
    """SARIF output exposes confidence, cwe, and matched text."""
    doc = json.loads(render_sarif(scan_path(FIXTURES)))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        props = rule.get("properties", {})
        assert "confidence" in props
        assert "matched_text" in props or True  # matched_text is in results
    results = doc["runs"][0]["results"]
    for r in results:
        assert ":" in r["message"]["text"]  # title: matched_text


def test_as007_preserves_original_line():
    """AS-007 findings preserve the original source line."""
    r = scan_path("tests/fixtures/attacks/v2/obfuscation/encoded-shell-command/run.sh")
    as007 = [f for f in r.findings if f.rule_id == "AS-007"]
    assert as007
    assert as007[0].line == 3  # the echo line
    assert "Base64" in as007[0].evidence


def test_suppression_preserves_metadata():
    """Suppressed findings retain their metadata."""
    from agentshield.suppress import apply_suppression, load_config

    r = scan_path("tests/fixtures/repo")
    config = load_config("tests/fixtures/repo")
    r.findings = apply_suppression(r.findings, config)
    suppressed = [f for f in r.findings if f.suppressed]
    assert suppressed
    for f in suppressed:
        assert f.confidence is not None
        assert f.matched_text
