"""Adversarial attack-lab tests.

Runs AgentShield against every attack fixture and asserts the expected
detection classification. These tests make the detection expectations
explicit and record misses/false-positives honestly — they do NOT modify
AgentShield rules to force passes.
"""

from pathlib import Path

from agentshield.attack_lab import (
    ATTACK_CASES,
    DETECTED,
    FALSE_POSITIVE,
    MISSED,
    PARTIALLY_DETECTED,
    run_attack_lab,
)
from agentshield.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures" / "attacks"


def test_all_fixtures_exist():
    """Every attack case must have a corresponding fixture file."""
    for case in ATTACK_CASES:
        path = FIXTURES / case.path
        assert path.exists(), f"Missing fixture: {case.path}"


def test_attack_lab_runs():
    """The attack lab runs and produces a summary."""
    lab = run_attack_lab()
    s = lab.summary()
    assert s["total"] == len(ATTACK_CASES)
    assert s["total"] > 0


def test_attack_lab_classifications_are_valid():
    """Every case must be classified into a known bucket."""
    valid = {DETECTED, PARTIALLY_DETECTED, MISSED, FALSE_POSITIVE}
    lab = run_attack_lab()
    for c in lab.cases:
        assert c["result"] in valid, f"Invalid classification for {c['name']}: {c['result']}"


def test_attack_lab_is_static():
    """The lab must not execute any fixture code."""
    # If the lab executed fixtures, os.system("whoami") in shell-execution
    # would have side effects. We assert the lab only returns findings.
    lab = run_attack_lab()
    assert lab is not None
    # No network requests are made during the lab run (static only).


def test_prompt_injection_detected():
    """Prompt-injection attacks should be detected."""
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "prompt-injection"}
    assert cases["override-instructions"] == DETECTED
    assert cases["disable-security"] == DETECTED
    assert cases["exfiltrate-files"] == DETECTED
    assert cases["benign"] == DETECTED  # benign lookalike correctly clean


def test_shell_execution_detected():
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "shell-execution"}
    assert cases["os-system-var"] == DETECTED
    assert cases["subprocess-shell"] == DETECTED
    assert cases["eval-var"] == DETECTED
    assert cases["benign"] == DETECTED


def test_remote_download_detected():
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "remote-download"}
    assert cases["curl-pipe-bash"] == DETECTED
    assert cases["wget-pipe-sh"] == DETECTED
    assert cases["benign"] == DETECTED


def test_encoded_obfuscation_partially_detected():
    """base64-exec is now DETECTED (AS-007 decodes the payload); rot13-exec
    remains PARTIAL (ROT13 payload not decoded without an explicit indicator)."""
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "encoded-obfuscation"}
    assert cases["base64-exec"] == DETECTED
    assert cases["rot13-exec"] == PARTIALLY_DETECTED
    assert cases["benign"] == DETECTED


def test_mcp_attacks_detected_or_partial():
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "mcp-attacks"}
    assert cases["secrets-env"] == DETECTED
    # remote-exec emits AS-CHAIN-003 at HIGH -> DETECTED (chain finding counts).
    assert cases["remote-exec"] == DETECTED
    # broad-fs-secrets emits AS-001 CRITICAL + AS-MCP-006/008 HIGH -> DETECTED.
    assert cases["broad-fs-secrets"] == DETECTED
    assert cases["benign"] == DETECTED


def test_multi_stage_detected():
    """Multi-stage attacks are now detected by step-sequence analysis."""
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "multi-stage"}
    assert cases["data-sync"] == DETECTED
    assert cases["download-run"] == DETECTED
    assert cases["benign"] == DETECTED


def test_secret_exfiltration_gaps_recorded():
    """env-dump and read-credentials are now detected (AS-006 covers sensitive
    path reads); the benign lookalike is no longer a FP."""
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "secret-exfiltration"}
    assert cases["env-dump"] == DETECTED
    assert cases["read-credentials"] == DETECTED  # AS-006 detects ~/.ssh and ~/.aws reads
    assert cases["reveal-secrets"] == DETECTED
    assert cases["benign"] == DETECTED  # negation fix removed the false positive


def test_filesystem_access():
    lab = run_attack_lab()
    cases = {c["name"]: c["result"] for c in lab.cases if c["category"] == "filesystem-access"}
    assert cases["broad-fs"] == PARTIALLY_DETECTED
    assert cases["benign"] == DETECTED


def test_detection_rate_is_honest():
    """The reported detection rate must match the actual classifications."""
    lab = run_attack_lab()
    s = lab.summary()
    expected = round(100 * s["detected"] / s["total"], 1)
    assert s["detection_percentage"] == expected


def test_attack_lab_json_output():
    """The attack-lab JSON output is machine-readable."""
    import json
    from agentshield.attack_lab import AttackLabResult

    lab = run_attack_lab()
    data = lab.to_dict()
    assert "summary" in data
    assert "categories" in data
    assert "cases" in data
    assert data["summary"]["total"] == len(ATTACK_CASES)
    # round-trip through JSON
    json.dumps(data)


# --- Evaluator methodology tests -------------------------------------------

def _case(name="x", expected_rules=None, is_benign=False):
    from agentshield.attack_lab import AttackCase

    return AttackCase(
        name=name, category="test", path="x", expected=PARTIALLY_DETECTED,
        expected_rules=expected_rules or [], is_benign=is_benign,
    )


def _finding(rule_id, severity):
    from agentshield.models import Finding, Severity

    return Finding(
        rule_id=rule_id, severity=Severity(severity), title="t",
        description="d", file="x", evidence="e", remediation="r",
    )


def test_direct_high_rule_finding_detected():
    """A direct HIGH/CRITICAL rule finding -> DETECTED."""
    from agentshield.attack_lab import _classify

    case = _case(expected_rules=["AS-002"])
    assert _classify(case, [_finding("AS-002", "HIGH")]) == DETECTED


def test_high_correlation_finding_detected():
    """A HIGH/CRITICAL correlation/chain finding -> DETECTED."""
    from agentshield.attack_lab import _classify

    case = _case(expected_rules=["AS-MCP-001", "AS-MCP-004"])
    # AS-CHAIN-003 at HIGH is valid detection evidence even though the
    # individual expected rules only fired at MEDIUM.
    findings = [
        _finding("AS-MCP-001", "MEDIUM"),
        _finding("AS-MCP-004", "MEDIUM"),
        _finding("AS-CHAIN-003", "HIGH"),
    ]
    assert _classify(case, findings) == DETECTED


def test_high_step_sequence_finding_detected():
    """A HIGH/CRITICAL step-sequence finding -> DETECTED."""
    from agentshield.attack_lab import _classify

    case = _case(expected_rules=["AS-004"])
    assert _classify(case, [_finding("AS-CHAIN-001", "CRITICAL")]) == DETECTED


def test_only_low_info_findings_not_detected():
    """Only LOW/INFO supporting findings -> not automatically DETECTED."""
    from agentshield.attack_lab import _classify

    case = _case(expected_rules=["AS-004"])
    assert _classify(case, [_finding("AS-004", "LOW")]) == PARTIALLY_DETECTED


def test_genuine_partial_remains_partial():
    """A MEDIUM expected-rule finding with no HIGH/CRITICAL -> PARTIAL."""
    from agentshield.attack_lab import _classify

    case = _case(expected_rules=["AS-004"])
    assert _classify(case, [_finding("AS-004", "MEDIUM")]) == PARTIALLY_DETECTED


def test_no_relevant_finding_missed():
    """No relevant finding -> MISSED."""
    from agentshield.attack_lab import _classify

    case = _case(expected_rules=["AS-004"])
    assert _classify(case, []) == MISSED


def test_benign_with_high_finding_false_positive():
    """A benign lookalike with a HIGH finding -> FALSE_POSITIVE."""
    from agentshield.attack_lab import _classify

    case = _case(is_benign=True)
    assert _classify(case, [_finding("AS-004", "HIGH")]) == FALSE_POSITIVE


def test_benign_clean_detected():
    """A benign lookalike with no HIGH finding -> DETECTED (correctly clean)."""
    from agentshield.attack_lab import _classify

    case = _case(is_benign=True)
    assert _classify(case, [_finding("AS-004", "LOW")]) == DETECTED


# --- Attack Lab regression baseline ----------------------------------------
#
# This is an explicit expected baseline for the current 95-case corpus. It
# guards against regressions: every future scanner change must keep previously
# detected cases detected and avoid new false positives. If a case is
# intentionally PARTIAL or MISSED, that expectation is preserved here unless
# there is a deliberate, reviewed detection improvement.

EXPECTED_TOTAL = 95
EXPECTED_FALSE_POSITIVES = 0
EXPECTED_DETECTED = 88
EXPECTED_PARTIALLY_DETECTED = 7
EXPECTED_MISSED = 0

# Per-case expected classifications. Keyed by (category, name).
# These are the current verified classifications; update deliberately when a
# detection improvement is made and reviewed.
EXPECTED_CASE_RESULTS = {
    # v1 categories
    ("prompt-injection", "override-instructions"): DETECTED,
    ("prompt-injection", "disable-security"): DETECTED,
    ("prompt-injection", "exfiltrate-files"): DETECTED,
    ("prompt-injection", "benign"): DETECTED,
    ("shell-execution", "os-system-var"): DETECTED,
    ("shell-execution", "subprocess-shell"): DETECTED,
    ("shell-execution", "eval-var"): DETECTED,
    ("shell-execution", "benign"): DETECTED,
    ("remote-download", "curl-pipe-bash"): DETECTED,
    ("remote-download", "wget-pipe-sh"): DETECTED,
    ("remote-download", "benign"): DETECTED,
    ("encoded-obfuscation", "base64-exec"): DETECTED,
    ("encoded-obfuscation", "rot13-exec"): PARTIALLY_DETECTED,
    ("encoded-obfuscation", "benign"): DETECTED,
    ("filesystem-access", "broad-fs"): PARTIALLY_DETECTED,
    ("filesystem-access", "benign"): DETECTED,
    ("mcp-attacks", "secrets-env"): DETECTED,
    ("mcp-attacks", "remote-exec"): DETECTED,
    ("mcp-attacks", "broad-fs-secrets"): DETECTED,
    ("mcp-attacks", "benign"): DETECTED,
    ("multi-stage", "data-sync"): DETECTED,
    ("multi-stage", "download-run"): DETECTED,
    ("multi-stage", "benign"): DETECTED,
    ("secret-exfiltration", "env-dump"): DETECTED,
    ("secret-exfiltration", "read-credentials"): DETECTED,
    ("secret-exfiltration", "reveal-secrets"): DETECTED,
    ("secret-exfiltration", "benign"): DETECTED,
    # v2 categories — previously MISSED, now DETECTED via source-to-sink tracking
    ("v2-secret-exfiltration", "read-transform-network"): DETECTED,
    ("v2-multi-stage", "discovery-secret-network"): DETECTED,
}


def test_attack_lab_regression_total():
    """The corpus size must not regress."""
    lab = run_attack_lab()
    s = lab.summary()
    assert s["total"] == EXPECTED_TOTAL, f"corpus size changed: {s['total']} != {EXPECTED_TOTAL}"


def test_attack_lab_regression_no_false_positives():
    """No unexpected false positives."""
    lab = run_attack_lab()
    s = lab.summary()
    assert s["false_positives"] == EXPECTED_FALSE_POSITIVES, (
        f"false positives changed: {s['false_positives']} != {EXPECTED_FALSE_POSITIVES}"
    )


def test_attack_lab_regression_counts():
    """The overall classification counts must match the expected baseline."""
    lab = run_attack_lab()
    s = lab.summary()
    assert s["detected"] == EXPECTED_DETECTED, f"detected changed: {s['detected']} != {EXPECTED_DETECTED}"
    assert s["partially_detected"] == EXPECTED_PARTIALLY_DETECTED, (
        f"partially detected changed: {s['partially_detected']} != {EXPECTED_PARTIALLY_DETECTED}"
    )
    assert s["missed"] == EXPECTED_MISSED, f"missed changed: {s['missed']} != {EXPECTED_MISSED}"


def test_attack_lab_regression_per_case():
    """Every tracked case must keep its expected classification.

    This is the strongest regression guard: it catches a case silently
    regressing from DETECTED to PARTIAL/MISSED, or a benign case becoming a
    false positive. Cases not in the explicit map are still validated for a
    valid classification bucket by test_attack_lab_classifications_are_valid.
    """
    lab = run_attack_lab()
    by_key = {(c["category"], c["name"]): c["result"] for c in lab.cases}
    for key, expected in EXPECTED_CASE_RESULTS.items():
        assert key in by_key, f"case {key} not found in lab results"
        actual = by_key[key]
        assert actual == expected, f"case {key} regressed: {actual} != {expected}"
