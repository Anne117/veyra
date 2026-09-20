"""Tests for SecurityAssertion (Commit 36).

SecurityAssertion deterministically compares expected security properties
against explicit observed properties: violated = expected - observed. It does
NOT create BenchmarkEvaluationResult, invoke the evaluator/runner, inspect
scenarios, infer threats/OWASP, or execute anything.
"""

import pytest

from veyra.threats import (
    SecurityAssertion,
    SecurityScenario,
    ThreatModelError,
)


SA = SecurityAssertion()


# ---- 1. Basic assertion behavior ----
def test_no_expected_no_violations():
    assert SA.assert_properties(expected_properties=(), observed_properties=()) == ()


def test_all_expected_observed_no_violations():
    assert SA.assert_properties(
        expected_properties=("a", "b"), observed_properties=("a", "b")) == ()


def test_one_missing_expected():
    assert SA.assert_properties(
        expected_properties=("no-secret-exfiltration", "no-network-egress"),
        observed_properties=("no-secret-exfiltration",)) == ("no-network-egress",)


def test_multiple_missing_expected():
    assert SA.assert_properties(
        expected_properties=("a", "b", "c"), observed_properties=("c",)) == ("a", "b")


def test_observed_extra_ignored():
    assert SA.assert_properties(
        expected_properties=("a", "b"), observed_properties=("a", "b", "extra")) == ()


def test_exact_string_matching_only():
    # Identifiers are compared exactly (after trim); a genuinely different
    # string is NOT matched.
    assert SA.assert_properties(
        expected_properties=("secret-read",), observed_properties=("secret-reader",)) == (
        "secret-read",)


def test_whitespace_exact_match_after_normalization():
    # Whitespace is normalized on both sides, so identical strings match.
    assert SA.assert_properties(
        expected_properties=(" secret-read  ",), observed_properties=("  secret-read ",)) == ()


# ---- 2. Determinism ----
def test_result_ordering_deterministic():
    # expected is normalized (sorted); violations follow expected order.
    assert SA.assert_properties(
        expected_properties=("c", "a", "b"), observed_properties=("c",)) == ("a", "b")


def test_duplicate_expected_properties():
    assert SA.assert_properties(
        expected_properties=("a", "a", "b"), observed_properties=("a",)) == ("b",)


def test_duplicate_observed_properties():
    assert SA.assert_properties(
        expected_properties=("a", "b"), observed_properties=("a", "a", "a")) == ("b",)


def test_whitespace_normalization():
    assert SA.assert_properties(
        expected_properties=(" a ", "b"), observed_properties=(" a ",)) == ("b",)


def test_repeated_calls_identical():
    exp = ("a", "b")
    obs = ("a",)
    assert SA.assert_properties(exp, obs) == SA.assert_properties(exp, obs)


def test_inputs_remain_unchanged():
    exp = ["b", "a"]
    obs = ["b", "extra"]
    before_exp = list(exp)
    before_obs = list(obs)
    SA.assert_properties(exp, obs)
    assert exp == before_exp
    assert obs == before_obs


# ---- 3. Validation ----
def test_non_sequence_expected_rejected():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties="scalar", observed_properties=())


def test_scalar_string_expected_rejected():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties="a", observed_properties=())


def test_invalid_expected_element_rejected():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties=("a", 5), observed_properties=())


def test_non_sequence_observed_rejected():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties=("a",), observed_properties=7)


def test_scalar_string_observed_rejected():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties=("a",), observed_properties="a")


def test_invalid_observed_element_rejected():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties=("a",), observed_properties=("a", None))  # type: ignore[list-item]


def test_none_expected_rejected():
    # The existing threat-model helper treats None as an empty collection, so
    # None yields no violations (no elements to require).
    assert SA.assert_properties(expected_properties=None, observed_properties=()) == ()  # type: ignore[arg-type]


def test_invalid_runtime_type_raises():
    with pytest.raises(ThreatModelError):
        SA.assert_properties(expected_properties=[["a"]], observed_properties=())


# ---- 4. SecurityScenario integration ----
def test_works_with_scenario_expected_properties():
    sc = SecurityScenario(
        scenario_id="sc",
        name="n",
        description="d",
        expected_security_properties=("no-secret-exfiltration", "no-network-egress"),
    )
    violated = SA.assert_properties(sc.expected_security_properties, ("no-secret-exfiltration",))
    assert violated == ("no-network-egress",)


def test_assert_layer_does_not_mutate_scenario():
    sc = SecurityScenario(
        scenario_id="sc",
        name="n",
        description="d",
        expected_security_properties=("a", "b"),
    )
    snap = sc.expected_security_properties
    SA.assert_properties(sc.expected_security_properties, ("a",))
    assert sc.expected_security_properties == snap


def test_does_not_inspect_scenario_metadata():
    # The assertion layer only reads explicit identifiers, never scenario
    # name/description/threat ids. A scenario with a misleading threat title
    # behaves identically.
    sc = SecurityScenario(
        scenario_id="sc",
        name="This is definitely a secret exfil scenario",
        description="description that implies violations",
        expected_security_properties=("a",),
    )
    assert SA.assert_properties(sc.expected_security_properties, ("a",)) == ()


# ---- 5. Architectural isolation ----
def test_no_benchmark_evaluation_result_created():
    r = SA.assert_properties(("a",), ())
    # Returns a plain tuple of strings, not a result model.
    assert isinstance(r, tuple)
    assert all(isinstance(x, str) for x in r)


def test_no_evaluator_invocation(monkeypatch):
    import veyra.threats.evaluator as ev
    calls = []
    def _fake(self, *a, **k):
        calls.append(a)
        return None
    monkeypatch.setattr(ev.BenchmarkEvaluator, "evaluate", _fake)
    SA.assert_properties(("a",), ())
    assert calls == []


def test_no_benchmark_case_dependency():
    # Works purely on property identifiers.
    assert SA.assert_properties(("a", "b"), ("a",)) == ("b",)


def test_no_runner_dependency():
    import veyra.threats.runner as runner_mod
    assert not hasattr(runner_mod, "SecurityAssertion")


def test_no_security_graph():
    from veyra.graph import SecurityGraph
    r = SA.assert_properties(("a",), ())
    assert not isinstance(r, SecurityGraph)
    assert not hasattr(r, "nodes")


def test_no_attack_path():
    from veyra.graph.path import AttackPath
    r = SA.assert_properties(("a",), ())
    assert not isinstance(r, AttackPath)


def test_no_scanner(monkeypatch):
    import veyra.scanner as scanner_mod
    calls = []
    def _fake(*a, **k):
        calls.append(a)
    monkeypatch.setattr(scanner_mod, "scan_path", _fake)
    SA.assert_properties(("a",), ())
    assert calls == []


def test_no_risk_severity_confidence():
    r = SA.assert_properties(("a",), ("b",))
    for attr in ("risk_score", "severity", "confidence", "attack_type"):
        assert not hasattr(r, attr)
    assert not hasattr(SA, "risk_score")


def test_no_owasp_or_threat_inference():
    # OWASP-like identifiers are treated as opaque property strings.
    assert SA.assert_properties(("ASI01",), ("ASI02",)) == ("ASI01",)
    assert SA.assert_properties(("ASI01",), ("ASI01",)) == ()


def test_no_network_subprocess_filesystem(monkeypatch):
    import socket as socket_mod
    import os as os_mod
    import subprocess as subprocess_mod
    net = []
    class Sock:
        def connect(self, *a):
            net.append(a)
    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    monkeypatch.setattr(os_mod, "listdir", lambda *a, **k: net.append("ls"))
    monkeypatch.setattr(subprocess_mod, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess")))
    SA.assert_properties(("a",), ())
    assert net == []


# ---- 6. Exact semantics ----
def test_semantics_empty_observed():
    assert SA.assert_properties(("a",), ()) == ("a",)


def test_semantics_observed_all():
    assert SA.assert_properties(("a",), ("a",)) == ()


def test_semantics_observed_different():
    assert SA.assert_properties(("a",), ("b",)) == ("a",)


def test_semantics_multiple_expected():
    assert SA.assert_properties(("a", "b"), ("a",)) == ("b",)


def test_semantics_observed_extra():
    assert SA.assert_properties(("a",), ("a", "b")) == ()


def test_case_sensitive_identifiers():
    assert SA.assert_properties(("SecretRead",), ("secretread",)) == ("SecretRead",)
    assert SA.assert_properties(("a",), ("A",)) == ("a",)


def test_no_fuzzy_matching():
    # Distinct but similar identifiers are NOT matched.
    assert SA.assert_properties(("no-network-egress",), ("no-network-egres",)) == (
        "no-network-egress",)


def test_no_substring_matching():
    assert SA.assert_properties(("exfil",), ("secret-exfil",)) == ("exfil",)
    assert SA.assert_properties(("network",), ("no-network-egress",)) == ("network",)


# ---- 7. Public API ----
def test_public_export():
    from veyra import threats
    assert hasattr(threats, "SecurityAssertion")
    assert threats.SecurityAssertion is SecurityAssertion


def test_existing_exports_preserved():
    from veyra import threats
    for name in ("SecurityScenario", "SecurityScenarioThreatMapping", "BenchmarkCase",
                 "BenchmarkEvaluator", "BenchmarkEvaluationResult",
                 "BenchmarkRunner", "ObservationBenchmarkRunner",
                 "BenchmarkEvaluationAggregator", "CrossBenchmarkEvaluationAggregator",
                 "ThreatScenario", "ThreatTaxonomy"):
        assert hasattr(threats, name), f"missing {name}"


def test_mixed_expected_observed():
    # Combination: some expected present, some missing, some observed extra.
    assert SA.assert_properties(
        expected_properties=("a", "b", "c"),
        observed_properties=("a", "c", "z"),
    ) == ("b",)


def test_empty_expected_any_observed():
    assert SA.assert_properties(expected_properties=(), observed_properties=("x", "y")) == ()


def test_observed_superset_still_no_violation():
    assert SA.assert_properties(
        expected_properties=("a", "b"), observed_properties=("a", "b", "c", "d")) == ()


def test_all_expected_missing_sorted():
    assert SA.assert_properties(expected_properties=("b", "a"), observed_properties=()) == ("a", "b")
