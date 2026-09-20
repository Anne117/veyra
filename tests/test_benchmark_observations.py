"""Tests for BenchmarkObservation (Commit 38).

BenchmarkObservation is the immutable, normalized representation of explicit
observed security properties. It is a transport/contract model only: it
normalizes identifiers, performs no security inference, and is not a security
verdict. SecurityAssertion remains the only violation-derivation layer.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkEvaluationResult,
    BenchmarkEvaluationSummary,
    BenchmarkObservation,
    BenchmarkEvaluator,
    SecurityAssertion,
    SecurityScenario,
    SecurityScenarioThreatMapping,
    BenchmarkCase,
    ThreatModelError,
    serialize_benchmark_evaluation_result,
    serialize_benchmark_observation,
)


# ---- A. Model construction ----
def test_empty_observation():
    o = BenchmarkObservation()
    assert o.properties == ()


def test_one_property():
    o = BenchmarkObservation(properties=("a",))
    assert o.properties == ("a",)


def test_multiple_properties():
    o = BenchmarkObservation(properties=("b", "a", "c"))
    assert o.properties == ("a", "b", "c")


def test_normalization_trims_whitespace():
    o = BenchmarkObservation(properties=("  a  ", " b "))
    assert o.properties == ("a", "b")


def test_blank_values_removed():
    o = BenchmarkObservation(properties=("a", "", "  ", "b"))
    assert o.properties == ("a", "b")


def test_duplicates_removed():
    o = BenchmarkObservation(properties=("a", "a", "a", "b"))
    assert o.properties == ("a", "b")


def test_deterministic_sorting():
    o1 = BenchmarkObservation(properties=("b", "a", "c"))
    o2 = BenchmarkObservation(properties=("c", "a", "b"))
    assert o1.properties == o2.properties == ("a", "b", "c")


def test_case_sensitive_identifiers():
    o = BenchmarkObservation(properties=("ASI01", "asi01", "ASI01"))
    assert o.properties == ("ASI01", "asi01")


def test_frozen_immutable():
    o = BenchmarkObservation(properties=("a",))
    with pytest.raises(AttributeError):
        o.properties = ("x",)  # type: ignore[misc]


def test_repeated_construction_deterministic():
    a = BenchmarkObservation(properties=(" x ", "y", "x"))
    b = BenchmarkObservation(properties=("y", "x", " x "))
    assert a.properties == b.properties == ("x", "y")


# ---- B. Validation ----
def test_scalar_string_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkObservation(properties="scalar")


def test_integer_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkObservation(properties=(1, 2))


def test_none_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkObservation(properties=(None,))  # type: ignore[list-item]


def test_object_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkObservation(properties=[object()])  # type: ignore[list-item]


def test_mixed_invalid_sequence_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkObservation(properties=("ok", 5))


def test_invalid_property_type_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkObservation(properties=(b"bytes",))


def test_empty_sequence_accepted():
    o = BenchmarkObservation(properties=())
    assert o.properties == ()


# ---- C. Serialization ----
def test_empty_serialization():
    d = serialize_benchmark_observation(BenchmarkObservation())
    assert d == {"properties": []}


def test_one_property_serialization():
    d = serialize_benchmark_observation(BenchmarkObservation(properties=("a",)))
    assert d == {"properties": ["a"]}


def test_multi_property_serialization():
    d = serialize_benchmark_observation(BenchmarkObservation(properties=("b", "a")))
    assert d == {"properties": ["a", "b"]}


def test_normalized_serialization():
    d = serialize_benchmark_observation(BenchmarkObservation(properties=(" b ", "a", "b")))
    assert d == {"properties": ["a", "b"]}


def test_deterministic_serialization():
    o = BenchmarkObservation(properties=("x", "y"))
    assert serialize_benchmark_observation(o) == serialize_benchmark_observation(o)


def test_exact_key_name():
    d = serialize_benchmark_observation(BenchmarkObservation(properties=("a",)))
    assert set(d.keys()) == {"properties"}


def test_no_extra_fields():
    d = serialize_benchmark_observation(BenchmarkObservation(properties=("a",)))
    assert "benchmark_id" not in d
    assert "case_id" not in d
    assert "severity" not in d
    assert "metadata" not in d


def test_json_safe():
    d = serialize_benchmark_observation(BenchmarkObservation(properties=("a", "b")))
    assert json.loads(json.dumps(d)) == d


# ---- D. Evaluator integration ----
def test_evaluator_normalizes_through_observation():
    case = _case()
    r = BenchmarkEvaluator().evaluate(case, observed_properties=(" no-exfiltration ", "no-exfiltration"))
    assert r.observed_properties == ("no-exfiltration",)


def test_result_contains_normalized_properties():
    sc = _scenario(expected=())
    case = _case(scenario=sc)
    r = BenchmarkEvaluator().evaluate(case, observed_properties=(" z ", "a", "z"))
    assert r.observed_properties == ("a", "z")


def test_assertion_receives_normalized_observations(monkeypatch):
    real = SecurityAssertion()
    orig = SecurityAssertion.assert_properties
    seen = {}
    def _spy(self, expected, observed):
        seen["observed"] = tuple(observed)
        return orig(self, expected, observed)
    monkeypatch.setattr(SecurityAssertion, "assert_properties", _spy)
    BenchmarkEvaluator().evaluate(_case(), observed_properties=(" b ", "a", "b"))
    assert list(seen["observed"]) == ["a", "b"]


def test_violations_still_derived_by_assertion():
    sc = _scenario(expected=("no-exfiltration",))
    r = BenchmarkEvaluator().evaluate(_case(scenario=sc), observed_properties=())
    assert r.violated_properties == ("no-exfiltration",)
    assert r.passed is False


def test_passed_semantics_unchanged():
    sc = _scenario(expected=("no-exfiltration",))
    ev = BenchmarkEvaluator()
    assert ev.evaluate(_case(scenario=sc), observed_properties=("no-exfiltration",)).passed is True
    assert ev.evaluate(_case(scenario=sc), observed_properties=()).passed is False


def test_expected_only_from_scenario():
    sc = _scenario(expected=("a", "b"))
    r = BenchmarkEvaluator().evaluate(_case(scenario=sc), observed_properties=("a",))
    assert r.violated_properties == ("b",)


def test_caller_cannot_control_violations():
    r = BenchmarkEvaluator().evaluate(_case(), observed_properties=())
    assert r.violated_properties == ("no-exfiltration",)


def test_old_violated_properties_keyword_raises_typeerror():
    with pytest.raises(TypeError):
        BenchmarkEvaluator().evaluate(
            _case(), observed_properties=("a",),
            violated_properties=("fake",))  # type: ignore[call-arg]


# ---- E. Isolation ----
def test_observation_only_has_properties_field():
    # The model exposes no inference/scenario/graph/risk members.
    o = BenchmarkObservation(properties=("a",))
    assert set(vars(o).keys()) == {"properties"}
    for attr in ("benchmark_id", "case_id", "scenario", "threat_mapping", "nodes",
                 "edges", "severity", "risk_score", "confidence", "attack_type",
                 "findings"):
        assert not hasattr(o, attr), f"unexpected member {attr}"


def test_observation_is_not_attack_path_or_graph():
    from veyra.graph.path import AttackPath
    from veyra.graph import SecurityGraph
    o = BenchmarkObservation(properties=("a",))
    assert not isinstance(o, AttackPath)
    assert not isinstance(o, SecurityGraph)
    assert not isinstance(o, BenchmarkEvaluationResult)


def test_observation_does_not_import_scanner_graph_owasp():
    import veyra.threats.observations as obs_mod
    # The model only imports the threat-layer normalization helper (no runner,
    # scanner, graph, evaluator, or OWASP catalog).
    names = list(obs_mod.__dict__.keys())
    for banned in ("BenchmarkEvaluator", "SecurityAssertion", "BenchmarkCase",
                   "OWASP_AGENTIC_2026", "scanner", "graph"):
        assert banned not in names, f"observation module imports/displays {banned}"


def test_observation_does_not_import_benchmark_case():
    import veyra.threats.observations as obs_mod
    assert "BenchmarkCase" not in obs_mod.__dict__


def test_no_network_subprocess_filesystem(monkeypatch):
    import socket, os, subprocess
    calls = []
    class Sock:
        def connect(self, *a):
            calls.append(a)
    monkeypatch.setattr(socket.socket, "connect", Sock().connect)
    monkeypatch.setattr(os, "listdir", lambda *a, **k: calls.append("ls"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess")))
    BenchmarkObservation(properties=("a",))
    assert calls == []


def test_observation_does_not_mutate_input():
    props = ["b", " a ", "a"]
    before = list(props)
    BenchmarkObservation(properties=props)
    assert list(props) == before


def test_public_api_exports():
    from veyra import threats
    assert hasattr(threats, "BenchmarkObservation")
    assert threats.BenchmarkObservation is BenchmarkObservation
    assert hasattr(threats, "serialize_benchmark_observation")


def test_existing_threat_exports_intact():
    from veyra import threats
    for name in ("SecurityAssertion", "SecurityScenario", "BenchmarkCase",
                 "BenchmarkEvaluationResult", "BenchmarkEvaluationSummary",
                 "BenchmarkEvaluator", "SecurityScenarioThreatMapping"):
        assert hasattr(threats, name), f"missing {name}"


# helpers
def _scenario(expected=("no-exfiltration",)):
    return SecurityScenario(scenario_id="s", name="n", description="d",
                            expected_security_properties=expected)


def _case(benchmark_id="b", case_id="c", scenario=None):
    return BenchmarkCase(
        benchmark_id=benchmark_id,
        case_id=case_id,
        name="n",
        description="d",
        scenario=scenario if scenario is not None else _scenario(),
        threat_mapping=SecurityScenarioThreatMapping(scenario_id="s"),
    )
