"""Tests for BenchmarkEvaluator (Commit 31).

The evaluator is the first, pure and deterministic evaluation logic layer. It
converts a BenchmarkCase plus explicit observations/violations into a
BenchmarkEvaluationResult. It does NOT execute benchmarks, run the Veyra
scanner, build graphs/paths, compute Veyra risk, or infer anything.

The only evaluation rule is the benchmark property contract:
    passed = (number of normalized violated_properties == 0)
"""

import pytest

from veyra.threats import (
    SecurityScenario,
    SecurityScenarioThreatMapping,
    BenchmarkCase,
    BenchmarkEvaluationResult,
    BenchmarkEvaluator,
    ThreatModelError,
    serialize_benchmark_evaluation_result,
)
from veyra.threats.adapters import AgentDojoAdapter, AgentThreatBenchAdapter


def _case(benchmark_id="dummy", case_id="c-1", **kw):
    base = dict(
        benchmark_id=benchmark_id,
        case_id=case_id,
        name="Secret Exfil",
        description="Ensure secrets stay confidential.",
        scenario=SecurityScenario(
            scenario_id="s-1",
            name="Scenario",
            description="Expected: no exfiltration.",
            threat_categories=("ASI02", "data-exfiltration"),
            expected_security_properties=("no-exfiltration",),
        ),
        threat_mapping=SecurityScenarioThreatMapping(scenario_id="s-1", threat_ids=("ASI02",)),
    )
    base.update(kw)
    return BenchmarkCase(**base)


EV = BenchmarkEvaluator()


def _case_from_adapter(benchmark_id, adapter):
    bc = adapter.adapt({
        "case_id": "c-x",
        "name": "n",
        "description": "d",
        "threat_ids": ["ASI01"],
        "threat_categories": ["ASI01"],
    })
    # Rebuild with the desired benchmark_id via a new case sharing scenario/mapping.
    return BenchmarkCase(
        benchmark_id=benchmark_id, case_id=bc.case_id, name=bc.name,
        description=bc.description, scenario=bc.scenario, threat_mapping=bc.threat_mapping,
    )


# 1. minimal successful evaluation
def test_minimal_success():
    r = EV.evaluate(_case())
    assert r is not None
    assert r.passed is True


# 2. failed evaluation with one violation
def test_one_violation_fails():
    r = EV.evaluate(_case(), violated_properties=("leak",))
    assert r.passed is False
    assert r.violated_properties == ("leak",)


# 3. failed evaluation with multiple violations
def test_multiple_violations_fail():
    r = EV.evaluate(_case(), violated_properties=("a", "b"))
    assert r.passed is False
    assert r.violated_properties == ("a", "b")


# 4. benchmark_id copied from BenchmarkCase
def test_benchmark_id_copied():
    assert EV.evaluate(_case(benchmark_id="x")).benchmark_id == "x"


# 5. case_id copied from BenchmarkCase
def test_case_id_copied():
    assert EV.evaluate(_case(case_id="abc")).case_id == "abc"


# 6. observed_properties passed through
def test_observed_passthrough():
    r = EV.evaluate(_case(), observed_properties=("secret-read", "no-leak"))
    assert r.observed_properties == ("no-leak", "secret-read")


# 7. violated_properties passed through
def test_violated_passthrough():
    r = EV.evaluate(_case(), violated_properties=("exfil",))
    assert r.violated_properties == ("exfil",)


# 8. status preservation
def test_status_preserved():
    assert EV.evaluate(_case(), status="error").status == "error"


# 9. default status
def test_default_status():
    assert EV.evaluate(_case()).status == "completed"


# 10. explicit message
def test_explicit_message():
    assert EV.evaluate(_case(), message="all good").message == "all good"


# 11. default message
def test_default_message():
    assert EV.evaluate(_case()).message == "Benchmark evaluation completed."


# 12. metadata preservation
def test_metadata_preserved():
    r = EV.evaluate(_case(), metadata=(("k1", "v1"),))
    assert r.metadata == (("k1", "v1"),)


# 13. passed=True when violations empty
def test_passed_true_empty_violations():
    assert EV.evaluate(_case(), violated_properties=()).passed is True


# 14. passed=False when violations non-empty
def test_passed_false_nonempty_violations():
    assert EV.evaluate(_case(), violated_properties=("x",)).passed is False


# 15. observed properties do NOT affect passed
def test_observed_does_not_affect_passed():
    r = EV.evaluate(_case(), observed_properties=("secret-read",))
    assert r.passed is True
    assert r.observed_properties == ("secret-read",)


# 16. expected_security_properties do NOT affect passed
def test_expected_security_properties_do_not_affect_passed():
    case = _case()
    assert "no-exfiltration" in case.scenario.expected_security_properties
    r = EV.evaluate(case, observed_properties=("secret-read",), violated_properties=())
    # Violations explicitly empty -> passed even though an expected property
    # "no-exfiltration" is NOT in observed properties.
    assert r.passed is True


# 17. description does NOT affect passed
def test_description_does_not_affect_passed():
    case = _case(description="This scenario MUST prevent exfiltration.")
    r = EV.evaluate(case, violated_properties=())
    assert r.passed is True


# 18. threat IDs do NOT affect passed
def test_threat_ids_do_not_affect_passed():
    case = _case()
    assert case.threat_mapping.threat_ids == ("ASI02",)
    r = EV.evaluate(case, violated_properties=())
    assert r.passed is True


# 19. OWASP categories do NOT affect passed
def test_owasp_categories_do_not_affect_passed():
    case = _case()
    assert case.scenario.threat_categories == ("ASI02", "data-exfiltration")
    r = EV.evaluate(case, violated_properties=())
    assert r.passed is True


# 20. deterministic property normalization
def test_deterministic_normalization():
    a = EV.evaluate(_case(), observed_properties=("b", "a"), violated_properties=("x", "y"))
    b = EV.evaluate(_case(), observed_properties=("a", "b"), violated_properties=("y", "x"))
    assert serialize_benchmark_evaluation_result(a) == serialize_benchmark_evaluation_result(b)


# 21. deterministic serialization
def test_deterministic_serialization():
    r = EV.evaluate(_case(), observed_properties=("a",), metadata=(("k", "v"),))
    assert serialize_benchmark_evaluation_result(r) == serialize_benchmark_evaluation_result(r)


# 22. invalid case type
def test_invalid_case_type():
    with pytest.raises(ThreatModelError):
        EV.evaluate("not-a-case")


# 23. invalid observed_properties scalar
def test_invalid_observed_scalar():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), observed_properties="abc")


# 24. invalid observed_properties element
def test_invalid_observed_element():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), observed_properties=("ok", 5))


# 25. invalid violated_properties scalar
def test_invalid_violated_scalar():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), violated_properties=5)


# 26. invalid violated_properties element
def test_invalid_violated_element():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), violated_properties=(None,))  # type: ignore[arg-type]


# 27. invalid status
def test_invalid_status():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), status="")


def test_invalid_status_type():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), status=1)


# 28. invalid message type
def test_invalid_message_type():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), message=["x"])


# 29. invalid metadata
def test_invalid_metadata():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), metadata=(("k", 5),))  # type: ignore[list-item]  # noqa: E501


# 30. metadata normalization delegated to result model
def test_metadata_normalization_delegated():
    r = EV.evaluate(_case(), metadata=((" b ", "2"), (" a ", "1")))
    assert r.metadata == (("a", "1"), ("b", "2"))


# 31. case immutability
def test_case_immutability():
    case = _case()
    snap_nodes = tuple(case.scenario.threat_categories)
    snap_map = case.threat_mapping.threat_ids
    snap_meta = (case.benchmark_id, case.case_id, case.name, case.description)
    EV.evaluate(case, observed_properties=("p",), violated_properties=("q",),
                metadata=(("k", "v"),))
    assert case.scenario.threat_categories == snap_nodes
    assert case.threat_mapping.threat_ids == snap_map
    assert (case.benchmark_id, case.case_id, case.name, case.description) == snap_meta


# 32. result is BenchmarkEvaluationResult
def test_result_type():
    assert isinstance(EV.evaluate(_case()), BenchmarkEvaluationResult)


# 33. result is frozen
def test_result_frozen():
    r = EV.evaluate(_case())
    with pytest.raises(AttributeError):
        r.passed = False  # type: ignore[misc]


# 34. benchmark-agnostic AgentDojo case
def test_agentdojo_case_agnostic():
    case = _case_from_adapter("agentdojo", AgentDojoAdapter())
    r = EV.evaluate(case)
    assert r.benchmark_id == "agentdojo"
    assert r.passed is True


# 35. benchmark-agnostic AgentThreatBench case
def test_agentthreatbench_case_agnostic():
    case = _case_from_adapter("agentthreatbench", AgentThreatBenchAdapter())
    r = EV.evaluate(case)
    assert r.benchmark_id == "agentthreatbench"
    assert r.passed is True


# 36. no AttackPath creation
def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    r = EV.evaluate(_case())
    assert not isinstance(r, AttackPath)
    assert not hasattr(r, "nodes")
    assert not hasattr(r, "evidence")


# 37. no SecurityGraph mutation
def test_no_graph_mutation():
    from veyra.graph import SecurityGraph
    g = SecurityGraph()
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    EV.evaluate(_case())
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# 38. no network execution
def test_no_network_execution(monkeypatch):
    import socket as socket_mod
    calls = []

    class Sock:
        def connect(self, *a):  # pragma: no cover - must not be called
            calls.append(a)

    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    EV.evaluate(_case())
    assert calls == []


# 39. no subprocess execution
def test_no_subprocess_execution(monkeypatch):
    import subprocess as subprocess_mod

    def _popen(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("must not execute subprocess")

    monkeypatch.setattr(subprocess_mod, "Popen", _popen)
    EV.evaluate(_case())
    assert True


# 40. no external benchmark imports/execution
def test_no_external_benchmark_execution():
    # Evaluator works purely on the supplied case; no dataset/package access.
    r = EV.evaluate(_case_from_adapter("agentdojo", AgentDojoAdapter()))
    assert r.passed is True


# no risk/severity/confidence/attack_type fields
def test_no_risk_or_security_fields():
    r = EV.evaluate(_case(), violated_properties=("x",))
    for attr in ("risk_score", "severity", "confidence", "attack_type", "findings"):
        assert not hasattr(r, attr), f"unexpected {attr}"
    d = serialize_benchmark_evaluation_result(r)
    for banned in ("risk", "severity", "confidence", "attack_type", "findings",
                   "attack_paths", "scanner"):
        assert banned not in d


# passed semantics is purely "no violated properties"
def test_passed_semantics_only_no_violations():
    # Even with observed_properties contradicting expectations, passed is True
    # because violations are explicitly empty.
    case = _case(description="MUST never leak", )
    r = EV.evaluate(case, observed_properties=("secret-read", "external-send"))
    assert r.passed is True


# message="" maps to deterministic default message
def test_empty_message_default():
    r = EV.evaluate(_case(), message="")
    assert r.message == "Benchmark evaluation completed."


def test_whitespace_message_default():
    r = EV.evaluate(_case(), message="   ")
    assert r.message == "Benchmark evaluation completed."


# public API export
def test_public_api_exports():
    from veyra import threats
    assert hasattr(threats, "BenchmarkEvaluator")
    assert threats.BenchmarkEvaluator is BenchmarkEvaluator


# REGRESSION: AgentDojoAdapter unchanged
def test_agentdojo_adapter_regression():
    bc = AgentDojoAdapter().adapt({"case_id": "x", "name": "n", "description": "d",
                                   "threat_ids": ["ASI01"]})
    assert bc.benchmark_id == "agentdojo"
    assert bc.threat_mapping.threat_ids == ("ASI01",)


# REGRESSION: AgentThreatBenchAdapter unchanged
def test_agentthreatbench_adapter_regression():
    bc = AgentThreatBenchAdapter().adapt({"case_id": "x", "name": "n", "description": "d",
                                          "threat_ids": ["ASI01"]})
    assert bc.benchmark_id == "agentthreatbench"
    assert bc.threat_mapping.threat_ids == ("ASI01",)
