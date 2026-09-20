"""Tests for ObservationBenchmarkRunner (Commit 35).

The runner is the explicit observation-driven bridge between a BenchmarkCase and
BenchmarkEvaluator. It does NOT execute an external benchmark and infers
nothing. Execution and evaluation remain separate; evaluation is delegated to
BenchmarkEvaluator.evaluate().
"""

import pytest

from veyra.threats import (
    BenchmarkCase,
    BenchmarkEvaluationAggregator,
    BenchmarkEvaluationResult,
    BenchmarkEvaluator,
    CrossBenchmarkEvaluationAggregator,
    ObservationBenchmarkRunner,
    SecurityScenario,
    SecurityScenarioThreatMapping,
    ThreatModelError,
    serialize_benchmark_evaluation_result,
)
from veyra.threats.adapters import AgentDojoAdapter, AgentThreatBenchAdapter
from veyra.threats.execution import (
    BenchmarkExecutionBoundary,
    BenchmarkExecutionRequest,
)


def _scenario(bid="s"):
    return SecurityScenario(scenario_id=bid, name="n", description="d")


def _mapping(bid="s"):
    return SecurityScenarioThreatMapping(scenario_id=bid)


def _case(benchmark_id="bench-1", case_id="c-1"):
    return BenchmarkCase(
        benchmark_id=benchmark_id,
        case_id=case_id,
        name="n",
        description="d",
        scenario=_scenario(),
        threat_mapping=_mapping(),
    )


RUNNER = ObservationBenchmarkRunner()


# ---- A. Basic runner behavior ----
def test_valid_case_empty_observations():
    r = RUNNER.run(_case())
    assert r.passed is True
    assert r.observed_properties == ()
    assert r.violated_properties == ()


def test_valid_case_observed_properties():
    r = RUNNER.run(_case(), observed_properties=("a", "b"))
    assert r.observed_properties == ("a", "b")


def test_valid_case_violated_properties():
    r = RUNNER.run(_case(), violated_properties=("x",))
    assert r.violated_properties == ("x",)
    assert r.passed is False


def test_status_propagation():
    assert RUNNER.run(_case(), status="error").status == "error"


def test_message_propagation():
    assert RUNNER.run(_case(), message="custom msg").message == "custom msg"


def test_metadata_propagation():
    r = RUNNER.run(_case(), metadata=(("k", "v"),))
    assert r.metadata == (("k", "v"),)


def test_returns_benchmark_evaluation_result():
    assert isinstance(RUNNER.run(_case()), BenchmarkEvaluationResult)


def test_exactly_one_result_per_run():
    r = RUNNER.run(_case())
    assert isinstance(r, BenchmarkEvaluationResult)
    # One run returns the single object directly, not a collection.
    assert not isinstance(r, (list, tuple))


# ---- B. Identity ----
def test_benchmark_id_copied_from_case():
    assert RUNNER.run(_case(benchmark_id="zzz")).benchmark_id == "zzz"


def test_case_id_copied_from_case():
    assert RUNNER.run(_case(case_id="42")).case_id == "42"


def test_runner_cannot_override_identity():
    # No constructor params for identity; result always matches case.
    r = RUNNER.run(_case(benchmark_id="abc", case_id="case-7"))
    assert (r.benchmark_id, r.case_id) == ("abc", "case-7")


def test_multiple_benchmark_ids():
    for bid in ("agentdojo", "agentthreatbench", "custom"):
        assert RUNNER.run(_case(benchmark_id=bid)).benchmark_id == bid


def test_multiple_case_ids():
    for cid in ("a", "b", "c-3"):
        assert RUNNER.run(_case(case_id=cid)).case_id == cid


# ---- C. Evaluation delegation ----
def test_evaluator_invoked(monkeypatch):
    real = BenchmarkEvaluator()
    orig = BenchmarkEvaluator.evaluate  # capture before patching
    calls = []

    def _check(self, case, **kw):
        calls.append((case, kw))
        return orig(real, case, **kw)

    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _check)
    case = _case()
    RUNNER.run(case, observed_properties=("p",), metadata=(("m", "n"),))
    assert len(calls) == 1
    assert calls[0][0] is case


def test_observed_properties_forwarded(monkeypatch):
    real = BenchmarkEvaluator()
    orig = BenchmarkEvaluator.evaluate
    seen = {}
    def _check(self, case, **kw):
        seen.update(kw)
        return orig(real, case, **kw)
    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _check)
    RUNNER.run(_case(), observed_properties=("x", "y"))
    assert list(seen["observed_properties"]) == ["x", "y"]


def test_violated_properties_forwarded(monkeypatch):
    real = BenchmarkEvaluator()
    orig = BenchmarkEvaluator.evaluate
    seen = {}
    def _check(self, case, **kw):
        seen.update(kw)
        return orig(real, case, **kw)
    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _check)
    RUNNER.run(_case(), violated_properties=("leak",))
    assert list(seen["violated_properties"]) == ["leak"]


def test_status_forwarded(monkeypatch):
    real = BenchmarkEvaluator()
    orig = BenchmarkEvaluator.evaluate
    seen = {}
    def _check(self, case, **kw):
        seen.update(kw)
        return orig(real, case, **kw)
    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _check)
    RUNNER.run(_case(), status="failed")
    assert seen["status"] == "failed"


def test_message_forwarded(monkeypatch):
    real = BenchmarkEvaluator()
    orig = BenchmarkEvaluator.evaluate
    seen = {}
    def _check(self, case, **kw):
        seen.update(kw)
        return orig(real, case, **kw)
    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _check)
    RUNNER.run(_case(), message="hi")
    assert seen["message"] == "hi"


def test_metadata_forwarded(monkeypatch):
    real = BenchmarkEvaluator()
    orig = BenchmarkEvaluator.evaluate
    seen = {}
    def _check(self, case, **kw):
        seen.update(kw)
        return orig(real, case, **kw)
    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _check)
    RUNNER.run(_case(), metadata=(("k", "v"),))
    assert list(seen["metadata"]) == [("k", "v")]


def test_evaluator_result_returned_unchanged():
    result = RUNNER.run(_case())
    # The runner returns exactly what the evaluator produced.
    assert isinstance(result, BenchmarkEvaluationResult)


# ---- D. Dependency injection ----
def test_default_evaluator_created():
    runner = ObservationBenchmarkRunner()
    r = runner.run(_case())
    assert isinstance(r, BenchmarkEvaluationResult)


def test_supplied_evaluator_accepted():
    evaluator = BenchmarkEvaluator()
    runner = ObservationBenchmarkRunner(evaluator)
    assert runner.run(_case()).passed is True


def test_invalid_evaluator_rejected():
    with pytest.raises(ThreatModelError):
        ObservationBenchmarkRunner(evaluator="not-evaluator")  # type: ignore[arg-type]


def test_evaluator_not_mutated():
    evaluator = BenchmarkEvaluator()
    runner = ObservationBenchmarkRunner(evaluator)
    before = len(serialize_benchmark_evaluation_result(runner.run(_case())))
    assert isinstance(evaluator, BenchmarkEvaluator)
    assert before >= 0


def test_evaluator_reused_across_runs():
    evaluator = BenchmarkEvaluator()
    runner = ObservationBenchmarkRunner(evaluator)
    runner.run(_case())
    runner.run(_case(case_id="other"))
    assert isinstance(evaluator, BenchmarkEvaluator)


# ---- E. Boundary integration ----
def test_boundary_create_request_invoked(monkeypatch):
    calls = []
    orig = BenchmarkExecutionBoundary.create_request
    def _spy(boundary, case):
        calls.append(case)
        return orig(boundary, case)
    monkeypatch.setattr(BenchmarkExecutionBoundary, "create_request", _spy)
    case = _case()
    RUNNER.run(case)
    assert len(calls) == 1
    assert calls[0] is case


def test_request_identity_matches_case():
    case = _case(benchmark_id="b9", case_id="c9")
    r = RUNNER.run(case)
    request = BenchmarkExecutionBoundary().create_request(case)
    assert (request.benchmark_id, request.case_id) == (r.benchmark_id, r.case_id)
    assert (request.benchmark_id, request.case_id) == ("b9", "c9")


def test_boundary_side_effect_free():
    case = _case()
    snap = (case.benchmark_id, case.case_id)
    RUNNER.run(case)
    assert (case.benchmark_id, case.case_id) == snap


# ---- F. Validation ----
def test_non_benchmark_case_rejected():
    with pytest.raises(ThreatModelError):
        RUNNER.run("junk")


def test_none_rejected():
    with pytest.raises(ThreatModelError):
        RUNNER.run(None)  # type: ignore[arg-type]


def test_dict_rejected():
    with pytest.raises(ThreatModelError):
        RUNNER.run({"benchmark_id": "b", "case_id": "c"})  # type: ignore[arg-type]


def test_string_rejected():
    with pytest.raises(ThreatModelError):
        RUNNER.run("abc")


def test_malformed_observations_propagate():
    with pytest.raises(ThreatModelError):
        RUNNER.run(_case(), observed_properties="scalar")  # type: ignore[arg-type]


def test_invalid_metadata_propagates():
    with pytest.raises(ThreatModelError):
        RUNNER.run(_case(), metadata=(("k", 5),))  # type: ignore[list-item]


# ---- G. Architectural isolation ----
def test_no_aggregator_created():
    import veyra.threats.runner as runner_mod
    for name in ("BenchmarkEvaluationAggregator", "CrossBenchmarkEvaluationAggregator"):
        assert not hasattr(runner_mod, name), f"runner module should not define {name}"


def test_no_security_graph():
    from veyra.graph import SecurityGraph
    r = RUNNER.run(_case())
    assert not isinstance(r, SecurityGraph)
    assert not hasattr(r, "nodes")


def test_no_attack_path():
    from veyra.graph.path import AttackPath
    r = RUNNER.run(_case())
    assert not isinstance(r, AttackPath)


def test_no_scanner(monkeypatch):
    import veyra.scanner as scanner_mod
    calls = []
    def _fake(*a, **k):
        calls.append(a)
    monkeypatch.setattr(scanner_mod, "scan_path", _fake)
    RUNNER.run(_case())
    assert calls == []


def test_no_risk_or_severity():
    r = RUNNER.run(_case(), violated_properties=("leak",))
    for attr in ("risk_score", "severity", "confidence", "attack_type"):
        assert not hasattr(r, attr)
    assert not hasattr(r, "threat_ids")
    assert not hasattr(r, "owasp")


def test_no_expected_property_inference():
    # expected_security_properties present, but runner must NOT auto-infer
    # that a violation occurred when violated_properties is empty.
    case = _case()
    r = RUNNER.run(case, observed_properties=("secret-read",), violated_properties=())
    assert r.passed is True
    assert r.violated_properties == ()


def test_no_network(monkeypatch):
    import socket as socket_mod
    calls = []
    class Sock:
        def connect(self, *a):
            calls.append(a)
    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    RUNNER.run(_case())
    assert calls == []


def test_no_subprocess(monkeypatch):
    import subprocess as subprocess_mod
    def _fake(*a, **k):
        raise AssertionError("must not run subprocess")
    monkeypatch.setattr(subprocess_mod, "Popen", _fake)
    RUNNER.run(_case())
    assert True


def test_no_filesystem(monkeypatch):
    import os as os_mod
    calls = []
    monkeypatch.setattr(os_mod, "listdir", lambda *a, **k: calls.append(a))
    RUNNER.run(_case())
    assert calls == []


# ---- H. Benchmark agnosticism ----
def test_agentdojo_case():
    case = AgentDojoAdapter().adapt({"case_id": "ad1", "name": "n", "description": "d"})
    r = RUNNER.run(case)
    assert r.benchmark_id == "agentdojo"
    assert r.case_id == "ad1"


def test_agentthreatbench_case():
    case = AgentThreatBenchAdapter().adapt(
        {"case_id": "atb1", "name": "n", "description": "d"})
    r = RUNNER.run(case)
    assert r.benchmark_id == "agentthreatbench"
    assert r.case_id == "atb1"


def test_custom_case():
    r = RUNNER.run(_case(benchmark_id="custom-b", case_id="c-99"))
    assert (r.benchmark_id, r.case_id) == ("custom-b", "c-99")


# ---- I. Public API ----
def test_runner_exported():
    from veyra import threats
    assert hasattr(threats, "ObservationBenchmarkRunner")


def test_existing_exports_preserved():
    from veyra import threats
    for name in ("BenchmarkRunner", "BenchmarkExecutionRequest",
                 "BenchmarkExecutionBoundary", "BenchmarkCase", "BenchmarkEvaluator",
                 "BenchmarkEvaluationResult", "BenchmarkEvaluationAggregator",
                 "CrossBenchmarkEvaluationAggregator", "BenchmarkEvaluationSummary"):
        assert hasattr(threats, name), f"missing {name}"


# ---- J. Determinism / immutability ----
def test_repeated_runs_equal():
    a = serialize_benchmark_evaluation_result(
        RUNNER.run(_case(), observed_properties=("a", "b")))
    b = serialize_benchmark_evaluation_result(
        RUNNER.run(_case(), observed_properties=("a", "b")))
    assert a == b


def test_input_case_unchanged():
    case = _case()
    snap = (case.benchmark_id, case.case_id, case.name, case.description)
    RUNNER.run(case, metadata=(("k", "v"),), observed_properties=("p",))
    assert (case.benchmark_id, case.case_id, case.name, case.description) == snap


def test_observation_inputs_unchanged():
    observed = ("z", "a")
    violated = ("q",)
    meta = (("k1", "v1"),)
    RUNNER.run(_case(), observed_properties=observed, violated_properties=violated,
               metadata=meta)
    assert list(observed) == ["z", "a"]
    assert list(violated) == ["q"]
    assert list(meta) == [("k1", "v1")]
