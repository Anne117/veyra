"""Tests for the benchmark execution boundary / runner foundation (Commit 34).

This layer defines the typed seam between BenchmarkCase and
BenchmarkEvaluationResult WITHOUT executing anything. BenchmarkRunner is a
protocol only; BenchmarkExecutionBoundary creates only a
BenchmarkExecutionRequest. No network, subprocess, dataset, scanner, graph, or
benchmark execution.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkCase,
    BenchmarkEvaluationAggregator,
    BenchmarkEvaluationResult,
    BenchmarkEvaluationSummary,
    BenchmarkEvaluator,
    BenchmarkExecutionBoundary,
    BenchmarkExecutionRequest,
    BenchmarkRunner,
    CrossBenchmarkEvaluationAggregator,
    ThreatModelError,
    SecurityScenario,
    SecurityScenarioThreatMapping,
    serialize_benchmark_execution_request,
)
from veyra.threats.adapters import AgentDojoAdapter, AgentThreatBenchAdapter


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


BOUNDARY = BenchmarkExecutionBoundary()


# ---- A. BenchmarkExecutionRequest ----
def test_valid_construction():
    r = BenchmarkExecutionRequest(benchmark_id="b", case_id="c")
    assert r.benchmark_id == "b"
    assert r.case_id == "c"


def test_whitespace_normalization():
    r = BenchmarkExecutionRequest(benchmark_id="  b  ", case_id=" c ")
    assert r.benchmark_id == "b"
    assert r.case_id == "c"


def test_empty_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id="", case_id="c")


def test_whitespace_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id="   ", case_id="c")


def test_empty_case_id_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id="b", case_id="")


def test_whitespace_case_id_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id="b", case_id="   ")


def test_non_string_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id=123, case_id="c")


def test_non_string_case_id_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id="b", case_id=None)  # type: ignore[arg-type]


def test_bool_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionRequest(benchmark_id=True, case_id="c")  # type: ignore[arg-type]


def test_frozen():
    r = BenchmarkExecutionRequest(benchmark_id="b", case_id="c")
    with pytest.raises(AttributeError):
        r.case_id = "x"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        r.benchmark_id = "x"  # type: ignore[misc]


def test_deterministic_serialization():
    r = BenchmarkExecutionRequest(benchmark_id="b", case_id="c")
    a = serialize_benchmark_execution_request(r)
    b = serialize_benchmark_execution_request(r)
    assert a == b


def test_exact_serialization_keys():
    r = BenchmarkExecutionRequest(benchmark_id="b", case_id="c")
    d = serialize_benchmark_execution_request(r)
    assert list(d.keys()) == ["benchmark_id", "case_id"]


def test_json_safe_serialization():
    r = BenchmarkExecutionRequest(benchmark_id="b", case_id="c")
    d = serialize_benchmark_execution_request(r)
    assert json.loads(json.dumps(d)) == d
    assert d == {"benchmark_id": "b", "case_id": "c"}


# ---- B. BenchmarkExecutionBoundary ----
def test_boundary_valid_case():
    r = BOUNDARY.create_request(_case())
    assert isinstance(r, BenchmarkExecutionRequest)


def test_boundary_benchmark_id_copied():
    assert BOUNDARY.create_request(_case(benchmark_id="zzz")).benchmark_id == "zzz"


def test_boundary_case_id_copied():
    assert BOUNDARY.create_request(_case(case_id="42")).case_id == "42"


def test_boundary_invalid_object_rejected():
    with pytest.raises(ThreatModelError):
        BOUNDARY.create_request("not-a-case")


def test_boundary_none_rejected():
    with pytest.raises(ThreatModelError):
        BOUNDARY.create_request(None)  # type: ignore[arg-type]


def test_boundary_dict_rejected():
    with pytest.raises(ThreatModelError):
        BOUNDARY.create_request({"benchmark_id": "b", "case_id": "c"})


def test_boundary_string_rejected():
    with pytest.raises(ThreatModelError):
        BOUNDARY.create_request("abc")


def test_boundary_no_case_mutation():
    case = _case()
    snap = (case.benchmark_id, case.case_id, case.name, case.description,
            case.scenario.scenario_id, case.threat_mapping.scenario_id)
    BOUNDARY.create_request(case)
    assert (case.benchmark_id, case.case_id, case.name, case.description,
            case.scenario.scenario_id, case.threat_mapping.scenario_id) == snap


def test_boundary_repeated_deterministic():
    a = BOUNDARY.create_request(_case())
    b = BOUNDARY.create_request(_case())
    assert a == b
    assert serialize_benchmark_execution_request(a) == \
        serialize_benchmark_execution_request(b)


# ---- C. BenchmarkRunner protocol ----
def test_protocol_runtime_checkable():
    class Dummy:
        benchmark_id = "dummy"
        def run(self, case):
            return BenchmarkEvaluationResult(
                benchmark_id="dummy", case_id=case.case_id, passed=True,
                status="completed", message="ok")

    assert isinstance(Dummy(), BenchmarkRunner)


def test_fake_runner_returns_evaluation_result():
    class Dummy:
        benchmark_id = "dummy"
        def run(self, case):
            return BenchmarkEvaluationResult(
                benchmark_id="dummy", case_id=case.case_id, passed=True,
                status="completed", message="ok")

    r = Dummy().run(_case())
    assert isinstance(r, BenchmarkEvaluationResult)
    assert r.passed is True


def test_protocol_benchmark_agnostic():
    # benchmark_id is a class-level annotation; `run` is a method.
    assert "benchmark_id" in BenchmarkRunner.__annotations__
    assert hasattr(BenchmarkRunner, "run")
    assert callable(BenchmarkRunner.run)


def test_no_default_execution_implementation():
    # BenchmarkRunner has no concrete execution body.
    src = BenchmarkRunner.run.__doc__ or ""
    assert "Never invoked" in src or "concrete runner supplies" in src
    # The protocol itself carries a class-level benchmark_id annotation only.
    assert set(BenchmarkRunner.__annotations__.keys()) == {"benchmark_id"}


# ---- D. Architectural isolation ----
def test_boundary_does_not_reference_evaluator_or_aggregators():
    # The execution module defines only the request/boundary/protocol. It does
    # not import or instantiate BenchmarkEvaluator / aggregators.
    import veyra.threats as threats_root
    import veyra.threats.execution as exc
    # No evaluation/aggregation components leaked into the execution module.
    for name in ("BenchmarkEvaluator", "BenchmarkEvaluationAggregator",
                 "CrossBenchmarkEvaluationAggregator"):
        assert not hasattr(exc, name), f"execution module should not define {name}"
    # Boundary returns only a request, never any of those components.
    r = BOUNDARY.create_request(_case())
    assert not isinstance(r, threats_root.BenchmarkEvaluationAggregator)
    assert not isinstance(r, threats_root.CrossBenchmarkEvaluationAggregator)
    assert not hasattr(r, "benchmarks")


def test_no_security_graph_created():
    from veyra.graph import SecurityGraph
    # The boundary does not import/create a SecurityGraph.
    g = SecurityGraph()
    assert len(g.nodes) == 0
    r = BOUNDARY.create_request(_case())
    # The request carries no graph reference.
    assert not hasattr(r, "nodes")
    assert not hasattr(r, "edges")
    assert not isinstance(r, SecurityGraph)


def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    r = BOUNDARY.create_request(_case())
    assert not isinstance(r, AttackPath)
    assert not hasattr(r, "nodes")


def test_no_scanner_invocation(monkeypatch):
    import veyra.scanner as scanner_mod
    calls = []
    def _fake(*a, **k):
        calls.append(a)
    monkeypatch.setattr(scanner_mod, "scan_path", _fake)
    r = BOUNDARY.create_request(_case())
    assert calls == []


def test_no_network_calls(monkeypatch):
    import socket as socket_mod
    calls = []
    class Sock:
        def connect(self, *a):
            calls.append(a)
    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    BOUNDARY.create_request(_case())
    assert calls == []


def test_no_subprocess(monkeypatch):
    import subprocess as subprocess_mod
    def _fake(*a, **k):
        raise AssertionError("must not run subprocess")
    monkeypatch.setattr(subprocess_mod, "Popen", _fake)
    BOUNDARY.create_request(_case())
    assert True


def test_no_filesystem_discovery(monkeypatch):
    import os as os_mod
    calls = []

    def _fake_listdir(*a, **k):
        calls.append(a)
    monkeypatch.setattr(os_mod, "listdir", _fake_listdir)
    r = BOUNDARY.create_request(_case())
    assert calls == []


def test_no_inference():
    case = _case(benchmark_id="custom", case_id="c")
    r = BOUNDARY.create_request(case)
    assert r.benchmark_id == "custom"
    assert r.case_id == "c"


# ---- E. API ----
def test_public_exports():
    from veyra import threats
    for name in ("BenchmarkRunner", "BenchmarkExecutionRequest",
                 "BenchmarkExecutionBoundary", "serialize_benchmark_execution_request"):
        assert hasattr(threats, name), f"missing {name}"


def test_previous_exports_remain():
    from veyra import threats
    for name in ("BenchmarkCase", "BenchmarkAdapter", "BenchmarkEvaluationResult",
                 "BenchmarkEvaluator", "BenchmarkEvaluationSummary",
                 "BenchmarkEvaluationAggregator", "CrossBenchmarkEvaluationSummary",
                 "CrossBenchmarkEvaluationAggregator", "SecurityScenario",
                 "SecurityScenarioThreatMapping", "ThreatScenario", "ThreatTaxonomy"):
        assert hasattr(threats, name), f"missing {name}"


# ---- F. Benchmark agnosticism ----
def test_agnostic_agentdojo():
    case = AgentDojoAdapter().adapt({"case_id": "ad1", "name": "n", "description": "d"})
    r = BOUNDARY.create_request(case)
    assert r.benchmark_id == "agentdojo"
    assert r.case_id == "ad1"


def test_agnostic_agentthreatbench():
    case = AgentThreatBenchAdapter().adapt(
        {"case_id": "atb1", "name": "n", "description": "d"})
    r = BOUNDARY.create_request(case)
    assert r.benchmark_id == "agentthreatbench"
    assert r.case_id == "atb1"


def test_agnostic_custom():
    r = BOUNDARY.create_request(_case(benchmark_id="my-custom-bench", case_id="case-9"))
    assert r.benchmark_id == "my-custom-bench"
    assert r.case_id == "case-9"
