"""Tests for BenchmarkEvaluationSummary and BenchmarkEvaluationAggregator
(Commit 32).

The aggregation layer combines already-produced BenchmarkEvaluationResult
objects into a deterministic BenchmarkEvaluationSummary. It is aggregation
ONLY: no benchmark execution, no BenchmarkEvaluator invocation, no Veyra
scanner/graph/path building, no risk scoring, no inference.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkEvaluationAggregator,
    BenchmarkEvaluationResult,
    BenchmarkEvaluationSummary,
    ThreatModelError,
    serialize_benchmark_evaluation_summary,
)
from veyra.threats.evaluator import BenchmarkEvaluator


def _result(status="completed", passed=True, benchmark_id="b-1"):
    return BenchmarkEvaluationResult(
        benchmark_id=benchmark_id,
        case_id="c",
        passed=passed,
        status=status,
        message="msg",
    )


AGG = BenchmarkEvaluationAggregator()


# ---- A. Minimal aggregation ----
def test_one_passed():
    s = AGG.aggregate("b-1", [_result(status="completed", passed=True)])
    assert s.total_cases == 1
    assert s.passed_cases == 1
    assert s.failed_cases == 0
    assert s.error_cases == 0


def test_one_failed():
    s = AGG.aggregate("b-1", [_result(status="completed", passed=False)])
    assert s.total_cases == 1
    assert s.passed_cases == 0
    assert s.failed_cases == 1
    assert s.error_cases == 0


def test_one_error():
    s = AGG.aggregate("b-1", [_result(status="error", passed=False)])
    assert s.total_cases == 1
    assert s.passed_cases == 0
    assert s.failed_cases == 0
    assert s.error_cases == 1


def test_mixed():
    s = AGG.aggregate("b-1", [
        _result(status="completed", passed=True),
        _result(status="completed", passed=False),
        _result(status="error", passed=False),
        _result(status="failed", passed=False),
    ])
    # per rules: completed/True=passed, completed/False=failed,
    # error/False=error, failed/False=failed (status!="error")
    assert (s.total_cases, s.passed_cases, s.failed_cases, s.error_cases) == (4, 1, 2, 1)


def test_empty_results():
    s = AGG.aggregate("b-1", [])
    assert (s.total_cases, s.passed_cases, s.failed_cases, s.error_cases) == (0, 0, 0, 0)
    assert s.statuses == ()


# ---- B. Counting ----
def test_arithmetic_invariant():
    s = AGG.aggregate("b-1", [
        _result(status="completed", passed=True),
        _result(status="completed", passed=False),
        _result(status="error", passed=False),
    ])
    assert s.total_cases == s.passed_cases + s.failed_cases + s.error_cases


def test_count_error_regardless_of_passed():
    # A result with status="error" counts toward error_cases even if passed=True.
    s = AGG.aggregate("b-1", [_result(status="error", passed=True)])
    assert s.error_cases == 1
    assert s.passed_cases == 0


# ---- C. Status frequency ----
def test_status_single():
    s = AGG.aggregate("b-1", [_result(status="completed")])
    assert s.statuses == (("completed", 1),)


def test_status_repeated():
    s = AGG.aggregate("b-1", [
        _result(status="completed"), _result(status="completed"),
    ])
    assert s.statuses == (("completed", 2),)


def test_status_multiple_lexical():
    s = AGG.aggregate("b-1", [
        _result(status="completed"),
        _result(status="error"),
        _result(status="failed"),
        _result(status="completed"),
    ])
    assert s.statuses == (("completed", 2), ("error", 1), ("failed", 1))


def test_status_lexical_ordering():
    s = AGG.aggregate("b-1", [
        _result(status="zeta"), _result(status="alpha"), _result(status="alpha"),
    ])
    assert s.statuses == (("alpha", 2), ("zeta", 1))


def test_status_duplicate_merge():
    s = AGG.aggregate("b-1", [_result(status="ok"), _result(status="ok"), _result(status="ok")])
    assert s.statuses == (("ok", 3),)


# ---- D. Benchmark identity ----
def test_benchmark_id_copied():
    s = AGG.aggregate("mybench", [_result(benchmark_id="mybench")])
    assert s.benchmark_id == "mybench"


def test_benchmark_id_mismatch_rejected():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", [_result(benchmark_id="b-2")])


def test_empty_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("", [_result()])


def test_invalid_benchmark_id_type():
    with pytest.raises(ThreatModelError):
        AGG.aggregate(7, [_result()])


# ---- E. Result validation ----
def test_invalid_result_scalar():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", "not-a-list")


def test_invalid_result_object():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", [None])  # type: ignore[list-item]


def test_mixed_valid_invalid():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", [_result(), {"not": "result"}, _result()])


def test_no_silent_skipping():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", [{"evil": 1}, _result()])


# ---- F. Counter (summary constructor) validation ----
def test_negative_total():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=-1,
                                   passed_cases=0, failed_cases=0, error_cases=0)


def test_negative_passed():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=1, passed_cases=-1,
                                   failed_cases=1, error_cases=0)


def test_negative_failed():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=1, passed_cases=1,
                                   failed_cases=-1, error_cases=0)


def test_negative_error():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=1, passed_cases=1,
                                   failed_cases=0, error_cases=-1)


def test_bool_rejected_as_integer():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=True,
                                   passed_cases=1, failed_cases=0, error_cases=0)


def test_float_rejected_as_integer():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=1.0,
                                   passed_cases=1, failed_cases=0, error_cases=0)


def test_arithmetic_invariant_rejection():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=3,
                                   passed_cases=1, failed_cases=1, error_cases=0,
                                   statuses=(("completed", 2),))


# ---- G. Status (summary constructor) validation ----
def test_invalid_status_type():
    with pytest.raises(ThreatModelError):
        _status_summary(statuses=((5, 1),))  # type: ignore[list-item]


def test_ws_status_trimmed():
    s = _status_summary(statuses=((" done ", 1),))
    assert s.statuses == (("done", 1),)


def test_blank_status_dropped():
    # A blank/whitespace-only status must be REJECTED (a count must never be
    # silently discarded).
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b",
                                   passed_cases=0, failed_cases=0, error_cases=0,
                                   total_cases=0, statuses=(("   ", 1),))


def test_empty_status_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=0,
                                   passed_cases=0, failed_cases=0, error_cases=0,
                                   statuses=(("", 1),))


def test_whitespace_status_nonzero_count_not_discarded():
    # A non-zero count under a blank status must NOT be silently dropped; it
    # must raise instead.
    with pytest.raises(ThreatModelError):
        BenchmarkEvaluationSummary(benchmark_id="b", total_cases=5,
                                   passed_cases=0, failed_cases=0, error_cases=0,
                                   statuses=(("   ", 5),))


def test_invalid_count_type():
    with pytest.raises(ThreatModelError):
        _status_summary(statuses=(("ok", "5"),))  # type: ignore[list-item]


def test_negative_count():
    with pytest.raises(ThreatModelError):
        _status_summary(statuses=(("ok", -1),))


def test_bool_count_rejected():
    with pytest.raises(ThreatModelError):
        _status_summary(statuses=(("ok", True),))  # type: ignore[list-item]


def test_statuses_not_a_sequence():
    with pytest.raises(ThreatModelError):
        _status_summary(statuses="not-a-seq")


# ---- H. Serialization ----
def test_serialization_structure():
    s = AGG.aggregate("b-1", [
        _result(status="completed", passed=True),
        _result(status="error", passed=False),
    ])
    d = serialize_benchmark_evaluation_summary(s)
    assert d == {
        "benchmark_id": "b-1",
        "total_cases": 2,
        "passed_cases": 1,
        "failed_cases": 0,
        "error_cases": 1,
        "statuses": [
            {"status": "completed", "count": 1},
            {"status": "error", "count": 1},
        ],
    }


def test_serialization_deterministic():
    s = AGG.aggregate("b-1", [_result(status="x"), _result(status="y")])
    assert (serialize_benchmark_evaluation_summary(s)
            == serialize_benchmark_evaluation_summary(s))


def test_serialization_json_safe():
    s = AGG.aggregate("b-1", [_result()])
    assert json.loads(json.dumps(serialize_benchmark_evaluation_summary(s))) \
        == serialize_benchmark_evaluation_summary(s)


def test_no_security_fields():
    s = AGG.aggregate("b-1", [_result()])
    d = serialize_benchmark_evaluation_summary(s)
    for banned in ("risk", "severity", "confidence", "attack_type", "findings",
                   "attack_paths", "graph", "scanner"):
        assert banned not in d


# ---- I. Immutability ----
def test_input_results_unchanged():
    results = [_result(status="completed", passed=True)]
    before = tuple((r.benchmark_id, r.case_id, r.passed, r.status, r.message)
                   for r in results)
    AGG.aggregate("b-1", results)
    after = tuple((r.benchmark_id, r.case_id, r.passed, r.status, r.message)
                  for r in results)
    assert before == after


def test_summary_frozen():
    s = AGG.aggregate("b-1", [_result()])
    with pytest.raises(AttributeError):
        s.total_cases = 5  # type: ignore[misc]


# ---- J. Architectural isolation ----
def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    s = AGG.aggregate("b-1", [_result()])
    assert not isinstance(s, AttackPath)
    assert not hasattr(s, "nodes")


def test_no_graph_mutation():
    from veyra.graph import SecurityGraph
    g = SecurityGraph()
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    AGG.aggregate("b-1", [_result()])
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


def test_aggregator_does_not_invoke_evaluator(monkeypatch):
    calls = []

    def _fake_eval(self, *a, **k):
        calls.append(a)
        return _result()

    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _fake_eval)
    AGG.aggregate("b-1", [_result()])
    assert calls == []


def test_no_network_execution(monkeypatch):
    import socket as socket_mod
    calls = []

    class Sock:
        def connect(self, *a):  # pragma: no cover - must not be called
            calls.append(a)

    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    AGG.aggregate("b-1", [_result()])
    assert calls == []


def test_no_subprocess_execution(monkeypatch):
    import subprocess as subprocess_mod

    def _popen(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("must not run subprocess")

    monkeypatch.setattr(subprocess_mod, "Popen", _popen)
    AGG.aggregate("b-1", [_result()])
    assert True


def test_no_owasp_inference():
    # Aggregation ignores any threat/OWASP info; only result.passed/status used.
    low = AGG.aggregate("b-1", [_result(status="completed", passed=True)])
    assert low.statuses == (("completed", 1),)


# ---- K. Benchmark agnosticism ----
def _agentdojo_result(benchmark_id="agentdojo"):
    return BenchmarkEvaluationResult(
        benchmark_id=benchmark_id, case_id="ad", passed=True, status="completed", message="m")


def _agentthreatbench_result(benchmark_id="agentthreatbench"):
    return BenchmarkEvaluationResult(
        benchmark_id=benchmark_id, case_id="atb", passed=False, status="completed", message="m")


def test_agentdojo_and_atb_treated_identically():
    sa = AGG.aggregate("agentdojo", [_agentdojo_result()])
    st = AGG.aggregate("agentthreatbench", [_agentthreatbench_result()])
    # Both follow the same rule based only on result fields.
    assert sa.passed_cases == 1
    assert st.failed_cases == 1
    assert sa.statuses == st.statuses == (("completed", 1),)


def test_public_api_exports():
    from veyra import threats
    for name in ("BenchmarkEvaluationSummary", "BenchmarkEvaluationAggregator",
                 "serialize_benchmark_evaluation_summary"):
        assert hasattr(threats, name), f"missing {name}"


def _status_summary(**over):
    base = dict(benchmark_id="b", total_cases=1, passed_cases=1,
                failed_cases=0, error_cases=0)
    base.update(over)
    return BenchmarkEvaluationSummary(**base)


# ---- corrective fixes (Commit 32.1) ----
def test_sequence_contract_custom_sequence():
    # A non-list/non-tuple Sequence is accepted (Sequence contract).
    class MySeq(list):
        pass

    results = MySeq([_result(status="completed", passed=True)])
    s = AGG.aggregate("b-1", results)
    assert s.total_cases == 1
    assert s.passed_cases == 1


def test_sequence_contract_numpy_like_rejected():
    # A bare iterable (not a Sequence) must be rejected.
    def gen():
        yield _result()
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", gen())


def test_sequence_contract_scalar_string_rejected():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("b-1", "not-a-sequence")


def test_benchmark_id_whitespace_normalized():
    # " b-1 " normalizes to "b-1"; result with "b-1" matches.
    s = AGG.aggregate(" b-1 ", [_result(status="completed", passed=True)])
    assert s.benchmark_id == "b-1"


def test_benchmark_id_normalized_result_accepted():
    s = AGG.aggregate("  b-1  ", [_result(status="completed", passed=True)])
    assert s.statuses == (("completed", 1),)


def test_benchmark_id_empty_rejected():
    with pytest.raises(ThreatModelError):
        AGG.aggregate("   ", [_result()])


def test_benchmark_id_non_string_rejected():
    with pytest.raises(ThreatModelError):
        AGG.aggregate(12345, [_result(benchmark_id="12345")])
    with pytest.raises(ThreatModelError):
        AGG.aggregate(None, [_result()])  # type: ignore[arg-type]
