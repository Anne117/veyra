"""Tests for CrossBenchmarkEvaluationSummary and
CrossBenchmarkEvaluationAggregator (Commit 33).

The cross-benchmark layer combines already-produced BenchmarkEvaluationSummary
objects. It is reporting/aggregation ONLY: no benchmark execution, no
BenchmarkEvaluator / BenchmarkEvaluationAggregator invocation, no Veyra
scanner/graph/path building, no risk scoring, no inference.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkEvaluationAggregator,
    BenchmarkEvaluationResult,
    BenchmarkEvaluationSummary,
    CrossBenchmarkEvaluationAggregator,
    CrossBenchmarkEvaluationSummary,
    ThreatModelError,
    serialize_cross_benchmark_evaluation_summary,
)
from veyra.threats.evaluator import BenchmarkEvaluator


def _summary(benchmark_id="b-1", total=None, passed=None, failed=None,
             error=None, **kw):
    base = dict(
        benchmark_id=benchmark_id,
        total_cases=3 if total is None else total,
        passed_cases=1 if passed is None else passed,
        failed_cases=1 if failed is None else failed,
        error_cases=1 if error is None else error,
    )
    base.update(kw)
    # Enforce the summary invariants: passed+failed+error must equal total_cases,
    # and sum(statuses) must equal total_cases. Reconcile counters against the
    # given total by adjusting `failed` and building a matching statuses tuple.
    t = base["total_cases"]
    p = base["passed_cases"]
    f = base["failed_cases"]
    e = base["error_cases"]
    f = t - p - e
    base["failed_cases"] = f
    statuses = [
        ("passed", p),
        ("failed", f),
        ("error", e),
    ]
    base.setdefault("statuses", tuple(sorted(s for s in statuses if s[1] > 0)))
    return BenchmarkEvaluationSummary(**base)


CROSS = CrossBenchmarkEvaluationAggregator()


# ---- A. Minimal aggregation ----
def test_empty_summaries():
    s = CROSS.aggregate([])
    assert (s.total_benchmarks, s.total_cases, s.passed_cases,
            s.failed_cases, s.error_cases) == (0, 0, 0, 0, 0)
    assert s.benchmarks == ()


def test_one_benchmark():
    s = CROSS.aggregate([_summary(benchmark_id="b1")])
    assert s.total_benchmarks == 1
    assert s.total_cases == 3
    assert s.benchmarks == (("b1", 3),)


def test_multiple_benchmarks():
    s = CROSS.aggregate([_summary(benchmark_id="a"), _summary(benchmark_id="b")])
    assert s.total_benchmarks == 2
    assert s.total_cases == 6
    assert s.benchmarks == (("a", 3), ("b", 3))


def test_mixed_counts():
    s = CROSS.aggregate([
        _summary(benchmark_id="a", total=4, passed=2, failed=1, error=1),
        _summary(benchmark_id="b", total=2, passed=0, failed=2, error=0),
    ])
    assert (s.total_cases, s.passed_cases, s.failed_cases, s.error_cases) == (6, 2, 3, 1)


# ---- B. Counting ----
def test_total_benchmarks():
    s = CROSS.aggregate([_summary(benchmark_id="a"), _summary(benchmark_id="b"),
                         _summary(benchmark_id="c")])
    assert s.total_benchmarks == 3


def test_total_cases_summed():
    s = CROSS.aggregate([_summary(benchmark_id="a", total=5, passed=3, failed=2, error=0),
                         _summary(benchmark_id="b", total=2, passed=1, failed=0, error=1)])
    assert s.total_cases == 7


def test_arithmetic_invariant():
    s = CROSS.aggregate([_summary(benchmark_id="a", total=3, passed=1, failed=1, error=1)])
    assert s.total_cases == s.passed_cases + s.failed_cases + s.error_cases


# ---- C. Benchmark collection ----
def test_benchmark_ids_copied():
    s = CROSS.aggregate([_summary(benchmark_id="zebra"), _summary(benchmark_id="alpha")])
    assert [bid for bid, _ in s.benchmarks] == ["alpha", "zebra"]


def test_benchmark_case_counts_copied():
    s = CROSS.aggregate([
        _summary(benchmark_id="a", total=7, passed=4, failed=3, error=0),
        _summary(benchmark_id="b", total=1, passed=0, failed=0, error=1)])
    assert s.benchmarks == (("a", 7), ("b", 1))


def test_deterministic_lexical_sorting():
    s1 = CROSS.aggregate([_summary(benchmark_id="c"), _summary(benchmark_id="a"),
                          _summary(benchmark_id="b")])
    s2 = CROSS.aggregate([_summary(benchmark_id="a"), _summary(benchmark_id="b"),
                          _summary(benchmark_id="c")])
    assert s1.benchmarks == (("a", 3), ("b", 3), ("c", 3))
    assert s1.benchmarks == s2.benchmarks


def test_unique_benchmark_ids():
    s = CROSS.aggregate([_summary(benchmark_id="x"), _summary(benchmark_id="y")])
    ids = [bid for bid, _ in s.benchmarks]
    assert len(ids) == len(set(ids)) == 2


def test_duplicate_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        CROSS.aggregate([_summary(benchmark_id="x"), _summary(benchmark_id="x")])


def test_duplicate_summaries_not_merged():
    # Two identical summaries must NOT be merged; duplicate id raises.
    s1 = _summary(benchmark_id="dup", total=5)
    s2 = _summary(benchmark_id="dup", total=5)
    with pytest.raises(ThreatModelError):
        CROSS.aggregate([s1, s2])


# ---- D. Validation ----
def test_invalid_summaries_input():
    with pytest.raises(ThreatModelError):
        CROSS.aggregate("not-a-list")


def test_string_rejected():
    with pytest.raises(ThreatModelError):
        CROSS.aggregate("abc")


def test_generator_rejected():
    def gen():
        yield _summary()
    with pytest.raises(ThreatModelError):
        CROSS.aggregate(gen())


def test_invalid_summary_object():
    with pytest.raises(ThreatModelError):
        CROSS.aggregate([None])  # type: ignore[list-item]


def test_mixed_valid_invalid():
    with pytest.raises(ThreatModelError):
        CROSS.aggregate([_summary(), {"not": "summary"}, _summary()])


def test_no_silent_skipping():
    with pytest.raises(ThreatModelError):
        CROSS.aggregate(["junk", _summary()])  # type: ignore[list-item]


# ---- E. Counter validation (constructor) ----
def test_negative_counter_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_benchmarks=-1, total_cases=0)
    with pytest.raises(ThreatModelError):
        _cross_summary(passed_cases=-1, total_cases=-1)


def test_bool_counter_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_cases=True, total_benchmarks=True)  # type: ignore[arg-type]


def test_float_counter_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_cases=1.0)  # type: ignore[arg-type]


def test_arithmetic_invariant_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_cases=3, passed_cases=2, failed_cases=0, error_cases=0)


def test_benchmark_count_invariant_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_benchmarks=1, benchmarks=(("a", 1), ("b", 1)))


def test_benchmark_case_sum_invariant_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_cases=1, benchmarks=(("a", 5),))


# ---- F. Benchmark ID validation ----
def test_empty_id_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(benchmarks=(("", 1),))


def test_whitespace_id_normalized():
    s = _cross_summary(benchmarks=(("  b1  ", 1),))
    assert s.benchmarks == (("b1", 1),)


def test_non_string_id_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(benchmarks=((5, 1),))  # type: ignore[list-item]


def test_duplicate_normalized_ids_rejected():
    with pytest.raises(ThreatModelError):
        _cross_summary(total_benchmarks=2, benchmarks=(("b", 1), (" B ", 1)))


# ---- G. Serialization ----
def test_serialization_structure():
    s = CROSS.aggregate([_summary(benchmark_id="a", total=2, passed=1, failed=1, error=0)])
    d = serialize_cross_benchmark_evaluation_summary(s)
    assert d == {
        "total_benchmarks": 1,
        "total_cases": 2,
        "passed_cases": 1,
        "failed_cases": 1,
        "error_cases": 0,
        "benchmarks": [{"benchmark_id": "a", "case_count": 2}],
    }


def test_serialization_deterministic():
    s = CROSS.aggregate([_summary(benchmark_id="a"), _summary(benchmark_id="b")])
    a = serialize_cross_benchmark_evaluation_summary(s)
    b = serialize_cross_benchmark_evaluation_summary(s)
    assert a == b


def test_serialization_json_safe():
    s = CROSS.aggregate([_summary()])
    d = serialize_cross_benchmark_evaluation_summary(s)
    assert json.loads(json.dumps(d)) == d


def test_serialization_sorted():
    s = CROSS.aggregate([_summary(benchmark_id="z"), _summary(benchmark_id="a")])
    d = serialize_cross_benchmark_evaluation_summary(s)
    assert [e["benchmark_id"] for e in d["benchmarks"]] == ["a", "z"]


def test_no_security_fields():
    s = CROSS.aggregate([_summary()])
    d = serialize_cross_benchmark_evaluation_summary(s)
    for banned in ("risk", "severity", "confidence", "attack_type", "findings",
                   "attack_paths", "scanner", "graph", "owasp", "threat"):
        assert banned not in d


def test_no_extra_toplevel_keys():
    s = CROSS.aggregate([_summary()])
    d = serialize_cross_benchmark_evaluation_summary(s)
    assert set(d.keys()) == {"total_benchmarks", "total_cases", "passed_cases",
                             "failed_cases", "error_cases", "benchmarks"}


# ---- H. Immutability ----
def test_input_summaries_unchanged():
    s1 = _summary(benchmark_id="a", total=2, passed=1, failed=1, error=0)
    s2 = _summary(benchmark_id="b", total=1, passed=1, failed=0, error=0)
    before = [
        (s.benchmark_id, s.total_cases, s.passed_cases, s.failed_cases, s.error_cases)
        for s in (s1, s2)
    ]
    CROSS.aggregate([s1, s2])
    after = [
        (s.benchmark_id, s.total_cases, s.passed_cases, s.failed_cases, s.error_cases)
        for s in (s1, s2)
    ]
    assert before == after


def test_result_summary_frozen():
    s = CROSS.aggregate([_summary()])
    with pytest.raises(AttributeError):
        s.total_cases = 9  # type: ignore[misc]


# ---- I. Architectural isolation ----
def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    s = CROSS.aggregate([_summary()])
    assert not isinstance(s, AttackPath)
    assert not hasattr(s, "nodes")


def test_no_graph_mutation():
    from veyra.graph import SecurityGraph
    g = SecurityGraph()
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    CROSS.aggregate([_summary()])
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


def test_no_benchmark_evaluator_invocation(monkeypatch):
    calls = []

    def _fake_eval(self, *a, **k):
        calls.append(a)
        return _summary()

    monkeypatch.setattr(BenchmarkEvaluator, "evaluate", _fake_eval)
    CROSS.aggregate([_summary()])
    assert calls == []


def test_no_benchmark_aggregator_invocation(monkeypatch):
    calls = []

    def _fake_agg(self, *a, **k):
        calls.append(a)
        return _summary()

    monkeypatch.setattr(BenchmarkEvaluationAggregator, "aggregate", _fake_agg)
    CROSS.aggregate([_summary()])
    assert calls == []


def test_no_network_execution(monkeypatch):
    import socket as socket_mod
    calls = []

    class Sock:
        def connect(self, *a):  # pragma: no cover - must not be called
            calls.append(a)

    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    CROSS.aggregate([_summary()])
    assert calls == []


def test_no_subprocess_execution(monkeypatch):
    import subprocess as subprocess_mod

    def _popen(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("must not run subprocess")

    monkeypatch.setattr(subprocess_mod, "Popen", _popen)
    CROSS.aggregate([_summary()])
    assert True


def test_no_owasp_inference():
    s = CROSS.aggregate([_summary(benchmark_id="a"), _summary(benchmark_id="b")])
    assert s.benchmarks == (("a", 3), ("b", 3))


# ---- J. Benchmark agnosticism ----
def _agentdojo_summary():
    return BenchmarkEvaluationSummary(benchmark_id="agentdojo", total_cases=2,
                                      passed_cases=1, failed_cases=1, error_cases=0,
                                      statuses=(("passed", 1), ("failed", 1)))


def _agentthreatbench_summary():
    return BenchmarkEvaluationSummary(benchmark_id="agentthreatbench", total_cases=1,
                                      passed_cases=0, failed_cases=1, error_cases=0,
                                      statuses=(("failed", 1),))


def _custom_summary():
    return BenchmarkEvaluationSummary(benchmark_id="custom-bench", total_cases=5,
                                      passed_cases=2, failed_cases=2, error_cases=1,
                                      statuses=(("passed", 2), ("failed", 2), ("error", 1)))


def test_benchmark_agnostic():
    s = CROSS.aggregate([_agentdojo_summary(), _agentthreatbench_summary(),
                         _custom_summary()])
    assert s.total_benchmarks == 3
    assert s.total_cases == 8
    assert s.passed_cases == 3
    assert s.failed_cases == 4
    assert s.error_cases == 1
    assert s.benchmarks == (
        ("agentdojo", 2), ("agentthreatbench", 1), ("custom-bench", 5))


def test_public_api_exports():
    from veyra import threats
    for name in ("CrossBenchmarkEvaluationSummary",
                 "CrossBenchmarkEvaluationAggregator",
                 "serialize_cross_benchmark_evaluation_summary"):
        assert hasattr(threats, name), f"missing {name}"


def _cross_summary(**over):
    base = dict(total_benchmarks=1, total_cases=1, passed_cases=1,
                failed_cases=0, error_cases=0)
    base.update(over)
    return CrossBenchmarkEvaluationSummary(**base)
