"""Cross-benchmark evaluation summary foundation (Commit 33).

A small deterministic layer that combines already-produced
:class:`BenchmarkEvaluationSummary` objects from multiple benchmarks into one
cross-benchmark summary.

REPORTING/AGGREGATION ONLY. It must NOT execute benchmarks, invoke
:class:`BenchmarkEvaluator` or :class:`BenchmarkEvaluationAggregator`, run Veyra
scans, build SecurityGraphs/AttackPaths, calculate Veyra risk, infer threats,
resolve OWASP categories, inspect scenario descriptions, or access
network/filesystem resources. It consumes only already-computed summary
counters and benchmark identity.
"""

from __future__ import annotations

from collections.abc import Sequence as ABCSequence
from dataclasses import dataclass
from typing import Any, Dict, Sequence, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.aggregation import (
    BenchmarkEvaluationSummary,
    _require_count,
)
from veyra.threats.scenarios import _require_str


def _require_bench_pair(value: Any) -> Tuple[str, int]:
    """Validate one (benchmark_id, case_count) pair.

    benchmark_id is normalized via ``_require_str``; case_count must be a
    non-negative integer.
    """
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ThreatModelError(
            f"benchmark entry must be a (benchmark_id, case_count) pair, "
            f"got {type(value).__name__}"
        )
    benchmark_id, case_count = value
    benchmark_id = _require_str(benchmark_id, "benchmark id")
    case_count = _require_count(case_count, "benchmark case count")
    return (benchmark_id, case_count)


def _normalize_benchmarks(values: Any) -> Tuple[Tuple[str, int], ...]:
    """Normalize a benchmarks sequence deterministically.

    Each entry is a (benchmark_id, case_count) pair; IDs are normalized via
    ``_require_str``, must be unique, and entries are sorted lexicographically
    by benchmark_id.
    """
    if values is None:
        return ()
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ThreatModelError(
            f"benchmarks must be a sequence of (benchmark_id, case_count) pairs, "
            f"got {type(values).__name__}"
        )
    seen: dict[str, int] = {}
    cleaned: dict[str, int] = {}
    for item in values:
        benchmark_id, case_count = _require_bench_pair(item)
        if benchmark_id in seen:
            raise ThreatModelError(f"duplicate benchmark id: {benchmark_id!r}")
        seen[benchmark_id] = case_count
        cleaned[benchmark_id] = case_count
    return tuple(sorted(cleaned.items()))


@dataclass(frozen=True)
class CrossBenchmarkEvaluationSummary:
    """Deterministic aggregate case counts across distinct benchmarks.

    ``benchmarks`` is a normalized, unique, lexicographically-sorted tuple of
    ``(benchmark_id, case_count)`` pairs, each representing one benchmark's
    total case count.
    """

    total_benchmarks: int
    total_cases: int
    passed_cases: int
    failed_cases: int
    error_cases: int
    benchmarks: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self):
        total_benchmarks = _require_count(self.total_benchmarks, "total_benchmarks")
        total_cases = _require_count(self.total_cases, "total_cases")
        passed = _require_count(self.passed_cases, "passed_cases")
        failed = _require_count(self.failed_cases, "failed_cases")
        error = _require_count(self.error_cases, "error_cases")
        object.__setattr__(self, "total_benchmarks", total_benchmarks)
        object.__setattr__(self, "total_cases", total_cases)
        object.__setattr__(self, "passed_cases", passed)
        object.__setattr__(self, "failed_cases", failed)
        object.__setattr__(self, "error_cases", error)
        benchmarks = _normalize_benchmarks(self.benchmarks)
        object.__setattr__(self, "benchmarks", benchmarks)

        if total_cases != passed + failed + error:
            raise ThreatModelError(
                "total_cases must equal passed_cases + failed_cases + error_cases"
            )
        if total_benchmarks != len(benchmarks):
            raise ThreatModelError(
                f"total_benchmarks ({total_benchmarks}) must equal the number of "
                f"benchmark entries ({len(benchmarks)})"
            )
        benchmarks_sum = sum(count for _, count in benchmarks)
        if benchmarks_sum != total_cases:
            raise ThreatModelError(
                f"sum of benchmark case counts ({benchmarks_sum}) must equal "
                f"total_cases ({total_cases})"
            )


def serialize_cross_benchmark_evaluation_summary(
    summary: CrossBenchmarkEvaluationSummary,
) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one cross-benchmark summary.

    No timestamps, random IDs, metadata, or security/risk fields.
    """
    return {
        "total_benchmarks": summary.total_benchmarks,
        "total_cases": summary.total_cases,
        "passed_cases": summary.passed_cases,
        "failed_cases": summary.failed_cases,
        "error_cases": summary.error_cases,
        "benchmarks": [
            {"benchmark_id": benchmark_id, "case_count": case_count}
            for benchmark_id, case_count in summary.benchmarks
        ],
    }


class CrossBenchmarkEvaluationAggregator:
    """Combines already-produced BenchmarkEvaluationSummary objects.

    Each summary contributes exactly one benchmark. Duplicate benchmark IDs are
    rejected rather than merged.
    """

    def aggregate(
        self,
        summaries: Sequence[BenchmarkEvaluationSummary],
    ) -> CrossBenchmarkEvaluationSummary:
        if isinstance(summaries, str) or not isinstance(summaries, ABCSequence):
            raise ThreatModelError(
                f"summaries must be a sequence of BenchmarkEvaluationSummary, "
                f"got {type(summaries).__name__}"
            )

        total_benchmarks = 0
        total_cases = 0
        passed = 0
        failed = 0
        error = 0
        benchmarks: dict[str, int] = {}

        for summary in summaries:
            if not isinstance(summary, BenchmarkEvaluationSummary):
                raise ThreatModelError(
                    f"summary must be a BenchmarkEvaluationSummary, "
                    f"got {type(summary).__name__}"
                )
            benchmark_id = summary.benchmark_id
            if benchmark_id in benchmarks:
                raise ThreatModelError(
                    f"duplicate benchmark id: {benchmark_id!r}"
                )
            benchmarks[benchmark_id] = summary.total_cases
            total_benchmarks += 1
            total_cases += summary.total_cases
            passed += summary.passed_cases
            failed += summary.failed_cases
            error += summary.error_cases

        return CrossBenchmarkEvaluationSummary(
            total_benchmarks=total_benchmarks,
            total_cases=total_cases,
            passed_cases=passed,
            failed_cases=failed,
            error_cases=error,
            benchmarks=tuple(benchmarks.items()),
        )
