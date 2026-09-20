"""Benchmark evaluation aggregation foundation (Commit 32).

A small, deterministic, benchmark-agnostic aggregation layer that combines
already-produced :class:`BenchmarkEvaluationResult` objects into a
:class:`BenchmarkEvaluationSummary`.

Aggregation ONLY. It must NOT execute benchmarks, invoke
:class:`BenchmarkEvaluator`, run Veyra scans, construct SecurityGraphs or
AttackPaths, calculate Veyra risk, infer threats, resolve OWASP categories,
inspect scenario descriptions, or access network/filesystem resources.

``"error"`` is the explicit aggregation convention for the ``error_cases``
counter only; all other status strings remain opaque at this layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Sequence, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.evaluation import BenchmarkEvaluationResult
from veyra.threats.scenarios import _require_str


def _require_count(value: Any, what: str) -> int:
    """Require a non-negative integer, rejecting booleans."""
    if isinstance(value, bool):
        raise ThreatModelError(f"{what} must be an integer, got bool")
    if not isinstance(value, int):
        raise ThreatModelError(
            f"{what} must be an integer, got {type(value).__name__}"
        )
    if value < 0:
        raise ThreatModelError(f"{what} must be >= 0, got {value}")
    return value


def _require_status_pair(value: Any) -> Tuple[str, int] | None:
    """Validate one (status, count) pair; returns None if the status is blank
    after trimming (so blank entries can be dropped, consistent with the threat
    model's tuple normalization).
    """
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ThreatModelError(
            f"status entry must be a (status, count) pair, got {type(value).__name__}"
        )
    status, count = value
    if not isinstance(status, str):
        raise ThreatModelError(
            f"status must be a string, got {type(status).__name__}"
        )
    status = status.strip()
    if not status:
        return None
    count = _require_count(count, "status count")
    return (status, count)


def _normalize_statuses(values: Any) -> Tuple[Tuple[str, int], ...]:
    """Normalize a statuses sequence deterministically.

    Each entry is a (status, count) pair; status strings are trimmed, blank
    entries dropped, duplicate identical statuses merged by summing counts, then
    sorted lexicographically by status string.
    """
    if values is None:
        return ()
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ThreatModelError(
            f"statuses must be a sequence of (status, count) pairs, "
            f"got {type(values).__name__}"
        )
    merged: dict[str, int] = {}
    for item in values:
        pair = _require_status_pair(item)
        if pair is not None:
            status, count = pair
            merged[status] = merged.get(status, 0) + count
    return tuple(sorted(merged.items()))


@dataclass(frozen=True)
class BenchmarkEvaluationSummary:
    """Deterministic aggregate counts over already-produced evaluation results.

    ``statuses`` is a normalized, deduplicated, lexicographically-sorted tuple of
    ``(status, count)`` pairs. ``"passed"``/``"failed"``/``"error"`` remain
    opaque strings here; only ``"error"`` is special-cased by the aggregator's
    ``error_cases`` counter.
    """

    benchmark_id: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    error_cases: int
    statuses: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "benchmark_id", _require_str(self.benchmark_id, "benchmark id"))
        total = _require_count(self.total_cases, "total_cases")
        passed = _require_count(self.passed_cases, "passed_cases")
        failed = _require_count(self.failed_cases, "failed_cases")
        error = _require_count(self.error_cases, "error_cases")
        object.__setattr__(self, "total_cases", total)
        object.__setattr__(self, "passed_cases", passed)
        object.__setattr__(self, "failed_cases", failed)
        object.__setattr__(self, "error_cases", error)
        statuses = _normalize_statuses(self.statuses)
        object.__setattr__(self, "statuses", statuses)

        if total != passed + failed + error:
            raise ThreatModelError(
                "total_cases must equal passed_cases + failed_cases + error_cases"
            )
        status_sum = sum(count for _, count in statuses)
        if status_sum != total:
            raise ThreatModelError(
                f"sum of status counts ({status_sum}) must equal total_cases ({total})"
            )


def serialize_benchmark_evaluation_summary(
    summary: BenchmarkEvaluationSummary,
) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one summary.

    No timestamps, random IDs, runtime metadata, risk fields, severity,
    confidence, AttackPath, SecurityGraph, findings, scanner fields, or
    benchmark-specific metrics.
    """
    return {
        "benchmark_id": summary.benchmark_id,
        "total_cases": summary.total_cases,
        "passed_cases": summary.passed_cases,
        "failed_cases": summary.failed_cases,
        "error_cases": summary.error_cases,
        "statuses": [
            {"status": status, "count": count}
            for status, count in summary.statuses
        ],
    }


class BenchmarkEvaluationAggregator:
    """Combines already-produced BenchmarkEvaluationResult objects into a
    deterministic BenchmarkEvaluationSummary.

    ``"error"`` is the explicit aggregation convention for the ``error_cases``
    counter; the aggregator interprets no other status value.
    """

    def aggregate(
        self,
        benchmark_id: str,
        results: Sequence[BenchmarkEvaluationResult],
    ) -> BenchmarkEvaluationSummary:
        if not isinstance(results, (list, tuple)):
            raise ThreatModelError(
                f"results must be a sequence, got {type(results).__name__}"
            )

        total = 0
        passed = 0
        failed = 0
        error = 0
        status_counts: dict[str, int] = {}

        for result in results:
            if not isinstance(result, BenchmarkEvaluationResult):
                raise ThreatModelError(
                    f"result must be a BenchmarkEvaluationResult, "
                    f"got {type(result).__name__}"
                )
            if result.benchmark_id != benchmark_id:
                raise ThreatModelError(
                    f"result benchmark_id {result.benchmark_id!r} does not match "
                    f"expected {benchmark_id!r}"
                )
            total += 1
            status = result.status
            status_counts[status] = status_counts.get(status, 0) + 1
            if status == "error":
                error += 1
            elif result.passed:
                passed += 1
            else:
                failed += 1

        return BenchmarkEvaluationSummary(
            benchmark_id=benchmark_id,
            total_cases=total,
            passed_cases=passed,
            failed_cases=failed,
            error_cases=error,
            statuses=tuple(status_counts.items()),
        )
