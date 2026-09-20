"""Benchmark execution boundary / runner foundation (Commit 34).

Defines the typed architectural seam between a :class:`BenchmarkCase` and a
:class:`BenchmarkEvaluationResult`, WITHOUT implementing any actual benchmark
execution.

- ``BenchmarkRunner`` is a prototype-only runnable interface (a
  ``@runtime_checkable`` Protocol) that future concrete execution adapters will
  satisfy.
- ``BenchmarkExecutionRequest`` is a frozen, deterministic data contract
  describing which benchmark/case would be executed.
- ``BenchmarkExecutionBoundary`` currently only derives such a request from a
  :class:`BenchmarkCase`.

This commit does NOT execute AgentDojo, AgentThreatBench, external datasets,
network calls, subprocesses, LLMs, Veyra scans, or benchmark environments.
It adds no runner discovery, registry, plugin loading, filesystem discovery, or
benchmark-specific branching.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol, final, runtime_checkable

from veyra.threats._error import ThreatModelError
from veyra.threats.benchmarks import BenchmarkCase
from veyra.threats.evaluation import BenchmarkEvaluationResult
from veyra.threats.scenarios import _require_str


@runtime_checkable
class BenchmarkRunner(Protocol):
    """Future execution interface: BenchmarkCase -> BenchmarkEvaluationResult.

    This is a benchmark-agnostic protocol only. It provides NO default execution
    implementation; concrete benchmark runners will be added in later commits.
    The existing adapters remain data adapters, and BenchmarkEvaluationResult
    remains the canonical evaluation result.
    """

    benchmark_id: str

    def run(self, case: BenchmarkCase) -> BenchmarkEvaluationResult:
        """Execute one benchmark case and return the evaluation result.

        Never invoked by this layer; a concrete runner supplies the execution.
        """
        ...


@dataclass(frozen=True)
class BenchmarkExecutionRequest:
    """A frozen, deterministic description of a benchmark execution.

    Both fields are non-empty strings normalized consistently with the existing
    threat-model conventions (surrounding whitespace stripped).
    """

    benchmark_id: str
    case_id: str

    def __post_init__(self):
        object.__setattr__(self, "benchmark_id", _require_str(self.benchmark_id, "benchmark id"))
        object.__setattr__(self, "case_id", _require_str(self.case_id, "case id"))


def serialize_benchmark_execution_request(request: BenchmarkExecutionRequest) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one execution request."""
    return {
        "benchmark_id": request.benchmark_id,
        "case_id": request.case_id,
    }


@final
class BenchmarkExecutionBoundary:
    """A typed architectural seam; creates only a BenchmarkExecutionRequest.

    It performs no execution, no discovery, and no inference — it merely derives
    the execution identity from an already-constructed BenchmarkCase.
    """

    def create_request(self, case: BenchmarkCase) -> BenchmarkExecutionRequest:
        if not isinstance(case, BenchmarkCase):
            raise ThreatModelError(
                f"case must be a BenchmarkCase, got {type(case).__name__}"
            )
        return BenchmarkExecutionRequest(
            benchmark_id=case.benchmark_id,
            case_id=case.case_id,
        )
