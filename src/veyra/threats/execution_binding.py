"""Benchmark execution binding contract (Commit 40).

A passive, immutable identity/binding layer that states explicitly which
:class:`BenchmarkExecutionRequest` a :class:`BenchmarkExecutionObservation`
belongs to::

    BenchmarkExecutionRequest
        +
    BenchmarkExecutionObservation
        ↓
    BenchmarkExecutionBinding

The binding derives and infers nothing. Execution identity remains owned by
:class:`BenchmarkExecutionRequest` (``binding.request.benchmark_id`` /
``binding.request.case_id`` are authoritative); execution facts remain owned by
:class:`BenchmarkExecutionObservation`. Security evaluation remains with
BenchmarkEvaluator / SecurityAssertion.

It performs NO execution and NO evaluation: no ``passed``, no
``violated_properties``, no expected-vs-observed comparison, no risk/severity/
confidence, no threat/OWASP inference, no AttackPath or scanner access, and no
subprocess/network/filesystem operations. Commit 40 introduces the contract only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from veyra.threats._error import ThreatModelError
from veyra.threats.execution import (
    BenchmarkExecutionRequest,
    serialize_benchmark_execution_request,
)
from veyra.threats.execution_observation import (
    BenchmarkExecutionObservation,
    serialize_benchmark_execution_observation,
)


@dataclass(frozen=True)
class BenchmarkExecutionBinding:
    """Explicit association: this observation belongs to this request.

    Fields are exactly ``request`` then ``observation``. No identity duplication
    (no ``benchmark_id``/``case_id``), no status duplication, no security fields.
    """

    request: BenchmarkExecutionRequest
    observation: BenchmarkExecutionObservation

    def __post_init__(self):
        if not isinstance(self.request, BenchmarkExecutionRequest):
            raise ThreatModelError(
                "request must be a BenchmarkExecutionRequest, "
                f"got {type(self.request).__name__}"
            )
        if not isinstance(self.observation, BenchmarkExecutionObservation):
            raise ThreatModelError(
                "observation must be a BenchmarkExecutionObservation, "
                f"got {type(self.observation).__name__}"
            )


def serialize_benchmark_execution_binding(
    binding: BenchmarkExecutionBinding,
) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one execution binding.

    Delegates to the canonical serializers; exact shape
    ``{"request": {...}, "observation": {...}}`` with no extra keys.
    """
    return {
        "request": serialize_benchmark_execution_request(binding.request),
        "observation": serialize_benchmark_execution_observation(
            binding.observation
        ),
    }
