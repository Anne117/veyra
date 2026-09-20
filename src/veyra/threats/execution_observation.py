"""Benchmark execution observation contract (Commit 39).

An immutable data contract representing the explicit outcome reported by a
(future) benchmark execution boundary.

It contains ONLY explicit execution facts: ``status``, optional ``message``, a
:class:`BenchmarkObservation` (the only representation of observed security
properties), and opaque ``metadata``.

It must NOT calculate ``passed``/``violated_properties``, compare expected vs
observed, invoke SecurityAssertion, inspect SecurityScenario/BenchmarkCase/
AttackPath/scanner findings, infer threats/OWASP IDs, calculate
risk/severity/confidence, run network/subprocess/filesystem operations, or
execute a benchmark. Security evaluation remains with BenchmarkEvaluator;
identity remains owned by BenchmarkCase / execution-request context. Commit 39
introduces the contract only — actual benchmark execution is not implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.evaluation import _require_meta_pairs
from veyra.threats.observations import BenchmarkObservation
from veyra.threats.scenarios import _require_str


def _require_optional_message(value: Any) -> str:
    """Trim and require a string; empty string is allowed (no default)."""
    if not isinstance(value, str):
        raise ThreatModelError(
            f"message must be a string, got {type(value).__name__}"
        )
    return value.strip()


@dataclass(frozen=True)
class BenchmarkExecutionObservation:
    """Explicit facts reported by a (future) benchmark execution boundary.

    ``status`` is a non-empty trimmed string (no enum, no fixed status set).
    ``message`` is optional and trimmed (empty stays ``""``). ``observed_properties``
    MUST be a :class:`BenchmarkObservation`; a raw sequence is not accepted.
    ``metadata`` is opaque, normalized key/value metadata.
    """

    status: str
    message: str = ""
    observed_properties: BenchmarkObservation = BenchmarkObservation()
    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "status", _require_str(self.status, "status"))
        object.__setattr__(self, "message", _require_optional_message(self.message))
        if not isinstance(self.observed_properties, BenchmarkObservation):
            raise ThreatModelError(
                "observed_properties must be a BenchmarkObservation, "
                f"got {type(self.observed_properties).__name__}"
            )
        object.__setattr__(
            self, "metadata", _require_meta_pairs(self.metadata)
        )


def serialize_benchmark_execution_observation(
    observation: BenchmarkExecutionObservation,
) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one execution observation.

    Exact shape (status/message/observed_properties/metadata, no extra keys).
    """
    return {
        "status": observation.status,
        "message": observation.message,
        "observed_properties": {
            "properties": list(observation.observed_properties.properties),
        },
        "metadata": [
            [key, value] for key, value in observation.metadata
        ],
    }
