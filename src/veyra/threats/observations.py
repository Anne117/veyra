"""Benchmark observation contract (Commit 38).

:class:`BenchmarkObservation` is the immutable, normalized representation of
the explicit observed security properties supplied at the evaluation boundary.

It is a transport/contract model ONLY. It does NOT infer security properties,
inspect BenchmarkCase/SecurityScenario/AttackPath/findings/scanner output/OWASP,
calculate violations, compute passed/failed or severity/risk/confidence, or
execute anything. It simply normalizes explicitly supplied observed property
identifiers.

Violation derivation remains exclusively with :class:`SecurityAssertion`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Sequence, Tuple

from veyra.threats.scenarios import _require_str_tuple


@dataclass(frozen=True)
class BenchmarkObservation:
    """An immutable collection of explicitly observed security properties.

    ``properties`` is normalized (trimmed, non-empty-only, deduplicated, sorted)
    using the standard threat-model conventions. It is a pure identifier
    collection; no other fields, no inference, and no security verdict.
    """

    properties: Tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(
            self, "properties", _require_str_tuple(self.properties, "properties")
        )


def serialize_benchmark_observation(observation: BenchmarkObservation) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one observation.

    Produces exactly ``{"properties": [...]}`` with no extra fields.
    """
    return {
        "properties": list(observation.properties),
    }
