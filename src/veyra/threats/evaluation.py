"""Benchmark evaluation result foundation (Commit 30).

A minimal, deterministic, benchmark-agnostic :class:`BenchmarkEvaluationResult`
is the RESULT DATA CONTRACT that a future benchmark evaluator/runner can
produce. It is a passive, independently-serializable data model only.

It must NOT execute benchmarks, run Veyra scans, build AttackPaths, derive
pass/fail, calculate risk, infer threat IDs/OWASP, or resolve mappings. All of
its fields are explicitly supplied by the future evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.scenarios import _require_str, _require_str_tuple


def _require_meta_pair(value: Any, what: str) -> Tuple[str, str] | None:
    """Validate one metadata (key, value) pair.

    A pair must be a 2-element sequence of two non-empty strings. The pair's
    key/value are trimmed. Returns the normalized pair, or None if it is empty
    (both sides blank) so it can be dropped deterministically.
    """
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ThreatModelError(
            f"{what} must be a (key, value) pair (a 2-element sequence), "
            f"got {type(value).__name__}"
        )
    key, val = value
    if not isinstance(key, str):
        raise ThreatModelError(
            f"{what} key must be a string, got {type(key).__name__}"
        )
    if not isinstance(val, str):
        raise ThreatModelError(
            f"{what} value must be a string, got {type(val).__name__}"
        )
    key = key.strip()
    val = val.strip()
    if not key or not val:
        return None
    return (key, val)


def _require_meta_pairs(values: Any) -> Tuple[Tuple[str, str], ...]:
    """Validate and normalize a metadata sequence deterministically.

    Each item must be a (key, value) string pair; keys/values are trimmed,
    blank pairs dropped, duplicate identical pairs removed, then sorted by
    (key, value) for deterministic order.
    """
    if values is None:
        return ()
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ThreatModelError(
            f"metadata must be a sequence of (key, value) pairs, "
            f"got {type(values).__name__}"
        )
    cleaned: list[Tuple[str, str]] = []
    for item in values:
        pair = _require_meta_pair(item, "metadata")
        if pair is not None:
            cleaned.append(pair)
    # Deduplicate (key,value) pairs preserving one occurrence, then sort.
    return tuple(sorted(dict.fromkeys(cleaned)))


@dataclass(frozen=True)
class BenchmarkEvaluationResult:
    """The RESULT DATA CONTRACT for a (future) benchmark evaluation run.

    Fields (documented, deterministic order):

    - ``benchmark_id`` : ``str`` — opaque benchmark source identifier; no registry/validation.
    - ``case_id``      : ``str`` — opaque evaluated-case identifier.
    - ``passed``       : ``bool`` — explicit evaluator boolean; never derived here.
    - ``status``       : ``str`` — explicit opaque status string (e.g. "passed", "failed", "error").
    - ``message``      : ``str`` — explicit human-readable evaluator message.
    - ``observed_properties``  : ``Tuple[str, ...]`` — normalized observed properties.
    - ``violated_properties``  : ``Tuple[str, ...]`` — normalized violated properties.
    - ``metadata``     : ``Tuple[Tuple[str, str], ...]`` — deterministic key/value metadata.

    This model performs NO analysis and never interprets its own fields.
    """

    benchmark_id: str
    case_id: str
    passed: bool
    status: str
    message: str
    observed_properties: Tuple[str, ...] = ()
    violated_properties: Tuple[str, ...] = ()
    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "benchmark_id", _require_str(self.benchmark_id, "benchmark id"))
        object.__setattr__(self, "case_id", _require_str(self.case_id, "case id"))
        if not isinstance(self.passed, bool):
            raise ThreatModelError(
                f"passed must be a boolean, got {type(self.passed).__name__}"
            )
        object.__setattr__(self, "status", _require_str(self.status, "status"))
        object.__setattr__(self, "message", _require_str(self.message, "message"))
        object.__setattr__(
            self, "observed_properties", _require_str_tuple(self.observed_properties, "observed properties")
        )
        object.__setattr__(
            self, "violated_properties", _require_str_tuple(self.violated_properties, "violated properties")
        )
        object.__setattr__(
            self, "metadata", _require_meta_pairs(self.metadata)
        )


def serialize_benchmark_evaluation_result(result: BenchmarkEvaluationResult) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one BenchmarkEvaluationResult.

    Pure primitive output; no dataclass implementation detail and no
    security-analysis fields (severity/confidence/risk_score/attack_type/
    findings/attack_paths) unless carried via generic ``metadata``.
    """
    return {
        "benchmark_id": result.benchmark_id,
        "case_id": result.case_id,
        "passed": result.passed,
        "status": result.status,
        "message": result.message,
        "observed_properties": list(result.observed_properties),
        "violated_properties": list(result.violated_properties),
        "metadata": [
            {"key": k, "value": v} for k, v in result.metadata
        ],
    }
