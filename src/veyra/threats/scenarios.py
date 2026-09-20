"""SecurityScenario evaluation contract.

A minimal, deterministic, immutable :class:`SecurityScenario` describes an
evaluation/security test scenario that FUTURE layers (benchmark adapters and
the evaluation runner) can build upon. It is an **evaluation contract** — it
states expected security behavior and properties, and performs NO analysis.

Unlike :class:`veyra.threats.ThreatScenario` (which is a descriptive threat
knowledge model), a ``SecurityScenario`` is scoped to evaluation: it describes
*expectations*, never observed results.

It must NOT:
- perform analysis, build a SecurityGraph, construct AttackPaths, or scan files;
- infer threats, AttackType, risk, severity, or confidence;
- resolve OWASP taxonomy identifiers automatically;
- make network requests.

A ``SecurityScenario`` may reference threat knowledge by stable string
identifiers (e.g. ``"ASI01"``), but does NOT resolve/validate them against the
OWASP catalog — that mapping belongs to a later stage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.models import (
    ThreatSource,
    _normalize_tuple,
    _require_scope,
)


def _require_str(value: Any, what: str) -> str:
    """Require a non-empty string, rejecting invalid runtime types."""
    if not isinstance(value, str):
        raise ThreatModelError(
            f"{what} must be a string, got {type(value).__name__}"
        )
    return _require_scope(value, what)


def _require_str_tuple(values: Any, what: str) -> Tuple[str, ...]:
    """Validate and normalize a string tuple, rejecting invalid runtime types."""
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise ThreatModelError(
            f"{what} must be a sequence of strings, got {type(values).__name__}"
        )
    for v in values:
        if not isinstance(v, str):
            raise ThreatModelError(
                f"{what} must contain only strings, got {type(v).__name__}"
            )
    return _normalize_tuple(values, what)


@dataclass(frozen=True)
class SecurityScenario:
    """An evaluation/security test contract.

    ``threat_categories``, ``attack_behaviors``, ``entry_conditions`` and
    ``expected_security_properties`` are normalized (trimmed, non-empty-only,
    deduplicated, sorted) immutable string tuples. ``source`` is optional
    provenance of the scenario.

    This is a pure expectation model. It performs no analysis and infers
    nothing from its inputs.
    """

    scenario_id: str
    name: str
    description: str
    threat_categories: Tuple[str, ...] = ()
    attack_behaviors: Tuple[str, ...] = ()
    entry_conditions: Tuple[str, ...] = ()
    expected_security_properties: Tuple[str, ...] = ()
    source: Optional[ThreatSource] = None

    def __post_init__(self):
        object.__setattr__(self, "scenario_id", _require_str(self.scenario_id, "scenario id"))
        object.__setattr__(self, "name", _require_str(self.name, "name"))
        object.__setattr__(self, "description", _require_str(self.description, "description"))
        object.__setattr__(
            self, "threat_categories", _require_str_tuple(self.threat_categories, "threat categories")
        )
        object.__setattr__(
            self, "attack_behaviors", _require_str_tuple(self.attack_behaviors, "attack behaviors")
        )
        object.__setattr__(
            self, "entry_conditions", _require_str_tuple(self.entry_conditions, "entry conditions")
        )
        object.__setattr__(
            self,
            "expected_security_properties",
            _require_str_tuple(self.expected_security_properties, "expected security properties"),
        )
        if self.source is not None and not isinstance(self.source, ThreatSource):
            raise ThreatModelError(
                f"source must be a ThreatSource or None, got {type(self.source).__name__}"
            )


def serialize_security_scenario(scenario: SecurityScenario) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one SecurityScenario.

    Primitive values only; no dataclass implementation detail leaks. The
    ``source`` field is serialized only when present.
    """
    d: Dict[str, Any] = {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "description": scenario.description,
        "threat_categories": list(scenario.threat_categories),
        "attack_behaviors": list(scenario.attack_behaviors),
        "entry_conditions": list(scenario.entry_conditions),
        "expected_security_properties": list(scenario.expected_security_properties),
    }
    if scenario.source is not None:
        d["source"] = {
            "name": scenario.source.name,
            "version": scenario.source.version,
            "reference": scenario.source.reference,
        }
    return d
