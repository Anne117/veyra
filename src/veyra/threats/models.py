"""Threat knowledge foundation model.

A small, deterministic, read-only internal foundation for Veyra's future threat
knowledge layer. It establishes a stable internal model that future
threat-taxonomy and benchmark adapters (e.g. OWASP, AgentDojo, AgentThreatBench,
Agent Egress Corpus, internal scenarios) can use WITHOUT changing the core
model.

It does NOT yet implement OWASP taxonomy, AgentDojo, AgentThreatBench, Agent
Egress Corpus, runtime telemetry, OpenTelemetry, a runtime graph, ML/LLM
analysis, benchmark execution, threat scoring, or attack-path modification.

A :class:`ThreatScenario` is descriptive/evaluation metadata. It NEVER modifies
an AttackPath, creates graph nodes/edges, introduces new AttackType/EdgeType
values, calculates risk, assigns ownership/responsibility, or infers threats
from component names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from veyra.threats._error import ThreatModelError


def _require_scope(value: str, what: str) -> str:
    """Strip and require a non-empty string value."""
    value = (value or "").strip()
    if not value:
        raise ThreatModelError(f"empty {what}")
    return value


def _normalize_tuple(values: Optional[Sequence[str]], what: str) -> Tuple[str, ...]:
    """Normalize a tuple deterministically: trimmed, non-empty-only, deduplicated,
    sorted. Preserves the caller's explicit order only if the project conventions
    support it; here we normalize deterministically per the model contract.
    """
    if not values:
        return ()
    cleaned = [v.strip() for v in values if v and v.strip()]
    # Deduplicate while preserving first occurrence, then sort for determinism.
    return tuple(sorted(dict.fromkeys(cleaned)))


@dataclass(frozen=True)
class ThreatSource:
    """The origin of a ThreatScenario (e.g. a benchmark or taxonomy).

    Name/version/reference are free-form descriptive strings supplied by the
    caller; the model never invents or guesses them.
    """

    name: str
    version: str
    reference: str

    def __post_init__(self):
        object.__setattr__(self, "name", _require_scope(self.name, "source name"))
        object.__setattr__(self, "version", _require_scope(self.version, "source version"))
        object.__setattr__(self, "reference", _require_scope(self.reference, "source reference"))


@dataclass(frozen=True)
class ThreatScenario:
    """Descriptive/evaluation metadata describing a security threat scenario.

    ``threat_categories``, ``attack_behaviors``, ``entry_conditions`` and
    ``expected_security_properties`` are normalized (trimmed, non-empty-only,
    deduplicated, sorted) immutable tuples. ``source`` is optional provenance.

    This is a stable, taxonomy-agnostic foundation: it holds NO OWASP-specific
    fields and never infers threat values.
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
        object.__setattr__(self, "scenario_id", _require_scope(self.scenario_id, "scenario id"))
        object.__setattr__(self, "name", _require_scope(self.name, "name"))
        object.__setattr__(self, "description", _require_scope(self.description, "description"))
        object.__setattr__(
            self, "threat_categories", _normalize_tuple(self.threat_categories, "threat categories")
        )
        object.__setattr__(
            self, "attack_behaviors", _normalize_tuple(self.attack_behaviors, "attack behaviors")
        )
        object.__setattr__(
            self, "entry_conditions", _normalize_tuple(self.entry_conditions, "entry conditions")
        )
        object.__setattr__(
            self,
            "expected_security_properties",
            _normalize_tuple(self.expected_security_properties, "expected security properties"),
        )


def _serialize_scenario(scenario: ThreatScenario) -> Dict[str, Any]:
    """JSON-safe serialization of one ThreatScenario (primitive values only)."""
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


def serialize_threat_scenario(scenario: ThreatScenario) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one ThreatScenario."""
    return _serialize_scenario(scenario)


def serialize_threat_scenarios(scenarios: Sequence[ThreatScenario]) -> List[Dict[str, Any]]:
    """Deterministic, JSON-safe serialization of many ThreatScenarios.

    Ordering preserves the caller's sequence order.
    """
    return [_serialize_scenario(s) for s in scenarios]
