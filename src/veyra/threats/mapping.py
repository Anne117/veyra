"""Explicit SecurityScenario<->threat-knowledge mapping.

A minimal, deterministic, immutable :class:`SecurityScenarioThreatMapping`
explicitly associates an evaluation scenario (``scenario_id``) with a set of
threat-knowledge identifiers (``threat_ids``).

The identifiers are **opaque stable strings**. They may reference:
- ThreatScenario IDs;
- taxonomy entry IDs such as ``ASI01``;
- future benchmark/threat identifiers.

This layer is GENERIC and taxonomy-agnostic: it never hard-codes OWASP, never
auto-resolves/validates identifiers against any catalog, never case-folds, and
never aliases/canonicalizes. Only explicit identifiers supplied by the caller
establish a mapping — no inference from names, descriptions, attack-behavior
text, keywords, component names, AttackPath, AttackType, or graph structure.

It must NOT modify/create a SecurityGraph, build AttackPaths, run the scanner,
calculate risk, infer AttackType, or mutate SecurityScenario / ThreatScenario.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from veyra.threats.scenarios import _require_str, _require_str_tuple


@dataclass(frozen=True)
class SecurityScenarioThreatMapping:
    """An explicit, caller-supplied mapping from an evaluation scenario to
    threat-knowledge identifiers.

    ``scenario_id`` is a required non-empty string. ``threat_ids`` is a
    normalized (trimmed, non-empty-only, deduplicated, sorted) immutable tuple
    of opaque stable strings. Identifiers are preserved exactly — no
    case-folding, aliasing, or canonicalization.
    """

    scenario_id: str
    threat_ids: Tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "scenario_id", _require_str(self.scenario_id, "scenario id"))
        object.__setattr__(self, "threat_ids", _require_str_tuple(self.threat_ids, "threat ids"))


def serialize_security_scenario_threat_mapping(
    mapping: SecurityScenarioThreatMapping,
) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one mapping.

    Output is exactly ``{"scenario_id": ..., "threat_ids": [...]}`` with no
    extra metadata.
    """
    return {
        "scenario_id": mapping.scenario_id,
        "threat_ids": list(mapping.threat_ids),
    }
