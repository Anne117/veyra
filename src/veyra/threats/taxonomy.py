"""Taxonomy model for Veyra's threat knowledge foundation.

A taxonomy is a separate catalog layer from :class:`ThreatScenario`.
``ThreatTaxonomy`` describes a fixed, named catalog of authoritative threat
entries; it is entirely taxonomy-agnostic and holds no OWASP- or
CWE/ATT&CK-specific fields. The concrete OWASP Agentic AI 2026 catalog lives in
``veyra.threats.catalogs.owasp_agentic_2026``.

This layer is deterministic and read-only: it never infers a category from an
AttackPath, never modifies the graph, and never calculates risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.models import ThreatSource, _require_scope


@dataclass(frozen=True)
class ThreatTaxonomyEntry:
    """A single authoritative entry within a ThreatTaxonomy.

    ``entry_id`` and ``name`` preserve the source taxonomy's exact terminology
    (e.g. ``"ASI01"`` / ``"Agent Goal Hijack"``). ``description`` is a concise,
    authoritative summary.
    """

    entry_id: str
    name: str
    description: str
    source: ThreatSource

    def __post_init__(self):
        object.__setattr__(self, "entry_id", _require_scope(self.entry_id, "entry id"))
        object.__setattr__(self, "name", _require_scope(self.name, "entry name"))
        object.__setattr__(self, "description", _require_scope(self.description, "entry description"))


@dataclass(frozen=True)
class ThreatTaxonomy:
    """A fixed, named taxonomy catalog with ordered authoritative entries.

    ``entries`` is an immutable tuple of :class:`ThreatTaxonomyEntry`.
    """

    taxonomy_id: str
    name: str
    version: str
    reference: str
    entries: Tuple[ThreatTaxonomyEntry, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "taxonomy_id", _require_scope(self.taxonomy_id, "taxonomy id"))
        object.__setattr__(self, "name", _require_scope(self.name, "taxonomy name"))
        object.__setattr__(self, "version", _require_scope(self.version, "taxonomy version"))
        object.__setattr__(self, "reference", _require_scope(self.reference, "taxonomy reference"))
        entries = tuple(self.entries)
        object.__setattr__(self, "entries", entries)
        # Reject duplicate entry ids deterministically.
        seen = set()
        for e in entries:
            if e.entry_id in seen:
                raise ThreatModelError(f"duplicate taxonomy entry id: {e.entry_id}")
            seen.add(e.entry_id)


def _serialize_entry(entry: ThreatTaxonomyEntry) -> Dict[str, Any]:
    return {
        "entry_id": entry.entry_id,
        "name": entry.name,
        "description": entry.description,
        "source": {
            "name": entry.source.name,
            "version": entry.source.version,
            "reference": entry.source.reference,
        },
    }


def serialize_threat_taxonomy(taxonomy: ThreatTaxonomy) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one ThreatTaxonomy."""
    return {
        "taxonomy_id": taxonomy.taxonomy_id,
        "name": taxonomy.name,
        "version": taxonomy.version,
        "reference": taxonomy.reference,
        "entries": [_serialize_entry(e) for e in taxonomy.entries],
    }


def serialize_threat_taxonomies(taxonomies: Sequence[ThreatTaxonomy]) -> List[Dict[str, Any]]:
    """Deterministic, JSON-safe serialization of many ThreatTaxonomies.

    Ordering preserves the caller's sequence order.
    """
    return [serialize_threat_taxonomy(t) for t in taxonomies]
