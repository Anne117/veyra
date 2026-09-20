"""Threat knowledge foundation.

A small, deterministic, read-only internal foundation for Veyra's future threat
knowledge layer.

- ``ThreatScenario`` / ``ThreatSource``       — generic descriptive scenario model
- ``ThreatTaxonomy`` / ``ThreatTaxonomyEntry`` — taxonomy/catalog structure
- ``OWASP_AGENTIC_2026``                       — one concrete taxonomy catalog
- ``SecurityScenario``                         — evaluation/security test contract

This commit does NOT infer OWASP categories from AttackPaths and does NOT yet
implement AgentDojo, AgentThreatBench, Agent Egress Security Corpus, runtime
telemetry, or benchmark execution.
"""

from veyra.threats._error import ThreatModelError
from veyra.threats.catalogs import (
    OWASP_AGENTIC_2026,
    get_owasp_agentic_2026,
)
from veyra.threats.models import (
    ThreatScenario,
    ThreatSource,
    serialize_threat_scenario,
    serialize_threat_scenarios,
)
from veyra.threats.taxonomy import (
    ThreatTaxonomy,
    ThreatTaxonomyEntry,
    serialize_threat_taxonomies,
    serialize_threat_taxonomy,
)
from veyra.threats.scenarios import (
    SecurityScenario,
    serialize_security_scenario,
)

__all__ = [
    "ThreatModelError",
    "ThreatScenario",
    "ThreatSource",
    "ThreatTaxonomy",
    "ThreatTaxonomyEntry",
    "OWASP_AGENTIC_2026",
    "get_owasp_agentic_2026",
    "SecurityScenario",
    "serialize_security_scenario",
    "serialize_threat_scenario",
    "serialize_threat_scenarios",
    "serialize_threat_taxonomy",
    "serialize_threat_taxonomies",
]
