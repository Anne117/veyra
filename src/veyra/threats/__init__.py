"""Threat knowledge foundation.

A small, deterministic, read-only internal foundation for Veyra's future threat
knowledge layer. This commit establishes ONLY the stable internal model; it does
NOT yet implement OWASP taxonomy, AgentDojo, AgentThreatBench, Agent Egress
Corpus, runtime telemetry, or threat scoring.
"""

from veyra.threats._error import ThreatModelError
from veyra.threats.models import (
    ThreatScenario,
    ThreatSource,
    serialize_threat_scenario,
    serialize_threat_scenarios,
)

__all__ = [
    "ThreatModelError",
    "ThreatScenario",
    "ThreatSource",
    "serialize_threat_scenario",
    "serialize_threat_scenarios",
]
