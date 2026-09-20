"""First benchmark-adapter foundation.

A minimal, deterministic, immutable transport/adpatation model that maps an
external benchmark case into Veyra's stable internal evaluation contract
(a :class:`SecurityScenario` plus an explicit
:class:`SecurityScenarioThreatMapping`).

This layer does NOT execute the benchmark, run attacks, run the Veyra scanner,
build AttackPaths, calculate detection metrics, or download datasets. It is only
a stable seam that future benchmark adapters (AgentDojo, AgentThreatBench,
Agent Egress Security Corpus, internal corpi) can build on.

External benchmark formats are unstable and benchmark-specific; Veyra's internal
evaluation contract stays stable. Therefore a :class:`BenchmarkCase` carries only
the normalized, benchmark-agnostic representation — no raw external benchmark
objects, no benchmark scores, no detection results.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol, runtime_checkable

from veyra.threats._error import ThreatModelError
from veyra.threats.mapping import (
    SecurityScenarioThreatMapping,
    serialize_security_scenario_threat_mapping,
)
from veyra.threats.scenarios import (
    SecurityScenario,
    _require_str,
    serialize_security_scenario,
)


@dataclass(frozen=True)
class BenchmarkCase:
    """An internal normalized representation of an external benchmark case.

    It preserves ``benchmark_id`` and ``case_id`` exactly after the existing
    required-string validation (no lowercasing, aliasing, canonicalization, and
    no inference from names or descriptions). It contains NO AttackPath,
    findings, detection results, risk/severity/confidence, benchmark scores,
    or raw external benchmark objects.
    """

    benchmark_id: str
    case_id: str
    name: str
    description: str
    scenario: SecurityScenario
    threat_mapping: SecurityScenarioThreatMapping

    def __post_init__(self):
        object.__setattr__(self, "benchmark_id", _require_str(self.benchmark_id, "benchmark id"))
        object.__setattr__(self, "case_id", _require_str(self.case_id, "case id"))
        object.__setattr__(self, "name", _require_str(self.name, "name"))
        object.__setattr__(self, "description", _require_str(self.description, "description"))
        if not isinstance(self.scenario, SecurityScenario):
            raise ThreatModelError(
                f"scenario must be a SecurityScenario, got {type(self.scenario).__name__}"
            )
        if not isinstance(self.threat_mapping, SecurityScenarioThreatMapping):
            raise ThreatModelError(
                "threat_mapping must be a SecurityScenarioThreatMapping, "
                f"got {type(self.threat_mapping).__name__}"
            )


def serialize_benchmark_case(case: BenchmarkCase) -> Dict[str, Any]:
    """Deterministic, JSON-safe serialization of one BenchmarkCase.

    Nested objects are serialized through their public serializers
    (``serialize_security_scenario`` and
    ``serialize_security_scenario_threat_mapping``). No timestamps, hashes,
    runtime metadata, or implementation details are added.
    """
    return {
        "benchmark_id": case.benchmark_id,
        "case_id": case.case_id,
        "name": case.name,
        "description": case.description,
        "scenario": serialize_security_scenario(case.scenario),
        "threat_mapping": serialize_security_scenario_threat_mapping(case.threat_mapping),
    }


@runtime_checkable
class BenchmarkAdapter(Protocol):
    """Minimal adapter contract: external benchmark case -> BenchmarkCase.

    It expresses only the conversion boundary and performs NO execution. A
    concrete adapter must expose a stable ``benchmark_id`` and an ``adapt``
    method that returns a :class:`BenchmarkCase`. Adapters are not auto-
    discovered, registered, loaded from plugins, or run.
    """

    benchmark_id: str

    def adapt(self, case: Any) -> BenchmarkCase:
        """Convert one external benchmark case into a BenchmarkCase.

        Never executed by this layer; adapter implementations provide the
        benchmark-specific conversion.
        """
        ...
