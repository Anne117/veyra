"""AgentDojo benchmark adapter (Commit 28).

Converts an **already-supplied** AgentDojo-style case representation into a
:class:`veyra.threats.benchmarks.BenchmarkCase`. This is a pure data
transformation only.

It must NOT execute AgentDojo, install/download/import AgentDojo, access the
network, read the filesystem, run the scanner, build AttackPaths, or calculate
risk/detection metrics.

The external benchmark is NOT a runtime dependency. The adapter consumes a small,
explicitly documented mapping-shaped input contract (defined in Veyra itself):

- ``case_id``          : required non-empty string
- ``name``             : required non-empty string
- ``description``      : required non-empty string
- ``threat_ids``       : optional sequence of strings
- ``threat_categories``: optional sequence of strings
- ``attack_behaviors`` : optional sequence of strings
- ``entry_conditions`` : optional sequence of strings
- ``expected_security_properties``: optional sequence of strings

No fuzzy field matching, no arbitrary nested-field search, and no inference.
``threat_categories`` are copied into ``SecurityScenario.threat_categories``
only; they are NEVER automatically turned into ``threat_ids``. Identifiers are
preserved exactly (case-sensitive, opaque) and are not validated against any
OWASP catalog.
"""

from __future__ import annotations

from typing import Any, Mapping

from veyra.threats._error import ThreatModelError
from veyra.threats.benchmarks import BenchmarkAdapter, BenchmarkCase
from veyra.threats.mapping import SecurityScenarioThreatMapping
from veyra.threats.scenarios import (
    SecurityScenario,
    _require_str,
    _require_str_tuple,
)


_MISSING = object()


def _optional_seq(case: Any, key: str) -> tuple:
    value = case.get(key, _MISSING)
    if value is _MISSING or value is None:
        return ()
    return _require_str_tuple(value, key)


class AgentDojoAdapter:
    """Converts an AgentDojo-style case mapping into a BenchmarkCase.

    Satisfies the :class:`BenchmarkAdapter` protocol.
    """

    benchmark_id = "agentdojo"

    def adapt(self, case: Any) -> BenchmarkCase:
        if not isinstance(case, Mapping):
            raise ThreatModelError(
                f"AgentDojo case must be a mapping, got {type(case).__name__}"
            )
        case_id = _require_str(case.get("case_id", _MISSING), "case_id")
        name = _require_str(case.get("name", _MISSING), "name")
        description = _require_str(case.get("description", _MISSING), "description")

        threat_ids = _optional_seq(case, "threat_ids")
        threat_categories = _optional_seq(case, "threat_categories")
        attack_behaviors = _optional_seq(case, "attack_behaviors")
        entry_conditions = _optional_seq(case, "entry_conditions")
        expected_security_properties = _optional_seq(case, "expected_security_properties")

        scenario = SecurityScenario(
            scenario_id=case_id,
            name=name,
            description=description,
            threat_categories=threat_categories,
            attack_behaviors=attack_behaviors,
            entry_conditions=entry_conditions,
            expected_security_properties=expected_security_properties,
        )
        threat_mapping = SecurityScenarioThreatMapping(
            scenario_id=case_id,
            threat_ids=threat_ids,
        )
        return BenchmarkCase(
            benchmark_id=self.benchmark_id,
            case_id=case_id,
            name=name,
            description=description,
            scenario=scenario,
            threat_mapping=threat_mapping,
        )
