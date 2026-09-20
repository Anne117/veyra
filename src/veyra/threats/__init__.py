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
from veyra.threats.mapping import (
    SecurityScenarioThreatMapping,
    serialize_security_scenario_threat_mapping,
)
from veyra.threats.benchmarks import (
    BenchmarkAdapter,
    BenchmarkCase,
    serialize_benchmark_case,
)
from veyra.threats.evaluation import (
    BenchmarkEvaluationResult,
    serialize_benchmark_evaluation_result,
)
from veyra.threats.evaluator import BenchmarkEvaluator
from veyra.threats.aggregation import (
    BenchmarkEvaluationSummary,
    BenchmarkEvaluationAggregator,
    serialize_benchmark_evaluation_summary,
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
    "SecurityScenarioThreatMapping",
    "BenchmarkCase",
    "BenchmarkAdapter",
    "BenchmarkEvaluationResult",
    "BenchmarkEvaluator",
    "BenchmarkEvaluationSummary",
    "BenchmarkEvaluationAggregator",
    "serialize_benchmark_case",
    "serialize_benchmark_evaluation_result",
    "serialize_benchmark_evaluation_summary",
    "serialize_security_scenario",
    "serialize_security_scenario_threat_mapping",
    "serialize_threat_scenario",
    "serialize_threat_scenarios",
    "serialize_threat_taxonomy",
    "serialize_threat_taxonomies",
]
