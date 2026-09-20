"""Tests for the AgentThreatBench adapter (Commit 29).

AgentThreatBenchAdapter is a pure data transformation: it converts an
already-supplied AgentThreatBench-style mapping into a BenchmarkCase. No
AgentThreatBench dependency, no network/filesystem access, no benchmark/scanner
execution, no inference.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkCase,
    SecurityScenario,
    SecurityScenarioThreatMapping,
    ThreatModelError,
    serialize_benchmark_case,
)
from veyra.threats.adapters import AgentDojoAdapter, AgentThreatBenchAdapter
from veyra.threats.benchmarks import BenchmarkAdapter


def _minimal():
    return {
        "case_id": "atb-001",
        "name": "Secret exfiltration",
        "description": "Ensure the secret is not exfiltrated.",
    }


def _full():
    return {
        "case_id": "atb-001",
        "name": "Secret exfiltration",
        "description": "Ensure the secret is not exfiltrated.",
        "threat_ids": ["T-001", "T-002"],
        "threat_categories": ["ASI01", "data-exfiltration"],
        "attack_behaviors": ["reads-secret", "sends-to-endpoint"],
        "entry_conditions": ["has-secret", "has-network"],
        "expected_security_properties": ["no-exfiltration", "secret-confidentiality"],
    }


ADAPTER = AgentThreatBenchAdapter()


# 1. valid minimal case
def test_valid_minimal():
    bc = ADAPTER.adapt(_minimal())
    assert isinstance(bc, BenchmarkCase)
    assert bc.case_id == "atb-001"


# 2. valid full case
def test_valid_full():
    bc = ADAPTER.adapt(_full())
    assert bc.case_id == "atb-001"
    assert bc.scenario.attack_behaviors == ("reads-secret", "sends-to-endpoint")
    assert bc.threat_mapping.threat_ids == ("T-001", "T-002")


# 3. benchmark_id
def test_benchmark_id():
    assert AgentThreatBenchAdapter.benchmark_id == "agentthreatbench"
    assert ADAPTER.adapt(_minimal()).benchmark_id == "agentthreatbench"


# 4. case_id preservation
def test_case_id_preservation():
    assert ADAPTER.adapt(_minimal()).case_id == "atb-001"


# 5. scenario_id == case_id
def test_scenario_id_equals_case_id():
    bc = ADAPTER.adapt(_minimal())
    assert bc.scenario.scenario_id == "atb-001"


# 6. mapping.scenario_id == case_id
def test_mapping_scenario_id_equals_case_id():
    bc = ADAPTER.adapt(_minimal())
    assert bc.threat_mapping.scenario_id == "atb-001"


# 7-8. name / description preservation
def test_name_description_preserved():
    bc = ADAPTER.adapt(_full())
    assert bc.name == "Secret exfiltration"
    assert bc.description == "Ensure the secret is not exfiltrated."
    assert bc.scenario.name == "Secret exfiltration"
    assert bc.scenario.description == "Ensure the secret is not exfiltrated."


# 9. explicit threat_ids preserved
def test_threat_ids_preserved():
    assert ADAPTER.adapt(_full()).threat_mapping.threat_ids == ("T-001", "T-002")


# 10. explicit threat_categories preserved
def test_threat_categories_preserved():
    assert ADAPTER.adapt(_full()).scenario.threat_categories == ("ASI01", "data-exfiltration")


# 11. attack_behaviors preserved
def test_attack_behaviors_preserved():
    assert ADAPTER.adapt(_full()).scenario.attack_behaviors == (
        "reads-secret", "sends-to-endpoint")


# 12. entry_conditions preserved (sorted deterministically by existing norm)
def test_entry_conditions_preserved():
    assert ADAPTER.adapt(_full()).scenario.entry_conditions == (
        "has-network", "has-secret")


# 13. expected_security_properties preserved
def test_expected_security_properties_preserved():
    assert ADAPTER.adapt(_full()).scenario.expected_security_properties == (
        "no-exfiltration", "secret-confidentiality")


# 14. missing optional fields become empty tuples
def test_missing_optional_fields_empty():
    bc = ADAPTER.adapt(_minimal())
    assert bc.scenario.threat_categories == ()
    assert bc.scenario.attack_behaviors == ()
    assert bc.scenario.entry_conditions == ()
    assert bc.scenario.expected_security_properties == ()
    assert bc.threat_mapping.threat_ids == ()


# 15. normalization uses existing tuple behavior (trim + dedupe + sort)
def test_tuple_normalization():
    bc = ADAPTER.adapt({
        "case_id": "x", "name": "n", "description": "d",
        "threat_ids": [" b ", "a", "b", ""],
        "threat_categories": ["  A  ", "c", " A", "c"],
    })
    assert bc.threat_mapping.threat_ids == ("a", "b")
    assert bc.scenario.threat_categories == ("A", "c")


# 16. duplicate threat_ids removed
def test_duplicate_threat_ids_removed():
    bc = ADAPTER.adapt({"case_id": "x", "name": "n", "description": "d",
                        "threat_ids": ["T-001", "T-001"]})
    assert bc.threat_mapping.threat_ids == ("T-001",)


# 17. case-sensitive threat IDs preserved
def test_case_sensitive_threat_ids():
    bc = ADAPTER.adapt({"case_id": "x", "name": "n", "description": "d",
                        "threat_ids": ["ASI01", "asi01"]})
    assert bc.threat_mapping.threat_ids == ("ASI01", "asi01")


# 18. threat_categories are NOT converted into threat_ids
def test_threat_categories_not_converted():
    bc = ADAPTER.adapt({"case_id": "x", "name": "Secret exfiltration",
                        "description": "...", "threat_categories": ["ASI02"],
                        "threat_ids": []})
    assert bc.scenario.threat_categories == ("ASI02",)
    assert bc.threat_mapping.threat_ids == ()


# 19. no OWASP auto-resolution
def test_no_owasp_auto_resolution():
    bc = ADAPTER.adapt({"case_id": "x", "name": "n", "description": "d",
                        "threat_ids": ["ASI01", "ASI999-NOT-REAL"]})
    assert bc.threat_mapping.threat_ids == ("ASI01", "ASI999-NOT-REAL")


# 20. unknown threat IDs accepted
def test_unknown_threat_ids_accepted():
    bc = ADAPTER.adapt({"case_id": "x", "name": "n", "description": "d",
                        "threat_ids": ["internal-future-id/7"]})
    assert bc.threat_mapping.threat_ids == ("internal-future-id/7",)


# 21. invalid input rejected deterministically
def test_non_mapping_rejected():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt(["case_id"])


def test_missing_case_id_rejected():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({"name": "n", "description": "d"})


def test_empty_case_id_rejected():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "case_id": ""})


def test_missing_name_rejected():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({"case_id": "x", "description": "d"})


def test_empty_description_rejected():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "description": "   "})


# 22. invalid optional field types rejected
def test_invalid_threat_ids_element_type():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "threat_ids": ["T", 5]})


def test_invalid_threat_ids_scalar_type():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "threat_ids": "T"})


def test_invalid_threat_categories_element_type():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "threat_categories": ["ASI01", None]})


def test_invalid_attack_behaviors_element_type():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "attack_behaviors": ["r", {"x": 1}]})


def test_invalid_entry_conditions_type():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "entry_conditions": 7})


def test_invalid_expected_properties_element_type():
    with pytest.raises(ThreatModelError):
        ADAPTER.adapt({**_minimal(), "expected_security_properties": [b"x"]})


# 23-25. resulting object types
def test_result_is_benchmark_case():
    assert isinstance(ADAPTER.adapt(_full()), BenchmarkCase)


def test_result_scenario_is_security_scenario():
    assert isinstance(ADAPTER.adapt(_full()).scenario, SecurityScenario)


def test_result_mapping_is_security_scenario_threat_mapping():
    assert isinstance(ADAPTER.adapt(_full()).threat_mapping, SecurityScenarioThreatMapping)


# 26. serialization through serialize_benchmark_case
def test_serialization_through_serialize_benchmark_case():
    bc = ADAPTER.adapt(_full())
    d = serialize_benchmark_case(bc)
    assert d["benchmark_id"] == "agentthreatbench"
    assert d["case_id"] == "atb-001"
    assert d["scenario"]["scenario_id"] == "atb-001"
    assert d["scenario"]["threat_categories"] == ["ASI01", "data-exfiltration"]
    assert d["threat_mapping"]["threat_ids"] == ["T-001", "T-002"]
    assert json.loads(json.dumps(d)) == d


# 27. adapter satisfies BenchmarkAdapter Protocol
def test_satisfies_benchmark_adapter_protocol():
    assert isinstance(ADAPTER, BenchmarkAdapter)
    assert hasattr(ADAPTER, "benchmark_id")
    assert hasattr(ADAPTER, "adapt")
    assert isinstance(ADAPTER.adapt(_minimal()), BenchmarkCase)


# 28. no AttackPath created
def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    bc = ADAPTER.adapt(_full())
    assert not isinstance(bc, AttackPath)
    assert not hasattr(bc, "nodes")
    assert not hasattr(bc.scenario, "attack_type")


# 29. no SecurityGraph mutation
def test_no_graph_mutation():
    from veyra.graph import EdgeType, Node, NodeType, SecurityGraph
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="DATA:x", type=NodeType.DATA))
    g.add_edge("SKILL:A", "DATA:x", EdgeType.READS)
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    ADAPTER.adapt(_full())
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# 30. no risk/AttackType inference
def test_no_risk_or_attacktype():
    bc = ADAPTER.adapt(_full())
    for obj in (bc, bc.scenario, bc.threat_mapping):
        for attr in ("risk_score", "severity", "confidence", "attack_type"):
            assert not hasattr(obj, attr), f"unexpected {attr}"
    d = serialize_benchmark_case(bc)
    for banned in ("risk", "severity", "confidence", "attack_type", "score"):
        assert banned not in d["scenario"]
        assert banned not in d["threat_mapping"]


# 31. no execution/network/filesystem behavior
def test_no_execution_network_filesystem(monkeypatch):
    import socket as socket_mod
    calls = []
    orig_connect = socket_mod.socket.connect

    class Sock:
        def connect(self, *a):  # pragma: no cover - must not be called
            calls.append(a)
            return None

    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    ADAPTER.adapt(_full())
    assert calls == []


# 32. no benchmark execution
def test_no_benchmark_execution(monkeypatch):
    import subprocess as subprocess_mod

    def _popen(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("adapter must not execute anything")

    monkeypatch.setattr(subprocess_mod, "Popen", _popen)
    bc = ADAPTER.adapt(_full())
    assert isinstance(bc, BenchmarkCase)
    assert isinstance(bc.scenario, SecurityScenario)
    assert bc.__class__.__module__ == "veyra.threats.benchmarks"


# public API export
def test_public_api_exports():
    from veyra.threats import adapters
    assert hasattr(adapters, "AgentThreatBenchAdapter")
    assert adapters.AgentThreatBenchAdapter is AgentThreatBenchAdapter
    # AgentDojoAdapter export remains unchanged.
    assert hasattr(adapters, "AgentDojoAdapter")
    assert adapters.AgentDojoAdapter is AgentDojoAdapter


# REGRESSION PROTECTION: AgentDojoAdapter must keep working unchanged
def test_agentdojo_regression():
    bc = AgentDojoAdapter().adapt({
        "case_id": "ad-001",
        "name": "Secret exfiltration",
        "description": "Ensure the secret is not exfiltrated.",
        "threat_ids": ["ASI01"],
        "threat_categories": ["ASI01", "data-exfiltration"],
    })
    assert isinstance(bc, BenchmarkCase)
    assert bc.benchmark_id == "agentdojo"
    assert bc.case_id == "ad-001"
    assert bc.scenario.threat_categories == ("ASI01", "data-exfiltration")
    assert bc.threat_mapping.threat_ids == ("ASI01",)
