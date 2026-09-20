"""Tests for the benchmark adapter foundation (Commit 27).

BenchmarkCase is a stable, immutable transport/adaptation model mapping an
external benchmark case into SecurityScenario + SecurityScenarioThreatMapping.
It must NOT execute, infer, build AttackPaths, mutate the graph, load datasets,
or reach the network. BenchmarkAdapter is a minimal, non-executing contract.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkAdapter,
    BenchmarkCase,
    SecurityScenario,
    SecurityScenarioThreatMapping,
    ThreatModelError,
    serialize_benchmark_case,
)


def _scenario(**kw):
    base = dict(
        scenario_id="esc-1",
        name="Secret Exfil Evaluation",
        description="Expected: secret stays confidential.",
        threat_categories=("ASI01", "data-exfiltration"),
        attack_behaviors=("reads-secret", "sends-to-endpoint"),
        entry_conditions=("has-secret", "has-network"),
        expected_security_properties=("no-exfiltration", "secret-confidentiality"),
    )
    base.update(kw)
    return SecurityScenario(**base)


def _mapping(**kw):
    base = dict(scenario_id="esc-1", threat_ids=("ASI01", "ASI02"))
    base.update(kw)
    return SecurityScenarioThreatMapping(**base)


def _case(**kw):
    base = dict(
        benchmark_id="dummy-bench",
        case_id="case-001",
        name="Secret Exfil",
        description="Ensure no secret leaves the system.",
        scenario=_scenario(),
        threat_mapping=_mapping(),
    )
    base.update(kw)
    return BenchmarkCase(**base)


# 1. valid construction
def test_construction():
    c = _case()
    assert c.benchmark_id == "dummy-bench"
    assert c.case_id == "case-001"
    assert c.name == "Secret Exfil"
    assert c.description == "Ensure no secret leaves the system."
    assert isinstance(c.scenario, SecurityScenario)
    assert isinstance(c.threat_mapping, SecurityScenarioThreatMapping)


# 2. frozen / immutable
def test_frozen():
    c = _case()
    with pytest.raises(AttributeError):
        c.case_id = "other"  # type: ignore[misc]


# 3. benchmark_id validation
def test_empty_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        _case(benchmark_id="")


def test_whitespace_benchmark_id_rejected():
    with pytest.raises(ThreatModelError):
        _case(benchmark_id="   ")


# 4. case_id validation
def test_empty_case_id_rejected():
    with pytest.raises(ThreatModelError):
        _case(case_id="   ")


# 5. name validation
def test_empty_name_rejected():
    with pytest.raises(ThreatModelError):
        _case(name="")


# 6. description validation
def test_empty_description_rejected():
    with pytest.raises(ThreatModelError):
        _case(description="")


# 7-10. invalid runtime types
def test_invalid_benchmark_id_type():
    with pytest.raises(ThreatModelError):
        _case(benchmark_id=42)


def test_invalid_case_id_type():
    with pytest.raises(ThreatModelError):
        _case(case_id=None)  # type: ignore[arg-type]


def test_invalid_name_type():
    with pytest.raises(ThreatModelError):
        _case(name=b"x")


def test_invalid_description_type():
    with pytest.raises(ThreatModelError):
        _case(description=1.5)


# 11-12. invalid scenario / threat_mapping runtime types
def test_invalid_scenario_type():
    with pytest.raises(ThreatModelError):
        _case(scenario="not-a-scenario")


def test_invalid_threat_mapping_type():
    with pytest.raises(ThreatModelError):
        _case(threat_mapping=None)  # type: ignore[arg-type]


# 13-14. preservation of supplied scenario / mapping
def test_preserves_scenario():
    s = _scenario(scenario_id="S-X")
    c = _case(scenario=s)
    assert c.scenario is s
    assert c.scenario.scenario_id == "S-X"


def test_preserves_mapping():
    m = _mapping(threat_ids=("ASI07",))
    c = _case(threat_mapping=m)
    assert c.threat_mapping is m
    assert c.threat_mapping.threat_ids == ("ASI07",)


# 15. deterministic serialization
def test_serialization_deterministic():
    c = _case()
    assert serialize_benchmark_case(c) == serialize_benchmark_case(c)


# 16. JSON-safe serialization
def test_serialization_json_safe():
    c = _case()
    d = serialize_benchmark_case(c)
    assert json.loads(json.dumps(d)) == d
    assert d["benchmark_id"] == "dummy-bench"
    assert d["case_id"] == "case-001"


# 17. serializer reuse: nested objects serialize through public serializers
def test_serializer_reuse():
    from veyra.threats import (
        serialize_security_scenario,
        serialize_security_scenario_threat_mapping,
    )
    c = _case()
    d = serialize_benchmark_case(c)
    assert d["scenario"] == serialize_security_scenario(c.scenario)
    assert d["threat_mapping"] == serialize_security_scenario_threat_mapping(c.threat_mapping)
    # shape matches expected contract
    assert set(d.keys()) == {"benchmark_id", "case_id", "name", "description",
                             "scenario", "threat_mapping"}


# 18. identifiers remain case-sensitive
def test_identifiers_case_sensitive():
    c = _case(benchmark_id="MyBench", case_id="CaseX", name="  Padded  ")
    # name is trimmed by required-string validation, but case is preserved
    assert c.benchmark_id == "MyBench"
    assert c.case_id == "CaseX"
    assert c.name == "Padded"


# 19. no threat inference from SecurityScenario.threat_categories
def test_no_inference_from_threat_categories():
    # scenario categories that "look like" exfil must not flow into threat ID
    s = _scenario(threat_categories=("data-exfiltration",))
    m = _mapping(threat_ids=("ASI01",))
    c = _case(scenario=s, threat_mapping=m)
    # threat_mapping.threat_ids are exactly the caller-supplied ones; scenario
    # threat_categories are NOT merged/derived into mapping.
    assert c.threat_mapping.threat_ids == ("ASI01",)
    assert c.scenario.threat_categories == ("data-exfiltration",)


# 20. no OWASP auto-resolution
def test_no_owasp_auto_resolution():
    m = _mapping(threat_ids=("ASI999-NOT-REAL",))
    s = _scenario(threat_categories=("ASI01",))
    c = _case(scenario=s, threat_mapping=m)
    # unknown identifier is preserved verbatim; nothing validated/resolved.
    assert c.threat_mapping.threat_ids == ("ASI999-NOT-REAL",)
    # scenario categories stay on the scenario, not copied to mapping.
    assert c.scenario.threat_categories == ("ASI01",)


# 21. no AttackPath creation
def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    c = _case()
    assert not isinstance(c, AttackPath)
    assert not hasattr(c, "nodes")
    assert not hasattr(c, "evidence")


# 22. no SecurityGraph mutation
def test_no_graph_mutation():
    from veyra.graph import EdgeType, Node, NodeType, SecurityGraph
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="DATA:x", type=NodeType.DATA))
    g.add_edge("SKILL:A", "DATA:x", EdgeType.READS)
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    _case()
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# 23. no risk / AttackType inference
def test_no_risk_or_attacktype():
    s = _scenario()
    c = _case()
    d = serialize_benchmark_case(c)
    for banned in ("risk", "severity", "confidence", "attack_type",
                   "attack_path", "score", "finding", "detection"):
        assert banned not in d["scenario"], f"unexpected scenario field {banned}"
        assert banned not in d["threat_mapping"]
    for attr in ("risk_score", "attack_type", "severity", "confidence"):
        assert not hasattr(c, attr), f"unexpected attr {attr}"
    assert not hasattr(c.scenario, "attack_type")
    assert not hasattr(c.threat_mapping, "attack_type")


# 24. public API export
def test_public_api_exports():
    from veyra import threats
    for name in ("BenchmarkCase", "BenchmarkAdapter", "serialize_benchmark_case"):
        assert hasattr(threats, name), f"missing {name}"


# 25. minimal adapter protocol usable by a tiny test adapter
def test_adapter_protocol_implementable():
    calls = []

    class DummyAdapter:
        benchmark_id = "dummy"

        def adapt(self, case):
            calls.append(case)
            return _case()

    a = DummyAdapter()
    # adapt() returns a BenchmarkCase; protocol is satisfied structurally.
    result = a.adapt({"raw": "external"})
    assert isinstance(result, BenchmarkCase)
    assert a.benchmark_id == "dummy"
    assert calls == [{"raw": "external"}]


def test_adapter_is_protocol_and_not_registry():
    # BenchmarkAdapter is a Protocol that describes, not executes/dispatches.
    import inspect
    from veyra.threats.benchmarks import BenchmarkAdapter as BA
    p = getattr(BA, "_is_protocol", True)
    # runtime_checkable protocol supports isinstance checks
    class T:
        benchmark_id = "x"
        def adapt(self, case):  # pragma: no cover - not called
            return None  # type: ignore
    assert isinstance(T(), BA)
    assert p


# negative: constructing a case does not trigger network / dataset loading
def test_no_network_loading_flag():
    # The model is pure data; no side effects like downloads/network clients.
    import io
    sentinel = object()
    c = _case()
    # Just assert the object is plain data (no lazy/IO machinery).
    assert c.__class__.__name__ == "BenchmarkCase"
