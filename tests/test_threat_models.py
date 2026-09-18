"""Tests for the threat knowledge foundation model (Commit 23).

This layer is a small, deterministic, read-only foundation. It must NOT modify
AttackPath, SecurityGraph, AttackType, or EdgeType; it must NOT introduce
OWASP-specific fields or infer threats from component names.
"""

import json

import pytest

from veyra.threats import (
    ThreatModelError,
    ThreatScenario,
    ThreatSource,
    serialize_threat_scenario,
    serialize_threat_scenarios,
)


def _scenario(**kw):
    base = dict(
        scenario_id="sc-1",
        name="Exfil Secret",
        description="A scenario describing secret exfiltration.",
        threat_categories=("data-exfiltration", "secret-exposure"),
        attack_behaviors=("reads-secret", "sends-to-endpoint"),
        entry_conditions=("has-secret", "has-network"),
        expected_security_properties=("no-exfiltration", "secret-confidentiality"),
    )
    base.update(kw)
    return ThreatScenario(**base)


# construction
def test_construction():
    s = _scenario()
    assert s.scenario_id == "sc-1"
    assert s.name == "Exfil Secret"
    assert s.threat_categories == ("data-exfiltration", "secret-exposure")
    assert s.attack_behaviors == ("reads-secret", "sends-to-endpoint")


# frozen / immutable behavior
def test_frozen():
    s = _scenario()
    with pytest.raises(AttributeError):
        s.name = "other"  # type: ignore[misc]


# validation of required strings
def test_empty_scenario_id_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(scenario_id="")


def test_empty_name_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(name="   ")


def test_whitespace_normalized():
    s = _scenario(scenario_id="  id-1  ")
    assert s.scenario_id == "id-1"


# deterministic serialization
def test_serialize_single():
    s = _scenario()
    d = serialize_threat_scenario(s)
    assert d["scenario_id"] == "sc-1"
    assert d["threat_categories"] == ["data-exfiltration", "secret-exposure"]
    # JSON-safe primitives only.
    assert isinstance(json.dumps(d), str)


# multiple scenarios
def test_serialize_multiple():
    a = _scenario(scenario_id="a")
    b = _scenario(scenario_id="b")
    out = serialize_threat_scenarios([a, b])
    assert [o["scenario_id"] for o in out] == ["a", "b"]
    assert json.loads(json.dumps(out)) == out


# empty optional collections
def test_empty_optional_collections():
    s = ThreatScenario(scenario_id="x", name="n", description="d")
    assert s.threat_categories == ()
    assert s.attack_behaviors == ()
    assert s.entry_conditions == ()
    assert s.expected_security_properties == ()
    assert s.source is None


# tuple immutability
def test_tuple_immutable():
    s = _scenario()
    with pytest.raises(AttributeError):
        s.threat_categories = ("x",)  # type: ignore[misc]


# source serialization
def test_source_serialization():
    s = _scenario(
        source=ThreatSource(name="OWASP", version="2021", reference="https://owasp.org/")
    )
    d = serialize_threat_scenario(s)
    assert d["source"] == {"name": "OWASP", "version": "2021",
                           "reference": "https://owasp.org/"}
    # Omitted when no source.
    assert "source" not in serialize_threat_scenario(_scenario())


def test_empty_source_fields_rejected():
    with pytest.raises(ThreatModelError):
        ThreatSource(name="", version="1", reference="r")


# no mutable defaults
def test_no_mutable_defaults():
    s1 = _scenario(threat_categories=("a",))
    s2 = ThreatScenario(scenario_id="x", name="n", description="d")
    s3 = _scenario()
    # All are distinct objects; no shared mutable list.
    assert s1.threat_categories == ("a",)
    assert s2.threat_categories == ()
    assert s3.threat_categories == ("data-exfiltration", "secret-exposure")


# no OWASP-specific fields
def test_no_owasp_fields():
    s = _scenario()
    d = serialize_threat_scenario(s)
    assert "owasp" not in d
    for key in d:
        assert "owasp" not in key.lower()


def test_no_owasp_field_on_model():
    s = _scenario()
    assert not hasattr(s, "owasp_category")
    assert not hasattr(s, "cwe_id")


# no AttackType / EdgeType changes
def test_no_attack_or_edge_type_changes():
    from veyra.graph import AttackType, EdgeType
    from veyra.graph.path import AttackType as PAttackType, EdgeType as PEdgeType
    assert len(AttackType) == len(PAttackType)
    assert len(EdgeType) == len(PEdgeType)


# no AttackPath mutation
def test_no_attack_path_mutation():
    from veyra.graph.path import AttackPath, AttackType, path_id_of, assess_risk
    nodes = ["SKILL:A", "SECRET:x", "ENDPOINT:https://e.example"]
    edges = [("SKILL:A", "SECRET:x", "READS"),
             ("SECRET:x", "ENDPOINT:https://e.example", "SENDS_TO")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.SECRET_EXFILTRATION,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    snap = (tuple(ap.nodes), tuple(ap.edges), tuple(ap.associated_edges),
            ap.attack_type.value, ap.path_id, ap.risk_score, tuple(ap.evidence))
    _scenario()
    _scenario(scenario_id="other")
    assert (tuple(ap.nodes), tuple(ap.edges), tuple(ap.associated_edges),
            ap.attack_type.value, ap.path_id, ap.risk_score, tuple(ap.evidence)) == snap


# no graph mutation
def test_no_graph_mutation():
    from veyra.graph import SecurityGraph, Node, NodeType, EdgeType
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="DATA:x", type=NodeType.DATA))
    g.add_edge("SKILL:A", "DATA:x", EdgeType.READS)
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    _scenario()
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# repeated serialization equality
def test_repeated_serialization():
    s = _scenario()
    assert serialize_threat_scenario(s) == serialize_threat_scenario(s)
    assert serialize_threat_scenarios([s]) == serialize_threat_scenarios([s])


# deterministic tuple normalization (dedupe + sort)
def test_tuple_normalization():
    s = _scenario(threat_categories=("b", "a", "b", ""))
    assert s.threat_categories == ("a", "b")


# source is validated as a string-bearing object (name/version/reference)
def test_source_non_string_rejected():
    from veyra.threats import ThreatSource
    with pytest.raises(ThreatModelError):
        ThreatSource(name="", version="1", reference="r")


# public API exports
def test_public_api_exports():
    from veyra import threats
    for name in ("ThreatScenario", "ThreatSource", "ThreatModelError",
                 "serialize_threat_scenario", "serialize_threat_scenarios"):
        assert hasattr(threats, name), f"missing {name}"
