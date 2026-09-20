"""Tests for the SecurityScenario evaluation contract (Commit 25).

SecurityScenario is an EVALUATION contract: it describes expected security
behavior and properties. It must NOT perform analysis, build graphs, construct
AttackPaths, infer threats/attack types/risk/severity/confidence, resolve the
OWASP catalog, or make network requests.
"""

import json

import pytest

from veyra.threats import (
    SecurityScenario,
    ThreatModelError,
    ThreatSource,
    ThreatScenario,
    serialize_security_scenario,
)


def _scenario(**kw):
    base = dict(
        scenario_id="esc-1",
        name="Secret Exfil Evaluation",
        description="Expected: secret stays confidential, no external send.",
        threat_categories=("ASI01", "data-exfiltration"),
        attack_behaviors=("reads-secret", "sends-to-endpoint"),
        entry_conditions=("has-secret", "has-network"),
        expected_security_properties=("no-exfiltration", "secret-confidentiality"),
    )
    base.update(kw)
    return SecurityScenario(**base)


# 1. construction with valid data
def test_construction():
    s = _scenario()
    assert s.scenario_id == "esc-1"
    assert s.name == "Secret Exfil Evaluation"
    assert s.description == "Expected: secret stays confidential, no external send."
    assert s.threat_categories == ("ASI01", "data-exfiltration")


# 2. frozen / immutable behavior
def test_frozen():
    s = _scenario()
    with pytest.raises(AttributeError):
        s.name = "other"  # type: ignore[misc]


def test_tuple_immutable():
    s = _scenario()
    with pytest.raises(AttributeError):
        s.threat_categories = ("x",)  # type: ignore[misc]


# 3. required string validation
def test_empty_required_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(scenario_id="")


def test_whitespace_required_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(name="   ")


def test_whitespace_normalized_on_required():
    s = _scenario(scenario_id="  esc-1  ")
    assert s.scenario_id == "esc-1"


# 4. invalid runtime types
def test_non_string_id_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(scenario_id=123)


def test_non_string_tuple_element_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(threat_categories=("a", 5))


def test_non_sequence_tuple_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(threat_categories="ASI01")  # a bare string, not a sequence


def test_bad_source_type_rejected():
    with pytest.raises(ThreatModelError):
        _scenario(source="OWASP")


# 5. deterministic tuple normalization +
# 7. whitespace trimming +
# 8. deterministic ordering
def test_tuple_normalization():
    s = _scenario(threat_categories=(" z ", "ASI01", " a", "ASI01", ""))
    # trimmed, non-empty-only, deduplicated, sorted
    assert s.threat_categories == ("ASI01", "a", "z")


# 6. duplicate removal
def test_duplicate_removal():
    s = _scenario(attack_behaviors=("r", "r", "r"))
    assert s.attack_behaviors == ("r",)


# empty optional collections default to ()
def test_empty_optional_collections():
    s = SecurityScenario(scenario_id="x", name="n", description="d")
    assert s.threat_categories == ()
    assert s.attack_behaviors == ()
    assert s.entry_conditions == ()
    assert s.expected_security_properties == ()
    assert s.source is None


# 9. optional ThreatSource
def test_optional_source():
    src = ThreatSource(name="Internal", version="1.0", reference="ref://internal")
    s = _scenario(source=src)
    assert s.source is src


# 10. deterministic serialization
def test_serialization_deterministic():
    s = _scenario()
    assert serialize_security_scenario(s) == serialize_security_scenario(s)


# 11. JSON-safe serialization
def test_serialization_json_safe():
    s = _scenario()
    d = serialize_security_scenario(s)
    assert json.loads(json.dumps(d)) == d
    assert d["threat_categories"] == ["ASI01", "data-exfiltration"]


# source serialization and omission when absent
def test_source_serialization():
    s = _scenario(source=ThreatSource(name="OWASP", version="2026", reference="ref"))
    d = serialize_security_scenario(s)
    assert d["source"] == {"name": "OWASP", "version": "2026", "reference": "ref"}
    assert "source" not in serialize_security_scenario(_scenario())


# 12. no implicit OWASP lookup
def test_no_implicit_owasp_lookup():
    from veyra.threats.catalogs import get_owasp_agentic_2026
    s = _scenario(threat_categories=("ASI01", "ASI999-NOT-A-REAL-ID"))
    # Construction must succeed even with an unknown category -> no auto-resolution.
    assert "ASI999-NOT-A-REAL-ID" in s.threat_categories


# 13. no implicit ThreatScenario conversion
def test_no_implicit_threatscenario_conversion():
    s = _scenario()
    assert not isinstance(s, ThreatScenario)
    assert not hasattr(s, "to_threat_scenario")
    # SecurityScenario is a distinct type.
    d = serialize_security_scenario(s)
    assert "threat_categories" in d


# test: logically equivalent objects serialize identically despite different
# input ordering/whitespace padding
def test_logically_equivalent_serialize_identically():
    a = _scenario(threat_categories=("ASI02", "asi01", "ASI02", "  asi01  "))
    b = _scenario(threat_categories=("  asi01 ", "ASI02"))
    assert a.threat_categories == b.threat_categories
    assert serialize_security_scenario(a) == serialize_security_scenario(b)


# 14. no graph/path mutation
def test_no_attack_path_mutation():
    from veyra.graph.path import AttackPath, AttackType, assess_risk, path_id_of
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


def test_no_graph_mutation():
    from veyra.graph import EdgeType, Node, NodeType, SecurityGraph
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="DATA:x", type=NodeType.DATA))
    g.add_edge("SKILL:A", "DATA:x", EdgeType.READS)
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    _scenario()
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# 15. public import/export
def test_public_api_exports():
    from veyra import threats
    for name in ("SecurityScenario", "serialize_security_scenario"):
        assert hasattr(threats, name), f"missing {name}"


# no mutable state exposed
def test_no_mutable_defaults():
    s1 = _scenario(threat_categories=("a",))
    s2 = SecurityScenario(scenario_id="x", name="n", description="d")
    assert s1.threat_categories == ("a",)
    assert s2.threat_categories == ()


# no risk/severity/confidence/attack-type fields
def test_no_risk_or_analysis_fields():
    s = _scenario()
    d = serialize_security_scenario(s)
    for banned in ("risk", "severity", "confidence", "attack_type", "policy",
                   "score", "winner", "model_output", "graph", "path_id"):
        assert banned not in d, f"unexpected field {banned}"
    for attr in ("risk_score", "severity", "confidence", "attack_type", "policy_ids"):
        assert not hasattr(s, attr), f"unexpected attr {attr}"
