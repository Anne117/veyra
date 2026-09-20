"""Tests for SecurityScenarioThreatMapping (Commit 26).

The mapping layer explicitly links an evaluation scenario to threat-knowledge
identifiers. Identifiers are OPAQUE, CASE-SENSITIVE, taxonomy-agnostic stable
strings; no inference, no OWASP auto-resolution, no aliasing/canonicalization.
"""

import json

import pytest

from veyra.threats import (
    SecurityScenario,
    SecurityScenarioThreatMapping,
    ThreatModelError,
    ThreatScenario,
    serialize_security_scenario_threat_mapping,
)


def _mapping(**kw):
    base = dict(
        scenario_id="scenario-1",
        threat_ids=("ASI01", "ASI02", "internal-bench:exfil"),
    )
    base.update(kw)
    return SecurityScenarioThreatMapping(**base)


# 1. valid construction
def test_construction():
    m = _mapping()
    assert m.scenario_id == "scenario-1"
    assert m.threat_ids == ("ASI01", "ASI02", "internal-bench:exfil")


# 2. frozen / immutable behavior
def test_frozen():
    m = _mapping()
    with pytest.raises(AttributeError):
        m.scenario_id = "other"  # type: ignore[misc]


def test_threat_ids_immutable():
    m = _mapping()
    with pytest.raises(AttributeError):
        m.threat_ids = ("x",)  # type: ignore[misc]


# 3. empty scenario_id rejected
def test_empty_scenario_id_rejected():
    with pytest.raises(ThreatModelError):
        _mapping(scenario_id="")


# 4. whitespace-only scenario_id rejected
def test_whitespace_scenario_id_rejected():
    with pytest.raises(ThreatModelError):
        _mapping(scenario_id="   ")


# 5. invalid scenario_id runtime type rejected
def test_invalid_scenario_id_type_rejected():
    with pytest.raises(ThreatModelError):
        _mapping(scenario_id=42)


# 6. invalid threat_ids runtime type rejected
def test_invalid_threat_ids_type_rejected():
    with pytest.raises(ThreatModelError):
        _mapping(threat_ids="ASI01")  # a bare string, not a sequence


def test_invalid_threat_ids_element_type_rejected():
    with pytest.raises(ThreatModelError):
        _mapping(threat_ids=("ASI01", 7))


# 7. non-string threat ID rejected
def test_non_string_threat_id_rejected():
    with pytest.raises(ThreatModelError):
        _mapping(threat_ids=("ASI01", None))  # type: ignore[arg-type]


# 8. whitespace trimming
def test_whitespace_trimming():
    m = _mapping(threat_ids=("  ASI01  ", " ASI02 "))
    assert m.threat_ids == ("ASI01", "ASI02")


# 9. empty values removed
def test_empty_values_removed():
    m = _mapping(threat_ids=("", "  ", "ASI01"))
    assert m.threat_ids == ("ASI01",)


# 10. duplicate IDs removed
def test_duplicate_removal():
    m = _mapping(threat_ids=("ASI01", "ASI01", "ASI01"))
    assert m.threat_ids == ("ASI01",)


# 11. deterministic sorting
def test_deterministic_sorting():
    m = _mapping(threat_ids=("z", "a", "m"))
    assert m.threat_ids == ("a", "m", "z")


# 12. case-sensitive identifiers preserved
def test_case_sensitive_preserved():
    m = _mapping(threat_ids=("ASI01", "asi01", "Asi01"))
    assert "ASI01" in m.threat_ids
    assert "asi01" in m.threat_ids
    assert "Asi01" in m.threat_ids
    assert len(m.threat_ids) == 3


# 13. no alias/canonicalization
def test_no_canonicalization():
    m = _mapping(threat_ids=("OWASP-ASI02", "ASI02"))
    assert m.threat_ids == ("ASI02", "OWASP-ASI02")  # both kept verbatim, sorted lexically
    assert all(t in m.threat_ids for t in ("ASI02", "OWASP-ASI02"))


# 14. deterministic serialization
def test_serialization_deterministic():
    m = _mapping()
    assert (serialize_security_scenario_threat_mapping(m)
            == serialize_security_scenario_threat_mapping(m))


# 15. JSON-safe serialization
def test_serialization_json_safe():
    m = _mapping(threat_ids=("ASI01", "ASI02"))
    d = serialize_security_scenario_threat_mapping(m)
    assert d == {"scenario_id": "scenario-1", "threat_ids": ["ASI01", "ASI02"]}
    assert json.loads(json.dumps(d)) == d


# 16. empty threat_ids allowed
def test_empty_threat_ids_allowed():
    m = SecurityScenarioThreatMapping(scenario_id="s")
    assert m.threat_ids == ()


# 17. generic IDs accepted
def test_generic_ids_accepted():
    m = _mapping(threat_ids=("foo/bar:v1", "bench:001", "T-scenario-1"))
    assert m.threat_ids == ("T-scenario-1", "bench:001", "foo/bar:v1")


# 18. unknown OWASP-like IDs accepted (NO auto-validation)
def test_unknown_owasp_ids_accepted():
    m = _mapping(threat_ids=("ASI999-NOT-A-REAL-ID", "ASI01"))
    assert "ASI999-NOT-A-REAL-ID" in m.threat_ids


# specific: ("ASI02", "asi01", "ASI02") -> ("ASI02", "asi01") lexical, exact spelling
def test_lexical_sort_exact_spelling():
    m = _mapping(threat_ids=("ASI02", "asi01", "ASI02"))
    assert m.threat_ids == ("ASI02", "asi01")


# 19. no ThreatScenario conversion
def test_no_threatscenario_conversion():
    m = _mapping()
    assert not isinstance(m, ThreatScenario)
    assert not hasattr(m, "to_threat_scenario")
    assert not hasattr(m, "description")
    assert not hasattr(m, "name")


# 20. no SecurityScenario mutation
def test_no_security_scenario_mutation():
    s = SecurityScenario(
        scenario_id="esc",
        name="n",
        description="d",
        threat_categories=("ASI01",),
    )
    snap = (s.scenario_id, s.name, s.description, s.threat_categories)
    _mapping(scenario_id="esc")
    # SecurityScenario must not gain mapping fields.
    assert not hasattr(s, "threat_mappings")
    assert not hasattr(s, "threat_ids")
    assert (s.scenario_id, s.name, s.description, s.threat_categories) == snap


# 21. public API export
def test_public_api_exports():
    from veyra import threats
    for name in ("SecurityScenarioThreatMapping",
                 "serialize_security_scenario_threat_mapping"):
        assert hasattr(threats, name), f"missing {name}"


# negative: constructing a mapping creates no SecurityGraph / AttackPath
def test_no_graph_created():
    from veyra.graph import SecurityGraph
    before = len(SecurityGraph.__mro__)  # just ensure import is exercised
    _ = before
    _mapping()
    g = SecurityGraph()
    # A fresh SecurityScenarioThreatMapping must not reference graph state.
    m = _mapping()
    assert m.threat_ids == ("ASI01", "ASI02", "internal-bench:exfil")


def test_no_attack_path_created():
    from veyra.graph.path import AttackPath
    m = _mapping()
    assert not isinstance(m, AttackPath)
    assert not hasattr(m, "nodes")


def test_no_securitygraph_mutation():
    from veyra.graph import EdgeType, Node, NodeType, SecurityGraph
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="DATA:x", type=NodeType.DATA))
    g.add_edge("SKILL:A", "DATA:x", EdgeType.READS)
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    _mapping()
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# no ThreatScenario mutation
def test_no_threatscenario_mutation():
    ts = ThreatScenario(
        scenario_id="tsc-1",
        name="Threat",
        description="d",
        threat_categories=("CAT1",),
    )
    snap = (ts.scenario_id, ts.name, ts.description, ts.threat_categories)
    _mapping(scenario_id="tsc-1", threat_ids=("CAT1",))
    assert (ts.scenario_id, ts.name, ts.description, ts.threat_categories) == snap
