"""Tests for explicit security-behavior component context (Commit 18).

Component context is CONTEXT/SCOPE metadata: it associates an existing
SecurityGraph *security* edge (READS/WRITES/SENDS_TO/EXECUTES/PRODUCES/FLOWS_TO)
with an explicitly declared component (AGENT/SKILL/TOOL/MCPSERVER). It must
never create a security edge, never infer a component, never change path_id /
risk / evidence / breakpoints / policy, and always serialize deterministically.
"""

import json

import pytest

from veyra.graph import (
    SecurityGraph,
    PathAnalyzer,
    Node,
    NodeType,
    EdgeType,
    associate_security_behavior,
    ComponentContext,
    ComponentContextAssociation,
    ComponentContextError,
    get_component_context,
    serialize_component_context,
)
from veyra.models import ScanResult
from veyra.policy import PolicyEngine
from veyra.reporters import render_html, render_json, render_sarif


def _exfil_graph():
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:checkout", type=NodeType.SKILL))
    g.add_node(Node(id="SECRET:.env", type=NodeType.SECRET))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_node(Node(id="AGENT:alice", type=NodeType.AGENT))
    g.add_node(Node(id="TOOL:curl", type=NodeType.TOOL))
    g.add_node(Node(id="MCPSERVER:filesystem", type=NodeType.MCPSERVER))
    g.add_edge("SKILL:checkout", "SECRET:.env", EdgeType.READS,
               attributes={"files": ["skill/SKILL.md"]})
    g.add_edge("SECRET:.env", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO,
               attributes={"files": ["skill/SKILL.md"]})
    return g


READS = ("SKILL:checkout", "SECRET:.env", EdgeType.READS)


# A. Basic association -------------------------------------------------------
def test_associate_security_behavior_happy_path():
    g = _exfil_graph()
    before = len(g.edges)
    a = associate_security_behavior(g, READS,
                                    ComponentContext("SKILL:checkout", NodeType.SKILL),
                                    source="scope.yaml")
    # Edge count unchanged — no new security edge.
    assert len(g.edges) == before
    assert isinstance(a, ComponentContextAssociation)
    assert a.component.component_id == "SKILL:checkout"
    assert a.edge_key[2] == EdgeType.READS
    # Attached to the path as metadata.
    p = PathAnalyzer(g).analyze()[0]
    assert p.context_components and p.context_components[0]["component_id"] == "SKILL:checkout"


# B. Graph edge unchanged, no new edge ----------------------------------------
def test_no_new_graph_edge_created():
    g = _exfil_graph()
    before = [e for e in g.edges]
    associate_security_behavior(g, READS, ComponentContext("TOOL:curl", NodeType.TOOL))
    assert [e for e in g.edges] == before
    assert len(g.edges) == len(before)


# C. Cross-component: SKILL owns REWADS, agent NOT inferred --------------------
def test_skill_context_no_agent_inference():
    g = _exfil_graph()
    # Declare AGENT:alice --USES--> SKILL:checkout explicitly.
    from veyra.graph import apply_component_declarations, RelationshipDeclaration
    apply_component_declarations(g, [],
        [RelationshipDeclaration("AGENT:alice", "SKILL:checkout", EdgeType.USES)])
    # Associate READS only with the SKILL.
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL))
    p = PathAnalyzer(g).analyze()[0]
    # Agent is NOT inferred from USES.
    assert all(c["component_id"] != "AGENT:alice" for c in p.context_components)
    assert any(c["component_id"] == "SKILL:checkout" for c in p.context_components)


# D. Multiple contexts survive + explicit both -------------------------------
def test_multiple_contexts_survive():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL))
    associate_security_behavior(g, READS, ComponentContext("AGENT:alice", NodeType.AGENT))
    p = PathAnalyzer(g).analyze()[0]
    comps = {c["component_id"] for c in p.context_components}
    assert comps == {"SKILL:checkout", "AGENT:alice"}


# E. Idempotency --------------------------------------------------------------
def test_duplicate_association_idempotent():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL))
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL))
    assert len(get_component_context(g)) == 1
    # Different explicit association (agent) also survives.
    associate_security_behavior(g, READS, ComponentContext("AGENT:alice", NodeType.AGENT))
    assert len(get_component_context(g)) == 2


# F. Validation: missing component --------------------------------------------
def test_missing_component_rejected():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, READS, ComponentContext("SKILL:nope", NodeType.SKILL))


# G. Validation: missing security edge ---------------------------------------
def test_missing_security_edge_rejected():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, ("SKILL:checkout", "MCPSERVER:filesystem", EdgeType.READS),
                                    ComponentContext("SKILL:checkout", NodeType.SKILL))


# H. Validation: component type restricted -----------------------------------
def test_data_secret_endpoint_action_component_rejected():
    g = _exfil_graph()
    for bad in (NodeType.DATA, NodeType.SECRET, NodeType.ENDPOINT, NodeType.ACTION):
        with pytest.raises(ComponentContextError):
            ComponentContext("X:x", bad)


# I. Validation: component type mismatch --------------------------------------
def test_component_type_mismatch_rejected():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        # SKILL:a declared but type says AGENT.
        associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.AGENT))


# J. Validation: invalid edge type (component relationship) ------------------
def test_component_relationship_not_behavior_rejected():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, ("SKILL:checkout", "TOOL:curl", EdgeType.USES),
                                    ComponentContext("SKILL:checkout", NodeType.SKILL))
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, ("AGENT:alice", "TOOL:curl", EdgeType.TRUSTS),
                                    ComponentContext("TOOL:curl", NodeType.TOOL))


# K. Validation: malformed ids -----------------------------------------------
def test_malformed_ids_rejected():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, ("", "SECRET:.env", EdgeType.READS),
                                    ComponentContext("SKILL:checkout", NodeType.SKILL))
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, READS, ComponentContext("", NodeType.SKILL))


# L. Validation failure leaves graph unchanged --------------------------------
def test_failed_association_leaves_graph_unchanged():
    g = _exfil_graph()
    before_edges = len(g.edges)
    before_context = len(get_component_context(g))
    for call in (
        lambda: associate_security_behavior(g, READS, ComponentContext("SKILL:nope", NodeType.SKILL)),
        lambda: associate_security_behavior(g, ("SKILL:checkout", "MCPSERVER:filesystem", EdgeType.READS),
                                            ComponentContext("SKILL:checkout", NodeType.SKILL)),
    ):
        with pytest.raises(ComponentContextError):
            call()
    assert len(g.edges) == before_edges
    assert len(get_component_context(g)) == before_context


# M. Association provenance separate from edge provenance --------------------
def test_association_provenance_separate():
    g = _exfil_graph()
    # Edge has origin skill/SKILL.md; association source is scope.yaml.
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL),
                                 source="scope.yaml")
    d = serialize_component_context(g)[0]
    assert d["source"] == "scope.yaml"
    # Underlying edge provenance untouched.
    re = [e for e in g.edges if e.type == EdgeType.READS][0]
    assert re.attributes.get("files") == ["skill/SKILL.md"]
    # No association source -> unknown/None.
    associate_security_behavior(g, ("SECRET:.env", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO),
                                ComponentContext("SKILL:checkout", NodeType.SKILL))
    d2 = [x for x in serialize_component_context(g) if x["behavior"]["edge_type"] == "SENDS_TO"][0]
    assert d2["source"] is None


# N. path_id / risk / evidence / breakpoints / policy unchanged ---------------- 
def test_context_does_not_change_attack_path_semantics():
    g1 = _exfil_graph()
    p1 = PathAnalyzer(g1).analyze()[0]
    sn1 = snapshot(p1)

    g2 = _exfil_graph()
    associate_security_behavior(g2, READS, ComponentContext("SKILL:checkout", NodeType.SKILL), source="scope1")
    associate_security_behavior(g2, READS, ComponentContext("AGENT:alice", NodeType.AGENT), source="scope2")
    p2 = PathAnalyzer(g2).analyze()[0]
    assert snapshot(p2) == sn1
    # path_id unchanged despite different context associations.
    assert p1.path_id == p2.path_id


def snapshot(p):
    return (
        p.nodes, p.edges, p.associated_edges, p.attack_type.value,
        p.entry_node, p.asset_node, p.sink_node, p.path_id,
        p.risk_severity.value, p.risk_confidence.value, p.risk_score,
        tuple(p.evidence), tuple(p.policy_ids),
        tuple((b.edge_type, b.reason) for b in p.breakpoints),
    )


# O. Deterministic ordering independent of input order ------------------------
def test_deterministic_order():
    g1 = _exfil_graph()
    associate_security_behavior(g1, READS, ComponentContext("SKILL:checkout", NodeType.SKILL))
    associate_security_behavior(g1, READS, ComponentContext("AGENT:alice", NodeType.AGENT))
    g2 = _exfil_graph()
    associate_security_behavior(g2, READS, ComponentContext("AGENT:alice", NodeType.AGENT))
    associate_security_behavior(g2, READS, ComponentContext("SKILL:checkout", NodeType.SKILL))
    assert serialize_component_context(g1) == serialize_component_context(g2)


# P. JSON contains context ---------------------------------------------------
def test_json_contains_context():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL), source="scope.yaml")
    p = PathAnalyzer(g).analyze()[0]
    result = ScanResult(target="x", attack_paths=[p])
    d = json.loads(render_json(result))
    cc = d["attack_paths"][0]["context_components"]
    assert cc and cc[0]["component_id"] == "SKILL:checkout"
    assert cc[0]["behavior"]["source"] == "SKILL:checkout"
    assert cc[0]["source"] == "scope.yaml"


# Q. SARIF contains context under properties ----------------------------------
def test_sarif_contains_context():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL), source="scope.yaml")
    p = PathAnalyzer(g).analyze()[0]
    result = ScanResult(target="x", attack_paths=[p],
                        policy_results=PolicyEngine().evaluate([p]))
    doc = json.loads(render_sarif(result))
    ap = [r for r in doc["runs"][0]["results"] if r["ruleId"].startswith("ATTACK-PATH")][0]
    assert "security_behavior_context" in ap["properties"]
    assert ap["properties"]["security_behavior_context"][0]["component_id"] == "SKILL:checkout"
    # message.text untouched.
    assert ap["message"]["text"] == p.explanation


# R. HTML contains context + escaping ----------------------------------------
def test_html_contains_context():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:checkout", NodeType.SKILL), source="scope.yaml")
    p = PathAnalyzer(g).analyze()[0]
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "Component Context" in doc
    assert "SKILL:checkout" in doc
    assert "scope.yaml" in doc


def test_html_escapes_hostile_context():
    g = _exfil_graph()
    evil = "<script>alert(1)</script>"
    # Associate the SENDS_TO walk edge with a hostile tool component id + source.
    g.add_node(Node(id="TOOL:" + evil, type=NodeType.TOOL))
    associate_security_behavior(g, ("SECRET:.env", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO),
                                ComponentContext("TOOL:" + evil, NodeType.TOOL),
                                source="<img src=x onerror=alert(1)>")
    p = PathAnalyzer(g).analyze()[0]
    assert any(c["component_id"] == "TOOL:" + evil for c in p.context_components)
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "<script>" not in doc
    assert "<img" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc


# S. Behavior-edge reference safety: fabricated tuple rejected ----------------
def test_fabricated_edge_reference_rejected():
    g = _exfil_graph()
    # Valid-looking but nonexistent edge tuple.
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, ("SKILL:checkout", "SECRET:.env", EdgeType.SENDS_TO),
                                    ComponentContext("SKILL:checkout", NodeType.SKILL))
