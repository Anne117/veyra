"""Tests for ComponentSecurityScope (Commit 19).

ComponentSecurityScope is a deterministic, read-only aggregation of the
explicit ComponentContextAssociation metadata. It is NOT a graph edge, NOT an
ownership inference engine, and NOT a new attack-path type. It must never
infer component ownership from USES/CONTAINS/CALLS/TRUSTS/HANDOFF, file paths,
node ids, provenance, labels, findings, or naming — only explicit associations
establish it.
"""

import json

import pytest

from veyra.graph import (
    SecurityGraph,
    Node,
    NodeType,
    EdgeType,
    associate_security_behavior,
    ComponentContext,
    ComponentContextAssociation,
    ComponentContextError,
    ComponentSecurityScope,
    build_component_security_scopes,
    serialize_component_security_scopes,
    apply_component_declarations,
    RelationshipDeclaration,
    ComponentDeclaration,
    PathAnalyzer,
)
from veyra.models import ScanResult
from veyra.reporters import render_html, render_sarif, render_json


def _exfil_graph():
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="AGENT:B", type=NodeType.AGENT))
    g.add_node(Node(id="TOOL:C", type=NodeType.TOOL))
    g.add_node(Node(id="SECRET:x", type=NodeType.SECRET))
    g.add_node(Node(id="ENDPOINT:evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:A", "SECRET:x", EdgeType.READS)
    g.add_edge("SECRET:x", "ENDPOINT:evil.example", EdgeType.SENDS_TO)
    return g


READS = ("SKILL:A", "SECRET:x", EdgeType.READS)
SENDS_TO = ("SECRET:x", "ENDPOINT:evil.example", EdgeType.SENDS_TO)


# 1. empty graph / no context => []
def test_empty_scopes():
    g = _exfil_graph()
    assert build_component_security_scopes(g) == []
    assert serialize_component_security_scopes(g) == []
    # A completely fresh graph likewise yields [].
    assert build_component_security_scopes(SecurityGraph()) == []


# 2. one component + one security behavior
def test_one_component_one_behavior():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    scopes = build_component_security_scopes(g)
    assert len(scopes) == 1
    s = scopes[0]
    assert isinstance(s, ComponentSecurityScope)
    assert s.component.component_id == "SKILL:A"
    assert s.component.component_type == NodeType.SKILL
    assert s.security_behaviors == (("SKILL:A", "READS", "SECRET:x"),)


# 3. one component + multiple security behaviors
def test_one_component_multiple_behaviors():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    associate_security_behavior(g, SENDS_TO, ComponentContext("SKILL:A", NodeType.SKILL))
    scopes = build_component_security_scopes(g)
    assert len(scopes) == 1
    assert scopes[0].security_behaviors == (
        ("SECRET:x", "SENDS_TO", "ENDPOINT:evil.example"),
        ("SKILL:A", "READS", "SECRET:x"),
    )


# 4. multiple components associated with same security edge => independent scopes
def test_multiple_components_same_edge():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    associate_security_behavior(g, READS, ComponentContext("AGENT:B", NodeType.AGENT))
    associate_security_behavior(g, READS, ComponentContext("TOOL:C", NodeType.TOOL))
    scopes = build_component_security_scopes(g)
    # Three independent scopes — never merged into one owner.
    assert len(scopes) == 3
    ids = {s.component.component_id for s in scopes}
    assert ids == {"SKILL:A", "AGENT:B", "TOOL:C"}
    for s in scopes:
        assert s.security_behaviors == (("SKILL:A", "READS", "SECRET:x"),)


# 5. duplicate semantic associations deduplicated
def test_duplicates_deduplicated():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL), source="s1")
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL), source="s2")
    scopes = build_component_security_scopes(g)
    assert len(scopes) == 1
    # One behavior regardless of differing provenance.
    assert scopes[0].security_behaviors == (("SKILL:A", "READS", "SECRET:x"),)
    assert len(scopes[0].security_behaviors) == 1


# 6. deterministic ordering regardless of insertion order
def test_deterministic_ordering():
    g1 = _exfil_graph()
    associate_security_behavior(g1, SENDS_TO, ComponentContext("SKILL:A", NodeType.SKILL))
    associate_security_behavior(g1, READS, ComponentContext("SKILL:A", NodeType.SKILL))

    g2 = _exfil_graph()
    associate_security_behavior(g2, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    associate_security_behavior(g2, SENDS_TO, ComponentContext("SKILL:A", NodeType.SKILL))

    assert serialize_component_security_scopes(g1) == serialize_component_security_scopes(g2)
    assert json.dumps(serialize_component_security_scopes(g1)) == \
        json.dumps(serialize_component_security_scopes(g2))


# 7. only allowed security behavior edge types accepted (already validated upstream,
#    but scope builder emits only those that pass)
def test_only_security_behavior_types():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    associate_security_behavior(g, SENDS_TO, ComponentContext("SKILL:A", NodeType.SKILL))
    s = serialize_component_security_scopes(g)[0]
    edge_types = {b["edge_type"] for b in s["security_behaviors"]}
    assert edge_types <= {"READS", "WRITES", "SENDS_TO", "EXECUTES", "PRODUCES", "FLOWS_TO"}


# 8. component relationship edges never appear as security behaviors
def test_component_relationships_never_behaviors():
    g = _exfil_graph()
    # A component-relationship edge exists in the graph but is never associable
    # as security behavior; the association API rejects it.
    from veyra.graph import ComponentDeclaration
    apply_component_declarations(
        g,
        [ComponentDeclaration("SKILL:A", NodeType.SKILL), ComponentDeclaration("TOOL:C", NodeType.TOOL)],
        [RelationshipDeclaration("SKILL:A", "TOOL:C", EdgeType.USES)],
    )
    with pytest.raises(ComponentContextError):
        associate_security_behavior(g, ("SKILL:A", "TOOL:C", EdgeType.USES),
                                    ComponentContext("SKILL:A", NodeType.SKILL))
    # No scope exists from the USES edge.
    assert build_component_security_scopes(g) == []


# 9. no inference from AGENT USES SKILL
def test_no_ownership_inference_from_uses():
    g = _exfil_graph()
    apply_component_declarations(
        g,
        [ComponentDeclaration("AGENT:B", NodeType.AGENT), ComponentDeclaration("SKILL:A", NodeType.SKILL)],
        [RelationshipDeclaration("AGENT:B", "SKILL:A", EdgeType.USES)],
    )
    # Only the SKILL is explicitly associated with the READS.
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    scopes = build_component_security_scopes(g)
    assert len(scopes) == 1
    assert scopes[0].component.component_id == "SKILL:A"
    # AGENT:B must NOT appear — ownership is never inferred from USES.
    assert all(s.component.component_id != "AGENT:B" for s in scopes)


# 10. only explicit ComponentContextAssociation creates scope
def test_only_explicit_association_creates_scope():
    g = _exfil_graph()
    # No association at all.
    assert build_component_security_scopes(g) == []
    # A component declared but NOT associated => still no scope.
    apply_component_declarations(
        g,
        [ComponentDeclaration("AGENT:B", NodeType.AGENT)],
        [],
    )
    assert build_component_security_scopes(g) == []


# 11. all referenced behavior edges actually exist
def test_referenced_edges_exist():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    # All referenced edges exist => builds fine.
    assert len(build_component_security_scopes(g)) == 1


# 12. invalid/stale context handled deterministically (raises)
def test_stale_metadata_raises():
    g = _exfil_graph()
    # Manually craft a stale association referencing a nonexistent edge and
    # place it directly on the graph.
    stale = ComponentContextAssociation(
        edge_key=("SKILL:A", "ENDPOINT:evil.example", EdgeType.READS),
        component=ComponentContext("SKILL:A", NodeType.SKILL),
    )
    g._component_context = [stale]
    with pytest.raises(ComponentContextError):
        build_component_security_scopes(g)


# 13. graph unchanged after scope building
def test_graph_unchanged():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    nodes_before = list(g.nodes.keys())
    edges_before = [(e.source, e.target, e.type) for e in g.edges]
    ctx_before = list(getattr(g, "_component_context", []))
    build_component_security_scopes(g)
    assert list(g.nodes.keys()) == nodes_before
    assert [(e.source, e.target, e.type) for e in g.edges] == edges_before
    assert list(getattr(g, "_component_context", [])) == ctx_before


# 14. context associations unchanged after scope building
def test_associations_unchanged():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL), source="scope.yaml")
    assocs_before = list(getattr(g, "_component_context", []))
    build_component_security_scopes(g)
    assert list(getattr(g, "_component_context", [])) == assocs_before


# 15-17. AttackPath / path_id / risk / evidence / breakpoints / policy unchanged
def _snapshot(p):
    return (
        tuple(p.nodes), tuple(p.edges), tuple(p.associated_edges), p.attack_type.value,
        p.entry_node, p.asset_node, p.sink_node, p.path_id, p.canonical_identity,
        p.severity.value, p.confidence.value,
        p.risk_severity.value, p.risk_confidence.value, p.risk_score,
        tuple(p.evidence), tuple(p.policy_ids),
        tuple((b.edge_type, b.reason) for b in p.breakpoints),
    )


def test_attack_path_semantics_unchanged():
    g1 = _exfil_graph()
    p1 = PathAnalyzer(g1).analyze()[0]
    snap1 = _snapshot(p1)

    g2 = _exfil_graph()
    associate_security_behavior(g2, READS, ComponentContext("SKILL:A", NodeType.SKILL), source="scope1")
    associate_security_behavior(g2, SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT), source="scope2")
    p2 = PathAnalyzer(g2).analyze()[0]
    assert _snapshot(p2) == snap1
    assert p1.path_id == p2.path_id


# 18. JSON serialization deterministic
def test_json_serialization():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL), source="s")
    result = ScanResult(target="x", attack_paths=PathAnalyzer(g).analyze())
    result.component_security_scopes = serialize_component_security_scopes(g)
    d = json.loads(render_json(result))
    assert d["component_security_scopes"][0]["component_id"] == "SKILL:A"
    assert d["component_security_scopes"][0]["component_type"] == "SKILL"
    assert d["component_security_scopes"][0]["security_behaviors"] == [
        {"source": "SKILL:A", "edge_type": "READS", "target": "SECRET:x"}
    ]


# 19. SARIF additive field and message.text unchanged
def test_sarif_additive():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    paths = PathAnalyzer(g).analyze()
    result = ScanResult(target="x", attack_paths=paths)
    result.component_security_scopes = serialize_component_security_scopes(g)
    doc = json.loads(render_sarif(result))
    run = doc["runs"][0]
    assert run["properties"]["component_security_scopes"][0]["component_id"] == "SKILL:A"
    # message.text unchanged.
    ap = [r for r in run["results"] if r["ruleId"].startswith("ATTACK-PATH")][0]
    assert ap["message"]["text"] == paths[0].explanation


# 20. HTML rendering
def test_html_renders_scope():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL), source="scope.yaml")
    result = ScanResult(target="x", attack_paths=PathAnalyzer(g).analyze())
    result.component_security_scopes = serialize_component_security_scopes(g)
    doc = render_html(result)
    assert "Component Security Scope" in doc
    assert "SKILL:A" in doc
    assert "SKILL" in doc
    assert "READS" in doc
    assert "SECRET:x" in doc


# 21. HTML XSS escaping
def test_html_xss_escaping():
    g = _exfil_graph()
    evil = "<script>alert(1)</script>"
    g.add_node(Node(id="TOOL:" + evil, type=NodeType.TOOL))
    g.add_edge("SECRET:x", "ENDPOINT:evil.example", EdgeType.SENDS_TO)
    associate_security_behavior(g, SENDS_TO,
                                ComponentContext("TOOL:" + evil, NodeType.TOOL),
                                source="<img src=x onerror=alert(1)>")
    result = ScanResult(target="x", attack_paths=PathAnalyzer(g).analyze())
    result.component_security_scopes = serialize_component_security_scopes(g)
    doc = render_html(result)
    assert "<script>" not in doc
    assert "<img" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc


# 22. public API exports
def test_public_api_exports():
    from veyra import graph
    assert hasattr(graph, "ComponentSecurityScope")
    assert hasattr(graph, "build_component_security_scopes")
    assert hasattr(graph, "serialize_component_security_scopes")
    from veyra.graph.context import (
        ComponentContext,
        ComponentContextAssociation,
        ComponentContextError,
    )
    assert callable(ComponentContext)
    assert callable(ComponentContextAssociation)
    assert issubclass(ComponentContextError, ValueError)


# 23. JSON-safe output contains no Enum objects / dataclass reprs
def test_json_safe_output():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    serialized = serialize_component_security_scopes(g)
    # Round-trips through json cleanly — proves no enums/reprs leak.
    text = json.dumps(serialized)
    parsed = json.loads(text)
    assert parsed == serialized
    assert "EdgeType" not in text
    assert "ComponentSecurityScope" not in text


# 24. deterministic repeated serialization
def test_repeated_serialization_stable():
    g = _exfil_graph()
    associate_security_behavior(g, READS, ComponentContext("SKILL:A", NodeType.SKILL))
    assert serialize_component_security_scopes(g) == serialize_component_security_scopes(g)
    assert json.dumps(serialize_component_security_scopes(g)) == \
        json.dumps(serialize_component_security_scopes(g))
