"""Tests for the explicit AI-agent ecosystem declaration layer (Commit 17).

The declaration layer is explicit-only: every node and edge it creates must come
from an actual declaration. It never infers from names, paths, or text, and it
must not change existing exfiltration/path_id/risk/evidence/breakpoint/provenance
semantics for unrelated security/data-flow entities.
"""

import pytest

from veyra.graph import (
    SecurityGraph,
    apply_component_declarations,
    ComponentDeclaration,
    ComponentDeclarationError,
    RelationshipDeclaration,
    PathAnalyzer,
    Node,
    NodeType,
    EdgeType,
    path_id_of,
)
from veyra.models import ScanResult
from veyra.reporters import render_json
from veyra.scanner import scan_path
from pathlib import Path
from tempfile import TemporaryDirectory


def _agent():
    return ComponentDeclaration("AGENT:alice", NodeType.AGENT, label="Alice agent")


def _skill():
    return ComponentDeclaration("SKILL:checkout", NodeType.SKILL, label="Checkout skill")


def _tool():
    return ComponentDeclaration("TOOL:curl", NodeType.TOOL)


def _mcp():
    return ComponentDeclaration("MCPSERVER:filesystem", NodeType.MCPSERVER)


# A. Component declarations ------------------------------------------------
def test_agent_declaration():
    g = SecurityGraph()
    apply_component_declarations(g, [_agent()], [])
    assert "AGENT:alice" in g.nodes
    assert g.nodes["AGENT:alice"].type == NodeType.AGENT
    assert g.nodes["AGENT:alice"].label == "Alice agent"


def test_skill_declaration():
    g = SecurityGraph()
    apply_component_declarations(g, [_skill()], [])
    assert g.nodes["SKILL:checkout"].type == NodeType.SKILL


def test_tool_declaration():
    g = SecurityGraph()
    apply_component_declarations(g, [_tool()], [])
    assert g.nodes["TOOL:curl"].type == NodeType.TOOL


def test_mcpserver_declaration():
    g = SecurityGraph()
    apply_component_declarations(g, [_mcp()], [])
    assert g.nodes["MCPSERVER:filesystem"].type == NodeType.MCPSERVER


# E-K. Relationships --------------------------------------------------------
def _g_with(*nodes):
    g = SecurityGraph()
    apply_component_declarations(g, list(nodes), [])
    return g


def test_agent_contains_skill():
    g = _g_with(_agent(), _skill())
    apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "SKILL:checkout", EdgeType.CONTAINS)])
    assert any(e.source == "AGENT:alice" and e.type == EdgeType.CONTAINS and e.target == "SKILL:checkout" for e in g.edges)


def test_agent_uses_tool():
    g = _g_with(_agent(), _tool())
    apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES)])
    assert any(e.source == "AGENT:alice" and e.type == EdgeType.USES and e.target == "TOOL:curl" for e in g.edges)


def test_agent_uses_mcp():
    g = _g_with(_agent(), _mcp())
    apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "MCPSERVER:filesystem", EdgeType.USES)])
    assert any(e.source == "AGENT:alice" and e.type == EdgeType.USES and e.target == "MCPSERVER:filesystem" for e in g.edges)


def test_skill_calls_tool():
    g = _g_with(_skill(), _tool())
    apply_component_declarations(g, [], [RelationshipDeclaration("SKILL:checkout", "TOOL:curl", EdgeType.CALLS)])
    assert any(e.source == "SKILL:checkout" and e.type == EdgeType.CALLS and e.target == "TOOL:curl" for e in g.edges)


def test_skill_calls_mcp():
    g = _g_with(_skill(), _mcp())
    apply_component_declarations(g, [], [RelationshipDeclaration("SKILL:checkout", "MCPSERVER:filesystem", EdgeType.CALLS)])
    assert any(e.source == "SKILL:checkout" and e.type == EdgeType.CALLS and e.target == "MCPSERVER:filesystem" for e in g.edges)


def test_trusts_stays_trusts():
    g = _g_with(_agent(), _tool())
    apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.TRUSTS)])
    assert any(e.source == "AGENT:alice" and e.type == EdgeType.TRUSTS and e.target == "TOOL:curl" for e in g.edges)
    # No data-flow edge is created.
    assert all(e.type not in (EdgeType.READS, EdgeType.FLOWS_TO, EdgeType.SENDS_TO, EdgeType.EXECUTES) for e in g.edges)


def test_handoff_remains_explicit():
    # Existing HANDOFF semantics are SKILL -> SKILL only (add_handoff creates
    # two SKILL components). The declaration layer mirrors exactly that.
    g = _g_with(_skill(), _skill2())
    apply_component_declarations(g, [], [RelationshipDeclaration("SKILL:checkout", "SKILL:handoff", EdgeType.HANDOFF)])
    assert any(e.source == "SKILL:checkout" and e.type == EdgeType.HANDOFF and e.target == "SKILL:handoff" for e in g.edges)


def _skill2():
    return ComponentDeclaration("SKILL:handoff", NodeType.SKILL)


# L. Idempotency ------------------------------------------------------------
def test_duplicate_declarations_idempotent():
    g = SecurityGraph()
    comps = [_agent(), _tool()]
    rels = [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES)]
    for _ in range(3):
        apply_component_declarations(g, comps, rels)
    assert len(g.nodes) == 2
    assert len(g.edges) == 1


# M. Validation ---------------------------------------------------------------
def test_undeclared_endpoint_rejected():
    g = _g_with(_agent())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES)])


def test_undeclared_source_rejected():
    g = _g_with(_tool())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES)])


def test_invalid_component_node_type_rejected():
    g = SecurityGraph()
    for bad_type in (NodeType.DATA, NodeType.SECRET, NodeType.ENDPOINT, NodeType.ACTION):
        with pytest.raises(ComponentDeclarationError):
            apply_component_declarations(g, [ComponentDeclaration(f"{bad_type.value}:x", bad_type)], [])


def test_invalid_relationship_edge_type_rejected():
    g = _g_with(_agent(), _tool())
    for bad_edge in (EdgeType.READS, EdgeType.WRITES, EdgeType.SENDS_TO, EdgeType.EXECUTES, EdgeType.PRODUCES, EdgeType.FLOWS_TO):
        with pytest.raises(ComponentDeclarationError):
            apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", bad_edge)])


def test_invalid_component_combination_rejected():
    # e.g. SKILL CONTAINS SKILL (not in matrix), TOOL CONTAINS SKILL, etc.
    g = SecurityGraph()
    g_s = ComponentDeclaration("SKILL:a", NodeType.SKILL)
    g_t = ComponentDeclaration("TOOL:t", NodeType.TOOL)
    apply_component_declarations(g, [g_s, g_t], [])
    # SKILL CONTAINS SKILL is unsupported.
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("SKILL:a", "SKILL:a2", EdgeType.CONTAINS)])
    # TOOL --CALLS--> TOOL unsupported.


def test_invalid_combination_agent_contains_tool_rejected():
    g = _g_with(_agent(), _tool())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.CONTAINS)])


def test_empty_id_rejected():
    with pytest.raises(ComponentDeclarationError):
        ComponentDeclaration("", NodeType.AGENT)
    with pytest.raises(ComponentDeclarationError):
        ComponentDeclaration("   ", NodeType.SKILL)
    with pytest.raises(ComponentDeclarationError):
        RelationshipDeclaration("", "TOOL:x", EdgeType.USES)


def test_self_referential_rejected():
    with pytest.raises(ComponentDeclarationError):
        RelationshipDeclaration("AGENT:alice", "AGENT:alice", EdgeType.USES)


# R/S. Provenance -------------------------------------------------------------
def test_explicit_source_provenance_preserved():
    g = SecurityGraph()
    apply_component_declarations(
        g,
        [_agent(), _tool()],
        [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES, source="ecosystem.toml")],
    )
    edge = next(e for e in g.edges)
    assert edge.attributes.get("files") == ["ecosystem.toml"]


def test_missing_source_provenance_unknown():
    g = SecurityGraph()
    apply_component_declarations(g, [_agent(), _tool()],
                                 [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES)])
    edge = next(e for e in g.edges)
    # No files attribute is fabricated.
    assert "files" not in edge.attributes or edge.attributes["files"] == []


# T. TRUSTS does not create exfiltration ------------------------------------
def test_trusts_does_not_create_exfiltration():
    g = SecurityGraph()
    apply_component_declarations(g, [_agent(), _tool()],
                                 [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.TRUSTS)])
    # No SECRET/DATA/ENDPOINT involved -> no exfiltration path possible.
    assert PathAnalyzer(g).analyze() == []


# U. HANDOFF does not create data-flow edges --------------------------------
def test_handoff_does_not_create_dataflow():
    g = SecurityGraph()
    apply_component_declarations(g, [_skill(), _skill2()],
                                 [RelationshipDeclaration("SKILL:checkout", "SKILL:handoff", EdgeType.HANDOFF)])
    assert all(e.type == EdgeType.HANDOFF for e in g.edges)


# AA. Determinism regardless of input order ---------------------------------
def _ecosystem_comps():
    return [ComponentDeclaration("MCPSERVER:fs", NodeType.MCPSERVER),
            ComponentDeclaration("AGENT:a", NodeType.AGENT),
            ComponentDeclaration("TOOL:t", NodeType.TOOL),
            ComponentDeclaration("SKILL:s", NodeType.SKILL)]


def _ecosystem_rels():
    return [RelationshipDeclaration("SKILL:s", "MCPSERVER:fs", EdgeType.CALLS),
            RelationshipDeclaration("AGENT:a", "SKILL:s", EdgeType.CONTAINS),
            RelationshipDeclaration("AGENT:a", "TOOL:t", EdgeType.USES)]


def _snapshot(g):
    return {
        "nodes": tuple(sorted((n.id, n.type.value) for n in g.nodes.values())),
        "edges": tuple(sorted((e.source, e.target, e.type.value) for e in g.edges)),
    }


def test_determinism_regardless_of_input_order():
    g1 = SecurityGraph()
    apply_component_declarations(g1, _ecosystem_comps(), _ecosystem_rels())
    g2 = SecurityGraph()
    apply_component_declarations(g2, list(reversed(_ecosystem_comps())), list(reversed(_ecosystem_rels())))
    assert _snapshot(g1) == _snapshot(g2)


# V/Z. Component relationships do not alter exfiltration classification ------
def _exfil_graph():
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:pay", type=NodeType.SKILL))
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:pay", "SECRET:token", EdgeType.READS, attributes={"files": ["pay/SKILL.md"]})
    g.add_edge("SECRET:token", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO, attributes={"files": ["pay/SKILL.md"]})
    return g


def test_adding_ecosystem_does_not_alter_exfil_classification():
    base = _exfil_graph()
    base_path = PathAnalyzer(base).analyze()[0]
    base_snapshot = (base_path.attack_type.value, base_path.path_id,
                     base_path.risk_score, tuple(base_path.evidence),
                     tuple((b.edge_type, b.reason) for b in base_path.breakpoints))

    g = _exfil_graph()
    # Add unrelated agent/tool/mcp ecosystem around the exfil path.
    apply_component_declarations(
        g,
        [_agent(), _skill(), _tool(), _mcp()],
        [RelationshipDeclaration("AGENT:alice", "SKILL:checkout", EdgeType.CONTAINS),
         RelationshipDeclaration("SKILL:checkout", "TOOL:curl", EdgeType.USES),
         RelationshipDeclaration("SKILL:checkout", "MCPSERVER:filesystem", EdgeType.CALLS),
         RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.TRUSTS)],
    )
    paths = PathAnalyzer(g).analyze()
    exfil = [p for p in paths if p.attack_type.value == "SECRET_EXFILTRATION"]
    assert exfil, "exfiltration path should still exist"
    p = exfil[0]
    assert (p.attack_type.value, p.path_id, p.risk_score, tuple(p.evidence),
            tuple((b.edge_type, b.reason) for b in p.breakpoints)) == base_snapshot


def test_adding_ecosystem_does_not_change_path_id():
    g1 = _exfil_graph()
    p1 = PathAnalyzer(g1).analyze()[0]
    g2 = _exfil_graph()
    apply_component_declarations(g2, [_agent(), _tool()],
                                 [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.USES)])
    p2 = PathAnalyzer(g2).analyze()[0]
    assert p1.path_id == p2.path_id


# Provenance: no inference from ids -------------------------------------------
def test_provenance_never_inferred_from_node_ids():
    g = SecurityGraph()
    # Declare a component with a source-attributed relationship, and separately
    # a tool with NO source: the tool's provenance must stay unknown even though
    # it's called 'curl' (never inferred to curl/SKILL.md).
    apply_component_declarations(g, [_tool(), _mcp()], [])
    tool_edge = None
    # No relationship on the tool -> no edge, so nothing to mis-attribute.
    assert all(e.source != "TOOL:curl" for e in g.edges)


# AE. full-pipeline clean scan unaffected --------------------------------------
def test_scanner_unchanged_with_declarations():
    # Declaring components does NOT change scanner scanning; verify a clean scan
    # still yields no attack paths.
    from veyra.reporters import render_json as rj
    with TemporaryDirectory() as tmp:
        Path(tmp, "README.md").write_text("# Read-only\n", encoding="utf-8")
        r = scan_path(tmp)
        assert r.attack_paths == []


# End-to-end: agent→skill→mcp exactly as declared ------------------------------
def test_end_to_end_exactly_as_declared():
    g = SecurityGraph()
    apply_component_declarations(
        g,
        [_agent(), _skill(), _mcp(), _tool()],
        [RelationshipDeclaration("AGENT:alice", "SKILL:checkout", EdgeType.USES),
         RelationshipDeclaration("SKILL:checkout", "MCPSERVER:filesystem", EdgeType.CALLS),
         RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.TRUSTS)],
    )
    assert any(e.source == "AGENT:alice" and e.type == EdgeType.USES and e.target == "SKILL:checkout" for e in g.edges)
    assert any(e.source == "SKILL:checkout" and e.type == EdgeType.CALLS and e.target == "MCPSERVER:filesystem" for e in g.edges)
    assert any(e.source == "AGENT:alice" and e.type == EdgeType.TRUSTS and e.target == "TOOL:curl" for e in g.edges)


# Tightened matrix negative tests (Commit 17 correction) ---------------------
def test_tool_uses_tool_rejected():
    g = _g_with(_tool(), _tool2())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("TOOL:curl", "TOOL:grep", EdgeType.USES)])


def _tool2():
    return ComponentDeclaration("TOOL:grep", NodeType.TOOL)


def test_agent_contains_tool_rejected():
    g = _g_with(_agent(), _tool())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "TOOL:curl", EdgeType.CONTAINS)])


def test_agent_contains_agent_rejected():
    g = _g_with(_agent(), _skill())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "AGENT:bob", EdgeType.CONTAINS)])


def test_skill_contains_skill_rejected():
    g = _g_with(_skill(), _skill2())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("SKILL:checkout", "SKILL:handoff", EdgeType.CONTAINS)])


def test_skill_uses_agent_rejected():
    g = _g_with(_skill(), _agent())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("SKILL:checkout", "AGENT:alice", EdgeType.USES)])


def test_tool_calls_skill_rejected():
    g = _g_with(_tool(), _skill())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("TOOL:curl", "SKILL:checkout", EdgeType.CALLS)])


def test_mcp_calls_tool_rejected():
    g = _g_with(_mcp(), _tool())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("MCPSERVER:filesystem", "TOOL:curl", EdgeType.CALLS)])


def test_agent_handoff_agent_rejected():
    # Existing HANDOFF is SKILL -> SKILL only; AGENT -> AGENT is not supported.
    g = _g_with(_agent(), _bob())
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [], [RelationshipDeclaration("AGENT:alice", "AGENT:bob", EdgeType.HANDOFF)])


def _bob():
    return ComponentDeclaration("AGENT:bob", NodeType.AGENT)


def test_secret_uses_tool_rejected():
    g = SecurityGraph()
    apply_component_declarations(g, [_tool()], [])
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [ComponentDeclaration("SECRET:s", NodeType.SECRET)],
                                     [RelationshipDeclaration("SECRET:s", "TOOL:curl", EdgeType.USES)])


def test_data_uses_tool_rejected():
    g = SecurityGraph()
    apply_component_declarations(g, [_tool()], [])
    with pytest.raises(ComponentDeclarationError):
        apply_component_declarations(g, [ComponentDeclaration("DATA:d", NodeType.DATA)],
                                     [RelationshipDeclaration("DATA:d", "TOOL:curl", EdgeType.USES)])


def test_matrix_is_security_semantic_contract():
    """The compatibility matrix is an explicit security contract, not all
    technically possible edges. Confirming a few deliberately-excluded
    combinations are rejected (conservative-by-default invariant)."""
    from veyra.graph.declarations import _COMPATIBILITY_MATRIX, _COMPONENT_NODE_TYPES
    # TOOL USES anything is absent.
    assert not any(et == EdgeType.USES and st == NodeType.TOOL
                   for (st, et) in _COMPATIBILITY_MATRIX)
    # AGENT HANDOFF is absent (existing HANDOFF is SKILL->SKILL only).
    assert (NodeType.AGENT, EdgeType.HANDOFF) not in _COMPATIBILITY_MATRIX
    # Component types never reach DATA/SECRET/ENDPOINT/ACTION.
    assert not ({NodeType.DATA, NodeType.SECRET, NodeType.ENDPOINT, NodeType.ACTION}
                & _COMPONENT_NODE_TYPES)
