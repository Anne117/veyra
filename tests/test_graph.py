"""Tests for the Security Graph models and builder."""

from veyra.graph import (
    Edge,
    EdgeType,
    Node,
    NodeType,
    SecurityGraph,
    build_from_actions,
    build_from_findings,
)
from veyra.models import Confidence, Finding, Severity
from veyra.step_sequence import Action


def _finding(rule_id="AS-001", file="SKILL.md"):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        description="d",
        file=file,
        evidence="e",
        remediation="r",
        confidence=Confidence.MEDIUM,
    )


# --- Models ---------------------------------------------------------------

def test_node_create_and_to_dict():
    n = Node(id="SKILL:main", type=NodeType.SKILL, label="main")
    d = n.to_dict()
    assert d["id"] == "SKILL:main"
    assert d["type"] == "SKILL"
    assert d["label"] == "main"


def test_edge_create_and_to_dict():
    e = Edge(source="a", target="b", type=EdgeType.READS)
    d = e.to_dict()
    assert d["source"] == "a"
    assert d["target"] == "b"
    assert d["type"] == "READS"


def test_graph_add_and_get_node():
    g = SecurityGraph()
    g.add_node(Node(id="x", type=NodeType.DATA, label="data"))
    assert g.get_node("x").label == "data"


def test_graph_get_or_create_reuses():
    g = SecurityGraph()
    g.get_or_create("y", NodeType.SECRET, label="s1")
    g.get_or_create("y", NodeType.SECRET, label="s2")
    assert len(g.nodes) == 1
    assert g.get_node("y").label == "s1"


def test_graph_add_edge_requires_existing_nodes():
    g = SecurityGraph()
    g.add_node(Node(id="a", type=NodeType.SKILL))
    g.add_node(Node(id="b", type=NodeType.DATA))
    g.add_edge("a", "b", EdgeType.READS)
    assert len(g.edges) == 1
    assert g.edges[0].type == EdgeType.READS


def test_graph_add_edge_missing_node_raises():
    g = SecurityGraph()
    g.add_node(Node(id="a", type=NodeType.SKILL))
    try:
        g.add_edge("a", "missing", EdgeType.READS)
        assert False, "should have raised"
    except KeyError:
        pass


def test_graph_neighbors():
    g = SecurityGraph()
    g.add_node(Node(id="a", type=NodeType.SKILL))
    g.add_node(Node(id="s", type=NodeType.SECRET))
    g.add_node(Node(id="e", type=NodeType.ENDPOINT))
    g.add_edge("a", "s", EdgeType.READS)
    g.add_edge("a", "e", EdgeType.SENDS_TO)
    out = g.neighbors("a")
    assert {e.target for e in out} == {"s", "e"}


def test_graph_to_dict():
    g = SecurityGraph()
    g.get_or_create("a", NodeType.SKILL)
    g.get_or_create("b", NodeType.DATA)
    g.add_edge("a", "b", EdgeType.READS)
    d = g.to_dict()
    assert len(d["nodes"]) == 2
    assert len(d["edges"]) == 1


# --- Builder: findings ----------------------------------------------------

def test_build_from_findings_agent_contains_skill():
    g = build_from_findings([_finding("AS-001", "SKILL.md")])
    types = {n.type for n in g.nodes.values()}
    assert NodeType.AGENT in types
    assert NodeType.SKILL in types
    assert NodeType.SECRET in types
    # agent CONTAINS skill, skill CONTAINS secret
    edge_types = {e.type for e in g.edges}
    assert EdgeType.CONTAINS in edge_types


def test_build_from_findings_skips_unmapped_rules():
    g = build_from_findings([_finding("AS-UNKNOWN")])
    # only the agent node is created (no mapped rule)
    assert len(g.nodes) == 1


def test_build_from_findings_deterministic():
    g1 = build_from_findings([_finding("AS-001"), _finding("AS-006")])
    g2 = build_from_findings([_finding("AS-001"), _finding("AS-006")])
    assert g1.to_dict() == g2.to_dict()


def test_build_from_findings_network_uses_endpoint():
    g = build_from_findings([_finding("AS-003", "main.py")])
    types = {n.type for n in g.nodes.values()}
    assert NodeType.ENDPOINT in types
    edge_types = {e.type for e in g.edges}
    assert EdgeType.USES in edge_types


# --- Builder: actions -----------------------------------------------------

def _actions():
    return [
        Action(verb="read", object="config", destination=None, category="SOURCE"),
        Action(verb="send", object="config", destination="https://example.com", category="NETWORK"),
    ]


def test_build_from_actions_source_reads_data():
    g = build_from_actions(_actions())
    types = {n.type for n in g.nodes.values()}
    assert NodeType.DATA in types
    assert NodeType.ENDPOINT in types
    edge_types = {e.type for e in g.edges}
    assert EdgeType.READS in edge_types
    assert EdgeType.SENDS_TO in edge_types


def test_build_from_actions_sensitive_reads_secret():
    g = build_from_actions([Action(verb="extract", object="token", destination=None, category="SENSITIVE")])
    types = {n.type for n in g.nodes.values()}
    assert NodeType.SECRET in types
    edge_types = {e.type for e in g.edges}
    assert EdgeType.READS in edge_types


def test_build_from_actions_transform_produces():
    g = build_from_actions([
        Action(verb="transform", object="data", destination=None, category="TRANSFORM", output="report")
    ])
    edge_types = {e.type for e in g.edges}
    assert EdgeType.PRODUCES in edge_types


def test_build_from_actions_deterministic():
    g1 = build_from_actions(_actions())
    g2 = build_from_actions(_actions())
    assert g1.to_dict() == g2.to_dict()
