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
    # AS-001 finding with no concrete identity -> preserved as an ACTION node.
    assert NodeType.ACTION in types
    # agent CONTAINS skill
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


def test_build_from_findings_no_fabricated_entity_without_identity():
    """A finding with no extractable URL/secret must NOT create a fake endpoint."""
    g = build_from_findings([_finding("AS-003", "main.py")])
    types = {n.type for n in g.nodes.values()}
    assert NodeType.ENDPOINT not in types
    assert NodeType.ACTION in types


# --- Findings identity: unified semantic nodes -----------------------------

def _endpoint_finding(rule_id, file, url):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        description="d",
        file=file,
        evidence=f"seen at {url}",
        remediation="r",
        confidence=Confidence.MEDIUM,
        matched_text=f"the endpoint {url}",
    )


def test_same_endpoint_via_different_rules_single_node():
    """The same endpoint referenced by AS-003 and AS-CHAIN-001 -> one node."""
    url = "https://example.com/upload"
    g = build_from_findings([
        _endpoint_finding("AS-003", "a.py", url),
        _endpoint_finding("AS-CHAIN-001", "b.py", url),
    ])
    endpoints = [n for n in g.nodes.values() if n.type == NodeType.ENDPOINT]
    assert len(endpoints) == 1
    assert endpoints[0].id == f"ENDPOINT:{url}"


def test_same_endpoint_via_multiple_files_single_node():
    """The same endpoint referenced from multiple files -> one node."""
    url = "https://example.com/upload"
    g = build_from_findings([
        _endpoint_finding("AS-003", "service-a/x.py", url),
        _endpoint_finding("AS-003", "service-b/y.py", url),
    ])
    endpoints = [n for n in g.nodes.values() if n.type == NodeType.ENDPOINT]
    assert len(endpoints) == 1
    skill_ids = {n.id for n in g.nodes.values() if n.type == NodeType.SKILL}
    assert len(skill_ids) == 2  # distinct service components


def test_distinct_component_paths_are_distinct_nodes():
    """service-a/critical.py and service-b/critical.py -> distinct nodes."""
    g = build_from_findings([
        _endpoint_finding("AS-003", "service-a/critical.py", "https://a.example.com"),
        _endpoint_finding("AS-003", "service-b/critical.py", "https://b.example.com"),
    ])
    skills = [n for n in g.nodes.values() if n.type == NodeType.SKILL]
    ids = {s.id for s in skills}
    assert len(ids) == 2
    assert "service-a/critical.py" in " ".join(ids)
    assert "service-b/critical.py" in " ".join(ids)


def test_findings_and_actions_resolve_same_endpoint():
    """Action-derived and finding-derived endpoint identity -> same node."""
    url = "https://example.com/upload"
    # Action builder: Skill READS data, SENDS_TO same endpoint.
    fg = build_from_findings([_endpoint_finding("AS-003", "x.py", url)])
    ag = build_from_actions([
        Action(verb="send", object="data", destination=url, category="NETWORK"),
    ])
    f_endpoint = [n for n in fg.nodes.values() if n.type == NodeType.ENDPOINT][0].id
    a_endpoint = [n for n in ag.nodes.values() if n.type == NodeType.ENDPOINT][0].id
    assert f_endpoint == a_endpoint == f"ENDPOINT:{url}"


def test_no_rule_id_in_semantic_endpoint_node_id():
    """Semantic endpoint node IDs contain the URL, not an AS-* rule ID."""
    url = "https://example.com/upload"
    g = build_from_findings([
        _endpoint_finding("AS-003", "x.py", url),
        _endpoint_finding("AS-CHAIN-004", "y.py", url),
    ])
    endpoints = [n for n in g.nodes.values() if n.type == NodeType.ENDPOINT]
    assert len(endpoints) == 1
    assert "AS-" not in endpoints[0].id


def test_secret_finding_semantic_identity():
    """AS-006 with a real sensitive path -> SECRET node keyed by that path."""
    f = Finding(
        rule_id="AS-006",
        severity=Severity.HIGH,
        title="t",
        description="sensitive credential file access",
        file="skill.md",
        evidence="access",
        remediation="r",
        matched_text="read ~/.aws/credentials",
    )
    g = build_from_findings([f])
    secrets = [n for n in g.nodes.values() if n.type == NodeType.SECRET]
    assert len(secrets) == 1
    assert "credentials" in secrets[0].id


def test_mcp_finding_semantic_identity():
    """AS-MCP finding with a server name -> MCPSERVER node keyed by that name."""
    f = Finding(
        rule_id="AS-MCP-004",
        severity=Severity.HIGH,
        title="t",
        description="MCP server 'filesystem' runs a dynamic package",
        file=".mcp.json",
        evidence="npx",
        remediation="r",
    )
    g = build_from_findings([f])
    servers = [n for n in g.nodes.values() if n.type == NodeType.MCPSERVER]
    assert len(servers) == 1
    assert servers[0].label == "filesystem"


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
