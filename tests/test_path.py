"""Tests for the deterministic Attack Path Analyzer."""

from veyra.graph import (
    Edge,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    build_from_actions,
)
from veyra.models import Confidence, Severity
from veyra.step_sequence import Action


def _graph(actions, subject="skill"):
    """Build a SecurityGraph from actions (subject node id = 'SKILL:skill' unless overridden)."""
    return build_from_actions(actions, subject_id=subject)


def _paths(graph):
    return PathAnalyzer(graph).analyze()


def test_secret_to_external_endpoint():
    """READ Secret -> SENDS_TO Endpoint => secret-exposure path."""
    g = _graph([
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="send", object="token", destination="https://evil.com", category="NETWORK"),
    ], subject="my-skill")
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    assert p.title == "Secret exposed to external endpoint"
    # Path includes the secret origin and the external endpoint sink.
    assert p.nodes[-1] == "ENDPOINT:https://evil.com"
    assert p.nodes[1] == "SECRET:token"


def test_secret_flows_to_data_then_endpoint():
    """SECRET -> derived DATA (FLOWS_TO) -> SENDS_TO Endpoint => exposure path."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    d = Node(id="DATA:payload", type=NodeType.DATA, label="payload")
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT, label="evil")
    for n in (s, sec, d, ep):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, d.id, EdgeType.FLOWS_TO)
    g.add_edge(s.id, ep.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    # data-flow edge FLOWS_TO between SECRET:token and DATA:payload is present.
    assert any(e[2] == "FLOWS_TO" for e in p.edges)
    assert "DATA:payload" in p.nodes
    assert p.nodes[-1] == "ENDPOINT:https://evil.com"


def test_sensitive_data_to_derived_to_endpoint():
    """Source DATA -> derived DATA (FLOWS_TO) -> SENDS_TO Endpoint."""
    g = _graph([
        Action(verb="read", object="config", destination=None, category="SOURCE"),
        Action(verb="transform", object="config", destination=None, category="TRANSFORM", output="report"),
        Action(verb="send", object="report", destination="https://evil.com", category="NETWORK"),
    ], subject="my-skill")
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    assert "sensitive-data" in p.title.lower() or "data" in p.title.lower()
    # derived data object appears in the node sequence.
    assert "DATA:report" in p.nodes
    assert any(e[2] == "FLOWS_TO" for e in p.edges)


def test_secret_plus_execution():
    """Skill READS Secret and EXECUTES an Action => execution path."""
    g = _graph([
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="run", object="script", destination=None, category="EXECUTION"),
    ], subject="my-skill")
    paths = _paths(g)
    assert len(paths) == 1
    assert paths[0].title == "Secret access followed by command execution"


def test_benign_graph_no_paths():
    """A graph with reads but no external sink produces zero paths."""
    g = _graph([
        Action(verb="read", object="config", destination=None, category="SOURCE"),
    ], subject="my-skill")
    assert _paths(g) == []


def test_multiple_paths_all_found():
    """Two distinct endpoints from the same secret => two exposure paths."""
    g = _graph([
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="send", object="token", destination="https://a.com", category="NETWORK"),
        Action(verb="send", object="token", destination="https://b.com", category="NETWORK"),
    ], subject="my-skill")
    paths = _paths(g)
    assert len(paths) == 2
    sinks = {p.nodes[-1] for p in paths}
    assert sinks == {"ENDPOINT:https://a.com", "ENDPOINT:https://b.com"}


def test_duplicate_paths_deduplicated():
    """Two equivalent findings yield one path (edge metadata aggregated, not duplicate path)."""
    # Same structure repeated via a second set of actions referencing same objects.
    g = _graph([
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="send", object="token", destination="https://evil.com", category="NETWORK"),
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="send", object="token", destination="https://evil.com", category="NETWORK"),
    ], subject="my-skill")
    paths = _paths(g)
    assert len(paths) == 1


def test_cyclic_graph_terminates():
    """A FLOWS_TO cycle must terminate safely (cycle guard)."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    d1 = Node(id="DATA:a", type=NodeType.DATA, label="a")
    d2 = Node(id="DATA:b", type=NodeType.DATA, label="b")
    ep = Node(id="ENDPOINT:https://x.com", type=NodeType.ENDPOINT, label="x")
    for n in (s, d1, d2, ep):
        g.add_node(n)
    g.add_edge(s.id, d1.id, EdgeType.READS)
    g.add_edge(d1.id, d2.id, EdgeType.FLOWS_TO)
    g.add_edge(d2.id, d1.id, EdgeType.FLOWS_TO)  # cycle
    g.add_edge(s.id, ep.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) >= 1  # terminates, no infinite recursion


def test_path_length_bounded():
    """A long data-flow chain is bounded to MAX_PATH_EDGES."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    ep = Node(id="ENDPOINT:https://x.com", type=NodeType.ENDPOINT, label="x")
    g.add_node(s)
    g.add_node(ep)
    # chain of 15 data nodes
    a = Node(id="DATA:a0", type=NodeType.DATA, label="a0")
    g.add_node(a)
    g.add_edge(s.id, a.id, EdgeType.READS)
    prev = "DATA:a0"
    for i in range(1, 15):
        n = Node(id=f"DATA:a{i}", type=NodeType.DATA, label=f"a{i}")
        g.add_node(n)
        g.add_edge(prev, n.id, EdgeType.FLOWS_TO)
        prev = n.id
    g.add_edge(s.id, ep.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert paths
    # bounded: each path node count (incl. skill+endpoint) stays within MAX+2.
    for p in paths:
        assert len(p.nodes) <= 12 + 2


def test_severity_confidence_deterministic():
    """Same graph analyzed twice yields identical results."""
    g = _graph([
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="send", object="token", destination="https://evil.com", category="NETWORK"),
    ], subject="my-skill")
    p1 = [x.to_dict() for x in _paths(g)]
    p2 = [x.to_dict() for x in _paths(g)]
    assert p1 == p2


def test_same_path_multiple_rules():
    """A path supported by multiple findings/rules is a single path."""
    # Build from actions (semantic) — two read + send pairs both to same endpoint.
    g = _graph([
        Action(verb="read", object="report", destination=None, category="SOURCE"),
        Action(verb="send", object="report", destination="https://evil.com", category="NETWORK"),
        Action(verb="read", object="report", destination=None, category="SOURCE"),
    ], subject="my-skill")
    paths = _paths(g)
    assert len(paths) == 1


def test_no_rule_ids_required():
    """Paths are found purely from graph semantics; no AS-* rule IDs needed."""
    # Build the graph directly with semantic node/edge types only.
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    d = Node(id="DATA:payload", type=NodeType.DATA, label="payload")
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT, label="evil")
    for n in (s, sec, d, ep):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, d.id, EdgeType.FLOWS_TO)
    g.add_edge(s.id, d.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 1
    assert "AS-" not in paths[0].title
    assert "AS-" not in " ".join(e[2] for e in paths[0].edges)


def test_attackpath_to_dict():
    """AttackPath.to_dict exposes the structured fields."""
    g = _graph([
        Action(verb="extract", object="token", destination=None, category="SENSITIVE"),
        Action(verb="send", object="token", destination="https://evil.com", category="NETWORK"),
    ], subject="my-skill")
    p = _paths(g)[0]
    d = p.to_dict()
    assert "nodes" in d and "edges" in d and "severity" in d
    assert "title" in d and "description" in d and "confidence" in d
