"""Tests for explicit component-transfer evidence (Commit: feat(graph): model
explicit component transfer evidence).

A TRANSFER Action is explicit component-transfer EVIDENCE: its destination
names a canonical target component, and build_from_actions turns it into a real
SKILL:A --HANDOFF--> SKILL:B edge. The source scanner NEVER emits TRANSFER
automatically — generic function calls, HTTP requests, endpoint/tool/MCP use,
shared DATA/SECRET, PRODUCES+READS, USES, or name-like strings are NOT handoffs.
"""

from veyra.graph import (
    AttackType,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    add_handoff,
    build_from_actions,
    canonical_path_identity,
    path_id_of,
)
from veyra.step_sequence import Action


def _g():
    return SecurityGraph()


# Positive: explicit TRANSFER action -> HANDOFF edge -> composed path ---------

def test_explicit_transfer_action_produces_handoff_edge():
    acts = [Action(verb="handoff", object="", destination="compB", category="TRANSFER")]
    g = build_from_actions(acts, subject_id="compA")
    assert any(e.type == EdgeType.HANDOFF for e in g.edges)
    e = next(e for e in g.edges if e.type == EdgeType.HANDOFF)
    assert e.source == "SKILL:compA"
    assert e.target == "SKILL:compB"
    # Attribute records the explicit evidence provenance.
    assert e.attributes.get("evidence") == "explicit component-transfer action"


def test_transfer_action_end_to_end_composed_path():
    acts = [Action(verb="handoff", object="", destination="compB", category="TRANSFER")]
    g = build_from_actions(acts, subject_id="compA")
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert len(composed) == 1
    p = composed[0]
    assert p.is_composed is True
    assert p.component_ids == ["compA", "compB"]
    # The ordered contiguous walk contains the actual HANDOFF edge.
    assert p.nodes == ["SKILL:compA", "SKILL:compB"]
    assert p.edges == [("SKILL:compA", "SKILL:compB", "HANDOFF")]
    assert p.is_contiguous
    # Control transfer alone is not exfiltration.
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0


def test_transfer_action_missing_destination_is_noop():
    # A TRANSFER with no resolvable destination must NOT create a HANDOFF edge.
    acts = [Action(verb="handoff", object="", destination=None, category="TRANSFER")]
    g = build_from_actions(acts, subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    # Even an empty-string target (not a canonical component) is ignored.
    acts2 = [Action(verb="handoff", object="", destination="", category="TRANSFER")]
    g2 = build_from_actions(acts2, subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g2.edges)


# Negative: these MUST NOT become HANDOFF -------------------------------------

def _transfer_categories():
    # (category, destination) pairs that are ordinary operations, not transfers.
    return [
        ("SOURCE", None), ("SENSITIVE", None), ("TRANSFORM", None),
        ("NETWORK", "https://compB.example"), ("DOWNLOAD", "https://x.example"),
        ("EXECUTION", None),
    ]


def test_generic_calls_not_handoff():
    """Generic function call / HTTP / tool invocation must NOT become HANDOFF."""
    for cat, dest in _transfer_categories():
        acts = [Action(verb="do", object="thing", destination=dest, category=cat)]
        g = build_from_actions(acts, subject_id="compA")
        assert not any(e.type == EdgeType.HANDOFF for e in g.edges), cat
    # requests.get / foo() / subprocess.run style operations (EXECUTION) stay non-handoff.
    g = build_from_actions([Action(verb="run", object="script", destination=None,
                                   category="EXECUTION")], subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)


def test_endpoint_usage_not_handoff():
    g = build_from_actions([Action(verb="use", object="tool", destination="https://x.example",
                                   category="DOWNLOAD")], subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)


def test_mcp_usage_without_transfer_not_handoff():
    # A finding-driven MCP server is not a component transfer.
    acts = [Action(verb="call", object="mcp", destination="filesystem", category="SOURCE")]
    g = build_from_actions(acts, subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)


def test_shared_data_not_handoff():
    """A produces doc; B reads the SAME data node => no HANDOFF edge."""
    g = _g()
    a = Node(id="SKILL:compA", type=NodeType.SKILL)
    b = Node(id="SKILL:compB", type=NodeType.SKILL)
    d = Node(id="DATA:doc", type=NodeType.DATA)
    for n in (a, b, d):
        g.add_node(n)
    g.add_edge(a.id, d.id, EdgeType.PRODUCES)
    g.add_edge(b.id, d.id, EdgeType.READS)   # shared data node, no transfer
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


def test_shared_secret_not_handoff():
    g = _g()
    a = Node(id="SKILL:compA", type=NodeType.SKILL)
    b = Node(id="SKILL:compB", type=NodeType.SKILL)
    sec = Node(id="SECRET:token", type=NodeType.SECRET)
    ep = Node(id="ENDPOINT:https://a.example", type=NodeType.ENDPOINT)
    for n in (a, b, sec, ep):
        g.add_node(n)
    g.add_edge(a.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)
    g.add_edge(b.id, sec.id, EdgeType.READS)  # shared secret, no transfer
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


def test_produces_plus_reads_not_handoff():
    g = _g()
    a = Node(id="SKILL:compA", type=NodeType.SKILL)
    b = Node(id="SKILL:compB", type=NodeType.SKILL)
    d = Node(id="DATA:doc", type=NodeType.DATA)
    for n in (a, b, d):
        g.add_node(n)
    g.add_edge(a.id, d.id, EdgeType.PRODUCES)
    g.add_edge(b.id, d.id, EdgeType.READS)
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    assert PathAnalyzer(g).analyze(compose=True) == []


def test_uses_not_handoff():
    g = build_from_actions([Action(verb="use", object="endpoint",
                                   destination="https://x.example", category="DOWNLOAD")],
                           subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)


def test_arbitrary_name_like_string_not_handoff():
    # A TRANSFER action whose destination is a generic string is only honored
    # at graph level when a caller explicitly supplies it; the scanner never
    # produces such strings from arbitrary text.
    g = build_from_actions([Action(verb="run", object="thing", destination="compB",
                                   category="EXECUTION")], subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)


def test_filename_modulename_alone_not_handoff():
    # A plain module/file-like string is not a canonical component identity.
    g = build_from_actions([Action(verb="import", object="other_skill.py",
                                   destination=None, category="SOURCE")],
                           subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)


# Determinism / identity ------------------------------------------------------

def test_transfer_semantics_deterministic():
    def build(subject, target):
        g = build_from_actions([Action(verb="handoff", object="", destination=target,
                                       category="TRANSFER")], subject_id=subject)
        return PathAnalyzer(g).analyze(compose=True)
    r1 = build("compA", "compB")
    r2 = build("compA", "compB")  # same -> same
    k1 = [(p.path_id, tuple(p.component_ids)) for p in r1]
    k2 = [(p.path_id, tuple(p.component_ids)) for p in r2]
    assert [k for k in k1] == [k for k in k2]
    # Different target -> different path_id.
    other = build("compA", "compC")
    assert [p.path_id for p in r1] != [p.path_id for p in other]


def test_transfer_path_id_is_canonical_walk_deterministic():
    g = build_from_actions([Action(verb="handoff", object="", destination="compB",
                                   category="TRANSFER")], subject_id="compA")
    p = PathAnalyzer(g).analyze(compose=True)[0]
    assert path_id_of(p.nodes, p.edges, p.associated_edges) == p.path_id
    assert canonical_path_identity(["SKILL:compA", "SKILL:compB"],
                                   [("SKILL:compA", "SKILL:compB", "HANDOFF")], []) == \
        p.canonical_identity


def test_transfer_edge_not_dataflow_or_sink():
    # TRANSFER/HANDOFF must not be treated as data lineage or an exfiltration sink.
    g = build_from_actions([Action(verb="handoff", object="", destination="compB",
                                   category="TRANSFER")], subject_id="compA")
    paths = PathAnalyzer(g).analyze()
    for p in paths:
        assert p.attack_type == AttackType.UNKNOWN
        assert p.risk_score == 0
        assert p.evidence == []
