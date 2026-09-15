"""Tests for explicit agentic handoff semantics (Commit: feat(graph): add
explicit agentic handoff semantics).

HANDOFF is an explicit control/component transfer between two SKILL components.
It is ONLY asserted when a real HANDOFF edge is present in the ordered graph
walk. It is never inferred from shared DATA/SECRET/ENDPOINT identity, PRODUCES,
READS, USES, or FLOWS_TO. A HANDOFF alone never proves secret/data exfiltration.
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


def _add_skill(g, comp):
    n = Node(id=f"SKILL:{comp}", type=NodeType.SKILL, label=comp)
    g.add_node(n)
    return n.id


def _add_data(g, name):
    n = Node(id=f"DATA:{name}", type=NodeType.DATA, label=name)
    g.add_node(n)
    return n.id


def _add_secret(g, name):
    n = Node(id=f"SECRET:{name}", type=NodeType.SECRET, label=name)
    g.add_node(n)
    return n.id


def _add_ep(g, url):
    n = Node(id=f"ENDPOINT:{url}", type=NodeType.ENDPOINT, label=url)
    g.add_node(n)
    return n.id


# A. Explicit handoff is represented correctly --------------------------------

def test_handoff_edge_represented_explicitly():
    g = _g()
    add_handoff(g, "compA", "compB")
    # The edge is SKILL:A --HANDOFF--> SKILL:B with concrete component ids.
    assert any(e.type == EdgeType.HANDOFF for e in g.edges)
    e = next(e for e in g.edges if e.type == EdgeType.HANDOFF)
    assert e.source == "SKILL:compA"
    assert e.target == "SKILL:compB"


# B. Handoff edge has deterministic identity ----------------------------------

def test_handoff_edge_deterministic_identity():
    g1, g2 = _g(), _g()
    add_handoff(g1, "compA", "compB")
    add_handoff(g2, "compA", "compB")
    # Same explicit transfer => same canonical path identity / path_id.
    p1 = PathAnalyzer(g1).analyze()[0]
    p2 = PathAnalyzer(g2).analyze()[0]
    assert p1.nodes == ["SKILL:compA", "SKILL:compB"]
    assert p1.edges == [("SKILL:compA", "SKILL:compB", "HANDOFF")]
    assert p1.path_id == p2.path_id
    assert path_id_of(p1.nodes, p1.edges, p1.associated_edges) == p1.path_id


# C. Shared DATA does NOT create a handoff ------------------------------------

def test_shared_data_no_handoff():
    g = _g()
    a, b = _add_skill(g, "compA"), _add_skill(g, "compB")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, d, EdgeType.PRODUCES)
    g.add_edge(b, d, EdgeType.READS)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    # No HANDOFF edge anywhere.
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


# D. Shared SECRET does NOT create a handoff ----------------------------------

def test_shared_secret_no_handoff():
    g = _g()
    a, b = _add_skill(g, "compA"), _add_skill(g, "compB")
    sec = _add_secret(g, "token")
    ep_a = _add_ep(g, "https://a.example")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, ep_a, EdgeType.SENDS_TO)
    g.add_edge(b, sec, EdgeType.READS)
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


# E. PRODUCES + READS across components does NOT create a handoff -------------

def test_produces_plus_reads_no_handoff():
    g = _g()
    a, b = _add_skill(g, "compA"), _add_skill(g, "compB")
    d = _add_data(g, "doc")
    g.add_edge(a, d, EdgeType.PRODUCES)
    g.add_edge(b, d, EdgeType.READS)
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    assert PathAnalyzer(g).analyze(compose=True) == []


# F. USES across components does NOT create a handoff -------------------------

def test_uses_no_handoff():
    g = _g()
    a, b = _add_skill(g, "compA"), _add_skill(g, "compB")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://remote.example")
    # a produces doc; b uses the endpoint. No transfer.
    g.add_edge(a, d, EdgeType.PRODUCES)
    g.add_edge(b, ep, EdgeType.USES)
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    assert PathAnalyzer(g).analyze(compose=True) == []


# G. Real explicit handoff produces a contiguous graph walk -------------------

def test_real_handoff_contiguous_walk():
    g = _g()
    add_handoff(g, "compA", "compB")
    paths = PathAnalyzer(g).analyze()
    assert len(paths) == 1
    p = paths[0]
    assert p.is_contiguous
    assert p.nodes == ["SKILL:compA", "SKILL:compB"]
    assert p.edges == [("SKILL:compA", "SKILL:compB", "HANDOFF")]
    # Every consecutive pair corresponds to an actual graph edge.
    assert (p.nodes[0], p.nodes[1], "HANDOFF") in {
        (e.source, e.target, e.type.value) for e in g.edges
    }


# H. Composition is true only when the actual path contains the handoff -------

def test_composition_true_only_with_handoff_in_walk():
    g = _g()
    add_handoff(g, "compA", "compB")
    comp = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert len(comp) == 1
    p = comp[0]
    assert p.is_composed is True
    assert p.component_ids == ["compA", "compB"]
    # Exactly the handoff edge is on the walk.
    assert "HANDOFF" in [et for _, _, et in p.edges]
    assert p.edges == [("SKILL:compA", "SKILL:compB", "HANDOFF")]


# I. Composition remains false for existing false-positive cases --------------

def test_composition_false_without_handoff():
    g = _g()
    a, b = _add_skill(g, "compA"), _add_skill(g, "compB")
    sec = _add_secret(g, "token")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(a, d, EdgeType.PRODUCES)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    g.add_edge(b, d, EdgeType.PRODUCES)   # unrelated producer in compB
    # No HANDOFF edge => no composed path.
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


# J. Handoff does not by itself become data exfiltration ----------------------

def test_handoff_is_not_exfiltration():
    g = _g()
    add_handoff(g, "compA", "compB")
    p = PathAnalyzer(g).analyze()[0]
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0
    assert p.evidence == []
    assert p.to_dict()["attack_type"] == "UNKNOWN"


# K. Existing secret/data exfiltration semantics remain unchanged --------------

def test_existing_exfiltration_unchanged():
    g = _g()
    a = _add_skill(g, "compA")
    sec = _add_secret(g, "token")
    d = _add_data(g, "payload")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    paths = PathAnalyzer(g).analyze()
    assert len(paths) == 1
    p = paths[0]
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert p.risk_score == 95
    assert p.is_contiguous


# L. Canonical path identity remains stable and deterministic -----------------

def test_handoff_does_not_break_canonical_identity():
    g = _g()
    add_handoff(g, "compA", "compB")
    p = PathAnalyzer(g).analyze()
    assert len(p) == 1
    c1 = canonical_path_identity(p[0].nodes, p[0].edges, p[0].associated_edges)
    c2 = canonical_path_identity(list(p[0].nodes), list(p[0].edges), p[0].associated_edges)
    assert c1 == c2
    # canonical identity includes the HANDOFF edge deterministically.
    assert "HANDOFF" in c1


# M. Existing correlated secret execution semantics unchanged ------------------

def test_correlated_execution_unchanged():
    g = _g()
    a = _add_skill(g, "compA")
    sec = _add_secret(g, "token")
    act = Node(id="ACTION:run", type=NodeType.ACTION)
    g.add_node(act)
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(a, act.id, EdgeType.EXECUTES)
    paths = PathAnalyzer(g).analyze()
    assert any(p.attack_type == AttackType.CORRELATED_SECRET_EXECUTION for p in paths)
    for p in paths:
        assert not any(s == sec and t == act.id for s, t, _ in p.edges)


# N. Repeated analysis / insertion order deterministic ------------------------

def test_handoff_deterministic_across_insertion_order():
    def build(reversed_order):
        g = _g()
        # Nodes added in differing order; the handoff edge is the same.
        a = _add_skill(g, "compB" if reversed_order else "compA")
        b = _add_skill(g, "compA" if reversed_order else "compB")
        add_handoff(g, "compA", "compB")
        return PathAnalyzer(g).analyze()

    r1 = build(False)
    r2 = build(True)
    k1 = [(p.path_id, p.is_composed, tuple(p.component_ids))
          for p in sorted(r1, key=lambda p: p.path_id)]
    k2 = [(p.path_id, p.is_composed, tuple(p.component_ids))
          for p in sorted(r2, key=lambda p: p.path_id)]
    assert k1 == k2


# Graph-builder API directly (scanner has no handoff inference) ---------------

def test_builder_api_direct_and_scanner_conservative():
    # The Action model has no verb/category for a component transfer, so
    # build_from_actions never emits HANDOFF: automatic scanner inference is
    # conservatively absent by design.
    acts = [
        Action(verb="run", object="script", destination=None, category="EXECUTION"),
        Action(verb="upload", object="report", destination="https://x.example",
               category="NETWORK"),
    ]
    g = build_from_actions(acts, subject_id="compA")
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    # Explicit construction still works at graph level.
    add_handoff(g, "compA", "compB")
    assert any(e.type == EdgeType.HANDOFF for e in g.edges)
    # The handoff walk is present, bounded and not an exfiltration sink.
    hp = [p for p in PathAnalyzer(g).analyze() if "HANDOFF" in [et for _, _, et in p.edges]]
    assert len(hp) == 1
    assert hp[0].is_contiguous
