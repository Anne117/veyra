"""Tests for multi-hop handoff composition (Commit: feat(graph): add multi-hop
handoff composition).

A composed control path may contain multiple explicit HANDOFF edges. Only real
HANDOFF edges establish composition. Multi-hop chains emit ONE composed
contiguous walk. HANDOFF stays control-only: a pure chain is UNKNOWN, risk 0,
no evidence. No new inference from shared names/produces/uses/endpoints.
"""

from veyra.graph import (
    AttackType,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    build_from_actions,
    path_id_of,
)
from veyra.step_sequence import Action


def _g():
    return SecurityGraph()


def _skills(g, *comps):
    ids = {}
    for c in comps:
        n = Node(id=f"SKILL:{c}", type=NodeType.SKILL, label=c)
        g.add_node(n)
        ids[c] = n.id
    return ids


def _chain(g, *comps):
    """Add HANDOFF edges A->B->C for consecutive pairs."""
    for i in range(len(comps) - 1):
        g.add_edge(f"SKILL:{comps[i]}", f"SKILL:{comps[i+1]}", EdgeType.HANDOFF)


# G. one HANDOFF edge -> one composed path ------------------------------------

def test_single_handoff_one_composed_path():
    g = _g()
    _skills(g, "A", "B")
    _chain(g, "A", "B")
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert len(composed) == 1
    p = composed[0]
    assert p.nodes == ["SKILL:A", "SKILL:B"]
    assert p.edges == [("SKILL:A", "SKILL:B", "HANDOFF")]
    assert p.component_ids == ["A", "B"]
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0
    assert p.evidence == []


# H. two HANDOFF edges A->B->C produce exactly one composed multi-hop path ----

def test_two_handoff_edges_one_multi_hop_path():
    g = _g()
    _skills(g, "A", "B", "C")
    _chain(g, "A", "B", "C")
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    # Exactly ONE composed path (maximal chain A->B->C, not sub-chains).
    assert len(composed) == 1
    p = composed[0]
    assert p.nodes == ["SKILL:A", "SKILL:B", "SKILL:C"]
    assert p.edges == [("SKILL:A", "SKILL:B", "HANDOFF"),
                       ("SKILL:B", "SKILL:C", "HANDOFF")]
    assert p.component_ids == ["A", "B", "C"]
    assert p.is_contiguous
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0
    assert p.evidence == []


# End-to-end via explicit TRANSFER Actions ------------------------------------

def test_multi_hop_via_transfer_actions_end_to_end():
    acts = [
        Action(verb="handoff", object="", destination="compB", category="TRANSFER"),
        Action(verb="handoff", object="", destination="compC", category="TRANSFER"),
    ]
    # Both actions belong to compA; but A transfers to B and (from the same
    # subject) to C would be two separate edges. For a truthful A->B->C chain we
    # need B->C from B. Build a single graph then add explicit B->C edge.
    g_a = build_from_actions([acts[0]], subject_id="compA")
    g_c = build_from_actions([Action(verb="handoff", object="", destination="compC",
                                     category="TRANSFER")], subject_id="compB")
    # Merge the two graphs.
    merged = _g()
    for g in (g_a, g_c):
        for node in g.nodes.values():
            if merged.get_node(node.id) is None:
                merged.get_or_create(node.id, node.type, label=node.label)
        for e in g.edges:
            merged.add_edge(e.source, e.target, e.type, attributes=dict(e.attributes))
    # Explicit A->B->C handoff chain is present.
    chain_edges = [(e.source, e.target) for e in merged.edges
                   if e.type == EdgeType.HANDOFF]
    assert ("SKILL:compA", "SKILL:compB") in chain_edges
    assert ("SKILL:compB", "SKILL:compC") in chain_edges
    composed = [p for p in PathAnalyzer(merged).analyze(compose=True) if p.is_composed]
    assert len(composed) == 1
    p = composed[0]
    assert p.nodes == ["SKILL:compA", "SKILL:compB", "SKILL:compC"]
    assert len(p.edges) == 2
    assert all(et == "HANDOFF" for _, _, et in p.edges)
    assert p.is_contiguous
    assert p.component_ids == ["compA", "compB", "compC"]


# A. shared DATA not composition ----------------------------------------------

def test_shared_data_no_composition():
    g = _g()
    ids = _skills(g, "A", "B")
    d = Node(id="DATA:doc", type=NodeType.DATA)
    g.add_node(d)
    g.add_edge(ids["A"], d.id, EdgeType.PRODUCES)
    g.add_edge(ids["B"], d.id, EdgeType.READS)
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    assert [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed] == []


# B. shared SECRET not composition --------------------------------------------

def test_shared_secret_no_composition():
    g = _g()
    ids = _skills(g, "A", "B")
    sec = Node(id="SECRET:token", type=NodeType.SECRET)
    ep = Node(id="ENDPOINT:https://a.example", type=NodeType.ENDPOINT)
    g.add_node(sec); g.add_node(ep)
    g.add_edge(ids["A"], sec.id, EdgeType.READS)
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)
    g.add_edge(ids["B"], sec.id, EdgeType.READS)
    assert not any(e.type == EdgeType.HANDOFF for e in g.edges)
    assert [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed] == []


# C. PRODUCES + READS not composition -----------------------------------------

def test_produces_plus_reads_no_composition():
    g = _g()
    ids = _skills(g, "A", "B")
    d = Node(id="DATA:doc", type=NodeType.DATA)
    g.add_node(d)
    g.add_edge(ids["A"], d.id, EdgeType.PRODUCES)
    g.add_edge(ids["B"], d.id, EdgeType.READS)
    assert [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed] == []


# D. USES not composition -----------------------------------------------------

def test_uses_no_composition():
    g = _g()
    ids = _skills(g, "A", "B")
    ep = Node(id="ENDPOINT:https://x.example", type=NodeType.ENDPOINT)
    g.add_node(ep)
    g.add_edge(ids["B"], ep.id, EdgeType.USES)
    assert [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed] == []


# E. endpoint identity not composition ----------------------------------------

def test_endpoint_identity_no_composition():
    g = _g()
    ids = _skills(g, "A", "B")
    sec = Node(id="SECRET:sA", type=NodeType.SECRET)
    ep = Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT)
    g.add_node(sec); g.add_node(ep)
    g.add_edge(ids["A"], sec.id, EdgeType.READS)
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)
    g.add_edge(ids["B"], "SECRET:sA", EdgeType.READS)
    assert [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed] == []


# F. two independent components with unrelated nodes ---------------------------

def test_two_independent_components_no_composition():
    g = _g()
    ids = _skills(g, "A", "B")
    sec_a = Node(id="SECRET:a", type=NodeType.SECRET)
    sec_b = Node(id="SECRET:b", type=NodeType.SECRET)
    ep_a = Node(id="ENDPOINT:https://a.example", type=NodeType.ENDPOINT)
    ep_b = Node(id="ENDPOINT:https://b.example", type=NodeType.ENDPOINT)
    for n in (sec_a, sec_b, ep_a, ep_b):
        g.add_node(n)
    g.add_edge(ids["A"], sec_a.id, EdgeType.READS)
    g.add_edge(sec_a.id, ep_a.id, EdgeType.SENDS_TO)
    g.add_edge(ids["B"], sec_b.id, EdgeType.READS)
    g.add_edge(sec_b.id, ep_b.id, EdgeType.SENDS_TO)
    assert [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed] == []


# I. repeated analysis identical ----------------------------------------------

def test_repeated_analysis_identical():
    g = _g()
    _skills(g, "A", "B", "C")
    _chain(g, "A", "B", "C")
    r1 = [(p.path_id, tuple(p.component_ids)) for p in PathAnalyzer(g).analyze(compose=True)]
    r2 = [(p.path_id, tuple(p.component_ids)) for p in PathAnalyzer(g).analyze(compose=True)]
    r3 = [(p.path_id, tuple(p.component_ids)) for p in PathAnalyzer(g).analyze(compose=True)]
    assert r1 == r2 == r3


# J. insertion order -> same path_id ------------------------------------------

def test_insertion_order_same_path_id():
    def build(reversed_order):
        g = _g()
        ids = _skills(g, "C" if reversed_order else "A",
                      "B", "A" if reversed_order else "C")
        _chain(g, "A", "B", "C")
        return PathAnalyzer(g).analyze(compose=True)

    p1 = build(False)[0]
    p2 = build(True)[0]
    assert p1.path_id == p2.path_id
    assert p1.nodes == ["SKILL:A", "SKILL:B", "SKILL:C"]
    assert p1.path_id == path_id_of(p1.nodes, p1.edges, p1.associated_edges)


# Path identity: A->B vs A->B->C differ ----------------------------------------

def test_multi_hop_path_ids_differ_from_shorter():
    g1 = _g(); _skills(g1, "A", "B"); _chain(g1, "A", "B")
    g2 = _g(); _skills(g2, "A", "B", "C"); _chain(g2, "A", "B", "C")
    p_ab = PathAnalyzer(g1).analyze(compose=True)[0]
    p_abc = PathAnalyzer(g2).analyze(compose=True)[0]
    assert p_ab.path_id != p_abc.path_id


# K. cycle terminates deterministically ----------------------------------------

def test_handoff_cycle_terminates():
    g = _g()
    _skills(g, "A", "B", "C")
    _chain(g, "A", "B", "C")
    g.add_edge("SKILL:C", "SKILL:A", EdgeType.HANDOFF)  # cycle
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    # A pure HANDOFF cycle (A->B->C->A) has no unambiguous chain head: every
    # node has an incoming HANDOFF. Conservatively no composed path is emitted,
    # and analysis terminates without recursion or infinite duplication.
    assert composed == []
    # Repeated analysis stays deterministically empty and stable.
    r1 = [p.path_id for p in PathAnalyzer(g).analyze(compose=True)]
    r2 = [p.path_id for p in PathAnalyzer(g).analyze(compose=True)]
    assert r1 == r2 == []


# HANDOFF remains control-only (no exfiltration) ------------------------------

def test_handoff_chain_not_exfiltration():
    g = _g()
    _skills(g, "A", "B", "C")
    _chain(g, "A", "B", "C")
    p = PathAnalyzer(g).analyze()[0]
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0
    assert p.evidence == []
    assert p.breakpoints == []


# Mixed: HANDOFF + READS must NOT invent A->secret lineage ---------------------

def test_mixed_handoff_reads_keeps_semantics_separate():
    g = _g()
    ids = _skills(g, "A", "B")
    _chain(g, "A", "B")
    sec = Node(id="SECRET:S", type=NodeType.SECRET)
    ep = Node(id="ENDPOINT:https://e.example", type=NodeType.ENDPOINT)
    g.add_node(sec); g.add_node(ep)
    g.add_edge(ids["B"], sec.id, EdgeType.READS)
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)
    # B has a real exfiltration path (B reads secret -> sends). A->B is a
    # handoff. The two must remain DISTINCT semantics.
    all_paths = PathAnalyzer(g).analyze()
    handoff_paths = [p for p in all_paths if "HANDOFF" in [et for _, _, et in p.edges]]
    exfil_paths = [p for p in all_paths if p.attack_type == AttackType.SECRET_EXFILTRATION]
    # The HANDOFF path is control-only, not an exfiltration of the secret.
    assert len(handoff_paths) == 1
    assert handoff_paths[0].attack_type == AttackType.UNKNOWN
    # B's separate exfiltration is a distinct truth path.
    assert len(exfil_paths) == 1
    assert exfil_paths[0].nodes == ["SKILL:B", "SECRET:S", "ENDPOINT:https://e.example"]
