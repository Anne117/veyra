"""Tests for truthful cross-component attack path composition (Commit 10 fix).

Composition is claimed ONLY from semantic components actually represented in the
ordered AttackPath. The current graph model roots every truthful walk at exactly
one SKILL and has no explicit semantic edge connecting two components' SKILLs
within one real walk, so composition is conservatively empty. NO producer
attribution, shared object/secret/endpoint name, or unrelated graph edge may be
used to infer a component transition. All paths remain truthful and contiguous.
"""

from veyra.graph import (
    AttackType,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    path_id_of,
)
from veyra.step_sequence import Action


def _g():
    return SecurityGraph()


def _add_skill(g, name, comp):
    n = Node(id=f"SKILL:{comp}:{name}", type=NodeType.SKILL, label=name)
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


# A/B. Existing single-component exfiltration unchanged ------------------------

def test_single_component_secret_exfil_unchanged():
    g = _g()
    sk = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(sk, sec, EdgeType.READS)
    g.add_edge(sec, ep, EdgeType.SENDS_TO)
    p = PathAnalyzer(g).analyze()[0]
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert p.is_composed is False
    assert p.component_ids == []
    assert p.risk_score == 95
    assert p.to_dict()["is_composed"] is False


def test_single_component_data_exfil_unchanged():
    g = _g()
    sk = _add_skill(g, "a", "compA")
    d = _add_data(g, "source")
    d2 = _add_data(g, "report")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(sk, d, EdgeType.READS)
    g.add_edge(d, d2, EdgeType.FLOWS_TO)
    g.add_edge(d2, ep, EdgeType.SENDS_TO)
    p = PathAnalyzer(g).analyze()[0]
    assert p.attack_type == AttackType.DATA_EXFILTRATION
    assert p.is_composed is False
    assert p.component_ids == []


# C. Producer-only cross-component attribution does NOT compose ---------------

def test_producer_only_attribution_does_not_compose():
    g = _g()
    a = _add_skill(g, "a", "compA")
    x = _add_data(g, "doc")
    b = _add_skill(g, "b", "compB")
    g.add_edge(a, x, EdgeType.PRODUCES)   # A produces doc
    g.add_edge(b, x, EdgeType.READS)      # B reads doc
    # No exfiltration (no SENDS_TO), and crucially no DATA->SKILL edge.
    paths = PathAnalyzer(g).analyze(compose=True)
    assert paths == []
    # Even locally, no fabricated DATA -> SKILL walk.
    local = PathAnalyzer(g).analyze()
    for p in local:
        assert not any(s.startswith("DATA:") and t.startswith("SKILL:")
                       for s, t, _ in p.edges)


# D. Same object producer in another component does NOT compose ---------------

def test_same_object_producer_other_component_does_not_compose():
    # Path A reads secret -> flows to X -> sends to ENDPOINT.
    # Separately, component B PRODUCES X but B is NOT on the ordered A path.
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    x = _add_data(g, "payload")
    ep = _add_ep(g, "https://evil.example")
    b = _add_skill(g, "b", "compB")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, x, EdgeType.FLOWS_TO)
    g.add_edge(x, ep, EdgeType.SENDS_TO)
    g.add_edge(b, x, EdgeType.PRODUCES)   # unrelated: B produces payload
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    # B is not in the A path's nodes/edges, so A->B must NOT be claimed.
    assert composed == []
    # The single-component local exfiltration still exists with correct IDs.
    local = [p for p in PathAnalyzer(g).analyze()]
    assert any(p.attack_type == AttackType.SECRET_EXFILTRATION for p in local)


# E. Shared secret across components does NOT compose -------------------------

def test_shared_secret_does_not_compose():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "shared")
    d = _add_data(g, "payload")
    ep = _add_ep(g, "https://evil.example")
    b = _add_skill(g, "b", "compB")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    g.add_edge(b, sec, EdgeType.READS)   # b reads same secret node
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


# F. Shared endpoint across components does NOT compose -----------------------

def test_shared_endpoint_does_not_compose():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec_a = _add_secret(g, "sA")
    ep = _add_ep(g, "https://evil.example")
    b = _add_skill(g, "b", "compB")
    sec_b = _add_secret(g, "sB")
    g.add_edge(a, sec_a, EdgeType.READS)
    g.add_edge(sec_a, ep, EdgeType.SENDS_TO)
    g.add_edge(b, sec_b, EdgeType.READS)
    g.add_edge(sec_b, ep, EdgeType.SENDS_TO)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


# G. Independent files/components do NOT compose -------------------------------

def test_independent_components_do_not_compose():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec_a = _add_secret(g, "sA")
    ep_a = _add_ep(g, "https://a.example")
    b = _add_skill(g, "b", "compB")
    sec_b = _add_secret(g, "sB")
    ep_b = _add_ep(g, "https://b.example")
    g.add_edge(a, sec_a, EdgeType.READS)
    g.add_edge(sec_a, ep_a, EdgeType.SENDS_TO)
    g.add_edge(b, sec_b, EdgeType.READS)
    g.add_edge(sec_b, ep_b, EdgeType.SENDS_TO)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    assert composed == []


# H. PRODUCES remains non-traversable ------------------------------------------

def test_produces_remains_non_traversable():
    g = _g()
    a = _add_skill(g, "a", "compA")
    d = _add_data(g, "report")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, d, EdgeType.PRODUCES)   # manufactures, NOT data flow
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    # No READS; PRODUCES alone is not a read, so no exfiltration path.
    paths = PathAnalyzer(g).analyze()
    assert all(p.attack_type == AttackType.UNKNOWN for p in paths)


# I. USES remains non-data-flow / non-sink ------------------------------------

def test_uses_remains_non_data_flow():
    g = _g()
    a = _add_skill(g, "a", "compA")
    d = _add_data(g, "doc")
    b = _add_skill(g, "b", "compB")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, d, EdgeType.PRODUCES)
    g.add_edge(d, ep, EdgeType.USES)      # not a send sink
    paths = PathAnalyzer(g).analyze()
    assert not any(p.attack_type in (AttackType.SECRET_EXFILTRATION,
                                     AttackType.DATA_EXFILTRATION) for p in paths)


# J. Correlated secret execution preserved ------------------------------------

def test_correlated_secret_execution_preserved():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    act = Node(id="ACTION:run", type=NodeType.ACTION)
    g.add_node(act)
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(a, act.id, EdgeType.EXECUTES)
    local = PathAnalyzer(g).analyze()
    assert any(p.attack_type == AttackType.CORRELATED_SECRET_EXECUTION for p in local)
    for p in local:
        assert not any(s == sec and t == act.id for s, t, _ in p.edges)
    composed = PathAnalyzer(g).analyze(compose=True)
    assert composed == []


# K. No truthful explicit cross-component edge => composition empty ----------

def test_graph_model_cannot_emit_composed_path_conservatively():
    """Document that the current graph model has no explicit cross-component edge.

    Every truthful walk roots at exactly one SKILL (via _analyze_skill) and no
    edge connects one component's SKILL to another within a real walk. Therefore
    no path is composed, and this is the correct conservative result rather than
    synthesizing an unsupported handoff. This test pins that contract.
    """
    # Build the most plausible "connected" two-component scenario:
    #   A reads secret -> FLOWS_TO X (A produces X) -> SENDS_TO endpoint,
    #   B PRODUCES Y, and X FLOWS_TO Y (Y would be the "handoff target").
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    x = _add_data(g, "x")
    y = _add_data(g, "y")
    ep = _add_ep(g, "https://evil.example")
    b = _add_skill(g, "b", "compB")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, x, EdgeType.FLOWS_TO)
    g.add_edge(a, x, EdgeType.PRODUCES)   # A produces x
    g.add_edge(x, y, EdgeType.FLOWS_TO)
    g.add_edge(b, y, EdgeType.PRODUCES)   # B produces y (NOT on the A path)
    g.add_edge(y, ep, EdgeType.SENDS_TO)
    composed = [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]
    # B is not represented in the ordered A walk; the A->B handoff is NOT
    # justified by the actual graph connectivity of the path itself.
    assert composed == []
    # The single-component walk that does exist is truthful and contiguous.
    local = PathAnalyzer(g).analyze()
    for p in local:
        assert p.is_contiguous
        # The walk's only SKILL is the root component's skill.
        skills = [n for n in p.nodes if n.startswith("SKILL:")]
        assert len(skills) == 1


# Determinism / identity -------------------------------------------------------

def test_composition_metadata_does_not_change_path_id():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://evil.example")
    b = _add_skill(g, "b", "compB")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    g.add_edge(b, d, EdgeType.PRODUCES)   # unrelated producer in compB
    local = PathAnalyzer(g).analyze()[0]
    composed_run = PathAnalyzer(g).analyze(compose=True)
    # The canonical path_id derives only from the semantic walk, never from
    # composition metadata.
    assert path_id_of(local.nodes, local.edges, local.associated_edges) == local.path_id
    for p in composed_run:
        assert path_id_of(p.nodes, p.edges, p.associated_edges) == p.path_id


def test_metadata_changes_do_not_alter_identity():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    p = PathAnalyzer(g).analyze()[0]
    baseline = p.path_id
    p.title = "changed"
    p.description = "changed"
    p.is_composed = True     # flipping metadata must NOT change identity
    p.component_ids = ["compA", "compB"]
    assert path_id_of(p.nodes, p.edges, p.associated_edges) == baseline


def test_duplicate_equivalent_paths_deduped():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)   # duplicate lineage edge
    ids = [p.path_id for p in PathAnalyzer(g).analyze()]
    assert len(ids) == len(set(ids))


def test_order_deterministic_across_analyses():
    g = _g()
    a = _add_skill(g, "a", "compA")
    sec = _add_secret(g, "token")
    d = _add_data(g, "doc")
    ep = _add_ep(g, "https://evil.example")
    g.add_edge(a, sec, EdgeType.READS)
    g.add_edge(sec, d, EdgeType.FLOWS_TO)
    g.add_edge(d, ep, EdgeType.SENDS_TO)
    # Local: one single-component path, deterministic ordering.
    local1 = [p.path_id for p in PathAnalyzer(g).analyze(compose=False)]
    local2 = [p.path_id for p in PathAnalyzer(g).analyze(compose=False)]
    assert local1 == local2 and len(local1) == 1
    # Composed pass: this graph has no truthful cross-component walk, so it
    # yields no composed paths (deterministically).
    comp1 = [p.path_id for p in PathAnalyzer(g).analyze(compose=True)]
    comp2 = [p.path_id for p in PathAnalyzer(g).analyze(compose=True)]
    assert comp1 == comp2 == []
