"""Tests for branch-aware handoff composition (Commit: feat(graph): model
branch-aware handoff composition).

At a HANDOFF head with multiple outgoing HANDOFF edges, every deterministic
maximal path is emitted. Only REAL explicit HANDOFF edges establish composition
— never shared DATA/SECRET/ENDPOINT, PRODUCES+READS, USES, names, files, or
generic calls. No cross-branch path is ever constructed.
"""

from veyra.graph import (
    AttackType,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    build_from_actions,
)
from veyra.step_sequence import Action


def _g():
    return SecurityGraph()


def _skills(g, *comps):
    for c in comps:
        g.add_node(Node(id=f"SKILL:{c}", type=NodeType.SKILL, label=c))


def _edges(g, pairs):
    """Add HANDOFF edges from (source, target) pairs."""
    for (s, t) in pairs:
        g.add_edge(f"SKILL:{s}", f"SKILL:{t}", EdgeType.HANDOFF)


def _composed_paths(g):
    return [p for p in PathAnalyzer(g).analyze(compose=True) if p.is_composed]


# A. Single branch ------------------------------------------------------------

def test_single_branch_one_path():
    g = _g(); _skills(g, "A", "B"); _edges(g, [("A", "B")])
    cp = _composed_paths(g)
    assert len(cp) == 1
    assert cp[0].nodes == ["SKILL:A", "SKILL:B"]
    assert cp[0].component_ids == ["A", "B"]


# B. Linear multi-hop ----------------------------------------------------------

def test_linear_multihop_one_path():
    g = _g(); _skills(g, "A", "B", "C"); _edges(g, [("A", "B"), ("B", "C")])
    cp = _composed_paths(g)
    assert len(cp) == 1
    assert cp[0].nodes == ["SKILL:A", "SKILL:B", "SKILL:C"]


# C. Two-way branch -----------------------------------------------------------

def test_two_way_branch_two_paths():
    g = _g(); _skills(g, "A", "B", "C"); _edges(g, [("A", "B"), ("A", "C")])
    paths = sorted(_composed_paths(g), key=lambda p: p.path_id)
    assert len(paths) == 2
    nodes_set = {tuple(p.nodes) for p in paths}
    assert nodes_set == {("SKILL:A", "SKILL:B"), ("SKILL:A", "SKILL:C")}
    assert {tuple(p.component_ids) for p in paths} == {("A", "B"), ("A", "C")}


# D. Two-level branch ----------------------------------------------------------

def test_two_level_branch_two_paths():
    g = _g(); _skills(g, "A", "B", "C", "D", "E")
    _edges(g, [("A", "B"), ("A", "C"), ("B", "D"), ("C", "E")])
    paths = sorted(_composed_paths(g), key=lambda p: p.path_id)
    assert len(paths) == 2
    nodes_set = {tuple(p.nodes) for p in paths}
    assert nodes_set == {("SKILL:A", "SKILL:B", "SKILL:D"),
                         ("SKILL:A", "SKILL:C", "SKILL:E")}


# E. Asymmetric branch --------------------------------------------------------

def test_asymmetric_branch_three_paths():
    # A->B, A->C, B->D, B->E  =>  A->B->D, A->B->E, A->C
    g = _g(); _skills(g, "A", "B", "C", "D", "E")
    _edges(g, [("A", "B"), ("A", "C"), ("B", "D"), ("B", "E")])
    paths = sorted(_composed_paths(g), key=lambda p: p.path_id)
    assert len(paths) == 3
    nodes_set = {tuple(p.nodes) for p in paths}
    assert nodes_set == {("SKILL:A", "SKILL:B", "SKILL:D"),
                         ("SKILL:A", "SKILL:B", "SKILL:E"),
                         ("SKILL:A", "SKILL:C")}


# F. Deep branch ---------------------------------------------------------------

def test_deep_branch_two_paths():
    g = _g(); _skills(g, "A", "B", "C", "D", "E", "F", "G")
    _edges(g, [("A", "B"), ("A", "C"), ("B", "D"), ("C", "E"),
               ("D", "F"), ("E", "G")])
    paths = sorted(_composed_paths(g), key=lambda p: p.path_id)
    assert len(paths) == 2
    nodes_set = {tuple(p.nodes) for p in paths}
    assert nodes_set == {("SKILL:A", "SKILL:B", "SKILL:D", "SKILL:F"),
                         ("SKILL:A", "SKILL:C", "SKILL:E", "SKILL:G")}


# G. Different insertion order -> identical -----------------------------------

def test_different_insertion_order_identical():
    def build(order_is_forward):
        g = _g(); _skills(g, "A", "B", "C", "D", "E")
        pairs = [("A", "B"), ("A", "C"), ("B", "D"), ("C", "E")]
        if not order_is_forward:
            pairs.reverse()
        _edges(g, pairs)
        paths = sorted(_composed_paths(g), key=lambda p: p.path_id)
        return [(p.path_id, tuple(p.component_ids), tuple(p.nodes)) for p in paths]
    assert build(True) == build(False)


# H. Repeated analysis ---------------------------------------------------------

def test_repeated_analysis_identical():
    g = _g(); _skills(g, "A", "B", "C")
    _edges(g, [("A", "B"), ("A", "C")])
    r1 = [(p.path_id, tuple(p.nodes)) for p in _composed_paths(g)]
    r2 = [(p.path_id, tuple(p.nodes)) for p in _composed_paths(g)]
    r3 = [(p.path_id, tuple(p.nodes)) for p in _composed_paths(g)]
    assert r1 == r2 == r3


# I. Pure cycle ----------------------------------------------------------------

def test_pure_cycle_terminates_no_path():
    g = _g(); _skills(g, "A", "B", "C")
    _edges(g, [("A", "B"), ("B", "C"), ("C", "A")])
    assert _composed_paths(g) == []  # no true head


# J. Head-attached cycle -------------------------------------------------------

def test_head_attached_cycle_finite():
    # A->B, B->C, C->B. Head A emits A->B->C (C revisits B, stops).
    g = _g(); _skills(g, "A", "B", "C")
    _edges(g, [("A", "B"), ("B", "C"), ("C", "B")])
    paths = sorted(_composed_paths(g), key=lambda p: p.path_id)
    assert len(paths) == 1
    p = paths[0]
    assert p.nodes == ["SKILL:A", "SKILL:B", "SKILL:C"]
    # B and C each appear once within the walk (no duplication / no revisit).
    assert len(p.nodes) == len(set(p.nodes))
    assert p.is_contiguous


# K. Pure branch risk / control-only ------------------------------------------

def test_pure_branch_control_only():
    g = _g(); _skills(g, "A", "B", "C")
    _edges(g, [("A", "B"), ("A", "C")])
    for p in _composed_paths(g):
        assert p.attack_type == AttackType.UNKNOWN
        assert p.risk_score == 0
        assert p.evidence == []
        assert p.breakpoints == []


# No cross-branch fabricated paths --------------------------------------------

def test_no_cross_branch_paths():
    g = _g(); _skills(g, "A", "B", "C", "D", "E")
    _edges(g, [("A", "B"), ("A", "C"), ("B", "D"), ("C", "E")])
    for p in _composed_paths(g):
        # No walk may mix targets from different branches (A->B->E, A->C->D...).
        for i in range(len(p.edges) - 1):
            # consecutive edges share the middle node contiguously; cross-branch
            # would violate contiguity, which is already asserted by is_contiguous.
            assert p.is_contiguous
        assert len({tuple(p.nodes)}) == 1
    # Only the two real walks exist.
    assert {tuple(p.nodes) for p in _composed_paths(g)} == {
        ("SKILL:A", "SKILL:B", "SKILL:D"),
        ("SKILL:A", "SKILL:C", "SKILL:E"),
    }


# Negative: shared/related nodes must NOT branch-compose ----------------------

def test_shared_data_not_composition():
    g = _g(); _skills(g, "A", "B")
    d = Node(id="DATA:doc", type=NodeType.DATA); g.add_node(d)
    g.add_edge("SKILL:A", "DATA:doc", EdgeType.PRODUCES)
    g.add_edge("SKILL:B", "DATA:doc", EdgeType.READS)
    assert _composed_paths(g) == []


def test_shared_secret_not_composition():
    g = _g(); _skills(g, "A", "B")
    sec = Node(id="SECRET:s", type=NodeType.SECRET); g.add_node(sec)
    g.add_edge("SKILL:A", "SECRET:s", EdgeType.READS)
    g.add_edge("SKILL:B", "SECRET:s", EdgeType.READS)
    assert _composed_paths(g) == []


def test_produces_plus_reads_not_composition():
    g = _g(); _skills(g, "A", "B")
    d = Node(id="DATA:doc", type=NodeType.DATA); g.add_node(d)
    g.add_edge("SKILL:A", "DATA:doc", EdgeType.PRODUCES)
    g.add_edge("SKILL:B", "DATA:doc", EdgeType.READS)
    assert _composed_paths(g) == []


def test_uses_not_composition():
    g = _g(); _skills(g, "A", "B")
    ep = Node(id="ENDPOINT:https://x.example", type=NodeType.ENDPOINT); g.add_node(ep)
    g.add_edge("SKILL:B", "ENDPOINT:https://x.example", EdgeType.USES)
    assert _composed_paths(g) == []


def test_same_endpoint_not_composition():
    g = _g(); _skills(g, "A", "B")
    sec = Node(id="SECRET:sA", type=NodeType.SECRET); g.add_node(sec)
    ep = Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT); g.add_node(ep)
    g.add_edge("SKILL:A", "SECRET:sA", EdgeType.READS)
    g.add_edge("SECRET:sA", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO)
    g.add_edge("SKILL:B", "SECRET:sA", EdgeType.READS)
    assert _composed_paths(g) == []


def test_same_mcp_not_composition():
    g = _g(); _skills(g, "A", "B")
    mcp = Node(id="MCPSERVER:filesystem", type=NodeType.MCPSERVER); g.add_node(mcp)
    g.add_edge("SKILL:A", "MCPSERVER:filesystem", EdgeType.USES)
    g.add_edge("SKILL:B", "MCPSERVER:filesystem", EdgeType.USES)
    assert _composed_paths(g) == []


def test_name_like_string_not_composition():
    g = _g(); _skills(g, "A", "B")
    act = Node(id="ACTION:compB", type=NodeType.ACTION); g.add_node(act)
    g.add_edge("SKILL:A", "ACTION:compB", EdgeType.EXECUTES)
    assert _composed_paths(g) == []


def test_generic_function_and_tool_call_not_composition():
    g = _g(); _skills(g, "A", "B")
    act = Node(id="ACTION:foo", type=NodeType.ACTION); g.add_node(act)
    g.add_edge("SKILL:A", "ACTION:foo", EdgeType.EXECUTES)
    tool = Node(id="TOOL:send", type=NodeType.TOOL); g.add_node(tool)
    g.add_edge("SKILL:B", "TOOL:send", EdgeType.USES)
    assert _composed_paths(g) == []


# End-to-end via explicit TRANSFER actions -----------------------------------

def test_branch_end_to_end_transfer_actions():
    # compA hands off to compB and compC; compB->compD; compC->compE.
    graphs = []
    for (src, dst) in [("compA", "compB"), ("compA", "compC"),
                       ("compB", "compD"), ("compC", "compE")]:
        g = build_from_actions([Action(verb="handoff", object="", destination=dst,
                                       category="TRANSFER")], subject_id=src)
        graphs.append(g)
    merged = _g()
    for g in graphs:
        for node in g.nodes.values():
            if merged.get_node(node.id) is None:
                merged.get_or_create(node.id, node.type, label=node.label)
        for e in g.edges:
            merged.add_edge(e.source, e.target, e.type, attributes=dict(e.attributes))
    paths = sorted(_composed_paths(merged), key=lambda p: p.path_id)
    assert len(paths) == 2
    nodes_set = {tuple(p.nodes) for p in paths}
    assert nodes_set == {("SKILL:compA", "SKILL:compB", "SKILL:compD"),
                         ("SKILL:compA", "SKILL:compC", "SKILL:compE")}
    # Both paths carry only actual HANDOFF edges, contiguously.
    for p in paths:
        assert p.is_contiguous
        assert all(et == "HANDOFF" for _, _, et in p.edges)
