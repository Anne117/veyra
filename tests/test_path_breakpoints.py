"""Tests for deterministic Attack Path breakpoints (Commit 9).

A breakpoint is an EXISTING semantic graph edge whose removal would interrupt a
proven attack path. Breakpoints must reference only actual path edges, be
deterministic and identity-stable, and never fabricate a flow edge (especially
not SECRET -> ACTION for a correlation).
"""

from veyra.graph import (
    AttackPath,
    AttackType,
    BreakpointImpact,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    breakpoints_for,
    classify_path,
)
from veyra.models import Severity


def _secret_exfil_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL),
        Node(id="SECRET:token", type=NodeType.SECRET),
        Node(id="DATA:payload", type=NodeType.DATA),
        Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO)
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
    return g


def _data_exfil_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL),
        Node(id="DATA:source", type=NodeType.DATA),
        Node(id="DATA:report", type=NodeType.DATA),
        Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "DATA:source", EdgeType.READS)
    g.add_edge("DATA:source", "DATA:report", EdgeType.FLOWS_TO)
    g.add_edge("DATA:report", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
    return g


def _correlated_exec_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL),
        Node(id="SECRET:token", type=NodeType.SECRET),
        Node(id="ACTION:run", type=NodeType.ACTION),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("SKILL:skill", "ACTION:run", EdgeType.EXECUTES)
    return g


def _btypes(bps):
    """Tuple (source, target, edge_type, impact) per breakpoint, in order."""
    return [(b.source_node, b.target_node, b.edge_type, b.impact.value) for b in bps]


# --- A/B: secret & data exfiltration breakpoints ------------------------------

def test_secret_exfiltration_breakpoints():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert _btypes(p.breakpoints) == [
        ("SKILL:skill", "SECRET:token", "READS", "ACCESS"),
        ("SECRET:token", "DATA:payload", "FLOWS_TO", "DATA_FLOW"),
        ("DATA:payload", "ENDPOINT:https://evil.com", "SENDS_TO", "EXTERNAL_TRANSMISSION"),
    ]
    reasons = [b.reason for b in p.breakpoints]
    assert reasons == [
        "Restricts access to the sensitive asset.",
        "Breaks the proven data lineage.",
        "Prevents transmission to the external endpoint.",
    ]


def test_data_exfiltration_breakpoints():
    p = PathAnalyzer(_data_exfil_graph()).analyze()[0]
    assert p.attack_type == AttackType.DATA_EXFILTRATION
    types = [b.edge_type for b in p.breakpoints]
    assert types == ["READS", "FLOWS_TO", "SENDS_TO"]
    assert all(b.impact in (BreakpointImpact.ACCESS, BreakpointImpact.DATA_FLOW,
                            BreakpointImpact.EXTERNAL_TRANSMISSION) for b in p.breakpoints)


# --- C: breakpoints reference only actual edges -------------------------------

def test_breakpoints_reference_only_actual_edges():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    actual = {(s, t, et) for s, t, et in p.edges}
    for b in p.breakpoints:
        assert (b.source_node, b.target_node, b.edge_type) in actual, \
            f"breakpoint references nonexistent edge {b}"
    # Every walk edge is represented.
    assert {(b.source_node, b.target_node, b.edge_type) for b in p.breakpoints} == actual


# --- D: correlated execution never fabricates SECRET -> ACTION ----------------

def test_correlated_execution_breakpoints_no_fake_edge():
    p = PathAnalyzer(_correlated_exec_graph()).analyze()[0]
    assert p.attack_type == AttackType.CORRELATED_SECRET_EXECUTION
    bts = _btypes(p.breakpoints)
    # Both control edges are exposed: READS (shared-skill) and EXECUTES (walk).
    assert ("SKILL:skill", "SECRET:token", "READS", "ACCESS") in bts
    assert ("SKILL:skill", "ACTION:run", "EXECUTES", "EXECUTION") in bts
    # There is NO fabricated SECRET -> ACTION edge.
    assert not any(s == "SECRET:token" and t == "ACTION:run" for s, t, _, _ in bts)
    # No data-flow labels on a correlation.
    assert not any(iv == "DATA_FLOW" or iv == "EXTERNAL_TRANSMISSION" for _, _, _, iv in bts)


# --- E: UNKNOWN has no breakpoints --------------------------------------------

def test_unknown_no_breakpoints():
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")])
    classify_path(p)
    # UNKNOWN (no sink) -> no breakpoints.
    bps = breakpoints_for(p)
    assert p.attack_type == AttackType.UNKNOWN
    assert bps == []


def test_noncontiguous_path_no_breakpoints():
    p = AttackPath(
        nodes=["SKILL:skill", "SECRET:token", "ENDPOINT:https://evil.com"],
        edges=[("SKILL:skill", "SECRET:token", "READS"),
               ("SKILL:skill", "ENDPOINT:https://evil.com", "SENDS_TO")],
    )
    classify_path(p)
    assert p.attack_type == AttackType.UNKNOWN
    assert breakpoints_for(p) == []


# --- F: insertion-order independence ------------------------------------------

def test_breakpoints_stable_across_insertion_order():
    def build(reversed_order):
        g = SecurityGraph()
        nodes = [
            Node(id="SKILL:skill", type=NodeType.SKILL),
            Node(id="SECRET:token", type=NodeType.SECRET),
            Node(id="DATA:payload", type=NodeType.DATA),
            Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT),
        ]
        seq = list(reversed(nodes)) if reversed_order else nodes
        for n in seq:
            g.add_node(n)
        g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
        g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO)
        g.add_edge("DATA:payload", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
        return PathAnalyzer(g).analyze()[0]

    a, b = build(False), build(True)
    assert _btypes(a.breakpoints) == _btypes(b.breakpoints)
    assert [bp.to_dict() for bp in a.breakpoints] == [bp.to_dict() for bp in b.breakpoints]


# --- G: breakpoint ordering deterministic -------------------------------------

def test_breakpoint_ordering_deterministic_across_analyses():
    g = _secret_exfil_graph()
    r1 = [bp.to_dict() for bp in PathAnalyzer(g).analyze()[0].breakpoints]
    r2 = [bp.to_dict() for bp in PathAnalyzer(g).analyze()[0].breakpoints]
    r3 = [bp.to_dict() for bp in PathAnalyzer(g).analyze()[0].breakpoints]
    assert r1 == r2 == r3


# --- H: metadata changes do not change breakpoints ----------------------------

def test_metadata_changes_do_not_change_breakpoints():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    baseline = [bp.to_dict() for bp in p.breakpoints]
    p.title = "changed title"
    p.description = "changed description"
    p.severity = Severity.LOW
    p.breakpoints = breakpoints_for(p)  # recompute
    assert [bp.to_dict() for bp in p.breakpoints] == baseline


# --- I: serialization ---------------------------------------------------------

def test_to_dict_serializes_breakpoints():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    d = p.to_dict()
    assert "breakpoints" in d
    assert len(d["breakpoints"]) == 3
    b0 = d["breakpoints"][0]
    for key in ("source_node", "target_node", "edge_type", "reason", "impact"):
        assert key in b0
    assert b0["edge_type"] == "READS"
    assert b0["impact"] == "ACCESS"


def test_correlated_to_dict_breakpoints():
    p = PathAnalyzer(_correlated_exec_graph()).analyze()[0]
    d = p.to_dict()
    bts = [(b["source_node"], b["target_node"], b["edge_type"]) for b in d["breakpoints"]]
    assert ("SKILL:skill", "SECRET:token", "READS") in bts
    assert ("SKILL:skill", "ACTION:run", "EXECUTES") in bts
    assert not any(s == "SECRET:token" and t == "ACTION:run" for s, t, _ in bts)
