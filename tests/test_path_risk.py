"""Tests for deterministic Attack Path risk and evidence semantics (Commit 8).

Risk/evidence must be derived only from semantic path facts, be deterministic
and identity-stable (same canonical identity -> same risk/evidence), and never
claim a data-flow the graph does not support.
"""

from veyra.graph import (
    AttackPath,
    AttackType,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    assess_risk,
    classify_path,
)
from veyra.models import Confidence, Severity


def _secret_exfil_graph(with_flow=True):
    """Skill READS Secret ->(FLOWS_TO Data)-> SENDS_TO Endpoint."""
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL),
        Node(id="SECRET:token", type=NodeType.SECRET),
        Node(id="DATA:payload", type=NodeType.DATA),
        Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    if with_flow:
        g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO)
        g.add_edge("DATA:payload", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
    else:
        g.add_edge("SECRET:token", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
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


# --- A/B: proven exfiltration risk/evidence ----------------------------------

def test_secret_exfiltration_has_deterministic_risk_and_evidence():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert p.risk_severity == Severity.CRITICAL
    assert p.risk_confidence == Confidence.HIGH
    assert p.risk_score == 95
    assert p.evidence == ["secret read", "data transformation", "sensitive data flow",
                          "external network send"]
    assert "secret" in p.explanation.lower()
    assert p.to_dict()["evidence"] == p.evidence


def test_data_exfiltration_has_deterministic_risk_and_evidence():
    p = PathAnalyzer(_data_exfil_graph()).analyze()[0]
    assert p.attack_type == AttackType.DATA_EXFILTRATION
    assert p.risk_severity == Severity.HIGH
    assert p.risk_confidence == Confidence.HIGH
    assert p.risk_score == 70
    assert p.to_dict()["risk_score"] == 70


def test_direct_secret_send_no_transform_evidence():
    p = PathAnalyzer(_secret_exfil_graph(with_flow=False)).analyze()[0]
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert p.risk_score == 95
    # No transformation edge => no "data transformation"/"data flow" evidence.
    assert "data transformation" not in p.evidence
    assert "external network send" in p.evidence


# --- C: correlated secret execution -------------------------------------------

def test_correlated_execution_evidence_is_correlation_only():
    p = PathAnalyzer(_correlated_exec_graph()).analyze()[0]
    assert p.attack_type == AttackType.CORRELATED_SECRET_EXECUTION
    assert p.risk_severity == Severity.MEDIUM
    assert p.risk_confidence == Confidence.MEDIUM
    assert p.risk_score == 38  # 45 * 0.85 rounded
    # Evidence lists only shared-skill correlation signals, never a
    # secret-to-action data-flow claim.
    assert p.evidence == ["secret read", "execution"]
    assert "external network send" not in p.evidence
    assert "sensitive data flow" not in p.evidence
    # Explanation must describe it as a shared-skill correlation, not a proven
    # secret->action data flow.
    assert "secret is read by the skill" in p.explanation
    assert "executes an action" in p.explanation
    assert "flows into" not in p.explanation


# --- D: UNKNOWN gets no unsupported evidence ----------------------------------

def test_unknown_no_unsupported_evidence():
    # A bare READ (no sink) stays UNKNOWN.
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:skill", type=NodeType.SKILL))
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    p = PathAnalyzer(g).analyze()
    assert p == []
    # Directly construct a non-contiguous/sinkless path -> UNKNOWN risk.
    raw = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                     edges=[("SKILL:skill", "SECRET:token", "READS")])
    classify_path(raw)
    assess_risk(raw)
    assert raw.attack_type == AttackType.UNKNOWN
    assert raw.risk_score == 0
    assert raw.evidence == []


def test_noncontiguous_path_unknown_risk():
    p = AttackPath(
        nodes=["SKILL:skill", "SECRET:token", "ENDPOINT:https://evil.com"],
        edges=[("SKILL:skill", "SECRET:token", "READS"),
               ("SKILL:skill", "ENDPOINT:https://evil.com", "SENDS_TO")],
    )
    classify_path(p)
    assess_risk(p)
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0
    assert p.evidence == []


# --- E: identity-stable risk/evidence -----------------------------------------

def test_risk_identity_stable_across_insertion_order():
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
    for attr in ("path_id", "risk_score", "evidence", "explanation",
                 "risk_severity", "risk_confidence"):
        av, bv = getattr(a, attr), getattr(b, attr)
        if isinstance(av, list):
            assert list(av) == list(bv)
        else:
            assert av == bv


# --- F: dedup still one path --------------------------------------------------

def test_duplicate_paths_still_deduped_with_risk():
    g = _secret_exfil_graph()
    # Add duplicate/equivalent edges -> single deduped path.
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
    paths = PathAnalyzer(g).analyze()
    assert len(paths) == 1
    assert paths[0].risk_score == 95


# --- G: title/rule metadata does not change risk ------------------------------

def test_title_metadata_does_not_change_risk():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    baseline = (p.risk_score, list(p.evidence), p.risk_severity, p.risk_confidence)
    p.title = "Totally different title"
    p.description = "different description"
    p.severity = Severity.LOW
    p.confidence = Confidence.LOW
    assess_risk(p)  # recompute after mutating non-semantic metadata
    assert (p.risk_score, list(p.evidence), p.risk_severity, p.risk_confidence) == baseline


# --- H: to_dict contains all new fields ---------------------------------------

def test_to_dict_contains_risk_evidence_explanation():
    p = PathAnalyzer(_correlated_exec_graph()).analyze()[0]
    d = p.to_dict()
    for key in ("risk_score", "risk_severity", "risk_confidence", "evidence", "explanation"):
        assert key in d
    assert d["risk_severity"] == "MEDIUM"
    assert d["evidence"] == ["secret read", "execution"]


# --- I: terminal output -------------------------------------------------------

def test_terminal_shows_id_attack_type_risk():
    from veyra.models import ScanResult
    from veyra.reporters import render_terminal
    paths = PathAnalyzer(_secret_exfil_graph()).analyze()
    out = render_terminal(ScanResult(target="x", findings=[], attack_paths=paths))
    assert "Attack Paths" in out
    assert "risk=95" in out
    assert "SECRET_EXFILTRATION" in out
    assert "id " in out
    assert "Secret exposed to external endpoint" in out
