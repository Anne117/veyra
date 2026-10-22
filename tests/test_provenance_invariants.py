"""The assertion layer: a path may not claim more than it proves.

These tests cover two things and deliberately keep them apart:

- the PRODUCER (``assess_risk``) caps declared severity/confidence at the proven
  walk, one-sidedly, so a correlation-only path can no longer serialize
  ``severity=HIGH`` beside ``risk_severity=MEDIUM``;
- the AUDITOR (:mod:`veyra.invariants`) must still *catch* that shape when it is
  built by hand, because an invariant that only ever sees already-fixed input
  proves nothing.
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
from veyra.invariants import (
    PROVEN_CEILING,
    ProvenanceInvariantError,
    assert_provenance,
    check_attack_paths,
    check_policy_results,
    check_provenance,
)
from veyra.models import Confidence, Severity
from veyra.policy import PolicyEngine
from veyra.scanner import scan_path


def _correlated_graph(edge_severity="HIGH"):
    """Secret read + execution by the same skill: a correlation, not a flow."""
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL),
        Node(id="SECRET:token", type=NodeType.SECRET),
        Node(id="ACTION:run", type=NodeType.ACTION),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS,
               attributes={"severity": edge_severity, "confidence": edge_severity})
    g.add_edge("SKILL:skill", "ACTION:run", EdgeType.EXECUTES,
               attributes={"severity": edge_severity, "confidence": edge_severity})
    return g


def _secret_exfil_graph(edge_severity="LOW"):
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL),
        Node(id="SECRET:token", type=NodeType.SECRET),
        Node(id="ENDPOINT:https://evil.test", type=NodeType.ENDPOINT),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS,
               attributes={"severity": edge_severity, "confidence": edge_severity})
    g.add_edge("SECRET:token", "ENDPOINT:https://evil.test", EdgeType.SENDS_TO,
               attributes={"severity": edge_severity, "confidence": edge_severity})
    return g


# --- producer: one-sided clamp ------------------------------------------------


def test_correlation_does_not_carry_high_metadata_into_the_report():
    """The defect: HIGH edge metadata made a MEDIUM correlation declare HIGH."""
    p = PathAnalyzer(_correlated_graph("HIGH")).analyze()[0]
    assert p.attack_type == AttackType.CORRELATED_SECRET_EXECUTION
    # Proven semantics are unchanged -- a correlation is MEDIUM/MEDIUM.
    assert (p.risk_severity, p.risk_confidence, p.risk_score) == (
        Severity.MEDIUM, Confidence.MEDIUM, 38)
    # And the declared pair no longer outruns them in a serialized report.
    assert (p.severity, p.confidence) == (Severity.MEDIUM, Confidence.MEDIUM)
    assert p.to_dict()["severity"] == "MEDIUM"
    assert p.to_dict()["risk_severity"] == "MEDIUM"


def test_clamp_never_raises_a_declared_value():
    """Proof is a floor for the verdict, never a ceiling lifted by metadata."""
    p = PathAnalyzer(_secret_exfil_graph("LOW")).analyze()[0]
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert p.risk_severity == Severity.CRITICAL
    # Weaker edge metadata stays where it is (the MEDIUM metadata default); it is
    # certainly not promoted to the earned CRITICAL.
    assert p.severity == Severity.MEDIUM
    assert p.confidence == Confidence.MEDIUM


def test_unknown_walk_is_downgraded_to_the_ceiling():
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")],
                   severity=Severity.HIGH, confidence=Confidence.HIGH)
    classify_path(p)
    assess_risk(p)
    assert p.attack_type == AttackType.UNKNOWN
    assert (p.severity, p.confidence) == (Severity.INFO, Confidence.LOW)


# --- auditor: catches what the producer would have fixed ---------------------


def test_high_on_a_correlation_is_reported_as_unproven():
    p = AttackPath(nodes=["SKILL:skill", "ACTION:run"],
                   edges=[("SKILL:skill", "ACTION:run", "EXECUTES")],
                   associated_edges=[("SKILL:skill", "SECRET:token", "READS")],
                   severity=Severity.HIGH, confidence=Confidence.HIGH)
    p.ensure_path_id()
    classify_path(p)
    assess_risk(p)
    # Re-introduce the defect the producer now prevents, then audit it.
    p.severity, p.confidence = Severity.HIGH, Confidence.HIGH
    violations = check_attack_paths([p])
    kinds = {v.kind for v in violations}
    assert kinds == {"unproven_severity", "unproven_confidence"}
    assert all(v.subject == p.path_id for v in violations)


def test_risk_above_the_ceiling_is_reported_too():
    """The risk model is inside the assertion surface, not above it."""
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")])
    classify_path(p)
    assess_risk(p)
    p.risk_severity = Severity.HIGH  # a hypothetical regression in _risk_for
    kinds = {v.kind for v in check_attack_paths([p])}
    assert "risk_above_ceiling" in kinds


def test_path_without_identity_is_reported():
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")])
    classify_path(p)
    assess_risk(p)
    violations = check_attack_paths([p])
    # One defect, one report: identity is absent, so there is nothing to compare.
    assert [v.kind for v in violations] == ["missing_path_id"]


def test_forged_identity_is_reported():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    p.path_id = "deadbeef"
    assert [v.kind for v in check_attack_paths([p])] == ["path_id_mismatch"]


def test_edge_absent_from_the_graph_is_reported():
    g = _secret_exfil_graph()
    p = PathAnalyzer(g).analyze()[0]
    p.nodes = list(p.nodes) + ["ENDPOINT:https://other.test"]
    p.edges = list(p.edges) + [("SECRET:token", "ENDPOINT:https://other.test",
                                "SENDS_TO")]
    p.ensure_path_id()  # a real identity for the forged walk
    kinds = {v.kind for v in check_attack_paths([p], graph=g)}
    assert "phantom_edge" in kinds
    assert "phantom_node" in kinds


def test_policy_result_pointing_at_a_missing_path_is_reported():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    results = PolicyEngine().evaluate([p])
    orphan = type(results[0])(policy_id="SECRET-EXFILTRATION-001",
                              path_id="not-a-real-path", violated=True,
                              reason="x")
    kinds = {v.kind for v in check_policy_results([p], list(results) + [orphan])}
    assert kinds == {"orphan_policy_result"}


def test_violation_resting_on_an_unproven_walk_is_reported():
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")])
    classify_path(p)
    assess_risk(p)
    p.ensure_path_id()
    # Build the shape directly: a violated result on an UNKNOWN path.
    from veyra.policy import PolicyResult
    bad = PolicyResult(policy_id="SECRET-EXFILTRATION-001", path_id=p.path_id,
                       violated=True, reason="claims exfiltration")
    kinds = {v.kind for v in check_policy_results([p], [bad])}
    assert kinds == {"violation_without_proof"}


def test_duplicate_evaluation_is_reported():
    p = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    results = PolicyEngine().evaluate([p])
    kinds = {v.kind for v in check_policy_results([p], list(results) + list(results))}
    assert kinds == {"duplicate_policy_result"}


def test_assert_provenance_raises_with_every_violation():
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")],
                   severity=Severity.CRITICAL, confidence=Confidence.HIGH)
    classify_path(p)
    assess_risk(p)
    p.severity = Severity.CRITICAL
    try:
        assert_provenance([p])
    except ProvenanceInvariantError as exc:
        assert exc.violations
        assert "unproven_severity" in {v.kind for v in exc.violations}
        assert isinstance(exc, AssertionError)
    else:  # pragma: no cover
        raise AssertionError("assert_provenance did not raise")


# --- end to end: a real scan satisfies the invariants ------------------------


def test_real_scan_paths_are_traceable_end_to_end():
    result = scan_path("tests/fixtures/attacks/multi-stage/exfiltration-flow")
    assert len(result.attack_paths) == 1
    assert check_provenance(result.attack_paths, result.policy_results) == []
    assert len(result.policy_results) == 3
    # The proven data flow keeps its earned HIGH; the metadata default (MEDIUM)
    # is not what the report calls severity any more than the ceiling is.
    assert result.attack_paths[0].attack_type == AttackType.DATA_EXFILTRATION
    assert result.attack_paths[0].risk_severity == Severity.HIGH
    assert result.attack_paths[0].severity == Severity.MEDIUM


def test_ceiling_table_covers_every_attack_type():
    assert set(PROVEN_CEILING) == {t.value for t in AttackType}
