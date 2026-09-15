"""Tests for the deterministic AttackPath Policy Engine (Commit: feat(policy):
add deterministic attack path policies).

Policies evaluate EXISTING AttackPath semantics only. They never perform graph
traversal, never infer attacks, never use rule IDs/finding text/filenames, and
never mutate the paths. UNKNOWN (incl. pure HANDOFF) paths violate nothing.
"""

import copy

from veyra import (
    CORRELATED_SECRET_EXECUTION_POLICY,
    DATA_EXFILTRATION_POLICY,
    SECRET_EXFILTRATION_POLICY,
    Policy,
    PolicyEngine,
    PolicyResult,
)
from veyra.graph import (
    AttackPath,
    AttackType,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
)
from veyra.graph import classify_path


def _g():
    return SecurityGraph()


def _skills(g, *comps):
    for c in comps:
        g.add_node(Node(id=f"SKILL:{c}", type=NodeType.SKILL, label=c))


# --- Real AttackPath construction via the graph machinery -------------------

def _secret_exfil_path():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="DATA:payload", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO)
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO)
    return PathAnalyzer(g).analyze()[0]


def _data_exfil_path():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="DATA:source", type=NodeType.DATA))
    g.add_node(Node(id="DATA:report", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "DATA:source", EdgeType.READS)
    g.add_edge("DATA:source", "DATA:report", EdgeType.FLOWS_TO)
    g.add_edge("DATA:report", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO)
    return PathAnalyzer(g).analyze()[0]


def _correlated_exec_path():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ACTION:run", type=NodeType.ACTION))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("SKILL:skill", "ACTION:run", EdgeType.EXECUTES)
    return PathAnalyzer(g).analyze()[0]


def _pure_handoff_path():
    g = _g(); _skills(g, "A", "B")
    g.add_edge("SKILL:A", "SKILL:B", EdgeType.HANDOFF)
    return PathAnalyzer(g).analyze(compose=True)[0]


def _unknown_attack_path():
    p = AttackPath(nodes=["SKILL:skill", "SECRET:token"],
                   edges=[("SKILL:skill", "SECRET:token", "READS")])
    classify_path(p)
    return p


# A/B/C. Each built-in triggers on its matching AttackType -------------------

def test_secret_exfil_triggers_secret_policy():
    p = _secret_exfil_path()
    results = PolicyEngine().evaluate([p])
    sr = [r for r in results if r.policy_id == "SECRET-EXFILTRATION-001"][0]
    assert sr.violated is True
    assert sr.path_id == p.path_id
    assert "external endpoint" in sr.reason


def test_data_exfil_triggers_data_policy():
    p = _data_exfil_path()
    results = PolicyEngine().evaluate([p])
    dr = [r for r in results if r.policy_id == "DATA-EXFILTRATION-001"][0]
    assert dr.violated is True
    assert dr.path_id == p.path_id


def test_correlated_exec_triggers_correlation_policy():
    p = _correlated_exec_path()
    results = PolicyEngine().evaluate([p])
    cr = [r for r in results if r.policy_id == "CORRELATED-SECRET-EXECUTION-001"][0]
    assert cr.violated is True
    # Review policy, never a proven-data-flow claim.
    assert "require review" in cr.reason


# D/E. UNKNOWN and pure HANDOFF trigger nothing ------------------------------

def test_unknown_triggers_nothing():
    p = _unknown_attack_path()
    assert p.attack_type == AttackType.UNKNOWN
    results = PolicyEngine().evaluate([p])
    assert not any(r.violated for r in results)


def test_pure_handoff_triggers_nothing():
    p = _pure_handoff_path()
    assert p.attack_type == AttackType.UNKNOWN
    assert p.risk_score == 0
    results = PolicyEngine().evaluate([p])
    assert not any(r.violated for r in results)


# F/G/H. Non-proven paths do not trigger exfiltration policies ---------------

def test_secret_reads_without_proven_exfil_triggers_nothing():
    p = _unknown_attack_path()  # READS only; not proven exfiltration
    results = PolicyEngine().evaluate([p])
    assert not any(r.violated for r in results)


def test_sends_to_without_proven_exfil_triggers_nothing():
    # Skill SENDS_TO endpoint, but no object lineage (classic non-exfil shape).
    p = AttackPath(
        nodes=["SKILL:skill", "SECRET:token", "ENDPOINT:https://evil.example"],
        edges=[("SKILL:skill", "SECRET:token", "READS"),
               ("SKILL:skill", "ENDPOINT:https://evil.example", "SENDS_TO")],
    )
    classify_path(p)
    assert p.attack_type == AttackType.UNKNOWN
    results = PolicyEngine().evaluate([p])
    assert not any(r.violated for r in results)


def test_uses_endpoint_triggers_no_exfil_policy():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("ENDPOINT:https://evil.example", "SKILL:skill", EdgeType.USES)
    # No proven exfiltration path; USES is not a send sink.
    g.add_edge("SKILL:skill", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO)
    paths = PathAnalyzer(g).analyze()
    results = PolicyEngine().evaluate(paths)
    assert not any(r.violated for r in results)


# I. Disabled policy not evaluated -------------------------------------------

def test_disabled_policy_not_evaluated():
    off = Policy(policy_id="SECRET-EXFILTRATION-001", name="x", description="x",
                  enabled=False)
    engine = PolicyEngine(policies=[off, DATA_EXFILTRATION_POLICY])
    p_secret = _secret_exfil_path()
    p_data = _data_exfil_path()
    results = engine.evaluate([p_secret, p_data])
    assert not any(r.policy_id == "SECRET-EXFILTRATION-001" for r in results)
    assert any(r.policy_id == "DATA-EXFILTRATION-001" and r.violated for r in results)


# J/K. Multiple paths and policies -> deterministic ordering -----------------

def test_multiple_paths_multiple_policies_deterministic():
    paths = [_secret_exfil_path(), _data_exfil_path(), _correlated_exec_path(),
             _pure_handoff_path()]
    r1 = PolicyEngine().evaluate(paths)
    r2 = PolicyEngine().evaluate(paths)
    keys = [(r.policy_id, r.path_id) for r in r1]
    assert keys == sorted(keys)
    assert [r.to_dict() for r in r1] == [r.to_dict() for r in r2]


# L. Repeated evaluation identical ---------------------------------------------

def test_repeated_evaluation_identical():
    p = _secret_exfil_path()
    a = [r.to_dict() for r in PolicyEngine().evaluate([p])]
    b = [r.to_dict() for r in PolicyEngine().evaluate([p])]
    c = [r.to_dict() for r in PolicyEngine().evaluate([p])]
    assert a == b == c


# M. Policy evaluation does not mutate AttackPath -----------------------------

def test_policy_evaluation_no_mutation():
    p = _secret_exfil_path()
    before = (p.attack_type, p.risk_score, list(p.nodes), list(p.edges),
              list(p.associated_edges), list(p.component_ids))
    snap = copy.deepcopy(p.to_dict())
    PolicyEngine().evaluate([p])
    after = (p.attack_type, p.risk_score, list(p.nodes), list(p.edges),
             list(p.associated_edges), list(p.component_ids))
    assert before == after
    assert p.to_dict() == snap


# N. Policy serialization deterministic ---------------------------------------

def test_policy_result_serialization_deterministic():
    p = _data_exfil_path()
    results = PolicyEngine().evaluate([p])
    r = [x for x in results if x.policy_id == "DATA-EXFILTRATION-001"][0]
    d = r.to_dict()
    assert set(d) >= {"policy_id", "path_id", "violated", "reason"}
    assert d["policy_id"] == "DATA-EXFILTRATION-001"
    # No timestamps/random ids.
    assert "time" not in d and "random" not in d


# O. path_id preserved exactly -------------------------------------------------

def test_path_id_preserved():
    p = _secret_exfil_path()
    for r in PolicyEngine().evaluate([p]):
        assert r.path_id == p.path_id


# --- Policy model serialization ----------------------------------------------

def test_policy_model_serialization():
    for pol in (SECRET_EXFILTRATION_POLICY, DATA_EXFILTRATION_POLICY,
                CORRELATED_SECRET_EXECUTION_POLICY):
        d = pol.to_dict()
        assert d["policy_id"] == pol.policy_id
        assert d["name"]
        assert d["description"]
        assert d["enabled"] is True


# Policies consume AttackPath semantics only (not finding/source text) --------

def test_policy_ignores_non_semantic_text():
    # Same SECRET_EXFILTRATION semantics but arbitrary title/description text
    # must trigger identically — policy reacts to attack_type only.
    p = _secret_exfil_path()
    r1 = {r.policy_id: r.violated for r in PolicyEngine().evaluate([p])}
    q = copy.deepcopy(p)
    q.title = "completely different title"
    q.description = "some arbitrary source text without 'secret'"
    r2 = {r.policy_id: r.violated for r in PolicyEngine().evaluate([q])}
    assert r1 == r2


# End-to-end: graph -> analyzer -> attack path -> policy engine --------------

def test_end_to_end_secret_exfil():
    p = _secret_exfil_path()
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    result = [r for r in PolicyEngine().evaluate([p])
              if r.policy_id == "SECRET-EXFILTRATION-001"][0]
    assert result.violated is True
    assert result.path_id == p.path_id


def test_end_to_end_handoff_no_violation():
    p = _pure_handoff_path()
    assert p.attack_type == AttackType.UNKNOWN
    assert not any(r.violated for r in PolicyEngine().evaluate([p]))
