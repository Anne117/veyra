"""Tests for AttackPath provenance (Commit 15).

Provenance is metadata: it records which scanned component/file contributed a
node or edge, from real graph construction data. It must never change path_id,
classification, risk, policies, or breakpoints, and must never be guessed.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from veyra.graph.builder import SecurityGraph, add_handoff, build_from_actions, build_from_findings
from veyra.graph.models import Node, NodeType, EdgeType, SecurityGraph as SG
from veyra.graph.path import AttackPath, AttackType, PathAnalyzer, Provenance, path_id_of
from veyra.models import Finding, ScanResult, Severity
from veyra.policy import PolicyEngine, associate_policy_ids
from veyra.reporters import render_html, render_json, render_sarif
from veyra.scanner import scan_path


# --- Helpers ---------------------------------------------------------------

def _g():
    return SecurityGraph()


def _skills(g, *names):
    for n in names:
        g.add_node(Node(id=f"SKILL:{n}", type=NodeType.SKILL, label=n))


def _secret_exfil_graph():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="DATA:payload", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS,
               attributes={"files": ["skill/SKILL.md"]})
    g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO,
               attributes={"files": ["skill/SKILL.md"]})
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO,
               attributes={"files": ["skill/SKILL.md"]})
    return PathAnalyzer(g).analyze()[0]


def _correlated_exec_path():
    # SKILL --EXECUTES--> ACTION (walk) + SKILL --READS--> SECRET (assoc).
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ACTION:run", type=NodeType.ACTION))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS,
               attributes={"files": ["compa/SKILL.md"]})
    g.add_edge("SKILL:skill", "ACTION:run", EdgeType.EXECUTES,
               attributes={"files": ["compa/SKILL.md"]})
    return PathAnalyzer(g).analyze()[0]


# A. Single-component node provenance --------------------------------------
def test_single_component_node_provenance():
    p = _secret_exfil_graph()
    prov = p.provenance
    assert prov.nodes["SKILL:skill"].components == ("skill/SKILL.md",)
    assert prov.nodes["SECRET:token"].components == ("skill/SKILL.md",)
    assert prov.nodes["ENDPOINT:https://evil.example"].components == ("skill/SKILL.md",)


# B. Single-component edge provenance ---------------------------------------
def test_single_component_edge_provenance():
    p = _secret_exfil_graph()
    ed = p.provenance.edges
    assert len(ed) == 3  # parallel to path.edges
    assert ed[0].components == ("skill/SKILL.md",)  # READS
    assert ed[1].components == ("skill/SKILL.md",)  # FLOWS_TO
    assert ed[2].components == ("skill/SKILL.md",)  # SENDS_TO


# C. Cross-component provenance preserved per edge --------------------------
def test_cross_component_edge_provenance_preserved():
    # Build two graph fragments with distinct components, merge, and analyze.
    gA = _g(); _skills(gA, "skill")
    gA.add_node(Node(id="DATA:data", type=NodeType.DATA))
    gA.add_node(Node(id="DATA:report", type=NodeType.DATA))
    gA.add_edge("SKILL:skill", "DATA:data", EdgeType.READS,
                attributes={"files": ["a/SKILL.md"]})
    gA.add_edge("DATA:data", "DATA:report", EdgeType.FLOWS_TO,
                attributes={"files": ["a/SKILL.md"]})

    gB = _g()
    gB.add_node(Node(id="DATA:report", type=NodeType.DATA))  # same semantic node
    gB.add_node(Node(id="ENDPOINT:https://e.example", type=NodeType.ENDPOINT))
    gB.add_edge("DATA:report", "ENDPOINT:https://e.example", EdgeType.SENDS_TO,
                attributes={"files": ["b/SKILL.md"]})

    # Merge into one graph (as the scanner cross-component composition does).
    merged = SecurityGraph()
    for n in gA.nodes.values():
        merged.get_or_create(n.id, n.type, label=n.label)
    for n in gB.nodes.values():
        merged.get_or_create(n.id, n.type, label=n.label)
    for e in gA.edges + gB.edges:
        merged.add_edge(e.source, e.target, e.type, attributes=dict(e.attributes))
    # Anchor the walk on the skill.
    p = PathAnalyzer(merged).analyze()[0]
    assert p.nodes[-1].startswith("ENDPOINT:")
    eds = p.provenance.edges
    # READS + FLOWS_TO contributed by component a; SENDS_TO by component b.
    assert ed_types(p) == ["READS", "FLOWS_TO", "SENDS_TO"]
    assert eds[0].components == ("a/SKILL.md",)
    assert eds[1].components == ("a/SKILL.md",)
    assert eds[2].components == ("b/SKILL.md",)


def ed_types(p):
    return [e[2] for e in p.edges]


# D. Associated edges retain separate provenance ----------------------------
def test_associated_edges_retain_separate_provenance():
    p = _correlated_exec_path()
    # Contiguous walk is SKILL --EXECUTES--> ACTION.
    assert ed_types(p) == ["EXECUTES"]
    # Associated evidence is SECRET READS from compa.
    assert len(p.associated_edges) == 1
    ap = p.provenance.associated_edges
    assert len(ap) == 1
    assert ap[0].components == ("compa/SKILL.md",)
    # The contiguous edge provenance is separate from associated.
    assert p.provenance.edges and p.provenance.edges[0].components == ("compa/SKILL.md",)


# E. Missing provenance explicit / never guessed ----------------------------
def test_missing_provenance_never_guessed():
    # Edges without file attribution => empty (unknown), not invented.
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)  # no attributes
    g.add_edge("SECRET:token", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO)
    p = PathAnalyzer(g).analyze()[0]
    for nd in p.nodes:
        assert p.provenance.nodes[nd].components == ()  # known-empty, not guessed
    for e in p.provenance.edges:
        assert e.components == ()
    assert p.provenance.nodes["SECRET:token"].known is False


# F. Provenance does not change path_id -------------------------------------
def test_provenance_does_not_change_path_id():
    p = _secret_exfil_graph()
    pid1 = p.path_id
    # Re-analyze the same semantics WITHOUT file attribution (no provenance).
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="DATA:payload", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO)
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO)
    p2 = PathAnalyzer(g).analyze()[0]
    assert p2.path_id == pid1
    # Different provenance on the SAME semantics => same path_id.
    g3 = _g(); _skills(g3, "skill")
    g3.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g3.add_node(Node(id="DATA:payload", type=NodeType.DATA))
    g3.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g3.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS, attributes={"files": ["other/SKILL.md"]})
    g3.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO, attributes={"files": ["other/SKILL.md"]})
    g3.add_edge("DATA:payload", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO, attributes={"files": ["other/SKILL.md"]})
    p3 = PathAnalyzer(g3).analyze()[0]
    assert p3.path_id == pid1
    assert p3.provenance.edges[0].components == ("other/SKILL.md",)


def test_provenance_excluded_from_canonical_identity():
    # Provenance is never part of canonical_path_identity / path_id_of.
    nodes = ["SKILL:skill", "SECRET:token", "ENDPOINT:https://e.example"]
    edges = [("SKILL:skill", "SECRET:token", "READS"), ("SECRET:token", "ENDPOINT:https://e.example", "SENDS_TO")]
    a = path_id_of(nodes, edges, [])
    # Identical semantics regardless of any provenance metadata.
    assert a == path_id_of(list(nodes), list(edges), [])


# G. Repeated analysis identical --------------------------------------------
def test_repeated_analysis_identical_provenance():
    p1 = _secret_exfil_graph()
    p2 = _secret_exfil_graph()
    assert p1.provenance.to_dict() == p2.provenance.to_dict()
    assert p1.path_id == p2.path_id


# H. JSON contains provenance -----------------------------------------------
def test_json_contains_provenance():
    p = _secret_exfil_graph()
    result = ScanResult(target="x", attack_paths=[p],
                        policy_results=PolicyEngine().evaluate([p]))
    d = json.loads(render_json(result))
    ap = d["attack_paths"][0]
    assert "provenance" in ap
    assert ap["provenance"]["nodes"]["SKILL:skill"]["components"] == ["skill/SKILL.md"]
    assert ap["provenance"]["edges"][0]["components"] == ["skill/SKILL.md"]
    assert "provenance" in ap and isinstance(ap["provenance"]["associated_edges"], list)
    # Existing fields preserved.
    for field in ("path_id", "attack_type", "nodes", "edges", "risk_score", "evidence", "policy_ids", "breakpoints"):
        assert field in ap


# I. SARIF contains provenance under properties ------------------------------
def test_sarif_contains_provenance():
    p = _secret_exfil_graph()
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    result = ScanResult(target="x", attack_paths=[p],
                        policy_results=PolicyEngine().evaluate([p]))
    doc = json.loads(render_sarif(result))
    run = doc["runs"][0]
    ap = [r for r in run["results"] if r["ruleId"].startswith("ATTACK-PATH")][0]
    props = ap["properties"]
    assert "provenance" in props
    assert props["provenance"]["nodes"]["SKILL:skill"] == ["skill/SKILL.md"]
    # Existing attack-path fields intact.
    assert props["path_id"] == p.path_id
    assert props["attack_type"] == "SECRET_EXFILTRATION"
    assert "policy_ids" in props
    # SARIF remains valid 2.1.0.
    assert doc["version"] == "2.1.0"


# J. HTML displays provenance -----------------------------------------------
def test_html_displays_provenance():
    p = _secret_exfil_graph()
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "Provenance" in doc
    assert "skill/SKILL.md" in doc


# K. HTML escapes malicious provenance values --------------------------------
def test_html_escapes_malicious_provenance():
    g = _g(); _skills(g, "skill")
    evil = "<script>alert(1)</script>"
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS, attributes={"files": [evil]})
    g.add_edge("SECRET:token", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO,
               attributes={"files": ["&good<.md"]})
    p = PathAnalyzer(g).analyze()[0]
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "<script>" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc
    assert "&amp;good&lt;.md" in doc


# L. Attack-path semantics unchanged ----------------------------------------
def test_semantics_risk_policy_breakpoints_unchanged():
    # SECRET_EXFILTRATION keeps its exact semantics with provenance present.
    p = _secret_exfil_graph()
    assert p.attack_type == AttackType.SECRET_EXFILTRATION
    assert p.risk_severity.value == "CRITICAL"
    assert p.risk_score == 95
    assert p.evidence  # preserved
    # policy association unchanged.
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    assert p.policy_ids == ["SECRET-EXFILTRATION-001"]


# M. Policy associations unchanged via real pipeline ------------------------
def test_policy_association_unchanged_with_provenance():
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(
            "Read the .env secrets.\nRun the script.\n", encoding="utf-8"
        )
        r = scan_path(tmp)
    # Correlated execution paths still associate the correlated policy.
    for p in r.attack_paths:
        if p.attack_type == AttackType.CORRELATED_SECRET_EXECUTION:
            assert "CORRELATED-SECRET-EXECUTION-001" in p.policy_ids


# N. Breakpoints unchanged ----------------------------------------------------
def test_breakpoints_unchanged():
    p = _secret_exfil_graph()
    assert p.breakpoints  # still computed
    for b in p.breakpoints:
        assert b.edge_type in ("READS", "FLOWS_TO", "SENDS_TO")


# O. Empty scan / path without provenance renders cleanly --------------------
def test_empty_path_without_provenance_renders_clean():
    # A manually constructed path has empty provenance by default.
    p = AttackPath(
        nodes=["SKILL:a", "ACTION:b"],
        edges=[("SKILL:a", "ACTION:b", "EXECUTES")],
        path_id="manual",
        attack_type=AttackType.UNKNOWN,
    )
    assert p.provenance.to_dict() == {"nodes": {}, "edges": [], "associated_edges": []}
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "not available" in doc or "No provenance recorded." in doc


# P. repeated semantic node across components => collection ------------------
def test_semantic_node_reuse_collects_all_contributors():
    # Two components each contribute an edge that touches the SAME semantic
    # node id (DATA:report). Provenance must preserve BOTH, not overwrite.
    gA = _g(); _skills(gA, "skillA")
    gA.add_node(Node(id="DATA:report", type=NodeType.DATA))
    gA.add_edge("SKILL:skillA", "DATA:report", EdgeType.READS,
                attributes={"files": ["a/SKILL.md"]})

    gB = _g(); _skills(gB, "skillB")
    gB.add_node(Node(id="DATA:report", type=NodeType.DATA))
    gB.add_node(Node(id="ENDPOINT:https://e.example", type=NodeType.ENDPOINT))
    gB.add_edge("DATA:report", "ENDPOINT:https://e.example", EdgeType.SENDS_TO,
                attributes={"files": ["b/SKILL.md"]})

    merged = SecurityGraph()
    for n in list(gA.nodes.values()) + list(gB.nodes.values()):
        merged.get_or_create(n.id, n.type, label=n.label)
    for e in gA.edges + gB.edges:
        merged.add_edge(e.source, e.target, e.type, attributes=dict(e.attributes))

    paths = PathAnalyzer(merged).analyze()
    # The DATA:report node appears in at least one path; its provenance is a
    # collection of both contributors.
    seen = False
    for p in paths:
        nd = "DATA:report"
        if nd in p.provenance.nodes and len(p.provenance.nodes[nd].components) > 0:
            comps = set(p.provenance.nodes[nd].components)
            assert comps == {"a/SKILL.md", "b/SKILL.md"}, comps  # both preserved
            seen = True
    assert seen, "expected a path referencing DATA:report"
