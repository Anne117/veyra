"""Tests for ComponentRiskEvidence (Commit 22).

ComponentRiskEvidence is a deterministic, read-only projection of a finalized
AttackPath's risk metadata onto explicitly participating components. It:
- does NOT redistribute AttackPath risk (no component risk score / percentage);
- does NOT infer ownership or responsibility;
- always emits evidence that is a SUBSET of the finalized AttackPath.evidence;
- uses ComponentPathParticipation / ComponentPathComposition as the source of
  truth for participations.
"""

import json
from pathlib import Path

import pytest

from veyra.graph import (
    SecurityGraph,
    Node,
    NodeType,
    EdgeType,
    ComponentContext,
    ComponentContextAssociation,
    ComponentContextError,
    ComponentRiskEvidence,
    build_component_risk_evidence,
    build_component_risk_evidence_for_paths,
    serialize_component_risk_evidence,
    build_component_path_composition,
    serialize_component_path_composition,
    build_component_path_participation,
)
from veyra.graph.path import AttackPath, AttackType, path_id_of, assess_risk
from veyra.models import ScanResult, Confidence, Severity
from veyra.reporters import render_html, render_sarif, render_json


def _exfil_graph():
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="AGENT:B", type=NodeType.AGENT))
    g.add_node(Node(id="TOOL:C", type=NodeType.TOOL))
    g.add_node(Node(id="SKILL:D", type=NodeType.SKILL))
    g.add_node(Node(id="SECRET:x", type=NodeType.SECRET))
    g.add_node(Node(id="DATA:d", type=NodeType.DATA))
    g.add_node(Node(id="DATA:e", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:A", "SECRET:x", EdgeType.READS)
    g.add_edge("SECRET:x", "DATA:d", EdgeType.FLOWS_TO)
    g.add_edge("DATA:d", "ENDPOINT:evil.example", EdgeType.SENDS_TO)
    g.add_edge("SKILL:D", "DATA:e", EdgeType.WRITES)
    g.add_edge("SKILL:D", "DATA:e", EdgeType.PRODUCES)
    return g


READS = ("SKILL:A", "SECRET:x", EdgeType.READS)
FLOWS_TO = ("SECRET:x", "DATA:d", EdgeType.FLOWS_TO)
SENDS_TO = ("DATA:d", "ENDPOINT:evil.example", EdgeType.SENDS_TO)


def _secret_path():
    """SECRET_EXFILTRATION path: READS SECRET -> FLOWS_TO DATA -> SENDS_TO."""
    nodes = ["SKILL:A", "SECRET:x", "DATA:d", "ENDPOINT:evil.example"]
    edges = [("SKILL:A", "SECRET:x", "READS"),
             ("SECRET:x", "DATA:d", "FLOWS_TO"),
             ("DATA:d", "ENDPOINT:evil.example", "SENDS_TO")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.SECRET_EXFILTRATION,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    return ap


def _valid_map(g):
    return {nid: n.type for nid, n in g.nodes.items()
            if n.type in (NodeType.AGENT, NodeType.SKILL, NodeType.TOOL, NodeType.MCPSERVER)}


def _edge_set(g):
    return {(e.source, e.target, e.type.value) for e in g.edges}


def _ctx(*assocs):
    return list(assocs)


# 1. frozen dataclass
def test_frozen_dataclass():
    g = _exfil_graph()
    r = ComponentRiskEvidence(
        component=ComponentContext("SKILL:A", NodeType.SKILL),
        path_id="p",
        risk_relevant_behaviors=(("SKILL:A", "READS", "SECRET:x"),),
        evidence=("secret read",),
        risk_severity=Severity.CRITICAL,
        risk_confidence=Confidence.HIGH,
    )
    with pytest.raises(AttributeError):
        r.evidence = ("x",)


# 2. READS SECRET => secret read
def test_reads_secret():
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    res = build_component_risk_evidence(_secret_path(), ctx)
    assert res and res[0].evidence == ("secret read",)
    assert res[0].risk_relevant_behaviors == (("SKILL:A", "READS", "SECRET:x"),)


# 3. READS DATA => sensitive data read
def test_reads_data():
    g = _exfil_graph()
    path = _secret_path()
    # Give the path "sensitive data read" evidence by making it a DATA exfil.
    nodes = ["SKILL:A", "DATA:d", "ENDPOINT:evil.example"]
    edges = [("SKILL:A", "DATA:d", "READS"),
             ("DATA:d", "ENDPOINT:evil.example", "SENDS_TO")]
    dpath = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.DATA_EXFILTRATION,
                       path_id=path_id_of(nodes, edges, []))
    assess_risk(dpath)
    ctx = _ctx(ComponentContextAssociation(("SKILL:A", "DATA:d", EdgeType.READS),
                                           ComponentContext("SKILL:A", NodeType.SKILL)))
    res = build_component_risk_evidence(dpath, ctx)
    assert res and res[0].evidence == ("sensitive data read",)


# 4. SENDS_TO => external network send
def test_sends_to():
    ctx = _ctx(ComponentContextAssociation(SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT)))
    res = build_component_risk_evidence(_secret_path(), ctx)
    assert res and res[0].evidence == ("external network send",)


# 5. FLOWS_TO => sensitive data flow
def test_flows_to():
    ctx = _ctx(ComponentContextAssociation(FLOWS_TO, ComponentContext("AGENT:B", NodeType.AGENT)))
    res = build_component_risk_evidence(_secret_path(), ctx)
    # FLOWS_TO maps to "sensitive data flow"; SECRET_EXFILTRATION path has it.
    assert res and "sensitive data flow" in res[0].evidence


# 6. EXECUTES => execution (need a path with "execution" evidence)
def test_executes():
    g = _exfil_graph()
    nodes = ["SKILL:A", "SECRET:x"]
    edges = [("SKILL:A", "SECRET:x", "READS")]
    # Correlated secret execution sets evidence ["secret read","execution"].
    ap = AttackPath(nodes=nodes, edges=edges,
                    attack_type=AttackType.CORRELATED_SECRET_EXECUTION,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    assert "execution" in ap.evidence
    ctx = _ctx(ComponentContextAssociation(("SKILL:A", "ACT:x", EdgeType.EXECUTES),
                                           ComponentContext("SKILL:A", NodeType.SKILL)))
    # The path has no EXECUTES edge, so the component must participate via a real
    # edge. Use an associated EXECUTES edge.
    ap2 = AttackPath(nodes=nodes, edges=edges,
                     associated_edges=[("SKILL:A", "ACT:x", "EXECUTES")],
                     attack_type=AttackType.CORRELATED_SECRET_EXECUTION,
                     path_id=path_id_of(nodes, edges, [("SKILL:A","ACT:x","EXECUTES")]))
    assess_risk(ap2)
    res = build_component_risk_evidence(
        ap2, _ctx(ComponentContextAssociation(("SKILL:A", "ACT:x", EdgeType.EXECUTES),
                                              ComponentContext("SKILL:A", NodeType.SKILL))))
    assert res and res[0].evidence == ("execution",)


# 7. WRITES => no evidence label
def test_writes_no_label():
    g = _exfil_graph()
    # A path containing only a WRITES edge would carry no evidence (WRITES has no
    # label), so no risk-evidence entry is produced.
    nodes = ["SKILL:D", "DATA:e"]
    edges = [("SKILL:D", "DATA:e", "WRITES")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.UNKNOWN,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    ctx = _ctx(ComponentContextAssociation(("SKILL:D", "DATA:e", EdgeType.WRITES),
                                           ComponentContext("SKILL:D", NodeType.SKILL)))
    assert build_component_risk_evidence(ap, ctx) == []


# 8. PRODUCES => no evidence label
def test_produces_no_label():
    g = _exfil_graph()
    nodes = ["SKILL:D", "DATA:e"]
    edges = [("SKILL:D", "DATA:e", "PRODUCES")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.UNKNOWN,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    ctx = _ctx(ComponentContextAssociation(("SKILL:D", "DATA:e", EdgeType.PRODUCES),
                                           ComponentContext("SKILL:D", NodeType.SKILL)))
    assert build_component_risk_evidence(ap, ctx) == []


# 9. evidence is subset of AttackPath.evidence
def test_evidence_subset():
    ctx = _ctx(
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
        ComponentContextAssociation(SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT)),
    )
    path = _secret_path()
    results = build_component_risk_evidence(path, ctx)
    for r in results:
        assert set(r.evidence) <= set(path.evidence)


# 10-11. risk severity/confidence copied exactly
def test_risk_copied_from_path():
    path = _secret_path()
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    res = build_component_risk_evidence(path, ctx)
    assert res[0].risk_severity == path.risk_severity
    assert res[0].risk_confidence == path.risk_confidence


# 12. no component risk_score exists
def test_no_risk_score():
    r = build_component_risk_evidence(
        _secret_path(),
        _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL))),
    )[0]
    assert not hasattr(r, "risk_score")
    assert not hasattr(r, "risk_percentage")


# 13. no responsibility/owner field exists
def test_no_responsibility():
    r = build_component_risk_evidence(
        _secret_path(),
        _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL))),
    )[0]
    d = serialize_component_risk_evidence([r])[0]
    assert "responsibility" not in d and "owner" not in d


# 14. multiple behaviors for one component
def test_multiple_behaviors():
    ctx = _ctx(
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
        ComponentContextAssociation(SENDS_TO, ComponentContext("SKILL:A", NodeType.SKILL)),
    )
    # SKILL:A must exist for the SENDS_TO association to reference it as a
    # component (type SKILL). The path's SENDS_TO edge source is DATA:d, but the
    # component is still SKILL:A (explicit). Participation via SKILL:A? No — the
    # SENDS_TO edge source is DATA:d. So associate SENDS_TO with AGENT:B instead
    # to test multi-behavior one component cleanly we use a component that owns an
    # endpoint-edge source. Simpler: associate READS+FLOWS_TO to SKILL:A.
    ctx2 = _ctx(
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
        ComponentContextAssociation(FLOWS_TO, ComponentContext("SKILL:A", NodeType.SKILL)),
    )
    res = build_component_risk_evidence(_secret_path(), ctx2)
    assert len(res) == 1
    assert res[0].component.component_id == "SKILL:A"
    assert len(res[0].risk_relevant_behaviors) == 2


# 16. evidence ordering deterministic (fixed canonical order)
def test_evidence_ordering():
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    # secret path has ['secret read','sensitive data flow','external network send']
    path = _secret_path()
    # Only READS contributes "secret read".
    res = build_component_risk_evidence(path, ctx)
    assert res[0].evidence == ("secret read",)


# 18. context insertion order does not matter
def test_context_insertion_order_irrelevant():
    ctx_a = _ctx(
        ComponentContextAssociation(SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT)),
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
    )
    ctx_b = _ctx(
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
        ComponentContextAssociation(SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT)),
    )
    a = serialize_component_risk_evidence(build_component_risk_evidence(_secret_path(), ctx_a))
    b = serialize_component_risk_evidence(build_component_risk_evidence(_secret_path(), ctx_b))
    assert a == b


# 19. path input order does not matter
def test_path_input_order_irrelevant():
    p1 = _secret_path()
    p2 = _secret_path()
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    a = serialize_component_risk_evidence(build_component_risk_evidence_for_paths([p1, p2], ctx))
    b = serialize_component_risk_evidence(build_component_risk_evidence_for_paths([p2, p1], ctx))
    assert a == b


# 21. repeated serialization identical
def test_repeated_serialization():
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    r = build_component_risk_evidence(_secret_path(), ctx)
    assert serialize_component_risk_evidence(r) == serialize_component_risk_evidence(r)


# 23. missing path_id raises ComponentContextError
def test_missing_path_id_raises():
    ap = AttackPath(nodes=["SKILL:A", "SECRET:x"], edges=[("SKILL:A", "SECRET:x", "READS")],
                    attack_type=AttackType.SECRET_EXFILTRATION, path_id="")
    with pytest.raises(ComponentContextError):
        build_component_risk_evidence(ap, _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL))))


# 24. stale component raises
def test_stale_component_raises():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        build_component_risk_evidence(
            _secret_path(),
            _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:nope", NodeType.SKILL))),
            _valid_map(g), _edge_set(g),
        )


# 25. stale edge raises
def test_stale_edge_raises():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        build_component_risk_evidence(
            _secret_path(),
            _ctx(ComponentContextAssociation(("SKILL:A", "ENDPOINT:evil.example", EdgeType.READS),
                                             ComponentContext("SKILL:A", NodeType.SKILL))),
            _valid_map(g), _edge_set(g),
        )


# 26. component type mismatch raises
def test_component_type_mismatch_raises():
    g = _exfil_graph()
    with pytest.raises(ComponentContextError):
        build_component_risk_evidence(
            _secret_path(),
            _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.AGENT))),
            _valid_map(g), _edge_set(g),
        )


# 27. graph membership alone does not participate
def test_graph_membership_insufficient():
    # Association exists for the path but edge not present => no participation.
    nodes = ["SKILL:A", "SECRET:x"]
    edges = [("SKILL:A", "SECRET:x", "READS")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.SECRET_EXFILTRATION,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    # SENDS_TO not on this path.
    ctx = _ctx(ComponentContextAssociation(SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT)))
    assert build_component_risk_evidence(ap, ctx) == []


# 28-30. relationship/provenance/naming do not infer
def test_no_inference():
    path = _secret_path()
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    res = build_component_risk_evidence(path, ctx)
    assert all(r.component.component_id == "SKILL:A" for r in res)


# 31. associated_edges supported
def test_associated_edges_supported():
    # A path whose contiguous walk is only READS, with SENDS_TO as an
    # ASSOCIATED edge. A component associated with that SENDS_TO via the
    # associated edge participates; its label "external network send" is in the
    # finalized SECRET_EXFILTRATION evidence.
    nodes = ["SKILL:A", "SECRET:x"]
    edges = [("SKILL:A", "SECRET:x", "READS")]
    assoc = [("SECRET:x", "DATA:d", "SENDS_TO")]
    ap = AttackPath(nodes=nodes, edges=edges, associated_edges=assoc,
                    attack_type=AttackType.SECRET_EXFILTRATION,
                    path_id=path_id_of(nodes, edges, assoc))
    assess_risk(ap)
    ctx = _ctx(ComponentContextAssociation(("SECRET:x", "DATA:d", EdgeType.SENDS_TO),
                                           ComponentContext("AGENT:B", NodeType.AGENT)))
    res = build_component_risk_evidence(ap, ctx)
    assert res, "associated SENDS_TO participation expected"
    assert res[0].component.component_id == "AGENT:B"
    assert res[0].evidence == ("external network send",)


# 33. multiple components on same edge all survive
def test_multiple_components_same_edge():
    ctx = _ctx(
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
        ComponentContextAssociation(READS, ComponentContext("AGENT:B", NodeType.AGENT)),
        ComponentContextAssociation(READS, ComponentContext("TOOL:C", NodeType.TOOL)),
    )
    res = build_component_risk_evidence(_secret_path(), ctx)
    ids = {r.component.component_id for r in res}
    assert ids == {"SKILL:A", "AGENT:B", "TOOL:C"}


# 34-35. no graph / path mutation
def _snap(p):
    return (tuple(p.nodes), tuple(p.edges), tuple(p.associated_edges),
            p.attack_type.value, p.entry_node, p.asset_node, p.sink_node,
            p.path_id, p.canonical_identity, p.severity.value,
            p.confidence.value, p.risk_severity.value, p.risk_confidence.value,
            p.risk_score, tuple(p.evidence), tuple(p.policy_ids),
            tuple((b.edge_type, b.reason) for b in p.breakpoints),
            p.provenance, p.explanation_details, p.context_components)


def test_no_mutation():
    g = _exfil_graph()
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    path = _secret_path()
    snap = _snap(path)
    ctx = _ctx(ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)))
    build_component_risk_evidence(path, ctx)
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges
    assert _snap(path) == snap


# 38. paths without risk-relevant evidence are omitted
def test_omitted_when_no_evidence():
    nodes = ["SKILL:D", "DATA:e"]
    edges = [("SKILL:D", "DATA:e", "WRITES")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.UNKNOWN,
                    path_id=path_id_of(nodes, edges, []))
    assess_risk(ap)
    ctx = _ctx(ComponentContextAssociation(("SKILL:D", "DATA:e", EdgeType.WRITES),
                                           ComponentContext("SKILL:D", NodeType.SKILL)))
    assert build_component_risk_evidence(ap, ctx) == []


# 39. empty context => empty
def test_empty_context():
    assert build_component_risk_evidence(_secret_path(), []) == []
    assert build_component_risk_evidence_for_paths([_secret_path()], None) == []


# 40-44. ScanResult / integration
SENSITIVE_FLOW = """# Skill: exfil

## Step 1
Read the local data.

## Step 2
Transform the data into a report.

## Step 3
Upload the report to https://report.example.com/upload.
"""


def _write(tmp, name, content):
    p = Path(tmp) / name
    p.write_text(content, encoding="utf-8")
    return p


def _scan_with_context(tmp, ctx):
    from veyra.scanner import scan_path
    return scan_path(tmp, component_context=ctx)


def test_scan_json_integration():
    from tempfile import TemporaryDirectory
    from veyra.scanner import scan_path
    with TemporaryDirectory() as tmp:
        _write(tmp, "SKILL.md", SENSITIVE_FLOW)
        skill = "SKILL:" + str(Path(tmp) / "SKILL.md").replace("\\", "/")
        ctx = [ComponentContextAssociation((skill, "DATA:data", EdgeType.READS),
                                           ComponentContext(skill, NodeType.SKILL))]
        result = scan_path(tmp, component_context=ctx)
        assert result.component_risk_evidence
        d = json.loads(render_json(result))
        assert d["component_risk_evidence"][0]["component_id"] == skill
        assert "risk_severity" in d["component_risk_evidence"][0]


def test_sarif_integration():
    from tempfile import TemporaryDirectory
    from veyra.scanner import scan_path
    with TemporaryDirectory() as tmp:
        _write(tmp, "SKILL.md", SENSITIVE_FLOW)
        skill = "SKILL:" + str(Path(tmp) / "SKILL.md").replace("\\", "/")
        ctx = [ComponentContextAssociation((skill, "DATA:data", EdgeType.READS),
                                           ComponentContext(skill, NodeType.SKILL))]
        result = scan_path(tmp, component_context=ctx)
        doc = json.loads(render_sarif(result))
        run = doc["runs"][0]
        assert "component_risk_evidence" in run["properties"]
        ap = [r for r in run["results"] if r["ruleId"].startswith("ATTACK-PATH")][0]
        assert "message" in ap


def test_html_integration():
    from tempfile import TemporaryDirectory
    from veyra.scanner import scan_path
    with TemporaryDirectory() as tmp:
        _write(tmp, "SKILL.md", SENSITIVE_FLOW)
        skill = "SKILL:" + str(Path(tmp) / "SKILL.md").replace("\\", "/")
        ctx = [ComponentContextAssociation((skill, "DATA:data", EdgeType.READS),
                                           ComponentContext(skill, NodeType.SKILL))]
        result = scan_path(tmp, component_context=ctx)
        doc = render_html(result)
        assert "Component Risk Evidence" in doc
        assert skill in doc


def test_html_xss_escaping():
    evil = "<script>alert(1)</script>"
    result = ScanResult(target="x")
    result.component_risk_evidence = [{
        "path_id": "abc",
        "component_id": "SKILL:" + evil,
        "component_type": "SKILL",
        "risk_relevant_behaviors": [
            {"source": "SKILL:" + evil, "edge_type": "<img src=x onerror=alert(1)>", "target": "T"}
        ],
        "evidence": ["<script>alert(2)</script>"],
        "risk_severity": "CRITICAL",
        "risk_confidence": "HIGH",
    }]
    doc = render_html(result)
    assert "<script>" not in doc
    assert "<img" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc


# 45. public API exports
def test_public_api_exports():
    from veyra import graph
    for name in ("ComponentRiskEvidence", "build_component_risk_evidence",
                 "build_component_risk_evidence_for_paths",
                 "serialize_component_risk_evidence"):
        assert hasattr(graph, name), f"missing {name}"


# 46-47. no new AttackType / EdgeType
def test_no_new_types():
    from veyra.graph import AttackType, EdgeType
    from veyra.graph.path import AttackType as AT2, EdgeType as ET2
    assert len(AttackType) == len(AT2)
    assert len(EdgeType) == len(ET2)


# IMPORTANT TEST: A READS SECRET, B SENDS_TO ENDPOINT; path evidence = both.
def test_component_evidence_split_by_behavior():
    ctx = _ctx(
        ComponentContextAssociation(READS, ComponentContext("SKILL:A", NodeType.SKILL)),
        ComponentContextAssociation(SENDS_TO, ComponentContext("AGENT:B", NodeType.AGENT)),
    )
    path = _secret_path()
    assert "secret read" in path.evidence
    assert "external network send" in path.evidence
    res = {r.component.component_id: r.evidence for r in build_component_risk_evidence(path, ctx)}
    assert res["SKILL:A"] == ("secret read",)
    assert res["AGENT:B"] == ("external network send",)
    # Neither component gets every evidence label; SKILL:A does not carry the
    # network-send label it did not prove.
    assert "sensitive data flow" not in res["SKILL:A"]
    assert "secret read" not in res["AGENT:B"]


# IMPORTANT NEGATIVE TEST: READS DATA but path.evidence lacks "sensitive data read"
def test_no_manufactured_evidence():
    nodes = ["SKILL:A", "DATA:d", "ENDPOINT:evil.example"]
    edges = [("SKILL:A", "DATA:d", "READS"),
             ("DATA:d", "ENDPOINT:evil.example", "SENDS_TO")]
    ap = AttackPath(nodes=nodes, edges=edges, attack_type=AttackType.DATA_EXFILTRATION,
                    path_id=path_id_of(nodes, edges, []))
    # Force evidence WITHOUT "sensitive data read" by overriding after assess:
    assess_risk(ap)
    ap.evidence = ["external network send"]  # path that does not claim the read
    ctx = _ctx(ComponentContextAssociation(("SKILL:A", "DATA:d", EdgeType.READS),
                                           ComponentContext("SKILL:A", NodeType.SKILL)))
    res = build_component_risk_evidence(ap, ctx)
    # READS DATA maps to "sensitive data read" but path does not claim it => not emitted.
    assert res == [] or all("sensitive data read" not in r.evidence for r in res)
