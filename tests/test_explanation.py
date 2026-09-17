"""Tests for the deterministic AttackPath explanation layer (Commit 16).

The explanation is a presentation layer derived ONLY from already-proven
AttackPath fields. It must never add edges, never merge associated_edges into
the contiguous path, never change path_id / risk / policies / provenance /
breakpoints, and always HTML-escape hostile values.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from veyra.graph.builder import SecurityGraph
from veyra.graph.models import Node, NodeType, EdgeType
from veyra.graph.path import AttackPath, AttackType, PathAnalyzer, build_explanation, path_id_of
from veyra.models import ScanResult
from veyra.policy import PolicyEngine, associate_policy_ids
from veyra.reporters import render_html, render_json, render_sarif
from veyra.scanner import scan_path


# --- Fixtures ---------------------------------------------------------------

def _g():
    return SecurityGraph()


def _skills(g, *names):
    for n in names:
        g.add_node(Node(id=f"SKILL:{n}", type=NodeType.SKILL, label=n))


def _secret_exfil():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="DATA:payload", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:https://evil.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS, attributes={"files": ["a/SKILL.md"]})
    g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO, attributes={"files": ["a/SKILL.md"]})
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.example", EdgeType.SENDS_TO, attributes={"files": ["a/SKILL.md"]})
    return PathAnalyzer(g).analyze()[0]


def _data_exfil():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="DATA:data", type=NodeType.DATA))
    g.add_node(Node(id="DATA:report", type=NodeType.DATA))
    g.add_node(Node(id="ENDPOINT:https://e.example", type=NodeType.ENDPOINT))
    g.add_edge("SKILL:skill", "DATA:data", EdgeType.READS, attributes={"files": ["x/SKILL.md"]})
    g.add_edge("DATA:data", "DATA:report", EdgeType.FLOWS_TO, attributes={"files": ["x/SKILL.md"]})
    g.add_edge("DATA:report", "ENDPOINT:https://e.example", EdgeType.SENDS_TO, attributes={"files": ["y/SKILL.md"]})
    return PathAnalyzer(g).analyze()[0]


def _correlated_exec():
    g = _g(); _skills(g, "skill")
    g.add_node(Node(id="SECRET:token", type=NodeType.SECRET))
    g.add_node(Node(id="ACTION:run", type=NodeType.ACTION))
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS, attributes={"files": ["a/SKILL.md"]})
    g.add_edge("SKILL:skill", "ACTION:run", EdgeType.EXECUTES, attributes={"files": ["a/SKILL.md"]})
    return PathAnalyzer(g).analyze()[0]


def _unknown_path():
    p = AttackPath(
        nodes=["SKILL:a", "ACTION:noop"],
        edges=[("SKILL:a", "ACTION:noop", "EXECUTES")],
        path_id="unknown-path",
        attack_type=AttackType.UNKNOWN,
    )
    return p


def _associated_expl(path):
    return build_explanation(path)


# A/B/C/D. Per-type explanation ----------------------------------------------
def test_secret_exfil_explanation():
    p = _secret_exfil()
    e = _associated_expl(p)
    assert "secret is read" in e.summary
    assert "external endpoint" in e.summary


def test_data_exfil_explanation():
    p = _data_exfil()
    e = _associated_expl(p)
    assert "Sensitive data" in e.summary
    assert "external endpoint" in e.summary


def test_correlated_exec_explanation():
    p = _correlated_exec()
    e = _associated_expl(p)
    assert "same skill" in e.summary
    assert "requires review" in e.summary


def test_unknown_explanation():
    p = _unknown_path()
    e = _associated_expl(p)
    assert "without a classified attack type" in e.summary


# E. Exact contiguous steps ---------------------------------------------------
def test_steps_derive_from_nodes_and_edges():
    p = _secret_exfil()
    e = _associated_expl(p)
    assert list(e.steps) == [
        "SKILL:skill --READS--> SECRET:token",
        "SECRET:token --FLOWS_TO--> DATA:payload",
        "DATA:payload --SENDS_TO--> ENDPOINT:https://evil.example",
    ]


# F. Associated evidence separate --------------------------------------------
def test_associated_evidence_separate():
    p = _correlated_exec()
    e = _associated_expl(p)
    # Contiguous steps = EXECUTES only; READS is in associated_evidence.
    assert list(e.steps) == ["SKILL:skill --EXECUTES--> ACTION:run"]
    assert list(e.associated_evidence) == ["SKILL:skill --READS--> SECRET:token"]


# G. No synthetic SECRET -> ACTION -------------------------------------------
def test_no_synthetic_secret_action_step():
    p = _correlated_exec()
    e = _associated_expl(p)
    full = " ".join(list(e.steps) + list(e.associated_evidence))
    # SECRET is never joined to ACTION.
    assert "SECRET:token --EXECUTES--> ACTION" not in full
    assert "SECRET:token --READS--> ACTION" not in full
    assert "SECRET -> ACTION" not in full


# H. Entry/asset/sink are truthful and present in the explanation itself ------
def test_entry_asset_sink_in_explanation_data_exfil():
    p = _data_exfil()
    e = _associated_expl(p)
    assert e.entry == p.entry_node
    assert e.asset == p.asset_node
    assert e.sink == p.sink_node
    # Present in to_dict().
    d = e.to_dict()
    assert d["entry"] == p.entry_node
    assert d["asset"] == p.asset_node
    assert d["sink"] == p.sink_node
    # Present in JSON output.
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    jd = json.loads(render_json(ScanResult(target="x", attack_paths=[p],
                                           policy_results=PolicyEngine().evaluate([p]))))
    ed = jd["attack_paths"][0]["explanation_details"]
    assert ed["entry"] == p.entry_node
    assert ed["asset"] == p.asset_node
    assert ed["sink"] == p.sink_node


def test_entry_asset_sink_in_explanation_secret_exfil():
    p = _secret_exfil()
    e = _associated_expl(p)
    assert e.entry == p.entry_node
    assert e.asset == p.asset_node
    assert e.sink == p.sink_node
    assert e.asset == "SECRET:token"
    assert e.sink == "ENDPOINT:https://evil.example"


def test_entry_asset_sink_correlated_stays_truthful():
    # Correlated secret execution: the sink is the ACTION, and the SECRET is only
    # an associated asset. No SECRET -> ACTION relationship is invented.
    p = _correlated_exec()
    e = _associated_expl(p)
    assert e.asset == "SECRET:token"  # the associated asset, proven by AttackPath
    assert e.sink == "ACTION:run"      # the contiguous sink (EXECUTES)
    # steps describe the contiguous EXECUTES-only path, never a secret->action.
    assert all("--EXECUTES-->" in s for s in e.steps)
    assert not any("SECRET:token --" in s for s in e.steps)


def test_entry_asset_sink_missing_stays_none():
    # A path with empty entry/asset/sink keeps None and never infers values.
    p = AttackPath(
        nodes=["SKILL:a", "ACTION:noop"],
        edges=[("SKILL:a", "ACTION:noop", "EXECUTES")],
        path_id="missing-eas",
        attack_type=AttackType.UNKNOWN,
    )
    # On AttackPath these fields default to "" (empty). The explanation maps the
    # empty value to None so it is explicitly "not available", never guessed.
    e = _associated_expl(p)
    assert e.entry is None
    assert e.asset is None
    assert e.sink is None
    # No inferred SECRET/ENDPOINT values.
    assert e.asset not in ("SECRET:token", "ENDPOINT:https://evil.example")


def test_entry_asset_sink_none_to_dict():
    # AttackPathExplanation constructed directly with None fields preserves None.
    from veyra.graph.path import AttackPathExplanation
    e = AttackPathExplanation(summary="s")
    assert e.entry is None and e.asset is None and e.sink is None
    d = e.to_dict()
    assert d["entry"] is None and d["asset"] is None and d["sink"] is None


# I. Policy IDs from path.policy_ids -----------------------------------------
def test_policies_taken_from_path_policy_ids():
    p = _secret_exfil()
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    e = _associated_expl(p)
    assert list(e.policies) == ["SECRET-EXFILTRATION-001"]
    # Not derived from attack_type string in a way that invents a wrong policy.
    assert "DATA-EXFILTRATION-001" not in e.policies


# J. Breakpoints truthful -----------------------------------------------------
def test_breakpoints_truthful():
    p = _secret_exfil()
    e = _associated_expl(p)
    assert e.breakpoints  # non-empty
    for b in e.breakpoints:
        assert "READS" in b or "FLOWS_TO" in b or "SENDS_TO" in b
        assert ":" in b  # includes reason/impact
        assert "fixes" not in b.lower()


# K. Provenance/components truthful ------------------------------------------
def test_components_truthful():
    p = _data_exfil()
    e = _associated_expl(p)
    # Two contributors preserved (a and b components on separate edges).
    assert set(e.components) == {"x/SKILL.md", "y/SKILL.md"}


# L. Missing optional fields handled cleanly ----------------------------------
def test_missing_optional_fields_clean():
    p = _unknown_path()  # unknown semantics, no provenance, no policies
    e = _associated_expl(p)
    assert e.policies == ()
    assert e.breakpoints == ()
    assert e.components == ()
    # Neutral summary, no escalation.
    assert "classified attack type" in e.summary


# M. Deterministic repeated generation ---------------------------------------
def test_deterministic_repeated_generation():
    p1 = _secret_exfil()
    p2 = _secret_exfil()
    assert _associated_expl(p1).to_dict() == _associated_expl(p2).to_dict()


# N. Explanation does not affect path_id -------------------------------------
def test_explanation_does_not_change_path_id():
    g = _g(); _skills(g, "skill")
    for nid, nt in [("SECRET:t", NodeType.SECRET), ("DATA:p", NodeType.DATA), ("ENDPOINT:https://e", NodeType.ENDPOINT)]:
        g.add_node(Node(id=nid, type=nt))
    g.add_edge("SKILL:skill", "SECRET:t", EdgeType.READS, attributes={"files": ["z/SKILL.md"]})
    g.add_edge("SECRET:t", "DATA:p", EdgeType.FLOWS_TO, attributes={"files": ["z/SKILL.md"]})
    g.add_edge("DATA:p", "ENDPOINT:https://e", EdgeType.SENDS_TO, attributes={"files": ["w/SKILL.md"]})
    p = PathAnalyzer(g).analyze()[0]
    pure = path_id_of(p.nodes, p.edges, p.associated_edges)
    # Different provenance/explanation -> same path_id.
    assert p.path_id == pure
    assert p.path_id == path_id_of(p.nodes, p.edges, p.associated_edges)


def test_explanation_fields_do_not_enter_identity():
    # Adding/removing entry/asset/sink explanation values must not change the
    # semantic identity of the path.
    p = _secret_exfil()
    pure = path_id_of(p.nodes, p.edges, p.associated_edges)
    e1 = build_explanation(p)
    # Rebuild with different entry/asset/sink explanation metadata.
    p2 = _secret_exfil()
    p2.entry_node = "SOMETHING_ELSE"
    e2 = build_explanation(p2)
    assert e1.to_dict() != e2.to_dict()      # explanation differs
    assert p.path_id == pure                  # path_id unchanged
    assert path_id_of(p2.nodes, p2.edges, p2.associated_edges) == pure


# O. JSON contains explanation -----------------------------------------------
def test_json_contains_explanation():
    p = _secret_exfil()
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    d = json.loads(render_json(ScanResult(target="x", attack_paths=[p],
                                          policy_results=PolicyEngine().evaluate([p]))))
    ap = d["attack_paths"][0]
    assert "explanation_details" in ap
    ed = ap["explanation_details"]
    assert "summary" in ed and "steps" in ed and "impact" in ed
    assert ed["summary"] == _associated_expl(p).summary
    # Existing string explanation preserved.
    assert ap["explanation"] == p.explanation


# P. SARIF contains explanation ----------------------------------------------
def test_sarif_contains_explanation():
    p = _secret_exfil()
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    doc = json.loads(render_sarif(ScanResult(target="x", attack_paths=[p],
                                             policy_results=PolicyEngine().evaluate([p]))))
    ap = [r for r in doc["runs"][0]["results"] if r["ruleId"].startswith("ATTACK-PATH")][0]
    props = ap["properties"]
    assert "explanation" in props
    assert props["explanation"]["summary"] == _associated_expl(p).summary
    # Message unchanged (string explanation).
    assert ap["message"]["text"] == p.explanation


# Q. HTML contains explanation -----------------------------------------------
def test_html_contains_explanation():
    p = _secret_exfil()
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "Explanation" in doc
    assert "A secret is read and reaches an external endpoint." in doc
    # Steps are HTML-escaped: the literal '-->' arrow is rendered as '--&gt;'.
    assert "SKILL:skill --READS--&gt; SECRET:token" in doc


# R. HTML XSS escaping -------------------------------------------------------
def test_html_explanation_xss():
    evil = "<img src=x onerror=alert(1)>"
    script = "<script>alert(1)</script>"
    p = AttackPath(
        nodes=["SKILL:" + evil, "SECRET:" + script],
        edges=[("SKILL:" + evil, "SECRET:" + script, "READS")],
        path_id="evil-explain",
        attack_type=AttackType.SECRET_EXFILTRATION,
    )
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "<script>" not in doc
    assert "<img" not in doc
    assert "onerror=" not in doc or "&lt;img" in doc  # escaped if present
    assert "&lt;img src=x onerror=alert(1)&gt;" in doc


# S-N. Regression: existing features intact -----------------------------------
def test_graph_visualization_intact():
    from tests.test_html_report import _exfil_path, GRAPH_LEGEND
    p = _exfil_path("SECRET")
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert GRAPH_LEGEND in doc  # Commit 13 visualization still present


def test_provenance_intact():
    from veyra.reporters.html import render_html as rh
    p = _secret_exfil()
    doc = rh(ScanResult(target="x", attack_paths=[p]))
    assert "Provenance" in doc  # Commit 15 still present
    assert "a/SKILL.md" in doc


def test_policy_association_intact():
    p = _secret_exfil()
    associate_policy_ids([p], PolicyEngine().evaluate([p]))
    assert p.policy_ids == ["SECRET-EXFILTRATION-001"]


def test_breakpoints_intact():
    p = _secret_exfil()
    assert p.breakpoints  # Commit 14 breakpoints computed unchanged
    for b in p.breakpoints:
        assert b.edge_type in ("READS", "FLOWS_TO", "SENDS_TO")


# W. End-to-end -----------------------------------------------------------------
def test_scan_pipeline_populates_explanation():
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(
            "# Skill\n\nRead the .env secrets.\n\nRun the script.\n", encoding="utf-8"
        )
        r = scan_path(tmp)
    for p in r.attack_paths:
        assert p.explanation_details is not None
        assert p.explanation_details.summary  # non-empty
