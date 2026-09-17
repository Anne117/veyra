"""Tests for the standalone HTML security report renderer."""

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from veyra.cli import main
from veyra.graph.path import (
    AttackPath,
    AttackType,
    Breakpoint,
    BreakpointImpact,
    path_id_of,
)
from veyra.models import Confidence, Finding, ScanResult, Severity
from veyra.policy import PolicyResult
from veyra.reporters.html import render_html
from veyra.scanner import scan_path


GRAPH_CLASS = 'class="graph"'
GRAPH_LEGEND = "Contiguous attack path"
ASSOC_GRAPH = "Associated evidence"


def _graph_slice(doc: str) -> str:
    """The contiguous (non-dashed) graph block for a path."""
    start = doc.find(GRAPH_LEGEND)
    assert start != -1, "contiguous graph legend missing"
    end = doc.find(ASSOC_GRAPH, start)
    return doc[start:end if end != -1 else len(doc)]


def _exfil_path(asset="SECRET"):
    """A realistic contiguous SECRET/DATA_EXFILTRATION walk."""
    if asset == "SECRET":
        nodes = ["SKILL:payment", "SECRET:.aws/credentials", "DATA:payload", "ENDPOINT:https://example.com"]
        edges = [
            ("SKILL:payment", "SECRET:.aws/credentials", "READS"),
            ("SECRET:.aws/credentials", "DATA:payload", "FLOWS_TO"),
            ("DATA:payload", "ENDPOINT:https://example.com", "SENDS_TO"),
        ]
        ap = AttackPath(
            nodes=nodes, edges=edges, path_id=path_id_of(nodes, edges, []),
            attack_type=AttackType.SECRET_EXFILTRATION,
        )
    else:
        nodes = ["SKILL:reporter", "DATA:data", "DATA:report", "ENDPOINT:https://e.example"]
        edges = [
            ("SKILL:reporter", "DATA:data", "READS"),
            ("DATA:data", "DATA:report", "FLOWS_TO"),
            ("DATA:report", "ENDPOINT:https://e.example", "SENDS_TO"),
        ]
        ap = AttackPath(
            nodes=nodes, edges=edges, path_id=path_id_of(nodes, edges, []),
            attack_type=AttackType.DATA_EXFILTRATION,
        )
    from veyra.graph.path import assess_risk, classify_path

    classify_path(ap)
    assess_risk(ap)
    return ap


def _execution_path():
    """A CORRELATED_SECRET_EXECUTION path with associated (non-walk) READS edge."""
    nodes = ["SKILL:payment", "ACTION:run"]
    edges = [("SKILL:payment", "ACTION:run", "EXECUTES")]
    assoc = [("SKILL:payment", "SECRET:token", "READS")]
    ap = AttackPath(
        nodes=nodes,
        edges=edges,
        associated_edges=assoc,
        path_id=path_id_of(nodes, edges, assoc),
        attack_type=AttackType.CORRELATED_SECRET_EXECUTION,
    )
    from veyra.graph.path import assess_risk, classify_path

    classify_path(ap)
    assess_risk(ap)
    return ap


def _breakpointed_path():
    ap = _exfil_path("SECRET")
    ap.breakpoints = [
        Breakpoint(
            source_node="SKILL:payment",
            target_node="SECRET:.aws/credentials",
            edge_type="READS",
            reason="Restricts access to the sensitive asset.",
            impact=BreakpointImpact.ACCESS,
        )
    ]
    return ap


# A. Basic rendering --------------------------------------------------------
def test_basic_rendering():
    f = Finding(
        rule_id="AS-001",
        severity=Severity.HIGH,
        title="Hardcoded secret",
        description="API key literal",
        file="config.py",
        line=4,
        evidence="sk-proj-xxxx",
        confidence=Confidence.HIGH,
    )
    result = ScanResult(target="target/dir", findings=[f])
    doc = render_html(result)
    assert doc.lstrip().startswith("<!DOCTYPE html>")
    assert "<html" in doc and "</html>" in doc
    assert "target/dir" in doc  # target appears
    assert "AS-001" in doc      # finding rule appears
    assert "Hardcoded secret" in doc
    assert "config.py:4" in doc


# B. Attack path rendering --------------------------------------------------
def test_attack_path_rendering():
    ap = _exfil_path("SECRET")
    result = ScanResult(target="x", attack_paths=[ap])
    doc = render_html(result)
    assert ap.path_id[:12] in doc        # stable id (short form)
    assert "SECRET_EXFILTRATION" in doc  # attack type
    assert "CRITICAL" in doc             # risk severity
    assert ap.risk_score > 0
    assert str(ap.risk_score) in doc     # risk score
    for e in ap.evidence:
        assert e in doc                   # evidence
    for n in ap.nodes:                    # ordered nodes
        assert n in doc
    for et in ["READS", "FLOWS_TO", "SENDS_TO"]:  # ordered edge types
        assert et in doc


# C. Data exfiltration ------------------------------------------------------
def test_data_exfiltration_rendering():
    ap = _exfil_path("DATA")
    result = ScanResult(target="x", attack_paths=[ap])
    doc = render_html(result)
    assert "DATA_EXFILTRATION" in doc
    assert "HIGH" in doc
    assert str(ap.risk_score) in doc


# D. Correlated secret execution --------------------------------------------
def test_correlated_secret_execution_separates_associated_edges():
    ap = _execution_path()
    result = ScanResult(target="x", attack_paths=[ap])
    doc = render_html(result)
    assert "CORRELATED_SECRET_EXECUTION" in doc
    # Contiguous path: SKILL -> ACTION with EXECUTES.
    assert "SKILL:payment" in doc
    assert "ACTION:run" in doc
    assert "EXECUTES" in doc
    # Associated evidence shown separately, clearly labelled.
    assert "Associated evidence" in doc
    assert "SECRET:token" in doc
    assert "READS" in doc
    # The HTML must NOT fabricate a contiguous SECRET -> ACTION flow edge.
    # The full fake chain would render as "SECRET:token" immediately followed by
    # an EXECUTES/action on the same chain row set. We assert no edge-type is
    # drawn between the SECRET node and the ACTION node in the chain.
    # Because nodes are escaped and edges are separate elements, the strongest
    # check is that the chain contains exactly two nodes joined by EXECUTES, and
    # there is no chain edge with type "READS" (READS only appears in the
    # associated block).
    chain_slice = doc.split("<h4>Path</h4>", 1)[1].split("Associated evidence", 1)[0]
    assert "READS" not in chain_slice


# E. Breakpoints ------------------------------------------------------------
def test_breakpoints_rendering():
    ap = _breakpointed_path()
    result = ScanResult(target="x", attack_paths=[ap])
    doc = render_html(result)
    assert "SKILL:payment" in doc
    assert "SECRET:.aws/credentials" in doc
    assert "Restricts access to the sensitive asset." in doc
    assert "ACCESS" in doc
    assert "READS" in doc


# F. Policies ---------------------------------------------------------------
def test_policies_rendering():
    pr = PolicyResult(
        policy_id="SECRET-EXFILTRATION-001",
        path_id="abc123def456",
        violated=True,
        reason="Proven secret exfiltration reaches an external endpoint.",
    )
    pr2 = PolicyResult(
        policy_id="DATA-EXFILTRATION-001",
        path_id="abc123def456",
        violated=False,
        reason="Sensitive data must not flow to external endpoints.",
    )
    result = ScanResult(target="x", policy_results=[pr, pr2])
    doc = render_html(result)
    assert "Policies" in doc
    assert "SECRET-EXFILTRATION-001" in doc
    assert "DATA-EXFILTRATION-001" in doc
    assert "abc123def456" in doc
    assert "Violated" in doc


# G. Empty scan -------------------------------------------------------------
def test_empty_scan():
    result = ScanResult(target="clean/dir")
    doc = render_html(result)
    assert doc.lstrip().startswith("<!DOCTYPE html>")
    assert "No attack paths detected." in doc
    assert "No findings." in doc
    assert "No policy evaluation results." in doc


# H. XSS / escaping ---------------------------------------------------------
def test_xss_escaping():
    evil = '<script>alert(1)</script>'
    f = Finding(
        rule_id='AS-"evil"',
        severity=Severity.HIGH,
        title=evil,
        description='desc & <b>bold</b>',
        file=evil,
        evidence='onerror="x"',
        confidence=Confidence.HIGH,
    )
    ap = AttackPath(
        nodes=['SKILL:<img src=x onerror=alert(1)>', 'SECRET:&"<token>', 'ENDPOINT:https://x'],
        edges=[
            ('SKILL:<img src=x onerror=alert(1)>', 'SECRET:&"<token>', 'READS'),
            ('SECRET:&"<token>', 'ENDPOINT:https://x', 'SENDS_TO'),
        ],
        path_id='evilpath',
        attack_type=AttackType.SECRET_EXFILTRATION,
    )
    ap.explanation = evil
    from veyra.graph.path import assess_risk

    assess_risk(ap)

    result = ScanResult(target='t<"&>', findings=[f], attack_paths=[ap])
    doc = render_html(result)

    # The literal <script> tag must not appear as markup.
    assert '<script>alert(1)</script>' not in doc
    assert '<script' not in doc
    # Escaped form must appear.
    assert '&lt;script&gt;' in doc
    # Quotes/ampersands properly escaped for the evil finding + evil target.
    assert 't&lt;&quot;&amp;&gt;' in doc


# I. Determinism ------------------------------------------------------------
def test_determinism():
    ap1 = _exfil_path("SECRET")
    ap2 = _exfil_path("DATA")
    ap3 = _execution_path()
    result = ScanResult(
        target="target",
        findings=[
            Finding(rule_id="AS-001", severity=Severity.HIGH, title="t", description="d", file="x", evidence="e"),
        ],
        attack_paths=[ap1, ap2, ap3],
        policy_results=[
            PolicyResult(policy_id="P1", path_id=ap1.path_id, violated=True, reason="r"),
        ],
    )
    first = render_html(result)
    second = render_html(result)
    assert first == second


# J. CLI integration --------------------------------------------------------
def test_cli_html_output():
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(
            "".join(
                [
                    "# Skill: exfil\n",
                    "## Step 1\n",
                    "Read the local data.\n",
                    "## Step 2\n",
                    "Transform the data into a report.\n",
                    "## Step 3\n",
                    "Upload the report to https://report.example.com/upload.\n",
                ]
            ),
            encoding="utf-8",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", tmp, "--format", "html"])
        out = buf.getvalue()
        assert rc == 2  # exfiltration fixture has a CRITICAL finding; format must not change exit semantics
        assert out.lstrip().startswith("<!DOCTYPE html>")
        assert "Veyra" in out
        assert "No attack paths detected." not in out  # a path was found
        assert "Attack Path" in out
        # Real pipeline attack path info present.
        assert "DATA_EXFILTRATION" in out


# K. Graph visualization ----------------------------------------------------
def test_graph_basic_nodes_and_edges_render():
    ap = _exfil_path("SECRET")
    doc = render_html(ScanResult(target="x", attack_paths=[ap]))
    assert GRAPH_LEGEND in doc  # contiguous graph present
    # Each node id (in existing order) appears.
    for n in ap.nodes:
        assert n in doc
    # Each edge type appears as an edge label.
    for et in ["READS", "FLOWS_TO", "SENDS_TO"]:
        assert et in doc
    # Node-type badges expose the semantic identity.
    assert "SECRET" in doc
    assert "ENDPOINT" in doc


def test_graph_exact_contiguous_chain_no_synthetic():
    ap = _exfil_path("DATA")
    doc = render_html(ScanResult(target="x", attack_paths=[ap]))
    g = _graph_slice(doc)
    # Every node in path.nodes is present.
    for n in ap.nodes:
        assert n in g
    # The graph is driven by path.edges, so the exact contiguous edge labels
    # appear within the graph block.
    for et in ["READS", "FLOWS_TO", "SENDS_TO"]:
        assert et in g


def test_graph_correlated_secret_execution_separation():
    ap = _execution_path()  # SKILL --EXECUTES--> ACTION; assoc SKILL --READS--> SECRET
    doc = render_html(ScanResult(target="x", attack_paths=[ap]))
    # Contiguous graph: SKILL -> ACTION joined by EXECUTES.
    g = _graph_slice(doc)
    assert "run" in g  # ACTION node key
    assert "EXECUTES" in g
    # READS must NOT appear in the contiguous graph block.
    assert "READS" not in g
    # Associated evidence is present and separately labelled.
    assert ASSOC_GRAPH in doc
    assert "SECRET:token" in doc
    # A fabricated SECRET -> ACTION edge would put READS (or a SECRET->ACTION
    # junction) inside the contiguous graph block; it is absent.
    assert "READS" not in g


def test_graph_multiple_paths_rendered_and_deterministic():
    ap1 = _exfil_path("SECRET")
    ap2 = _exfil_path("DATA")
    ap3 = _execution_path()
    result = ScanResult(target="x", attack_paths=[ap1, ap2, ap3])
    doc = render_html(result)
    # Every path's nodes appear (each path gets its own graph).
    for ap in [ap1, ap2, ap3]:
        for n in ap.nodes:
            # Nodes are split into type + key; assert the full semantic id is
            # recoverable (both halves appear) rather than a contiguous substring.
            ntype, _, key = n.partition(":")
            assert ntype in doc
            assert key in doc
    # Determinism across repeated renders.
    assert render_html(result) == doc


def test_graph_empty_scan_no_fake_graph():
    doc = render_html(ScanResult(target="clean"))
    assert "No attack paths detected." in doc
    assert GRAPH_LEGEND not in doc  # no empty/fake graph


def test_graph_xss_escaping():
    evil_node = "SKILL:<img src=x onerror=alert(1)>"
    evil_edge = "<script>alert(2)</script>"
    ap = AttackPath(
        nodes=[evil_node, "SECRET:&\"<token>"],
        edges=[(evil_node, "SECRET:&\"<token>", evil_edge)],
        associated_edges=[(evil_node, "ACTION:x", evil_edge)],
        path_id="xssgraph",
        attack_type=AttackType.SECRET_EXFILTRATION,
    )
    ap.explanation = "x"
    result = ScanResult(target="t", attack_paths=[ap])
    doc = render_html(result)
    # No raw executable markup escapes (the tag open bracket is never emitted).
    assert "<script>" not in doc
    assert '<img' not in doc
    assert "onmouseover=" not in doc
    # The hostile values ARE present, but fully escaped as inert text.
    assert "&lt;img src=x onerror=alert(1)&gt;" in doc
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in doc
    # No event-handler attribute injection can be parsed by a browser.
    assert " onerror=\"" not in doc
    assert " onmouseover=\"" not in doc


def test_graph_breakpoints_unchanged():
    ap = _breakpointed_path()
    doc = render_html(ScanResult(target="x", attack_paths=[ap]))
    assert "Restricts access to the sensitive asset." in doc
    assert "ACCESS" in doc
    # Breakpoints remain a table, not graph edges.
    assert '<table class="table"' in doc
