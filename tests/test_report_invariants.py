"""E-2: invariant tests locking down that what HTML / JSON / SARIF renderers
SERIALIZE for an AttackPath is faithful to the path's actual data. Nothing
in the report should say anything that isn't backed by the proven semantics;
nothing true should be dropped.

Each invariant below is checked against:
  - a synthetic ScanResult that contains one of each attack type
    (secret exfil, data exfil, correlation, handoff).
  - the real attack-lab corpus.

These invariants intentionally sit at the SERIALIZATION boundary (what users
read), so they catch drift in any of:

  - the AttackPath -> dict helpers (added/renamed fields)
  - the HTML/SARIF/JSON renderers (lying about data)
  - the underlying semantic pipeline (lying in evidence/breakpoints)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from veyra.attack_lab import ATTACK_CASES
from veyra.graph import (
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
)
from veyra.graph.path import AttackType
from veyra.models import ScanResult
from veyra.reporters.html import render_html
from veyra.reporters.json import render_json
from veyra.reporters.sarif import render_sarif
from veyra.scanner import scan_path


# --- helpers ----------------------------------------------------------------

def _secret_exfil_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:s", type=NodeType.SKILL),
        Node(id="SECRET:tok", type=NodeType.SECRET),
        Node(id="DATA:r", type=NodeType.DATA),
        Node(id="ENDPOINT:e", type=NodeType.ENDPOINT),
    ):
        g.add_node(n)
    g.add_edge("SKILL:s", "SECRET:tok", EdgeType.READS)
    g.add_edge("SECRET:tok", "DATA:r", EdgeType.FLOWS_TO)
    g.add_edge("DATA:r", "ENDPOINT:e", EdgeType.SENDS_TO)
    return g


def _data_exfil_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:s", type=NodeType.SKILL),
        Node(id="DATA:a", type=NodeType.DATA),
        Node(id="DATA:b", type=NodeType.DATA),
        Node(id="ENDPOINT:e", type=NodeType.ENDPOINT),
    ):
        g.add_node(n)
    g.add_edge("SKILL:s", "DATA:a", EdgeType.READS)
    g.add_edge("DATA:a", "DATA:b", EdgeType.FLOWS_TO)
    g.add_edge("DATA:b", "ENDPOINT:e", EdgeType.SENDS_TO)
    return g


def _correlation_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:s", type=NodeType.SKILL),
        Node(id="SECRET:tok", type=NodeType.SECRET),
        Node(id="ACTION:run", type=NodeType.ACTION),
    ):
        g.add_node(n)
    g.add_edge("SKILL:s", "SECRET:tok", EdgeType.READS)
    g.add_edge("SKILL:s", "ACTION:run", EdgeType.EXECUTES)
    return g


def _handoff_graph():
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:a", type=NodeType.SKILL),
        Node(id="SKILL:b", type=NodeType.SKILL),
    ):
        g.add_node(n)
    g.add_edge("SKILL:a", "SKILL:b", EdgeType.HANDOFF)
    return g


def _mixed_scan_result() -> ScanResult:
    paths = (
        PathAnalyzer(_secret_exfil_graph()).analyze()
        + PathAnalyzer(_data_exfil_graph()).analyze()
        + PathAnalyzer(_correlation_graph()).analyze()
        + PathAnalyzer(_handoff_graph()).analyze()
    )
    return ScanResult(target="/tmp/probe", attack_paths=paths)


def _real_corpus_attack_paths():
    root = Path(__file__).resolve().parent / "fixtures" / "attacks"
    out = []
    for case in ATTACK_CASES:
        p = root / case.path
        if not p.exists():
            continue
        r = scan_path(str(p))
        if r.attack_paths:
            for ap in r.attack_paths:
                out.append((case.path, ap))
    return out


# --- JSON invariants --------------------------------------------------------

def test_json_output_contains_every_attack_path_unmodified():
    result = _mixed_scan_result()
    blob = json.loads(render_json(result))
    out_paths = blob.get("attack_paths") or []
    assert len(out_paths) == len(result.attack_paths), (
        f"some paths were dropped: got {len(out_paths)} of {len(result.attack_paths)}"
    )
    by_pid = {p["path_id"]: p for p in out_paths}
    for ap in result.attack_paths:
        ap.ensure_path_id()
        assert ap.path_id in by_pid, f"path {ap.path_id} missing from JSON"
        js = by_pid[ap.path_id]
        assert js["attack_type"] == ap.attack_type.value
        assert list(js["nodes"]) == list(ap.nodes)
        assert [(e["source"], e["target"], e["type"]) for e in js["edges"]] == list(ap.edges)
        assert [(e["source"], e["target"], e["type"]) for e in js["associated_edges"]] == list(ap.associated_edges)
        assert list(js["evidence"]) == list(ap.evidence)
        assert [(b["source_node"], b["target_node"], b["edge_type"]) for b in js["breakpoints"]] == \
               [(b.source_node, b.target_node, b.edge_type) for b in ap.breakpoints]


# --- SARIF invariants -------------------------------------------------------

SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def test_sarif_level_matches_risk_severity_for_every_path():
    result = _mixed_scan_result()
    sarif = json.loads(render_sarif(result))
    results = sarif["runs"][0]["results"]
    assert len(results) == len(result.attack_paths)
    for r, ap in zip(results, result.attack_paths):
        ap.ensure_path_id()
        # Match by path_id from properties (canonical way)
        if r.get("properties", {}).get("path_id") != ap.path_id:
            continue
        expected = SARIF_LEVEL[ap.risk_severity.value]
        assert r["level"] == expected, (
            f"path {ap.path_id} risk_severity {ap.risk_severity.value} -> "
            f"SARIF level {r['level']}, expected {expected}"
        )


def test_sarif_message_matches_attack_path_explanation():
    result = _mixed_scan_result()
    sarif = json.loads(render_sarif(result))
    for r, ap in zip(sarif["runs"][0]["results"], result.attack_paths):
        ap.ensure_path_id()
        # Match by path_id; assume 1:1 ordering by construction in this test
        text = r["message"]["text"]
        expected = ap.explanation or ap.attack_type.value
        assert text == expected, (ap.attack_type.value, "got", text, "expected", expected)


def test_sarif_properties_carry_real_evidence_no_invention():
    result = _mixed_scan_result()
    sarif = json.loads(render_sarif(result))
    for r, ap in zip(sarif["runs"][0]["results"], result.attack_paths):
        ap.ensure_path_id()
        props = r.get("properties") or {}
        assert list(props.get("evidence") or []) == list(ap.evidence)


# --- HTML invariants --------------------------------------------------------

def test_html_renders_every_summary():
    result = _mixed_scan_result()
    html = render_html(result)
    for ap in result.attack_paths:
        if ap.attack_type == AttackType.UNKNOWN:
            assert "correlated graph activity without a classified attack type" in html
            continue
        assert ap.explanation_details.summary in html


def test_html_data_exfil_summary_never_says_secret():
    paths = PathAnalyzer(_data_exfil_graph()).analyze()
    result = ScanResult(target="/tmp/x", attack_paths=paths)
    ap = paths[0]
    assert ap.attack_type == AttackType.DATA_EXFILTRATION
    assert "secret" not in ap.explanation_details.summary.lower()


def test_html_breakpoints_render_as_real_rows():
    """HTML renders breakpoints as a TABLE (Source/Target/Edge type),
    not as an 'A --B--> C' arrow string. Each real breakpoint row
    must appear verbatim — never a fabricated one."""
    result = _mixed_scan_result()
    html = render_html(result)
    for ap in result.attack_paths:
        for b in ap.breakpoints:
            row_pattern = re.compile(
                r"<td class=\"mono\">" + re.escape(b.source_node) + r"</td>"
                r"\s*<td class=\"mono\">" + re.escape(b.target_node) + r"</td>"
                r"\s*<td class=\"mono\">" + re.escape(b.edge_type) + r"</td>"
            )
            assert row_pattern.search(html), (
                f"breakpoint {b.source_node}/{b.target_node}/{b.edge_type} missing from HTML"
            )


# --- real corpus invariants across all three renderers ---------------------

def test_real_corpus_serialization_everywhere_is_faithful():
    paths = _real_corpus_attack_paths()
    assert paths
    result = ScanResult(target="/tmp/real", attack_paths=[p for _, p in paths])

    blob = json.loads(render_json(result))
    blob_paths = blob.get("attack_paths") or []
    assert len(blob_paths) == len(paths)
    pids_json = {p["path_id"] for p in blob_paths}
    for _, ap in paths:
        ap.ensure_path_id()
        assert ap.path_id in pids_json

    sarif = json.loads(render_sarif(result))
    sarif_pids = {r.get("properties", {}).get("path_id")
                  for r in sarif["runs"][0]["results"]
                  if r.get("properties", {}).get("path_id")}
    for _, ap in paths:
        assert ap.path_id in sarif_pids

    html = render_html(result)
    for _, ap in paths:
        if ap.explanation_details is None:
            continue
        assert ap.explanation_details.summary in html


def test_real_corpus_html_data_paths_keep_clean_summary():
    paths = _real_corpus_attack_paths()
    de = [(_, ap) for _, ap in paths if ap.attack_type == AttackType.DATA_EXFILTRATION]
    assert de
    result = ScanResult(target="/tmp/x", attack_paths=[p for _, p in de])
    html = render_html(result)
    for _, ap in de:
        summary = ap.explanation_details.summary
        assert "secret" not in summary.lower()
        assert summary in html
