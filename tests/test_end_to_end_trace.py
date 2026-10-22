"""T7: one end-to-end trace, from a file on disk to a word in a report.

The queue's last item asks for a single regression that walks
``scan -> findings -> paths -> policy -> JSON/SARIF/HTML`` and checks three
things on real output, not on hand-built objects:

* every claim in a report points at an artifact that exists -- a finding's file
  and line, a path's nodes and edges, a policy result's path;
* no result is allowed to read as "safe"/"passed" when part of the target was
  never read (the T4/T5 contract, checked through all three surfaces);
* the SARIF/HTML surfaces neither state one incident twice nor strengthen a
  claim: the chain finding keeps its evidence but is marked superseded by the
  path that carries the walk, and every level/badge is the earned ``risk_*``
  value, never the declared one.

Values are either derived from the artifact they claim to describe, or compared
against a second render of the same ScanResult. Nothing here hardcodes an
"expected" count that the scanner could be tuned to.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from veyra.coverage import COVERAGE_FULL, COVERAGE_PARTIAL, SKIP_REASONS
from veyra.models import MAX_SCORE, RISK_UNKNOWN, SEVERITY_WEIGHTS, Severity
from veyra.reporters.html import render_html
from veyra.reporters.json import render_json
from veyra.reporters.sarif import render_sarif
from veyra.scanner import scan_path

REPO = Path(__file__).resolve().parents[1]
CHAIN = REPO / "tests" / "fixtures" / "attacks" / "multi-stage" / "exfiltration-flow"

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
LEVEL_OF_SEV = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}
LEVEL_RANK = {"none": 0, "note": 1, "warning": 2, "error": 3}


def _render(result):
    return (
        json.loads(render_json(result)),
        json.loads(render_sarif(result)),
        render_html(result),
    )


def _rank(value) -> int:
    return SEV_RANK[getattr(value, "value", value)]


def _uri(path: str) -> str:
    return path.replace("\\", "/")


# --- claims about findings --------------------------------------------------


def _assert_findings_trace_to_source(doc):
    for finding in doc["findings"]:
        artifact = Path(finding["file"])
        assert artifact.is_file(), f"finding cites a file that is not there: {artifact}"
        lines = artifact.read_text(encoding="utf-8", errors="replace").splitlines()
        line = finding.get("line")
        if line is not None:
            assert 1 <= line <= len(lines), (
                f"{finding['rule_id']} cites line {line} of a {len(lines)}-line file"
            )
            cited = lines[line - 1]
        else:
            cited = "\n".join(lines)
        matched = finding.get("matched_text") or ""
        if finding["rule_id"].startswith("AS-CHAIN-"):
            # A correlation rule's "matched_text" is its own label for the walk,
            # not a quotation. Pin that distinction so a chain finding can never
            # pass as source text, and a line rule can never pass as a label.
            assert matched == finding["evidence"]
            assert matched not in cited
        else:
            assert matched, f"{finding['rule_id']} quotes nothing"
            assert matched in cited, (
                f"{finding['rule_id']} claims a match that is not on line {line}"
            )


# --- claims about paths and policy -----------------------------------------


def _assert_paths_trace_to_graph(doc):
    ids = [p["path_id"] for p in doc.get("attack_paths", [])]
    assert len(ids) == len(set(ids)), "two paths share one identity"
    for path in doc["attack_paths"]:
        assert path["path_id"]

        nodes = path["nodes"]
        edges = path["edges"]
        assert path["entry_node"] == nodes[0]
        assert len(edges) == len(nodes) - 1, "the walk names an edge it does not take"
        for i, edge in enumerate(edges):
            assert edge["source"] == nodes[i]
            assert edge["target"] == nodes[i + 1]
            assert edge["type"]
        for node in nodes:
            if node.startswith("SKILL:"):
                assert Path(node.split(":", 1)[1]).is_file(), (
                    f"path starts in a file that is not there: {node}"
                )

        # Declared severity/confidence may not outrun what the walk proves.
        assert _rank(path["severity"]) <= _rank(path["risk_severity"])
        assert _rank(path["confidence"]) <= _rank(path["risk_confidence"])
        if path["risk_score"] > 0:
            assert path["evidence"], "risk without evidence"
            assert path["explanation"], "path without an explanation"

        violated = sorted(
            r["policy_id"]
            for r in doc["policy_results"]
            if r["violated"] and r["path_id"] == path["path_id"]
        )
        assert path["policy_ids"] == violated


def _assert_policy_and_summary_are_derived(doc):
    paths = doc.get("attack_paths", [])
    path_ids = {p["path_id"] for p in paths}
    violated_ids = set()
    for result in doc["policy_results"]:
        assert result["path_id"] in path_ids, "a policy result names no real path"
        assert result["reason"], "a policy result states no reason"
        if result["violated"]:
            violated_ids.add(result["policy_id"])
            owner = next(p for p in paths if p["path_id"] == result["path_id"])
            assert result["policy_id"] in owner["policy_ids"]

    findings = doc["findings"]
    active = [f for f in findings if not f["suppressed"]]
    assert doc["score"] == min(
        sum(SEVERITY_WEIGHTS[Severity(f["severity"])] for f in active), MAX_SCORE
    )
    for severity in ("critical", "high", "medium", "low"):
        assert doc["summary"][severity] == sum(
            1 for f in active if f["severity"] == severity.upper()
        )
    assert doc["summary"]["suppressed"] == len(findings) - len(active)

    coverage = doc["coverage"]["coverage_status"]
    if violated_ids:
        assert doc["policy_status"] == "FAIL"
    elif coverage == COVERAGE_FULL:
        assert doc["policy_status"] == "PASS"
    else:
        assert doc["policy_status"] == "UNKNOWN"
    if doc["score"] > 0:
        assert doc["risk_level"] != "SAFE"
    elif coverage != COVERAGE_FULL:
        assert doc["risk_level"] == RISK_UNKNOWN


# --- the three surfaces agree, and none of them inflates --------------------


def _assert_sarif_and_html_agree(doc, sarif, html):
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"

    finding_files = {f["file"] for f in doc["findings"]}
    assert {a["location"]["uri"] for a in run["artifacts"]} == {
        _uri(f) for f in finding_files
    }, "SARIF invents or drops an artifact"

    path_results = [
        r for r in run["results"] if r["properties"].get("result_kind") == "attack_path"
    ]
    finding_results = [
        r for r in run["results"] if r["properties"].get("result_kind") == "finding"
    ]
    assert len(finding_results) == len(doc["findings"])
    assert len(path_results) == len(doc.get("attack_paths", []))
    assert [r["properties"]["path_id"] for r in path_results] == [
        p["path_id"] for p in doc.get("attack_paths", [])
    ], "SARIF reorders, repeats or invents a path"

    doc_paths = {p["path_id"]: p for p in doc.get("attack_paths", [])}
    for result in path_results:
        path = doc_paths[result["properties"]["path_id"]]
        assert result["properties"]["risk_severity"] == path["risk_severity"]
        assert result["properties"]["risk_confidence"] == path["risk_confidence"]
        assert LEVEL_RANK[result["level"]] <= LEVEL_RANK[
            LEVEL_OF_SEV[path["risk_severity"]]
        ], "SARIF states a level stronger than the earned severity"
        if result.get("locations"):
            assert result["properties"]["location_provenance"] == "entry_node_skill_file"
            # The location the SARIF consumer clicks must be the file the walk
            # starts in -- the same SKILL node the JSON names, not a guess.
            assert result["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ] == _uri(path["nodes"][0].split(":", 1)[1])
        else:
            assert result["properties"]["location_provenance"] == "omitted"

    doc_findings = {f["rule_id"]: f for f in doc["findings"]}
    for result in finding_results:
        finding = doc_findings[result["ruleId"]]
        assert LEVEL_RANK[result["level"]] <= LEVEL_RANK[
            LEVEL_OF_SEV[finding["severity"]]
        ]

    # One incident, stated once: a correlation finding keeps its evidence but is
    # marked superseded by the path carrying the same walk.
    for result in finding_results:
        if result["ruleId"].startswith("AS-CHAIN-"):
            assert result["properties"]["superseded_by_path"] in doc_paths
            assert result.get("suppressions"), "the duplicated incident is not marked"
    effective = [
        r for r in run["results"] if not r["properties"].get("superseded_by_path")
    ]
    plain_findings = [
        r for r in finding_results if not r["ruleId"].startswith("AS-CHAIN-")
    ]
    assert len(effective) == len(path_results) + len(plain_findings)

    cards = html.count('<article class="card">')
    assert cards == len(doc.get("attack_paths", [])), "HTML repeats or drops an incident"
    for path in doc.get("attack_paths", []):
        short_id = path["path_id"][:12]
        assert html.count(f'<span class="mono">{short_id}</span>') == 1
        badge = (
            f'<div class="card-badges"><span class="badge sev-'
            f'{path["risk_severity"].lower()}">{path["risk_severity"]}</span></div>'
        )
        assert badge in html, "the path card prints a severity the walk did not earn"
        for node in path["nodes"]:
            assert f'<span class="node">{node}</span>' in html

    coverage = doc["coverage"]["coverage_status"]
    assert run["properties"]["coverage"] == doc["coverage"]
    assert (
        f'<div class="stat-label">Coverage</div>'
        f'<div class="stat-value">{coverage}</div>'
    ) in html
    if coverage != COVERAGE_FULL:
        assert "sev-safe" not in html
        assert "badge sev-pass" not in html
        assert ">PASS<" not in html


# --- the single end-to-end regression --------------------------------------


def test_end_to_end_report_is_traceable_and_never_falsely_safe(tmp_path):
    # 1. The chain fixture: every word in the report points at a real artifact.
    chain = scan_path(str(CHAIN))
    assert chain.findings and chain.attack_paths and chain.policy_results
    doc, sarif, html = _render(chain)
    assert doc["coverage"]["coverage_status"] == COVERAGE_FULL
    assert doc["policy_status"] == "FAIL"
    assert doc["risk_level"] != "SAFE"
    _assert_findings_trace_to_source(doc)
    _assert_paths_trace_to_graph(doc)
    _assert_policy_and_summary_are_derived(doc)
    _assert_sarif_and_html_agree(doc, sarif, html)

    # 2. The same chain beside a file the scanner refuses: proof survives, and
    #    silence never upgrades or downgrades it.
    mixed = tmp_path / "chain-with-binary"
    shutil.copytree(CHAIN, mixed)
    # A file outside the scannable set is refused earlier (``not_scannable``);
    # to reach the binary refusal the name must be one the scanner would read.
    (mixed / "payload.md").write_bytes(b"\x00\x01binary\x00")
    refused = scan_path(str(mixed))
    assert refused.coverage_status == COVERAGE_PARTIAL
    assert [f.rule_id for f in refused.findings] == [f.rule_id for f in chain.findings]
    assert refused.score == chain.score
    assert [p.attack_type for p in refused.attack_paths] == [
        p.attack_type for p in chain.attack_paths
    ]
    assert refused.policy_status == chain.policy_status == "FAIL"
    refused_doc, refused_sarif, refused_html = _render(refused)
    _assert_findings_trace_to_source(refused_doc)
    _assert_paths_trace_to_graph(refused_doc)
    _assert_policy_and_summary_are_derived(refused_doc)
    _assert_sarif_and_html_agree(refused_doc, refused_sarif, refused_html)

    # 3. A clean target: SAFE/PASS only while the whole target was read; one
    #    unread file turns the same zero findings into "not answered".
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "notes.md").write_text("# Notes\n\nNothing to see here.\n", encoding="utf-8")
    clean_only = scan_path(str(clean))
    assert clean_only.findings == [] and clean_only.score == 0
    assert clean_only.coverage_status == COVERAGE_FULL
    assert clean_only.risk_level == "SAFE"
    assert clean_only.policy_status == "PASS"
    clean_doc, clean_sarif, clean_html = _render(clean_only)
    assert "sev-safe" in clean_html
    assert clean_sarif["runs"][0]["results"] == []

    (clean / "payload.md").write_bytes(b"\x00\x01binary\x00")
    unread = scan_path(str(clean))
    assert unread.findings == [] and unread.score == 0
    assert unread.coverage_status == COVERAGE_PARTIAL
    assert unread.risk_level == RISK_UNKNOWN
    assert unread.policy_status == "UNKNOWN"
    unread_doc, unread_sarif, unread_html = _render(unread)
    skipped = unread_doc["coverage"]["files_skipped"]
    assert skipped == [{"path": str(clean / "payload.md"), "reason": "binary"}]
    assert {entry["reason"] for entry in skipped} <= SKIP_REASONS
    assert unread_sarif["runs"][0]["results"] == clean_sarif["runs"][0]["results"] == []
    assert unread_sarif["runs"][0]["artifacts"] == []
    assert unread_sarif["runs"][0]["properties"]["coverage"] == unread_doc["coverage"]
    _assert_policy_and_summary_are_derived(unread_doc)
    _assert_sarif_and_html_agree(unread_doc, unread_sarif, unread_html)
