"""CLI/reporter integration tests for the Security Graph + AttackPath output."""

import json

from veyra.graph import EdgeType, Node, NodeType, PathAnalyzer, SecurityGraph
from veyra.models import Confidence, Finding, ScanResult, Severity
from veyra.reporters import render_json, render_sarif, render_terminal


def _path_graph():
    """A graph with a genuine object-continuity exfiltration path."""
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:skill", type=NodeType.SKILL, label="skill"),
        Node(id="SECRET:token", type=NodeType.SECRET, label="token"),
        Node(id="DATA:payload", type=NodeType.DATA, label="payload"),
        Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT, label="evil"),
    ):
        g.add_node(n)
    g.add_edge("SKILL:skill", "SECRET:token", EdgeType.READS)
    g.add_edge("SECRET:token", "DATA:payload", EdgeType.FLOWS_TO)
    g.add_edge("DATA:payload", "ENDPOINT:https://evil.com", EdgeType.SENDS_TO)
    return g


def _finding():
    return Finding(
        rule_id="AS-006",
        severity=Severity.HIGH,
        title="Sensitive credential file access",
        description="a credential is read",
        file="SKILL.md",
        evidence="access",
        remediation="r",
        confidence=Confidence.HIGH,
    )


def test_json_exposes_attack_paths_present():
    """A ScanResult with attack paths exposes them as a top-level field."""
    paths = PathAnalyzer(_path_graph()).analyze()
    assert len(paths) == 1
    result = ScanResult(
        target="x",
        findings=[_finding()],
        attack_paths=paths,
    )
    d = json.loads(render_json(result))
    assert "attack_paths" in d
    assert "findings" in d
    assert d["attack_paths"][0]["title"] == "Secret exposed to external endpoint"
    assert "AS-" not in d["attack_paths"][0]["title"]


def test_json_omits_attack_paths_when_absent():
    """A scan without attack paths has no attack_paths field, findings intact."""
    result = ScanResult(target="x", findings=[_finding()], attack_paths=[])
    d = json.loads(render_json(result))
    assert "attack_paths" not in d
    assert len(d["findings"]) == 1


def test_terminal_includes_attack_paths_section():
    """Human-readable output includes an Attack Paths section when paths exist."""
    paths = PathAnalyzer(_path_graph()).analyze()
    result = ScanResult(target="x", findings=[_finding()], attack_paths=paths)
    out = render_terminal(result)
    assert "Attack Paths" in out
    assert "Secret exposed to external endpoint" in out
    # findings still present
    assert "Sensitive credential file access" in out


def test_terminal_no_noisy_section_without_paths():
    """No Attack Paths section is printed when there are none."""
    result = ScanResult(target="x", findings=[_finding()], attack_paths=[])
    out = render_terminal(result)
    assert "Attack Paths" not in out
    assert "Sensitive credential file access" in out


def test_path_used_is_contiguous():
    """The exposed attack path is a truthful contiguous walk."""
    paths = PathAnalyzer(_path_graph()).analyze()
    assert paths[0].is_contiguous
    d = paths[0].to_dict()
    nodes = d["nodes"]
    edges = d["edges"]
    for i, e in enumerate(edges):
        assert e["source"] == nodes[i]
        assert e["target"] == nodes[i + 1]
