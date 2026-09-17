"""Tests for AttackPath <-> policy association (Commit 14).

Verifies that each AttackPath carries an explicit, deterministic, serializable
list of the policy IDs it actually violates, projected from the PolicyEngine
output (the single source of truth). policy_ids must never affect path identity.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from veyra.cli import main
from veyra.graph.path import AttackPath, AttackType, PathAnalyzer, path_id_of
from veyra.graph.builder import SecurityGraph, build_from_findings, add_handoff
from veyra.graph.models import EdgeType, Node, NodeType
from veyra.models import Finding, ScanResult, Severity
from veyra.policy import PolicyEngine, PolicyResult, associate_policy_ids
from veyra.reporters import render_html, render_json, render_sarif
from veyra.scanner import scan_path


# --- Fixture builders ------------------------------------------------------

def _secret_exfil_path():
    """A contiguous SECRET_EXFILTRATION walk (READS -> FLOWS_TO -> SENDS_TO)."""
    nodes = ["SKILL:payment", "SECRET:.aws/credentials", "DATA:payload", "ENDPOINT:https://example.com"]
    edges = [
        ("SKILL:payment", "SECRET:.aws/credentials", "READS"),
        ("SECRET:.aws/credentials", "DATA:payload", "FLOWS_TO"),
        ("DATA:payload", "ENDPOINT:https://example.com", "SENDS_TO"),
    ]
    from veyra.graph.path import assess_risk, classify_path

    ap = AttackPath(nodes=nodes, edges=edges, path_id=path_id_of(nodes, edges, []))
    classify_path(ap)
    assess_risk(ap)
    return ap


def _data_exfil_path():
    nodes = ["SKILL:reporter", "DATA:data", "DATA:report", "ENDPOINT:https://e.example"]
    edges = [
        ("SKILL:reporter", "DATA:data", "READS"),
        ("DATA:data", "DATA:report", "FLOWS_TO"),
        ("DATA:report", "ENDPOINT:https://e.example", "SENDS_TO"),
    ]
    from veyra.graph.path import assess_risk, classify_path

    ap = AttackPath(nodes=nodes, edges=edges, path_id=path_id_of(nodes, edges, []))
    classify_path(ap)
    assess_risk(ap)
    return ap


def _correlated_exec_path():
    nodes = ["SKILL:payment", "ACTION:run"]
    edges = [("SKILL:payment", "ACTION:run", "EXECUTES")]
    assoc = [("SKILL:payment", "SECRET:token", "READS")]
    from veyra.graph.path import assess_risk, classify_path

    ap = AttackPath(
        nodes=nodes, edges=edges, associated_edges=assoc,
        path_id=path_id_of(nodes, edges, assoc),
    )
    classify_path(ap)
    assess_risk(ap)
    return ap


def _clean_path():
    nodes = ["SKILL:compA", "ACTION:noop"]
    edges = [("SKILL:compA", "ACTION:noop", "EXECUTES")]
    ap = AttackPath(nodes=nodes, edges=edges, path_id=path_id_of(nodes, edges, []))
    from veyra.graph.path import assess_risk, classify_path

    classify_path(ap)
    assess_risk(ap)
    return ap


def _evaluate(paths):
    engine = PolicyEngine()
    results = engine.evaluate(paths)
    associate_policy_ids(paths, results)
    return paths, results


# A/B/C. Correct association per attack type --------------------------------
def test_secret_exfil_gets_only_secret_policy():
    p, _ = _evaluate([_secret_exfil_path()])
    assert p[0].policy_ids == ["SECRET-EXFILTRATION-001"]


def test_data_exfil_gets_only_data_policy():
    p, _ = _evaluate([_data_exfil_path()])
    assert p[0].policy_ids == ["DATA-EXFILTRATION-001"]


def test_correlated_exec_gets_only_correlated_policy():
    p, _ = _evaluate([_correlated_exec_path()])
    assert p[0].policy_ids == ["CORRELATED-SECRET-EXECUTION-001"]


# D. A path does NOT receive unrelated policies ------------------------------
def test_path_does_not_receive_unrelated_policies():
    # SECRET_EXFILTRATION must not auto-receive DATA or CORRELATED policies.
    p, results = _evaluate([_secret_exfil_path()])
    assert p[0].policy_ids == ["SECRET-EXFILTRATION-001"]
    # Every non-violating policy is absent from policy_ids.
    assert "DATA-EXFILTRATION-001" not in p[0].policy_ids
    assert "CORRELATED-SECRET-EXECUTION-001" not in p[0].policy_ids


def test_correlated_exec_does_not_receive_exfil_policy_for_secret_in_evidence():
    # A SECRET appears in associated_edges but the path is correlated execution,
    # so no exfiltration policy is attached.
    p, _ = _evaluate([_correlated_exec_path()])
    assert "SECRET" in p[0].associated_edges[0][1]  # evidence has a SECRET
    assert p[0].policy_ids == ["CORRELATED-SECRET-EXECUTION-001"]
    assert "SECRET-EXFILTRATION-001" not in p[0].policy_ids
    assert "DATA-EXFILTRATION-001" not in p[0].policy_ids


# E. Deterministic ordering / multiple policies ------------------------------
def test_policy_ids_sorted_deterministically():
    p, _ = _evaluate([_secret_exfil_path(), _data_exfil_path(), _correlated_exec_path()])
    # Each path has exactly one own policy; list is deterministic (single/sorted).
    for ap in p:
        assert ap.policy_ids == sorted(ap.policy_ids)
    # Re-run -> identical results (deterministic).
    p2, _ = _evaluate([_secret_exfil_path(), _data_exfil_path(), _correlated_exec_path()])
    assert [ap.policy_ids for ap in p] == [ap.policy_ids for ap in p2]


def test_policy_association_deterministic_repeated():
    # Same ScanResult rendered repeatedly must give identical policy_ids.
    ap = _secret_exfil_path()
    _evaluate([ap])
    first = list(ap.policy_ids)
    second = None
    ap2 = _secret_exfil_path()
    _evaluate([ap2])
    assert first == ap2.policy_ids


# F. policy_ids do not affect path_id ----------------------------------------
def test_policy_ids_do_not_change_path_id():
    ap1 = _data_exfil_path()
    pid_before = ap1.path_id
    _evaluate([ap1])  # populates policy_ids
    assert ap1.policy_ids == ["DATA-EXFILTRATION-001"]
    assert ap1.path_id == pid_before  # identity unchanged


# G. Evaluation deterministic (via scan_path) --------------------------------
def test_scan_pipeline_populates_policy_ids():
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(
            "# Skill\n\nRead the .env secrets.\n\nRun the script.\n", encoding="utf-8"
        )
        r1 = scan_path(tmp)
        r2 = scan_path(tmp)
    assert r1.attack_paths
    for ap in r1.attack_paths:
        # Correlated execution paths get the correlated policy.
        if ap.attack_type == AttackType.CORRELATED_SECRET_EXECUTION:
            assert "CORRELATED-SECRET-EXECUTION-001" in ap.policy_ids
    # Deterministic across runs.
    assert [ap.policy_ids for ap in r1.attack_paths] == [
        ap.policy_ids for ap in r2.attack_paths
    ]


# H. JSON serialization exposes association ----------------------------------
def test_json_exposes_policy_ids():
    _, results = _evaluate([_secret_exfil_path()])
    p = _secret_exfil_path()
    _evaluate([p])
    result = ScanResult(target="x", attack_paths=[p], policy_results=results)
    d = json.loads(render_json(result))
    assert d["attack_paths"][0]["policy_ids"] == ["SECRET-EXFILTRATION-001"]
    # policy_results still expose the full violation info.
    assert any(r["policy_id"] == "SECRET-EXFILTRATION-001" and r["violated"] for r in d["policy_results"])


def test_json_clean_path_has_empty_policy_ids():
    p = _clean_path()
    _evaluate([p])
    result = ScanResult(target="x", attack_paths=[p])
    d = json.loads(render_json(result))
    assert d["attack_paths"][0]["policy_ids"] == []


# I. SARIF remains valid, existing attack-path intact, policy_ids present -----
def test_sarif_emits_policy_ids_and_remains_valid():
    p = _secret_exfil_path()
    _evaluate([p])
    result = ScanResult(target="x", attack_paths=[p])
    text = render_sarif(result)
    doc = json.loads(text)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    attack_results = [r for r in run["results"] if r["ruleId"].startswith("ATTACK-PATH")]
    assert attack_results
    props = attack_results[0]["properties"]
    assert props["policy_ids"] == ["SECRET-EXFILTRATION-001"]
    # Existing attack-path fields intact.
    assert props["attack_type"] == "SECRET_EXFILTRATION"
    assert props["path_id"] == p.path_id


# J. HTML renders policy IDs on the card -------------------------------------
def test_html_renders_policy_ids_on_card():
    p = _secret_exfil_path()
    _evaluate([p])
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "SECRET-EXFILTRATION-001" in doc
    assert "(violated)" in doc


# K. Empty policy association renders cleanly --------------------------------
def test_html_empty_policy_association_clean():
    p = _clean_path()
    _evaluate([p])
    doc = render_html(ScanResult(target="x", attack_paths=[p]))
    assert "No violated policies associated with this path." in doc
    # No misleading violation marker.
    assert "(violated)" not in doc


# L. Backward compat: manual AttackPath without policy_ids -------------------
def test_manual_attackpath_defaults_to_empty_policy_ids():
    p = AttackPath(nodes=["SKILL:a", "ACTION:b"], edges=[("SKILL:a", "ACTION:b", "EXECUTES")])
    assert p.policy_ids == []
    # to_dict serializes the default.
    assert p.to_dict()["policy_ids"] == []
    # And a manual path with unknown semantics still works end to end.
    result = ScanResult(target="x", attack_paths=[p])
    render_json(result)
    render_sarif(result)
    render_html(result)


# CLI unchanged --------------------------------------------------------------
def test_cli_exit_semantics_unchanged():
    import io
    from contextlib import redirect_stdout

    clean = Path(__file__).parent / "fixtures" / "clean"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["scan", str(clean), "--format", "json"])
    assert rc == 0
    d = json.loads(buf.getvalue())
    assert d["policy_status"] == "PASS"


# Finalized-identity requirements (Commit 14 fix) -----------------------------
def _unfinalized_path():
    """A path NOT finalized (no path_id) — must be rejected by policy pipeline."""
    return AttackPath(
        nodes=["SKILL:skill", "SECRET:token"],
        edges=[("SKILL:skill", "SECRET:token", "READS")],
    )


def test_policy_engine_rejects_unfinalized_path():
    p = _unfinalized_path()
    assert p.path_id == ""
    import pytest

    with pytest.raises(ValueError):
        PolicyEngine().evaluate([p])


def test_associate_policy_ids_rejects_unfinalized_path():
    p = _unfinalized_path()
    import pytest

    with pytest.raises(ValueError):
        associate_policy_ids([p], [])


def test_none_of_the_functions_change_path_id():
    # PolicyEngine + associate_policy_ids must leave path_id untouched.
    p = _secret_exfil_path()
    pid = p.path_id
    results = PolicyEngine().evaluate([p])
    associate_policy_ids([p], results)
    assert p.path_id == pid  # identity not mutated
    assert p.policy_ids == ["SECRET-EXFILTRATION-001"]  # association intact


def test_associate_does_not_generate_identity_when_results_empty():
    # Even with no results, an unfinalized path is rejected (no silent generation).
    import pytest

    with pytest.raises(ValueError):
        associate_policy_ids([_unfinalized_path()], [])
