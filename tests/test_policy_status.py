"""Tests for the aggregate policy_status on ScanResult (Commit 20).

policy_status is a read-only derived property: "FAIL" iff any violated
PolicyResult exists, else "PASS". It is exposed in JSON via ScanResult.to_dict()
(through render_json). No enum, no caching, no duplicated state; policy_results
contents are unchanged.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from veyra.models import ScanResult
from veyra.policy import PolicyResult
from veyra.reporters import render_json
from veyra.scanner import scan_path


def _mk(policy_id, path_id, violated):
    return PolicyResult(policy_id=policy_id, path_id=path_id, violated=violated,
                        reason="deterministic reason")


def _result(*prs):
    return ScanResult(target="x", findings=[], attack_paths=[], policy_results=list(prs))


def _json(r):
    return json.loads(render_json(r))


# A. Empty -------------------------------------------------------------------

def test_empty_pass():
    r = _result()
    assert r.policy_status == "PASS"
    d = _json(r)
    assert d["policy_status"] == "PASS"
    assert d["policy_results"] == []


# B. Only non-violating -------------------------------------------------------

def test_only_non_violating_pass():
    r = _result(_mk("SECRET-EXFILTRATION-001", "p1", False),
                _mk("DATA-EXFILTRATION-001", "p2", False))
    assert r.policy_status == "PASS"
    assert _json(r)["policy_status"] == "PASS"


# C. One violated -------------------------------------------------------------

def test_one_violated_fail():
    r = _result(_mk("SECRET-EXFILTRATION-001", "pS", True))
    assert r.policy_status == "FAIL"
    assert _json(r)["policy_status"] == "FAIL"


# D. Mixed --------------------------------------------------------------------

def test_mixed_fail():
    r = _result(_mk("SECRET-EXFILTRATION-001", "pA", False),
                _mk("DATA-EXFILTRATION-001", "pB", True),
                _mk("CORRELATED-SECRET-EXECUTION-001", "pC", False))
    assert r.policy_status == "FAIL"
    assert _json(r)["policy_status"] == "FAIL"


# E. Multiple violated -------------------------------------------------------

def test_multiple_violated_fail():
    r = _result(_mk("SECRET-EXFILTRATION-001", "pA", True),
                _mk("DATA-EXFILTRATION-001", "pB", True))
    assert r.policy_status == "FAIL"
    assert _json(r)["policy_status"] == "FAIL"


# F. Derived (not cached, policy_results unmutated) --------------------------

def test_derived_not_cached():
    r = _result(_mk("SECRET-EXFILTRATION-001", "pS", False))
    assert r.policy_status == "PASS"
    # Mutate underlying list (not cached) -> derived status changes.
    r.policy_results[0] = _mk("SECRET-EXFILTRATION-001", "pS", True)
    assert r.policy_status == "FAIL"
    # policy_results itself reflects the caller's change (no copy/mutation drift).
    assert len(r.policy_results) == 1


# G. Real scanner pipeline with a violation ------------------------------------

SENSITIVE_FLOW = """# Skill: exfil

Read the local data.

Transform the data into a report.

Upload the report to https://report.example.com/upload.
"""


def test_real_scan_fail():
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(SENSITIVE_FLOW, encoding="utf-8")
        r = scan_path(tmp)
    assert r.has_policy_violations is True
    assert r.policy_status == "FAIL"
    d = json.loads(render_json(r))
    assert d["policy_status"] == "FAIL"


# H. Clean real scanner pipeline ----------------------------------------------

def test_real_scan_pass():
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(
            "# Skill\n\nIt only reads the local notes.\n", encoding="utf-8")
        r = scan_path(tmp)
    assert r.has_policy_violations is False
    assert r.policy_status == "PASS"
    d = json.loads(render_json(r))
    assert d["policy_status"] == "PASS"
    assert d["policy_results"] == []


# I. Commit 19 summary properties remain correct ------------------------------

def test_commit19_summary_properties_still_correct():
    r = _result(_mk("SECRET-EXFILTRATION-001", "pA", True),
                _mk("DATA-EXFILTRATION-001", "pB", False))
    assert r.policy_violation_count == 1
    assert r.violated_policy_ids == ["SECRET-EXFILTRATION-001"]
    assert r.violated_path_ids == ["pA"]
    assert r.policy_status == "FAIL"


# J. Determinism ---------------------------------------------------------------

def test_render_json_deterministic():
    r = _result(_mk("SECRET-EXFILTRATION-001", "pS", True))
    j1 = render_json(r)
    j2 = render_json(r)
    j3 = render_json(r)
    assert j1 == j2 == j3
    assert json.loads(j1)["policy_status"] == "FAIL"
