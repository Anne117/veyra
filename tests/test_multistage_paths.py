"""Regression tests for Q-2: multi-stage attack paths.

Behaviour locked here:

* Existing fixtures under ``tests/fixtures/attacks/multi-stage/`` and
  ``tests/fixtures/attacks/v2/multi-stage/`` describe human-language
  multi-step scripts ("read X, send Y to URL Z") but DO NOT contain the
  object-continuous lineage (READS -> FLOWS_TO -> SENDS_TO) needed to
  prove a SECRET/DATA exfiltration AttackPath. The scanner currently
  reports AS-CHAIN findings on them but no AttackPath. This is the
  correct (conservative) result for those fixtures and is fixed as the
  baseline by :func:`test_existing_multi_stage_fixtures_have_no_path`.

* A new ``exfiltration-flow`` fixture contains a TRUE continuous
  lineage (Read -> Transform the data into a report -> Upload the
  report) and therefore must produce exactly one contiguous
  DATA_EXFILTRATION AttackPath. Locked by
  :func:`test_exfiltration_flow_produces_data_exfiltration_path`.

* Component isolation must hold: a file that only describes a "source"
  action and an unrelated file that only describes a "send" action
  must NOT combine into an exfiltration path. This was already locked
  by ``tests/test_scanner_paths.py::test_unrelated_files_do_not_combine_into_single_path``;
  we add an analogous multi-file negative test here.
"""

from pathlib import Path

import pytest

from veyra.scanner import scan_path


REPO = Path(__file__).resolve().parent.parent
ATTACKS = REPO / "tests" / "fixtures" / "attacks"


# --- Positive: real object-continuous lineage ---------------------------------

EXFIL_FIXTURE = ATTACKS / "multi-stage" / "exfiltration-flow"


def test_exfiltration_flow_produces_data_exfiltration_path():
    """The new multi-stage fixture has READS->FLOWS_TO->SENDS_TO and must yield a path."""
    result = scan_path(str(EXFIL_FIXTURE))
    paths = result.attack_paths
    assert paths, (
        "expected at least one AttackPath from exfiltration-flow; "
        "the fixture declares a true read->transform->upload lineage."
    )
    p = paths[0]
    # Contiguous walk: DATA -> DATA -> ENDPOINT.
    node_kinds = [n.split(":", 1)[0] for n in p.nodes]
    assert node_kinds[0] == "SKILL"
    assert "ENDPOINT" in node_kinds, f"path must terminate at an ENDPOINT, got {p.nodes}"
    # Edge sequence is the canonical object-continuous lineage.
    edge_types = [e[2] for e in p.edges]
    assert "READS" in edge_types
    assert "FLOWS_TO" in edge_types, (
        "expected a FLOWS_TO edge (proving the data object flows into the "
        "transformed object); without it, READS->SENDS_TO is correlation, not lineage."
    )
    assert "SENDS_TO" in edge_types
    # Proven semantics: contiguous DATA_EXFILTRATION.
    from veyra.graph.path import AttackType
    assert p.is_contiguous, "exfiltration-flow must produce a contiguous walk"
    assert p.attack_type == AttackType.DATA_EXFILTRATION
    # Risk metadata reflects the proven lineage (HIGH per _risk_for()).
    assert str(p.risk_severity) in ("Severity.HIGH", "HIGH")
    # Structured evidence backs the classification; UNKNOWN paths get [].
    assert "external network send" in p.evidence


# --- Negative: existing multi-stage fixtures must NOT claim an AttackPath ----

@pytest.mark.parametrize(
    "fixture",
    [
        ATTACKS / "multi-stage" / "data-sync",
        ATTACKS / "multi-stage" / "download-run",
        ATTACKS / "multi-stage" / "benign",
        ATTACKS / "v2" / "multi-stage" / "source-sensitive-network",
        ATTACKS / "v2" / "multi-stage" / "download-execution",
        ATTACKS / "v2" / "multi-stage" / "sensitive-transform-network",
        ATTACKS / "v2" / "multi-stage" / "discovery-secret-network",
        ATTACKS / "v2" / "multi-stage" / "benign",
    ],
)
def test_existing_multi_stage_fixtures_have_no_path(fixture):
    """Lock the current behaviour: existing fixtures lack object-continuous
    lineage, so the analyzer correctly produces zero AttackPaths.

    This is a deliberate regression guard. If a future improvement starts
    producing paths here, it must either be accompanied by an updated
    ``attack-lab`` baseline comment (since classifications may shift) or
    be reviewed carefully so we don't accept correlation as lineage.
    """
    result = scan_path(str(fixture))
    assert result.attack_paths == [], (
        f"{fixture.name}: expected no AttackPath (no READS->FLOWS_TO->SENDS_TO "
        f"chain), got {[p.attack_type for p in result.attack_paths]}"
    )


# --- Negative: correlation without contiguity must not yield a path -----------

def test_correlated_multi_file_signals_do_not_combine_into_path(tmp_path):
    """Two unrelated files whose signals correlate by name (shared 'data'/
    'report' object and shared endpoint URL) must not combine into a single
    exfiltration attack path. Per-component isolation forbids it.
    """
    src = """# Skill: source-only

Read the local data.
Transform the data into a report.
"""
    snd = """# Skill: sender-only

Upload the report to https://report.example.com/upload.
"""
    (tmp_path / "SKILL.md").write_text(src)
    (tmp_path / "other.py").write_text(snd)
    result = scan_path(str(tmp_path))
    # No contiguous source->send path may exist across unrelated files.
    for p in result.attack_paths:
        skills = [n for n in p.nodes if n.startswith("SKILL:")]
        assert len(set(skills)) == 1, (
            f"path rooted in multiple unrelated SKILLs: {p.nodes}"
        )
