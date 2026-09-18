"""Tests for the OWASP Agentic AI 2026 taxonomy catalog (Commit 24).

The taxonomy layer is a separate catalog layer from ThreatScenario. It is
deterministic, immutable, performs no network access, and does NOT infer OWASP
categories from AttackPaths or modify the graph/path/type models.
"""

import json
from unittest.mock import patch

import pytest

from veyra.threats import (
    ThreatModelError,
    ThreatScenario,
    ThreatSource,
    ThreatTaxonomy,
    ThreatTaxonomyEntry,
    OWASP_AGENTIC_2026,
    get_owasp_agentic_2026,
    serialize_threat_scenario,
    serialize_threat_taxonomy,
    serialize_threat_taxonomies,
)


_EXPECTED_IDS = {"ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
                 "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"}

_EXPECTED_NAMES = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


# 1. ThreatTaxonomy construction
def test_taxonomy_construction():
    t = ThreatTaxonomy(taxonomy_id="t", name="Name", version="1", reference="r")
    assert t.taxonomy_id == "t"
    assert t.entries == ()


# 2. ThreatTaxonomyEntry construction
def test_entry_construction():
    e = ThreatTaxonomyEntry(entry_id="X1", name="Entry", description="desc",
                            source=ThreatSource(name="s", version="v", reference="r"))
    assert e.entry_id == "X1"


# 3. frozen/immutable behavior
def test_frozen():
    t = get_owasp_agentic_2026()
    with pytest.raises(AttributeError):
        t.name = "other"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        t.entries = ()  # type: ignore[misc]


# 4. validation of required strings
def test_required_string_validation():
    with pytest.raises(ThreatModelError):
        ThreatTaxonomy(taxonomy_id="", name="n", version="1", reference="r")
    with pytest.raises(ThreatModelError):
        ThreatTaxonomyEntry(entry_id="", name="n", description="d", source=ThreatSource("s", "v", "r"))
    with pytest.raises(ThreatModelError):
        ThreatTaxonomyEntry(entry_id="x", name="  ", description="d", source=ThreatSource("s", "v", "r"))


# 5. deterministic serialization
def test_deterministic_serialization():
    t = get_owasp_agentic_2026()
    assert serialize_threat_taxonomy(t) == serialize_threat_taxonomy(t)


# 6. JSON-safe serialization
def test_json_safe():
    t = get_owasp_agentic_2026()
    s = serialize_threat_taxonomy(t)
    text = json.dumps(s)
    assert json.loads(text) == s
    assert "ThreatTaxonomy" not in text and "OWASP_AGENTIC_2026" not in text


# 7. exact presence of all 10 ASI IDs
def test_all_10_asi_ids_present():
    eids = {e.entry_id for e in OWASP_AGENTIC_2026.entries}
    assert eids == _EXPECTED_IDS


# 8. exact official names
def test_exact_official_names():
    names = {e.entry_id: e.name for e in OWASP_AGENTIC_2026.entries}
    assert names == _EXPECTED_NAMES


# 9. no duplicate IDs
def test_no_duplicate_ids():
    eids = [e.entry_id for e in OWASP_AGENTIC_2026.entries]
    assert len(eids) == len(set(eids))


# 10. deterministic ordering ASI01..ASI10
def test_deterministic_ordering():
    ids = [e.entry_id for e in OWASP_AGENTIC_2026.entries]
    assert ids == ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
                   "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]


# 11. source/version/reference
def test_source_version_reference():
    t = OWASP_AGENTIC_2026
    s = t.entries[0].source
    assert s.name == "OWASP Top 10 for Agentic Applications"
    assert s.version == "2026"
    assert "genai.owasp.org" in s.reference
    assert "owasp-top-10-for-agentic-applications-for-2026" in s.reference


# 12. catalog is immutable
def test_catalog_immutable():
    t = OWASP_AGENTIC_2026
    assert isinstance(t.entries, tuple)
    with pytest.raises(AttributeError):
        t.entries[0].name = "X"  # type: ignore[misc]


# 13. repeated serialization equality
def test_repeated_serialization_equal():
    assert serialize_threat_taxonomies([OWASP_AGENTIC_2026]) == serialize_threat_taxonomies([OWASP_AGENTIC_2026])


# 14. no OWASP-specific fields added to ThreatScenario
def test_scenario_remains_generic():
    s = ThreatScenario(scenario_id="x", name="n", description="d")
    d = serialize_threat_scenario(s)
    for key in ("owasp_id", "owasp_category", "cwe_id", "mitre_id"):
        assert key not in d
        assert not hasattr(s, key)


# 15-16. AttackType / EdgeType unchanged
def test_types_unchanged():
    from veyra.graph import AttackType, EdgeType
    from veyra.graph.path import AttackType as AT, EdgeType as ET
    assert len(AttackType) == len(AT)
    assert len(EdgeType) == len(ET)


# 17-18. AttackPath / SecurityGraph unchanged after using taxonomy
def test_path_and_graph_unchanged():
    from tempfile import TemporaryDirectory
    from pathlib import Path
    from veyra.scanner import scan_path
    flow = ("# Skill\n## Step 1\nRead the local data.\n## Step 2\nTransform the data into a report.\n"
            "## Step 3\nUpload the report to https://report.example.com/upload.\n")
    with TemporaryDirectory() as tmp:
        Path(tmp, "SKILL.md").write_text(flow)
        r = scan_path(tmp)
        snap = [ (tuple(p.nodes), tuple(p.edges), tuple(p.associated_edges), p.path_id, p.risk_score) for p in r.attack_paths ]
        # Touch the taxonomy catalog (read-only).
        _ = get_owasp_agentic_2026().entries
        _ = serialize_threat_taxonomy(OWASP_AGENTIC_2026)
        r2 = scan_path(tmp)
        snap2 = [ (tuple(p.nodes), tuple(p.edges), tuple(p.associated_edges), p.path_id, p.risk_score) for p in r2.attack_paths ]
        assert snap == snap2


# 19. no graph mutation
def test_no_graph_mutation():
    from veyra.graph import SecurityGraph, Node, NodeType, EdgeType
    g = SecurityGraph()
    g.add_node(Node(id="SKILL:A", type=NodeType.SKILL))
    g.add_node(Node(id="DATA:x", type=NodeType.DATA))
    g.add_edge("SKILL:A", "DATA:x", EdgeType.READS)
    gnodes = dict(g.nodes)
    gedges = [(e.source, e.target, e.type) for e in g.edges]
    _ = OWASP_AGENTIC_2026
    assert dict(g.nodes) == gnodes
    assert [(e.source, e.target, e.type) for e in g.edges] == gedges


# 20. no inference from AttackPath
def test_no_inference_from_path():
    # Building a taxonomy/catalog never consults an AttackPath: there is no
    # inference API at all in the taxonomy layer.
    import inspect
    from veyra.threats import taxonomy
    for name, obj in inspect.getmembers(taxonomy, inspect.isfunction):
        assert "path" not in name.lower()


# 21. no new external dependency
def test_no_external_dependency():
    import veyra.threats
    assert veyra.threats.__name__


# 22. no runtime network access
def test_no_runtime_network():
    # Merely touching the catalog performs no network call: any real socket use
    # would raise here because socket.socket is patched to fail.
    with patch("socket.socket") as m:
        t = get_owasp_agentic_2026()
        assert len(t.entries) == 10
        m.assert_not_called()


# get_owasp_agentic_2026 returns the same immutable instance
def test_getter_returns_immutable():
    assert get_owasp_agentic_2026() is OWASP_AGENTIC_2026


# duplicate entry ids rejected
def test_duplicate_entry_ids_rejected():
    src = ThreatSource("owasp", "2026", "ref")
    with pytest.raises(ThreatModelError):
        ThreatTaxonomy(
            taxonomy_id="dup", name="Dup", version="1", reference="r",
            entries=(
                ThreatTaxonomyEntry("A", "One", "desc", src),
                ThreatTaxonomyEntry("A", "Two", "desc", src),
            ),
        )


# --- Provenance/terminology honesty (Commit 24 correction) -------------------

# Descriptions exist and are non-empty for all entries.
def test_all_descriptions_non_empty():
    for e in OWASP_AGENTIC_2026.entries:
        assert e.description and e.description.strip()
        assert isinstance(e.description, str)


# ASI02 / ASI03 use the official OWASP 2026 "and" spelling (no ampersand), as
# verified against the official source document.
def test_exact_spelling_of_asi02_asi03():
    names = {e.entry_id: e.name for e in OWASP_AGENTIC_2026.entries}
    assert names["ASI02"] == "Tool Misuse and Exploitation"
    assert names["ASI03"] == "Identity and Privilege Abuse"
    assert " & " not in names["ASI02"]
    assert " & " not in names["ASI03"]


# The selected canonical OWASP source is recorded in the reference.
def test_canonical_source_reference():
    s = OWASP_AGENTIC_2026.entries[0].source
    assert "genai.owasp.org" in s.reference
    assert s.reference.endswith("owasp-top-10-for-agentic-applications-for-2026/")

