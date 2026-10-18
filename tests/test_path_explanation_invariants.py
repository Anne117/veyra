"""E-1: invariant tests locking down that AttackPath reports never lie.

After ``PathAnalyzer.analyze()`` (the only blessed entry point), every returned
``AttackPath`` must satisfy four truthfulness invariants. These invariants are
meant to be guard-rails that fail loudly the moment any other change (rule,
reporter, classification tweak, evidence wording) introduces an
unsupported claim. They exercise both fully synthetic graphs and the real
attack-lab corpus.

The four invariants:

(a) ``evidence`` is non-empty and every evidence entry names a node or edge
    that actually exists on this path.

(b) ``provenance`` is consistent with ``nodes`` / ``edges`` /
    ``associated_edges``: every path node has a provenance entry (possibly
    unknown), every walk edge has a parallel provenance entry, and every
    associated edge has a parallel one.

(c) ``breakpoints`` reference only existing semantic graph edges. For an
    exfiltration path each breakpoint is one of the contiguous walk's edges;
    for a correlated secret-execution path a breakpoint may be a REAL
    shared-skill ``READS`` associated edge. No breakpoint may be invented
    out of thin air (e.g. a fake ``SECRET -> ACTION`` flow edge).

(d) ``explanation`` / ``explanation_details.summary`` make only claims that
    are backed by the proven attack semantics. In particular, a
    ``DATA_EXFILTRATION`` summary never contains the word "secret" and the
    per-attack-type summary strings come from the existing controlled
    vocabulary (``_EXPLANATION_SUMMARIES``).

A regression on any of the four is a truthfulness violation and breaks CI.
"""

from __future__ import annotations

from pathlib import Path

from veyra.attack_lab import ATTACK_CASES
from veyra.graph import (
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
)
from veyra.graph.path import (
    AttackPath,
    AttackType,
    _EXPLANATION_SUMMARIES,
)


# --- helpers ----------------------------------------------------------------

def _secret_exfil_graph() -> SecurityGraph:
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


def _data_exfil_graph() -> SecurityGraph:
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


def _correlation_graph() -> SecurityGraph:
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


def _handoff_graph() -> SecurityGraph:
    g = SecurityGraph()
    for n in (
        Node(id="SKILL:a", type=NodeType.SKILL),
        Node(id="SKILL:b", type=NodeType.SKILL),
    ):
        g.add_node(n)
    g.add_edge("SKILL:a", "SKILL:b", EdgeType.HANDOFF)
    return g


def _walk_edge_keys(edges):
    """Return the {(s, t, type)} keys for an edge list."""
    return {(s, t, et) for s, t, et in edges}


def _check_invariants(name: str, ap: AttackPath, sink: list) -> None:
    """Single source of truth for the four E-1 invariants.

    Appends a (reason, ...) tuple to ``sink`` for any violation found.
    """
    d = ap.to_dict()
    atype = ap.attack_type.value
    nodes = ap.nodes
    edges = ap.edges
    assoc = ap.associated_edges
    ev = list(d.get("evidence") or [])
    bp = d.get("breakpoints") or []
    prov = d.get("provenance") or {}
    details = d.get("explanation_details") or {}

    # (a) evidence: non-empty for classified paths; entries are node/edge ids
    if atype != "UNKNOWN" and not ev:
        sink.append((name, "evidence_empty", atype))
    walk_set = _walk_edge_keys(edges) | _walk_edge_keys(assoc)
    node_set = set(nodes)
    for e in ev:
        # Allowed forms: plain label ("secret read"), or an edge triple
        # ("SKILL:s --READS--> SECRET:tok"), or an asset node id. We only
        # require that the label not mention an UNRELATED edge triple;
        # anything else is freeform text from the controlled vocabulary.
        if " --" in e and " --> " in e:
            head, rest = e.split(" --", 1)
            et, tail = rest.split(" --> ", 1)
            triple = (head, tail, et)
            if triple not in walk_set:
                sink.append((name, "evidence_edge_not_on_path", triple, ev))

    # (b) provenance: every node has entry, edges parallel in length
    pnodes = set((prov.get("nodes") or {}).keys())
    for n in nodes:
        if n not in pnodes:
            sink.append((name, "prov_missing_node", n))
    if len(prov.get("edges") or []) != len(edges):
        sink.append((name, "prov_edge_mismatch",
                     len(prov.get("edges") or []), len(edges)))
    if len(prov.get("associated_edges") or []) != len(assoc):
        sink.append((name, "prov_assoc_mismatch",
                     len(prov.get("associated_edges") or []), len(assoc)))

    # (c) breakpoints lie on the walk (or on assoc for correlation)
    walk_keys = _walk_edge_keys(edges)
    assoc_keys = _walk_edge_keys(assoc)
    for b in bp:
        key = (b["source_node"], b["target_node"], b["edge_type"])
        if key not in walk_keys and key not in assoc_keys:
            sink.append((name, "breakpoint_off_path", key, atype))
        if b["edge_type"] not in {"READS", "FLOWS_TO", "SENDS_TO", "EXECUTES"}:
            sink.append((name, "breakpoint_unknown_edge_type", b["edge_type"]))

    # (d) explanation summary uses only controlled vocabulary, never mentions
    # SECRET for a DATA path
    summary = (details.get("summary") or "").strip()
    allowed = set(_EXPLANATION_SUMMARIES.values()) | {
        "The path contains correlated graph activity without a classified attack type."
    }
    if summary and summary not in allowed:
        sink.append((name, "summary_not_in_vocabulary", summary))
    if atype == "DATA_EXFILTRATION" and "secret" in summary.lower():
        sink.append((name, "summary_mentions_secret_for_data", summary))
    # Steps count equals walk-edge count
    steps = details.get("steps") or []
    if len(steps) != len(edges):
        sink.append((name, "steps_count_mismatch", len(steps), len(edges)))
    # Each step points at a real walk edge
    for step in steps:
        if " --" in step and " --> " in step:
            head, rest = step.split(" --", 1)
            et, tail = rest.split(" --> ", 1)
            if (head, tail, et) not in walk_keys:
                sink.append((name, "step_off_walk", step, atype))


# --- synthetic-path invariants ---------------------------------------------

def test_synthetic_secret_exfil_satisfies_all_invariants():
    ap = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    sink = []
    _check_invariants("synth:secret_exfil", ap, sink)
    assert sink == [], f"violations: {sink}"


def test_synthetic_data_exfil_satisfies_all_invariants():
    ap = PathAnalyzer(_data_exfil_graph()).analyze()[0]
    sink = []
    _check_invariants("synth:data_exfil", ap, sink)
    assert sink == [], f"violations: {sink}"


def test_synthetic_correlation_satisfies_all_invariants():
    ap = PathAnalyzer(_correlation_graph()).analyze()[0]
    sink = []
    _check_invariants("synth:correlation", ap, sink)
    assert sink == [], f"violations: {sink}"


def test_synthetic_handoff_satisfies_all_invariants():
    """A HANDOFF-only path is not classified; UNKNOWN expects empty evidence
    and no breakpoints. The walk still produces a path object."""
    paths = PathAnalyzer(_handoff_graph()).analyze()
    assert paths, "handoff graph should produce at least one path"
    sink = []
    for ap in paths:
        _check_invariants("synth:handoff", ap, sink)
    assert sink == [], f"violations: {sink}"


# --- real corpus invariants -------------------------------------------------

def _real_corpus_paths():
    """Scan every ATTACK_CASES fixture and collect any AttackPath found."""
    root = Path(__file__).resolve().parent / "fixtures" / "attacks"
    out = []
    for case in ATTACK_CASES:
        p = root / case.path
        if not p.exists():
            continue
        from veyra.scanner import scan_path
        result = scan_path(str(p))
        for ap in result.attack_paths:
            out.append((case.path, ap))
    return out


def test_real_corpus_every_path_satisfies_all_invariants():
    paths = _real_corpus_paths()
    sink = []
    for name, ap in paths:
        _check_invariants(name, ap, sink)
    assert sink == [], f"violations: {sink}"


def test_real_corpus_at_least_three_paths_lock_the_baseline():
    """If the lab shrinks below the current 3 attack-paths we want CI to flag
    it loudly; the E-1 invariants are only meaningful when real semantics
    flow through the pipeline."""
    paths = _real_corpus_paths()
    assert len(paths) >= 3, f"expected >=3 attack paths in corpus, got {len(paths)}"


# --- explicit hard-coded anti-regression tests -----------------------------

def test_attackpath_explanations_use_only_controlled_vocabulary():
    """The deterministic AttackType->summary map is the source of truth; any
    fresh summary string is a truthfulness regression in waiting."""
    allowed = {
        "A secret is read and reaches an external endpoint.",
        "Data is read and reaches an external endpoint.",
        "Secret access is associated with execution in the same skill and requires review.",
    }
    assert set(_EXPLANATION_SUMMARIES.values()) == allowed


def test_classified_path_evidence_never_empty():
    """A regression check on the explicit attractor: if classification sets a
    real type (not UNKNOWN), the path's evidence must list at least one
    ground-truth signal. Correlated secret execution lists exactly the two
    correlation signals; exfiltration lists the asset-read + endpoint-send."""
    se = PathAnalyzer(_secret_exfil_graph()).analyze()[0]
    assert se.attack_type == AttackType.SECRET_EXFILTRATION
    assert se.evidence and "secret read" in se.evidence
    assert "external network send" in se.evidence

    de = PathAnalyzer(_data_exfil_graph()).analyze()[0]
    assert de.attack_type == AttackType.DATA_EXFILTRATION
    assert de.evidence and "sensitive data read" in de.evidence
    assert "external network send" in de.evidence

    cor = PathAnalyzer(_correlation_graph()).analyze()[0]
    assert cor.attack_type == AttackType.CORRELATED_SECRET_EXECUTION
    assert cor.evidence == ["secret read", "execution"]


def test_breakpoints_for_correlation_use_real_assoc_edges_only():
    """An explicit anti-fabrication test: the correlation path has NO
    SECRET->ACTION flow edge, so its breakpoints must use only the actual
    EXECUTES walk edge and the READS associated edge. Both must be present
    in either the walk or associated_edges."""
    ap = PathAnalyzer(_correlation_graph()).analyze()[0]
    assert ap.attack_type == AttackType.CORRELATED_SECRET_EXECUTION
    walk_keys = _walk_edge_keys(ap.edges)
    assoc_keys = _walk_edge_keys(ap.associated_edges)
    real_edges = walk_keys | assoc_keys
    keys = {(b.source_node, b.target_node, b.edge_type) for b in ap.breakpoints}
    assert keys, "expected at least one breakpoint"
    for k in keys:
        assert k in real_edges, f"breakpoint references absent edge: {k}"
    # Specifically: must NOT invent a SECRET -> ACTION edge
    secret_nodes = [n for n in ap.nodes if n.startswith("SECRET:")]
    action_nodes = [n for n in ap.nodes if n.startswith("ACTION:")]
    for b in ap.breakpoints:
        assert not (b.source_node in secret_nodes and b.target_node in action_nodes), (
            "fabricated SECRET -> ACTION flow edge"
        )


def test_unknown_path_has_no_unsupported_evidence_or_breakpoints():
    """Unknown / handoff path: no evidence list whatsoever, no breakpoints.
    This is the negative attractor for invariant (a)(c)(d)."""
    paths = PathAnalyzer(_handoff_graph()).analyze()
    for ap in paths:
        assert ap.attack_type == AttackType.UNKNOWN, "handoff alone is UNKNOWN"
        assert ap.evidence == [], f"UNKNOWN must have no evidence: {ap.evidence}"
        assert ap.breakpoints == [], f"UNKNOWN must have no breakpoints: {ap.breakpoints}"
        details = ap.explanation_details
        assert details is not None
        assert details.summary == (
            "The path contains correlated graph activity without a classified attack type."
        )
