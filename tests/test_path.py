"""Tests for the deterministic Attack Path Analyzer (truthful semantics)."""

from veyra.graph import (
    Edge,
    EdgeType,
    Node,
    NodeType,
    PathAnalyzer,
    SecurityGraph,
    build_from_actions,
    canonical_path_identity,
    path_id_of,
)
from veyra.models import Confidence, Severity
from veyra.step_sequence import Action


def _paths(graph):
    return PathAnalyzer(graph).analyze()


def _mk_nodes(**kw):
    """Create typed nodes. Keyword -> Node(id=<TYPE>:<name>, type=<TYPE>).

    Callers pass e.g. skill=NodeType.SKILL, origin=NodeType.SECRET,
    derived=NodeType.DATA, ep=NodeType.ENDPOINT. Returned dict is keyed by the
    keyword with node ids of the form TYPE:name where name is the keyword.
    """
    nodes = {}
    for name, ttype in kw.items():
        nid = f"{ttype.value}:{name}"
        nodes[name] = Node(id=nid, type=ttype, label=name)
    return nodes


def _exposure_graph(origin_kind, with_flow=True, sink_edge_type=EdgeType.SENDS_TO):
    """Skill reads an origin; optionally origin FLOWS_TO a derived object that is
    the one sent (via sink_edge_type) to an endpoint."""
    g = SecurityGraph()
    nodes = _mk_nodes(
        skill=NodeType.SKILL,
        origin=(NodeType.SECRET if origin_kind == "secret" else NodeType.DATA),
        derived=NodeType.DATA,
        ep=NodeType.ENDPOINT,
    )
    for n in nodes.values():
        g.add_node(n)
    g.add_edge("SKILL:skill", nodes["origin"].id, EdgeType.READS)
    if with_flow:
        g.add_edge(nodes["origin"].id, nodes["derived"].id, EdgeType.FLOWS_TO)
        g.add_edge(nodes["derived"].id, nodes["ep"].id, sink_edge_type)
    else:
        g.add_edge(nodes["origin"].id, nodes["ep"].id, sink_edge_type)
    return g


def test_every_edge_is_contiguous():
    """Every AttackPath satisfies nodes[i] --edges[i]--> nodes[i+1]."""
    g = SecurityGraph()
    n = _mk_nodes(skill=NodeType.SKILL, origin=NodeType.SECRET,
                  derived=NodeType.DATA, ep=NodeType.ENDPOINT)
    for x in n.values():
        g.add_node(x)
    g.add_edge(n["skill"].id, n["origin"].id, EdgeType.READS)
    g.add_edge(n["origin"].id, n["derived"].id, EdgeType.FLOWS_TO)
    g.add_edge(n["derived"].id, n["ep"].id, EdgeType.SENDS_TO)
    for p in _paths(g):
        assert p.is_contiguous, f"non-contiguous path: {p.nodes} / {p.edges}"


def test_reads_plus_send_without_object_flow_is_no_exfiltration_path():
    """Skill READS Secret + Skill SENDS_TO Endpoint (no object edge) => ZERO exposure paths."""
    g = SecurityGraph()
    n = _mk_nodes(skill=NodeType.SKILL, origin=NodeType.SECRET, ep=NodeType.ENDPOINT)
    for x in n.values():
        g.add_node(x)
    g.add_edge(n["skill"].id, n["origin"].id, EdgeType.READS)
    g.add_edge(n["skill"].id, n["ep"].id, EdgeType.SENDS_TO)  # skill-level send, not object
    paths = _paths(g)
    # No exposure/exfiltration path may be emitted.
    assert not any(p.title != "Secret access followed by command execution" for p in paths)


def test_secret_flows_to_data_then_endpoint():
    """Secret --FLOWS_TO--> Data --SENDS_TO--> Endpoint => valid contiguous exposure path."""
    g = SecurityGraph()
    n = _mk_nodes(skill=NodeType.SKILL, origin=NodeType.SECRET,
                  derived=NodeType.DATA, ep=NodeType.ENDPOINT)
    for x in n.values():
        g.add_node(x)
    g.add_edge(n["skill"].id, n["origin"].id, EdgeType.READS)
    g.add_edge(n["origin"].id, n["derived"].id, EdgeType.FLOWS_TO)
    g.add_edge(n["derived"].id, n["ep"].id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    assert p.title == "Secret exposed to external endpoint"
    assert p.nodes[-1] == n["ep"].id
    assert p.is_contiguous


def test_data_to_derived_to_endpoint():
    """Data --FLOWS_TO--> DerivedData --SENDS_TO--> Endpoint => valid sensitive-data path."""
    g = SecurityGraph()
    n = _mk_nodes(skill=NodeType.SKILL, origin=NodeType.DATA,
                  derived=NodeType.DATA, ep=NodeType.ENDPOINT)
    for x in n.values():
        g.add_node(x)
    g.add_edge(n["skill"].id, n["origin"].id, EdgeType.READS)
    g.add_edge(n["origin"].id, n["derived"].id, EdgeType.FLOWS_TO)
    g.add_edge(n["derived"].id, n["ep"].id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    assert "sensitive data" in p.title.lower()
    assert n["derived"].id in p.nodes
    assert p.is_contiguous


def test_uses_endpoint_not_an_exfiltration_sink():
    """USES Endpoint must NOT produce an exfiltration path."""
    g = _exposure_graph("secret", with_flow=True, sink_edge_type=EdgeType.USES)
    paths = _paths(g)
    # USES is not a send sink, so no exposure/exfiltration path may be emitted.
    assert not any("exposed" in p.title.lower() or "exfiltration" in p.title.lower() for p in paths)


def test_produces_is_not_flows_to():
    """PRODUCES (skill manufactures an object) must NOT be traversed as data-flow."""
    g = SecurityGraph()
    n = _mk_nodes(skill=NodeType.SKILL, origin=NodeType.DATA,
                  derived=NodeType.DATA, ep=NodeType.ENDPOINT)
    for x in n.values():
        g.add_node(x)
    g.add_edge("SKILL:skill", n["origin"].id, EdgeType.READS)
    g.add_edge("SKILL:skill", n["derived"].id, EdgeType.PRODUCES)  # not FLOWS_TO
    g.add_edge(n["derived"].id, n["ep"].id, EdgeType.SENDS_TO)
    paths = _paths(g)
    # No FLOWS_TO edge from origin, so no data lineage connects origin to derived.
    assert all(p.title != "Sensitive data sent to external endpoint" for p in paths)


def test_cyclic_graph_terminates():
    """A FLOWS_TO cycle must terminate safely (cycle guard, ordered nodes)."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    d1 = Node(id="DATA:a", type=NodeType.DATA, label="a")
    d2 = Node(id="DATA:b", type=NodeType.DATA, label="b")
    ep = Node(id="ENDPOINT:https://x.com", type=NodeType.ENDPOINT, label="x")
    for n in (s, d1, d2, ep):
        g.add_node(n)
    g.add_edge(s.id, d1.id, EdgeType.READS)
    g.add_edge(d1.id, d2.id, EdgeType.FLOWS_TO)
    g.add_edge(d2.id, d1.id, EdgeType.FLOWS_TO)  # cycle
    g.add_edge(d1.id, ep.id, EdgeType.SENDS_TO)
    g.add_edge(d2.id, ep.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    for p in paths:
        assert p.is_contiguous
    assert len(paths) >= 1  # terminates, no infinite recursion


def test_path_length_bounded():
    """A long data-flow chain is bounded to MAX_PATH_EDGES + endpoint."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    a = Node(id="DATA:a0", type=NodeType.DATA, label="a0")
    ep = Node(id="ENDPOINT:https://x.com", type=NodeType.ENDPOINT, label="x")
    for n in (s, a, ep):
        g.add_node(n)
    g.add_edge(s.id, a.id, EdgeType.READS)
    prev = "DATA:a0"
    for i in range(1, 15):
        n = Node(id=f"DATA:a{i}", type=NodeType.DATA, label=f"a{i}")
        g.add_node(n)
        g.add_edge(prev, n.id, EdgeType.FLOWS_TO)
        prev = n.id
    # Only a reachable node (within the DFS bound) sends to the endpoint.
    g.add_edge("DATA:a9", ep.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert paths
    for p in paths:
        assert p.is_contiguous
        # bounded: skill + origin + (≤ MAX_PATH_EDGES data nodes) + endpoint + sink edge
        assert len(p.edges) <= 10 + 2


def test_multiple_valid_paths_found():
    """Two distinct endpoints from the same secret => two exposure paths."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    epA = Node(id="ENDPOINT:https://a.com", type=NodeType.ENDPOINT, label="a")
    epB = Node(id="ENDPOINT:https://b.com", type=NodeType.ENDPOINT, label="b")
    for n in (s, sec, epA, epB):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, epA.id, EdgeType.SENDS_TO)
    g.add_edge(sec.id, epB.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 2
    assert {p.nodes[-1] for p in paths} == {epA.id, epB.id}
    for p in paths:
        assert p.is_contiguous


def test_deterministic_ordering_stable():
    """Same graph analyzed twice yields identical, ordered results."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    d = Node(id="DATA:payload", type=NodeType.DATA, label="payload")
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT, label="evil")
    for n in (s, sec, d, ep):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, d.id, EdgeType.FLOWS_TO)
    g.add_edge(d.id, ep.id, EdgeType.SENDS_TO)
    p1 = [x.to_dict() for x in _paths(g)]
    p2 = [x.to_dict() for x in _paths(g)]
    assert p1 == p2


def test_secret_plus_execution_contiguous():
    """Secret + execution is a shared-skill correlation, truthfully represented."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    act = Node(id="ACTION:run", type=NodeType.ACTION, label="run")
    for n in (s, sec, act):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(s.id, act.id, EdgeType.EXECUTES)
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    assert p.title == "Secret access followed by command execution"
    # The walk is Skill -> Action (contiguous); Secret is associated, NOT a
    # fabricated Secret -> Action edge.
    assert p.nodes == [s.id, act.id]
    assert p.is_contiguous
    assert (s.id, sec.id, "READS") in p.associated_edges


def test_no_rule_ids_required():
    """Paths are found purely from graph semantics; no AS-* rule IDs needed."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    d = Node(id="DATA:payload", type=NodeType.DATA, label="payload")
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT, label="evil")
    for n in (s, sec, d, ep):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, d.id, EdgeType.FLOWS_TO)
    g.add_edge(d.id, ep.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 1
    assert "AS-" not in paths[0].title


def test_benign_graph_no_paths():
    """A graph with reads but no external sink produces zero exfiltration paths."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    d = Node(id="DATA:config", type=NodeType.DATA, label="config")
    for n in (s, d):
        g.add_node(n)
    g.add_edge(s.id, d.id, EdgeType.READS)
    assert _paths(g) == []


def test_attackpath_to_dict():
    """AttackPath.to_dict exposes structured fields incl. associated_edges."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL, label="skill")
    sec = Node(id="SECRET:token", type=NodeType.SECRET, label="token")
    act = Node(id="ACTION:run", type=NodeType.ACTION, label="run")
    for n in (s, sec, act):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(s.id, act.id, EdgeType.EXECUTES)
    p = _paths(g)[0]
    d = p.to_dict()
    assert "nodes" in d and "edges" in d and "associated_edges" in d
    assert "severity" in d and "title" in d and "confidence" in d


# --- Commit 7: Attack Paths as first-class stable security objects -----------
# path_id must be a deterministic semantic identity, independent of insertion
# order, dedup of equivalent findings, unaffected by severity/confidence, and
# serialized into to_dict().


def test_path_id_deterministic_and_semantic():
    """identical semantic content => identical path_id; different => different."""
    nodes = ["SKILL:skill", "SECRET:token", "ENDPOINT:https://evil.com"]
    edges = [("SKILL:skill", "SECRET:token", "READS"),
             ("SECRET:token", "ENDPOINT:https://evil.com", "SENDS_TO")]
    a = path_id_of(nodes, edges, [])
    b = path_id_of(list(nodes), list(edges), [])
    assert a == b
    # A genuinely different semantic path (different endpoint) differs.
    other = path_id_of(nodes[:-1] + ["ENDPOINT:https://other.com"], edges[:-1] +
                       [("SECRET:token", "ENDPOINT:https://other.com", "SENDS_TO")], [])
    assert other != a


def test_path_id_independent_of_associated_insertion_order():
    """associated_edges sorted => order-insensitive identity."""
    nodes = ["SKILL:s", "ACTION:run"]
    edges = [("SKILL:s", "ACTION:run", "EXECUTES")]
    assoc_a = [("SKILL:s", "SECRET:a", "READS"), ("SKILL:s", "SECRET:b", "READS")]
    assoc_b = [("SKILL:s", "SECRET:b", "READS"), ("SKILL:s", "SECRET:a", "READS")]
    assert path_id_of(nodes, edges, assoc_a) == path_id_of(nodes, edges, assoc_b)


def test_path_id_stable_across_different_graph_insertion_order():
    """Same semantics inserted in different order => identical path_id (A)."""
    def build(secret_first: bool):
        g = SecurityGraph()
        s = Node(id="SKILL:skill", type=NodeType.SKILL)
        sec = Node(id="SECRET:token", type=NodeType.SECRET)
        d = Node(id="DATA:payload", type=NodeType.DATA)
        ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT)
        order = [s, sec, d, ep] if secret_first else [ep, d, sec, s]
        for n in order:
            g.add_node(n)
        g.add_edge(s.id, sec.id, EdgeType.READS)
        g.add_edge(sec.id, d.id, EdgeType.FLOWS_TO)
        g.add_edge(d.id, ep.id, EdgeType.SENDS_TO)
        return _paths(g)[0]
    p1 = build(True)
    p2 = build(False)
    assert p1.to_dict()["path_id"] == p2.to_dict()["path_id"]
    assert p1.path_id == p2.path_id


def test_duplicate_equivalent_paths_deduped_to_one():
    """Equivalent findings producing the same semantic path => one AttackPath (B)."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL)
    sec = Node(id="SECRET:token", type=NodeType.SECRET)
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT)
    for n in (s, sec, ep):
        g.add_node(n)
    # Duplicate/equivalent findings both add the same READS and SENDS_TO edges.
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(s.id, sec.id, EdgeType.READS)          # duplicate reads finding
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)      # duplicate send finding
    paths = _paths(g)
    assert len(paths) == 1
    p = paths[0]
    assert p.to_dict()["path_id"] == path_id_of(p.nodes, p.edges, p.associated_edges)


def test_distinct_semantic_paths_get_distinct_ids():
    """Two genuinely different semantic paths => different path_ids (C)."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL)
    sec = Node(id="SECRET:token", type=NodeType.SECRET)
    epA = Node(id="ENDPOINT:https://a.com", type=NodeType.ENDPOINT)
    epB = Node(id="ENDPOINT:https://b.com", type=NodeType.ENDPOINT)
    for n in (s, sec, epA, epB):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, epA.id, EdgeType.SENDS_TO)
    g.add_edge(sec.id, epB.id, EdgeType.SENDS_TO)
    paths = _paths(g)
    assert len(paths) == 2
    ids = {p.to_dict()["path_id"] for p in paths}
    assert len(ids) == 2


def test_path_id_unchanged_by_severity_confidence():
    """Changing severity/confidence must not change path_id (D)."""
    base_nodes = ["SKILL:skill", "SECRET:token", "ENDPOINT:https://evil.com"]
    base_edges = [("SKILL:skill", "SECRET:token", "READS"),
                  ("SECRET:token", "ENDPOINT:https://evil.com", "SENDS_TO")]
    from veyra.graph import AttackPath as _AP
    lo = _AP(nodes=list(base_nodes), edges=list(base_edges),
             severity=Severity.LOW, confidence=Confidence.LOW)
    hi = _AP(nodes=list(base_nodes), edges=list(base_edges),
             severity=Severity.CRITICAL, confidence=Confidence.HIGH)
    lo.ensure_path_id()
    hi.ensure_path_id()
    assert lo.path_id == hi.path_id
    assert lo.canonical_identity == hi.canonical_identity


def test_stable_ordering_across_repeated_scans():
    """Repeated scans of the same input yield identical path order (E)."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL)
    sec = Node(id="SECRET:token", type=NodeType.SECRET)
    d = Node(id="DATA:payload", type=NodeType.DATA)
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT)
    for n in (s, sec, d, ep):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, d.id, EdgeType.FLOWS_TO)
    g.add_edge(d.id, ep.id, EdgeType.SENDS_TO)
    r1 = [x.to_dict()["path_id"] for x in _paths(g)]
    r2 = [x.to_dict()["path_id"] for x in _paths(g)]
    r3 = [x.to_dict()["path_id"] for x in _paths(g)]
    assert r1 == r2 == r3


def test_correlated_execution_identity_includes_secret():
    """Correlated secret+execution: the associated secret is part of identity (F)."""
    from veyra.graph import AttackPath as _AP
    p = _AP(nodes=["SKILL:s", "ACTION:run"],
            edges=[("SKILL:s", "ACTION:run", "EXECUTES")],
            associated_edges=[("SKILL:s", "SECRET:token", "READS")])
    # Without the associated secret read the identity must differ, proving the
    # correlated evidence is represented in the identity.
    q = _AP(nodes=["SKILL:s", "ACTION:run"],
            edges=[("SKILL:s", "ACTION:run", "EXECUTES")])
    assert p.canonical_identity != q.canonical_identity
    assert path_id_of(p.nodes, p.edges, p.associated_edges) != \
        path_id_of(q.nodes, q.edges, q.associated_edges)
    assert path_id_of(p.nodes, p.edges, [("SKILL:s", "SECRET:token", "READS")]) == \
        path_id_of(p.nodes, p.edges, [("SKILL:s", "SECRET:token", "READS")])


def test_to_dict_includes_path_id():
    """Serialization includes path_id (G)."""
    g = SecurityGraph()
    s = Node(id="SKILL:skill", type=NodeType.SKILL)
    sec = Node(id="SECRET:token", type=NodeType.SECRET)
    ep = Node(id="ENDPOINT:https://evil.com", type=NodeType.ENDPOINT)
    for n in (s, sec, ep):
        g.add_node(n)
    g.add_edge(s.id, sec.id, EdgeType.READS)
    g.add_edge(sec.id, ep.id, EdgeType.SENDS_TO)
    p = _paths(g)[0]
    p.ensure_path_id()
    d = p.to_dict()
    assert "path_id" in d
    assert d["path_id"] == path_id_of(p.nodes, p.edges, p.associated_edges)
    assert len(d["path_id"]) == 64  # sha256 hex


def test_metadata_title_does_not_change_identity():
    """Rule-derived metadata (title/description) must not change identity."""
    from veyra.graph import AttackPath as _AP
    nodes = ["SKILL:skill", "SECRET:token", "ENDPOINT:https://evil.com"]
    edges = [("SKILL:skill", "SECRET:token", "READS"),
             ("SECRET:token", "ENDPOINT:https://evil.com", "SENDS_TO")]
    # Same semantic path but different rule-derived titles/descriptions.
    a = _AP(nodes=list(nodes), edges=list(edges), title="Secret exposed",
            description="via rule A")
    b = _AP(nodes=list(nodes), edges=list(edges), title="Exfil by rule B",
            description="via rule B")
    assert a.canonical_identity == b.canonical_identity
    assert path_id_of(a.nodes, a.edges, a.associated_edges) == \
        path_id_of(b.nodes, b.edges, b.associated_edges)
