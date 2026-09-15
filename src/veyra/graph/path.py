"""Deterministic Attack Path Analyzer for Veyra.

Operates on a :class:`~veyra.graph.models.SecurityGraph` and identifies
security-relevant paths across semantic relationships. It makes NO reference to
AS-* rule IDs — it reasons over NodeType / EdgeType semantics only.

Truthfulness guarantees:

- Every AttackPath ``edges`` list is a CONTIGUOUS directed graph walk:
  ``nodes[0] --edges[0]--> nodes[1] ... nodes[n-1] --edges[n-1]--> nodes[n]``.
  The listed edge set never implies an edge that does not exist in the graph.
- Data-exposure / exfiltration paths require REAL object continuity: the read
  origin FLOWS_TO the object that is actually SENDS_TO the external endpoint.
  A bare "skill reads a secret AND skill sends to an endpoint" without an
  object-flow edge is shared-skill correlation and is NOT emitted as an
  exfiltration path.
- ``USES`` is not an exfiltration sink; only ``SENDS_TO`` terminates an
  exposure path.
- ``PRODUCES`` (skill manufactures an object) is not object-to-object data
  flow; only ``FLOWS_TO`` is traversed for lineage.
- The ``Secret + execution`` correlation is preserved only as a truthful
  contiguous walk anchored on the shared SKILL; the Secret is recorded as an
  associated (non-walk) edge, never as a fabricated ``Secret -> Action`` edge.

No database, no LLM, no runtime analysis.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from veyra.graph.models import Edge, EdgeType, NodeType, SecurityGraph
from veyra.models import Confidence, Severity

# Maximum number of data-flow edges to traverse from a source (bounds cycles).
MAX_PATH_EDGES = 10

# Edge types that move data from one object to another. PRODUCES is excluded:
# it means a SKILL manufactures an output, not that object data flows to it.
_DATA_FLOW_EDGES = {EdgeType.FLOWS_TO}

# Edge types that represent reading a source object.
_READ_EDGES = {EdgeType.READS}

# Edge types that expose data to an external sink. USES is excluded: requesting
# from an endpoint is not the same as sending data to it.
_SEND_EDGES = {EdgeType.SENDS_TO}

# Edge types that represent executing something.
_EXEC_EDGES = {EdgeType.EXECUTES}

# Type-based rank for a path's worst (most dangerous) component.
_SEV_RANK = {Severity.CRITICAL.value: 4, Severity.HIGH.value: 3,
             Severity.MEDIUM.value: 2, Severity.LOW.value: 1, Severity.INFO.value: 0}
_CONF_RANK = {Confidence.HIGH.value: 2, Confidence.MEDIUM.value: 1, Confidence.LOW.value: 0}

# Deterministic explanations keyed by attack type.
_EXPLANATIONS = {
    "DATA_EXFILTRATION": "Sensitive data flows to an external endpoint.",
    "SECRET_EXFILTRATION": "A secret flows to an external endpoint.",
    "CORRELATED_SECRET_EXECUTION": "A secret is read by the skill and the same skill executes an action.",
}

# --- Deterministic risk model ------------------------------------------------
# Risk assessment is derived ONLY from semantic facts present on the path:
# attack_type, asset kind (SECRET vs DATA), whether the walk includes a data
# transformation (FLOWS_TO), the endpoint sink, and any shared-skill correlated
# secret read. The mutable fields (severity, confidence, title, description)
# that come from finding/edge metadata are deliberately NOT inputs, so the risk
# of a semantically identical path is always identical regardless of how the
# same semantics were discovered or inserted. The three concepts are kept
# distinct: risk_severity (impact), risk_confidence (how strongly the semantics
# are established), and risk_score (a single deterministic 0-100 number).

# Transparent deterministic points per risk severity (impact).
_RISK_SEVERITY_POINTS = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 0,
}

# Transparent deterministic confidence multiplier (how strongly established).
_RISK_CONFIDENCE_FACTOR = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.85,
    Confidence.LOW: 0.7,
}


def _risk_for(attack_type: "AttackType") -> Tuple[Severity, Confidence, int]:
    """Deterministic (risk_severity, risk_confidence, risk_score) for a path.

    Proven continuous lineage (SECRET_EXFILTRATION / DATA_EXFILTRATION) is the
    strongest signal: severity reflects asset impact and confidence is HIGH
    because the object flow is proven by the contiguous walk. A correlated
    secret + execution is real but only a correlation, so it is MEDIUM severity
    and MEDIUM confidence. UNKNOWN carries no supported semantic so it scores 0.
    """
    if attack_type == AttackType.SECRET_EXFILTRATION:
        sev, conf = Severity.CRITICAL, Confidence.HIGH
    elif attack_type == AttackType.DATA_EXFILTRATION:
        sev, conf = Severity.HIGH, Confidence.HIGH
    elif attack_type == AttackType.CORRELATED_SECRET_EXECUTION:
        sev, conf = Severity.MEDIUM, Confidence.MEDIUM
    else:  # UNKNOWN — no supported attack semantic established.
        return Severity.INFO, Confidence.LOW, 0
    points = _RISK_SEVERITY_POINTS[sev]
    score = int(round(points * _RISK_CONFIDENCE_FACTOR[conf]))
    return sev, conf, score


def _evidence_for(attack_type: "AttackType",
                  has_transformation: bool, has_flow: bool) -> List[str]:
    """Structured, deterministic list of facts explaining why the path is risky.

    Every fact is backed by a semantic signal present on the path. No claim is
    made that the graph does not support. Correlated secret execution records
    only the shared-skill correlation signals (secret read + execution) and
    never a secret-to-action data-flow claim. UNKNOWN carries no supported
    attack semantic, so it receives no attack evidence.
    """
    if attack_type == AttackType.SECRET_EXFILTRATION:
        ev = ["secret read"]
    elif attack_type == AttackType.DATA_EXFILTRATION:
        ev = ["sensitive data read"]
    elif attack_type == AttackType.CORRELATED_SECRET_EXECUTION:
        return ["secret read", "execution"]  # correlation signals only
    else:
        return []  # UNKNOWN and unsupported semantics get no attack evidence.
    if has_transformation:
        ev.append("data transformation")
    if has_flow:
        ev.append("sensitive data flow")
    ev.append("external network send")
    return ev


def assess_risk(path: "AttackPath") -> "AttackPath":
    """Populate and return the deterministic risk fields + evidence on `path`.

    Derived purely from semantic path facts (see _risk_for / _evidence_for).
    ``explanation`` is owned by :func:`classify_path`; this only adds the risk
    model. Independent of mutable metadata (severity, confidence, title, rule
    ids) and of graph insertion order, so identical canonical paths always
    yield identical risk and evidence.
    """
    is_contiguous = path.is_contiguous and bool(path.nodes)
    edge_types = [et for _, _, et in path.edges]
    has_flow = EdgeType.FLOWS_TO.value in edge_types
    has_transformation = any(
        et == EdgeType.FLOWS_TO.value and _node_kind(n) in ("SECRET", "DATA")
        for (_, n, et) in path.edges[1:] if et != EdgeType.READS.value
    )

    attack_type = path.attack_type if is_contiguous else AttackType.UNKNOWN
    path.risk_severity, path.risk_confidence, path.risk_score = _risk_for(attack_type)
    path.evidence = _evidence_for(attack_type, has_transformation, has_flow)
    return path


# --- Deterministic breakpoints ------------------------------------------------
# A breakpoint is an EXISTING semantic graph edge on the attack path whose
# removal would interrupt the proven attack. We only reference edges that are
# actually present (either in the contiguous walk ``path.edges`` or, for a
# correlated execution, the associated shared-skill read). We never fabricate
# edges, never claim a breakpoint "fixes" a vulnerability, and never invent a
# secret->action flow edge for a correlation that does not exist.

# Small controlled vocabulary for which semantic portion the breakpoint affects.
class BreakpointImpact(str, Enum):
    ACCESS = "ACCESS"                      # getting at the sensitive asset
    DATA_FLOW = "DATA_FLOW"                # object-to-object data lineage
    EXTERNAL_TRANSMISSION = "EXTERNAL_TRANSMISSION"  # sending to an endpoint
    EXECUTION = "EXECUTION"                # running a correlated action


# Deterministic reason for each breakpoint edge type. Wording is deliberately
# modest — it names what is interrupted, never "fixes the vulnerability".
_BREAKPOINT_REASONS = {
    "READS": "Restricts access to the sensitive asset.",
    "FLOWS_TO": "Breaks the proven data lineage.",
    "SENDS_TO": "Prevents transmission to the external endpoint.",
    "EXECUTES": "Restricts execution of the correlated action.",
}

_BREAKPOINT_IMPACTS = {
    "READS": BreakpointImpact.ACCESS,
    "FLOWS_TO": BreakpointImpact.DATA_FLOW,
    "SENDS_TO": BreakpointImpact.EXTERNAL_TRANSMISSION,
    "EXECUTES": BreakpointImpact.EXECUTION,
}


@dataclass
class Breakpoint:
    """An existing semantic graph edge whose removal interrupts the attack path.

    References an ACTUAL edge from the AttackPath (walk ``edges`` or, for a
    correlated execution, an associated shared-skill read). ``edge_type`` is the
    graph edge type; ``impact`` names the affected semantic portion from the
    small controlled vocabulary; ``reason`` is a deterministic, modest statement
    of what the edge's removal interrupts — never a "fix" or a stronger claim.
    """
    source_node: str
    target_node: str
    edge_type: str
    reason: str
    impact: BreakpointImpact

    def to_dict(self) -> Dict:
        return {
            "source_node": self.source_node,
            "target_node": self.target_node,
            "edge_type": self.edge_type,
            "reason": self.reason,
            "impact": self.impact.value,
        }


def breakpoints_for(path: "AttackPath") -> List[Breakpoint]:
    """Return the deterministic breakpoints for a classified attack path.

    SECRET_EXFILTRATION / DATA_EXFILTRATION: every edge of the contiguous walk
    (READS, each FLOWS_TO, SENDS_TO) is a necessary step of the proven lineage,
    so each is listed in walk order.

    CORRELATED_SECRET_EXECUTION: there is NO secret->action flow edge. We expose
    only the actual control edges that contribute to the shared-skill
    correlation: the walk's EXECUTES edge and the associated READS secret edge.
    Both are labelled as correlation/control points, never as a data-flow
    breakpoint.

    UNKNOWN: no supported attack semantic, so no breakpoints.
    """
    attack_type = path.attack_type if path.is_contiguous else AttackType.UNKNOWN
    bp: List[Breakpoint] = []

    if attack_type in (AttackType.SECRET_EXFILTRATION, AttackType.DATA_EXFILTRATION):
        for (s, t, et) in path.edges:
            reason = _BREAKPOINT_REASONS.get(et)
            impact = _BREAKPOINT_IMPACTS.get(et)
            if reason is None or impact is None:
                continue  # only known semantic edge types become breakpoints
            bp.append(Breakpoint(s, t, et, reason, impact))
        return bp

    if attack_type == AttackType.CORRELATED_SECRET_EXECUTION:
        # Walk edge: SKILL --EXECUTES--> ACTION (a control/correlation point).
        for (s, t, et) in path.edges:
            if et == "EXECUTES":
                bp.append(Breakpoint(s, t, et,
                                     _BREAKPOINT_REASONS[et], _BREAKPOINT_IMPACTS[et]))
        # Associated shared-skill read: SKILL --READS--> SECRET. Deterministic
        # ordering by (source, target) so it never depends on insertion order.
        for (s, t, et) in sorted(path.associated_edges, key=lambda e: (e[0], e[1], e[2])):
            if et == "READS":
                bp.append(Breakpoint(s, t, et,
                                     _BREAKPOINT_REASONS[et], _BREAKPOINT_IMPACTS[et]))
        return bp

    return []  # UNKNOWN — no breakpoints from unsupported semantics


class AttackType(str, Enum):
    """Deterministic classification of a proven attack path."""
    UNKNOWN = "UNKNOWN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    CORRELATED_SECRET_EXECUTION = "CORRELATED_SECRET_EXECUTION"

    # SECRET_TO_EXECUTION / DATA_TO_EXECUTION are intentionally NOT defined:
    # the current architecture only represents secret/data + execution as a
    # shared-skill correlation, never as a proven contiguous secret->action flow.


def _node_kind(node_id: str) -> Optional[str]:
    """Return the node-type prefix of an id (e.g. 'SECRET'), or None."""
    if ":" in node_id:
        return node_id.split(":", 1)[0]
    return None


# Canonical-identity delimiters. Unit/record separators cannot collide with the
# printable node ids/edge types that make up a semantic path, so the encoding is
# unambiguous without needing arbitrary Python repr() of the tuples.
_FIELD_SEP = "\x1f"   # separates tokens inside a path field
_RECORD_SEP = "\x1e"  # separates the nodes/edges/assoc fields


def _sem_escape(s: str) -> str:
    """Escape a token so it cannot collide with the identity delimiters."""
    return s.replace("\\", "\\\\").replace(_FIELD_SEP, "\\x1f").replace(_RECORD_SEP, "\\x1e")


def canonical_path_identity(
    nodes: List[str],
    edges: List[Tuple[str, str, str]],
    associated_edges: List[Tuple[str, str, str]],
) -> str:
    """Deterministic, insertion-order-independent canonical representation.

    The identity is the ordered node walk, the ordered edge walk, and the
    associated (correlated) edges sorted into a stable order. It is derived
    purely from SEMANTIC path content and excludes all mutable/evidentiary
    metadata (severity, confidence, rule ids, insertion order, title). It is
    identical for two paths that differ only in how the same semantics were
    discovered or inserted into the graph.

    The attack type is NOT included separately: it is fully derivable from the
    contiguous node/edge sequence plus the associated reads (see
    ``classify_path``), so any semantic difference that changes the attack type
    already changes this identity, and identical identities always classify to
    the same type.
    """
    fields = [
        "N" + _FIELD_SEP + _FIELD_SEP.join(_sem_escape(n) for n in nodes),
        "E" + _FIELD_SEP + _FIELD_SEP.join(
            _FIELD_SEP.join((_sem_escape(s), _sem_escape(t), _sem_escape(et)))
            for s, t, et in edges
        ),
        "A" + _FIELD_SEP + _FIELD_SEP.join(
            _FIELD_SEP.join((_sem_escape(s), _sem_escape(t), _sem_escape(et)))
            for s, t, et in sorted(associated_edges, key=lambda e: (e[0], e[1], e[2]))
        ),
    ]
    return _RECORD_SEP.join(fields)


def path_id_of(
    nodes: List[str],
    edges: List[Tuple[str, str, str]],
    associated_edges: List[Tuple[str, str, str]],
) -> str:
    """A stable, compact semantic path_id derived from the canonical identity."""
    return hashlib.sha256(canonical_path_identity(nodes, edges, associated_edges).encode("utf-8")).hexdigest()


def classify_path(path: "AttackPath") -> "AttackPath":
    """Deterministically classify an AttackPath into explicit security semantics.

    Classification is conservative: a type is assigned only when the actual
    (already-contiguous) edge SEQUENCE proves the relationship.

    Exfiltration requires object lineage:
        SKILL --READS--> ASSET
        ASSET --FLOWS_TO--> ... --FLOWS_TO--> DATA
        DATA --SENDS_TO--> ENDPOINT
    or the direct form:
        SKILL --READS--> ASSET
        ASSET --SENDS_TO--> ENDPOINT

    A shared-skill correlation (SKILL --EXECUTES--> ACTION plus an associated
    SKILL --READS--> SECRET) is classified CORRELATED_SECRET_EXECUTION and is
    NEVER described as proven secret->action flow.
    """
    nodes = path.nodes
    if not nodes or not path.is_contiguous:
        path.attack_type = AttackType.UNKNOWN
        return path

    path.entry_node = nodes[0]
    sink = nodes[-1]
    sink_kind = _node_kind(sink)

    # --- Exfiltration: prove object lineage across the contiguous walk ----
    if sink_kind == "ENDPOINT":
        result = _classify_exfiltration(path)
        if result is not None:
            path.attack_type, path.asset_node = result
            path.sink_node = sink

    # --- Execution: shared-skill correlation (NOT a proven asset->action flow)
    elif sink_kind == "ACTION":
        # The walk is SKILL --EXECUTES--> ACTION. A secret read is only an
        # associated (correlated) edge anchored on the same skill — it never
        # proves the secret flowed INTO the action.
        for (src, tgt, etype) in path.associated_edges:
            if etype == "READS" and _node_kind(tgt) == "SECRET":
                path.attack_type = AttackType.CORRELATED_SECRET_EXECUTION
                path.asset_node = tgt
                path.sink_node = sink
                break

    if path.attack_type is not AttackType.UNKNOWN:
        path.explanation = _EXPLANATIONS[path.attack_type.value]
    return path


def _classify_exfiltration(path: "AttackPath"):
    """Return (AttackType, asset_node) for a proven exfiltration lineage, or None.

    Verifies the actual contiguous edge sequence, NOT a loose "asset present +
    SENDS_TO present" test. The asset is the first SECRET/DATA in the walk; the
    edge into it must be READS, the edge into the ENDPOINT must be SENDS_TO
    from the asset lineage, and every step between must be FLOWS_TO.
    """
    nodes = path.nodes
    edges = path.edges

    # Find the first SECRET/DATA node in the walk (the asset).
    asset_idx = next((i for i, n in enumerate(nodes) if _node_kind(n) in ("SECRET", "DATA")), None)
    if asset_idx is None:
        return None
    asset = nodes[asset_idx]
    asset_kind = _node_kind(asset)

    # The edge entering the asset (from the skill) must be READS.
    if asset_idx < 1 or edges[asset_idx - 1][2] != "READS":
        return None

    # The terminal edge (into the ENDPOINT) must be SENDS_TO, and its source
    # must be the last node of the asset lineage (the node before ENDPOINT).
    if edges[-1][2] != "SENDS_TO":
        return None

    # Every edge from the asset up to (but not including) the final SENDS_TO
    # must be a FLOWS_TO link — proving the asset flows into the sent object.
    for idx in range(asset_idx, len(edges) - 1):
        if edges[idx][2] != "FLOWS_TO":
            return None

    return (AttackType.SECRET_EXFILTRATION if asset_kind == "SECRET" else AttackType.DATA_EXFILTRATION,
            asset)


@dataclass
class AttackPath:
    """A discovered security-relevant path in the graph.

    ``edge`` list is always a contiguous walk over ``nodes``.
    ``associated_edges`` hold shared-skill correlation edges (e.g. the Secret
    read for a ``Secret + execution`` path) that are NOT part of the linear
    walk and therefore never pretend to connect consecutive walk nodes.

    ``path_id`` is a stable semantic identity derived from the canonical path
    content (nodes + edges + sorted associated edges). It is independent of
    insertion order and of mutable/evidentiary metadata (severity, confidence,
    rule ids, title). Two paths with the same semantics always share a path_id;
    genuinely different semantics always differ.
    """
    nodes: List[str]
    edges: List[Tuple[str, str, str]]
    associated_edges: List[Tuple[str, str, str]] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    title: str = ""
    description: str = ""
    attack_type: AttackType = AttackType.UNKNOWN
    entry_node: str = ""
    asset_node: str = ""
    sink_node: str = ""
    explanation: str = ""
    path_id: str = ""
    risk_severity: Severity = Severity.INFO
    risk_confidence: Confidence = Confidence.LOW
    risk_score: int = 0
    evidence: List[str] = field(default_factory=list)
    breakpoints: List["Breakpoint"] = field(default_factory=list)
    is_composed: bool = False
    component_ids: List[str] = field(default_factory=list)

    @property
    def is_contiguous(self) -> bool:
        """True iff edges form a valid walk over nodes."""
        if len(self.nodes) != len(self.edges) + 1:
            return False
        for i, (s, t, _) in enumerate(self.edges):
            if s != self.nodes[i] or t != self.nodes[i + 1]:
                return False
        return True

    @property
    def canonical_identity(self) -> str:
        """Canonical semantic identity (see canonical_path_identity)."""
        return canonical_path_identity(self.nodes, self.edges, self.associated_edges)

    def ensure_path_id(self) -> str:
        """Populate and return a stable path_id if it is not already set."""
        if not self.path_id:
            self.path_id = path_id_of(self.nodes, self.edges, self.associated_edges)
        return self.path_id

    def to_dict(self) -> Dict:
        return {
            "path_id": self.path_id,
            "nodes": list(self.nodes),
            "edges": [{"source": s, "target": t, "type": et} for s, t, et in self.edges],
            "associated_edges": [{"source": s, "target": t, "type": et} for s, t, et in self.associated_edges],
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "description": self.description,
            "attack_type": self.attack_type.value,
            "entry_node": self.entry_node,
            "asset_node": self.asset_node,
            "sink_node": self.sink_node,
            "risk_score": self.risk_score,
            "risk_severity": self.risk_severity.value,
            "risk_confidence": self.risk_confidence.value,
            "evidence": list(self.evidence),
            "breakpoints": [b.to_dict() for b in self.breakpoints],
            "explanation": self.explanation,
            "is_composed": self.is_composed,
            "component_ids": list(self.component_ids),
        }


class PathAnalyzer:
    """Enumerate truthful attack paths in a SecurityGraph."""

    def __init__(self, graph: SecurityGraph):
        self.graph = graph
        # Precompute adjacency and an edge lookup for metadata.
        self._adj: Dict[str, List[Edge]] = {nid: [] for nid in graph.nodes}
        self._edge_index: Dict[Tuple[str, str, str], Edge] = {}
        for e in graph.edges:
            self._adj.setdefault(e.source, []).append(e)
            self._edge_index[(e.source, e.target, e.type.value)] = e

    # --- Public API ---------------------------------------------------------

    def analyze(self, compose: bool = False) -> List[AttackPath]:
        """Return all discovered attack paths, deduplicated and deterministically ordered.

        ``compose=True`` runs cross-component composition over the whole merged
        graph and returns ONLY paths that genuinely cross component boundaries
        (established by real PRODUCES attribution, never by shared names). Each
        returned path is classified into explicit security semantics.
        """
        paths: List[AttackPath] = []
        for skill_id, skill_node in self.graph.nodes.items():
            if skill_node.type != NodeType.SKILL:
                continue
            paths.extend(self._analyze_skill(skill_id))
        paths = self._dedupe(paths)
        out: List[AttackPath] = []
        for p in paths:
            classify_path(p)
            assess_risk(p)
            p.breakpoints = breakpoints_for(p)
            if compose:
                if not self._set_composition(p):
                    continue  # only genuinely multi-component walks qualify
            out.append(p)
        # De-duplication ordering is unaffected by classification/risk (both are
        # derived purely from the already-ordered node/edge sequences).
        return out

    # --- Composition --------------------------------------------------------

    def _set_composition(self, path: "AttackPath") -> bool:
        """Populate is_composed / component_ids for a walk; return whether composed.

        Composition is claimed ONLY from semantic components actually present
        in the ordered AttackPath. A component is identified by its SKILL node
        in ``path.nodes`` (``SKILL:<comp>``). No producer attribution, no shared
        object/secret/endpoint name, and no graph edge outside the walk is used.

        The current graph model roots every truthful walk at exactly one SKILL
        (``_analyze_skill``), and there is no explicit semantic edge connecting
        one component's SKILL to another. Therefore a walk never contains more
        than one component, ``is_composed`` stays False, and ``component_ids``
        lists that single root component. This is the conservative, correct
        answer: better no composed path than a synthetic one. If a future graph
        edge truthfully connects two SKILL components within one real walk,
        this logic would then report it accurately.
        """
        ordered: List[str] = []
        seen: Set[str] = set()
        for node in path.nodes:
            kind = _node_kind(node)
            if kind != "SKILL":
                continue
            comp = node.split(":", 1)[1] if ":" in node else None
            if comp is None or comp in seen:
                continue
            seen.add(comp)
            ordered.append(comp)
        path.component_ids = ordered
        path.is_composed = len(ordered) > 1
        return path.is_composed

    # --- Per-skill analysis -------------------------------------------------

    def _skill_edges(self, skill_id: str, edge_types: Set[EdgeType]) -> List[Tuple[str, str, str]]:
        """Return the skill's outgoing edges of the given types, deduplicated + sorted."""
        out: List[Tuple[str, str, str]] = []
        seen: Set[Tuple[str, str, str]] = set()
        for e in self._adj.get(skill_id, []):
            if e.type in edge_types:
                edge = (skill_id, e.target, e.type.value)
                if edge not in seen:
                    seen.add(edge)
                    out.append(edge)
        out.sort(key=lambda x: (x[1], x[2]))
        return out

    def _read_origins(self, skill_id: str) -> List[Tuple[str, str, str]]:
        """The skill's READS edges whose target is SECRET or DATA."""
        origins = []
        for edge in self._skill_edges(skill_id, _READ_EDGES):
            tgt = self.graph.get_node(edge[1])
            if tgt is not None and tgt.type in (NodeType.SECRET, NodeType.DATA):
                origins.append(edge)
        return origins

    def _handoff_paths(self, head: str) -> List[Tuple[List[str], List[Tuple[str, str, str]]]]:
        """Enumerate every MAXIMAL HANDOFF path reachable from ``head``.

        Branch-aware: at each node all outgoing HANDOFF edges are considered, so
        ``A -> B`` / ``A -> C`` yield two separate paths. A path is emitted only
        when it cannot be extended: the current node has no outgoing HANDOFF, or
        every following target would revisit a node already in the walk (cycle
        guard). This yields maximal leaf paths — ``A -> B -> C`` is emitted as
        one path, never ``A -> B`` or ``B -> C``. Traversal is deterministic
        (outgoing edges sorted by target). Never revisits a node within a walk,
        so it is bounded and finite.
        """
        results: List[Tuple[List[str], List[Tuple[str, str, str]]]] = []

        def dfs(nodes: List[str], edges: List[Tuple[str, str, str]]):
            cur = nodes[-1]
            handoffs = [e for e in self._adj.get(cur, [])
                        if e.type == EdgeType.HANDOFF]
            handoffs.sort(key=lambda e: (e.target, e.type.value))
            extended = False
            for e in handoffs:
                if e.target in nodes:
                    continue  # cycle guard — would revisit a node in this walk
                extended = True
                dfs(nodes + [e.target], edges + [(cur, e.target, EdgeType.HANDOFF.value)])
            if not extended:
                # Leaf: no extendable outgoing edge from this walk.
                if edges:
                    results.append((list(nodes), list(edges)))

        dfs([head], [])
        return results

    def _has_incoming_handoff(self, skill_id: str) -> bool:
        """True if ``skill_id`` is the target of some HANDOFF edge in the graph."""
        for e in self.graph.edges:
            if e.type == EdgeType.HANDOFF and e.target == skill_id:
                return True
        return False

    def _handoff_chains(self, skill_id: str) -> List[Tuple[List[str], List[Tuple[str, str, str]]]]:
        """Return the maximal HANDOFF paths that START at ``skill_id``.

        A head is a SKILL node with at least one outgoing HANDOFF edge and NO
        incoming HANDOFF edge. Every branch-aware maximal path from the head is
        emitted (see _handoff_paths). This keeps multi-hop composition complete,
        deduplicated, and deterministic.

        A pure HANDOFF cycle (``A -> B -> C -> A``) has no true head, so
        conservatively no composed path is emitted. A head-attached cycle is
        handled by the per-walk revisit guard. Analysis is bounded and finite.
        """
        if self._has_incoming_handoff(skill_id):
            return []
        paths = self._handoff_paths(skill_id)
        # Keep only maximal paths that contain at least one HANDOFF edge.
        return [(n, e) for (n, e) in paths if e]

    def _analyze_skill(self, skill_id: str) -> List[AttackPath]:
        paths: List[AttackPath] = []
        read_origins = self._read_origins(skill_id)
        exec_edges = self._skill_edges(skill_id, _EXEC_EDGES)

        # --- Pattern 0: explicit component handoff chains -------------------
        # SKILL:A --HANDOFF--> SKILL:B [--HANDOFF--> SKILL:C ...] is a truthful
        # control/component transfer. Each MAXIMAL contiguous HANDOFF chain is
        # emitted as one multi-hop composed AttackPath. It does NOT prove secret
        # or data exfiltration, and is never a data-lineage traversal. A node is
        # never revisited within a chain (cycle-guarded), so the walk is bounded
        # and finite.
        for nodes, edges in self._handoff_chains(skill_id):
            paths.append(self._make_path(nodes, edges, [], "handoff"))

        # --- Pattern 3: Secret + execution (shared-skill correlation) ------
        # The walk is Skill --EXECUTES--> Action (contiguous). The Secret read
        # is an ASSOCIATED edge anchored on the same Skill — it is never drawn
        # as Secret -> Action.
        for _, origin, _ in read_origins:
            origin_node = self.graph.get_node(origin)
            if origin_node is None or origin_node.type != NodeType.SECRET:
                continue
            for exec_edge in exec_edges:
                nodes = [skill_id, exec_edge[1]]
                edges = [exec_edge]
                assoc = [(skill_id, origin, "READS")]
                paths.append(self._make_path(nodes, edges, assoc, "execution"))

        # --- Patterns 1, 2, 4: object-identity-continuous exfiltration ------
        for _, origin, _ in read_origins:
            origin_node = self.graph.get_node(origin)
            if origin_node is None:
                continue
            is_secret = origin_node.type == NodeType.SECRET

            # Every prefix of the FLOWS_TO lineage from origin (incl. origin).
            for path_nodes, path_edges in self._flow_paths(origin):
                terminal = path_nodes[-1]
                # Only an actual SENDS_TO edge FROM the terminal data object
                # counts as the object reaching the endpoint.
                for send_edge in sorted(self._adj.get(terminal, []),
                                        key=lambda e: (e.target, e.type.value)):
                    if send_edge.type != EdgeType.SENDS_TO:
                        continue
                    endpoint = send_edge.target
                    nodes = [skill_id] + path_nodes + [endpoint]
                    edges: List[Tuple[str, str, str]] = [(skill_id, origin, "READS")]
                    for i in range(len(path_edges)):
                        edges.append((path_nodes[i], path_nodes[i + 1], path_edges[i]))
                    edges.append((terminal, endpoint, "SENDS_TO"))
                    kind = ("exposure" if is_secret
                            else ("sensitive-data" if len(path_nodes) > 1 else "data"))
                    paths.append(self._make_path(nodes, edges, [], kind))

        return paths

    # --- Bounded data-flow traversal ----------------------------------------

    def _flow_paths(self, origin: str) -> List[Tuple[List[str], List[str]]]:
        """Return all FLOWS_TO prefix paths from origin, each ending at a node.

        Each item is (node_ids_in_order, edge_types_in_order). Includes the
        singleton path ``([origin], [])``. Cycle-guarded and bounded.
        """
        results: List[Tuple[List[str], List[str]]] = []

        def dfs(node: str, path_nodes: List[str], path_edges: List[str]):
            results.append((list(path_nodes), list(path_edges)))
            if len(path_edges) >= MAX_PATH_EDGES:
                return
            for e in sorted(self._adj.get(node, []), key=lambda x: (x.target, x.type.value)):
                if e.type not in _DATA_FLOW_EDGES:
                    continue
                if e.target in path_nodes:
                    continue  # cycle guard — path_nodes is an ordered list
                dfs(e.target, path_nodes + [e.target], path_edges + [e.type.value])

        dfs(origin, [origin], [])
        return results

    # --- Path construction ---------------------------------------------------

    def _make_path(self, nodes: List[str], edges: List[Tuple[str, str, str]],
                   assoc: List[Tuple[str, str, str]], kind: str) -> AttackPath:
        severity, confidence = self._path_signals(edges, assoc)
        title, description = self._describe(kind, nodes, edges)
        return AttackPath(
            nodes=nodes,
            edges=edges,
            associated_edges=assoc,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            path_id=path_id_of(nodes, edges, assoc),
        )

    def _path_signals(self, edges: List[Tuple[str, str, str]],
                      assoc: List[Tuple[str, str, str]]) -> Tuple[Severity, Confidence]:
        """Conservative severity/confidence: strongest metadata among edges, else defaults."""
        worst_sev = Severity.MEDIUM
        worst_conf = Confidence.MEDIUM
        for src, tgt, etype in list(edges) + list(assoc):
            edge = self._edge_index.get((src, tgt, etype))
            if edge is None:
                continue
            sev = edge.attributes.get("severity")
            if sev and _SEV_RANK.get(sev, 2) > _SEV_RANK[worst_sev.value]:
                worst_sev = Severity(sev)
            conf = edge.attributes.get("confidence")
            if conf and _CONF_RANK.get(conf, 1) > _CONF_RANK[worst_conf.value]:
                worst_conf = Confidence(conf)
        return worst_sev, worst_conf

    def _describe(self, kind: str, nodes: List[str],
                  edges: List[Tuple[str, str, str]]) -> Tuple[str, str]:
        if kind == "handoff":
            title = "Cross-component control handoff"
            desc = ("Control is explicitly handed off from one semantic "
                    "component to another. This proves a component transfer; "
                    "it does not, by itself, establish secret or data "
                    "exfiltration.")
        elif kind == "execution":
            title = "Secret access followed by command execution"
            desc = ("A secret is read, and the skill also executes an action. "
                    "This may indicate credentials are used to power a command. "
                    "The read and the execution share the same skill (correlation; "
                    "the secret is not shown to flow into the command).")
        elif kind == "exposure":
            title = "Secret exposed to external endpoint"
            desc = ("A secret flows along a data lineage to an object that is sent "
                    "to an external endpoint.")
        elif kind == "sensitive-data":
            title = "Sensitive data sent to external endpoint"
            desc = "Data is read, transformed, and the derived object is sent to an external endpoint."
        else:
            title = "Data exfiltration path"
            desc = "Data is read and sent to an external endpoint."
        sink = nodes[-1] if nodes else ""
        return title, desc + f" Route terminates at {sink}."

    # --- Deduplication -------------------------------------------------------

    def _dedupe(self, paths: List[AttackPath]) -> List[AttackPath]:
        """Deduplicate by canonical semantic identity; sort deterministically.

        Two paths collapse to one when they share the same canonical identity
        (identical ordered nodes, ordered edge walk, and associated edges as a
        sorted set). This absorbs duplicate/equivalent findings and associated
        evidence while preserving the first-seen useful metadata (title,
        severity, confidence) where the existing architecture supports it. The
        canonical identity excludes mutable/evidentiary metadata, so two
        semantically identical paths never produce a duplicate.
        """
        seen: Set[str] = set()
        out: List[AttackPath] = []
        for p in paths:
            ident = p.canonical_identity
            if ident in seen:
                continue
            seen.add(ident)
            out.append(p)
        # Stable semantic ordering by path_id (a deterministic hash of the
        # canonical identity). Never relies on raw set/dict iteration so the
        # same graph analyzed repeatedly yields identical path order.
        out.sort(key=lambda p: p.path_id)
        return out
