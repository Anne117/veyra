"""Explicit security-behavior component context.

This is a CONTEXT / SCOPE metadata layer: it answers "which explicitly
declared Agent / Skill / Tool / MCP component is the context/owner of this
already-existing security behavior?", WITHOUT creating any security/data-flow
edge and WITHOUT adding new graph semantics.

A context association ties an existing SecurityGraph *security* edge (READS,
WRITES, SENDS_TO, EXECUTES, PRODUCES, FLOWS_TO) to an existing component node
(AGENT / SKILL / TOOL / MCPSERVER). The association is stored as metadata on
the graph; it never calls ``add_edge``, so the security edge count is
unchanged after association.

The central invariant: component context != security/data-flow edge. This
layer must never infer a component from a file path, node id, provenance,
finding source, edge metadata, label, or naming convention — the component id
is always supplied explicitly by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from veyra.graph.models import EdgeType, NodeType, SecurityGraph
from veyra.models import Confidence, Severity


class ComponentContextError(ValueError):
    """Raised for an invalid component-context association."""


# Component node types that may own security behavior context.
_CONTEXT_COMPONENT_TYPES = {
    NodeType.AGENT,
    NodeType.SKILL,
    NodeType.TOOL,
    NodeType.MCPSERVER,
}

# Security-behavior edge types that may be associated with a component.
# Component/ecosystem relationships (CONTAINS/USES/CALLS/TRUSTS/HANDOFF) are
# explicitly NOT security behavior and cannot be associated here.
_SECURITY_BEHAVIOR_EDGE_TYPES = {
    EdgeType.READS,
    EdgeType.WRITES,
    EdgeType.SENDS_TO,
    EdgeType.EXECUTES,
    EdgeType.PRODUCES,
    EdgeType.FLOWS_TO,
}


def _validate_id(value: str, what: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ComponentContextError(f"empty {what}")
    return value


@dataclass(frozen=True)
class ComponentContext:
    """An explicit reference to an already-existing component in the graph.

    ``component_id`` is the semantic node id (e.g. ``SKILL:checkout``) that must
    already exist in the SecurityGraph. ``component_type`` must agree with the
    graph node's actual type; it is authoritative after validation.
    """
    component_id: str
    component_type: NodeType

    def __post_init__(self):
        object.__setattr__(self, "component_id", _validate_id(self.component_id, "component id"))
        if not isinstance(self.component_type, NodeType):
            raise ComponentContextError(
                f"component_type must be a NodeType, got {type(self.component_type).__name__}"
            )
        if self.component_type not in _CONTEXT_COMPONENT_TYPES:
            raise ComponentContextError(
                f"unsupported context component type {self.component_type.value}; "
                f"allowed: {sorted(t.value for t in _CONTEXT_COMPONENT_TYPES)}"
            )


@dataclass(frozen=True)
class ComponentContextAssociation:
    """An explicit association between an existing security edge and a component.

    ``edge_key`` = (source, target, EdgeType) identifies an actual edge that must
    already exist in the graph. No synthetic security edge is created. ``source``
    is association provenance (e.g. a scope/config file) and stays separate from
    the underlying edge's own provenance.
    """
    edge_key: Tuple[str, str, EdgeType]
    component: ComponentContext
    source: Optional[str] = None

    def __post_init__(self):
        s, t, et = self.edge_key
        object.__setattr__(self, "edge_key", (_validate_id(s, "edge source"), _validate_id(t, "edge target"), et))
        if not isinstance(et, EdgeType):
            raise ComponentContextError(
                f"edge type must be an EdgeType, got {type(et).__name__}"
            )
        if et not in _SECURITY_BEHAVIOR_EDGE_TYPES:
            raise ComponentContextError(
                f"edge type {et.value} is not a security-behavior edge; "
                f"component relationships cannot be context associations"
            )


def _serialize_association(a: ComponentContextAssociation) -> Dict[str, Any]:
    edge_key = a.edge_key
    return {
        "component_id": a.component.component_id,
        "component_type": a.component.component_type.value,
        "behavior": {
            "source": edge_key[0],
            "edge_type": edge_key[2].value,
            "target": edge_key[1],
        },
        "source": a.source,
    }


def get_component_context(graph: SecurityGraph) -> List[ComponentContextAssociation]:
    """Return the context associations stored on a graph, deterministic order."""
    return list(getattr(graph, "_component_context", []))


def serialize_component_context(graph: SecurityGraph) -> List[Dict[str, Any]]:
    """Deterministic serialization of a graph's component-context associations.

    Ordering is independent of input order: sorted by (component_id, edge source,
    edge target, edge type, source).
    """
    associations = get_component_context(graph)
    associations = sorted(
        associations,
        key=lambda a: (
            a.component.component_id,
            a.edge_key[0],
            a.edge_key[1],
            a.edge_key[2].value,
            a.source or "",
        ),
    )
    return [_serialize_association(a) for a in associations]


@dataclass(frozen=True)
class ComponentSecurityScope:
    """Deterministic, read-only projection of the security behaviors explicitly
    associated with one component.

    This is NOT a graph relationship and NOT an ownership inference engine: it
    is a structured aggregation of the existing explicit
    :class:`ComponentContextAssociation` metadata. ``security_behaviors`` is an
    immutable tuple of ``(source, edge_type, target)`` where ``edge_type`` is
    serialized as its string value. No ``Edge`` objects are duplicated or
    embedded; the scope only references existing security-behavior edges.
    """

    component: ComponentContext
    security_behaviors: Tuple[Tuple[str, str, str], ...] = ()


def build_component_security_scopes(
    graph: SecurityGraph,
) -> List[ComponentSecurityScope]:
    """Aggregate explicit ComponentContextAssociation records into deterministic
    per-component security scopes.

    - Uses ONLY explicit associations stored on the graph (never infers
      ownership from USES/CONTAINS/CALLS/TRUSTS/HANDOFF, file paths, node ids,
      provenance, labels, findings, or naming).
    - Groups associations by component (component_id / component_type).
    - Preserves multiple components associated with the same security edge.
    - Deduplicates identical (component, behavior edge) pairs.
    - References only actual existing graph security edges, defensively raising
      ``ComponentContextError`` if stale/invalid metadata references a missing
      edge.
    - Never mutates the graph or its association records.

    Deterministic: scopes are sorted by (component_type, component_id) and each
    scope's behaviors by (source, edge_type, target).
    """
    associations = get_component_context(graph)
    if not associations:
        return []
    existing_edges = {(e.source, e.target, e.type.value) for e in graph.edges}
    components: Dict[Tuple[str, str], ComponentContext] = {}
    behaviors: Dict[Tuple[str, str], List[Tuple[str, str, str]]] = {}
    for a in associations:
        src, tgt, et = a.edge_key
        edge_key3 = (src, tgt, et.value)
        if edge_key3 not in existing_edges:
            raise ComponentContextError(
                f"security behavior edge ({src}, {tgt}, {et.value}) referenced "
                f"by component context does not exist in the graph"
            )
        ckey = (a.component.component_id, a.component.component_type.value)
        components.setdefault(ckey, a.component)
        behavior = (src, et.value, tgt)
        bucket = behaviors.setdefault(ckey, [])
        # Deduplicate identical (component, behavior edge) pairs.
        if behavior not in bucket:
            bucket.append(behavior)

    scopes: List[ComponentSecurityScope] = []
    for ckey in sorted(behaviors.keys()):
        ordered = tuple(sorted(behaviors[ckey], key=lambda b: (b[0], b[1], b[2])))
        scopes.append(ComponentSecurityScope(component=components[ckey], security_behaviors=ordered))
    scopes.sort(key=lambda s: (s.component.component_type.value, s.component.component_id))
    return scopes


def serialize_component_security_scopes(graph: SecurityGraph) -> List[Dict[str, Any]]:
    """Deterministic, JSON-safe serialization of a graph's component scopes.

    Returns a list of dicts shaped ``{"component_id", "component_type",
    "security_behaviors": [{"source", "edge_type", "target"}, ...]}``. No
    ``Edge`` objects or dataclass reprs leak into the output and no
    nondeterministic values are present.
    """
    scopes = build_component_security_scopes(graph)
    return [
        {
            "component_id": s.component.component_id,
            "component_type": s.component.component_type.value,
            "security_behaviors": [
                {"source": src, "edge_type": et, "target": tgt}
                for src, et, tgt in s.security_behaviors
            ],
        }
        for s in scopes
    ]


@dataclass(frozen=True)
class ComponentPathParticipation:
    """The explicit security behaviors of one component that are ACTUALLY
    present on one finalized :class:`~veyra.graph.path.AttackPath`.

    This is the first security-analysis consumer of component scope: a narrower
    projection than :class:`ComponentSecurityScope`. A component participates in
    a path iff there is an explicit ``ComponentContextAssociation`` for that
    component whose referenced security-behavior edge is an actual edge
    (``path.edges`` or ``path.associated_edges``) of that specific AttackPath.

    GRAPH MEMBERSHIP != ATTACK-PATH PARTICIPATION: an association whose edge
    exists in the graph but not in a particular path does NOT make the component
    participate in that path.

    Additive metadata only: it never mutates the AttackPath and is excluded from
    path_id / canonical_identity / attack_type / severity / confidence /
    risk_score / evidence / breakpoints / policy ids.
    """

    component: ComponentContext
    path_id: str
    security_behaviors: Tuple[Tuple[str, str, str], ...] = ()


def _validate_context_for(
    context: Sequence[ComponentContextAssociation],
    valid_components: Dict[str, NodeType],
    existing_edges: set,
) -> None:
    """Validate explicit context metadata deterministically, mirroring the
    existing association semantics.

    - component must be a declared component (AGENT/SKILL/TOOL/MCPSERVER);
    - referenced security-behavior edge must actually exist;
    - component type must be one of the four component types.

    Raises ``ComponentContextError`` on invalid/stale metadata. The caller must
    supply ``valid_components`` (allowed component node ids -> their types) and
    ``existing_edges`` (set of (source, target, edge_type_string) that exist in
    the graph). This never mutates anything.
    """
    for a in context:
        # ComponentContext already validates type in __post_init__; re-check
        # defense-in-depth so a raw association never sneaks an unsupported type.
        ctype = a.component.component_type
        if not isinstance(ctype, NodeType) or ctype not in _CONTEXT_COMPONENT_TYPES:
            raise ComponentContextError(
                f"unsupported context component type "
                f"{getattr(ctype, 'value', ctype)!r}; "
                f"allowed: {sorted(t.value for t in _CONTEXT_COMPONENT_TYPES)}"
            )
        if a.component.component_id not in valid_components:
            raise ComponentContextError(
                f"component '{a.component.component_id}' does not exist in the graph"
            )
        if valid_components[a.component.component_id] != ctype:
            raise ComponentContextError(
                f"component type mismatch: '{a.component.component_id}' is "
                f"{valid_components[a.component.component_id].value}, not "
                f"{ctype.value}"
            )
        # edge_key[2] is an EdgeType (validated in __post_init__).
        s, t, et = a.edge_key
        edge_key3 = (s, t, et.value)
        if edge_key3 not in existing_edges:
            raise ComponentContextError(
                f"security behavior edge ({s}, {t}, {et.value}) referenced "
                f"by component context does not exist in the graph"
            )


def build_component_path_participation(
    path,
    context: Sequence[ComponentContextAssociation],
    valid_components: Optional[Dict[str, NodeType]] = None,
    existing_edges: Optional[set] = None,
) -> List[ComponentPathParticipation]:
    """Build deterministic component path participation for one AttackPath.

    A component participates iff there is an explicit association for it and the
    associated security-behavior edge (``path.edges`` or ``path.associated_edges``)
    is an actual edge of this path. Only explicit context metadata drives
    participation — never USES/CONTAINS/CALLS/TRUSTS/HANDOFF, file paths, node
    ids, labels, provenance, findings, naming, graph proximity, or containment.

    ``valid_components`` / ``existing_edges`` (optional) describe the graph the
    context was validated against; when omitted, associations are only checked
    against the path itself (a caller-provided graph must already have rejected
    stale context). If provided, stale metadata raises ``ComponentContextError``.

    Read-only: never mutates the path, the graph, or the associations.
    """
    if path is None or context is None:
        return []
    # Use the already-finalized path_id; never invent one.
    if not path.path_id:
        raise ComponentContextError(
            f"cannot build path participation without a finalized path_id"
        )
    if valid_components is not None and existing_edges is not None:
        _validate_context_for(context, valid_components, existing_edges)

    # path.edges / associated_edges store edge types as plain strings.
    path_edge_keys = {(s, t, et) for s, t, et in path.edges}
    assoc_edge_keys = {(s, t, et) for s, t, et in path.associated_edges}

    components: Dict[Tuple[str, str], ComponentContext] = {}
    behaviors: Dict[Tuple[str, str], List[Tuple[str, str, str]]] = {}
    for a in context:
        src, tgt, et = a.edge_key
        edge_key3 = (src, tgt, et.value)
        # Only participates if the referenced edge is actually on THIS path.
        if edge_key3 not in path_edge_keys and edge_key3 not in assoc_edge_keys:
            continue
        ckey = (a.component.component_id, a.component.component_type.value)
        components.setdefault(ckey, a.component)
        behavior = (src, et.value, tgt)
        bucket = behaviors.setdefault(ckey, [])
        if behavior not in bucket:
            bucket.append(behavior)

    participations: List[ComponentPathParticipation] = []
    for ckey in sorted(behaviors.keys()):
        ordered = tuple(sorted(behaviors[ckey], key=lambda b: (b[0], b[1], b[2])))
        participations.append(
            ComponentPathParticipation(
                component=components[ckey],
                path_id=path.path_id,
                security_behaviors=ordered,
            )
        )
    participations.sort(
        key=lambda p: (p.path_id, p.component.component_type.value, p.component.component_id)
    )
    return participations


def build_component_path_participation_for_paths(
    paths: Sequence,
    context: Sequence[ComponentContextAssociation],
    valid_components: Optional[Dict[str, NodeType]] = None,
    existing_edges: Optional[set] = None,
) -> List[ComponentPathParticipation]:
    """Build deterministic component path participation across many AttackPaths.

    Processes paths deterministically, preserves every explicitly associated
    participating component, deduplicates identical
    ``(path_id, component, security_behavior)``, never merges unrelated paths,
    and returns deterministic ordering: ``(path_id, component_type,
    component_id, source, edge_type, target)``.
    """
    if not paths or context is None:
        return []
    if valid_components is not None and existing_edges is not None:
        _validate_context_for(context, valid_components, existing_edges)
    # Flatten (path, behavior) across all paths, deduplicating identical
    # (path_id, component, behavior); never merges unrelated paths.
    entries: List[Tuple[ComponentPathParticipation, Tuple[str, str, str]]] = []
    seen: set = set()
    for path in paths:
        if not path.path_id:
            raise ComponentContextError(
                f"cannot build path participation without a finalized path_id"
            )
        for p in build_component_path_participation(path, context):
            for behavior in p.security_behaviors:
                key = (p.path_id, p.component.component_id,
                        p.component.component_type.value, behavior)
                if key in seen:
                    continue
                seen.add(key)
                entries.append((p, behavior))
    # Deterministic global ordering: (path_id, component_type, component_id,
    # source, edge_type, target).
    entries.sort(
        key=lambda pb: (
            pb[0].path_id,
            pb[0].component.component_type.value,
            pb[0].component.component_id,
            pb[1][0], pb[1][1], pb[1][2],
        )
    )
    grouped: List[ComponentPathParticipation] = []
    idx = 0
    while idx < len(entries):
        p, behavior = entries[idx]
        comp_key = (p.path_id, p.component.component_id, p.component.component_type.value)
        group_behaviors = [behavior]
        j = idx + 1
        while j < len(entries):
            p2, b2 = entries[j]
            if (p2.path_id, p2.component.component_id, p2.component.component_type.value) == comp_key:
                group_behaviors.append(b2)
                j += 1
            else:
                break
        grouped.append(
            ComponentPathParticipation(
                component=p.component,
                path_id=p.path_id,
                security_behaviors=tuple(group_behaviors),
            )
        )
        idx = j
    return grouped


def serialize_component_path_participation(
    participations: Sequence[ComponentPathParticipation],
) -> List[Dict[str, Any]]:
    """Deterministic, JSON-safe serialization of component path participation.

    Returns a list of dicts shaped ``{"path_id", "component_id",
    "component_type", "security_behaviors": [{"source", "edge_type",
    "target"}, ...]}``. No Enum/Edge objects, dataclass reprs, memory addresses,
    or nondeterministic fields leak into the output.
    """
    return [
        {
            "path_id": p.path_id,
            "component_id": p.component.component_id,
            "component_type": p.component.component_type.value,
            "security_behaviors": [
                {"source": src, "edge_type": et, "target": tgt}
                for src, et, tgt in p.security_behaviors
            ],
        }
        for p in participations
    ]


@dataclass(frozen=True)
class ComponentPathCompositionEntry:
    """One explicitly participating component within a path composition.

    ``component`` is the explicitly declared participating component and
    ``behaviors`` is the deterministic tuple of that component's proven security
    behaviors actually present on the path. Plain string edge types only — never
    ``Edge`` objects and no mutable collections inside the frozen dataclass.
    """

    component: ComponentContext
    behaviors: Tuple[Tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class ComponentPathComposition:
    """Deterministic path-level grouping of the explicitly participating
    components in one finalized AttackPath and their proven security behaviors.

    This is an analytical projection over an already-finalized AttackPath plus
    explicit ComponentContextAssociation metadata. It is NOT ownership
    inference, NOT a new attack type, NOT a new graph edge, and NOT a
    replacement for AttackPath. COMPONENT PATH COMPOSITION DOES NOT CREATE
    COMPONENT RELATIONSHIPS: it never invents a component-to-component edge.
    """

    path_id: str
    components: Tuple[ComponentPathCompositionEntry, ...] = ()


def _entry_sort_key(entry: ComponentPathCompositionEntry, path_id: str):
    """Deterministic ordering key for a composition entry.

    Components ordered by ``(path_id, first_behavior_source,
    first_behavior_edge_type, first_behavior_target, component_type,
    component_id)``. An entry's first behavior is its lexicographically smallest.
    """
    first_behavior = min(entry.behaviors) if entry.behaviors else ("", "", "")
    return (
        path_id,
        first_behavior[0],
        first_behavior[1],
        first_behavior[2],
        entry.component.component_type.value,
        entry.component.component_id,
    )


def build_component_path_composition(
    path,
    context: Sequence[ComponentContextAssociation],
    valid_components: Optional[Dict[str, NodeType]] = None,
    existing_edges: Optional[set] = None,
) -> Optional[ComponentPathComposition]:
    """Build a deterministic component path composition for one AttackPath.

    The composition is derived from :func:`build_component_path_participation`
    (the source of truth for participation): only components with actual
    participation are retained. It never infers ownership, responsibility,
    trust, or component-to-component edges.
    """
    if path is None or context is None:
        return None
    if not path.path_id:
        raise ComponentContextError(
            f"cannot build path composition without a finalized path_id"
        )
    participation = build_component_path_participation(
        path, context, valid_components, existing_edges
    )
    if not participation:
        return None
    entries = [
        ComponentPathCompositionEntry(
            component=p.component,
            behaviors=tuple(sorted(p.security_behaviors, key=lambda b: (b[0], b[1], b[2]))),
        )
        for p in participation
    ]
    entries.sort(key=lambda e: _entry_sort_key(e, path.path_id))
    return ComponentPathComposition(path_id=path.path_id, components=tuple(entries))


def build_component_path_composition_for_paths(
    paths: Sequence,
    context: Sequence[ComponentContextAssociation],
    valid_components: Optional[Dict[str, NodeType]] = None,
    existing_edges: Optional[set] = None,
) -> List[ComponentPathComposition]:
    """Build deterministic component path compositions across many AttackPaths.

    Only paths with actual participating components are returned, in
    deterministic path_id order. Never merges unrelated paths.
    """
    if not paths or context is None:
        return []
    if valid_components is not None and existing_edges is not None:
        _validate_context_for(context, valid_components, existing_edges)
    compositions: List[ComponentPathComposition] = []
    for path in paths:
        comp = build_component_path_composition(path, context)
        if comp is not None:
            compositions.append(comp)
    compositions.sort(key=lambda c: c.path_id)
    return compositions


def serialize_component_path_composition(
    compositions: Sequence[ComponentPathComposition],
) -> List[Dict[str, Any]]:
    """Deterministic, JSON-safe serialization of component path compositions.

    Returns a list of dicts shaped ``{"path_id", "components": [
    {"component_id", "component_type", "security_behaviors": [{"source",
    "edge_type", "target"}, ...]}, ...]}``. No Enum/Edge objects, dataclass
    reprs, memory addresses, timestamps, or random identifiers.
    """
    return [
        {
            "path_id": c.path_id,
            "components": [
                {
                    "component_id": e.component.component_id,
                    "component_type": e.component.component_type.value,
                    "security_behaviors": [
                        {"source": src, "edge_type": et, "target": tgt}
                        for src, et, tgt in e.behaviors
                    ],
                }
                for e in c.components
            ],
        }
        for c in compositions
    ]


@dataclass(frozen=True)
class ComponentRiskEvidence:
    """Read-only projection of an existing AttackPath's finalized risk metadata
    onto explicitly participating components.

    It does not redistribute risk, infer ownership, or create component
    responsibility. ``risk_relevant_behaviors`` are exact behavior triples from
    the component's composition entry, ``evidence`` is a deterministic SUBSET of
    the existing AttackPath.evidence vocabulary, and ``risk_severity`` /
    ``risk_confidence`` are copied from the finalized AttackPath (never
    recalculated per component). There is NO component risk score and NO
    responsibility/ownership ranking.
    """

    component: ComponentContext
    path_id: str
    risk_relevant_behaviors: Tuple[Tuple[str, str, str], ...] = ()
    evidence: Tuple[str, ...] = ()
    risk_severity: Severity = Severity.INFO
    risk_confidence: Confidence = Confidence.LOW


# Fixed canonical order for evidence labels (only those actually evidenced and
# present in the finalized AttackPath.evidence are emitted).
_EVIDENCE_ORDER = (
    "secret read",
    "sensitive data read",
    "data transformation",
    "sensitive data flow",
    "external network send",
    "execution",
)


def _node_kind_prefix(node_id: str) -> str:
    """Return the node-type prefix (e.g. 'SECRET', 'DATA') of a semantic id."""
    if ":" in node_id:
        return node_id.split(":", 1)[0]
    return ""


def _evidence_label_for_behavior(
    behavior: Tuple[str, str, str],
) -> Optional[str]:
    """Map a behavior triple to a risk-relevant evidence label, or None.

    Mapping follows the existing AttackPath evidence vocabulary:
    - READS -> SECRET target  => "secret read"
    - READS -> DATA target    => "sensitive data read"
    - READS -> other          => no label
    - FLOWS_TO                => "sensitive data flow"
    - SENDS_TO                => "external network send"
    - EXECUTES                => "execution"
    - WRITES / PRODUCES       => no label
    """
    src, etype, tgt = behavior
    if etype == "READS":
        kind = _node_kind_prefix(tgt)
        if kind == "SECRET":
            return "secret read"
        if kind == "DATA":
            return "sensitive data read"
        return None
    if etype == "FLOWS_TO":
        return "sensitive data flow"
    if etype == "SENDS_TO":
        return "external network send"
    if etype == "EXECUTES":
        return "execution"
    return None


def build_component_risk_evidence(
    path,
    context: Sequence[ComponentContextAssociation],
    valid_components: Optional[Dict[str, NodeType]] = None,
    existing_edges: Optional[set] = None,
) -> List[ComponentRiskEvidence]:
    """Build deterministic component risk evidence for one AttackPath.

    Component participation is sourced from ComponentPathParticipation /
    ComponentPathComposition (the semantic source of truth); only components with
    at least one risk-relevant evidence label are returned. Every returned
    object's ``evidence`` is a subset of ``path.evidence`` and risk severity /
    confidence are copied from the finalized AttackPath without recalculation.
    Never infers ownership, responsibility, or evidence from relationship edges,
    provenance, naming, or file paths.
    """
    if path is None or context is None:
        return []
    if not path.path_id:
        raise ComponentContextError(
            f"cannot build component risk evidence without a finalized path_id"
        )
    # Source of truth: participation (which validates context when supplied).
    participation = build_component_path_participation(
        path, context, valid_components, existing_edges
    )
    if not participation:
        return []
    path_evidence = set(path.evidence)
    results: List[ComponentRiskEvidence] = []
    for p in participation:
        be = {b for b in p.security_behaviors if _evidence_label_for_behavior(b) is not None}
        if not be:
            continue
        relevant = tuple(sorted(be, key=lambda b: (b[0], b[1], b[2])))
        labels = [
            label for label in _EVIDENCE_ORDER
            if label in path_evidence
            and any(_evidence_label_for_behavior(b) == label for b in relevant)
        ]
        results.append(
            ComponentRiskEvidence(
                component=p.component,
                path_id=p.path_id,
                risk_relevant_behaviors=relevant,
                evidence=tuple(labels),
                risk_severity=path.risk_severity,
                risk_confidence=path.risk_confidence,
            )
        )
    results.sort(key=_risk_evidence_sort_key)
    return results


class _ComponentRiskEvidenceEntry:
    """Lightweight adapter so risk-evidence results reuse composition ordering."""

    def __init__(self, r: ComponentRiskEvidence):
        self.component = r.component
        self.behaviors = r.risk_relevant_behaviors


def _risk_evidence_sort_key(r: ComponentRiskEvidence):
    """Deterministic ordering for ComponentRiskEvidence matching composition.

    Components ordered by (path_id, first_behavior_source,
    first_behavior_edge_type, first_behavior_target, component_type,
    component_id).
    """
    return _entry_sort_key(_ComponentRiskEvidenceEntry(r), r.path_id)


def build_component_risk_evidence_for_paths(
    paths: Sequence,
    context: Sequence[ComponentContextAssociation],
    valid_components: Optional[Dict[str, NodeType]] = None,
    existing_edges: Optional[set] = None,
) -> List[ComponentRiskEvidence]:
    """Build deterministic component risk evidence across many AttackPaths.

    Only components with at least one risk-relevant evidence label on a given
    path are returned, in deterministic path_id order. Never merges unrelated
    paths.
    """
    if not paths or context is None:
        return []
    if valid_components is not None and existing_edges is not None:
        _validate_context_for(context, valid_components, existing_edges)
    results: List[ComponentRiskEvidence] = []
    for path in paths:
        results.extend(build_component_risk_evidence(path, context))
    results.sort(key=_risk_evidence_sort_key)
    return results


def serialize_component_risk_evidence(
    risk_evidence: Sequence[ComponentRiskEvidence],
) -> List[Dict[str, Any]]:
    """Deterministic, JSON-safe serialization of component risk evidence.

    Returns a list of dicts shaped ``{"path_id", "component_id",
    "component_type", "risk_relevant_behaviors": [{"source", "edge_type",
    "target"}, ...], "evidence": [...], "risk_severity": "...",
    "risk_confidence": "..."}``. No Enum objects, dataclass reprs, Edge objects,
    timestamps, memory addresses, or random identifiers.
    """
    return [
        {
            "path_id": r.path_id,
            "component_id": r.component.component_id,
            "component_type": r.component.component_type.value,
            "risk_relevant_behaviors": [
                {"source": src, "edge_type": et, "target": tgt}
                for src, et, tgt in r.risk_relevant_behaviors
            ],
            "evidence": list(r.evidence),
            "risk_severity": r.risk_severity.value,
            "risk_confidence": r.risk_confidence.value,
        }
        for r in risk_evidence
    ]


def associate_security_behavior(
    graph: SecurityGraph,
    behavior_edge: Tuple[str, str, EdgeType],
    component: ComponentContext,
    source: Optional[str] = None,
) -> ComponentContextAssociation:
    """Associate an existing security edge with an existing component.

    - All validation happens before any mutation.
    - The referenced security edge must already exist in ``graph`` (no new edge
      is created; the edge count is unchanged).
    - The component must already exist and must be AGENT / SKILL / TOOL /
      MCPSERVER with a matching graph type.
    - Repeated identical associations are idempotent (deduplicated); different
      explicit associations (e.g. the same edge associated with SKILL:A and
      AGENT:B) both survive.
    - No inference is performed: only the supplied component is recorded.

    Returns the recorded association.
    """
    # --- Validate component -------------------------------------------------
    s, t, et = behavior_edge
    _validate_id(s, "edge source")
    _validate_id(t, "edge target")

    if component.component_type not in _CONTEXT_COMPONENT_TYPES:
        raise ComponentContextError(
            f"unsupported context component type {component.component_type.value}"
        )
    if et not in _SECURITY_BEHAVIOR_EDGE_TYPES:
        raise ComponentContextError(
            f"edge type {et.value} is not a security-behavior edge; "
            f"component relationships cannot be context associations"
        )

    node = graph.get_node(component.component_id)
    if node is None:
        raise ComponentContextError(
            f"component '{component.component_id}' does not exist in the graph"
        )
    if node.type != component.component_type:
        raise ComponentContextError(
            f"component type mismatch: '{component.component_id}' is "
            f"{node.type.value}, not {component.component_type.value}"
        )

    # --- Validate behavior edge exists -------------------------------------
    edge_exists = any(
        e.source == s and e.target == t and e.type == et for e in graph.edges
    )
    if not edge_exists:
        raise ComponentContextError(
            f"security behavior edge ({s}, {t}, {et.value}) does not exist in the graph"
        )

    # --- Idempotent add (validation above is side-effect-free) --------------
    context: List[ComponentContextAssociation] = getattr(graph, "_component_context", None)
    if context is None:
        context = []
        graph._component_context = context  # type: ignore[attr-defined]

    existing_keys = {
        (a.edge_key, a.component.component_id, a.source) for a in context
    }
    assoc = ComponentContextAssociation(behavior_edge, component, source)
    key = (assoc.edge_key, assoc.component.component_id, assoc.source)
    if key not in existing_keys:
        context.append(assoc)
    return assoc
