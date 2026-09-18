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
