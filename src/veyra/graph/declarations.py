"""Explicit AI-agent ecosystem declaration layer.

This is a deterministic input/declaration API that populates an existing
:class:`~veyra.graph.models.SecurityGraph` with explicitly declared AI
ecosystem components and their relationships. It is NOT a discovery/inference
layer: every node and every edge it creates corresponds to an explicitly
supplied declaration, and it never reads the filesystem, the network, source
text, or natural language.

The supported component node types are only the explicit agent-ecosystem
types (AGENT, SKILL, TOOL, MCPSERVER). Security/data-flow entities (DATA,
SECRET, ENDPOINT, ACTION) remain owned by the existing scanner/builder
pipeline. The supported relationship types are the control/ecosystem
relationships (CONTAINS, USES, CALLS, TRUSTS, HANDOFF); security/data-flow
edges (READS, WRITES, SENDS_TO, EXECUTES, PRODUCES, FLOWS_TO) are never
created here.

TRUSTS and HANDOFF remain control/trust relationships: they are never
reinterpreted as data lineage (never READS/FLOWS_TO/SENDS_TO/EXECUTES), so
declaring them must not create exfiltration semantics.

The layer integrates with existing provenance: a relationship declaration may
optionally carry a ``source`` (e.g. a declaration file), which is recorded on
the resulting edge's ``attributes["files"]``. If no source is supplied,
provenance stays unknown — it is never inferred from node IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from veyra.graph.models import EdgeType, NodeType, SecurityGraph


# --- Supported declaration vocabulary --------------------------------------

class ComponentDeclarationError(ValueError):
    """Raised for an invalid or malformed component/relationship declaration."""


# Component node types this layer may create (agent-ecosystem entities only).
_COMPONENT_NODE_TYPES = {
    NodeType.AGENT,
    NodeType.SKILL,
    NodeType.TOOL,
    NodeType.MCPSERVER,
}

# Relationship edge types this layer may create (control/ecosystem only).
_RELATIONSHIP_EDGE_TYPES = {
    EdgeType.CONTAINS,
    EdgeType.USES,
    EdgeType.CALLS,
    EdgeType.TRUSTS,
    EdgeType.HANDOFF,
}

# Compatibility matrix: source node type -> allowed target node types per edge.
# This is a conservative security-semantic contract; unsupported combinations
# are rejected rather than guessed.
_COMPATIBILITY_MATRIX: Dict[Tuple[NodeType, EdgeType], Tuple[NodeType, ...]] = {
    (NodeType.AGENT, EdgeType.CONTAINS): (NodeType.SKILL,),
    (NodeType.AGENT, EdgeType.USES): (NodeType.SKILL, NodeType.TOOL, NodeType.MCPSERVER),
    (NodeType.AGENT, EdgeType.CALLS): (NodeType.TOOL, NodeType.MCPSERVER),
    (NodeType.AGENT, EdgeType.TRUSTS): (NodeType.SKILL, NodeType.TOOL, NodeType.MCPSERVER),
    (NodeType.SKILL, EdgeType.USES): (NodeType.TOOL, NodeType.MCPSERVER),
    (NodeType.SKILL, EdgeType.CALLS): (NodeType.TOOL, NodeType.MCPSERVER),
    (NodeType.SKILL, EdgeType.TRUSTS): (NodeType.TOOL, NodeType.MCPSERVER),
    (NodeType.TOOL, EdgeType.USES): (NodeType.TOOL,),  # tool chaining is permitted
    (NodeType.AGENT, EdgeType.HANDOFF): (NodeType.AGENT,),
    (NodeType.SKILL, EdgeType.HANDOFF): (NodeType.SKILL,),
}


def _validate_component_type(node_type: NodeType) -> None:
    if node_type not in _COMPONENT_NODE_TYPES:
        raise ComponentDeclarationError(
            f"unsupported component node type {node_type.value}; "
            f"allowed: {sorted(t.value for t in _COMPONENT_NODE_TYPES)}"
        )


def _validate_relationship_type(edge_type: EdgeType) -> None:
    if edge_type not in _RELATIONSHIP_EDGE_TYPES:
        raise ComponentDeclarationError(
            f"unsupported relationship edge type {edge_type.value}; "
            f"allowed: {sorted(e.value for e in _RELATIONSHIP_EDGE_TYPES)}"
        )


def _validate_id(node_id: str) -> str:
    node_id = (node_id or "").strip()
    if not node_id:
        raise ComponentDeclarationError("empty node id")
    return node_id


# --- Declaration models ------------------------------------------------------

@dataclass(frozen=True)
class ComponentDeclaration:
    """An explicit declaration of one agent-ecosystem component.

    ``node_id`` is the semantic identity (e.g. ``AGENT:alice``,
    ``SKILL:checkout``, ``TOOL:curl``, ``MCPSERVER:filesystem``) as stored in
    the existing SecurityGraph. ``node_type`` must be one of AGENT / SKILL /
    TOOL / MCPSERVER. ``label``, ``version``, ``source`` are optional metadata
    recorded on the node's attributes.
    """
    node_id: str
    node_type: NodeType
    label: Optional[str] = None
    version: Optional[str] = None
    source: Optional[str] = None

    def __post_init__(self):
        _validate_component_type(self.node_type)
        validated = _validate_id(self.node_id)
        object.__setattr__(self, "node_id", validated)


@dataclass(frozen=True)
class RelationshipDeclaration:
    """An explicit declaration of a relationship between two declared components.

    ``source_id`` / ``target_id`` must reference node ids from declared
    components. ``edge_type`` must be one of CONTAINS / USES / CALLS / TRUSTS /
    HANDOFF, and the (source_type, edge_type, target_type) combination must be
    supported by the compatibility matrix. ``source`` is optional provenance
    (e.g. the declaration file); it is recorded on the edge's
    ``attributes["files"]`` only when supplied.
    """
    source_id: str
    target_id: str
    edge_type: EdgeType
    source: Optional[str] = None

    def __post_init__(self):
        _validate_relationship_type(self.edge_type)
        sp = _validate_id(self.source_id)
        tp = _validate_id(self.target_id)
        object.__setattr__(self, "source_id", sp)
        object.__setattr__(self, "target_id", tp)
        if sp == tp:
            raise ComponentDeclarationError(
                "self-referential relationships are not supported by the "
                "component declaration layer"
            )


def apply_component_declarations(
    graph: SecurityGraph,
    components: Sequence[ComponentDeclaration],
    relationships: Sequence[RelationshipDeclaration],
) -> None:
    """Deterministically apply component + relationship declarations to a graph.

    Validation happens before any mutation: undeclared relationship endpoints
    and unsupported combinations raise before the graph is touched. Nodes are
    created idempotently (reusing the existing ``get_or_create``), and
    duplicate edges are collapsed so identical declarations never create
    duplicate semantic edges.

    Deterministic and side-effect-free on failure: if any declaration is
    invalid, ``ValueError`` / ``ComponentDeclarationError`` propagates and the
    graph is left unchanged.
    """
    # --- Validate all component declarations first -------------------------
    # Seed component types from already-present graph nodes so relationships
    # can reference components declared in earlier calls (declaration calls are
    # incremental, not all-or-nothing).
    node_metadata: Dict[str, Dict[str, Any]] = {}
    for nid, node in graph.nodes.items():
        if node.type in _COMPONENT_NODE_TYPES:
            node_metadata[nid] = {"node_type": node.type}
    for c in components:
        _validate_component_type(c.node_type)
        cid = _validate_id(c.node_id)
        if cid in node_metadata and node_metadata[cid]["node_type"] != c.node_type:
            raise ComponentDeclarationError(
                f"node id '{cid}' declared twice with different types "
                f"({node_metadata[cid]['node_type'].value} vs {c.node_type.value})"
            )
        node_metadata.setdefault(cid, {"node_type": c.node_type})

    # --- Validate all relationship declarations before mutating ------------
    declared_ids = set(node_metadata.keys())
    edges_to_add: List[Tuple[str, str, EdgeType, Dict[str, Any]]] = []
    for r in relationships:
        _validate_id(r.source_id)
        _validate_id(r.target_id)
        if r.source_id not in declared_ids:
            raise ComponentDeclarationError(
                f"relationship references undeclared source '{r.source_id}'"
            )
        if r.target_id not in declared_ids:
            raise ComponentDeclarationError(
                f"relationship references undeclared target '{r.target_id}'"
            )
        st = node_metadata[r.source_id]["node_type"]
        tt = node_metadata[r.target_id]["node_type"]
        allowed_targets = _COMPATIBILITY_MATRIX.get((st, r.edge_type))
        if allowed_targets is None or tt not in allowed_targets:
            raise ComponentDeclarationError(
                f"unsupported relationship {st.value} --{r.edge_type.value}--> "
                f"{tt.value}"
            )
        attrs: Dict[str, Any] = {}
        if r.source:
            attrs.setdefault("files", []).append(r.source)
        edges_to_add.append((r.source_id, r.target_id, r.edge_type, attrs))

    # --- Mutate (idempotently) ----------------------------------------------
    # The declared node_id is the existing semantic identity (e.g. AGENT:alice);
    # we create it directly, reusing the graph's get_or_create for idempotency.
    # Use the declaration's label/version when supplied (metadata only).
    for c in components:
        cid = c.node_id
        node = graph.get_or_create(cid, c.node_type, label=c.label if c.label else cid)
        if c.version:
            node.attributes["version"] = c.version
        if c.source:
            node.attributes["source"] = c.source

    # Deduplicate edges against BOTH the current graph and this call (idempotent
    # across repeated applications). Keep the first deterministic occurrence;
    # provenance attributes of the first occurrence are retained.
    existing: Dict[Tuple[str, str, str], bool] = {
        (e.source, e.target, e.type.value): True for e in graph.edges
    }
    seen: Dict[Tuple[str, str, str], bool] = {}
    for (src, tgt, et, attrs) in edges_to_add:
        key = (src, tgt, et.value)
        if key in seen or key in existing:
            continue
        seen[key] = True
        graph.add_edge(src, tgt, et, attributes=attrs)
