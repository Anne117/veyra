"""Security Graph models for Veyra.

A directed, deterministic graph that models how AI agent resources relate:
Skills, Tools, MCP servers, Data, Secrets, Endpoints, and the Actions that
connect them. This is a lightweight in-memory model — no database, no runtime
monitoring, no external API, no LLM.

This module is additive: it does not modify the scanner, rules, correlation
layer, or Attack Lab.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeType(str, Enum):
    AGENT = "AGENT"
    SKILL = "SKILL"
    TOOL = "TOOL"
    MCPSERVER = "MCPSERVER"
    DATA = "DATA"
    SECRET = "SECRET"
    ENDPOINT = "ENDPOINT"
    ACTION = "ACTION"


class EdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    USES = "USES"
    CALLS = "CALLS"
    READS = "READS"
    WRITES = "WRITES"
    SENDS_TO = "SENDS_TO"
    EXECUTES = "EXECUTES"
    PRODUCES = "PRODUCES"
    FLOWS_TO = "FLOWS_TO"
    TRUSTS = "TRUSTS"


@dataclass
class Node:
    """A single entity in the security graph."""
    id: str
    type: NodeType
    label: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "attributes": dict(self.attributes),
        }


@dataclass
class Edge:
    """A directed relationship between two nodes."""
    source: str
    target: str
    type: EdgeType
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "attributes": dict(self.attributes),
        }


@dataclass
class SecurityGraph:
    """A deterministic directed graph of nodes and edges."""
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        """Add or replace a node by id. Returns the node."""
        self.nodes[node.id] = node
        return node

    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def get_or_create(self, node_id: str, node_type: NodeType, label: str = "") -> Node:
        """Return an existing node or create it."""
        node = self.nodes.get(node_id)
        if node is not None:
            return node
        node = Node(id=node_id, type=node_type, label=label)
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Edge:
        """Add an edge. Both endpoints must exist (they are not auto-created)."""
        if source not in self.nodes:
            raise KeyError(f"Missing source node: {source}")
        if target not in self.nodes:
            raise KeyError(f"Missing target node: {target}")
        edge = Edge(
            source=source,
            target=target,
            type=edge_type,
            attributes=attributes or {},
        )
        self.edges.append(edge)
        return edge

    def neighbors(self, node_id: str) -> List[Edge]:
        """Return all edges originating from a node (its out-edges)."""
        return [e for e in self.edges if e.source == node_id]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }
