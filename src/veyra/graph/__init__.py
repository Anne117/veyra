"""Security Graph for Veyra.

Models the relationships between AI agent resources (Skills, Tools, MCP
servers, Data, Secrets, Endpoints) and the Actions that connect them. This is a
lightweight, deterministic, additive layer — it does not modify the scanner,
rules, correlation, or Attack Lab.
"""

from veyra.graph.builder import add_handoff, build_from_actions, build_from_findings
from veyra.graph.declarations import (
    ComponentDeclaration,
    ComponentDeclarationError,
    RelationshipDeclaration,
    apply_component_declarations,
)
from veyra.graph.models import (
    Edge,
    EdgeType,
    Node,
    NodeType,
    SecurityGraph,
)
from veyra.graph.path import (
    AttackPath,
    AttackType,
    Breakpoint,
    BreakpointImpact,
    PathAnalyzer,
    assess_risk,
    breakpoints_for,
    canonical_path_identity,
    classify_path,
    path_id_of,
)

__all__ = [
    "build_from_actions",
    "build_from_findings",
    "add_handoff",
    "apply_component_declarations",
    "ComponentDeclaration",
    "ComponentDeclarationError",
    "RelationshipDeclaration",
    "Edge",
    "EdgeType",
    "Node",
    "NodeType",
    "SecurityGraph",
    "AttackPath",
    "AttackType",
    "PathAnalyzer",
    "classify_path",
    "assess_risk",
    "Breakpoint",
    "BreakpointImpact",
    "breakpoints_for",
    "canonical_path_identity",
    "path_id_of",
]
