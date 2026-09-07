"""Security Graph builder for Veyra.

Constructs a SecurityGraph from existing scanner data:
  - Findings (from the scanner/correlation layer)
  - Action objects (from step_sequence)

The builder is deterministic, typed, and additive. It never changes the
scanner, rules, correlation, or Attack Lab behavior.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from veyra.graph.models import EdgeType, Node, NodeType, SecurityGraph
from veyra.models import Finding


def _node_id(type_: NodeType, key: str) -> str:
    """Stable node id: <TYPE>:<normalized-key>."""
    return f"{type_.value}:{key}"


# Map rule IDs to (subject node type, object node type, edge type).
# Used to derive graph relationships from findings.
_RULE_GRAPH_MAP: Dict[str, tuple] = {
    # Hardcoded secret in a file -> that file CONTAINS a Secret.
    "AS-001": (NodeType.SKILL, NodeType.SECRET, EdgeType.CONTAINS),
    # Sensitive credential file access -> Skill READS a Secret.
    "AS-006": (NodeType.SKILL, NodeType.SECRET, EdgeType.READS),
    # Encoded content executed -> Skill EXECUTES an Action.
    "AS-007": (NodeType.SKILL, NodeType.ACTION, EdgeType.EXECUTES),
    # Shell execution -> Skill EXECUTES an Action.
    "AS-002": (NodeType.SKILL, NodeType.ACTION, EdgeType.EXECUTES),
    # Network activity -> Skill USES an Endpoint.
    "AS-003": (NodeType.SKILL, NodeType.ENDPOINT, EdgeType.USES),
    # Prompt injection -> Skill CONTAINS an Action (manipulative instruction).
    "AS-004": (NodeType.SKILL, NodeType.ACTION, EdgeType.CONTAINS),
    # Suspicious URL -> Skill USES an Endpoint.
    "AS-005": (NodeType.SKILL, NodeType.ENDPOINT, EdgeType.USES),
    # MCP config findings -> SKILL USES an MCP Server.
    "AS-MCP-001": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-002": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-003": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-004": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-006": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-007": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-008": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.USES),
    # Correlation chains: exfiltration -> Skill SENDS_TO an Endpoint.
    "AS-CHAIN-001": (NodeType.SKILL, NodeType.ENDPOINT, EdgeType.SENDS_TO),
    # Download-and-execute -> Skill FLOWS_TO an Action.
    "AS-CHAIN-002": (NodeType.SKILL, NodeType.ACTION, EdgeType.FLOWS_TO),
    # Remote MCP execution -> Skill TRUSTS an MCP Server.
    "AS-CHAIN-003": (NodeType.SKILL, NodeType.MCPSERVER, EdgeType.TRUSTS),
    # Source-to-sink -> Skill SENDS_TO an Endpoint.
    "AS-CHAIN-004": (NodeType.SKILL, NodeType.ENDPOINT, EdgeType.SENDS_TO),
}


def _subject_key(file_path: str) -> str:
    """Subject node label derived from the source file path."""
    # Use the basename (e.g. SKILL.md) plus a short path hash-free form.
    return file_path.split("/")[-1].split("\\")[-1] or file_path


def build_from_findings(findings: List[Finding], source: str = "<agent>") -> SecurityGraph:
    """Build a SecurityGraph from a list of findings.

    `source` is the top-level subject (default '<agent>'). Each finding is
    mapped through `_RULE_GRAPH_MAP` to a (subject, object, edge) relationship.
    Deterministic: same findings -> same graph.
    """
    graph = SecurityGraph()

    # Top-level agent node.
    agent_node = graph.get_or_create(
        _node_id(NodeType.AGENT, source),
        NodeType.AGENT,
        label=source,
    )

    for f in findings:
        rule = f.rule_id
        if rule not in _RULE_GRAPH_MAP:
            continue

        subject_type, object_type, edge_type = _RULE_GRAPH_MAP[rule]

        # Subject: for the agent-level findings we use the source file as a
        # SKILL node contained by the agent; otherwise fall back to the agent.
        subject_key = _subject_key(f.file) if f.file else source
        subject_node = graph.get_or_create(
            _node_id(subject_type, subject_key),
            subject_type,
            label=subject_key,
        )
        if subject_node.id != agent_node.id:
            graph.add_edge(agent_node.id, subject_node.id, EdgeType.CONTAINS)

        # Object label/key.
        object_key = f"{rule}:{object_type.value}"  # stable, evidence-free key
        object_node = graph.get_or_create(
            _node_id(object_type, object_key),
            object_type,
            label=f"{object_type.value} ({rule})",
        )
        graph.add_edge(subject_node.id, object_node.id, edge_type)

    return graph


def build_from_actions(actions: List, subject_id: str = "<agent>") -> SecurityGraph:
    """Build a SecurityGraph from a list of Action objects.

    Actions come from `veyra.step_sequence.Action`. Each action produces
    subject -> object relationships depending on its category:
      SOURCE     : subject READS object
      SENSITIVE  : subject READS object (a Secret/Data)
      TRANSFORM  : subject PRODUCES output
      NETWORK    : subject SENDS_TO destination (an Endpoint)
      DOWNLOAD   : subject USES endpoint
      EXECUTION  : subject EXECUTES an Action

    Deterministic: same actions -> same graph. Endpoints and data are
    deduplicated by normalized id.
    """
    graph = SecurityGraph()
    subject_node = graph.get_or_create(
        _node_id(NodeType.SKILL, subject_id),
        NodeType.SKILL,
        label=subject_id,
    )

    for action in actions:
        verb = (action.verb or "").lower()
        obj = (action.object or "").strip()
        cat = (action.category or "").upper()

        if cat == "SOURCE":
            obj_node = graph.get_or_create(
                _node_id(NodeType.DATA, obj),
                NodeType.DATA,
                label=obj,
            )
            graph.add_edge(subject_node.id, obj_node.id, EdgeType.READS)
        elif cat == "SENSITIVE":
            obj_node = graph.get_or_create(
                _node_id(NodeType.SECRET, obj),
                NodeType.SECRET,
                label=obj,
            )
            graph.add_edge(subject_node.id, obj_node.id, EdgeType.READS)
        elif cat == "TRANSFORM" and action.output:
            out = action.output.strip()
            out_node = graph.get_or_create(
                _node_id(NodeType.DATA, out),
                NodeType.DATA,
                label=out,
            )
            graph.add_edge(subject_node.id, out_node.id, EdgeType.PRODUCES)
        elif cat == "NETWORK" and action.destination:
            dest = action.destination.strip()
            ep_node = graph.get_or_create(
                _node_id(NodeType.ENDPOINT, dest),
                NodeType.ENDPOINT,
                label=dest,
            )
            graph.add_edge(subject_node.id, ep_node.id, EdgeType.SENDS_TO)
        elif cat == "DOWNLOAD":
            if action.destination:
                dest = action.destination.strip()
                ep_node = graph.get_or_create(
                    _node_id(NodeType.ENDPOINT, dest),
                    NodeType.ENDPOINT,
                    label=dest,
                )
                graph.add_edge(subject_node.id, ep_node.id, EdgeType.USES)
        elif cat == "EXECUTION":
            act_node = graph.get_or_create(
                _node_id(NodeType.ACTION, verb),
                NodeType.ACTION,
                label=verb,
            )
            graph.add_edge(subject_node.id, act_node.id, EdgeType.EXECUTES)

    return graph
