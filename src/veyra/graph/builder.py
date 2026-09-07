"""Security Graph builder for Veyra.

Constructs a SecurityGraph from existing scanner data:
  - Findings (from the scanner/correlation layer)
  - Action objects (from step_sequence)

The builder is deterministic, typed, and additive. It never changes the
scanner, rules, correlation, or Attack Lab behavior.

Node identity is SEMANTIC: the same real entity (endpoint URL, sensitive
path, MCP server name) always yields the same node id, regardless of which
rule or finding discovered it. When a finding does not carry enough concrete
identity to name a real entity, the finding is preserved as an ACTION node
rather than fabricating a fake endpoint/secret.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from veyra.graph.models import EdgeType, Node, NodeType, SecurityGraph
from veyra.models import Finding

_URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)

# Sensitive-path patterns used to derive a concrete SECRET identity.
_SECRET_PATH = re.compile(
    r"(?:\.env\b|\.aws\S*|\.ssh\S*|credentials\S*|id_rsa|id_ed25519|\.pem\b|\.key\b)",
    re.IGNORECASE,
)

# MCP server name extraction: description like "MCP server 'filesystem' ...".
_MCP_SERVER_NAME = re.compile(r"server\s+'([^']+)'", re.IGNORECASE)


def _node_id(type_: NodeType, key: str) -> str:
    """Stable node id: <TYPE>:<normalized-key>."""
    return f"{type_.value}:{key}"


def _extract_endpoint(finding: Finding) -> Optional[str]:
    """Extract a concrete endpoint URL from a finding, or None."""
    # Look first in matched_text (the exact source line), then evidence.
    for text in (getattr(finding, "matched_text", "") or "", finding.evidence or ""):
        m = _URL.search(text)
        if m:
            return m.group(0)
    return None


def _extract_secret(finding: Finding) -> Optional[str]:
    """Extract a concrete sensitive-path secret identity, or None."""
    for text in (getattr(finding, "matched_text", "") or "", finding.evidence or ""):
        m = _SECRET_PATH.search(text)
        if m:
            return m.group(0).lower()
    return None


def _extract_mcp_server(finding: Finding) -> Optional[str]:
    """Extract a concrete MCP server name from a finding description, or None."""
    m = _MCP_SERVER_NAME.search(finding.description or "")
    if m:
        return m.group(1)
    return None


def _component_id(file_path: str) -> str:
    """Path-unique, machine-agnostic component identity.

    Normalizes separators and resolves the full given path so that
    service-a/critical.py and service-b/critical.py remain distinct nodes.
    """
    return (file_path or "<unknown>").replace("\\", "/").rstrip("/") or "<unknown>"


# Map rule ID -> (object node type, edge type) for the FINDING's semantics.
# Node identity comes from _extract_* helpers, NOT from the rule ID.
_RULE_EDGE_MAP: Dict[str, tuple] = {
    "AS-001": (NodeType.SECRET, EdgeType.CONTAINS),
    "AS-006": (NodeType.SECRET, EdgeType.READS),
    "AS-007": (NodeType.ACTION, EdgeType.EXECUTES),
    "AS-002": (NodeType.ACTION, EdgeType.EXECUTES),
    "AS-003": (NodeType.ENDPOINT, EdgeType.USES),
    "AS-004": (NodeType.ACTION, EdgeType.CONTAINS),
    "AS-005": (NodeType.ENDPOINT, EdgeType.USES),
    "AS-MCP-001": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-002": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-003": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-004": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-006": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-007": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-MCP-008": (NodeType.MCPSERVER, EdgeType.USES),
    "AS-CHAIN-001": (NodeType.ENDPOINT, EdgeType.SENDS_TO),
    "AS-CHAIN-002": (NodeType.ACTION, EdgeType.FLOWS_TO),
    "AS-CHAIN-003": (NodeType.MCPSERVER, EdgeType.TRUSTS),
    "AS-CHAIN-004": (NodeType.ENDPOINT, EdgeType.SENDS_TO),
}


def build_from_findings(findings: List[Finding], source: str = "<agent>") -> SecurityGraph:
    """Build a SecurityGraph from a list of findings.

    `source` is the top-level subject (default '<agent>'). Each finding is
    mapped through `_RULE_EDGE_MAP` using a SEMANTIC object identity extracted
    from the finding. If no concrete identity can be extracted, the finding is
    preserved as an ACTION node (rule-free key) rather than fabricating a fake
    endpoint/secret. Deterministic: same findings -> same graph.
    """
    graph = SecurityGraph()

    agent_node = graph.get_or_create(
        _node_id(NodeType.AGENT, source),
        NodeType.AGENT,
        label=source,
    )

    for f in findings:
        rule = f.rule_id
        if rule not in _RULE_EDGE_MAP:
            continue

        object_type, edge_type = _RULE_EDGE_MAP[rule]

        # Component (skill) identity is the full normalized path.
        skill_key = _component_id(f.file)
        skill_node = graph.get_or_create(
            _node_id(NodeType.SKILL, skill_key),
            NodeType.SKILL,
            label=skill_key,
        )
        if skill_node.id != agent_node.id:
            graph.add_edge(agent_node.id, skill_node.id, EdgeType.CONTAINS)

        # Resolve a concrete semantic identity for the object, if possible.
        object_id = None
        object_label = ""
        if object_type == NodeType.ENDPOINT:
            url = _extract_endpoint(f)
            if url:
                object_id = _node_id(NodeType.ENDPOINT, url)
                object_label = url
        elif object_type == NodeType.SECRET:
            secret = _extract_secret(f)
            if secret:
                object_id = _node_id(NodeType.SECRET, secret)
                object_label = secret
        elif object_type == NodeType.MCPSERVER:
            server = _extract_mcp_server(f)
            if server:
                object_id = _node_id(NodeType.MCPSERVER, server)
                object_label = server

        if object_id is None:
            # No concrete entity identity: preserve the finding as an ACTION
            # node keyed by file:line (rule-free, unique, deterministic).
            action_key = f"{skill_key}:{f.line or 0}:{edge_type.value}"
            object_id = _node_id(NodeType.ACTION, action_key)
            object_label = f"{rule} ({edge_type.value})"
            if object_id not in graph.nodes:
                graph.get_or_create(object_id, NodeType.ACTION, label=object_label)
            graph.add_edge(skill_node.id, object_id, edge_type)
            continue

        object_node = graph.get_or_create(object_id, object_type, label=object_label)
        graph.add_edge(skill_node.id, object_id, edge_type)

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
        elif cat == "TRANSFORM" and action.object and action.output:
            obj = action.object.strip()
            out = action.output.strip()
            # The input object (DATA) is transformed into the output object.
            in_node = graph.get_or_create(
                _node_id(NodeType.DATA, obj),
                NodeType.DATA,
                label=obj,
            )
            out_node = graph.get_or_create(
                _node_id(NodeType.DATA, out),
                NodeType.DATA,
                label=out,
            )
            # Subject produces the output...
            graph.add_edge(subject_node.id, out_node.id, EdgeType.PRODUCES)
            # ...and the input FLOWS_TO the output (data-flow relationship).
            graph.add_edge(in_node.id, out_node.id, EdgeType.FLOWS_TO)
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
