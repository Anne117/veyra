"""Security Graph builder for Veyra.

Constructs a SecurityGraph from existing scanner data:
  - Findings (from the scanner/correlation layer)
  - Action objects (from step_sequence)

The builder is deterministic, typed, and additive. It never changes the
scanner, rules, correlation, or Attack Lab behavior.

Node identity is SEMANTIC: the same real entity (endpoint URL, sensitive
path, MCP server name) always yields the same node id, regardless of which
rule or finding discovered it. rule_id is carried as edge METADATA only — it
never determines node identity or the semantic relationship.

Semantics are derived from finding TITLE/EVIDENCE, not from enumerating rule
IDs. This means a new detection rule that expresses an existing semantic
concept (reads-secret, executes, sends-to-endpoint, uses-mcp) is handled by
the same detector without modifying the graph builder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from veyra.graph.models import EdgeType, Node, NodeType, SecurityGraph
from veyra.models import Confidence, Finding, Severity

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
    """Path-unique, machine-agnostic component identity."""
    return (file_path or "<unknown>").replace("\\", "/").rstrip("/") or "<unknown>"


def _title(finding: Finding) -> str:
    return (finding.title or "").lower()


def _desc(finding: Finding) -> str:
    return (finding.description or "").lower()


# --- Semantic signal detectors ---------------------------------------------
# Each detector inspects finding TITLE/EVIDENCE (not rule_id) and returns an
# EdgeSpec describing the semantic relationship and how to name the object.

@dataclass
class EdgeSpec:
    signal: str          # stable semantic signal id (metadata, rule-free)
    object_type: NodeType
    edge_type: EdgeType
    resolve: str         # which identity extractor to use: "endpoint"|"secret"|"mcp"|"action"


_EXEC_TITLES = re.compile(
    r"\b(?:command|shell|eval|execution|exec|encoded content executed|dynamic code)\b",
    re.IGNORECASE,
)
_EXFIL_TITLES = re.compile(r"\b(?:exfiltration|source-to-sink)\b", re.IGNORECASE)
_REMOTE_MCP_TITLES = re.compile(r"\bremote mcp execution\b", re.IGNORECASE)


def _detect(finding: Finding) -> Optional[EdgeSpec]:
    """Classify a finding into a semantic EdgeSpec, or None (unsupported)."""
    title = _title(finding)
    desc = _desc(finding)

    # reads-secret: sensitive credential file access.
    if "sensitive credential" in title or "credential" in desc and _extract_secret(finding):
        return EdgeSpec("reads-secret", NodeType.SECRET, EdgeType.READS, "secret")

    # contains-secret: hardcoded secret in source.
    if "hardcoded secret" in title:
        return EdgeSpec("contains-secret", NodeType.SECRET, EdgeType.CONTAINS, "secret")

    # executes: shell/command/encoded execution.
    if _EXEC_TITLES.search(title):
        return EdgeSpec("executes", NodeType.ACTION, EdgeType.EXECUTES, "action")

    # sends-to-endpoint: exfiltration / source-to-sink chains.
    if _EXFIL_TITLES.search(title):
        return EdgeSpec("sends-to-endpoint", NodeType.ENDPOINT, EdgeType.SENDS_TO, "endpoint")

    # trusts-mcp: remote MCP execution chain.
    if _REMOTE_MCP_TITLES.search(title):
        return EdgeSpec("trusts-mcp", NodeType.MCPSERVER, EdgeType.TRUSTS, "mcp")

    # uses-endpoint: external network access / suspicious URL with a URL.
    if _extract_endpoint(finding) and ("network access" in title or "suspicious url" in title or "download and execute" in title):
        return EdgeSpec("uses-endpoint", NodeType.ENDPOINT, EdgeType.USES, "endpoint")

    # uses-mcp: MCP server finding.
    server = _extract_mcp_server(finding)
    if server and "mcp" in desc:
        return EdgeSpec("uses-mcp", NodeType.MCPSERVER, EdgeType.USES, "mcp")

    # contains-action: prompt-injection (manipulative instruction).
    if "prompt injection" in title:
        return EdgeSpec("contains-action", NodeType.ACTION, EdgeType.CONTAINS, "action")

    return None


def _resolve_object_id(spec: EdgeSpec, finding: Finding) -> Optional[str]:
    """Resolve a concrete object node id from a finding, or None."""
    if spec.resolve == "endpoint":
        url = _extract_endpoint(finding)
        return _node_id(NodeType.ENDPOINT, url) if url else None
    if spec.resolve == "secret":
        secret = _extract_secret(finding)
        return _node_id(NodeType.SECRET, secret) if secret else None
    if spec.resolve == "mcp":
        server = _extract_mcp_server(finding)
        return _node_id(NodeType.MCPSERVER, server) if server else None
    return None


def _severity_value(sev: Severity) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(getattr(sev, "value", str(sev)), 2)


def _merge_edge_attributes(existing: Dict[str, Any], finding: Finding) -> Dict[str, Any]:
    """Merge a finding's risk metadata into an edge's attributes, deterministically.

    Preserves a list of contributing rule IDs/files, the highest severity, the
    most confident confidence, and collected evidence snippets.
    """
    existing.setdefault("rule_ids", [])
    existing.setdefault("files", [])
    existing.setdefault("lines", [])
    existing.setdefault("evidence", [])
    existing.setdefault("severity", "LOW")

    rule_ids = list(existing["rule_ids"])
    if finding.rule_id and finding.rule_id not in rule_ids:
        rule_ids.append(finding.rule_id)
    existing["rule_ids"] = rule_ids

    files = list(existing["files"])
    if finding.file and finding.file not in files:
        files.append(finding.file)
    existing["files"] = files

    lines = list(existing["lines"])
    if finding.line and finding.line not in lines:
        lines.append(finding.line)
    existing["lines"] = lines

    if finding.evidence and finding.evidence not in existing["evidence"]:
        existing["evidence"].append(finding.evidence)

    # Highest severity wins (deterministic).
    if _severity_value(finding.severity) > _severity_value(Severity(existing["severity"])):
        existing["severity"] = finding.severity.value

    # Highest confidence wins (deterministic).
    conf_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    existing_conf = existing.get("confidence", "LOW")
    if conf_rank.get(finding.confidence.value, 1) > conf_rank.get(existing_conf, 1):
        existing["confidence"] = finding.confidence.value

    return existing


def build_from_findings(findings: List[Finding], source: str = "<agent>") -> SecurityGraph:
    """Build a SecurityGraph from a list of findings.

    Semantics are derived from finding TITLE/EVIDENCE via `_detect`, independent
    of rule IDs. Node identity is semantic (Commit 1). rule_id, severity and
    confidence are carried as edge METADATA. Duplicate equivalent edges are
    deduplicated by (source, target, edge_type) with aggregated attributes.
    Ambiguous/unsupported findings are preserved as ACTION nodes, never given a
    fabricated semantic relationship.
    """
    graph = SecurityGraph()
    agent_node = graph.get_or_create(
        _node_id(NodeType.AGENT, source),
        NodeType.AGENT,
        label=source,
    )

    # Dedup index: (source, target, edge_type) -> existing Edge.
    edge_index: Dict[tuple, Edge] = {}

    for f in findings:
        spec = _detect(f)
        if spec is None:
            continue

        skill_key = _component_id(f.file)
        skill_node = graph.get_or_create(
            _node_id(NodeType.SKILL, skill_key),
            NodeType.SKILL,
            label=skill_key,
        )
        if skill_node.id != agent_node.id:
            graph.add_edge(agent_node.id, skill_node.id, EdgeType.CONTAINS)

        # Resolve a concrete semantic object identity, if possible.
        object_id = _resolve_object_id(spec, f)

        if object_id is None:
            # No concrete entity identity: preserve the finding as an ACTION
            # node keyed by file:line (rule-free, unique, deterministic).
            object_key = f"{skill_key}:{f.line or 0}:{spec.signal}"
            object_id = _node_id(NodeType.ACTION, object_key)
            graph.get_or_create(object_id, NodeType.ACTION, label=f"{spec.signal} ({spec.edge_type.value})")
        else:
            graph.get_or_create(object_id, spec.object_type, label=object_id.split(":", 1)[1])

        key = (skill_node.id, object_id, spec.edge_type)
        if key in edge_index:
            # Deduplicate: merge findings metadata into the existing edge.
            existing_edge = edge_index[key]
            existing_edge.attributes = _merge_edge_attributes(existing_edge.attributes, f)
            continue

        edge = graph.add_edge(
            skill_node.id,
            object_id,
            spec.edge_type,
            attributes=_merge_edge_attributes({}, f),
        )
        edge_index[key] = edge

    return graph


def build_from_actions(actions: List, subject_id: str = "<agent>") -> SecurityGraph:
    """Build a SecurityGraph from a list of Action objects.

    Actions come from `veyra.step_sequence.Action`. Each action produces
    subject -> object relationships depending on its category:
      SOURCE     : subject READS object
      SENSITIVE  : subject READS object (a Secret/Data)
      TRANSFORM  : subject PRODUCES output, input FLOWS_TO output
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
            graph.add_edge(subject_node.id, out_node.id, EdgeType.PRODUCES)
            graph.add_edge(in_node.id, out_node.id, EdgeType.FLOWS_TO)
        elif cat == "NETWORK" and action.destination:
            dest = action.destination.strip()
            ep_node = graph.get_or_create(
                _node_id(NodeType.ENDPOINT, dest),
                NodeType.ENDPOINT,
                label=dest,
            )
            graph.add_edge(subject_node.id, ep_node.id, EdgeType.SENDS_TO)
            # The action genuinely sends the named object to the endpoint, so
            # record object -> endpoint data flow for object-continuity paths.
            if obj:
                obj_node = graph.get_or_create(
                    _node_id(NodeType.DATA, obj),
                    NodeType.DATA,
                    label=obj,
                )
                graph.add_edge(obj_node.id, ep_node.id, EdgeType.SENDS_TO)
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
