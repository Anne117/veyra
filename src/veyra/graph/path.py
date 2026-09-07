"""Deterministic Attack Path Analyzer for Veyra.

Operates on a :class:`~veyra.graph.models.SecurityGraph` and identifies
security-relevant paths across semantic relationships. It makes NO reference to
AS-* rule IDs — it reasons over NodeType / EdgeType semantics only.

This is the first user-facing security-intelligence layer on top of the graph.
It is intentionally small, deterministic, and framework-agnostic. No database,
no LLM, no runtime analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from veyra.graph.models import Edge, EdgeType, NodeType, SecurityGraph
from veyra.models import Confidence, Severity

# Maximum number of data-flow edges to traverse from a source (bounds cycles).
MAX_PATH_EDGES = 10

# Edge types that move data from one object to another.
_DATA_FLOW_EDGES = {EdgeType.FLOWS_TO, EdgeType.PRODUCES}

# Edge types that represent reading a source object.
_READ_EDGES = {EdgeType.READS}

# Edge types that represent exposing data to an external sink.
_SEND_EDGES = {EdgeType.SENDS_TO, EdgeType.USES}

# Edge types that represent executing something.
_EXEC_EDGES = {EdgeType.EXECUTES}

# Type-based rank for a path's worst (most dangerous) component.
_SEV_RANK = {Severity.CRITICAL.value: 4, Severity.HIGH.value: 3,
             Severity.MEDIUM.value: 2, Severity.LOW.value: 1, Severity.INFO.value: 0}
_CONF_RANK = {Confidence.HIGH.value: 2, Confidence.MEDIUM.value: 1, Confidence.LOW.value: 0}


@dataclass
class AttackPath:
    """A discovered security-relevant path in the graph."""
    # Ordered node ids forming the route.
    nodes: List[str]
    # Ordered edges (source, target, edge_type) forming the route.
    edges: List[Tuple[str, str, str]]
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    title: str = ""
    description: str = ""

    def to_dict(self) -> Dict:
        return {
            "nodes": list(self.nodes),
            "edges": [{"source": s, "target": t, "type": et} for s, t, et in self.edges],
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "description": self.description,
        }


class PathAnalyzer:
    """Enumerate meaningful attack paths in a SecurityGraph.

    The analyzer treats the graph as a real topology:
      - a SKILL READS origin objects (SECRET / DATA),
      - origins FLOW_TO derived DATA objects,
      - a SKILL SENDS_TO / USES external endpoints, and EXECUTES actions.

    A "secret exposure" path connects a read Secret through data-flow to a
    network sink. A "secret + execution" path connects a read Secret to an
    executed action via the shared SKILL.
    """

    def __init__(self, graph: SecurityGraph):
        self.graph = graph
        # Precompute adjacency: node_id -> [outgoing Edge].
        self._adj: Dict[str, List[Edge]] = {nid: [] for nid in graph.nodes}
        for e in graph.edges:
            self._adj.setdefault(e.source, []).append(e)

    # --- Public API ---------------------------------------------------------

    def analyze(self) -> List[AttackPath]:
        """Return all discovered attack paths, deduplicated and deterministically ordered."""
        paths: List[AttackPath] = []
        for skill_id, skill_node in self.graph.nodes.items():
            if skill_node.type != NodeType.SKILL:
                continue
            paths.extend(self._analyze_skill(skill_id))
        return self._dedupe(paths)

    # --- Per-skill analysis -------------------------------------------------

    def _analyze_skill(self, skill_id: str) -> List[AttackPath]:
        # Objects the skill READS (SECRET / DATA) + the read edges.
        origins = self._origins_for_skill(skill_id)
        read_edges = self._read_edges_for_skill(skill_id)

        # Endpoints the skill sends to / uses, and actions it executes.
        send_sinks = self._sinks_for_skill(skill_id, _SEND_EDGES)
        send_edges = self._sink_edges_for_skill(skill_id, _SEND_EDGES)
        exec_sinks = self._sinks_for_skill(skill_id, _EXEC_EDGES)
        exec_edges = self._sink_edges_for_skill(skill_id, _EXEC_EDGES)

        paths: List[AttackPath] = []

        for origin in origins:
            origin_node = self.graph.get_node(origin)
            is_secret = origin_node.type == NodeType.SECRET
            read_edge = read_edges.get(origin)

            # Pattern 3: secret + execution (shared SKILL branches).
            if is_secret and exec_sinks:
                for i, act in enumerate(exec_sinks):
                    if i >= len(exec_edges):
                        break
                    act_edge = exec_edges[i]
                    nodes = [skill_id, origin, act]
                    edges = []
                    if read_edge:
                        edges.append(read_edge)
                    if act_edge:
                        edges.append(act_edge)
                    paths.append(self._make_path(
                        nodes, edges, "execution",
                    ))

            # Patterns 1, 2, 4: origin flows outward to an external endpoint.
            dataflows = self._dataflow_paths(origin)
            for flow in dataflows:
                df_nodes = list(flow.nodes)   # [origin, ..., terminal]
                df_types = list(flow.edges)   # parallel data-flow edge types
                for send_edge in send_edges:
                    ep = send_edge[1]
                    nodes = [skill_id] + df_nodes + [ep]
                    edges: List[Tuple[str, str, str]] = []
                    if read_edge:
                        edges.append(read_edge)
                    # data-flow edges between consecutive df nodes
                    for k in range(len(df_types)):
                        edges.append((df_nodes[k], df_nodes[k + 1], df_types[k]))
                    edges.append(send_edge)
                    paths.append(self._make_path(
                        nodes, edges,
                        "exposure" if is_secret else ("sensitive-data" if len(df_nodes) > 1 else "data"),
                    ))

        return paths

    # --- Edge/neighbor helpers ------------------------------------------------

    def _origins_for_skill(self, skill_id: str) -> List[str]:
        """Return target SECRET/DATA node ids the skill READS, sorted."""
        out: List[str] = []
        for e in self._adj.get(skill_id, []):
            if e.type in _READ_EDGES:
                tgt = self.graph.get_node(e.target)
                if tgt is not None and tgt.type in (NodeType.SECRET, NodeType.DATA):
                    out.append(e.target)
        return _sorted_unique(out)

    def _read_edges_for_skill(self, skill_id: str) -> Dict[str, Tuple[str, str, str]]:
        """Return a map {target -> READS edge} for a skill's read edges."""
        out: Dict[str, Tuple[str, str, str]] = {}
        for e in self._adj.get(skill_id, []):
            if e.type in _READ_EDGES:
                out[e.target] = (skill_id, e.target, e.type.value)
        return out

    def _sinks_for_skill(self, skill_id: str, edge_types: Set[EdgeType]) -> List[str]:
        """Return target node ids of a skill's sink edges of the given types, sorted."""
        out: List[str] = []
        for e in self._adj.get(skill_id, []):
            if e.type in edge_types:
                out.append(e.target)
        return _sorted_unique(out)

    def _sink_edges_for_skill(self, skill_id: str, edge_types: Set[EdgeType]) -> List[Tuple[str, str, str]]:
        """Return matching sink edges of a skill, deduplicated, sorted."""
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

    # --- Bounded data-flow traversal ----------------------------------------

    @dataclass
    class _Flow:
        nodes: List[str]
        edges: List[str]  # edge types between consecutive nodes in `nodes`

    def _dataflow_paths(self, origin: str) -> List["PathAnalyzer._Flow"]:
        """Return all simple data-flow paths from origin (cycle-bounded)."""
        results: List[PathAnalyzer._Flow] = []

        def dfs(node: str, seen: Set[str], edges: List[str]):
            if len(edges) >= MAX_PATH_EDGES:
                # Hitting the bound is still a valid (truncated) data-flow path.
                results.append(PathAnalyzer._Flow(nodes=list(seen), edges=list(edges)))
                return
            progressed = False
            for e in sorted(self._adj.get(node, []), key=lambda x: (x.target, x.type.value)):
                if e.type not in _DATA_FLOW_EDGES:
                    continue
                if e.target in seen:
                    continue  # cycle guard
                progressed = True
                dfs(e.target, seen | {e.target}, edges + [e.type.value])
            if not progressed:
                results.append(PathAnalyzer._Flow(nodes=list(seen), edges=list(edges)))

        dfs(origin, {origin}, [])
        return results

    # --- Path construction ---------------------------------------------------

    def _make_path(self, nodes: List[str], edges: List[Tuple[str, str, str]],
                   kind: str) -> AttackPath:
        if not edges:
            severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        else:
            severity, confidence = self._path_signals(edges)
        title, description = self._describe(kind, nodes, edges)
        return AttackPath(
            nodes=nodes,
            edges=edges,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
        )

    def _path_signals(self, edges: List[Tuple[str, str, str]]) -> Tuple[Severity, Confidence]:
        """Conservative severity/confidence: strongest metadata among edges, else defaults."""
        worst_sev = Severity.MEDIUM
        worst_conf = Confidence.MEDIUM
        for src, tgt, _ in edges:
            for e in self._adj.get(src, []):
                if e.target == tgt:
                    sev = e.attributes.get("severity")
                    if sev and _SEV_RANK.get(sev, 2) > _SEV_RANK[worst_sev.value]:
                        worst_sev = Severity(sev)
                    conf = e.attributes.get("confidence")
                    if conf and _CONF_RANK.get(conf, 1) > _CONF_RANK[worst_conf.value]:
                        worst_conf = Confidence(conf)
                    break
        return worst_sev, worst_conf

    def _describe(self, kind: str, nodes: List[str],
                  edges: List[Tuple[str, str, str]]) -> Tuple[str, str]:
        if kind == "execution":
            title = "Secret access followed by command execution"
            desc = ("A secret is read, and the skill also executes an action. "
                    "This may indicate credentials are used to power a command.")
        elif kind == "exposure":
            title = "Secret exposed to external endpoint"
            desc = ("A secret is read and flows outward to an external endpoint. "
                    "Credentials may be exfiltrated.")
        elif kind == "sensitive-data":
            title = "Sensitive data sent to external endpoint"
            desc = ("Data is read and transformed, then sent outward to an external "
                    "endpoint.")
        else:
            title = "Data exfiltration path"
            desc = "Data is read and sent outward to an external endpoint."
        sink = nodes[-1] if nodes else ""
        return title, desc + f" Route terminates at {sink}."

    # --- Deduplication -------------------------------------------------------

    def _dedupe(self, paths: List[AttackPath]) -> List[AttackPath]:
        """Deduplicate by identical node sequence + edge set; sort deterministically."""
        seen: Set[Tuple[Tuple[str, ...], Tuple[Tuple[str, str, str], ...]]] = set()
        out: List[AttackPath] = []
        for p in paths:
            key = (tuple(p.nodes), tuple(sorted(p.edges)))
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
        out.sort(key=lambda p: (-_SEV_RANK[p.severity.value], p.nodes, tuple(sorted(p.edges))))
        return out


def _sorted_unique(items: List[str]) -> List[str]:
    return sorted(set(items))
