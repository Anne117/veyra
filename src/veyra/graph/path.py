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

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

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


@dataclass
class AttackPath:
    """A discovered security-relevant path in the graph.

    ``edge`` list is always a contiguous walk over ``nodes``.
    ``associated_edges`` hold shared-skill correlation edges (e.g. the Secret
    read for a ``Secret + execution`` path) that are NOT part of the linear
    walk and therefore never pretend to connect consecutive walk nodes.
    """
    nodes: List[str]
    edges: List[Tuple[str, str, str]]
    associated_edges: List[Tuple[str, str, str]] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    title: str = ""
    description: str = ""

    @property
    def is_contiguous(self) -> bool:
        """True iff edges form a valid walk over nodes."""
        if len(self.nodes) != len(self.edges) + 1:
            return False
        for i, (s, t, _) in enumerate(self.edges):
            if s != self.nodes[i] or t != self.nodes[i + 1]:
                return False
        return True

    def to_dict(self) -> Dict:
        return {
            "nodes": list(self.nodes),
            "edges": [{"source": s, "target": t, "type": et} for s, t, et in self.edges],
            "associated_edges": [{"source": s, "target": t, "type": et} for s, t, et in self.associated_edges],
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "description": self.description,
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

    def analyze(self) -> List[AttackPath]:
        """Return all discovered attack paths, deduplicated and deterministically ordered."""
        paths: List[AttackPath] = []
        for skill_id, skill_node in self.graph.nodes.items():
            if skill_node.type != NodeType.SKILL:
                continue
            paths.extend(self._analyze_skill(skill_id))
        return self._dedupe(paths)

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

    def _analyze_skill(self, skill_id: str) -> List[AttackPath]:
        paths: List[AttackPath] = []
        read_origins = self._read_origins(skill_id)
        exec_edges = self._skill_edges(skill_id, _EXEC_EDGES)

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
        if kind == "execution":
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
        """Deduplicate by identical node/edge/associated sequences; sort deterministically."""
        seen: Set[Tuple[Tuple[str, ...], Tuple[Tuple[str, str, str], ...],
                        Tuple[Tuple[str, str, str], ...]]] = set()
        out: List[AttackPath] = []
        for p in paths:
            key = (tuple(p.nodes), tuple(p.edges), tuple(p.associated_edges))
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
        out.sort(key=lambda p: (-_SEV_RANK[p.severity.value], p.nodes,
                                tuple(p.edges), tuple(p.associated_edges)))
        return out
