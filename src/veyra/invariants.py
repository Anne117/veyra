"""Assertion layer: an AttackPath may not claim more than it proves.

The pipeline builds findings, a security graph, attack paths, policy results
and finally a report. Each layer can, on its own, be internally consistent
while the assembled chain lies: a path with no ``path_id`` (so its policy
result points at nothing), an edge that exists only in the path list (never in
the graph), a policy ``violated=True`` resting on a walk with no proven
semantics, or a declared severity stronger than the walk establishes (HIGH on
a correlation-only path). A report built from that chain looks authoritative
and is not.

This module is the single place that states those invariants as executable
checks. It is deliberately independent of the layers it audits:

- identity is re-derived with :func:`path_id_of` from the path's own
  nodes/edges, never read back from the path;
- the severity/confidence ceiling is a fixed table in this file, not the risk
  model's own return value, so a change to the risk model cannot silently move
  the ceiling with it;
- "real node/edge" is decided against the graph the path was derived from.

The checks raise :class:`ProvenanceInvariantError` (a subclass of
``AssertionError``) and never repair anything. Repair belongs to the producer
(see ``assess_risk`` for the one-sided severity clamp); an auditor that quietly
fixes its subject can no longer be trusted to report a defect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from veyra.graph.path import path_id_of
from veyra.models import Confidence, Severity

_SEV_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}
_CONF_RANK = {
    Confidence.LOW.value: 0,
    Confidence.MEDIUM.value: 1,
    Confidence.HIGH.value: 2,
}

# The strongest severity/confidence each attack type can PROVE. Anything above
# the ceiling is an unsupported claim, not a finding: a correlation proves that
# a secret was read and an action executed by the same skill (MEDIUM), a
# continuous object flow proves exfiltration (HIGH/CRITICAL), and a walk with no
# classified semantics proves nothing at all (INFO/LOW).
PROVEN_CEILING: Dict[str, Tuple[Severity, Confidence]] = {
    "UNKNOWN": (Severity.INFO, Confidence.LOW),
    "CORRELATED_SECRET_EXECUTION": (Severity.MEDIUM, Confidence.MEDIUM),
    "DATA_EXFILTRATION": (Severity.HIGH, Confidence.HIGH),
    "SECRET_EXFILTRATION": (Severity.CRITICAL, Confidence.HIGH),
}


class ProvenanceInvariantError(AssertionError):
    """Raised when a path or policy result claims more than it proves."""

    def __init__(self, violations: Sequence["Violation"]):
        self.violations = list(violations)
        lines = [str(v) for v in self.violations]
        super().__init__(
            f"{len(self.violations)} provenance invariant violation(s):\n  "
            + "\n  ".join(lines)
        )


@dataclass(frozen=True)
class Violation:
    """One broken invariant, with the subject it was observed on."""

    kind: str
    subject: str
    detail: str

    def __str__(self) -> str:  # deterministic, no host paths
        return f"[{self.kind}] {self.subject}: {self.detail}"

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "subject": self.subject, "detail": self.detail}


def _graph_index(graph: Any) -> Tuple[Set[str], Set[Tuple[str, str, str]]]:
    """Real node ids and real (source, target, type) edges of ``graph``."""
    nodes = set(getattr(graph, "nodes", {}) or {})
    edges: Set[Tuple[str, str, str]] = set()
    for e in getattr(graph, "edges", []) or []:
        etype = getattr(e, "type", None)
        etype = getattr(etype, "value", etype)
        edges.add((e.source, e.target, etype))
    return nodes, edges


def check_attack_paths(
    paths: Iterable[Any],
    graph: Any = None,
) -> List[Violation]:
    """Audit every path's identity, walk reality and declared strength.

    ``graph`` is optional: when supplied, every walk node and every walk /
    associated edge must exist in it. Without a graph the identity, contiguity
    and strength checks still run.
    """
    materialized = list(paths)
    real_nodes: Optional[Set[str]] = None
    real_edges: Optional[Set[Tuple[str, str, str]]] = None
    if graph is not None:
        real_nodes, real_edges = _graph_index(graph)

    out: List[Violation] = []
    for p in materialized:
        pid = getattr(p, "path_id", "")
        subject = pid or "<no path_id>"

        # 1. Identity must exist and be the identity of this very walk.
        expected = path_id_of(list(p.nodes), list(p.edges), list(p.associated_edges))
        if not pid:
            out.append(Violation("missing_path_id", subject,
                                 "path carries no path_id; nothing can reference it"))
        elif pid != expected:
            out.append(Violation("path_id_mismatch", subject,
                                 "path_id does not match its own nodes/edges"))

        # 2. The walk must be a contiguous walk over its own nodes.
        if not p.is_contiguous:
            out.append(Violation("non_contiguous_walk", subject,
                                 "edges do not form a walk over nodes"))

        # 3. Every referenced node and edge must exist in the graph.
        if real_nodes is not None and real_edges is not None:
            for node in p.nodes:
                if node not in real_nodes:
                    out.append(Violation("phantom_node", subject,
                                         f"node {node!r} is not in the graph"))
            for (src, tgt, etype) in list(p.edges) + list(p.associated_edges):
                if (src, tgt, etype) not in real_edges:
                    out.append(Violation("phantom_edge", subject,
                                         f"edge {src!r} -{etype}-> {tgt!r} "
                                         "is not in the graph"))

        # 4. Declared strength may not exceed what the attack type proves.
        ceiling_sev, ceiling_conf = PROVEN_CEILING.get(
            getattr(p.attack_type, "value", str(p.attack_type)),
            PROVEN_CEILING["UNKNOWN"],
        )
        declared_sev = getattr(getattr(p, "severity", None), "value",
                               str(getattr(p, "severity", "")))
        declared_conf = getattr(getattr(p, "confidence", None), "value",
                                str(getattr(p, "confidence", "")))
        if _SEV_RANK.get(declared_sev, 0) > _SEV_RANK[ceiling_sev.value]:
            out.append(Violation("unproven_severity", subject,
                                 f"declared {declared_sev} > proven ceiling "
                                 f"{ceiling_sev.value} for "
                                 f"{getattr(p.attack_type, 'value', '?')}"))
        if _CONF_RANK.get(declared_conf, 0) > _CONF_RANK[ceiling_conf.value]:
            out.append(Violation("unproven_confidence", subject,
                                 f"declared {declared_conf} > proven ceiling "
                                 f"{ceiling_conf.value} for "
                                 f"{getattr(p.attack_type, 'value', '?')}"))

        # 5. Risk severity may not exceed the same ceiling either: the risk
        #    model is part of the assertion surface, not above it.
        risk_sev = getattr(getattr(p, "risk_severity", None), "value",
                           str(getattr(p, "risk_severity", "")))
        if _SEV_RANK.get(risk_sev, 0) > _SEV_RANK[ceiling_sev.value]:
            out.append(Violation("risk_above_ceiling", subject,
                                 f"risk_severity {risk_sev} > proven ceiling "
                                 f"{ceiling_sev.value}"))

        # 6. A risky verdict needs at least one stated, path-backed fact.
        if _SEV_RANK.get(risk_sev, 0) > 0 and not list(getattr(p, "evidence", []) or []):
            out.append(Violation("severity_without_evidence", subject,
                                 f"risk_severity {risk_sev} with no evidence"))

    out.sort(key=lambda v: (v.kind, v.subject, v.detail))
    return out


def check_policy_results(
    paths: Iterable[Any],
    results: Iterable[Any],
) -> List[Violation]:
    """Audit that every policy result points at a real, proven path."""
    materialized = list(paths)
    by_id = {getattr(p, "path_id", ""): p for p in materialized if getattr(p, "path_id", "")}
    out: List[Violation] = []
    seen: Set[Tuple[str, str]] = set()
    for r in results:
        pid = getattr(r, "path_id", "")
        policy_id = getattr(r, "policy_id", "")
        subject = f"{policy_id}@{pid or '<no path_id>'}"
        if not pid:
            out.append(Violation("result_without_path_id", subject,
                                 "policy result has no path_id"))
            continue
        path = by_id.get(pid)
        if path is None:
            out.append(Violation("orphan_policy_result", subject,
                                 "path_id does not resolve to any evaluated path"))
            continue
        if (policy_id, pid) in seen:
            out.append(Violation("duplicate_policy_result", subject,
                                 "same (policy_id, path_id) evaluated twice"))
        seen.add((policy_id, pid))
        if getattr(r, "violated", False):
            value = getattr(getattr(path, "attack_type", None), "value",
                            str(getattr(path, "attack_type", "")))
            if value == "UNKNOWN":
                out.append(Violation("violation_without_proof", subject,
                                     "violated=True on a path with no proven "
                                     "attack semantics"))
            if not (getattr(r, "reason", "") or "").strip():
                out.append(Violation("violation_without_reason", subject,
                                     "violated=True with an empty reason"))
    out.sort(key=lambda v: (v.kind, v.subject, v.detail))
    return out


def check_provenance(
    paths: Iterable[Any],
    results: Iterable[Any] = (),
    graph: Any = None,
) -> List[Violation]:
    """Every violation across paths and policy results (deterministically ordered)."""
    materialized = list(paths)
    violations = check_attack_paths(materialized, graph=graph)
    violations.extend(check_policy_results(materialized, list(results)))
    violations.sort(key=lambda v: (v.kind, v.subject, v.detail))
    return violations


def assert_provenance(
    paths: Iterable[Any],
    results: Iterable[Any] = (),
    graph: Any = None,
) -> None:
    """Raise :class:`ProvenanceInvariantError` if any invariant is broken."""
    violations = check_provenance(paths, results, graph=graph)
    if violations:
        raise ProvenanceInvariantError(violations)
