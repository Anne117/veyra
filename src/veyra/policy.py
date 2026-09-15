"""Deterministic AttackPath Policy Engine for Veyra.

Policies evaluate EXISTING :class:`~veyra.graph.path.AttackPath` objects. The
Policy Engine does NOT perform graph traversal, does NOT discover attacks, does
NOT infer missing semantics, and does NOT use an LLM. It only answers: "Does
this already-classified semantic attack path violate this policy?"

A policy consumes the AttackPath's proven semantic ``attack_type``. It never
inspects rule IDs, finding text, source code, filenames, arbitrary strings,
graph adjacency, or severity/title text. The AttackPath Analyzer already
decides whether SECRET_EXFILTRATION / DATA_EXFILTRATION /
CORRELATED_SECRET_EXECUTION is proven; the policy layer simply reacts to that
semantic.

Deterministic: enabled policies always produce the same PolicyResults for the
same paths, in a stable order (policy_id, then path_id). Policies never mutate
the supplied AttackPath objects and never mutate the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from veyra.graph.path import AttackType


@dataclass(frozen=True)
class Policy:
    """A named, deterministic policy over AttackPath semantics.

    ``policy_id`` is a stable machine key; ``enabled`` governs whether the
    policy participates in evaluation. Policies are immutable value objects.
    """
    policy_id: str
    name: str
    description: str
    enabled: bool = True

    def to_dict(self) -> Dict:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass(frozen=True)
class PolicyResult:
    """The deterministic result of applying one policy to one AttackPath.

    ``policy_id`` and ``path_id`` are preserved exactly from the inputs.
    ``reason`` is a modest, deterministic explanation. No timestamp or random id
    is included, so the result is byte-for-byte reproducible.
    """
    policy_id: str
    path_id: str
    violated: bool
    reason: str

    def to_dict(self) -> Dict:
        return {
            "policy_id": self.policy_id,
            "path_id": self.path_id,
            "violated": self.violated,
            "reason": self.reason,
        }


# --- Built-in policies --------------------------------------------------------

SECRET_EXFILTRATION_POLICY = Policy(
    policy_id="SECRET-EXFILTRATION-001",
    name="Secrets must not flow to external endpoints",
    description="Secrets must not flow to external endpoints.",
)
DATA_EXFILTRATION_POLICY = Policy(
    policy_id="DATA-EXFILTRATION-001",
    name="Sensitive data must not flow to external endpoints",
    description="Sensitive data must not flow to external endpoints.",
)
CORRELATED_SECRET_EXECUTION_POLICY = Policy(
    policy_id="CORRELATED-SECRET-EXECUTION-001",
    name="Review secret access combined with execution",
    description="Secret access combined with execution requires explicit review.",
)

# Each policy triggers ONLY on its matching proven AttackType. UNKNOWN paths
# (including pure HANDOFF control paths) never violate any built-in policy.
# The reason is modest and does not claim exploitability or a proven data flow
# for the correlation policy (which is review-only by design).
_POLICY_TRIGGER = {
    "SECRET-EXFILTRATION-001": (
        AttackType.SECRET_EXFILTRATION,
        "Proven secret exfiltration reaches an external endpoint.",
    ),
    "DATA-EXFILTRATION-001": (
        AttackType.DATA_EXFILTRATION,
        "Proven sensitive-data exfiltration reaches an external endpoint.",
    ),
    "CORRELATED-SECRET-EXECUTION-001": (
        AttackType.CORRELATED_SECRET_EXECUTION,
        "Secret access and execution occur in the same skill and require review.",
    ),
}

_BUILTIN_POLICIES: List[Policy] = [
    SECRET_EXFILTRATION_POLICY,
    DATA_EXFILTRATION_POLICY,
    CORRELATED_SECRET_EXECUTION_POLICY,
]


# --- Policy Engine -------------------------------------------------------------

class PolicyEngine:
    """Evaluate a set of policies against a set of AttackPath objects.

    Deterministic by construction: results are ordered by (policy_id, path_id),
    and only enabled policies are evaluated. No graph mutation and no AttackPath
    mutation occurs.
    """

    def __init__(self, policies: List[Policy] = None):
        # Deterministic ordering of the policy set by policy_id.
        self._policies = sorted(
            (policies if policies is not None else _BUILTIN_POLICIES),
            key=lambda p: p.policy_id,
        )

    def policies(self) -> List[Policy]:
        """The enabled policies in deterministic (policy_id) order."""
        return [p for p in self._policies if p.enabled]

    def evaluate(self, paths: List) -> List[PolicyResult]:
        """Evaluate every enabled policy against every AttackPath.

        Results are deterministic and stable: sorted by policy_id then path_id.
        ``paths`` may be any iterable of objects exposing ``attack_type`` and
        ``path_id``; the engine reads only those semantic fields. Neither the
        paths nor any graph is mutated.
        """
        results: List[PolicyResult] = []
        for policy in self.policies():
            trigger = _POLICY_TRIGGER[policy.policy_id]
            trigger_type, reason = trigger
            for path in paths:
                att = path.attack_type
                if att == trigger_type:
                    results.append(PolicyResult(
                        policy_id=policy.policy_id,
                        path_id=path.path_id,
                        violated=True,
                        reason=reason,
                    ))
                else:
                    # A deterministic "not violated" result is produced so that
                    # serialized policy output is complete and stable.
                    results.append(PolicyResult(
                        policy_id=policy.policy_id,
                        path_id=path.path_id,
                        violated=False,
                        reason=policy.description,
                    ))
        results.sort(key=lambda r: (r.policy_id, r.path_id))
        return results
