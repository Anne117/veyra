"""Data models for Veyra findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from veyra.graph.path import AttackPath
    from veyra.policy import PolicyResult


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """How confident we are that the detected behavior matches the rule.

    Distinct from Severity (how dangerous the behavior is). Confidence is a
    deterministic, rule-derived estimate of match reliability.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Transparent, deterministic MVP heuristic weights.
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

MAX_SCORE = 100


def risk_level_for_score(score: int) -> str:
    """Map a 0-100 score to a risk level (MVP heuristic)."""
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score >= 5:
        return "LOW"
    return "SAFE"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    file: str
    line: Optional[int] = None
    evidence: str = ""
    remediation: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    mitre: List[Dict[str, str]] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    matched_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        # Do not emit empty "mitre": [] for findings without a mapping.
        if not d.get("mitre"):
            d.pop("mitre", None)
        # Do not emit empty "cwe": [] for findings without a mapping.
        if not d.get("cwe"):
            d.pop("cwe", None)
        # Do not emit empty "matched_text" when absent.
        if not d.get("matched_text"):
            d.pop("matched_text", None)
        return d


@dataclass
class ScanResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    attack_paths: List["AttackPath"] = field(default_factory=list)
    # Deterministic policy evaluation results over the finalized attack paths.
    # Empty by default so existing callers that construct ScanResult manually
    # continue to work without specifying policy_results.
    policy_results: List["PolicyResult"] = field(default_factory=list)
    # Deterministic projection of explicit ComponentContextAssociation records
    # into per-component security scopes (see
    # build_component_security_scopes / serialize_component_security_scopes).
    # Additive metadata only — never a graph edge, never ownership inference,
    # never affects findings/attack-paths/policy. Empty by default so existing
    # callers that construct ScanResult manually keep working unchanged.
    component_security_scopes: List[Dict[str, Any]] = field(default_factory=list)
    # Deterministic projection of explicit ComponentContextAssociation records
    # into per-path component participation (see
    # build_component_path_participation / serialize_component_path_participation).
    # Additive metadata only, consistent with component_security_scopes: never a
    # graph edge, never ownership inference, never affects findings/attack-paths/
    # policy. Empty by default so existing callers keep working unchanged.
    component_path_participation: List[Dict[str, Any]] = field(default_factory=list)
    # Deterministic path-level grouping of explicitly participating components
    # and their proven behaviors (see build_component_path_composition /
    # serialize_component_path_composition). Additive metadata only, consistent
    # with component_security_scopes / component_path_participation: never a
    # graph edge, never component-relationship inference, never affects
    # findings/attack-paths/policy. Empty by default.
    component_path_composition: List[Dict[str, Any]] = field(default_factory=list)
    # Deterministic projection of the finalized AttackPath's risk metadata onto
    # explicitly participating components (see build_component_risk_evidence /
    # serialize_component_risk_evidence). Additive metadata only: never
    # redistributes risk, never infers ownership/responsibility. Empty by default.
    component_risk_evidence: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def score(self) -> int:
        total = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings if not f.suppressed)
        return min(total, MAX_SCORE)

    @property
    def risk_level(self) -> str:
        return risk_level_for_score(self.score)

    @property
    def policy_violation_count(self) -> int:
        """Number of PolicyResults with violated == True (derived, no stored state)."""
        return sum(1 for r in self.policy_results if r.violated)

    @property
    def has_policy_violations(self) -> bool:
        """True iff at least one PolicyResult has violated == True."""
        return self.policy_violation_count > 0

    @property
    def violated_policy_ids(self) -> List[str]:
        """Policy IDs of violated results, preserving policy_results ordering.

        Duplicate policy IDs are not deduplicated — every violated result is
        represented in order. No sets, no sorting.
        """
        return [r.policy_id for r in self.policy_results if r.violated]

    @property
    def violated_path_ids(self) -> List[str]:
        """Path IDs of violated results, preserving policy_results ordering."""
        return [r.path_id for r in self.policy_results if r.violated]

    @property
    def policy_status(self) -> str:
        """Aggregate policy status over the finalized policy results.

        "FAIL" iff at least one PolicyResult has violated == True, otherwise
        "PASS". Derived read-only from policy_results; never stored/cached.
        """
        return "FAIL" if self.has_policy_violations else "PASS"

    def summary(self) -> Dict[str, int]:
        active = [f for f in self.findings if not f.suppressed]
        return {
            "critical": sum(1 for f in active if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in active if f.severity == Severity.HIGH),
            "medium": sum(1 for f in active if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in active if f.severity == Severity.LOW),
            "suppressed": sum(1 for f in self.findings if f.suppressed),
        }

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "target": self.target,
            "score": self.score,
            "risk_level": self.risk_level,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.attack_paths:
            d["attack_paths"] = [p.to_dict() for p in self.attack_paths]
        # Pure projection of the finalized PolicyEngine evaluation results.
        # Always present (including an empty list for clean scans) so the JSON
        # representation is stable and complete regardless of findings.
        d["policy_results"] = [r.to_dict() for r in self.policy_results]
        d["policy_status"] = self.policy_status
        # Additive component-security-scope projection. Present only when the
        # caller supplied explicit scope data (never inferred); omitted when
        # empty so clean/unchanged scans keep the same stable shape.
        if self.component_security_scopes:
            d["component_security_scopes"] = self.component_security_scopes
        # Additive component-path-participation projection. Present only when
        # the caller supplied explicit scope data (never inferred); omitted
        # when empty so clean/unchanged scans keep the same stable shape.
        if self.component_path_participation:
            d["component_path_participation"] = self.component_path_participation
        # Additive component-path-composition projection. Present only when the
        # caller supplied explicit scope data (never inferred); omitted when
        # empty so clean/unchanged scans keep the same stable shape.
        if self.component_path_composition:
            d["component_path_composition"] = self.component_path_composition
        # Additive component-risk-evidence projection. Present only when the
        # caller supplied explicit scope data (never inferred); omitted when
        # empty so clean/unchanged scans keep the same stable shape.
        if self.component_risk_evidence:
            d["component_risk_evidence"] = self.component_risk_evidence
        return d
