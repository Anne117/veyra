"""Data models for Veyra findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


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

    @property
    def score(self) -> int:
        total = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings if not f.suppressed)
        return min(total, MAX_SCORE)

    @property
    def risk_level(self) -> str:
        return risk_level_for_score(self.score)

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
        return {
            "target": self.target,
            "score": self.score,
            "risk_level": self.risk_level,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
