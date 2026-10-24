"""Data models for Veyra findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from veyra.coverage import COVERAGE_FULL, coverage_status

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


# Not a bucket of ``risk_level_for_score``: a score cannot produce it. The
# bucket function answers "how much did the proven findings weigh"; UNKNOWN
# answers "may this clean score be believed at all" -- and only coverage can.
RISK_UNKNOWN = "UNKNOWN"

# Policy verdict vocabulary. ``PASS`` is a proof, not an absence: it may only be
# returned when the whole target was read. A violation is proof on its own and
# survives partial coverage -- an unread neighbour cannot clear a proven
# violation. The third word exists because "no violation found in the part I
# read" is not "no violation": it is "not proven either way".
POLICY_PASS = "PASS"
POLICY_FAIL = "FAIL"
POLICY_UNKNOWN = "UNKNOWN"


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
    # Baseline diff state, set only by ``veyra scan --baseline`` (T12):
    # ``"new"`` for a finding absent from the snapshot, ``"matched"`` for one
    # the snapshot already lists. ``None`` means no baseline was applied, and
    # then the key is not emitted at all, so a plain scan's JSON shape is
    # unchanged. It is a report annotation, never an input to detection: the
    # finding is still reported with its own severity, file and line.
    baseline_state: Optional[str] = None

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
        # Do not emit "baseline_state": null for a scan without a baseline.
        if d.get("baseline_state") is None:
            d.pop("baseline_state", None)
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
    # Deterministic mapping from finalized AttackPath.path_id to the real
    # source file backing that path's entry node (the SKILL node label).
    # Populated by the scanner from the same merged SecurityGraph that
    # produced the paths; empty by default so callers that construct
    # ScanResult manually continue to work. NEVER a fabricated location:
    # a path appears in this map only when its entry_node resolves to a
    # SKILL node whose label corresponds to an actually-scanned file.
    # Reporters (e.g. SARIF) MUST treat absence as "location omitted" and
    # mark that decision explicitly; they MUST NOT infer coordinates.
    attack_path_entry_files: Dict[str, str] = field(default_factory=dict)
    # Additive coverage accounting. What this scan actually READ, what it
    # refused, and why. Reasons are fixed tokens from ``veyra.coverage``
    # (``binary``, ``too_large``, ``unreadable``, ``decode_error``,
    # ``not_scannable``, ``baseline_snapshot``), never free text and never a
    # host path in prose. ``baseline_snapshot`` is the one caller-requested
    # skip: a baseline file inside the tree it describes is not scanned, and
    # the skip is recorded so ``full`` is withdrawn (T12).
    # ``rule_errors`` records a rule that raised (``line`` is None when the
    # rule failed on the file as a whole). Zero/empty means "no tree was
    # walked or nothing was refused" -- it NEVER by itself means "everything
    # was read": read ``files_scanned`` before believing a clean result.
    files_scanned: int = 0
    files_skipped: List[Dict[str, str]] = field(default_factory=list)
    rule_errors: List[Dict[str, Any]] = field(default_factory=list)
    # Directories the walk never entered, with a reason token from
    # ``veyra.coverage``. ``ignored_dir`` (machine state: ``.git``,
    # ``__pycache__``, caches, virtualenvs) and ``symlink_dir`` are records
    # only -- the verdict does not move. ``vendored_dir`` (``node_modules``,
    # ``dist``, ``build``, ``site-packages``) DOES move it: that subtree can
    # hold shipped configuration no rule here opened, so the scan cannot call
    # itself ``full``. Owner decision (b), see ``T8`` in ``NIGHT-QUEUE.md``.
    dirs_pruned: List[Dict[str, str]] = field(default_factory=list)
    # Files that were READ but not as the text they hold: the bytes were not
    # UTF-8, so the decoder inserted replacement characters and part of the
    # scanned text is the scanner's own. Reason token ``decode_error``. Such a
    # file is not ``skipped`` (its readable lines did produce findings) but it
    # is not a full read either -- ``coverage_status`` turns it into
    # ``partial``, and therefore a zero score into ``UNKNOWN`` rather than
    # ``SAFE``.
    decode_errors: List[Dict[str, str]] = field(default_factory=list)
    # Additive diff against a baseline snapshot (``veyra scan --baseline``).
    # ``{"matched": n, "new": n, "fixed": n}`` when a baseline was applied,
    # ``None`` otherwise -- so a scan without ``--baseline`` keeps its exact
    # previous JSON shape. The counts describe the findings that were compared,
    # not a verdict: ``policy_status`` and ``coverage`` are computed from the
    # same data as before and are never narrowed by this block.
    baseline: Optional[Dict[str, int]] = None

    @property
    def score(self) -> int:
        total = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings if not f.suppressed)
        return min(total, MAX_SCORE)

    @property
    def coverage_status(self) -> str:
        """What the scan actually read: ``full``, ``partial`` or ``none``.

        Derived from ``files_scanned`` / ``files_skipped`` / ``rule_errors``
        / ``decode_errors`` / ``dirs_pruned`` (see ``veyra.coverage``). A
        result built by hand, with no walk behind it, is ``none`` -- it never
        guesses that its target was covered.
        """
        return coverage_status(
            self.files_scanned,
            self.files_skipped,
            self.rule_errors,
            self.decode_errors,
            self.dirs_pruned,
        )

    @property
    def risk_level(self) -> str:
        """Risk verdict: a score bucket, downgraded to UNKNOWN when unproven.

        A non-zero score is a proven finding and keeps its bucket -- unread
        neighbours cannot make a HIGH go away. A zero score is only ``SAFE``
        when the coverage is ``full``; otherwise nothing was proven, and the
        verdict says so instead of borrowing certainty from silence.
        """
        level = risk_level_for_score(self.score)
        if level != "SAFE":
            return level
        if self.coverage_status != COVERAGE_FULL:
            return RISK_UNKNOWN
        return level

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
        """Aggregate policy verdict over the finalized results: FAIL/PASS/UNKNOWN.

        ``FAIL`` -- at least one PolicyResult has violated == True. That is
        proof, and unread files cannot take it away.

        ``PASS`` -- no violation AND ``coverage_status == "full"``. Only then
        does "no violations" mean "nothing violated in the target"; this is the
        one case in which the word is earned.

        ``UNKNOWN`` -- no violation proven, but part (or all) of the target was
        never read. Neither "passed" nor "violated": the question was not
        answered for the whole target. Previously this case reported ``PASS``,
        which read as "everything was checked" and was a false assurance.

        Derived read-only from policy_results and coverage; never stored/cached.
        """
        if self.has_policy_violations:
            return POLICY_FAIL
        if self.coverage_status != COVERAGE_FULL:
            return POLICY_UNKNOWN
        return POLICY_PASS

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
        # Additive coverage accounting, always present. A report that says
        # "SAFE" without saying how much of the target was read is the exact
        # silence this block exists to end, so it is emitted even when empty:
        # a manually-built ScanResult reports files_scanned=0 rather than
        # pretending it scanned something.
        d["coverage"] = {
            "coverage_status": self.coverage_status,
            "files_scanned": self.files_scanned,
            "files_skipped": list(self.files_skipped),
            "rule_errors": list(self.rule_errors),
            # Additive: subtrees the walk refused. ``coverage_status`` above
            # does not count them; printing both is what makes the residual
            # gap legible rather than invisible.
            "dirs_pruned": list(self.dirs_pruned),
            # Additive: files read with replacement characters. Separate from
            # ``files_skipped`` because the file WAS scanned; separate field
            # because "scanned" and "read in full" are different claims.
            "decode_errors": list(self.decode_errors),
        }
        if self.attack_paths:
            d["attack_paths"] = [p.to_dict() for p in self.attack_paths]
        # Pure projection of the finalized PolicyEngine evaluation results.
        # Always present (including an empty list for clean scans) so the JSON
        # representation is stable and complete regardless of findings.
        d["policy_results"] = [r.to_dict() for r in self.policy_results]
        d["policy_status"] = self.policy_status
        # Additive baseline diff. Present only when a baseline was applied, so
        # the shape of a plain scan is unchanged. ``matched`` is emitted next to
        # ``new`` on purpose: a growing backlog must be visible, not only the
        # part of it that fails the build.
        if self.baseline is not None:
            d["baseline"] = dict(self.baseline)
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
