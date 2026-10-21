"""Coverage accounting: what a scan read, what it refused, and why.

The scanner has always been able to drop an input without a word: a binary
file, a file above ``MAX_FILE_SIZE``, a path it cannot stat or read, a name
outside the scannable set, or a rule that raised. The visible result was
`score=0` / `risk_level=SAFE` / `policy_status=PASS` for a tree in which
nothing had actually been inspected (see ``docs/COVERAGE-GAPS.md``).

This module owns the *vocabulary* of those omissions so a report can state
them. Two rules hold everywhere:

* A reason is one of a fixed set of tokens. Never a free-text exception
  message, never a host path glued into prose -- a report must not leak the
  machine it ran on just to explain itself.
* A record is written only where the scanner really gave up. Nothing here
  infers coverage, and nothing here changes what the scanner detects.

Accounting is additive: adding it does not move findings, score, paths or
policy, it only makes the existing silence visible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

# --- fixed skip vocabulary ------------------------------------------------

SKIP_BINARY = "binary"
SKIP_TOO_LARGE = "too_large"
SKIP_UNREADABLE = "unreadable"
SKIP_DECODE_ERROR = "decode_error"
SKIP_NOT_SCANNABLE = "not_scannable"

SKIP_REASONS = frozenset(
    {
        SKIP_BINARY,
        SKIP_TOO_LARGE,
        SKIP_UNREADABLE,
        SKIP_DECODE_ERROR,
        SKIP_NOT_SCANNABLE,
    }
)

# --- fixed rule-error vocabulary ------------------------------------------
#
# A rule that raises is recorded by the *surface* that raised, not by the
# exception message: the message is free text and can carry a host path.
# ``line=null`` means the rule failed on the file as a whole (file rules have
# no line of their own), which is exactly the form a file-level loss needs to
# stay visible.

RULE_ERROR_LINE = "line_rule_exception"
RULE_ERROR_FILE = "file_rule_exception"

RULE_ERROR_TYPES = frozenset({RULE_ERROR_LINE, RULE_ERROR_FILE})


# --- coverage status --------------------------------------------------------
#
# A three-state verdict over what the walk actually read. It exists so that
# "no findings" can never be presented as "nothing was there":
#
#   full    -- at least one file was read, nothing was refused, no rule raised.
#   partial -- something was read, but part of the target was not inspected.
#   none    -- nothing was read at all: an empty tree, a target that was
#              entirely refused, or a result that never went through a walk.
#
# The status is derived from the accounting above and nothing else. It never
# infers that an unrecorded path was scanned.

COVERAGE_FULL = "full"
COVERAGE_PARTIAL = "partial"
COVERAGE_NONE = "none"

COVERAGE_STATUSES = frozenset({COVERAGE_FULL, COVERAGE_PARTIAL, COVERAGE_NONE})


def coverage_status(
    files_scanned: int,
    files_skipped: Sequence[Dict[str, str]],
    rule_errors: Sequence[Dict[str, Any]],
) -> str:
    """Classify how much of the target the scan actually inspected."""
    if files_scanned <= 0:
        return COVERAGE_NONE
    if files_skipped or rule_errors:
        return COVERAGE_PARTIAL
    return COVERAGE_FULL


def rule_identity(rule: Any) -> str:
    """Stable identity of a rule for a rule-error record.

    Line/file rules are plain functions registered through ``@register`` /
    ``@register_file_rule`` and carry no declared rule id, so the function name
    is the identity the registry itself uses. It is a bounded token from our
    own source, never text taken from the scanned input.
    """
    declared = getattr(rule, "rule_id", None)
    if isinstance(declared, str) and declared:
        return declared
    name = getattr(rule, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return "unknown"


@dataclass
class ScanCoverage:
    """Mutable recorder used while walking a target.

    The scanner fills exactly one of these per ``scan_path`` call; the scan
    result carries the sorted snapshot. Keeping it separate from ``ScanResult``
    means a partially-built result can never look like complete coverage.
    """

    files_scanned: int = 0
    files_skipped: List[Dict[str, str]] = field(default_factory=list)
    rule_errors: List[Dict[str, Any]] = field(default_factory=list)

    # -- writers ----------------------------------------------------------

    def counted(self) -> None:
        """One file was read and its rules were actually applied."""
        self.files_scanned += 1

    def skipped(self, path: str, reason: str) -> None:
        """The scanner gave up on ``path``; ``reason`` names the surface."""
        if reason not in SKIP_REASONS:
            raise ValueError(f"unknown skip reason: {reason!r}")
        self.files_skipped.append({"path": str(path), "reason": reason})

    def rule_failed(
        self,
        rule: Any,
        path: str,
        line: Optional[int],
        error_type: str,
    ) -> None:
        """A rule raised on ``path``; the scan continued without it."""
        if error_type not in RULE_ERROR_TYPES:
            raise ValueError(f"unknown rule error type: {error_type!r}")
        self.rule_errors.append(
            {
                "rule_id": rule_identity(rule),
                "path": str(path),
                "line": line,
                "error_type": error_type,
            }
        )

    # -- reader -----------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """Deterministic, JSON-safe view (sorted: walk order is not stable)."""
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": sorted(
                self.files_skipped, key=lambda r: (r["path"], r["reason"])
            ),
            "rule_errors": sorted(
                self.rule_errors,
                key=lambda r: (
                    r["path"],
                    -1 if r["line"] is None else r["line"],
                    r["rule_id"],
                    r["error_type"],
                ),
            ),
        }
