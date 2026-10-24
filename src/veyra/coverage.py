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
# A caller-owned artifact the walk was told not to read: a baseline snapshot
# that lives inside the tree it describes. The file is real target content --
# it sits in the tree, it is committed, and a rule would have read it -- so
# refusing it is a hole in the read and is recorded as one. Recording it also
# withdraws ``full``: a scan that skipped a file may not call itself complete
# (see ``coverage_status``). Without this, an in-tree baseline made the walk
# drop a ``.json`` file in silence while the report still said "everything was
# read".
SKIP_BASELINE = "baseline_snapshot"

SKIP_REASONS = frozenset(
    {
        SKIP_BINARY,
        SKIP_TOO_LARGE,
        SKIP_UNREADABLE,
        SKIP_DECODE_ERROR,
        SKIP_NOT_SCANNABLE,
        SKIP_BASELINE,
    }
)

# --- fixed rule-error vocabulary ------------------------------------------
#
# A rule that raises is recorded by the *surface* that raised, not by the
# exception message: the message is free text and can carry a host path.
# ``line=null`` means the rule failed on the file as a whole (file rules have
# no line of their own), which is exactly the form a file-level loss needs to
# stay visible.

# --- lossy-decode vocabulary ----------------------------------------------
#
# A file whose bytes are not valid UTF-8 is still scanned: decoding with
# replacement characters keeps every line the rules *can* read, and refusing
# the whole file would drop real findings (measured in
# ``docs/COVERAGE-GAPS.md``). What must not happen is the file counting as
# read in full -- the replacement characters are text the scanner invented,
# not the text the file holds. So the file is *read* and separately
# *declared lossy*; the reason token is the existing ``decode_error``, which
# until now was unreachable. No encoding is guessed: a cp1251 body is not
# "probably cp1251", it is "not UTF-8", and the report says exactly that.

LOSSY_DECODE_REASONS = frozenset({SKIP_DECODE_ERROR})

RULE_ERROR_LINE = "line_rule_exception"
RULE_ERROR_FILE = "file_rule_exception"

RULE_ERROR_TYPES = frozenset({RULE_ERROR_LINE, RULE_ERROR_FILE})


# --- pruned-directory vocabulary -------------------------------------------
#
# A directory the walk refused to enter is a different kind of omission from a
# file the reader refused to open: no rule was ever given a chance to run, so
# there is no path, no line and no matched text to attach. The tokens are kept
# out of ``SKIP_REASONS`` on purpose -- a pruned subtree does NOT by itself
# make ``coverage_status`` partial (that step is option (b) in
# ``docs/COVERAGE-GAPS.md`` and is a product decision, not an accounting one).
# Recording it is what lets a report say "full" and "eleven directories were
# not entered" in the same breath, so the contradiction is visible instead of
# implied.
#
# Three reasons, because there are three different refusals.
#
# ``ignored_dir`` -- machine-produced state the scanner chose to skip
# (``.git``, ``__pycache__``, caches, virtualenvs). Nothing the target's author
# wrote lives there, so refusing it is not a hole: the verdict does not move.
#
# ``vendored_dir`` -- third-party or build output the scanner chose to skip
# (``node_modules``, ``dist``, ``build``, ``site-packages``, ``.next``,
# ``target``). This one CAN hold shipped configuration -- an ``.env`` inside an
# installed package, a secret compiled into a bundle -- and no rule here ever
# opens it. A scan that stood on top of it therefore may not claim ``full``;
# this is the owner's decision (b) in ``docs/COVERAGE-GAPS.md``, taken in
# ``T8`` of ``NIGHT-QUEUE.md``.
#
# ``symlink_dir`` -- a subtree the walk never follows by construction
# (``os.walk`` without ``followlinks``): the scanner did not decide to skip it,
# it simply cannot see through the link, and a *file* symlink is still read
# (``stat`` follows it). That asymmetry is a fact about the target, not a
# policy -- so it is named, not judged.

PRUNE_IGNORED_DIR = "ignored_dir"
PRUNE_VENDORED_DIR = "vendored_dir"
PRUNE_SYMLINK_DIR = "symlink_dir"

PRUNE_REASONS = frozenset(
    {PRUNE_IGNORED_DIR, PRUNE_VENDORED_DIR, PRUNE_SYMLINK_DIR}
)

# Prune reasons that withdraw the claim of a complete read. A vendored subtree
# is content the target ships and the scanner never opened; machine state and
# an unfollowed link are named for the record but do not move the verdict.
PARTIAL_PRUNE_REASONS = frozenset({PRUNE_VENDORED_DIR})


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
    decode_errors: Sequence[Dict[str, Any]] = (),
    dirs_pruned: Sequence[Dict[str, str]] = (),
) -> str:
    """Classify how much of the target the scan actually inspected.

    ``decode_errors`` counts as partial: the file was scanned, but part of its
    text was invented by the decoder, so "full" would claim characters nobody
    read. ``dirs_pruned`` counts only for the reasons in
    ``PARTIAL_PRUNE_REASONS``: a skipped ``node_modules/`` is content the target
    ships and no rule opened, while a skipped ``.pytest_cache/`` is the machine's
    own state.
    """
    if files_scanned <= 0:
        return COVERAGE_NONE
    if files_skipped or rule_errors or decode_errors:
        return COVERAGE_PARTIAL
    if any(r.get("reason") in PARTIAL_PRUNE_REASONS for r in dirs_pruned):
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
    dirs_pruned: List[Dict[str, str]] = field(default_factory=list)
    # Files that were read, but not as the text they hold: the bytes did not
    # decode as UTF-8 and some characters are the scanner's replacement. Kept
    # out of ``files_skipped`` on purpose -- the file was scanned, and calling
    # it skipped would hide the findings it did produce.
    decode_errors: List[Dict[str, str]] = field(default_factory=list)

    # -- writers ----------------------------------------------------------

    def counted(self) -> None:
        """One file was read and its rules were actually applied."""
        self.files_scanned += 1

    def skipped(self, path: str, reason: str) -> None:
        """The scanner gave up on ``path``; ``reason`` names the surface."""
        if reason not in SKIP_REASONS:
            raise ValueError(f"unknown skip reason: {reason!r}")
        self.files_skipped.append({"path": str(path), "reason": reason})

    def lossy(self, path: str, reason: str = SKIP_DECODE_ERROR) -> None:
        """``path`` was read, but not every character came from the file.

        Recorded rather than refused: the readable lines were scanned, and
        only the claim of a *complete* read is withdrawn.
        """
        if reason not in LOSSY_DECODE_REASONS:
            raise ValueError(f"unknown decode reason: {reason!r}")
        self.decode_errors.append({"path": str(path), "reason": reason})

    def pruned(self, path: str, reason: str) -> None:
        """The walk refused to enter ``path``; no rule ran inside it."""
        if reason not in PRUNE_REASONS:
            raise ValueError(f"unknown prune reason: {reason!r}")
        self.dirs_pruned.append({"path": str(path), "reason": reason})

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
            "dirs_pruned": sorted(
                self.dirs_pruned, key=lambda r: (r["path"], r["reason"])
            ),
            "decode_errors": sorted(
                self.decode_errors, key=lambda r: (r["path"], r["reason"])
            ),
        }
