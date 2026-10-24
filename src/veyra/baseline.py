"""Baseline snapshots and finding diffs for CI (T12).

``veyra baseline create <target>`` writes the fingerprints of the findings the
tree already produces. ``veyra scan <target> --baseline <file>`` marks every
finding as ``new`` or ``matched`` against that snapshot, prints the new ones,
and fails the build only on the new ones, so a known backlog stays visible
without blocking every run.

The fingerprint is the whole record, never a wildcard:

    (rule_id, file relative to the target, line, evidence, severity)

Any "smart" matching -- ignoring the line, dropping the evidence, normalising
the severity -- would let a pre-seeded baseline absorb a finding nobody has
looked at yet, so nothing is normalised except the location (a baseline must
not carry host paths) and the key has no optional field. The consequences are
deliberate and documented rather than hidden:

* a line inserted above a finding moves it: the old record is ``fixed`` and
  the same finding is ``new``. Noisy, and safe: the gate opens, not closes.
* raising MEDIUM to CRITICAL is ``new`` because severity is in the key.
* two findings that differ in nothing at all are counted, not collapsed:
  the snapshot stores both, so a duplicate never turns into a silent "new"
  on the next run of an unchanged tree.

A baseline is an input a pull request can edit. Whoever can commit it can
mute a finding, so the file belongs in CODEOWNERS, ``matched`` is printed next
to ``new`` so growing debt is visible, and ``policy_status`` is never
downgraded by it. ``fixed`` is reported (terminal + JSON) but never fails the
build, and it is never removed from the file by a scan: only an explicit
``baseline create`` rewrites the snapshot.

Nothing is narrowed. The scan's findings, score, risk level, summary and
policy verdict describe the whole tree with or without ``--baseline``; the
diff is an annotation on top (``Finding.baseline_state`` plus the
``{matched, new, fixed}`` block). Narrowing the result set would make a
matched CRITICAL backlog render as SAFE/clean in every machine format, which
is the one thing a gate must never do.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import (
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
)

from veyra.models import Finding, ScanResult

#: Format version of the baseline file. A file written by another version is
#: refused (exit 2) rather than half-understood: a silent partial load would
#: turn every unmatched finding into "new" and fail a clean build.
BASELINE_VERSION = 1

#: Default file name inside a directory target. Kept out of the walk by the
#: caller (see ``exclude_paths``) so a snapshot can live next to the code.
DEFAULT_BASELINE_NAME = ".veyra-baseline.json"

#: Refusal limits. A baseline is usually a few hundred lines; a file past
#: these bounds is not a snapshot but a denial-of-service, and CI must say so
#: instead of reading it into memory.
MAX_BASELINE_BYTES = 5 * 1024 * 1024
MAX_BASELINE_RECORDS = 100_000


class BaselineError(Exception):
    """A baseline could not be read or written.

    The CLI turns this into exit code 2 with the message on stderr: a broken
    or missing baseline is an unusable gate, never an empty one.
    """


@dataclass(frozen=True)
class BaselineRecord:
    """One finding, with every location scrubbed of host context."""

    rule_id: str
    file: str
    line: Optional[int]
    evidence: str
    severity: str

    @property
    def key(self) -> Tuple[str, str, Optional[int], str, str]:
        """The match key: the full tuple, no wildcard, no optional member."""
        return (self.rule_id, self.file, self.line, self.evidence, self.severity)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line is not None else self.file

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "severity": self.severity,
        }

    def sort_key(self) -> Tuple:
        # ``None`` lines sort before real ones, deterministically.
        return (
            self.rule_id,
            self.file,
            self.line is not None,
            self.line if self.line is not None else 0,
            self.evidence,
            self.severity,
        )


@dataclass(frozen=True)
class BaselineDiff:
    """Counts for one scan against one baseline.

    ``matched + new == number of current records`` and
    ``matched + fixed == number of baseline records`` hold by construction:
    every record is on exactly one side of the comparison.
    """

    matched: int
    new: int
    fixed: int
    #: Records present in the file and absent from the tree, in file order.
    #: Printed so "we fixed it" is a visible claim, not a deletion.
    fixed_records: Tuple[BaselineRecord, ...] = ()

    def to_dict(self) -> Dict[str, int]:
        return {"matched": self.matched, "new": self.new, "fixed": self.fixed}


# --- Locations -------------------------------------------------------------
#
# A baseline is committed to git, so every host-shaped string in it is a new
# leak channel: absolute paths, the home directory, the cwd. The fingerprint
# keeps the finding, not the machine it was found on.


def scan_root(target: str) -> str:
    """Absolute directory the finding paths are made relative to.

    For a file target the root is its parent, so a snapshot of one file names
    the file and nothing above it.
    """
    path = Path(target)
    if path.is_dir():
        return os.path.abspath(str(path))
    return os.path.dirname(os.path.abspath(str(path)))


def baseline_path_for_target(target: str) -> str:
    """Default snapshot location for ``veyra baseline create <target>``."""
    path = Path(target)
    if path.is_dir():
        return str(path / DEFAULT_BASELINE_NAME)
    return str(path.with_name(path.name + ".baseline.json"))


def _relative_location(file: str, root_abs: str) -> str:
    """The finding's location relative to the scan root, without ``..``.

    ``<correlated>`` and friends are pseudo-locations, not paths, and stay as
    written. A finding outside the root (which the walk cannot produce) is
    named by its base name under a fixed, non-traversable prefix rather than
    leaking the directory it lived in.
    """
    if file.startswith("<") and file.endswith(">"):
        return file
    abs_file = os.path.abspath(file)
    if abs_file == root_abs:
        relative = "."
    elif abs_file.startswith(root_abs + os.sep):
        relative = abs_file[len(root_abs) + 1:]
    else:
        relative = ""
    relative = relative.replace(os.sep, "/")
    if not relative or relative == "." or relative == ".." or relative.startswith("../"):
        return "<outside>/" + os.path.basename(abs_file)
    return relative


def _location_map(
    findings: Sequence[Finding], root_abs: str
) -> Dict[str, str]:
    """Map every location the scan knows to its relative form.

    Correlation evidence embeds ``file:line`` of every contributing finding
    (``correlation._locations``), so "no host path" has to be enforced over the
    whole record, not just over the ``file`` field. The needles are the exact
    strings the scanner put into those findings -- as given and absolute -- so
    the rewrite is a dictionary lookup per token instead of a scan over every
    path for every finding (a 13 000-finding tree made that quadratic).
    """
    mapping: Dict[str, str] = {}
    for finding in findings:
        raw = finding.file
        if not raw or (raw.startswith("<") and raw.endswith(">")):
            continue
        relative = _relative_location(raw, root_abs)
        mapping[raw] = relative
        mapping[os.path.abspath(raw)] = relative
    return mapping


# A POSIX absolute path with at least one name component. The lookbehind keeps
# URLs ("https://host/x"), relative paths ("a/b", "./b") and version ranges out.
_ABSOLUTE_PATH = re.compile(
    r"(?<![\w:/.~+-])/(?:[A-Za-z0-9._~+-]+/)*[A-Za-z0-9._~+-]+"
)
# Path traversal, in the two shapes it appears in evidence text.
_TRAVERSAL_PREFIX = re.compile(r"(?:^|(?<=[\s\"'=(,:;]))(?:\.\./)+")
_TRAVERSAL_TOKEN = re.compile(r"(?<![\w.])\.\.(?![\w.])")
# One candidate location: whitespace and delimiters end it; "/" and ":" stay
# inside so "dir/a.md:3" is read as one piece.
_EVIDENCE_TOKEN = re.compile(r"[^\s,;()\[\]{}\"'<>]+")


def _split_line_suffix(token: str) -> Tuple[str, str]:
    """``a.md:3`` -> ``("a.md", ":3")``; anything else is its own location."""
    stem, sep, tail = token.rpartition(":")
    if sep and tail.isdigit():
        return stem, ":" + tail
    return token, ""


def _sanitize_evidence(
    evidence: str, root_abs: str, mapping: Dict[str, str]
) -> str:
    """Remove host paths from an evidence string.

    Exact file strings the scanner wrote go first (they turn
    ``Contributing: /build/a.md:3`` into ``Contributing: a.md:3``), then the
    remaining prefixes of the machine that produced the snapshot, then any
    absolute path left over, then path traversal. A URL is evidence, not a
    host path, and is left exactly as written.
    """

    def replace(match: "re.Match[str]") -> str:
        token = match.group(0)
        if "://" in token:
            return token
        location, suffix = _split_line_suffix(token)
        relative = mapping.get(location)
        if relative is None and location.startswith("/"):
            relative = _relative_location(location, root_abs)
        if relative is None:
            return token
        return relative + suffix

    text = _EVIDENCE_TOKEN.sub(replace, evidence)
    # Prefixes of the machine, for absolute paths no finding named (the exact
    # file strings were handled above).
    for prefix, replacement in (
        (root_abs + os.sep, ""),
        (os.path.expanduser("~") + os.sep, "<home>/"),
        (os.getcwd() + os.sep, "<cwd>/"),
    ):
        if prefix and prefix != "/" and prefix in text:
            text = text.replace(prefix, replacement)
    text = _ABSOLUTE_PATH.sub(
        lambda match: "<path>/" + match.group(0).rsplit("/", 1)[-1], text
    )
    text = _TRAVERSAL_PREFIX.sub("", text)
    text = _TRAVERSAL_TOKEN.sub("<up>", text)
    return text


# --- Records --------------------------------------------------------------


def _is_excluded(file: str, excludes: Collection[str]) -> bool:
    if not excludes or not file:
        return False
    if file.startswith("<") and file.endswith(">"):
        return False
    return os.path.abspath(file) in excludes


def _current_pairs(
    findings: Iterable[Finding],
    root_abs: str,
    exclude_paths: Sequence[str] = (),
) -> List[Tuple[Finding, BaselineRecord]]:
    """(finding, record) for everything a scan produced, in scan order.

    Suppressed findings are included on purpose: suppression is a config
    decision, and a baseline that skipped them would turn every unsuppressed
    finding into a fresh "new" finding the moment the config changes. The
    suppression flag is not part of the key either.
    """
    excludes = {
        os.path.abspath(str(candidate)) for candidate in exclude_paths if candidate
    }
    findings = list(findings)
    mapping = _location_map(findings, root_abs)
    pairs: List[Tuple[Finding, BaselineRecord]] = []
    for finding in findings:
        if _is_excluded(finding.file, excludes):
            continue
        record = BaselineRecord(
            rule_id=finding.rule_id,
            file=_relative_location(finding.file, root_abs),
            line=finding.line,
            evidence=_sanitize_evidence(finding.evidence or "", root_abs, mapping),
            severity=finding.severity.value,
        )
        pairs.append((finding, record))
    return pairs


def build_records(
    findings: Iterable[Finding],
    root_abs: str,
    exclude_paths: Sequence[str] = (),
) -> List[BaselineRecord]:
    """Fingerprints of ``findings``, relative to ``root_abs``, sorted."""
    records = [record for _, record in _current_pairs(findings, root_abs, exclude_paths)]
    return sorted(records, key=BaselineRecord.sort_key)


# --- Reading and writing --------------------------------------------------


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise BaselineError(f"baseline record has a non-string {field}")
    return value


def load_baseline(path: str) -> List[BaselineRecord]:
    """Read a snapshot, refusing anything that is not a bounded regular file.

    Every failure is a hard error (exit 2). A baseline that cannot be read is
    an unusable gate, and pretending it was empty would fail every build for
    the wrong reason -- or, worse, pass one.
    """
    try:
        info = os.stat(path)
    except OSError as exc:
        raise BaselineError(f"baseline not found: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        # A FIFO or a device would block or spool forever; a directory has no
        # single record. Checked before any read.
        raise BaselineError(f"baseline is not a regular file: {path}")
    if info.st_size > MAX_BASELINE_BYTES:
        raise BaselineError(
            f"baseline is too large: {info.st_size} bytes "
            f"(limit {MAX_BASELINE_BYTES})"
        )
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BaselineError(f"baseline is not readable UTF-8: {path}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline is not valid JSON: {path}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"baseline is not a JSON object: {path}")
    if data.get("version") != BASELINE_VERSION:
        raise BaselineError(
            f"unsupported baseline version {data.get('version')!r} "
            f"(this build writes version {BASELINE_VERSION})"
        )
    items = data.get("findings")
    if not isinstance(items, list):
        raise BaselineError("baseline has no 'findings' list")
    if len(items) > MAX_BASELINE_RECORDS:
        raise BaselineError(
            f"baseline has too many records: {len(items)} "
            f"(limit {MAX_BASELINE_RECORDS})"
        )

    records: List[BaselineRecord] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise BaselineError(f"baseline record {index} is not an object")
        line = item.get("line")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int)):
            raise BaselineError(f"baseline record {index} has a non-integer line")
        records.append(
            BaselineRecord(
                rule_id=_require_str(item.get("rule_id"), "rule_id"),
                file=_require_str(item.get("file"), "file"),
                line=line,
                evidence=_require_str(item.get("evidence"), "evidence"),
                severity=_require_str(item.get("severity"), "severity"),
            )
        )
    return records


def serialize_baseline(records: Sequence[BaselineRecord]) -> str:
    """The exact bytes written to disk: sorted records, stable field order."""
    ordered = sorted(records, key=BaselineRecord.sort_key)
    payload = {
        "version": BASELINE_VERSION,
        "findings": [record.to_dict() for record in ordered],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def write_baseline(path: str, records: Sequence[BaselineRecord]) -> None:
    text = serialize_baseline(records)
    try:
        parent = Path(path).parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot write baseline {path}: {exc}") from exc


# --- Diffing --------------------------------------------------------------


def diff_result(
    result: ScanResult,
    target: str,
    baseline_records: Sequence[BaselineRecord],
    exclude_paths: Sequence[str] = (),
) -> Tuple[List[Finding], BaselineDiff]:
    """Split the scan's findings into ``matched`` and ``new``, count ``fixed``.

    Matching is multiplicity-aware (a Counter, never a set): two identical
    findings against one baseline record is one match and one new finding, and
    an unchanged tree never reports its own duplicate as new.
    """
    pairs = _current_pairs(result.findings, scan_root(target), exclude_paths)
    current = Counter(record.key for _, record in pairs)
    baseline = Counter(record.key for record in baseline_records)
    matched_by_key = {
        key: min(current[key], baseline[key]) for key in current.keys() | baseline.keys()
    }
    matched = sum(matched_by_key.values())

    consumed: Counter = Counter()
    new_findings: List[Finding] = []
    for finding, record in pairs:
        key = record.key
        if consumed[key] < matched_by_key.get(key, 0):
            consumed[key] += 1
            continue
        new_findings.append(finding)

    seen: Counter = Counter()
    fixed_records: List[BaselineRecord] = []
    for record in baseline_records:
        key = record.key
        if seen[key] < matched_by_key.get(key, 0):
            seen[key] += 1
            continue
        fixed_records.append(record)

    diff = BaselineDiff(
        matched=matched,
        new=len(new_findings),
        fixed=len(fixed_records),
        fixed_records=tuple(fixed_records),
    )
    return new_findings, diff


def apply_baseline(
    result: ScanResult,
    target: str,
    baseline_records: Sequence[BaselineRecord],
    exclude_paths: Sequence[str] = (),
) -> Tuple[ScanResult, BaselineDiff]:
    """Annotate every finding with its baseline state and attach the counts.

    The findings are NOT narrowed. ``score``, ``risk_level``, ``summary()``,
    the attack paths and the policy verdict keep describing the WHOLE tree, so
    a backlog of matched CRITICAL findings can never be rendered as a clean
    run: the machine formats carry the full result set, each finding marked
    ``baseline_state`` (``new`` / ``matched``, emitted as SARIF
    ``baselineState``) plus a ``baseline`` block with the counts. Only the
    severity gate in the CLI -- and the terminal finding list, which the
    operator reads to act -- is restricted to the new findings.

    Findings produced for an excluded path (a snapshot inside the target that
    the walk refused) keep ``baseline_state = None``: they were not compared
    to anything, and the gate treats "not matched" as new, which is the safe
    direction. ``diff_result`` already documents the matching contract.
    """
    new_findings, diff = diff_result(result, target, baseline_records, exclude_paths)
    new_ids = {id(finding) for finding in new_findings}
    excludes = {
        os.path.abspath(str(candidate)) for candidate in exclude_paths if candidate
    }
    annotate = _annotate_findings(result.findings, new_ids, excludes)
    return (
        replace(result, findings=annotate, baseline=diff.to_dict()),
        diff,
    )


def _annotate_findings(
    findings: Sequence[Finding], new_ids: set, excludes: Collection[str]
) -> List[Finding]:
    """A copy of ``findings`` with ``baseline_state`` set, in the same order.

    A finding about an excluded path was never compared to the snapshot, so it
    keeps ``baseline_state = None``: calling it ``matched`` would hide it from
    an ``only_new`` gate without the snapshot ever listing it.
    """
    annotated: List[Finding] = []
    for finding in findings:
        if finding.baseline_state is not None:
            annotated.append(finding)
            continue
        if _is_excluded(finding.file, excludes):
            annotated.append(finding)
            continue
        annotated.append(
            replace(
                finding,
                baseline_state="new" if id(finding) in new_ids else "matched",
            )
        )
    return annotated
