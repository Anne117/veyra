"""Deterministic ``veyra explain <finding-id|path-id>`` (T13).

The command answers one question -- "what exactly is this record?" -- from a
fresh scan of the target, with no LLM, no network and no report file. It
explains ONE Finding or ONE AttackPath and says so: one record being explained
is never evidence that the rest of the target is clean.

Identity
--------
Finding ids are derived, not stored: ``fnd-`` plus the first 12 hex digits of
SHA-256 over the same five-field record tuple the baseline already uses
(``rule_id``, the file relative to the scan root, ``line``, the path-scrubbed
``evidence``, ``severity``). The fields are joined with the unit separator
``\\x1f`` and each field escapes ``\\`` and ``\\x1f`` first, so the encoding is
unambiguous without depending on a serialiser's options. ``docs/EXPLAIN.md``
states the recipe in full and a test executes that recipe as written.

Two findings that agree on all five fields produce the same id. The command
then refuses to pick one of them and reports the ambiguity; it never explains
"the first match".

Path ids are the existing full semantic ``AttackPath.path_id`` (64 lowercase
hex digits). Prefixes are not accepted: a prefix is ambiguous by construction.

Input handling
--------------
The id is validated against a strict regular expression *before* the target is
touched. It is never joined into a path, never globbed, never used as a format
string. A rejected or unknown id exits 2 with a message on stderr, an empty
stdout and no traceback; the id is echoed back escaped and the ids that do
exist in the run are listed next to it.

Untrusted text
--------------
``evidence``, ``matched_text``, file names, titles and node labels are
controlled by the author of the scanned repository. They go through the
baseline's path scrubber (``_sanitize_evidence`` -- reused on purpose, so
"no host path in output" keeps one definition) and through the single
control-character escaper in ``veyra.sanitize`` before anything is printed.

Proof, not assertion
--------------------
For a path the explanation re-checks the *stored* node/edge sequence against
the definition of its ``attack_type`` before it says anything about proof.
The definition is printed as a definition; the verdict is derived from the
record. A path whose stored edges do not establish its recorded type is
reported as ``proof-result: not-proven``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from veyra.baseline import (
    BaselineRecord,
    _current_pairs,
    _location_map,
    _sanitize_evidence,
    scan_root,
)
from veyra.coverage import PRUNE_VENDORED_DIR
from veyra.graph.path import AttackPath, AttackType, _node_kind
from veyra.models import POLICY_FAIL, POLICY_PASS, Finding, ScanResult
from veyra.sanitize import escape_untrusted

# --- identity -------------------------------------------------------------

FINDING_ID_PREFIX = "fnd-"
FINDING_ID_HEX = 12

#: Strict shapes. Checked before the target is touched; nothing else is
#: accepted, and no prefix of a path id is accepted either.
FINDING_ID_RE = re.compile(r"\Afnd-[0-9a-f]{12}\Z")
PATH_ID_RE = re.compile(r"\A[0-9a-f]{64}\Z")

#: Field separator of the derived finding id (ASCII unit separator).
FINDING_FIELD_SEP = "\x1f"

#: How many ids an error message lists before it says the rest are omitted.
MAX_LISTED_IDS = 20

# --- display vocabulary ---------------------------------------------------

#: Printed in place of a field that has no value. Carries no data of its own.
ABSENT = "(none)"
YES = "yes"
NO = "no"

#: The one sentence in the output that is not a field restatement. Fixed text:
#: the test asserts the printed line equals this constant verbatim.
SCOPE_NOTE = (
    "this explains one record of one run; it is not a verdict on the rest of "
    "the target"
)

#: Run-level labels. Every one of them is a ``ScanResult`` member or the fixed
#: ``scope`` note; a test derives that from the model rather than trusting this
#: tuple.
RUN_LABELS = ("target", "coverage_status", "policy_status", "scope")

# --- proof vocabulary -----------------------------------------------------
# A small fixed vocabulary, in the spirit of ``veyra.coverage``'s reason
# tokens: the explanation never invents a check name at runtime.

PROOF_CONTIGUOUS = "contiguous-walk"
PROOF_READS_INTO_ASSET = "reads-into-asset"
PROOF_FLOWS_TO_LINEAGE = "flows-to-lineage"
PROOF_SENDS_TO_ENDPOINT = "sends-to-endpoint"
PROOF_ASSET_KIND = "asset-kind-matches-type"
PROOF_SKILL_EXECUTES_ACTION = "skill-executes-action"
PROOF_ASSOCIATED_SECRET_READ = "associated-secret-read"
PROOF_NO_SECRET_TO_ACTION = "no-secret-to-action-edge"

PROOF_CHECKS = frozenset(
    {
        PROOF_CONTIGUOUS,
        PROOF_READS_INTO_ASSET,
        PROOF_FLOWS_TO_LINEAGE,
        PROOF_SENDS_TO_ENDPOINT,
        PROOF_ASSET_KIND,
        PROOF_SKILL_EXECUTES_ACTION,
        PROOF_ASSOCIATED_SECRET_READ,
        PROOF_NO_SECRET_TO_ACTION,
    }
)

PROOF_BANNER = "Proof check against this record's stored edges"

PROOF_RESULT_PROVEN = "proven"
PROOF_RESULT_NOT_PROVEN = "not-proven"

PROOF_LABELS = (
    "proof",
    "proof-definition",
    "proof-check",
    "proof-check-failed",
    "proof-edge",
    "proof-result",
)

#: Definition of each attack type, phrased as a definition ("X means ..."),
#: never as a claim about the record being explained. The stored edge sequence
#: is checked separately and the verdict is printed by ``proof-result``.
PROOF_DEFINITIONS = {
    AttackType.SECRET_EXFILTRATION.value: (
        "an attack_type of SECRET_EXFILTRATION means: a contiguous walk whose "
        "edge into the first SECRET asset is READS, whose edges from that asset "
        "up to the object before the endpoint are FLOWS_TO, and whose last edge "
        "is SENDS_TO, establishes that the secret reaches an external endpoint"
    ),
    AttackType.DATA_EXFILTRATION.value: (
        "an attack_type of DATA_EXFILTRATION means: a contiguous walk whose "
        "edge into the first DATA asset is READS, whose edges from that asset "
        "up to the object before the endpoint are FLOWS_TO, and whose last edge "
        "is SENDS_TO, establishes that the data object reaches an external "
        "endpoint"
    ),
    AttackType.CORRELATED_SECRET_EXECUTION.value: (
        "an attack_type of CORRELATED_SECRET_EXECUTION means: a contiguous "
        "SKILL --EXECUTES--> ACTION walk plus an associated SKILL --READS--> "
        "SECRET edge on the same skill establishes a shared-skill correlation "
        "only; it does not establish that the secret flowed into the action"
    ),
    AttackType.UNKNOWN.value: (
        "an attack_type of UNKNOWN means: no attack semantic was established "
        "for the stored walk, so no proof is stated for it"
    ),
}


class ExplainError(Exception):
    """An id could not be explained. The CLI maps this to exit 2."""


# --- id derivation --------------------------------------------------------


def _id_escape(text: str) -> str:
    """Escape a field so it cannot collide with ``FINDING_FIELD_SEP``."""
    return text.replace("\\", "\\\\").replace(FINDING_FIELD_SEP, "\\x1f")


def finding_id_for(record: BaselineRecord) -> str:
    """The derived id of one finding record (see ``docs/EXPLAIN.md``)."""
    fields = (
        _id_escape(record.rule_id),
        _id_escape(record.file),
        "" if record.line is None else str(record.line),
        _id_escape(record.evidence),
        _id_escape(record.severity),
    )
    digest = hashlib.sha256(
        FINDING_FIELD_SEP.join(fields).encode("utf-8")
    ).hexdigest()
    return FINDING_ID_PREFIX + digest[:FINDING_ID_HEX]


def classify_id(raw_id: str) -> Optional[str]:
    """Return ``"finding"``, ``"path"`` or ``None`` for ``raw_id``.

    Pure string matching: no filesystem access, no path joining, no globbing.
    """
    if FINDING_ID_RE.match(raw_id):
        return "finding"
    if PATH_ID_RE.match(raw_id):
        return "path"
    return None


# --- entries --------------------------------------------------------------


@dataclass(frozen=True)
class FindingEntry:
    """One finding of the run plus the record its id is derived from."""

    id: str
    record: BaselineRecord
    finding: Finding


def finding_entries(
    result: ScanResult, root_abs: Optional[str] = None
) -> List[FindingEntry]:
    """Every finding of ``result`` with its derived id, ordered by id."""
    root = root_abs if root_abs is not None else scan_root(result.target)
    entries = [
        FindingEntry(finding_id_for(record), record, finding)
        for finding, record in _current_pairs(result.findings, root)
    ]
    entries.sort(key=lambda e: (e.id, e.record.sort_key()))
    return entries


def path_entries(result: ScanResult) -> List[Tuple[str, AttackPath]]:
    """Every attack path of ``result`` with its semantic id, ordered by id."""
    pairs = [(path.ensure_path_id(), path) for path in result.attack_paths]
    pairs.sort(key=lambda item: item[0])
    return pairs


# --- display --------------------------------------------------------------


def display_text(text: Any, root_abs: str, mapping: Dict[str, str]) -> str:
    """Scrub host paths, then make control characters visible.

    The two steps are the existing ones -- ``veyra.baseline._sanitize_evidence``
    and ``veyra.sanitize.escape_untrusted`` -- applied in that order, so a
    scrubber rewrite cannot reintroduce a raw newline and an escape cannot hide
    a path behind ``\\x2f``.
    """
    return escape_untrusted(_sanitize_evidence(str(text), root_abs, mapping))


def _render_edge(edge: Tuple[str, str, str], display) -> str:
    source, target, edge_type = edge
    return f"{display(source)} --{edge_type}--> {display(target)}"


def _render_breakpoint(breakpoint, display) -> str:
    edge = (breakpoint.source_node, breakpoint.target_node, breakpoint.edge_type)
    return f"{_render_edge(edge, display)} [{breakpoint.impact.value}] {display(breakpoint.reason)}"


# --- explanation ----------------------------------------------------------


@dataclass(frozen=True)
class Explanation:
    """A rendered explanation, kept as its three blocks.

    ``body`` is a pure projection of one record: every line is
    ``<field>: <value>`` with a real dataclass field (or field of a nested
    record) on the left and a value taken from that record on the right.
    ``proof`` holds the definition/check/verdict lines for a path.
    """

    kind: str
    record_id: str
    header: Tuple[str, ...]
    body: Tuple[str, ...]
    proof: Tuple[str, ...] = ()

    def lines(self) -> List[str]:
        out = list(self.header) + [""] + list(self.body)
        if self.proof:
            out += [""] + list(self.proof)
        return out

    def text(self) -> str:
        return "\n".join(self.lines()) + "\n"


def _header(result: ScanResult, target: str) -> Tuple[str, ...]:
    # ``target`` is the caller's own argument, not scanned content: it is
    # escaped but not path-scrubbed, because rewriting what the user asked to
    # scan would make the line useless. Repo-controlled text below IS scrubbed.
    return (
        f"target: {escape_untrusted(target)}",
        _coverage_line(result),
        _policy_line(result),
        f"scope: {SCOPE_NOTE}",
    )


def _coverage_line(result: ScanResult) -> str:
    vendored = sum(
        1 for record in result.dirs_pruned if record.get("reason") == PRUNE_VENDORED_DIR
    )
    return (
        f"coverage_status: {result.coverage_status} "
        f"({result.files_scanned} files read, "
        f"{len(result.files_skipped)} skipped, "
        f"{len(result.decode_errors)} lossy, "
        f"{vendored} vendored dirs not entered)"
    )


def _policy_line(result: ScanResult) -> str:
    status = result.policy_status
    if status == POLICY_FAIL:
        note = "a policy violation is proven for this run"
    elif status == POLICY_PASS:
        note = "no violation is proven and the whole target was read"
    else:
        note = (
            f"coverage is {result.coverage_status}: no violation is proven, "
            "and that is not a pass"
        )
    return f"policy_status: {status} ({note})"


def _put(lines: List[str], label: str, value: str) -> None:
    lines.append(f"{label}: {value}")


def _or_absent(display, value: str) -> str:
    return display(value) if value else ABSENT


def explain_finding(
    result: ScanResult, target: str, entry: FindingEntry,
    root_abs: Optional[str] = None,
) -> Explanation:
    """Project one finding. No claim is made that is not a stored field."""
    root = root_abs if root_abs is not None else scan_root(target)
    mapping = _location_map(result.findings, root)
    display = lambda value: display_text(value, root, mapping)
    finding = entry.finding

    body: List[str] = []
    _put(body, "rule_id", display(finding.rule_id))
    _put(body, "severity", finding.severity.value)
    _put(body, "confidence", finding.confidence.value)
    _put(body, "title", _or_absent(display, finding.title))
    _put(body, "description", _or_absent(display, finding.description))
    _put(body, "file", display(finding.file))
    _put(body, "line", ABSENT if finding.line is None else str(finding.line))
    _put(body, "evidence", _or_absent(display, finding.evidence))
    _put(body, "matched_text", _or_absent(display, finding.matched_text))
    _put(body, "remediation", _or_absent(display, finding.remediation))
    for mapping_entry in finding.mitre:
        _put(body, "mitre", display(mapping_entry.get("id", "")))
        _put(body, "mitre", display(mapping_entry.get("name", "")))
    for cwe_id in finding.cwe:
        _put(body, "cwe", display(cwe_id))
    _put(body, "suppressed", YES if finding.suppressed else NO)
    if finding.suppressed:
        # A suppressed record is printed AS suppressed, with the stated reason.
        # Dropping it, or printing it as if nothing had matched, would turn a
        # configuration decision into a silent absence.
        _put(body, "suppression_reason", _or_absent(display, finding.suppression_reason))
    _put(body, "baseline_state", finding.baseline_state or ABSENT)

    return Explanation(
        kind="finding",
        record_id=entry.id,
        header=(f"Veyra explain  finding {entry.id}",)
        + _header(result, target),
        body=tuple(body),
    )


def explain_path(
    result: ScanResult, target: str, path: AttackPath,
    root_abs: Optional[str] = None,
) -> Explanation:
    """Project one attack path and verify its proof against its own edges."""
    root = root_abs if root_abs is not None else scan_root(target)
    mapping = _location_map(result.findings, root)
    display = lambda value: display_text(value, root, mapping)
    path_id = path.ensure_path_id()

    body: List[str] = []
    _put(body, "path_id", path_id)
    _put(body, "attack_type", path.attack_type.value)
    _put(body, "severity", path.severity.value)
    _put(body, "confidence", path.confidence.value)
    _put(body, "title", _or_absent(display, path.title))
    _put(body, "description", _or_absent(display, path.description))
    _put(body, "entry_node", _or_absent(display, path.entry_node))
    _put(body, "asset_node", _or_absent(display, path.asset_node))
    _put(body, "sink_node", _or_absent(display, path.sink_node))
    _put(body, "risk_severity", path.risk_severity.value)
    _put(body, "risk_confidence", path.risk_confidence.value)
    _put(body, "risk_score", str(path.risk_score))
    _put(body, "explanation", _or_absent(display, path.explanation))
    for node in path.nodes:
        _put(body, "nodes", display(node))
    for edge in path.edges:
        _put(body, "edges", _render_edge(edge, display))
    for edge in path.associated_edges:
        _put(body, "associated_edges", _render_edge(edge, display))
    for fact in path.evidence:
        _put(body, "evidence", display(fact))
    for policy_id in path.policy_ids:
        _put(body, "policy_ids", display(policy_id))
    for breakpoint in path.breakpoints:
        _put(body, "breakpoints", _render_breakpoint(breakpoint, display))
    _put(body, "is_composed", YES if path.is_composed else NO)
    for component_id in path.component_ids:
        _put(body, "component_ids", display(component_id))

    return Explanation(
        kind="path",
        record_id=path_id,
        header=(f"Veyra explain  attack path {path_id}",)
        + _header(result, target),
        body=tuple(body),
        proof=tuple(_proof_lines(path, display)),
    )


# --- proof verification ---------------------------------------------------


@dataclass(frozen=True)
class ProofCheck:
    """One clause of the attack-type definition, checked against the record."""

    token: str
    ok: bool
    edges: Tuple[Tuple[str, str, str], ...] = ()


def _check_exfiltration(path: AttackPath) -> List[ProofCheck]:
    nodes = list(path.nodes)
    edges = list(path.edges)
    contiguous = path.is_contiguous and bool(nodes)
    checks = [ProofCheck(PROOF_CONTIGUOUS, contiguous, tuple(edges))]
    if not contiguous:
        return checks

    asset_idx = next(
        (i for i, node in enumerate(nodes) if _node_kind(node) in ("SECRET", "DATA")),
        None,
    )
    read_ok = (
        asset_idx is not None
        and asset_idx >= 1
        and edges[asset_idx - 1][2] == "READS"
    )
    checks.append(
        ProofCheck(
            PROOF_READS_INTO_ASSET,
            read_ok,
            (edges[asset_idx - 1],) if read_ok else (),
        )
    )

    last = edges[-1]
    send_ok = last[2] == "SENDS_TO" and _node_kind(nodes[-1]) == "ENDPOINT"
    checks.append(ProofCheck(PROOF_SENDS_TO_ENDPOINT, send_ok, (last,) if send_ok else ()))

    lineage_edges: Tuple[Tuple[str, str, str], ...] = ()
    if asset_idx is not None and len(edges) > asset_idx and edges[-1][2] == "SENDS_TO":
        # The clause only means something when an edge actually leaves the
        # asset and the walk ends at the endpoint; otherwise "no intermediate
        # edge is not FLOWS_TO" would be vacuously true.
        tail = edges[asset_idx:len(edges) - 1]
        lineage_ok = all(edge[2] == "FLOWS_TO" for edge in tail)
        if lineage_ok:
            lineage_edges = tuple(tail)
    else:
        lineage_ok = False
    checks.append(ProofCheck(PROOF_FLOWS_TO_LINEAGE, lineage_ok, lineage_edges))

    wanted = "SECRET" if path.attack_type == AttackType.SECRET_EXFILTRATION else "DATA"
    kind_ok = asset_idx is not None and _node_kind(nodes[asset_idx]) == wanted
    checks.append(ProofCheck(PROOF_ASSET_KIND, kind_ok))
    return checks


def _check_correlated_execution(path: AttackPath) -> List[ProofCheck]:
    nodes = list(path.nodes)
    edges = list(path.edges)
    contiguous = path.is_contiguous and bool(nodes)
    checks = [ProofCheck(PROOF_CONTIGUOUS, contiguous, tuple(edges))]
    if not contiguous:
        return checks

    walk_ok = (
        len(nodes) == 2
        and len(edges) == 1
        and edges[0][2] == "EXECUTES"
        and _node_kind(nodes[0]) == "SKILL"
        and _node_kind(nodes[1]) == "ACTION"
    )
    checks.append(ProofCheck(PROOF_SKILL_EXECUTES_ACTION, walk_ok, (edges[0],) if walk_ok else ()))

    read_edges = tuple(
        edge
        for edge in path.associated_edges
        if edge[2] == "READS"
        and edge[0] == nodes[0]
        and _node_kind(edge[1]) == "SECRET"
    )
    checks.append(ProofCheck(PROOF_ASSOCIATED_SECRET_READ, bool(read_edges), read_edges))

    # The correlation is restated honestly only when no edge in this record
    # claims the secret flowed into the action. Both endpoints must be named
    # for the check to be able to mean anything: an unnamed asset would make
    # "no edge claims a flow" vacuously true.
    asset = path.asset_node
    sink = path.sink_node
    named = bool(asset and sink)
    claims_flow = named and any(
        edge[0] == asset and edge[1] == sink
        for edge in list(path.edges) + list(path.associated_edges)
    )
    checks.append(ProofCheck(PROOF_NO_SECRET_TO_ACTION, named and not claims_flow))
    return checks


def proof_checks(path: AttackPath) -> List[ProofCheck]:
    """Check the stored edges of ``path`` against its recorded ``attack_type``.

    ``UNKNOWN`` has no definition to satisfy, so it yields no checks and is
    never reported as proven.
    """
    attack_type = path.attack_type if path.is_contiguous else AttackType.UNKNOWN
    if attack_type == AttackType.SECRET_EXFILTRATION:
        return _check_exfiltration(path)
    if attack_type == AttackType.DATA_EXFILTRATION:
        return _check_exfiltration(path)
    if attack_type == AttackType.CORRELATED_SECRET_EXECUTION:
        return _check_correlated_execution(path)
    return []


def _proof_lines(path: AttackPath, display) -> List[str]:
    attack_type = path.attack_type if path.is_contiguous else AttackType.UNKNOWN
    lines: List[str] = [
        PROOF_BANNER,
        f"proof: {attack_type.value}",
        f"proof-definition: {PROOF_DEFINITIONS[attack_type.value]}",
    ]
    checks = proof_checks(path)
    for check in checks:
        label = "proof-check" if check.ok else "proof-check-failed"
        lines.append(f"{label}: {check.token}")
    cited: List[Tuple[str, str, str]] = []
    for check in checks:
        if not check.ok:
            continue
        for edge in check.edges:
            if edge not in cited:
                cited.append(edge)
    for edge in cited:
        lines.append(f"proof-edge: {_render_edge(edge, display)}")
    proven = bool(checks) and all(check.ok for check in checks)
    lines.append(
        f"proof-result: {PROOF_RESULT_PROVEN if proven else PROOF_RESULT_NOT_PROVEN}"
    )
    return lines


# --- resolution and rendering ---------------------------------------------


def _listed_ids(result: ScanResult, root_abs: str) -> List[str]:
    entries = finding_entries(result, root_abs)
    paths = path_entries(result)
    listed = [
        f"{entry.id}  finding  {entry.record.rule_id}  {entry.record.location}"
        for entry in entries
    ]
    listed += [
        f"{path_id}  path  {path.attack_type.value}  risk {path.risk_score}"
        for path_id, path in paths
    ]
    return listed


def _available_block(listed: Sequence[str]) -> List[str]:
    if not listed:
        return ["This run produced no findings and no attack paths."]
    lines = [f"Available ids ({len(listed)}):"]
    for line in listed[:MAX_LISTED_IDS]:
        lines.append(f"  {line}")
    if len(listed) > MAX_LISTED_IDS:
        lines.append(
            f"  ... {len(listed) - MAX_LISTED_IDS} more not shown"
        )
    return lines


def render_explanation(
    result: ScanResult, target: str, raw_id: str, kind: str
) -> str:
    """Explain the record ``raw_id`` of ``result``.

    ``kind`` must come from :func:`classify_id`; anything else is a programming
    error, not user input. Raises :class:`ExplainError` for an unknown or
    ambiguous id.
    """
    root = scan_root(target)
    if kind == "finding":
        entries = [entry for entry in finding_entries(result, root) if entry.id == raw_id]
        if not entries:
            raise ExplainError(_unknown_message(raw_id, result, root))
        if len(entries) > 1:
            raise ExplainError(_ambiguous_finding_message(raw_id, entries, root))
        return explain_finding(result, target, entries[0], root).text()

    paths = [path for path_id, path in path_entries(result) if path_id == raw_id]
    if not paths:
        raise ExplainError(_unknown_message(raw_id, result, root))
    if len(paths) > 1:
        raise ExplainError(_ambiguous_path_message(raw_id, paths))
    return explain_path(result, target, paths[0], root).text()


def render_index(result: ScanResult, target: str, root_abs: Optional[str] = None) -> str:
    """List the ids this run derives, so one of them can be explained."""
    root = root_abs if root_abs is not None else scan_root(target)
    mapping = _location_map(result.findings, root)
    # Same scrub+escape as an explanation: the listing carries rule ids and
    # locations exactly like the error message does.
    listed = [display_text(line, root, mapping) for line in _listed_ids(result, root)]
    header = ("Veyra explain  index",) + _header(result, target)
    body = tuple(_available_block(listed))
    return Explanation(
        kind="index", record_id="", header=header, body=body
    ).text()


def _escape_for_message(raw_id: str) -> str:
    """The rejected id, escaped and bounded, so it can be repeated safely."""
    return escape_untrusted(raw_id)


def invalid_id_message(raw_id: str) -> str:
    """Message for an id that is not one of the two accepted shapes."""
    return (
        f"Error: '{_escape_for_message(raw_id)}' is not a finding or path id. "
        f"Expected '{FINDING_ID_PREFIX}<{FINDING_ID_HEX} lowercase hex digits>' "
        "or a 64-character lowercase hex path id (see docs/EXPLAIN.md)."
    )


def _unknown_message(raw_id: str, result: ScanResult, root: str) -> str:
    mapping = _location_map(result.findings, root)
    lines = [
        f"Error: no record with id '{_escape_for_message(raw_id)}' in this run "
        f"of '{escape_untrusted(result.target)}'."
    ]
    listed = [display_text(line, root, mapping) for line in _listed_ids(result, root)]
    lines += _available_block(listed)
    return "\n".join(lines)


def _ambiguous_finding_message(
    raw_id: str, entries: Sequence[FindingEntry], root: str
) -> str:
    mapping = _location_map([entry.finding for entry in entries], root)
    lines = [
        f"Error: id '{_escape_for_message(raw_id)}' matches {len(entries)} "
        "distinct findings in this run; refusing to pick the first.",
        "Findings that agree on rule_id, file, line, evidence and severity "
        "share a derived id, so this id does not identify one record:",
    ]
    for entry in entries:
        lines.append(
            "  "
            f"{display_text(entry.record.rule_id, root, mapping)}  "
            f"{display_text(entry.record.location, root, mapping)}"
        )
    return "\n".join(lines)


def _ambiguous_path_message(raw_id: str, paths: Sequence[AttackPath]) -> str:
    lines = [
        f"Error: path id '{_escape_for_message(raw_id)}' matches {len(paths)} "
        "records in this run; refusing to pick the first.",
    ]
    for path in paths:
        lines.append(f"  {path.attack_type.value}  risk {path.risk_score}")
    return "\n".join(lines)
