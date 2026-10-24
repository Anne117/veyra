"""Core scanner: recursively inspects files relevant to AI agent skills.

Static analysis only. Never executes scanned code and never makes network
requests.
"""

from __future__ import annotations

import codecs
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from veyra.correlation import correlate_detailed
from veyra.coverage import (
    PRUNE_IGNORED_DIR,
    PRUNE_SYMLINK_DIR,
    PRUNE_VENDORED_DIR,
    RULE_ERROR_FILE,
    RULE_ERROR_LINE,
    SKIP_BASELINE,
    SKIP_BINARY,
    SKIP_DECODE_ERROR,
    SKIP_NOT_SCANNABLE,
    SKIP_TOO_LARGE,
    SKIP_UNREADABLE,
    ScanCoverage,
)
from veyra.cwe import cwe_for
from veyra.graph import PathAnalyzer, build_from_actions, build_from_findings, NodeType
from veyra.graph.context import (
    ComponentContextAssociation,
    ComponentContextError,
    associate_security_behavior,
    build_component_path_composition_for_paths,
    build_component_path_participation_for_paths,
    build_component_risk_evidence_for_paths,
    serialize_component_path_composition,
    serialize_component_path_participation,
    serialize_component_risk_evidence,
    serialize_component_security_scopes,
)
from veyra.mitre import mitre_for
from veyra.models import Confidence, Finding, ScanResult, Severity
from veyra.rules import load_file_rules, load_rules
from veyra.rules.network import collapse_http_claims
from veyra.step_sequence import analyze_file_chains, clear_code_line_cache

# File extensions we inspect. Everything else is skipped.
SCAN_EXTENSIONS = {
    ".md",
    ".markdown",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".txt",
    ".cfg",
    ".conf",
    ".ini",
    ".env",
}

# Files always inspected regardless of extension.
ALWAYS_SCAN = {"SKILL.md", "AGENTS.md", "CLAUDE.md", ".hermes.md", "HERMES.md"}

# Directories the walk never descends into, split by *why* it refuses them.
#
# The split is a statement about the target, not bookkeeping. Machine-produced
# state holds nothing the target's author wrote: skipping it is not a hole, and
# a coverage verdict must not move because a checkout carries a
# ``.pytest_cache``. Vendored and build output is a different claim -- it can
# ship configuration (an ``.env`` inside an installed package, a secret
# compiled into a bundle) that no rule here ever opens -- so a scan standing on
# top of it may not call itself complete. Both are named in ``dirs_pruned``;
# only the second makes ``coverage_status`` ``partial`` (owner decision (b),
# ``T8`` in ``NIGHT-QUEUE.md``).
SKIP_DIRS_MACHINE = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
}

SKIP_DIRS_VENDORED = {
    "node_modules",
    "dist",
    "build",
    "site-packages",
    ".next",
    "target",
    ".eggs",
}

# Kept as one name because callers and the walk only ask "is this skipped".
SKIP_DIRS = SKIP_DIRS_MACHINE | SKIP_DIRS_VENDORED

# Maximum file size to scan (bytes). Larger files are skipped as "binary/large".
MAX_FILE_SIZE = 1_000_000  # 1 MB


def _is_binary(data: bytes) -> bool:
    """Heuristic: a file is binary if it contains a NUL byte in the first chunk."""
    return b"\x00" in data[:8192]


# Byte-order marks that declare a file as text even though its ASCII characters
# are padded with NUL bytes. Longest first: the UTF-32LE mark opens with the
# UTF-16LE mark, so a shorter mark must never be tested first.
_TEXT_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _decode_declared_text(data: bytes) -> Optional[str]:
    """Decode a BOM-declared UTF-16/32 file; ``None`` if it is not one.

    The NUL heuristic calls every UTF-16 document binary, because each ASCII
    character carries a NUL byte. A BOM is the file saying what it is, so the
    declaration wins -- but only when the body decodes strictly: a BOM in front
    of garbage stays binary. BOM-less UTF-16 is still not guessed at.
    """
    for bom, encoding in _TEXT_BOMS:
        if data.startswith(bom):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                return None
    return None


def _should_scan(path: Path) -> bool:
    if path.name in ALWAYS_SCAN:
        return True
    return path.suffix.lower() in SCAN_EXTENSIONS


# One answer per line text.
#
# A line rule is a pure function of the text it is handed: ``file_path`` and
# ``line`` are stamped onto the Finding it returns, they never decide it. All
# 28 registered rules were checked over 291 742 lines -- same verdict for
# ``a.py`` line 1 and ``b.md`` line 977 -- and 34 985 of the 111 083 lines of
# ``agent/`` (31 %) are repeats of a line the same scan already read.
#
# So the scan remembers, per line text, the *indexes* of the rules that were
# not quiet: a rule that returned None for a text returns None for it again,
# and need not be asked. A replay calls exactly those rules, so every Finding
# is still produced by the rule itself on the current file path and line
# number -- the cache can only skip a question, never answer one.
#
# A rule that raised is recorded as loud, not quiet: the loss is a fact about
# *this* file and line and has to be written down again for each one. The
# entry is also bound to the rule list it was learned with, so a caller that
# scans two directories with two different rule sets never replays one set's
# answer against another's indexes.
_LINE_RULE_CACHE_SEGMENTS = 100_000
_loud_rule_indexes: Dict[str, Tuple[int, ...]] = {}
_loud_rule_list: Optional[List] = None


def _clear_line_rule_cache() -> None:
    """Forget the per-line answers; ``scanner.scan_path`` calls this twice."""
    global _loud_rule_list
    _loud_rule_indexes.clear()
    _loud_rule_list = None


def scan_path(
    target: str,
    component_context: Optional[List[ComponentContextAssociation]] = None,
    exclude_paths: Optional[List[str]] = None,
) -> ScanResult:
    """Scan a file or directory and return a ScanResult.

    ``exclude_paths`` names files the caller owns and the walk must not read
    (a baseline snapshot living inside the target). They are skipped before
    any rule sees them, and the skip is RECORDED in coverage
    (``baseline_snapshot``), because the file is target content nobody read:
    the report says how many files were skipped and ``coverage_status`` turns
    ``full`` into ``partial``. An unrecorded exclusion would be a detection
    hole that still claims a complete read -- the same silence the coverage
    block exists to end. Without the exclusion itself, a snapshot of a tree
    that sits inside that same tree fingerprints its own bytes, the next run
    sees a changed chain evidence line, and every scan manufactures a "new"
    finding.

    ``component_context`` is an OPTIONAL additive, explicit input: a list of
    already-validated :class:`ComponentContextAssociation` objects. When
    supplied, each association's security-behavior edge and component must
    actually exist in the scan's merged security graph (verified through the
    existing ``associate_security_behavior`` API), and the resulting
    per-component security scopes, per-path component participation, per-path
    component composition, AND per-path component risk evidence are projected
    onto ``ScanResult.component_security_scopes`` /
    ``ScanResult.component_path_participation`` /
    ``ScanResult.component_path_composition`` /
    ``ScanResult.component_risk_evidence`` (exposed in JSON/SARIF/HTML).

    Ownership is NEVER inferred: without explicit associations, no component
    security scopes are produced regardless of USES/CONTAINS/CALLS/TRUSTS/
    HANDOFF or any naming/provenance signal. Supplying no ``component_context``
    leaves all existing scan behaviour completely unchanged.
    """
    rules = load_rules()
    file_rules = load_file_rules()
    # One recorder per scan: every file the scanner refuses and every rule that
    # raises is written down here instead of disappearing (see veyra.coverage).
    coverage = ScanCoverage()
    # The tokenisation memo belongs to one scan, not to the process: the two
    # phases below ask for the same file's code lines, and a long-lived caller
    # (tests, serve mode) must not keep file contents alive between scans. The
    # per-line rule answers (``_loud_rule_indexes``) are dropped with it.
    clear_code_line_cache()
    _clear_line_rule_cache()
    findings: List[Finding] = []
    file_texts: List[str] = []  # (text, path) pairs for step-sequence analysis
    root = Path(target)
    excluded = {
        os.path.abspath(str(candidate)) for candidate in (exclude_paths or ()) if candidate
    }

    if root.is_file():
        if excluded and os.path.abspath(str(root)) in excluded:
            coverage.skipped(str(root), SKIP_BASELINE)
        else:
            findings.extend(_scan_file(root, rules, file_rules, file_texts, coverage))
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            # Name every subtree the walk refuses to enter. The name is a
            # record, not a verdict: coverage_status does not read it (see
            # veyra.coverage.PRUNE_REASONS), but the report can no longer say
            # "full" while silently standing on top of an unopened
            # node_modules/, dist/ or a symlinked directory.
            #
            # Three refusals, three names. ``SKIP_DIRS`` is the scanner's own
            # choice, and the group it belongs to decides whether the refusal
            # costs the verdict its "full" (see ``SKIP_DIRS_VENDORED``). A
            # symlinked directory is never followed by
            # ``os.walk`` (``followlinks=False``), while a symlinked *file*
            # is read -- so the reach of the scan depends on the link type
            # and, without a name here, on nothing the report can state.
            for name in dirnames:
                if name in SKIP_DIRS_VENDORED:
                    coverage.pruned(
                        str(Path(dirpath) / name), PRUNE_VENDORED_DIR
                    )
                elif name in SKIP_DIRS_MACHINE:
                    coverage.pruned(
                        str(Path(dirpath) / name), PRUNE_IGNORED_DIR
                    )
                elif (Path(dirpath) / name).is_symlink():
                    coverage.pruned(
                        str(Path(dirpath) / name), PRUNE_SYMLINK_DIR
                    )
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if excluded and os.path.abspath(str(fpath)) in excluded:
                    # Recorded, not silently dropped: the file is in the tree,
                    # no rule read it, and the report must say so (coverage
                    # turns ``partial``). See the docstring above.
                    coverage.skipped(str(fpath), SKIP_BASELINE)
                    continue
                findings.extend(
                    _scan_file(fpath, rules, file_rules, file_texts, coverage)
                )
    else:
        raise FileNotFoundError(f"Path not found: {target}")

    # Run the contextual correlation layer over all findings.
    # Correlation findings are added separately; original findings are preserved.
    correlated = correlate_detailed(findings)
    findings.extend(chain for chain, _ in correlated)

    # Run intra-file step-sequence analysis. This fills the gap when individual
    # steps are too benign to generate standalone findings. Deduplicate against
    # what correlation ALREADY reports: correlation chains are aggregated under
    # "<correlated>", so a per-rule-id check dropped every intra-file chain in
    # the tree as soon as one correlation chain of the same rule fired anywhere.
    # Coverage is per artifact AND per line, taken from the findings each chain
    # was built from: a chain is skipped only when a contributing finding of
    # the same rule in the same file sits inside the chain's own line span,
    # i.e. when both describe the same lines. A second, distinct chain in a
    # file that correlation also touches elsewhere is a different fact and is
    # reported. A contributor without a line covers the whole file.
    covered: Dict[Tuple[str, str], List[Optional[int]]] = {}
    for chain, contributors in correlated:
        for contributor in contributors:
            covered.setdefault((chain.rule_id, contributor.file), []).append(
                contributor.line
            )
    for text, path in file_texts:
        for chain, first, last in analyze_file_chains(text, path):
            lines = covered.get((chain.rule_id, path))
            if lines and any(line is None or first <= line <= last for line in lines):
                continue
            findings.append(chain)

    # Attach approved public MITRE ATT&CK metadata, CWE IDs, and a
    # deterministic confidence estimate to findings.
    # This is metadata/reporting only — it does not change detection logic.
    for f in findings:
        f.mitre = mitre_for(f.rule_id, f.evidence)
        f.cwe = cwe_for(f.rule_id)
        f.confidence = _confidence_for(f)
        # Correlation/step-sequence findings have no single source line; use
        # the evidence as the smallest defensible source fragment.
        if not f.matched_text:
            f.matched_text = f.evidence or ""

    result = ScanResult(target=target, findings=findings)
    # Coverage accounting (additive): what was read, what was refused and why.
    # This says nothing about detection -- it only stops a partial read from
    # looking like a complete one.
    coverage_snapshot = coverage.snapshot()
    result.files_scanned = coverage_snapshot["files_scanned"]
    result.files_skipped = coverage_snapshot["files_skipped"]
    result.rule_errors = coverage_snapshot["rule_errors"]
    result.decode_errors = coverage_snapshot["decode_errors"]
    result.dirs_pruned = coverage_snapshot["dirs_pruned"]
    attack_paths, merged = _build_attack_paths(findings, file_texts)
    result.attack_paths = attack_paths
    # Derive a deterministic mapping from finalized attack paths to a real
    # source file, using ONLY data already present in the merged SecurityGraph.
    # The entry node of an AttackPath is a real graph node; when its type is
    # SKILL, its label is the normalized file path that produced the finding.
    # This is NOT a fabrication: it references an actual node in the same
    # merged graph that produced the path itself. For non-SKILL entry nodes
    # (e.g. a SECRET/DATA/ENDPOINT reached through an upstream component) we
    # deliberately leave the path out of this map; SARIF will then explicitly
    # mark `location_provenance = "omitted"` rather than invent coordinates.
    from veyra.graph.builder import _component_id as _component_id_for_file
    entry_files: Dict[str, str] = {}
    for ap in attack_paths:
        if not ap.entry_node:
            continue
        node = merged.get_node(ap.entry_node)
        if node is None or node.type != NodeType.SKILL:
            continue
        file_path = (node.label or "").strip()
        if not file_path:
            continue
        # Trust the builder's normalization only for files this scan actually
        # read. This keeps synthetic nodes out without tying path locations to
        # whether a file happened to produce a finding: a file can produce a
        # proven path through a correlation node while its own line rules are
        # silent.
        if file_path not in {p for _, p in file_texts}:
            continue
        entry_files[ap.ensure_path_id()] = file_path
    result.attack_path_entry_files = entry_files
    # Evaluate the FINALIZED, deduplicated AttackPath objects with the built-in
    # PolicyEngine. PolicyEngine is the sole owner of policy trigger semantics;
    # the scanner only orchestrates finalized_paths -> evaluate() ->
    # ScanResult.policy_results. Local import avoids any import cycle.
    from veyra.policy import PolicyEngine, associate_policy_ids
    result.policy_results = PolicyEngine().evaluate(attack_paths)
    # Project the violated policy IDs onto each AttackPath (structured, explicit).
    # PolicyEngine remains the sole owner of trigger semantics; this only records
    # the deterministic relationship. Never changes path identity.
    associate_policy_ids(attack_paths, result.policy_results)
    # Refresh the deterministic explanation now that policy_ids are final, so the
    # structured explanation reflects the final (associated) path state. This is
    # metadata only and never changes path identity, risk, or policy semantics.
    from veyra.graph.path import build_explanation
    for p in attack_paths:
        p.explanation_details = build_explanation(p)
    # Assertion layer: every path must own its identity and every edge it names,
    # and no path or policy result may claim more than the walk proves. This runs
    # on the finalized artifacts against the very graph that produced them, so a
    # report can never be built from a chain that has already broken its own
    # provenance. It raises rather than repairs.
    from veyra.invariants import assert_provenance
    assert_provenance(attack_paths, result.policy_results, merged)

    # Additive explicit component-security-scope projection. Only when the
    # caller supplied explicit ComponentContextAssociation records: each is
    # re-validated through the existing association API against the merged
    # graph (real edge + real matching component), then grouped into
    # deterministic scopes and per-path participation. Without explicit
    # associations no ownership is ever inferred and both stay empty.
    if component_context:
        for assoc in component_context:
            associate_security_behavior(
                merged,
                assoc.edge_key,
                assoc.component,
                source=assoc.source,
            )
        result.component_security_scopes = serialize_component_security_scopes(merged)
        valid_components = {
            nid: n.type for nid, n in merged.nodes.items()
            if n.type in (NodeType.AGENT, NodeType.SKILL, NodeType.TOOL, NodeType.MCPSERVER)
        }
        existing_edges = {
            (e.source, e.target, e.type.value) for e in merged.edges
        }
        result.component_path_participation = serialize_component_path_participation(
            build_component_path_participation_for_paths(
                attack_paths,
                component_context,
                valid_components=valid_components,
                existing_edges=existing_edges,
            )
        )
        result.component_path_composition = serialize_component_path_composition(
            build_component_path_composition_for_paths(
                attack_paths,
                component_context,
                valid_components=valid_components,
                existing_edges=existing_edges,
            )
        )
        result.component_risk_evidence = serialize_component_risk_evidence(
            build_component_risk_evidence_for_paths(
                attack_paths,
                component_context,
                valid_components=valid_components,
                existing_edges=existing_edges,
            )
        )
    # Both phases that read code lines are done: drop the tokenisation memo and
    # the per-line rule answers now instead of letting the last scan's file
    # texts wait for the next one.
    clear_code_line_cache()
    _clear_line_rule_cache()
    return result


def _build_attack_paths(findings: List[Finding], file_texts: List[tuple]):
    """Construct attack paths from the Security Graph, analyzed PER COMPONENT.

    The scanner scans many files; findings and step-sequence actions belong to
    the specific file/component that produced them. Merging everything into a
    single global graph would let unrelated files cross-link through shared
    object names (e.g. two files both using ``DATA:report`` or the same
    endpoint), creating accidental cross-file attack paths.

    To preserve attribution and prevent cross-file paths, we group findings and
    actions by component identity (the same normalized path the graph builder
    uses) and analyze each component's graph independently. This guarantees
    that a path is attributable to the actual file that contains the relevant
    actions/findings.

    Deterministic; never modifies the findings.

    Returns ``(attack_paths, merged_graph)`` — the cross-component merged graph
    is also returned so callers can attach explicit component-context metadata
    (it is a superset of every per-component node/edge, so any real security
    edge referenced by an explicit association exists there).
    """
    from veyra.graph.builder import _component_id
    from veyra.step_sequence import _extract_action, _split_actions

    # Group findings by component.
    findings_by_component: Dict[str, List[Finding]] = {}
    for f in findings:
        findings_by_component.setdefault(_component_id(f.file), []).append(f)

    # Group step-sequence actions by component (same normalized path).
    actions_by_component: Dict[str, List] = {}
    for text, path in file_texts:
        key = _component_id(path)
        for line in text.splitlines():
            for segment in _split_actions(line):
                action = _extract_action(segment)
                if action is not None:
                    actions_by_component.setdefault(key, []).append(action)

    all_paths = []
    # Deterministic iteration order across components (set union otherwise
    # yields nondeterministic ordering on different runs/hash seeds).
    for key in sorted(set(findings_by_component) | set(actions_by_component)):
        comp_findings = findings_by_component.get(key, [])
        comp_actions = actions_by_component.get(key, [])

        # Findings graph for this component.
        graph = build_from_findings(comp_findings, source="<agent>")

        # Merge this component's action graph. subject_id=key so the action SKILL
        # node id matches the findings SKILL node id (both = SKILL:<normalized path>),
        # connecting object data-flow to the same component.
        if comp_actions:
            action_graph = build_from_actions(comp_actions, subject_id=key)
            for node in action_graph.nodes.values():
                if graph.get_node(node.id) is None:
                    graph.get_or_create(node.id, node.type, label=node.label)
            for edge in action_graph.edges:
                graph.add_edge(edge.source, edge.target, edge.type,
                               attributes=dict(edge.attributes))

        all_paths.extend(PathAnalyzer(graph).analyze())

    # Cross-component composition: analyze one MERGED graph built from all
    # components. Only genuinely cross-component walks (real PRODUCES
    # attribution on the merged graph's ordered walk) are returned by
    # analyze(compose=True); single-component paths are filtered out, so this
    # never duplicates or short-circuits the local paths above, and never
    # infers composition from shared names alone.
    flat_findings: List = []
    for key in sorted(findings_by_component):
        flat_findings.extend(findings_by_component.get(key, []))
    merged = build_from_findings(flat_findings, source="<agent>")
    for key in sorted(actions_by_component):
        if not actions_by_component.get(key):
            continue
        action_graph = build_from_actions(actions_by_component[key], subject_id=key)
        for node in action_graph.nodes.values():
            if merged.get_node(node.id) is None:
                merged.get_or_create(node.id, node.type, label=node.label)
        for edge in action_graph.edges:
            merged.add_edge(edge.source, edge.target, edge.type,
                            attributes=dict(edge.attributes))
    all_paths.extend(PathAnalyzer(merged).analyze(compose=True))

    return all_paths, merged


def _confidence_for(f: Finding) -> Confidence:
    """Deterministic confidence estimate based on rule semantics.

    Confidence reflects how reliably the detected behavior matches the rule,
    NOT how dangerous it is (that is Severity).
    """
    # Correlation/step-sequence chains are high-confidence by construction
    # (they require multiple corroborating signals).
    if f.rule_id.startswith("AS-CHAIN"):
        return Confidence.HIGH
    # Obfuscation findings require decoded content + execution/fetch context.
    if f.rule_id == "AS-007":
        return Confidence.HIGH
    # Sensitive credential access requires an access verb + sensitive path.
    if f.rule_id == "AS-006":
        return Confidence.HIGH
    # Hardcoded secrets with a strong pattern (OpenAI/Anthropic/GitHub/AWS/
    # private key) are high-confidence; generic key/password are medium.
    if f.rule_id == "AS-001":
        if "API credential detected" in f.evidence or "Private key block" in f.evidence:
            return Confidence.HIGH
        return Confidence.MEDIUM
    # MCP structural findings are medium-confidence (config-only, no runtime).
    if f.rule_id.startswith("AS-MCP"):
        return Confidence.MEDIUM
    # Prompt injection / network / URL / shell regex findings are medium.
    return Confidence.MEDIUM


# AS-006: an access needs code that can read. A sensitive path that survives
# only inside a string literal or a comment cannot open anything: it is a
# mention -- an entry in a detection table, an argparse help string, an HTTP
# route, a printed message. A Python line is kept when the path is still there
# in code (`self.env` is an identifier, not a dotenv file; that attribute form
# is its own measurement) or when a call on the line can consume the literal
# (`open`, `Path`, `subprocess.run`, ...). The *raw* line is checked for a read
# call because Python 3.11 tokenises an f-string as one STRING token, so
# `print(f"{open('.env').read()}")` would otherwise blank the call that reads.
_AS006_READ_CALL = re.compile(r"\b(?:open|read|read_text|read_bytes|Path)\s*\(")
_AS006_CONSUMER = re.compile(
    r"\b(?:open|read|read_text|read_bytes|readlines|Path|load|loads|safe_load"
    r"|expanduser|expandvars|system|popen|run|call|check_call|check_output"
    r"|Popen|copy|copyfile|copytree|send_file|FileResponse)\s*\("
)


def _scan_file(
    path: Path,
    rules,
    file_rules,
    file_texts,
    coverage: Optional[ScanCoverage] = None,
) -> List[Finding]:
    """Scan one file, recording every refusal in ``coverage``.

    Each of the early returns below used to be a bare ``return []``: the file
    was dropped and the report still said SAFE. They now name the surface that
    gave up (fixed vocabulary, no exception text, no host paths in prose).
    """
    if coverage is None:
        coverage = ScanCoverage()

    if not _should_scan(path):
        coverage.skipped(str(path), SKIP_NOT_SCANNABLE)
        return []

    try:
        size = path.stat().st_size
    except OSError:
        coverage.skipped(str(path), SKIP_UNREADABLE)
        return []

    if size > MAX_FILE_SIZE:
        coverage.skipped(str(path), SKIP_TOO_LARGE)
        return []

    try:
        data = path.read_bytes()
    except OSError:
        coverage.skipped(str(path), SKIP_UNREADABLE)
        return []

    if _is_binary(data):
        # A BOM is a declaration of text; the NUL heuristic is only a guess.
        text = _decode_declared_text(data)
        if text is None:
            coverage.skipped(str(path), SKIP_BINARY)
            return []
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            # Not UTF-8. Two things must both stay true: the readable lines are
            # still scanned (refusing the file drops real findings -- a secret
            # on an ASCII line inside a latin-1 note is one), and the file is
            # not reported as read in full (the replacement characters are the
            # scanner's invention, not the file's text). So it is scanned with
            # replacements AND recorded as lossy, which makes coverage partial.
            # No encoding is guessed: "not UTF-8" is the entire claim, and a
            # cp1251 body stays a cp1251 body nobody claimed to understand.
            text = data.decode("utf-8", errors="replace")
            coverage.lossy(str(path))

    file_texts.append((text, str(path)))
    coverage.counted()

    findings: List[Finding] = []

    def _keep(finding: Finding, source_line: str) -> None:
        # Preserve the exact source line that triggered the rule. For secret
        # findings, use the already-redacted evidence so the raw secret never
        # appears in reports.
        if not finding.matched_text:
            if finding.rule_id == "AS-001":
                finding.matched_text = finding.evidence or ""
            else:
                finding.matched_text = source_line.strip()
        findings.append(finding)

    # The cache entries are indexes into ``rules``, so they only mean anything
    # against the list they were learned with: a caller that scans with a
    # different rule set starts from an empty cache (see ``_loud_rule_indexes``).
    global _loud_rule_list
    if _loud_rule_list is not rules:
        _clear_line_rule_cache()
        _loud_rule_list = rules
    loud_by_line = _loud_rule_indexes

    # ``str(path)`` per line per rule was 3.1 M calls on ``agent/``
    # (docs/PERFORMANCE.md): the path does not change between lines.
    file_path = str(path)
    for lineno, line in enumerate(text.splitlines(), start=1):
        loud = loud_by_line.get(line)
        if loud is None:
            # First sight of this text in this scan: ask every rule, and keep
            # the indexes of the ones that were not quiet.
            loud_indexes: List[int] = []
            for index, rule in enumerate(rules):
                try:
                    finding = rule(line, file_path, lineno)
                except Exception:
                    # A rule must never crash the whole scan -- but it must not
                    # vanish either: the file was read, this rule contributed
                    # nothing, and that loss is a fact about the report.
                    coverage.rule_failed(rule, file_path, lineno, RULE_ERROR_LINE)
                    loud_indexes.append(index)
                    continue
                if finding is None:
                    continue
                loud_indexes.append(index)
                _keep(finding, line)
            if len(loud_by_line) >= _LINE_RULE_CACHE_SEGMENTS:
                # Past the cap the scan is reading a different vocabulary;
                # start a new epoch instead of refusing to remember.
                loud_by_line.clear()
            loud_by_line[line] = tuple(loud_indexes)
            continue
        # A text the scan has already read: only the rules that spoke last
        # time can speak now, and each of them is asked again for real.
        for index in loud:
            rule = rules[index]
            try:
                finding = rule(line, file_path, lineno)
            except Exception:
                coverage.rule_failed(rule, file_path, lineno, RULE_ERROR_LINE)
                continue
            if finding is not None:
                _keep(finding, line)

    # File-level rules (structured formats like MCP config).
    for frule in file_rules:
        try:
            for finding in frule(text, str(path)):
                # File-rule findings have no single line; use the evidence as
                # the smallest defensible source fragment.
                if not finding.matched_text:
                    finding.matched_text = finding.evidence or ""
                findings.append(finding)
        except Exception:
            # Same contract for file rules: the whole file-level pass is lost,
            # so the record carries line=None (there is no line to point at).
            coverage.rule_failed(frule, str(path), None, RULE_ERROR_FILE)
            continue

    # A line that is entirely a comment or a string literal is prose, not an
    # access. AS-006 is a line rule, so a docstring sentence such as
    # "read ~/.hermes/.env to load keys" was reported as a HIGH credential
    # access on a line that cannot touch the filesystem. Blank comments and
    # string literals before deciding; lines that still contain code (for
    # example `open(".env")`) are kept.
    #
    # AS-003 MEDIUM is the same judgement one rule over. A bare library name in
    # prose -- "later requests (retried)", "token-endpoint requests (exchange
    # only)" -- matches the client branch because the word is followed by a
    # parenthesis, and a comment line opens no socket. Field probe 2026-10-21
    # on the slice (agent/tools/skills/hermes_cli): 19 of 214 AS-003 MEDIUM sat
    # on a line with no code left in 16 files, every one the bare
    # ``requests (``/``httpx (``/``aiohttp (`` form; 8 of those files had no
    # other claim, so their report was prose only. The filter runs *before*
    # ``collapse_http_claims``: such a line counted as a call claim and dropped
    # the file's import claim, so filtering first leaves the one fact on the
    # import instead of nowhere.
    code_lines = None
    raw_lines = text.splitlines()
    if path.suffix == ".py":
        from veyra.rules.sensitive_paths import SENSITIVE_PATH as _AS006_SENSITIVE_PATH
        from veyra.step_sequence import _code_only_lines

        code_lines = _code_only_lines(text)

    if code_lines is not None:
        def _prose_line(lineno: int) -> bool:
            return 0 < lineno <= len(code_lines) and not code_lines[lineno - 1].strip()

        findings = [
            f
            for f in findings
            if not (
                f.rule_id == "AS-003"
                and f.severity is Severity.MEDIUM
                and f.line
                and _prose_line(f.line)
            )
        ]

    # One claim per file for AS-003 MEDIUM: an import that a call in the same
    # file supersedes is the same fact on a line that cannot make a request
    # (see ``collapse_http_claims``). Import-only files keep their finding.
    findings = collapse_http_claims(findings)

    if code_lines is not None:
        def _as006_mention(lineno: int) -> bool:
            """The path is text only and nothing on the line reads it."""
            code = code_lines[lineno - 1]
            if _AS006_SENSITIVE_PATH.search(code):
                return False
            if _AS006_READ_CALL.search(raw_lines[lineno - 1]):
                return False
            return not _AS006_CONSUMER.search(code)

        findings = [
            f
            for f in findings
            if not (
                f.rule_id == "AS-006"
                and f.line
                and 0 < f.line <= len(code_lines)
                and _as006_mention(f.line)
            )
        ]

    return findings
