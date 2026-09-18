"""Core scanner: recursively inspects files relevant to AI agent skills.

Static analysis only. Never executes scanned code and never makes network
requests.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from veyra.correlation import correlate
from veyra.cwe import cwe_for
from veyra.graph import PathAnalyzer, build_from_actions, build_from_findings, NodeType
from veyra.graph.context import (
    ComponentContextAssociation,
    ComponentContextError,
    associate_security_behavior,
    build_component_path_composition_for_paths,
    build_component_path_participation_for_paths,
    serialize_component_path_composition,
    serialize_component_path_participation,
    serialize_component_security_scopes,
)
from veyra.mitre import mitre_for
from veyra.models import Confidence, Finding, ScanResult
from veyra.rules import load_file_rules, load_rules
from veyra.step_sequence import analyze_file

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

# Directories we never descend into.
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".eggs",
    "site-packages",
}

# Maximum file size to scan (bytes). Larger files are skipped as "binary/large".
MAX_FILE_SIZE = 1_000_000  # 1 MB


def _is_binary(data: bytes) -> bool:
    """Heuristic: a file is binary if it contains a NUL byte in the first chunk."""
    return b"\x00" in data[:8192]


def _should_scan(path: Path) -> bool:
    if path.name in ALWAYS_SCAN:
        return True
    return path.suffix.lower() in SCAN_EXTENSIONS


def scan_path(
    target: str,
    component_context: Optional[List[ComponentContextAssociation]] = None,
) -> ScanResult:
    """Scan a file or directory and return a ScanResult.

    ``component_context`` is an OPTIONAL additive, explicit input: a list of
    already-validated :class:`ComponentContextAssociation` objects. When
    supplied, each association's security-behavior edge and component must
    actually exist in the scan's merged security graph (verified through the
    existing ``associate_security_behavior`` API), and the resulting
    per-component security scopes, per-path component participation, AND
    per-path component composition are projected onto
    ``ScanResult.component_security_scopes`` /
    ``ScanResult.component_path_participation`` /
    ``ScanResult.component_path_composition`` (exposed in JSON/SARIF/HTML).

    Ownership is NEVER inferred: without explicit associations, no component
    security scopes are produced regardless of USES/CONTAINS/CALLS/TRUSTS/
    HANDOFF or any naming/provenance signal. Supplying no ``component_context``
    leaves all existing scan behaviour completely unchanged.
    """
    rules = load_rules()
    file_rules = load_file_rules()
    findings: List[Finding] = []
    file_texts: List[str] = []  # (text, path) pairs for step-sequence analysis
    root = Path(target)

    if root.is_file():
        findings.extend(_scan_file(root, rules, file_rules, file_texts))
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                findings.extend(_scan_file(fpath, rules, file_rules, file_texts))
    else:
        raise FileNotFoundError(f"Path not found: {target}")

    # Run the contextual correlation layer over all findings.
    # Correlation findings are added separately; original findings are preserved.
    correlated = correlate(findings)
    findings.extend(correlated)

    # Run intra-file step-sequence analysis. This fills the gap when individual
    # steps are too benign to generate standalone findings. Deduplicate against
    # chains already emitted by correlation (same rule_id) to avoid duplicates.
    correlated_ids = {c.rule_id for c in correlated}
    for text, path in file_texts:
        for chain in analyze_file(text, path):
            if chain.rule_id in correlated_ids:
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
    attack_paths, merged = _build_attack_paths(findings, file_texts)
    result.attack_paths = attack_paths
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


def _scan_file(path: Path, rules, file_rules, file_texts) -> List[Finding]:
    if not _should_scan(path):
        return []

    try:
        size = path.stat().st_size
    except OSError:
        return []

    if size > MAX_FILE_SIZE:
        return []

    try:
        data = path.read_bytes()
    except OSError:
        return []

    if _is_binary(data):
        return []

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    file_texts.append((text, str(path)))

    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            try:
                finding = rule(line, str(path), lineno)
            except Exception:
                # A rule must never crash the whole scan.
                continue
            if finding is not None:
                # Preserve the exact source line that triggered the rule.
                # For secret findings, use the already-redacted evidence so
                # the raw secret never appears in reports.
                if not finding.matched_text:
                    if finding.rule_id == "AS-001":
                        finding.matched_text = finding.evidence or ""
                    else:
                        finding.matched_text = line.strip()
                findings.append(finding)

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
            continue

    return findings
