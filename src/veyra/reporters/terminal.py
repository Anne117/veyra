"""Terminal report renderer."""

from __future__ import annotations

from veyra.coverage import (
    PRUNE_IGNORED_DIR,
    PRUNE_SYMLINK_DIR,
    PRUNE_VENDORED_DIR,
)
from veyra.models import POLICY_UNKNOWN, ScanResult, Severity

# Simple box-drawing separator (no external deps).
SEP = "\u2501" * 30


def _pruned_counts(result: ScanResult) -> dict[str, int]:
    """Count pruned subtrees per fixed reason token (never per host path)."""
    counts = {PRUNE_IGNORED_DIR: 0, PRUNE_VENDORED_DIR: 0, PRUNE_SYMLINK_DIR: 0}
    for record in result.dirs_pruned:
        reason = record.get("reason")
        if reason in counts:
            counts[reason] += 1
    return counts


def _unknown_reasons(result: ScanResult) -> list[str]:
    """Why the verdict is not a PASS, in the terms the scan actually recorded."""
    reasons: list[str] = []
    if result.files_skipped:
        reasons.append(f"{len(result.files_skipped)} skipped files")
    if result.decode_errors:
        reasons.append(f"{len(result.decode_errors)} lossy files")
    if result.rule_errors:
        reasons.append(f"{len(result.rule_errors)} rule errors")
    vendored = _pruned_counts(result)[PRUNE_VENDORED_DIR]
    if vendored:
        reasons.append(f"{vendored} vendored dirs not entered")
    return reasons or ["nothing was read"]


def render_terminal(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("Veyra Security Report")
    lines.append(SEP)
    lines.append("")
    lines.append(f"Target: {result.target}")
    lines.append(f"Risk: {result.risk_level}")
    lines.append(f"Score: {result.score}/100")
    # A score without its denominator invites reading "0 findings" as
    # "nothing was there". The status word is the denominator.
    #
    # The pruned subtrees are printed as two groups, not one sum: machine state
    # (``.git``, caches) costs nothing, while a vendored tree (``node_modules``,
    # ``dist``) is content nobody opened and is what turned ``full`` into
    # ``partial``. A single "N pruned dirs" number would let the reader assume
    # both weigh the same.
    pruned = _pruned_counts(result)
    lines.append(
        "Coverage: "
        f"{result.coverage_status} "
        f"({result.files_scanned} read, {len(result.files_skipped)} skipped"
        f", {len(result.decode_errors)} lossy"
        f", {pruned[PRUNE_IGNORED_DIR]} machine dirs"
        f", {pruned[PRUNE_VENDORED_DIR]} vendored dirs"
        f", {pruned[PRUNE_SYMLINK_DIR]} linked dirs)"
    )
    # The policy verdict is printed even when it is PASS: a report that shows
    # violations only is silent about the case "not evaluated", which reads as
    # "checked and clean". UNKNOWN states its own reason instead of leaving the
    # reader to infer it from the missing violations section -- and names only
    # the reasons that actually apply, so "0 skipped" never stands in for a
    # subtree that was never entered.
    policy_line = f"Policy: {result.policy_status}"
    if result.policy_status == POLICY_UNKNOWN:
        reasons = _unknown_reasons(result)
        policy_line += (
            f" (no violation proven; coverage {result.coverage_status}: "
            f"{', '.join(reasons)})"
        )
    lines.append(policy_line)
    lines.append("")

    for f in result.findings:
        sev = f.severity.value
        loc = f"{f.file}"
        if f.line:
            loc += f":{f.line}"
        if f.suppressed:
            lines.append(f"[SUPPRESSED] {f.rule_id}  {f.title}")
            lines.append(f"          {loc}")
            lines.append(f"          {f.description}")
            lines.append(f"          Suppressed: {f.suppression_reason}")
        else:
            lines.append(f"{sev:<8}  {f.rule_id}  {f.title}")
            lines.append(f"          {loc}")
            lines.append(f"          {f.description}")
            if f.evidence:
                lines.append(f"          Evidence: {f.evidence}")
        if f.confidence:
            lines.append(f"          Confidence: {f.confidence.value}")
        if f.cwe:
            lines.append(f"          CWE: {', '.join(f.cwe)}")
        if f.mitre:
            for m in f.mitre:
                lines.append(f"          MITRE ATT&CK: {m['id']} — {m['name']}")
        if f.matched_text:
            lines.append(f"          Matched: {f.matched_text}")
        lines.append("")

    s = result.summary()
    lines.append("Summary")
    lines.append("-------")
    lines.append(f"Critical: {s['critical']}")
    lines.append(f"High:     {s['high']}")
    lines.append(f"Medium:   {s['medium']}")
    lines.append(f"Low:      {s['low']}")
    lines.append(f"Suppressed: {s['suppressed']}")
    lines.append("")

    if result.attack_paths:
        lines.append("Attack Paths")
        lines.append("-----------")
        for p in result.attack_paths:
            p.ensure_path_id()
            short = p.path_id[:10]
            lines.append(f"  [{p.risk_severity.value}] [{p.attack_type.value}] risk={p.risk_score} (id {short}) {p.title}")
            lines.append(f"    {' → '.join(p.nodes)}")
            if p.is_composed:
                lines.append(f"    Components: {' → '.join(p.component_ids)}")
            if p.attack_type and p.attack_type.value != "UNKNOWN":
                lines.append(f"    ({p.attack_type.value}: {p.explanation})")
            if p.breakpoints:
                lines.append("    Breakpoints:")
                for b in p.breakpoints:
                    lines.append(f"      - {b.edge_type}: {b.reason}")
        lines.append("")

    # Policy Violations: only violated PolicyResults, in the existing
    # PolicyEngine ordering. Non-violating results are never shown here.
    violations = [r for r in result.policy_results if r.violated]
    if violations:
        lines.append("Policy Violations")
        lines.append("----------------")
        for r in violations:
            lines.append(f"- {r.policy_id}")
            lines.append(f"  Path: {r.path_id}")
            lines.append(f"  Reason: {r.reason}")
        lines.append("")

    return "\n".join(lines)
