"""Contextual correlation layer for Veyra.

Runs AFTER the individual rules produce findings. Correlates existing
findings/signals into higher-level attack chains. This is a small,
deterministic, heuristic layer — it does NOT use an LLM and does NOT replace
the individual rules.

Design:
- Consumes the full list of findings from a ScanResult (across all files).
- Produces new correlation findings (AS-CHAIN-*) appended separately.
- Never executes scanned code, never makes network requests, never downloads.
- Preserves all original findings.
- Avoids duplicate correlation findings (deduplicated by chain id + key).
- Deterministic: same input -> same output.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from veyra.models import Finding, Severity
from veyra.step_sequence import CHAIN_MAX_LINE_SPAN

# --- Signal classification -------------------------------------------------
# Map rule IDs to the semantic signals they represent.

# Prompt injection / agent manipulation.
PROMPT_INJECTION_RULES = {"AS-004"}

# Secret / credential access.
SECRET_ACCESS_RULES = {"AS-001", "AS-004"}  # AS-001 hardcoded secret, AS-004 reveal-secrets

# External / network communication.
NETWORK_RULES = {"AS-003", "AS-005"}

# Shell / command execution.
SHELL_EXEC_RULES = {"AS-002"}

# Remote download / network access.
DOWNLOAD_RULES = {"AS-003", "AS-005"}

# MCP signals.
MCP_REMOTE_RULES = {"AS-MCP-001"}
MCP_DYNAMIC_EXEC_RULES = {"AS-MCP-004"}
MCP_SECRETS_RULES = {"AS-MCP-006"}
MCP_FS_RULES = {"AS-MCP-007"}

# Severity threshold for "strong" evidence.
STRONG_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def _has_rule(findings: List[Finding], rules: Set[str]) -> bool:
    return any(f.rule_id in rules for f in findings)


def _has_strong_rule(findings: List[Finding], rules: Set[str]) -> bool:
    return any(f.rule_id in rules and f.severity in STRONG_SEVERITIES for f in findings)


def _unique(findings: List[Finding]) -> List[Finding]:
    """Drop repeated objects while preserving order (Finding is not hashable)."""
    seen: Set[int] = set()
    out: List[Finding] = []
    for f in findings:
        if id(f) in seen:
            continue
        seen.add(id(f))
        out.append(f)
    return out


def _contributing(findings: List[Finding], rules: Set[str]) -> List[Finding]:
    return [f for f in findings if f.rule_id in rules]


def _locations(findings: List[Finding]) -> str:
    """Summarize contributing file:line locations."""
    locs = set()
    for f in findings:
        loc = f.file
        if f.line:
            loc += f":{f.line}"
        locs.add(loc)
    return ", ".join(sorted(locs))


def _local_evidence(group: List[Finding]) -> List[Finding]:
    """Return the findings that form one local three-signal group, else [].

    All three signal types must be present in the same file within
    CHAIN_MAX_LINE_SPAN lines. When a line number is unavailable the distance is
    unknown, so only the file must match (same rule as ``_same_artifact``).
    """
    injections = [f for f in group if f.rule_id in PROMPT_INJECTION_RULES]
    secrets = [f for f in group if f.rule_id in SECRET_ACCESS_RULES]
    networks = [f for f in group if f.rule_id in NETWORK_RULES]
    if not (injections and secrets and networks):
        return []

    # Prefer three distinct findings; AS-004 belongs to two signal sets, so a
    # single finding must not silently stand in for two steps of the chain.
    for require_distinct in (True, False):
        for a in injections:
            for b in secrets:
                for c in networks:
                    triple = [a, b, c]
                    if require_distinct and len({id(f) for f in triple}) < 3:
                        continue
                    lines = [f.line for f in triple if f.line is not None]
                    if len(lines) < len(triple):
                        return triple
                    if max(lines) - min(lines) <= CHAIN_MAX_LINE_SPAN:
                        return triple
    return []


def _same_artifact(a: Finding, b: Finding) -> bool:
    """True when two findings can plausibly describe one download-and-execute.

    Requires the same file and line proximity. A download in one file and an
    execution in another file are unrelated facts, not a sequence. When a line
    number is unavailable the distance is unknown, so only the file must match.
    """
    if a.file != b.file:
        return False
    if a.line is None or b.line is None:
        return True
    return abs(a.line - b.line) <= CHAIN_MAX_LINE_SPAN


def _chain_key(chain_id: str, findings: List[Finding]) -> str:
    """Deterministic dedup key: chain id + sorted contributing rule ids."""
    rules = sorted({f.rule_id for f in findings})
    return f"{chain_id}|{','.join(rules)}"


# --- Chain 1: Secret exfiltration ------------------------------------------

def _chain_secret_exfiltration(findings: List[Finding]) -> Optional[Finding]:
    """AS-CHAIN-001: prompt injection + secret access + network exfiltration.

    Locality requirement: all three signals must come from the SAME artifact and
    sit within CHAIN_MAX_LINE_SPAN lines of each other. A prompt-injection note in
    one module, a secret constant in a second and an HTTP call in a third are
    three unrelated facts about a codebase, not an ordered exfiltration chain.
    Without this the chain fires on any large tree that contains an HTTP client,
    a token field and one prompt-injection phrase somewhere, and its evidence
    degenerates into hundreds of unrelated locations.
    """
    candidates = _contributing(
        findings, PROMPT_INJECTION_RULES | SECRET_ACCESS_RULES | NETWORK_RULES
    )

    by_file: Dict[str, List[Finding]] = {}
    for f in candidates:
        by_file.setdefault(f.file, []).append(f)

    contributing: List[Finding] = []
    for group in by_file.values():
        local = _local_evidence(group)
        if local:
            contributing.extend(local)

    if not contributing:
        return None

    # Only the artifacts that actually carry all three signals contribute.
    contributing = _unique(contributing)
    return Finding(
        rule_id="AS-CHAIN-001",
        severity=Severity.CRITICAL,
        title="Potential secret exfiltration chain",
        description=(
            "Correlated signals indicate a potential secret-exfiltration chain: "
            "prompt injection/manipulation combined with secret or credential "
            "access and external network communication. The combination is more "
            "dangerous than the individual findings because it suggests the agent "
            "may be manipulated into sending secrets to an external destination."
        ),
        file="<correlated>",
        evidence=f"Signals: prompt-injection + secret-access + network. Contributing: {_locations(contributing)}",
        remediation="Review the correlated instructions and network destinations; remove any that request secret disclosure or exfiltration.",
    )


# --- Chain 2: Download -> execute ------------------------------------------

def _chain_download_execute(findings: List[Finding]) -> Optional[Finding]:
    """AS-CHAIN-002: remote download/network + shell/command execution.

    Locality requirement: the download signal and the execution signal must come
    from the SAME artifact. A download reported in one file and an execution
    reported in an unrelated file are two unrelated facts — pairing them across a
    tree asserts a sequence that no evidence supports (on a large tree it fires on
    almost any directory that holds a URL and a `curl | sh`). Only findings from
    files that carry BOTH signals contribute to the chain and to its evidence.
    """
    downloads = _contributing(findings, DOWNLOAD_RULES)
    executions = _contributing(findings, SHELL_EXEC_RULES)

    pairs = [
        (d, e)
        for d in downloads
        for e in executions
        if _same_artifact(d, e)
    ]
    if not pairs:
        return None

    # Keep the evidence deduplicated but ordered; each finding appears once.
    downloads = _unique([d for d, _ in pairs])
    executions = _unique([e for _, e in pairs])

    # Strong evidence: both signals present at HIGH/CRITICAL in the same artifact.
    strong = (
        any(f.severity in STRONG_SEVERITIES for f in downloads)
        and any(f.severity in STRONG_SEVERITIES for f in executions)
    )
    severity = Severity.CRITICAL if strong else Severity.HIGH

    contrib = downloads + executions
    return Finding(
        rule_id="AS-CHAIN-002",
        severity=severity,
        title="Remote download followed by execution",
        description=(
            "Correlated signals indicate remote content is downloaded and then "
            "executed. This is a classic supply-chain / remote-code-execution "
            "pattern and is more dangerous than either signal alone."
        ),
        file="<correlated>",
        evidence=f"Signals: remote-download + command-execution. Contributing: {_locations(contrib)}",
        remediation="Do not download and execute remote content; pin and review any fetched artifacts.",
    )


# --- Chain 3: Remote MCP execution -----------------------------------------

def _chain_remote_mcp_execution(findings: List[Finding]) -> Optional[Finding]:
    """AS-CHAIN-003: remote MCP endpoint + dynamic package execution (+ secrets/fs)."""
    has_remote = _has_rule(findings, MCP_REMOTE_RULES)
    has_dynamic = _has_rule(findings, MCP_DYNAMIC_EXEC_RULES)

    if not (has_remote and has_dynamic):
        return None

    # Additional risk signals raise severity.
    has_secrets = _has_rule(findings, MCP_SECRETS_RULES)
    has_fs = _has_rule(findings, MCP_FS_RULES)

    if has_secrets or has_fs:
        severity = Severity.CRITICAL
    else:
        severity = Severity.HIGH

    contrib = (
        _contributing(findings, MCP_REMOTE_RULES)
        + _contributing(findings, MCP_DYNAMIC_EXEC_RULES)
        + _contributing(findings, MCP_SECRETS_RULES)
        + _contributing(findings, MCP_FS_RULES)
    )
    return Finding(
        rule_id="AS-CHAIN-003",
        severity=severity,
        title="High-risk remote MCP execution chain",
        description=(
            "Correlated MCP signals indicate a remote endpoint combined with "
            "dynamic package execution. This can fetch and run code from a remote "
            "source. Additional secret or filesystem access raises the risk."
        ),
        file="<correlated>",
        evidence=f"Signals: remote-mcp + dynamic-exec. Contributing: {_locations(contrib)}",
        remediation="Verify the remote MCP endpoint and package provenance; avoid passing secrets or granting broad filesystem access.",
    )


# --- Public API ------------------------------------------------------------

def correlate(findings: List[Finding]) -> List[Finding]:
    """Run all correlation chains over the findings.

    Returns a list of NEW correlation findings (AS-CHAIN-*). Original findings
    are preserved and not modified. Deduplicated by chain id + contributing
    rules so the same chain is not emitted twice.
    """
    chains: List[Finding] = []
    seen: Set[str] = set()

    candidates = [
        _chain_secret_exfiltration(findings),
        _chain_download_execute(findings),
        _chain_remote_mcp_execution(findings),
    ]

    for chain in candidates:
        if chain is None:
            continue
        key = _chain_key(chain.rule_id, findings)
        if key in seen:
            continue
        seen.add(key)
        chains.append(chain)

    return chains
