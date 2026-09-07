"""Contextual correlation layer for AgentShield.

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

from agentshield.models import Finding, Severity

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


def _chain_key(chain_id: str, findings: List[Finding]) -> str:
    """Deterministic dedup key: chain id + sorted contributing rule ids."""
    rules = sorted({f.rule_id for f in findings})
    return f"{chain_id}|{','.join(rules)}"


# --- Chain 1: Secret exfiltration ------------------------------------------

def _chain_secret_exfiltration(findings: List[Finding]) -> Optional[Finding]:
    """AS-CHAIN-001: prompt injection + secret access + network exfiltration."""
    has_injection = _has_rule(findings, PROMPT_INJECTION_RULES)
    has_secret = _has_rule(findings, SECRET_ACCESS_RULES)
    has_network = _has_rule(findings, NETWORK_RULES)

    if not (has_injection and has_secret and has_network):
        return None

    contrib = (
        _contributing(findings, PROMPT_INJECTION_RULES)
        + _contributing(findings, SECRET_ACCESS_RULES)
        + _contributing(findings, NETWORK_RULES)
    )
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
        evidence=f"Signals: prompt-injection + secret-access + network. Contributing: {_locations(contrib)}",
        remediation="Review the correlated instructions and network destinations; remove any that request secret disclosure or exfiltration.",
    )


# --- Chain 2: Download -> execute ------------------------------------------

def _chain_download_execute(findings: List[Finding]) -> Optional[Finding]:
    """AS-CHAIN-002: remote download/network + shell/command execution."""
    has_download = _has_rule(findings, DOWNLOAD_RULES)
    has_exec = _has_rule(findings, SHELL_EXEC_RULES)

    if not (has_download and has_exec):
        return None

    # Strong evidence: both signals present at HIGH/CRITICAL.
    strong = _has_strong_rule(findings, DOWNLOAD_RULES) and _has_strong_rule(findings, SHELL_EXEC_RULES)
    severity = Severity.CRITICAL if strong else Severity.HIGH

    contrib = _contributing(findings, DOWNLOAD_RULES) + _contributing(findings, SHELL_EXEC_RULES)
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
