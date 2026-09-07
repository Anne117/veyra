"""Intra-file step-sequence analysis.

Detects ordered multi-stage attacks inside a single file, even when the
individual steps are too benign to generate standalone findings.

This is a small, deterministic, file-level analyzer. It is NOT a general
data-flow engine and does NOT use an LLM. It classifies each line of a file
into semantic step categories and checks for dangerous ordered sequences.

Step categories:
  SOURCE/READ   - read config/credentials/environment/sensitive files
  SENSITIVE     - api key, token, password, secret, credential, private key
  NETWORK SINK  - http request, POST/PUT/upload, webhook, send externally
  DOWNLOAD      - curl/wget/download/fetch remote content
  EXECUTION     - shell/command execution, running downloaded content

Chains detected (order matters):
  AS-CHAIN-001  SOURCE -> SENSITIVE -> NETWORK   (secret exfiltration)
  AS-CHAIN-002  DOWNLOAD -> EXECUTION            (download-and-execute)

The analyzer never executes code and never makes network requests.
"""

from __future__ import annotations

import re
from typing import List, Optional

from agentshield.models import Finding, Severity

# --- Step category detectors ----------------------------------------------

# SOURCE / READ: accessing sensitive data sources.
# "data" is a source noun when read/loaded (bounded). "list"/"find" are NOT
# added as generic SOURCE verbs to avoid flagging benign discovery text.
SOURCE_READ = re.compile(
    r"\b(?:read|load|open|access|get)\b[^\n]*\b(?:config|configuration|credential|secret|token|key|password|environment|data|\.ssh|\.aws|\.env)\b",
    re.IGNORECASE,
)

# SENSITIVE: extracting a sensitive value (requires an extraction verb).
# "find" is recognized only when combined with a secret noun (bounded).
SENSITIVE = re.compile(
    r"\b(?:extract|retrieve|obtain|grab|pull|find)\b[^\n]*\b(?:api\s*key|token|password|passwd|secret|credential|private\s*key)\b",
    re.IGNORECASE,
)

# DOWNLOAD: retrieving remote content.
# "retrieve" is recognized only when followed by a remote source (bounded).
DOWNLOAD = re.compile(
    r"\b(?:curl|wget|download|fetch|retrieve)\b[^\n]*\b(?:remote|http|https|url|script|content|file|package|server)\b",
    re.IGNORECASE,
)

# NETWORK SINK: sending data externally (requires a send verb + destination).
NETWORK_SINK = re.compile(
    r"\b(?:send|upload|post|put|transmit|exfiltrate|push)\b[^\n]*\b(?:http|https|url|endpoint|webhook|external|remote|upload)\b",
    re.IGNORECASE,
)

# EXECUTION: running content.
# "package" is recognized only in an execution context (run/execute/launch/
# install + package). "run it" / "run the script" are recognized as execution
# (bounded; the chain still requires a prior DOWNLOAD to fire).
EXECUTION = re.compile(
    r"\b(?:run|execute|exec|eval|install|launch|bash|sh|shell|popen|system)\b[^\n]*\b(?:command|script|content|payload|file|code|package)\b"
    r"|\b(?:run|execute)\s+(?:it|the\s+script)\b",
    re.IGNORECASE,
)


def _classify_line(line: str) -> Optional[str]:
    """Classify a single line into a step category, or None.

    Order matters: DOWNLOAD is checked before NETWORK so that
    "download ... https://..." is classified as DOWNLOAD, not NETWORK.
    """
    if SOURCE_READ.search(line):
        return "SOURCE"
    if SENSITIVE.search(line):
        return "SENSITIVE"
    if DOWNLOAD.search(line):
        return "DOWNLOAD"
    if NETWORK_SINK.search(line):
        return "NETWORK"
    if EXECUTION.search(line):
        return "EXECUTION"
    return None


# Deterministic action separators. Deliberately narrow — no general NLP.
# "and then" is matched before "then" so the longer phrase wins.
_ACTION_SEPARATOR = re.compile(
    r"\s+(?:and\s+then|then)\s+|\s*;\s*",
    re.IGNORECASE,
)


def _split_actions(line: str) -> List[str]:
    """Split a line into logical action segments on deterministic separators.

    Preserves order. Returns the segments (non-empty, stripped). A line with
    no separator returns a single segment. A leading "then"/"and then" on a
    segment (e.g. after a semicolon) is stripped.
    """
    parts = _ACTION_SEPARATOR.split(line)
    out = []
    for p in parts:
        p = p.strip()
        # Strip a leading "then" / "and then" left by a preceding separator.
        p = re.sub(r"^(?:and\s+then|then)\s+", "", p, flags=re.IGNORECASE).strip()
        if p:
            out.append(p)
    return out


def _find_sequence(steps: List[str], pattern: List[str]) -> Optional[List[int]]:
    """Find the first occurrence of `pattern` as an ordered subsequence of `steps`.

    Returns the indices of the matched steps, or None. Non-adjacent matches
    are allowed (harmless text/steps between signals are skipped).
    """
    pi = 0
    matched: List[int] = []
    for i, step in enumerate(steps):
        if step == pattern[pi]:
            matched.append(i)
            pi += 1
            if pi == len(pattern):
                return matched
    return None


def _evidence_for(steps: List[str], indices: List[int]) -> str:
    """Build a human-readable evidence string from matched step indices."""
    labels = {
        "SOURCE": "read sensitive data",
        "SENSITIVE": "extract secret",
        "NETWORK": "send externally",
        "DOWNLOAD": "download remote content",
        "EXECUTION": "execute",
    }
    return " -> ".join(labels[steps[i]] for i in indices)


def analyze_file(text: str, file_path: str) -> List[Finding]:
    """Analyze a single file's text for ordered multi-stage attack sequences.

    Returns a list of AS-CHAIN findings (0, 1, or 2). Never executes code.
    """
    # Classify each line into step categories. A single line may contain
    # multiple logical actions separated by deterministic separators
    # ("and then", "then", ";"), each producing its own step in order.
    steps: List[str] = []
    for line in text.splitlines():
        for segment in _split_actions(line):
            cat = _classify_line(segment)
            if cat:
                steps.append(cat)

    findings: List[Finding] = []

    # Chain 1: SOURCE -> SENSITIVE -> NETWORK (secret exfiltration).
    exfil_idx = _find_sequence(steps, ["SOURCE", "SENSITIVE", "NETWORK"])
    if exfil_idx:
        findings.append(
            Finding(
                rule_id="AS-CHAIN-001",
                severity=Severity.CRITICAL,
                title="Potential secret exfiltration chain",
                description=(
                    "Possible secret exfiltration chain detected: "
                    "read sensitive data -> extract secret -> send externally. "
                    "The ordered sequence of steps in this file suggests the agent "
                    "may be instructed to read a secret and send it to an external destination."
                ),
                file=file_path,
                evidence=f"Sequence: {_evidence_for(steps, exfil_idx)}",
                remediation="Review the ordered steps; remove any that read secrets and send them externally.",
            )
        )

    # Chain 2: DOWNLOAD -> EXECUTION (download-and-execute).
    dl_idx = _find_sequence(steps, ["DOWNLOAD", "EXECUTION"])
    if dl_idx:
        findings.append(
            Finding(
                rule_id="AS-CHAIN-002",
                severity=Severity.CRITICAL,
                title="Remote download followed by execution",
                description=(
                    "Possible download-and-execute chain detected: "
                    "download remote content -> execute. The ordered sequence suggests "
                    "remote content is fetched and then run, a supply-chain risk."
                ),
                file=file_path,
                evidence=f"Sequence: {_evidence_for(steps, dl_idx)}",
                remediation="Do not download and execute remote content; pin and review any fetched artifacts.",
            )
        )

    return findings
