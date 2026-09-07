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
  TRANSFORM     - encode/transform content (e.g. base64, "into a report")

Chains detected (order matters):
  AS-CHAIN-001  SOURCE -> SENSITIVE -> NETWORK   (secret exfiltration)
  AS-CHAIN-002  DOWNLOAD -> EXECUTION            (download-and-execute)
  AS-CHAIN-004  SOURCE/SENSITIVE -> NETWORK      (source-to-sink exfiltration,
                 same object flows to an external sink, optionally through a
                 TRANSFORM)

The analyzer never executes code and never makes network requests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from veyra.models import Finding, Severity

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

# TRANSFORM: encoding/transforming content (e.g. base64, "into a report").
TRANSFORM = re.compile(
    r"\b(?:transform|encode|convert|format|parse|serialize|decode)\b",
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
    if TRANSFORM.search(line):
        return "TRANSFORM"
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


# --- Structured action model ----------------------------------------------

@dataclass
class Action:
    """A normalized action extracted from a line/segment.

    Preserves semantic identity between actions so the correlation layer can
    determine whether the same object flows from a source to a sink.
    """
    verb: str
    object: str
    destination: Optional[str]
    category: str
    output: Optional[str] = None  # for TRANSFORM: the produced object


# Leading modifier/determiner words stripped during object normalization.
_MODIFIERS = {
    "the", "a", "an", "this", "that", "these", "those",
    "all", "every", "your", "our", "their", "my",
    "local", "remote", "internal", "external",
}

# Trailing container words stripped during object normalization, but only when
# a base noun remains (so "data" alone is kept, "local data" -> "local").
_CONTAINERS = {
    "file", "data", "content", "config", "configuration",
    "value", "contents", "report",
}

# Prepositions that end an object phrase.
_OBJECT_END = re.compile(r"\s+(?:to|into|from|via|using|with|and|then)\b", re.IGNORECASE)

# URL extraction for destinations.
_URL = re.compile(r"https?://[^\s'\"]+")


def _normalize_object(obj: str) -> str:
    """Conservative object normalization.

    Lowercases, strips punctuation, collapses whitespace, removes leading
    modifiers/determiners, and strips trailing container words only when a base
    noun remains. Does NOT do stemming or fuzzy matching.
    """
    s = obj.lower().strip()
    s = re.sub(r"[^a-z0-9\s./_-]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Strip trailing punctuation (periods, etc.).
    s = s.rstrip(".")
    words = s.split()
    # Strip leading modifiers/determiners.
    while words and words[0] in _MODIFIERS:
        words = words[1:]
    # Strip trailing container words only if a base noun remains.
    while words and words[-1] in _CONTAINERS and len(words) > 1:
        words = words[:-1]
    return " ".join(words)


def _extract_action(segment: str) -> Optional[Action]:
    """Extract a structured Action from a segment, or None if not an action."""
    cat = _classify_line(segment)
    if cat is None:
        return None

    # Verb = first word.
    vm = re.match(r"^\s*([a-z]+)", segment, re.IGNORECASE)
    verb = vm.group(1).lower() if vm else ""

    # Destination = URL if present.
    dest = None
    dm = _URL.search(segment)
    if dm:
        dest = dm.group(0)

    # Object = text after the verb, up to a preposition.
    rest = segment[len(verb):].strip() if verb else segment
    om = _OBJECT_END.search(rest)
    if om:
        obj_text = rest[:om.start()]
    else:
        obj_text = rest
    obj = _normalize_object(obj_text)

    # For TRANSFORM, extract the output object after "into"/"to".
    output = None
    if cat == "TRANSFORM":
        om2 = re.search(r"\b(?:into|to)\s+(.+)$", rest, re.IGNORECASE)
        if om2:
            output = _normalize_object(om2.group(1))

    return Action(
        verb=verb,
        object=obj,
        destination=dest,
        category=cat,
        output=output,
    )


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
        "TRANSFORM": "transform",
    }
    return " -> ".join(labels[steps[i]] for i in indices)


def _is_derived_from_produced(obj: str, produced: Set[str], derived: Dict[str, Set[str]]) -> bool:
    """Check whether `obj` is a produced object or a transform output of one.

    Walks the derived map backwards (output -> inputs) to handle chains like
    data -> report -> upload.
    """
    seen: Set[str] = set()
    stack = [obj]
    while stack:
        cur = stack.pop()
        if cur in produced:
            return True
        if cur in seen:
            continue
        seen.add(cur)
        for inp in derived.get(cur, []):
            stack.append(inp)
    return False


def _detect_source_sink(actions: List[Action]) -> Optional[Finding]:
    """Detect a source-to-sink exfiltration chain within a single file.

    Fires when the SAME object (optionally through a TRANSFORM) flows from a
    SOURCE or SENSITIVE action to an external NETWORK sink. This is the
    lightweight intra-file data-flow layer.
    """
    produced: Set[str] = set()
    derived: Dict[str, Set[str]] = {}

    for a in actions:
        if a.category in ("SOURCE", "SENSITIVE") and a.object:
            produced.add(a.object)
        elif a.category == "TRANSFORM" and a.object and a.output:
            derived.setdefault(a.output, set()).add(a.object)
        elif a.category == "NETWORK" and a.object and a.destination:
            if _is_derived_from_produced(a.object, produced, derived):
                return Finding(
                    rule_id="AS-CHAIN-004",
                    severity=Severity.CRITICAL,
                    title="Potential data exfiltration chain (source-to-sink)",
                    description=(
                        "A source/sensitive action produces an object that is then "
                        "sent to an external destination. The same object flows from "
                        "source to sink, indicating possible data exfiltration."
                    ),
                    file="<step-sequence>",
                    evidence=f"Source-to-sink: {a.object} -> external destination",
                    remediation="Review the ordered steps; remove any that read or extract data and send it externally.",
                )
    return None


def analyze_file(text: str, file_path: str) -> List[Finding]:
    """Analyze a single file's text for ordered multi-stage attack sequences.

    Returns a list of AS-CHAIN findings (0, 1, or 2). Never executes code.
    """
    # Classify each line into step categories. A single line may contain
    # multiple logical actions separated by deterministic separators
    # ("and then", "then", ";"), each producing its own step in order.
    steps: List[str] = []
    actions: List[Action] = []
    for line in text.splitlines():
        for segment in _split_actions(line):
            cat = _classify_line(segment)
            if cat:
                steps.append(cat)
            action = _extract_action(segment)
            if action is not None:
                actions.append(action)

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

    # Chain 4: source-to-sink exfiltration (lightweight intra-file data flow).
    sink = _detect_source_sink(actions)
    if sink is not None:
        sink.file = file_path
        findings.append(sink)

    return findings
