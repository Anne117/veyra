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

In Python source a line is a step only when the action is in code: comments and
string literals are data (pattern tables, finding messages, docstrings). The one
exception is a string literal handed to an execution sink, which is the command
being run.

The analyzer never executes code and never makes network requests.
"""

from __future__ import annotations

import io
import re
import tokenize
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


# A Python line is an action only when it is code. String literals in Python
# source are data — a regex pattern table, a finding message, a docstring — and
# reading them as steps made the analyzer report its own pattern tables as
# chains (field: two AS-CHAIN-002 from pure regex tuples). Comments are never
# executed at all. The one exception is a literal handed to an execution sink,
# where the literal IS the command being run: there the raw line is classified.
_EXECUTION_SINK = re.compile(
    r"(?:\b(?:subprocess\.(?:run|call|check_call|check_output|Popen)|os\.(?:system|popen)"
    r"|exec|eval)\s*\()|shell\s*=\s*True"
)


def _code_only_lines(text: str) -> Optional[List[str]]:
    """Blank comments and string literals in Python source, line by line.

    Returns None when the text does not tokenize; the caller then keeps the raw
    text, i.e. the previous behaviour.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    rows = [list(line) for line in text.splitlines()]
    for tok in tokens:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (sr, sc), (er, ec) = tok.start, tok.end
        for row in range(sr, er + 1):
            if row - 1 >= len(rows):
                break
            buf = rows[row - 1]
            start = sc if row == sr else 0
            end = ec if row == er else len(buf)
            if start < end:
                buf[start:end] = " " * (end - start)
    return ["".join(row) for row in rows]


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

    ``category`` is one of the step-category strings (SOURCE, SENSITIVE,
    DOWNLOAD, NETWORK, EXECUTION, TRANSFORM) or the explicit component-transfer
    category ``TRANSFER``. A ``TRANSFER`` action represents explicit
    component-transfer EVIDENCE: ``destination`` names the canonical target
    semantic component that control is handed off to. It is NEVER produced
    automatically by the source parser — an operation such as a generic function
    call, HTTP request, import, or endpoint/tool/MCP use is not a component
    transfer and the scanner classifies it exactly as before. A ``TRANSFER``
    action is only ever constructed by code that has explicit knowledge of the
    target component identity.
    """
    verb: str
    object: str
    destination: Optional[str]
    category: str
    output: Optional[str] = None  # for TRANSFORM: the produced object


# Explicit component-transfer category. Only used when an action's ``destination``
# is a canonical target component identity; the source scanner never emits it.
ACTION_CATEGORY_TRANSFER = "TRANSFER"


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


def strip_url_punctuation(url: str) -> str:
    """Strip trailing prose punctuation from a URL found in running text.

    In "upload it to https://example.com/x." the period belongs to the
    sentence, not to the destination. Keeping it would create a distinct
    ENDPOINT identity for the same URL and misreport the sink.
    """
    return url.rstrip(".,;:!?)]}\"'")


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
        dest = strip_url_punctuation(dm.group(0))

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


# Maximum line distance between the first and the last step of a chain.
# Measured on the corpus: every genuine DOWNLOAD -> EXECUTION fixture puts both
# steps on one line or within 3 lines; every genuine SOURCE -> SENSITIVE ->
# NETWORK fixture puts the three steps within 15 lines (the fixture that
# deliberately pads with unrelated text) and 6 lines otherwise. In the field
# slice the smallest false pair was 47 lines apart (a UI label that says "fetch"
# and another that says "exec" in the same rendering module), and a documented
# API skill matched SOURCE..NETWORK across 191 lines. Unbounded pairing over a
# file of a few thousand lines is not a sequence, it is any-two-lines.
CHAIN_MAX_LINE_SPAN = 20


def _find_sequence(
    steps: List[str],
    pattern: List[str],
    lines: Optional[List[int]] = None,
    max_span: Optional[int] = None,
) -> Optional[List[int]]:
    """Find the first occurrence of `pattern` as an ordered subsequence of `steps`.

    Returns the indices of the matched steps, or None. Non-adjacent matches
    are allowed (harmless text/steps between signals are skipped).

    When `lines` and `max_span` are both given the match must also be local: each
    matched step must lie at most `max_span` lines after the first matched step.
    The nearest qualifying match wins, so a distant match does not mask a close one.
    """
    if lines is not None and max_span is not None:
        # Locality applies to the whole sequence: every matched step must lie
        # within `max_span` lines of the FIRST one. For a two-step chain this is
        # exactly the old behaviour; for a longer chain it stops a SOURCE in one
        # part of a file from pairing with a NETWORK sink hundreds of lines away.
        for i, step in enumerate(steps):
            if step != pattern[0]:
                continue
            matched = [i]
            pi = 1
            for j in range(i + 1, len(steps)):
                if lines[j] - lines[i] > max_span:
                    break
                if steps[j] == pattern[pi]:
                    matched.append(j)
                    pi += 1
                    if pi == len(pattern):
                        return matched
        return None

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
    step_lines: List[int] = []
    actions: List[Action] = []
    code_lines = _code_only_lines(text) if file_path.lower().endswith(".py") else None
    for lineno, line in enumerate(text.splitlines(), start=1):
        scrubbed = line
        if code_lines is not None and lineno - 1 < len(code_lines):
            if not _EXECUTION_SINK.search(line):
                scrubbed = code_lines[lineno - 1]
        for segment in _split_actions(scrubbed):
            cat = _classify_line(segment)
            if cat:
                steps.append(cat)
                step_lines.append(lineno)
            action = _extract_action(segment)
            if action is not None:
                actions.append(action)

    findings: List[Finding] = []

    # Chain 1: SOURCE -> SENSITIVE -> NETWORK (secret exfiltration).
    exfil_idx = _find_sequence(
        steps,
        ["SOURCE", "SENSITIVE", "NETWORK"],
        lines=step_lines,
        max_span=CHAIN_MAX_LINE_SPAN,
    )
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
    dl_idx = _find_sequence(
        steps,
        ["DOWNLOAD", "EXECUTION"],
        lines=step_lines,
        max_span=CHAIN_MAX_LINE_SPAN,
    )
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
