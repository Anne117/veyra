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
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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


# Every one of the six detectors below needs one of these verbs, and each is a
# case-insensitive ``\b`` word in the pattern: SOURCE_READ (read/load/open/
# access/get), SENSITIVE (extract/retrieve/obtain/grab/pull/find), DOWNLOAD
# (curl/wget/download/fetch/retrieve), NETWORK_SINK (send/upload/post/put/
# transmit/exfiltrate/push), EXECUTION (run/execute/exec/eval/install/launch/
# bash/sh/shell/popen/system) and TRANSFORM (transform/encode/convert/format/
# parse/serialize/decode). "exec" covers "execute", "sh" covers "shell" and
# "bash", and the stems are matched as substrings of the lowercased line, so
# the set is a superset of every verb the patterns accept: a segment with none
# of them cannot match, and returns None without running six regexes.
#
# Measured on ``agent/`` (111 083 lines): 25 529 lines reach the detectors,
# no line answered the prefilter and then matched, and classification went
# 1.556 s -> 0.908 s on the tree. ``str.lower`` + ``in`` rather than an
# ``re.IGNORECASE`` alternation of the same words: on the same corpus the
# alternation was twice as slow as the detectors it was meant to replace.
_STEP_STEMS = (
    # SOURCE_READ / SENSITIVE / DOWNLOAD
    "read", "load", "open", "access", "get", "extract", "retrieve", "obtain",
    "grab", "pull", "find", "curl", "wget", "download", "fetch",
    # NETWORK_SINK
    "send", "upload", "post", "put", "transmit", "exfiltrate", "push",
    # EXECUTION
    "run", "exec", "eval", "install", "launch", "bash", "sh", "popen",
    "system",
    # TRANSFORM
    "transform", "encode", "convert", "format", "parse", "serialize",
    "decode",
)


def _may_be_a_step(line: str) -> bool:
    """True when the line contains a verb one of the six detectors needs."""
    lowered = line.lower()
    for stem in _STEP_STEMS:
        if stem in lowered:
            return True
    return False


def _classify_uncached(line: str) -> Optional[str]:
    """Classify a segment with the six detectors, in priority order."""
    if not _may_be_a_step(line):
        return None
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


# ``_classify_line`` is a pure function of the segment text, and the scan asks
# the same question about the same text more than once:
# ``analyze_file_chains`` classifies every segment it splits and then hands the
# same segment to ``_extract_action``, which classifies it again; the attack-path
# pass (``scanner._build_attack_paths``) splits and classifies every line of
# every text once more. Measured on ``agent/``: 244 257 calls for about 100 000
# segments, six regexes each -- 3.1 s of a 20.5 s scan (docs/PERFORMANCE.md).
# A hit answers with the string the miss computed, so the memo changes how many
# times the detectors run, never what they say.
#
# The memo is per scan: it keys on segment strings (never file text), it is
# capped, and ``clear_code_line_cache`` drops it at both ends of
# ``scanner.scan_path``.
_CLASSIFY_CACHE_SEGMENTS = 32768
_CLASSIFY_MISS = object()
_classify_cache: Dict[str, Optional[str]] = {}


def _classify_line(line: str) -> Optional[str]:
    """Classify a single line into a step category, or None.

    Order matters: DOWNLOAD is checked before NETWORK so that
    "download ... https://..." is classified as DOWNLOAD, not NETWORK.

    Memoised per segment text (see ``_classify_cache``).
    """
    cached = _classify_cache.get(line, _CLASSIFY_MISS)
    if cached is not _CLASSIFY_MISS:
        return cached  # type: ignore[return-value]
    category = _classify_uncached(line)
    if len(_classify_cache) >= _CLASSIFY_CACHE_SEGMENTS:
        # Past the cap the scan is on to a different vocabulary; start a new
        # epoch instead of refusing to memoise for the rest of the run.
        _classify_cache.clear()
    _classify_cache[line] = category
    return category


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


# The scanner asks for one file's code lines twice: once for the AS-003/AS-006
# line filters (``scanner._scan_file``) and once to classify steps
# (``analyze_file_chains``). Tokenising was 3.3 s of the 25.5 s scan on the
# ``agent/`` tree (docs/PERFORMANCE.md), and both callers pass the *same* ``str``
# object (field probe on ``src``: 112 calls, 56 distinct ids), so the second
# question is answered from the first answer instead of re-parsing the file.
# The bound is a file count, and ``scanner.scan_path`` clears the memo at the
# start of every scan, so no file text outlives the scan that read it.
_CODE_LINE_CACHE_FILES = 1024


@lru_cache(maxsize=_CODE_LINE_CACHE_FILES)
def _scrubbed_python_lines(text: str) -> Optional[Tuple[str, ...]]:
    """Tokenise one text into comment/string-blanked lines (memoised).

    Blanking keeps the line count, the column positions and every character
    outside a comment or string literal, so the answer is the raw line with each
    comment/string span replaced by spaces of the same length.

    The spans are collected first and applied per row, right to left, on the
    *original* line strings: a row with nothing to blank (the overwhelming
    majority of a real file) is passed through without being copied into a
    mutable character list. Building ``[list(row) for row in rows]`` for every
    line of every file was a fifth of the tokenisation phase -- measured on
    ``agent/`` (279 files, 5.5 M chars): 3.09 s -> 2.59 s, byte-identical
    output on all 279 files. Tokens do not overlap, so the spans on one row are
    disjoint and applying them in reverse order gives the same string as
    applying them in token order.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    rows = text.splitlines()
    spans: Dict[int, List[Tuple[int, int]]] = {}
    for tok in tokens:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (sr, sc), (er, ec) = tok.start, tok.end
        for row in range(sr, er + 1):
            if row - 1 >= len(rows):
                break
            length = len(rows[row - 1])
            start = sc if row == sr else 0
            end = ec if row == er else length
            if start < end:
                spans.setdefault(row, []).append((start, end))
    if not spans:
        return tuple(rows)
    out: List[str] = []
    for index, row in enumerate(rows, start=1):
        row_spans = spans.get(index)
        if row_spans is None:
            out.append(row)
            continue
        for start, end in sorted(row_spans, reverse=True):
            row = row[:start] + " " * (end - start) + row[end:]
        out.append(row)
    return tuple(out)


def _code_only_lines(text: str) -> Optional[List[str]]:
    """Blank comments and string literals in Python source, line by line.

    Returns None when the text does not tokenize; the caller then keeps the raw
    text, i.e. the previous behaviour. The tokenised answer is memoised per
    text (see ``_scrubbed_python_lines``); a fresh list is handed out each call
    so no caller can edit the answer the next caller reads.
    """
    scrubbed = _scrubbed_python_lines(text)
    return None if scrubbed is None else list(scrubbed)


def clear_code_line_cache() -> None:
    """Drop every per-scan memo; ``scanner.scan_path`` calls this twice.

    Two answers are memoised for the length of one scan -- the tokenisation of
    a text (``_scrubbed_python_lines``) and the step category of a segment
    (``_classify_cache``). Both are keyed on text the scan read, so both are
    dropped together when the scan that read it ends.
    """
    _scrubbed_python_lines.cache_clear()
    _classify_cache.clear()


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
    # Every branch of ``_ACTION_SEPARATOR`` needs a literal ``;`` or ``then``
    # (any case) in the line, and so does the leading-"then" strip below. A line
    # with neither therefore splits into exactly one segment: itself, stripped,
    # or nothing when it is blank -- which is what the regex below would say at
    # the price of a regex split on every line of every file (docs/PERFORMANCE.md:
    # 222 166 splits, 5.0 s of a 20.5 s scan).
    if ";" not in line and "then" not in line.lower():
        stripped = line.strip()
        return [stripped] if stripped else []
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
    # 1-based source line the action was read from; 0 when the caller did not
    # supply one. A chain that carries this can name the lines that prove it.
    line: int = 0


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


# ``_extract_action`` starts by classifying its segment. Its callers in
# ``analyze_file_chains`` have just classified the same segment for the step
# list, so they pass the answer in rather than ask the same six detectors
# twice. The sentinel keeps "the caller classified it as no category" distinct
# from "the caller did not classify it".
_NOT_CLASSIFIED = object()


def _extract_action(
    segment: str,
    line: int = 0,
    category: object = _NOT_CLASSIFIED,
) -> Optional[Action]:
    """Extract a structured Action from a segment, or None if not an action.

    ``category`` is the optional pre-computed :func:`_classify_line` answer for
    this exact segment; omit it and the segment is classified here.
    """
    cat = _classify_line(segment) if category is _NOT_CLASSIFIED else category
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
        line=line,
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


# --- Object continuity for DOWNLOAD -> EXECUTION ---------------------------
# A download and an execution in the same file, twenty lines apart, are not a
# sequence unless the execution acts on what was downloaded. Measured on the
# public corpus (docs/PUBLIC-CORPUS.md §6): all 10 intra-file AS-CHAIN-002 rows
# paired a DOWNLOAD with an EXECUTION whose object was something else -- an
# install prerequisite, a doc heading, a JSON field name, an unrelated "run it".
#
# Continuity holds when the execution's object
#   1. names a word the download's object also names (`deployment script` ->
#      `deployment script`, `signed installer file` -> `installer script`), or
#   2. is an anaphor (`download the script ... run it`) -- "it" can only mean
#      the thing just named, or
#   3. is a bare artefact kind (`run the script`, `execute the package`): the
#      execution names the artefact by kind and nothing else, so it can only
#      refer to the artefact the download named.
# Rule 3 is the loosest of the three and is the one that keeps this
# repository's own pinned fixture (`Download the installer ... Run the script`)
# green; its residual risk is recorded in the document, not hidden.
_OBJECT_STOPWORDS = frozenset({
    "the", "a", "an", "this", "that", "these", "those", "and", "or", "but",
    "for", "not", "with", "from", "into", "via", "using", "all", "every",
    "your", "our", "their", "my", "its", "you", "can", "will", "are", "was",
    "has", "have", "been", "when", "then", "than", "also", "only", "just",
})
# The verb of a step names the action, never the object it acts on: in
# "Install Go ... / Install golangci-lint ... let `script/lint` install the
# pinned version" the shared word is the verb, and a verb is not an object.
_ACTION_WORDS = frozenset({
    "run", "runs", "running", "execute", "executes", "exec", "eval", "install",
    "installs", "launch", "bash", "shell", "popen", "system", "fetch", "fetches",
    "download", "downloads", "curl", "wget", "retrieve", "retrieves", "read",
    "write", "open", "load", "get", "make", "add", "use", "call", "send",
    "setup", "lint", "build", "test",
})
_ANAPHORA = frozenset({"it", "them", "this", "that", "these", "those",
                        "itself", "themselves"})
_ARTEFACT_KINDS = frozenset({
    "script", "installer", "package", "binary", "executable", "program",
    "tool", "archive", "bundle", "plugin", "payload", "setup", "deployment",
    "file", "module", "application", "image", "container",
})
_MAX_EXEC_OBJECT_WORDS = 3
# Shortest word that may stand for the downloaded object: below this length a
# substring hit is a coincidence ("code" inside "encode"), not a reference.
_MIN_OBJECT_WORD = 5


def _object_words(obj: str) -> List[str]:
    """Content words of a normalized object phrase (never its verbs)."""
    return [
        w for w in obj.split()
        if len(w) >= _MIN_OBJECT_WORD
        and w not in _OBJECT_STOPWORDS
        and w not in _ACTION_WORDS
    ]


def _same_object(download: Action, execution: Action) -> bool:
    """True when the execution acts on the object the download named."""
    exec_obj = execution.object.strip(" .")
    if exec_obj in _ANAPHORA:
        return True
    exec_words = _object_words(exec_obj)
    if not exec_words:
        return False
    # An execution that names its object at all names it in a noun phrase.
    # A long phrase is a sentence *about* something, and any word it happens to
    # share with the download's object is a coincidence of subject matter:
    # "…read the relevant files…" and "…all SDK languages use the same
    # multi-file layout…" share "language" and nothing else.
    if len(exec_words) > _MAX_EXEC_OBJECT_WORDS:
        return False
    # The execution names the downloaded object: the word it uses is the one
    # the download used. Containment, not equality, because a download's object
    # often arrives glued to its URL (`https//host/bootstrap.sh`) while the
    # execution names the file alone (`bootstrap.sh`).
    downloaded = download.object.lower()
    if any(word in downloaded for word in exec_words):
        return True
    return all(w in _ARTEFACT_KINDS for w in exec_words)


def _find_download_execute(
    steps: List[str], actions: List[Optional[Action]], lines: List[int]
) -> Optional[List[int]]:
    """First DOWNLOAD -> EXECUTION whose objects are continuous, within span.

    Same locality rule as ``_find_sequence``: every matched step must lie at
    most ``CHAIN_MAX_LINE_SPAN`` lines after the download. The nearest
    continuous pair wins, so a distant unrelated pair cannot mask a close one.
    """
    for i, step in enumerate(steps):
        if step != "DOWNLOAD":
            continue
        download = actions[i]
        if download is None:
            continue
        for j in range(i + 1, len(steps)):
            if lines[j] - lines[i] > CHAIN_MAX_LINE_SPAN:
                break
            if steps[j] != "EXECUTION":
                continue
            execution = actions[j]
            if execution is None:
                continue
            if _same_object(download, execution):
                return [i, j]
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


def _producing_line(
    obj: str, produced: Dict[str, int], derived: Dict[str, Set[str]]
) -> int:
    """Line of the earliest SOURCE/SENSITIVE action ``obj`` derives from.

    Walks the transform map backwards to the producing action. Returns 0 when
    the producer carries no line number (the caller did not supply one).
    """
    seen: Set[str] = set()
    stack = [obj]
    lines: List[int] = []
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if cur in produced:
            lines.append(produced[cur])
        stack.extend(derived.get(cur, ()))
    return min(lines) if lines else 0


def _detect_source_sink(
    actions: List[Action],
) -> Optional[Tuple[Finding, int, int]]:
    """Detect a source-to-sink exfiltration chain within a single file.

    Fires when the SAME object (optionally through a TRANSFORM) flows from a
    SOURCE or SENSITIVE action to an external NETWORK sink. This is the
    lightweight intra-file data-flow layer.

    Returns the finding plus the first line (the SOURCE/SENSITIVE action that
    produced the object) and the last line (the NETWORK sink that closes the
    chain). Those are the two lines that prove the chain; ``(0, 0)`` only when
    the caller built Actions without line numbers.
    """
    produced: Dict[str, int] = {}
    derived: Dict[str, Set[str]] = {}

    for a in actions:
        if a.category in ("SOURCE", "SENSITIVE") and a.object:
            produced.setdefault(a.object, a.line)
        elif a.category == "TRANSFORM" and a.object and a.output:
            derived.setdefault(a.output, set()).add(a.object)
        elif a.category == "NETWORK" and a.object and a.destination:
            if _is_derived_from_produced(a.object, produced, derived):
                first = _producing_line(a.object, produced, derived)
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
                    line=first,
                    evidence=f"Source-to-sink: {a.object} -> external destination",
                    remediation="Review the ordered steps; remove any that read or extract data and send it externally.",
                ), first, a.line
    return None


def analyze_file_chains(
    text: str, file_path: str
) -> List[Tuple[Finding, int, int]]:
    """Analyze one file and return each chain with the lines that prove it.

    Returns ``(finding, first_line, last_line)`` triples: the finding plus the
    first and last line of the matched step sequence. Every chain now names the
    lines that prove it, AS-CHAIN-004 included: its first line is the
    SOURCE/SENSITIVE action, its last line the NETWORK sink. ``(0, 0)`` only
    appears when the caller supplied Actions without line numbers.
    ``analyze_file`` is the findings-only view of the same analysis. Never
    executes code.
    """
    # Classify each line into step categories. A single line may contain
    # multiple logical actions separated by deterministic separators
    # ("and then", "then", ";"), each producing its own step in order.
    steps: List[str] = []
    step_lines: List[int] = []
    step_actions: List[Optional[Action]] = []
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
            # The same segment, classified once: ``_extract_action`` would
            # otherwise run the six detectors again to reach the same answer.
            action = _extract_action(segment, lineno, cat)
            if action is not None:
                actions.append(action)
            # One entry per step, so the object of a step can be read back
            # (``_find_download_execute``); a step without an action has none.
            if cat:
                step_actions.append(action)

    chains: List[Tuple[Finding, int, int]] = []

    # Chain 1: SOURCE -> SENSITIVE -> NETWORK (secret exfiltration).
    exfil_idx = _find_sequence(
        steps,
        ["SOURCE", "SENSITIVE", "NETWORK"],
        lines=step_lines,
        max_span=CHAIN_MAX_LINE_SPAN,
    )
    if exfil_idx:
        chains.append((
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
                line=step_lines[exfil_idx[0]],
                evidence=f"Sequence: {_evidence_for(steps, exfil_idx)}",
                remediation="Review the ordered steps; remove any that read secrets and send them externally.",
            ),
            step_lines[exfil_idx[0]],
            step_lines[exfil_idx[-1]],
        ))

    # Chain 2: DOWNLOAD -> EXECUTION (download-and-execute).
    #
    # The execution must consume what the download produced (see
    # ``_find_download_execute``). Category adjacency alone is not a sequence:
    # in the public corpus every intra-file AS-CHAIN-002 paired a download with
    # an execution of something else.
    dl_idx = _find_download_execute(steps, step_actions, step_lines)
    if dl_idx:
        chains.append((
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
                line=step_lines[dl_idx[0]],
                evidence=f"Sequence: {_evidence_for(steps, dl_idx)}",
                remediation="Do not download and execute remote content; pin and review any fetched artifacts.",
            ),
            step_lines[dl_idx[0]],
            step_lines[dl_idx[-1]],
        ))

    # Chain 4: source-to-sink exfiltration (lightweight intra-file data flow).
    sink = _detect_source_sink(actions)
    if sink is not None:
        finding, first, last = sink
        finding.file = file_path
        chains.append((finding, first, last))

    return chains


def analyze_file(text: str, file_path: str) -> List[Finding]:
    """Analyze a single file's text for ordered multi-stage attack sequences.

    Returns a list of AS-CHAIN findings (0, 1, or 2). Never executes code.
    """
    return [finding for finding, _, _ in analyze_file_chains(text, file_path)]
