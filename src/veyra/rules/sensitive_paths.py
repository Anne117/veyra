"""Sensitive credential file access detection (AS-006).

Detects an actual READ/ACCESS operation against sensitive credential paths
and files (.env, ~/.aws, ~/.ssh, credential/secret/private-key files).

The rule requires evidence of an access/read operation — it does NOT flag a
sensitive path merely because it is mentioned. Negated/benign statements
("never read ~/.aws/credentials", "do not expose .env") are not flagged.

This is a pure static-analysis rule: it never executes commands and never
accesses the filesystem or network.
"""

from __future__ import annotations

import re

from veyra.models import Finding, Severity
from veyra.rules import register

# --- Sensitive path patterns ----------------------------------------------

# Sensitive credential-bearing paths/files.
# A sensitive path must be a *file or path*, not the bare noun. The previous
# pattern accepted any occurrence of "credential"/"credentials", so a line such
# as ``load_credentials()`` or ``self.env.get(...)`` counted as a credential-file
# access as soon as the line also contained any access verb. Measured on a real
# code slice (Hermes agent/, tools/, acp_adapter/, skills/): that alone produced
# most of 116 HIGH findings on benign source. A noun only counts when it names a
# file ("credentials file", "secret file") or sits in a path ("~/.aws/credentials").
SENSITIVE_PATH = re.compile(
    r"(?:"
    r"\.env(?!\.?\w|\()"                         # dotenv file, not `.env.get(` / `.env.example`
    r"|\.aws(?:[/\\]|\b)"                       # ~/.aws directory or its files
    r"|\.ssh(?:[/\\]|\b)"                       # ~/.ssh directory or its files
    r"|id_rsa|id_ed25519"                        # SSH private keys
    r"|\.pem(?![\w(])|\.key(?![\w(])"            # key material files, not attribute access
    r"|private\s+key"                            # "the private key"
    r"|[/\\]credentials?\b"                      # credentials as a path element
    r"|(?:credentials?|secrets?)\s+files?\b"      # "credentials file", "secret file"
    r")",
    re.IGNORECASE,
)

# Access/read verbs that indicate an actual read operation.
ACCESS_VERB = re.compile(
    r"\b(?:read|cat|open|load|access|get|print|display|show|dump|view|fetch|extract|include|report)\b",
    re.IGNORECASE,
)

# Generic config-file access (NOT sensitive by itself): the verb and the file
# noun are matched separately so that the *relation* between them can be tested
# (see ``_governs``). The pattern used to be one regex with ``[^\n]*`` between
# the two, which made "200 characters of prose" a single signal.
CONFIG_ACCESS_VERB = re.compile(
    r"\b(?:read|open|load|access|get|inspect|update|modify|edit)\b",
    re.IGNORECASE,
)
CONFIG_ACCESS_OBJECT = re.compile(
    r"\b(?:config(?:uration)?(?:\s+file)?|configuration)\b",
    re.IGNORECASE,
)
# The combined form the pre-T16 detector used, kept under its old name because
# docs/PUBLIC-CORPUS.md §3.3 and §4 quote it as the mechanism that fired. The
# detector no longer reads it: it asks ``CONFIG_ACCESS_VERB`` / ``_OBJECT`` and
# tests the relation (see ``_governs``).
CONFIG_ACCESS = re.compile(
    r"\b(?:read|open|load|access|get|inspect|update|modify|edit)\b[^\n]*\b(?:config(?:uration)?(?:\s+file)?|configuration)\b",
    re.IGNORECASE,
)

# Explicit credential extraction terms.
CREDENTIAL_EXTRACTION = re.compile(
    r"\b(?:password|passwd|tokens?|secrets?|credentials?|api\s*key|access\s+key|private\s+key)\b",
    re.IGNORECASE,
)

# Negation patterns: "never read", "do not expose", "don't access", etc.
# Reuse the same negation semantics as the prompt-injection rule.
NEGATION = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|should\s+not|shall\s+not|avoid|refrain\s+from|without|protect|secure|store|commit)\b",
    re.IGNORECASE,
)

# Advisory modality: a sentence that *prescribes a policy* is not an operation.
# "Restrict access to config files containing tokens" tells the reader what to
# do about a file; nothing on the line opens one. Field measurement (T15 §6):
# both `Restrict access to config…` rows in the public corpus are file
# permission advice.
ADVISORY = re.compile(
    r"\b(?:restrict|limit|ensure|recommend|advise|harden|prefer|enforce)\b",
    re.IGNORECASE,
)

# The verb must *govern* the object, not stand next to it (T15 §6): a verb on
# one side of a table cell, a sentence break or a coordinating conjunction does
# not reach the other side, and 120 characters is the widest gap measured
# between a verb and the object it actually takes. Measured against the 15
# AS-006 rows of the public corpus: every one of them fails at least one of
# these three conditions (see docs/PUBLIC-CORPUS.md §"T16: after").
MAX_SIGNAL_WINDOW = 120
_CLAUSE_BREAK = re.compile(
    r"[|;]|\.\s|\.$|\b(?:or|and|but|so|then)\b",
    re.IGNORECASE,
)

# `process.env` is the process environment, not a dotenv file. The path
# pattern sees the `.env` inside it; nothing is read from disk.
_PROCESS_ENV = re.compile(r"\bprocess\s*\.\s*env\b", re.IGNORECASE)


def _is_compound_word(content: str, start: int, end: int) -> bool:
    """True when the match at [start, end) is part of a hyphenated word.

    ``read-only`` is an adjective and ``Get-Content`` is a cmdlet name; the
    verb inside them is not the verb. Both appeared in the public corpus as
    AS-006 rows (T15 §6).
    """
    before = content[start - 1] if start > 0 else ""
    after = content[end] if end < len(content) else ""
    return before == "-" or after == "-"


def _governs(content: str, verb_end: int, object_start: int) -> bool:
    """True when a verb ending at ``verb_end`` takes the object that follows.

    Same line, forward direction (the verb governs what comes after it), inside
    ``MAX_SIGNAL_WINDOW`` characters, with no clause boundary between them.
    """
    if object_start < verb_end:
        return False
    gap = content[verb_end:object_start]
    if len(gap) > MAX_SIGNAL_WINDOW:
        return False
    return _CLAUSE_BREAK.search(gap) is None


def _first_governing_verb(content: str, object_start: int, verbs):
    """The first ``verbs`` match that governs the object at ``object_start``."""
    for m in verbs.finditer(content):
        if m.end() > object_start:
            return None
        if _is_compound_word(content, m.start(), m.end()):
            continue
        if _governs(content, m.end(), object_start):
            return m
    return None


def _first_path_outside_process_env(content: str):
    """The first sensitive-path match that is not ``process.env``."""
    for m in SENSITIVE_PATH.finditer(content):
        if any(p.start() <= m.start() < p.end() for p in _PROCESS_ENV.finditer(content)):
            continue
        return m
    return None


# One cheap question in front of five regexes. Every branch of
# ``SENSITIVE_PATH`` needs one of these stems (``.env`` -> "env", ``.aws`` ->
# "aws", ``.ssh`` -> "ssh", ``id_rsa`` -> "rsa", ``id_ed25519`` ->
# "ed25519", ``.pem`` -> "pem", ``.key``/``private key`` -> "key",
# ``/credentials`` / "credentials file" -> "cred", "secret file" -> "secret"),
# and the second signal needs ``CREDENTIAL_EXTRACTION``, whose every
# alternative ("password"/"passwd" -> "passw", "tokens?" -> "token",
# "secrets?" -> "secret", "credentials?" -> "cred", "api key"/"access key" ->
# "key") is in the same set. So a line that contains none of them cannot
# produce a finding, and NEGATION/SENSITIVE_PATH/ACCESS_VERB/CONFIG_ACCESS/
# CREDENTIAL_EXTRACTION all skip it. This rule ran on every line of every file
# and cost 1.334 s of the 20.5 s ``agent/`` scan (docs/PERFORMANCE.md); the
# stems are a superset of the regex alternatives, so no match is lost.
#
# ``str.lower`` + ``in`` rather than one ``re.IGNORECASE`` alternation: a wide
# literal alternation under IGNORECASE is not the cheap case in CPython, and on
# this corpus it measured slower than the five regexes it was meant to save.
# Measured on ``agent/`` (111 083 lines): 1.271 s -> 0.304 s for this rule,
# 9 626 lines reach the detectors, 0 lines dropped and then matched, and the
# tree's 43 findings are unchanged.
_AS006_STEMS = (
    "env", "aws", "ssh", "rsa", "ed25519", "pem", "key", "cred",
    "secret", "passw", "token",
)


def _may_name_a_credential(content: str) -> bool:
    """True when the line contains any stem a sensitive-path match needs."""
    lowered = content.lower()
    for stem in _AS006_STEMS:
        if stem in lowered:
            return True
    return False


@register
def detect_sensitive_path_access(content: str, file_path: str, line: int) -> "Finding | None":
    """Detect a read/access operation against a sensitive credential path.

    Two signals, both of which now require the verb to *govern* the object:

    1. A known sensitive path (.env, ~/.aws, ~/.ssh, etc.) that an access verb
       takes as its object.
    2. A generic config-file accessed in order to obtain credentials.

    A line with no credential stem at all is answered before any detector runs
    (see ``_AS006_STEMS``); the prefilter drops lines, never matches.

    T16 additions, each measured on the public corpus (docs/PUBLIC-CORPUS.md
    §"T16: after"); every one of the 15 AS-006 rows there fails at least one:

    - the verb must come *before* the path (``files are no longer read`` is not
      a read; ``private key, exchanges it for an access token`` is not an
      access to the key),
    - verb and object must be within ``MAX_SIGNAL_WINDOW`` characters with no
      clause boundary between them (a table cell, a sentence, `or`/`and`),
    - a compound word is not the verb (``read-only``, ``Get-Content``),
    - ``process.env`` is the environment, not a dotenv file,
    - advisory modality (``restrict``, ``ensure``, ...) prescribes a policy.
    """
    if not _may_name_a_credential(content):
        return None

    # If the access verb is negated (e.g. "never read ~/.aws/credentials",
    # "do not expose .env"), it is NOT an actual access operation.
    if NEGATION.search(content):
        return None

    # Signal 1: known sensitive path + a verb that governs it.
    path = _first_path_outside_process_env(content)
    if path is not None and _first_governing_verb(content, path.start(), ACCESS_VERB):
        return Finding(
            rule_id="AS-006",
            severity=Severity.HIGH,
            title="Sensitive credential file access",
            description="A read/access operation against a sensitive credential file or path was detected.",
            file=file_path,
            line=line,
            evidence="Access to sensitive credential path",
            remediation="Avoid reading credential files; use a secrets manager or scoped credentials.",
        )

    # Signal 2: generic config-file access combined with credential extraction.
    config = CONFIG_ACCESS_OBJECT.search(content)
    verb = (
        _first_governing_verb(content, config.start(), CONFIG_ACCESS_VERB)
        if config is not None
        else None
    )
    if verb is not None and CREDENTIAL_EXTRACTION.search(content):
        # Advisory modality before the verb: the sentence prescribes a policy.
        advisory = ADVISORY.search(content)
        if advisory is None or advisory.start() > verb.start():
            return Finding(
                rule_id="AS-006",
                severity=Severity.HIGH,
                title="Sensitive credential file access",
                description="A configuration file is being accessed in order to obtain credentials.",
                file=file_path,
                line=line,
                evidence="Config file access combined with credential extraction",
                remediation="Avoid extracting credentials from config files; use a secrets manager or scoped credentials.",
            )

    return None
