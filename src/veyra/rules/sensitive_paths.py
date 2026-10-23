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

# Generic config-file access (NOT sensitive by itself).
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

    Two signals:
    1. A read/access of a known sensitive path (.env, ~/.aws, ~/.ssh, etc.).
    2. A generic config-file access combined with explicit credential
       extraction (password/token/secret/credential/API key).

    A line with no credential stem at all is answered before any detector runs
    (see ``_AS006_STEMS``); the prefilter drops lines, never matches.
    """
    if not _may_name_a_credential(content):
        return None

    # If the access verb is negated (e.g. "never read ~/.aws/credentials",
    # "do not expose .env"), it is NOT an actual access operation.
    if NEGATION.search(content):
        return None

    # Signal 1: known sensitive path + access verb.
    if SENSITIVE_PATH.search(content) and ACCESS_VERB.search(content):
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
    if CONFIG_ACCESS.search(content) and CREDENTIAL_EXTRACTION.search(content):
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
