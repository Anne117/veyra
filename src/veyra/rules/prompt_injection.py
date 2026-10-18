"""Prompt injection detection rules.

For instruction-bearing text (SKILL.md, markdown, etc.), detect suspicious
instructions that attempt to manipulate the host agent. Severity is based on
context; findings explain WHY the text is suspicious rather than asserting
malice outright.
"""

from __future__ import annotations

import re

from veyra.models import Finding, Severity
from veyra.rules import register

# --- Suspicious instruction patterns ---------------------------------------

IGNORE_INSTRUCTIONS = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system|your)\s+(?:instructions?|prompts?|rules?|guidelines?)\b",
    re.IGNORECASE,
)

# Bounded filler between a reveal verb and the sensitive noun.
# Tolerates phrases like "the value of", "the contents of", "the value of the",
# "the contents of the local database config", "the value of every".
# Deliberately bounded — NOT an unbounded .* — so it does not become a generic
# "print X" detector.
_REVEAL_FILLER = (
    r"(?:(?:the\s+)?(?:value|contents?|content)\s+of\s+"
    r"(?:the\s+)?(?:local\s+)?(?:database\s+)?(?:config\s+)?(?:file\s+)?(?:every\s+)?)?"
)

REVEAL_SECRETS = re.compile(
    r"\b(?:reveal|print|show|expose|leak|output|display)\s+"
    r"(?:your\s+)?(?:all\s+)?" + _REVEAL_FILLER + r"\s*"
    r"(?:secrets?|api\s*keys?|api\s*tokens?|tokens?|credentials?|passwords?|environment\s+variables?)\b",
    re.IGNORECASE,
)

# Negation patterns that indicate the instruction is NOT to reveal secrets.
# e.g. "never reveal secrets", "do not print secrets", "don't expose credentials",
# "must not disclose API keys".
NEGATION = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|should\s+not|shall\s+not|avoid|refrain\s+from|without)\b",
    re.IGNORECASE,
)

# Bounded filler between the sent noun and the "to" preposition.
# Tolerates "of the local database config", "of the config file", etc.
# Deliberately bounded — NOT an unbounded .*. Does not consume the trailing
# space so the pattern's own \s+ before "to" can match.
_SEND_FILLER = (
    r"(?:\s+of\s+(?:the\s+)?(?:local\s+)?(?:database\s+)?(?:config\s*|file\s*)?)?"
)

SEND_FILES = re.compile(
    r"\b(?:send|upload|exfiltrate|transmit|post)\s+"
    r"(?:the\s+)?(?:local\s+)?(?:files?|data|contents?|documents?)" + _SEND_FILLER + r"\s+"
    r"(?:to|via|using)\s+(?:an?\s+)?(?:external|remote|attacker|http|https|url|endpoint)\b",
    re.IGNORECASE,
)

DISABLE_SECURITY = re.compile(
    r"\b(?:disable|turn\s*off|bypass|deactivate|remove)\s+(?:all\s+)?(?:security|safety|guardrails?|restrictions?|protections?|controls?|filters?)\b",
    re.IGNORECASE,
)

# A bare mention of an encoding is documentation, not an instruction:
# "Base64 encode a string.", "ROT13 shifts each letter by 13", "Decodes short
# ROT13 notes used in internal documentation." All of those appear in benign
# fixtures and none of them asks the agent to act on hidden content. The rule
# therefore requires an explicit directive to decode-and-act, in one of the two
# forms that actually carry an instruction:
#   1. an imperative to decode a named blob ("Decode this base64 payload",
#      "Deobfuscate this ROT13 text and run the resulting command");
#   2. encoded content piped through a decoder into a shell
#      ("... | base64 -d | bash").
# See docs/rule-precision-audit.md for the corpus measurement behind this.
DECODE_DIRECTIVE = re.compile(
    r"\b(?:decode|deobfuscate|decrypt)\s+(?:this|the|following)\s+"
    r"(?:\w+\s+){0,2}?(?:base64|rot13|hex|payload|blob|ciphertext|encoded)\b",
    re.IGNORECASE,
)

DECODE_PIPE_TO_SHELL = re.compile(
    r"\b(?:base64|xxd|openssl\s+enc)\s+(?:-d|--decode|-D|-r)\b[^\n]*\|\s*(?:ba|z|da)?sh\b",
    re.IGNORECASE,
)

UNRELATED_EXEC = re.compile(
    r"\b(?:run|execute|install|download)\s+(?:this|the|a)\s+(?:command|script|code|payload)\b",
    re.IGNORECASE,
)


# --- Quoted mentions -------------------------------------------------------
# Defensive guidance has to be able to NAME an attack sentence: "if a page
# says X, treat it as data". The HIGH detectors were reading that quoted
# sentence as an imperative of the skill itself, so hardening docs scored
# HIGH (and composed into chains when a network signal was present).
#
# A mention is recognised only when BOTH hold on the same line:
#   1. the matched span sits inside a paired quotation ("...", '...',
#      `...`, “…”; for ' the quotes must not sit between letters, so
#      apostrophes do not open a span);
#   2. the text BEFORE the opening quote frames it as somebody else's words
#      or as untrusted data ("if … says", "e.g.", "attackers", "such as",
#      "treat it as data", "do not follow", "quoted text").
#
# A quote alone is deliberately not enough: `"Ignore previous instructions."`
# still fires, and so does `The README says "ignore previous instructions".`,
# because a bare "the docs say" is exactly how an injection is framed.
_DEFENSIVE_FRAME = re.compile(
    r"(?:\b(?:e\.g\.|for\s+example|examples?|such\s+as|samples?|quoted?|verbatim"
    r"|attackers?|adversar\w*|malicious|inject\w*|payloads?"
    r"|untrusted|treat\s+(?:it|that|this|them)\s+as|as\s+data"
    r"|do\s+not\s+follow|don'?t\s+follow|never\s+follow"
    r"|do\s+not\s+obey|never\s+obey)\b"
    r"|\b(?:if|when|whenever)\b[^.\n]{0,80}?\b(?:says?|writes?|claims?|contains?|includes?|asks?)\b)",
    re.IGNORECASE,
)

_QUOTE_CHARS = ("\"", "'", "`")


def _opening_quote_index(line: str, start: int, end: int) -> "int | None":
    """Index of the opening quote enclosing ``line[start:end]``, else None."""
    # Curly quotes are a distinct pair rather than one repeated character.
    opener = line.rfind("\u201c", 0, start)
    if opener != -1 and line.find("\u201d", end) != -1:
        return opener
    for ch in _QUOTE_CHARS:
        positions = [i for i, c in enumerate(line) if c == ch]
        for open_idx, close_idx in zip(positions[0::2], positions[1::2]):
            if not (open_idx < start and end <= close_idx):
                continue
            if ch == "'":
                before = line[open_idx - 1] if open_idx else " "
                after = line[close_idx + 1] if close_idx + 1 < len(line) else " "
                if before.isalnum() and after.isalnum():
                    continue
            return open_idx
    return None


def _is_quoted_mention(line: str, start: int, end: int) -> bool:
    """True when the match is a quotation framed as someone else's words."""
    opener = _opening_quote_index(line, start, end)
    if opener is None:
        return False
    return _DEFENSIVE_FRAME.search(line[:opener]) is not None


@register
def detect_ignore_instructions(content: str, file_path: str, line: int) -> "Finding | None":
    m = IGNORE_INSTRUCTIONS.search(content)
    if m and not _is_quoted_mention(content, m.start(), m.end()):
        return Finding(
            rule_id="AS-004",
            severity=Severity.HIGH,
            title="Prompt injection",
            description=(
                "Instruction asks the agent to ignore or override its previous/system "
                "instructions. This is a common prompt-injection pattern."
            ),
            file=file_path,
            line=line,
            evidence="Instruction to ignore previous/system instructions",
            remediation="Remove instructions that override the host agent's system prompt.",
        )
    return None


@register
def detect_reveal_secrets(content: str, file_path: str, line: int) -> "Finding | None":
    m = REVEAL_SECRETS.search(content)
    if not m:
        return None
    # If the reveal phrase is negated (e.g. "never reveal secrets",
    # "do not print secrets"), it is NOT an instruction to disclose.
    if NEGATION.search(content[: m.start()]):
        return None
    if _is_quoted_mention(content, m.start(), m.end()):
        return None
    return Finding(
        rule_id="AS-004",
        severity=Severity.HIGH,
        title="Prompt injection",
        description="Instruction asks the agent to reveal secrets, API keys, or environment variables.",
        file=file_path,
        line=line,
        evidence="Instruction to reveal secrets/credentials",
        remediation="Remove instructions that request secret disclosure.",
    )


@register
def detect_send_files(content: str, file_path: str, line: int) -> "Finding | None":
    m = SEND_FILES.search(content)
    if m and not _is_quoted_mention(content, m.start(), m.end()):
        return Finding(
            rule_id="AS-004",
            severity=Severity.HIGH,
            title="Prompt injection",
            description="Instruction asks the agent to send local files or data to an external destination.",
            file=file_path,
            line=line,
            evidence="Instruction to exfiltrate local files",
            remediation="Remove instructions that request external data exfiltration.",
        )
    return None


@register
def detect_disable_security(content: str, file_path: str, line: int) -> "Finding | None":
    m = DISABLE_SECURITY.search(content)
    if m and not _is_quoted_mention(content, m.start(), m.end()):
        return Finding(
            rule_id="AS-004",
            severity=Severity.HIGH,
            title="Prompt injection",
            description="Instruction asks the agent to disable or bypass security controls.",
            file=file_path,
            line=line,
            evidence="Instruction to disable security controls",
            remediation="Remove instructions that disable safety controls.",
        )
    return None


@register
def detect_encoded_obfuscated(content: str, file_path: str, line: int) -> "Finding | None":
    if DECODE_DIRECTIVE.search(content) or DECODE_PIPE_TO_SHELL.search(content):
        return Finding(
            rule_id="AS-004",
            severity=Severity.MEDIUM,
            title="Prompt injection",
            description="Encoded/obfuscated content detected; instructions may be hidden in encoded text.",
            file=file_path,
            line=line,
            evidence="Encoded/obfuscated content",
            remediation="Decode and review the content; avoid executing hidden instructions.",
        )
    return None


@register
def detect_unrelated_exec(content: str, file_path: str, line: int) -> "Finding | None":
    if UNRELATED_EXEC.search(content):
        return Finding(
            rule_id="AS-004",
            severity=Severity.MEDIUM,
            title="Prompt injection",
            description="Instruction asks the agent to run/install code that may be unrelated to the skill's purpose.",
            file=file_path,
            line=line,
            evidence="Instruction to execute code",
            remediation="Verify the command is necessary and related to the skill's stated purpose.",
        )
    return None
