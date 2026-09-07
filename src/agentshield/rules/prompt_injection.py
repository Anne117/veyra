"""Prompt injection detection rules.

For instruction-bearing text (SKILL.md, markdown, etc.), detect suspicious
instructions that attempt to manipulate the host agent. Severity is based on
context; findings explain WHY the text is suspicious rather than asserting
malice outright.
"""

from __future__ import annotations

import re

from agentshield.models import Finding, Severity
from agentshield.rules import register

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

ENCODED_OBFUSCATED = re.compile(
    r"\b(?:base64|rot13|hex\s*encode|obfuscate|decode\s+this|deobfuscate)\b",
    re.IGNORECASE,
)

UNRELATED_EXEC = re.compile(
    r"\b(?:run|execute|install|download)\s+(?:this|the|a)\s+(?:command|script|code|payload)\b",
    re.IGNORECASE,
)


@register
def detect_ignore_instructions(content: str, file_path: str, line: int) -> "Finding | None":
    if IGNORE_INSTRUCTIONS.search(content):
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
    if SEND_FILES.search(content):
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
    if DISABLE_SECURITY.search(content):
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
    if ENCODED_OBFUSCATED.search(content):
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
