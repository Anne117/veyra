"""Security rules for AgentShield.

Two kinds of rules:

1. Line rules — callables with signature:

       def rule(content: str, file_path: str, line: int) -> Optional[Finding]

   Applied to each line of every scanned file.

2. File rules — callables with signature:

       def rule(text: str, file_path: str) -> List[Finding]

   Applied to the full text of a file. Used for structured formats
   (JSON/YAML MCP config) where line-by-line analysis is insufficient.

All rules are pure static-analysis functions. They never execute scanned
code and never make network requests.
"""

from __future__ import annotations

from typing import Callable, List

from agentshield.models import Finding

# A line rule inspects a single line and returns a finding or None.
Rule = Callable[[str, str, int], "Finding | None"]

# A file rule inspects the full file text and returns zero or more findings.
FileRule = Callable[[str, str], "List[Finding]"]

# Populated by the scanner; each module appends its rules here.
ALL_RULES: List[Rule] = []
ALL_FILE_RULES: List[FileRule] = []


def register(rule: Rule) -> Rule:
    ALL_RULES.append(rule)
    return rule


def register_file_rule(rule: FileRule) -> FileRule:
    ALL_FILE_RULES.append(rule)
    return rule


def load_rules() -> List[Rule]:
    """Import all rule modules so their @register decorators run."""
    from agentshield import rules as _rules  # noqa: F401
    from agentshield.rules import (  # noqa: F401
        network,
        prompt_injection,
        secrets,
        sensitive_paths,
        shell,
        suspicious_urls,
    )

    return ALL_RULES


def load_file_rules() -> List[FileRule]:
    """Import all file-rule modules so their @register_file_rule decorators run."""
    from agentshield import rules as _rules  # noqa: F401
    from agentshield.rules import mcp, obfuscation  # noqa: F401

    return ALL_FILE_RULES
