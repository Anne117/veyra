"""CWE (Common Weakness Enumeration) metadata for Veyra findings.

Contains only mappings that are defensible from the existing rule behavior.
Rules without a justified CWE mapping are left unmapped (empty list) — we do
not guess.

This is a static, deterministic lookup — no CWE database, no API, no dynamic
fetching.
"""

from __future__ import annotations

from typing import Dict, List

# Defensible CWE mappings: rule_id -> list of CWE IDs.
# Only include mappings that clearly match the rule's behavior.
CWE_MAPPINGS: Dict[str, List[str]] = {
    # Hardcoded secrets / credentials in source.
    "AS-001": ["CWE-798"],
    # Command and script execution.
    "AS-002": ["CWE-78"],
    # Sensitive credential file access.
    "AS-006": ["CWE-522"],
    # Encoded content executed/fetched (obfuscation + execution).
    "AS-007": ["CWE-749"],
    # MCP config with secrets in environment.
    "AS-MCP-006": ["CWE-798"],
    # MCP config with broad filesystem access.
    "AS-MCP-007": ["CWE-732"],
    # MCP config with dynamic package execution.
    "AS-MCP-004": ["CWE-749"],
    # MCP config with remote endpoint.
    "AS-MCP-001": ["CWE-749"],
}


def cwe_for(rule_id: str) -> List[str]:
    """Return the CWE IDs for a rule, or an empty list if unmapped."""
    return list(CWE_MAPPINGS.get(rule_id, []))
