"""MITRE ATT&CK metadata for AgentShield findings.

Contains the approved PUBLIC mappings only. Medium-confidence mappings are
deliberately NOT exposed. See docs/mitre-attack-mapping.md.

This is a static, deterministic lookup — no MITRE API, no database, no dynamic
fetching.
"""

from __future__ import annotations

from typing import Dict, List

# Approved public mappings: rule_id -> list of {id, name}.
# Only these five mappings are exposed. Do not add others without approval.
PUBLIC_MITRE_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "AS-001": [
        {"id": "T1552.001", "name": "Credentials In Files"},
    ],
    "AS-002": [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "AS-006": [
        {"id": "T1552.001", "name": "Credentials In Files"},
    ],
    "AS-CHAIN-002": [
        {"id": "T1105", "name": "Ingress Tool Transfer"},
    ],
    "AS-MCP-006": [
        {"id": "T1552.001", "name": "Credentials In Files"},
    ],
}

# Unix-shell-specific AS-002 detections also map to T1059.004.
# These are the evidence strings that indicate a Unix shell execution.
UNIX_SHELL_EVIDENCE = (
    "curl | bash pattern",
    "wget | sh pattern",
    "eval statement",
    "URL piped into shell",
)

# T1059.004 is added to AS-002 findings whose evidence indicates Unix shell use.
UNIX_SHELL_MITRE = {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"}


def mitre_for(rule_id: str, evidence: str = "") -> List[Dict[str, str]]:
    """Return the approved public MITRE mappings for a finding.

    AS-002 findings that indicate Unix shell execution also get T1059.004.
    Returns an empty list for rules without an approved mapping.
    """
    mappings = list(PUBLIC_MITRE_MAPPINGS.get(rule_id, []))

    if rule_id == "AS-002":
        for marker in UNIX_SHELL_EVIDENCE:
            if marker in evidence:
                mappings.append(UNIX_SHELL_MITRE)
                break

    return mappings
