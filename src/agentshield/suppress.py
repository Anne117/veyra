"""Suppression / allowlist system for AgentShield.

Loads a project configuration file (`.agentshield.toml`) and applies
suppression AFTER findings are generated. Suppressed findings are marked
with `suppressed=True` and a `suppression_reason`, so they remain
distinguishable from findings that were never detected.

Suppression is explicit and never silent: terminal and JSON output both
report suppressed findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from agentshield.models import Finding

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore


CONFIG_FILENAME = ".agentshield.toml"


@dataclass
class SuppressionConfig:
    servers: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.servers or self.domains or self.rules)


def _load_toml(path: Path) -> Optional[Dict]:
    if tomllib is None:
        return None
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


def load_config(path: Optional[str] = None) -> SuppressionConfig:
    """Load suppression config from a path or auto-discover `.agentshield.toml`.

    If `path` is a directory, looks for `.agentshield.toml` inside it.
    If `path` is a file, looks for `.agentshield.toml` in its parent.
    """
    if path is None:
        return SuppressionConfig()

    p = Path(path)
    if p.is_dir():
        config_file = p / CONFIG_FILENAME
    else:
        config_file = p.parent / CONFIG_FILENAME

    if not config_file.exists():
        return SuppressionConfig()

    data = _load_toml(config_file)
    if data is None:
        return SuppressionConfig()

    ignore = data.get("ignore", {})
    if not isinstance(ignore, dict):
        return SuppressionConfig()

    def _list(key: str) -> List[str]:
        v = ignore.get(key, [])
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            return [v]
        return []

    return SuppressionConfig(
        servers=_list("servers"),
        domains=_list("domains"),
        rules=_list("rules"),
    )


def _extract_domain(evidence: str) -> Optional[str]:
    """Extract a domain from a finding's evidence string."""
    m = re.search(r"https?://([^/\s'\"]+)", evidence)
    if m:
        return m.group(1).lower()
    return None


def _matches_domain(evidence: str, domains: List[str]) -> bool:
    """Check if any configured domain appears in the evidence (host or suffix)."""
    if not domains:
        return False
    ev = evidence.lower()
    for d in domains:
        d = d.lower().strip()
        if not d:
            continue
        # Match exact host or subdomain suffix.
        if d in ev or f".{d}" in ev:
            return True
    return False


def apply_suppression(findings: List[Finding], config: SuppressionConfig) -> List[Finding]:
    """Mark findings as suppressed based on the config.

    Returns a new list; original findings are not mutated.
    """
    if config.is_empty():
        return list(findings)

    suppressed_servers = set(config.servers)
    suppressed_rules = set(config.rules)

    out: List[Finding] = []
    for f in findings:
        reason = None

        # Suppress by rule ID.
        if f.rule_id in suppressed_rules:
            reason = f"rule {f.rule_id} ignored"

        # Suppress by MCP server name (AS-MCP findings carry the server name
        # in the description, e.g. "MCP server 'filesystem' ...").
        if reason is None and suppressed_servers:
            for s in suppressed_servers:
                if f"'{s}'" in f.description:
                    reason = f"MCP server '{s}' ignored"
                    break

        # Suppress by domain in evidence.
        if reason is None and _matches_domain(f.evidence, config.domains):
            reason = "domain ignored"

        if reason is not None:
            f.suppressed = True
            f.suppression_reason = reason

        out.append(f)

    return out
