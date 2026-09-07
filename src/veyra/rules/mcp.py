"""MCP (Model Context Protocol) configuration security rules.

Parses MCP server configuration files (.mcp.json, mcp.json, mcp_servers.json,
and structurally identifiable JSON/YAML) and flags security-relevant settings.

These are FILE rules: they receive the full file text and parse it as
structured data. They never execute MCP commands, never start servers, never
connect to endpoints, and never download or resolve remote URLs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from veyra.models import Finding, Severity
from veyra.rules import register_file_rule

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False

# --- MCP config file identification ----------------------------------------

# Files that are always treated as MCP config.
MCP_FILENAMES = {".mcp.json", "mcp.json", "mcp_servers.json", "mcp_servers.yaml", "mcp_servers.yml"}

# Top-level keys that indicate an MCP server map.
MCP_SERVER_KEYS = {"mcpServers", "mcp_servers", "servers", "mcp"}

# Keys inside a server entry that carry security-relevant settings.
SERVER_KEYS = {"command", "args", "env", "url", "type", "transport", "headers", "cwd"}

# --- Pattern helpers -------------------------------------------------------

# Dynamic package runners that fetch/execute code from a registry.
DYNAMIC_RUNNERS = re.compile(
    r"^(?:npx|npm|uvx|uv|pip|pipx|pnpm|yarn|deno|bun)\b",
    re.IGNORECASE,
)

# Secret-looking environment variable names.
SECRET_ENV_NAMES = re.compile(
    r"(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE_?KEY|ACCESS_?KEY|SESSION)",
    re.IGNORECASE,
)

# Broad filesystem access patterns in args.
BROAD_FS = re.compile(
    r"(?:/|/home|/Users|/root|/etc|/var|C:\\\\|C:/|\.\./|\.\.\\\\)",
    re.IGNORECASE,
)

# Suspicious command arguments.
SUSPICIOUS_ARGS = re.compile(
    r"(?:--allow-?all|--dangerous|--unsafe|--no-?sandbox|--privileged|--root|--force|--yes\b|--no-?verify|--insecure|--allow-?write|--allow-?read)",
    re.IGNORECASE,
)

# Remote URL combined with executable/download behavior.
REMOTE_EXEC = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|requests\.get|urllib|fetch|axios)\b[^\n]*(?:\.(?:exe|msi|sh|bat|ps1|jar|bin)\b|\|\s*(?:ba)?sh\b)",
    re.IGNORECASE,
)


def _is_mcp_config(path: str) -> bool:
    """Return True if the file looks like an MCP configuration."""
    name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if name in MCP_FILENAMES:
        return True
    # Structurally identifiable: JSON/YAML with an MCP server map.
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in {"json", "yaml", "yml"}


def _parse(text: str, path: str) -> Optional[Dict[str, Any]]:
    """Parse JSON or YAML into a dict. Returns None if unparseable."""
    name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext == "json" or name in {".mcp.json", "mcp.json", "mcp_servers.json"}:
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None
    if ext in {"yaml", "yml"} and _HAS_YAML:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None
    return None


def _find_server_map(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Locate the dict mapping server names to server configs."""
    for key in MCP_SERVER_KEYS:
        if key in data and isinstance(data[key], dict):
            return data[key]
    # Some configs nest under a single 'mcpServers' object directly.
    return None


def _iter_servers(data: Dict[str, Any]) -> List[tuple]:
    """Return a list of (server_name, server_config) tuples."""
    server_map = _find_server_map(data)
    if server_map is None:
        return []
    out = []
    for name, cfg in server_map.items():
        if isinstance(cfg, dict):
            out.append((name, cfg))
    return out


def _line_for(text: str, needle: str) -> Optional[int]:
    """Best-effort line number for a needle within the raw text."""
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return None


def _mk(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    file_path: str,
    evidence: str,
    remediation: str,
    text: str,
    needle: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        file=file_path,
        line=_line_for(text, needle),
        evidence=evidence,
        remediation=remediation,
    )


@register_file_rule
def scan_mcp_config(text: str, file_path: str) -> List[Finding]:
    """Analyze an MCP configuration file for security issues."""
    if not _is_mcp_config(file_path):
        return []

    data = _parse(text, file_path)
    if data is None:
        return []

    findings: List[Finding] = []
    servers = _iter_servers(data)

    if not servers:
        return findings

    for name, cfg in servers:
        findings.extend(_analyze_server(name, cfg, text, file_path))

    return findings


def _analyze_server(name: str, cfg: Dict[str, Any], text: str, file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    needle = name  # used for line lookup

    command = cfg.get("command")
    args = cfg.get("args")
    env = cfg.get("env")
    url = cfg.get("url")
    server_type = cfg.get("type") or cfg.get("transport")

    # --- AS-MCP-001: Remote MCP endpoint -----------------------------------
    if url:
        findings.append(
            _mk(
                "AS-MCP-001",
                Severity.MEDIUM,
                "Remote MCP endpoint",
                f"MCP server '{name}' connects to a remote endpoint. Remote servers are not inherently malicious, but they send data to an external host.",
                file_path,
                f"Remote endpoint: {url}",
                "Verify the endpoint is trusted and review what data it receives.",
                text,
                needle,
            )
        )

    # --- AS-MCP-002: HTTP without HTTPS ------------------------------------
    if isinstance(url, str) and url.startswith("http://"):
        findings.append(
            _mk(
                "AS-MCP-002",
                Severity.HIGH,
                "HTTP endpoint without HTTPS",
                f"MCP server '{name}' uses plain HTTP, which transmits data unencrypted.",
                file_path,
                f"Plain HTTP endpoint: {url}",
                "Use an HTTPS endpoint to encrypt traffic.",
                text,
                needle,
            )
        )

    # --- AS-MCP-003: Local command execution -------------------------------
    if command:
        findings.append(
            _mk(
                "AS-MCP-003",
                Severity.MEDIUM,
                "Local command execution",
                f"MCP server '{name}' launches a local command. The command runs on the host when the server starts.",
                file_path,
                f"Command: {command}",
                "Review the command and ensure it is trusted and pinned to a known version.",
                text,
                needle,
            )
        )

    # --- AS-MCP-004: Dynamic package execution -----------------------------
    if isinstance(command, str) and DYNAMIC_RUNNERS.match(command.strip()):
        findings.append(
            _mk(
                "AS-MCP-004",
                Severity.MEDIUM,
                "Dynamic package execution",
                f"MCP server '{name}' runs '{command}', which fetches and executes a package from a registry at runtime.",
                file_path,
                f"Dynamic runner: {command}",
                "Pin the package to a specific version and verify its provenance.",
                text,
                needle,
            )
        )

    # --- AS-MCP-005: Environment variables passed to server ----------------
    if isinstance(env, dict) and env:
        findings.append(
            _mk(
                "AS-MCP-005",
                Severity.LOW,
                "Environment variables passed to MCP server",
                f"MCP server '{name}' receives {len(env)} environment variable(s). These may expose host configuration to the server.",
                file_path,
                f"Environment variables: {', '.join(sorted(env.keys()))}",
                "Pass only the minimum variables the server needs.",
                text,
                needle,
            )
        )

    # --- AS-MCP-006: Secret-looking environment variables ------------------
    if isinstance(env, dict):
        for var, value in env.items():
            if SECRET_ENV_NAMES.search(var):
                findings.append(
                    _mk(
                        "AS-MCP-006",
                        Severity.HIGH,
                        "Secret passed to MCP server",
                        f"MCP server '{name}' receives '{var}', which looks like a secret. The value is exposed to the server process.",
                        file_path,
                        f"Secret-like env var: {var}",
                        "Avoid passing secrets to MCP servers; use a secrets manager or scoped credentials.",
                        text,
                        needle,
                    )
                )

    # --- AS-MCP-007: Broad filesystem/path access ---------------------------
    if isinstance(args, list):
        joined = " ".join(str(a) for a in args)
        if BROAD_FS.search(joined):
            findings.append(
                _mk(
                    "AS-MCP-007",
                    Severity.MEDIUM,
                    "Broad filesystem access",
                    f"MCP server '{name}' is granted broad filesystem/path access via its arguments.",
                    file_path,
                    f"Broad path in args: {joined[:120]}",
                    "Restrict the server to the specific directories it needs.",
                    text,
                    needle,
                )
            )

    # --- AS-MCP-008: Suspicious command arguments --------------------------
    if isinstance(args, list):
        joined = " ".join(str(a) for a in args)
        if SUSPICIOUS_ARGS.search(joined):
            findings.append(
                _mk(
                    "AS-MCP-008",
                    Severity.HIGH,
                    "Suspicious command arguments",
                    f"MCP server '{name}' uses flags that disable safety or grant elevated access.",
                    file_path,
                    f"Suspicious args: {joined[:120]}",
                    "Remove flags that disable sandboxing or grant unnecessary privileges.",
                    text,
                    needle,
                )
            )

    # --- AS-MCP-009: Remote URL + executable/download behavior -------------
    if isinstance(url, str) and REMOTE_EXEC.search(url):
        findings.append(
            _mk(
                "AS-MCP-009",
                Severity.HIGH,
                "Remote URL with executable/download behavior",
                f"MCP server '{name}' references a remote URL combined with download/execution behavior.",
                file_path,
                f"Remote executable URL: {url}",
                "Do not fetch and execute remote content; pin and review the artifact.",
                text,
                needle,
            )
        )

    # --- AS-MCP-010: Missing/ambiguous trust information -------------------
    # A server with no command, no url, and no type is ambiguous.
    if not command and not url and not server_type:
        findings.append(
            _mk(
                "AS-MCP-010",
                Severity.INFO,
                "Missing server trust information",
                f"MCP server '{name}' has no command, URL, or transport type, so its behavior is ambiguous.",
                file_path,
                "No command/url/type specified",
                "Specify the server's command or URL so its behavior is clear.",
                text,
                needle,
            )
        )

    return findings
