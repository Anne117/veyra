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

# Rule emitted when a YAML MCP config could not be parsed because PyYAML is
# not installed. Severity INFO: this is a coverage gap, not a finding about
# the scanned code itself.
_YAML_DEP_RULE_ID = "AS-MCP-WARN-YAML-DEP-MISSING"

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

# A token is a bare, unpinned package reference when it looks like a
# registry package name (letters/digits/_/-/.) without an explicit
# version pin (@x.y.z or ==x.y.z) and without a scope prefix (@scope/).
# Scoped packages like @modelcontextprotocol/server-filesystem are NOT
# considered bare because they come from a known namespace.
# Flags (starting with -) and filesystem paths are also excluded.
_BARE_UNPINNED_PKG = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-\.]*$")
_VERSION_PIN = re.compile(r"(?:@\d+\.\d+|==\d)")


# AS-MCP-003 precision. Every stdio MCP server is started by *some* command
# (``npx ...``, ``python -m ...``), so "a command exists" describes the
# transport, not a risk: on the corpus it fired on 10/10 attack cases and
# 4/4 benign lookalikes and separated nothing. The signal worth reporting is a
# command line that hides its payload inside a shell invocation or shell
# metacharacters -- the config then no longer says what will actually run.
# Plain launchers stay covered by AS-MCP-004 (dynamic runner / unpinned
# package), AS-MCP-007 (filesystem scope) and AS-MCP-008 (dangerous flags).
_SHELL_EXEC = re.compile(
    r"^(?:[A-Za-z]:\\[^\s]*\\|/[^\s]+/)?"
    r"(?:bash|sh|zsh|dash|ksh|fish|csh|tcsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)\b",
    re.IGNORECASE,
)
_SHELL_INLINE_FLAGS = {
    "-c", "/c", "/C", "--command", "-command", "-Command",
    "-encodedcommand", "-EncodedCommand", "-e",
}
_SHELL_METACHAR = re.compile(r"[;|&`$()<>]")


def _shell_wrapped_command(command, args) -> Optional[str]:
    """Return the command line when it hides its payload behind a shell.

    Returns ``None`` for a plain launcher (``npx``, ``python``, ``uvx``) and
    for a non-shell interpreter running an inline program
    (``python -c "print(1)"``), because neither hides anything: the executable
    and its arguments are both visible in the config.
    """
    if not isinstance(command, str):
        return None
    cmd = command.strip()
    if not cmd:
        return None
    arg_tokens = [str(a) for a in args] if isinstance(args, list) else []
    joined = " ".join([cmd, *arg_tokens])
    if _SHELL_METACHAR.search(cmd):
        return joined
    if not _SHELL_EXEC.match(cmd):
        return None
    inline = any(
        t in _SHELL_INLINE_FLAGS or t.startswith("--command=") for t in arg_tokens
    )
    if inline or _SHELL_METACHAR.search(joined):
        return joined
    return None


def _is_bare_unpinned_package(token):
    """True if token looks like a bare, unpinned package reference.

    A bare reference is riskier than a scoped or version-pinned one because
    typosquats and dependency-confusion attacks exploit exactly this shape.
    """
    if not isinstance(token, str):
        return False
    if token.startswith(("@", "-", "/", ".", "C:", "C\\")):
        return False
    if _VERSION_PIN.search(token):
        return False
    return bool(_BARE_UNPINNED_PKG.match(token))

# Secret-looking environment variable names.
SECRET_ENV_NAMES = re.compile(
    r"(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE_?KEY|ACCESS_?KEY|SESSION)",
    re.IGNORECASE,
)

# System-root filesystem path tokens that, when granted as an MCP server
# argument, give the agent access to top-level directories it normally would
# not have. Detected per-argument (not on the joined string) so a token like
# ``@modelcontextprotocol/server-filesystem`` is NOT misidentified as a path,
# and a scoped path like ``/tmp/project`` is correctly left alone.
_BROAD_FS_ROOT_TOKENS = {"/", "C:\\", "C:/", "."}
_BROAD_FS_SYSTEM_DIRS = {"/home", "/Users", "/root", "/etc", "/var"}


def _broad_path_arg_reason(token: str) -> Optional[str]:
    """Return a human-readable reason if ``token`` is a broad filesystem path.

    A token is "broad" when it grants access to a filesystem root
    (e.g. ``/``, ``C:\\``), a system-level directory as a whole
    (e.g. ``/etc``, ``/var``, ``/Users``), or escapes the working directory
    via a relative parent (e.g. ``../etc``). Scoped paths such as
    ``/tmp/project`` or ``/home/user/code`` and non-path tokens such as
    ``@scope/pkg`` are intentionally left alone.
    """
    if not isinstance(token, str):
        return None
    if token in _BROAD_FS_ROOT_TOKENS:
        return f"filesystem root ({token})"
    norm = token.rstrip("/\\")
    if norm in _BROAD_FS_SYSTEM_DIRS:
        return f"system-level directory ({norm})"
    parts = token.replace("\\", "/").split("/")
    if ".." in parts:
        return "parent-directory escape"
    return None

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
    """Parse JSON or YAML into a dict. Returns None if unparseable.

    Note: when a YAML MCP file is encountered but PyYAML is unavailable, this
    function returns None and the caller is expected to surface a warning
    finding (see _YAML_DEP_RULE_ID) so the report honestly indicates the gap
    instead of silently dropping the file.
    """
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


def _is_yaml_mcp_path(path: str) -> bool:
    """True if the file path looks like a YAML MCP config."""
    name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in {"yaml", "yml"} or name in MCP_FILENAMES and name.endswith((".yaml", ".yml"))


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

    # Honest-about-uncertainty: if this is a YAML MCP file but PyYAML is not
    # available, do not silently drop it. Emit an explicit low-severity
    # finding so the user can see which MCP configs were NOT analyzed.
    if _is_yaml_mcp_path(file_path) and not _HAS_YAML:
        return [
            Finding(
                rule_id=_YAML_DEP_RULE_ID,
                severity=Severity.INFO,
                title="YAML MCP config not analyzed: PyYAML not installed",
                description=(
                    "This file looks like a YAML MCP configuration, but the "
                    "PyYAML runtime dependency is not available in this "
                    "environment. The file was NOT parsed and any MCP server "
                    "definitions it contains were NOT checked. Install "
                    "PyYAML (>=6.0) to enable full YAML MCP analysis."
                ),
                file=file_path,
                line=None,
                evidence=file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                remediation=(
                    "pip install PyYAML>=6.0  (or  pip install veyra  to pick "
                    "up the declared runtime dependency)."
                ),
            )
        ]

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

    # --- AS-MCP-003: shell-wrapped local command execution ------------------
    shell_line = _shell_wrapped_command(command, args)
    if shell_line:
        if len(shell_line) > 160:
            shell_line = shell_line[:157] + "..."
        findings.append(
            _mk(
                "AS-MCP-003",
                Severity.MEDIUM,
                "Local command execution via shell",
                f"MCP server '{name}' hands its command line to a shell. The shell runs on the host when the server starts, and what it executes is not visible in the config.",
                file_path,
                f"Shell command line: {shell_line}",
                "Replace the shell wrapper with a direct executable, then review that command and pin it to a known version.",
                text,
                needle,
            )
        )

    # --- AS-MCP-004: Dynamic package execution -----------------------------
    if isinstance(command, str) and DYNAMIC_RUNNERS.match(command.strip()):
        # Severity escalates to HIGH when at least one arg is a bare,
        # unpinned package reference (no @scope/, no version pin). A bare
        # reference is a typosquat / dependency-confusion target: anyone
        # can publish "some-package" to PyPI/npm and the runner will fetch
        # and execute it. Scoped or version-pinned references (e.g.
        # @modelcontextprotocol/server-filesystem@1.0.0) stay MEDIUM because
        # they pin identity to a known publisher.
        bare_pkg_args = [
            str(a) for a in (args or [])
            if isinstance(a, str) and _is_bare_unpinned_package(a)
        ]
        dyn_severity = Severity.HIGH if bare_pkg_args else Severity.MEDIUM
        dyn_evidence = (
            f"Dynamic runner: {command}; bare unpinned package(s): "
            f"{', '.join(bare_pkg_args)}"
            if bare_pkg_args
            else f"Dynamic runner: {command}"
        )
        findings.append(
            _mk(
                "AS-MCP-004",
                dyn_severity,
                "Dynamic package execution",
                f"MCP server '{name}' runs '{command}', which fetches and executes a package from a registry at runtime.",
                file_path,
                dyn_evidence,
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
        # Token-level detection: only count tokens that genuinely look like
        # broad filesystem paths. Ignore flag values (-y, --allow-all) and
        # package-name tokens (@scope/pkg) which used to false-positive
        # against the old joined-string regex.
        broad_reasons: List[str] = []
        for arg in args:
            reason = _broad_path_arg_reason(str(arg))
            if reason is not None:
                broad_reasons.append(reason)
        if broad_reasons:
            # Severity escalates to HIGH when the server also launches a
            # dynamic package runner (npx/uvx/...), because handing root-
            # level filesystem access to a registry-fetched package is the
            # canonical MCP exfiltration setup.
            cmd_str = (command or "").strip() if isinstance(command, str) else ""
            is_dynamic_runner = bool(
                cmd_str and DYNAMIC_RUNNERS.match(cmd_str)
            )
            fs_severity = (
                Severity.HIGH if is_dynamic_runner else Severity.MEDIUM
            )
            findings.append(
                _mk(
                    "AS-MCP-007",
                    fs_severity,
                    "Broad filesystem access",
                    f"MCP server '{name}' is granted broad filesystem/path access via its arguments.",
                    file_path,
                    "Broad path in args: " + "; ".join(broad_reasons),
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
