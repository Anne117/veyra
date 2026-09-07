"""Shell / command execution detection rules.

Distinguishes simple command execution from clearly dangerous patterns
(e.g. piping remote content into a shell, eval of untrusted input).
"""

from __future__ import annotations

import re

from agentshield.models import Finding, Severity
from agentshield.rules import register

# --- Python: dangerous execution ------------------------------------------

# subprocess with shell=True
SUBPROCESS_SHELL = re.compile(r"subprocess\.(?:run|call|Popen|check_call|check_output)\([^)]*shell\s*=\s*True")

# os.system / os.popen
OS_SYSTEM = re.compile(r"\bos\.(?:system|popen)\s*\(")

# eval/exec of a variable (potentially untrusted)
EVAL_EXEC = re.compile(r"\b(?:eval|exec)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)")

# commands built from variables (user-controlled input)
COMMAND_FROM_VAR = re.compile(r"(?:subprocess|os\.system|os\.popen)\([^)]*\+[^)]*\)")

# --- JavaScript: child_process --------------------------------------------

JS_EXEC = re.compile(r"\b(?:exec|execSync|spawn|spawnSync)\s*\(")
JS_SHELL_TRUE = re.compile(r"\b(?:exec|execSync|spawn|spawnSync)\([^)]*shell\s*:\s*true")

# --- Shell: curl|bash, wget|sh, eval --------------------------------------

CURL_PIPE_SHELL = re.compile(r"\bcurl\b[^|;]*\|\s*(?:ba)?sh\b")
WGET_PIPE_SHELL = re.compile(r"\bwget\b[^|;]*\|\s*(?:ba)?sh\b")
SHELL_EVAL = re.compile(r"\beval\s+[^#\n]+")
SHELL_EXEC = re.compile(r"\b(?:exec|source)\s+[^#\n]+")


@register
def detect_subprocess_shell(content: str, file_path: str, line: int) -> "Finding | None":
    if SUBPROCESS_SHELL.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.HIGH,
            title="Remote command execution",
            description="subprocess invoked with shell=True, which can execute arbitrary shell commands.",
            file=file_path,
            line=line,
            evidence="subprocess call with shell=True",
            remediation="Avoid shell=True; pass arguments as a list to prevent shell injection.",
        )
    return None


@register
def detect_os_system(content: str, file_path: str, line: int) -> "Finding | None":
    if OS_SYSTEM.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.HIGH,
            title="Command execution",
            description="os.system/os.popen executes a shell command; dangerous if input is untrusted.",
            file=file_path,
            line=line,
            evidence="os.system/os.popen call",
            remediation="Use subprocess with a list of arguments and no shell.",
        )
    return None


@register
def detect_eval_exec(content: str, file_path: str, line: int) -> "Finding | None":
    if EVAL_EXEC.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.HIGH,
            title="Dynamic code execution",
            description="eval/exec of a variable can execute untrusted code.",
            file=file_path,
            line=line,
            evidence="eval/exec of a variable",
            remediation="Avoid eval/exec; use safe parsing or allowlists.",
        )
    return None


@register
def detect_command_from_var(content: str, file_path: str, line: int) -> "Finding | None":
    if COMMAND_FROM_VAR.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.MEDIUM,
            title="Command constructed from variables",
            description="Command string is built by concatenation, which may include user-controlled input.",
            file=file_path,
            line=line,
            evidence="Command built with string concatenation",
            remediation="Pass arguments as a list and validate inputs.",
        )
    return None


@register
def detect_js_exec(content: str, file_path: str, line: int) -> "Finding | None":
    if JS_SHELL_TRUE.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.HIGH,
            title="Command execution with shell",
            description="child_process exec/spawn with shell:true executes shell commands.",
            file=file_path,
            line=line,
            evidence="child_process call with shell:true",
            remediation="Avoid shell:true; pass arguments as an array.",
        )
    if JS_EXEC.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.MEDIUM,
            title="Command execution",
            description="child_process exec/spawn executes a system command.",
            file=file_path,
            line=line,
            evidence="child_process exec/spawn call",
            remediation="Validate inputs and avoid shell interpretation.",
        )
    return None


@register
def detect_curl_pipe_shell(content: str, file_path: str, line: int) -> "Finding | None":
    if CURL_PIPE_SHELL.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.CRITICAL,
            title="Remote command execution",
            description="Remote content is downloaded and piped directly into a shell.",
            file=file_path,
            line=line,
            evidence="curl | bash pattern",
            remediation="Do not pipe remote content into a shell; review and pin the script.",
        )
    return None


@register
def detect_wget_pipe_shell(content: str, file_path: str, line: int) -> "Finding | None":
    if WGET_PIPE_SHELL.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.CRITICAL,
            title="Remote command execution",
            description="Remote content is downloaded and piped directly into a shell.",
            file=file_path,
            line=line,
            evidence="wget | sh pattern",
            remediation="Do not pipe remote content into a shell; review and pin the script.",
        )
    return None


@register
def detect_shell_eval(content: str, file_path: str, line: int) -> "Finding | None":
    if SHELL_EVAL.search(content):
        return Finding(
            rule_id="AS-002",
            severity=Severity.HIGH,
            title="Shell eval",
            description="eval executes a string as shell code; dangerous if the string is untrusted.",
            file=file_path,
            line=line,
            evidence="eval statement",
            remediation="Avoid eval; use explicit, validated commands.",
        )
    return None
