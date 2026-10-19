"""Shell / command execution detection rules.

Distinguishes simple command execution from clearly dangerous patterns
(e.g. piping remote content into a shell, eval of untrusted input).
"""

from __future__ import annotations

import re

from veyra.models import Finding, Severity
from veyra.rules import register

# --- Comments -------------------------------------------------------------
# A line that *names* a shell pipeline is not that pipeline. In the field
# slice (`agent/ tools/ acp_adapter/ skills/`) 5 of 15 AS-002 hits were comment
# lines: "Recoverable operations (... curl|sh) stay in", "PowerShell's
# `curl | sh`", "``curl | sh`` in READMEs is caution, not a hard block". A
# comment is never executed: nothing is downloaded and nothing reaches a
# shell. Only a *full-line* comment counts -- a trailing `# ...` after code
# stays reportable, because the code before it may be the real pipeline.
_COMMENT_LINE = re.compile(r"^\s*(?:#|//)")


def _is_comment_line(content: str) -> bool:
    return bool(_COMMENT_LINE.match(content))


# --- Signature tables -----------------------------------------------------
# A pattern table *names* a call shape; it does not make the call. In the field
# slice (`agent/ tools/ acp_adapter/ skills/`) 2 of 10 remaining AS-002 hits
# were rows of skills_guard.py's own signature list:
#     (r'os\.system\s*\(', "python_os_system", "high", "execution",
#      "os.system() -- unguarded shell execution"),
# The call text appears twice -- once as a regex literal, once as a label --
# and the match lands inside the label. Shape test: the match lies inside a
# quoted literal, the line is a tuple row (`(` ... `),`) and the row carries at
# least three quoted fields. A real call keeps `os.system(` *outside* the
# quotes, so `("x", os.system(cmd), "y"),` still fires (pinned by a test).
_QUOTED_SPAN = re.compile(r"'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"")


def _is_table_row_mention(content: str, start: int, end: int) -> bool:
    stripped = content.strip()
    if not (stripped.startswith("(") and stripped.endswith("),")):
        return False
    spans = list(_QUOTED_SPAN.finditer(content))
    if len(spans) < 3:
        return False
    return any(s.start() <= start and end <= s.end() for s in spans)


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

# A child_process call, and nothing else. The callee is either qualified
# (the child_process module member), or a bare destructured name glued to its
# paren. A receiver-qualified call is some other object's method (the sandbox
# SDK, a pty process class, Java's Runtime), and prose like "Use spawn
# (default)" or "-exec (runs in each match's directory)" has a space and a
# non-command argument. Both used to be reported at MEDIUM; the argument must
# therefore look like a command: a string/template literal or a plain
# identifier, and the paren list must not end in a definition body (`) {`),
# which is how a same-named method is declared (p5.js `spawn(x, y) {`).
JS_EXEC = re.compile(
    r"(?:\bchild_process\s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(|"
    r"(?<![\w.])(?:exec|execSync|spawn|spawnSync)\()"
    r"(?![^)]*\)\s*(?:=>|\{))"
    r"\s*(?:[rubfRUBF]*[\"'`]|\w+\s*[,)])"
)
JS_SHELL_TRUE = re.compile(r"\b(?:exec|execSync|spawn|spawnSync)\([^)]*shell\s*:\s*true")

# --- Shell: curl|bash, wget|sh, eval --------------------------------------

CURL_PIPE_SHELL = re.compile(r"\bcurl\b[^|;]*\|\s*(?:ba)?sh\b")
WGET_PIPE_SHELL = re.compile(r"\bwget\b[^|;]*\|\s*(?:ba)?sh\b")
# `eval` takes code, so in real shell code the argument starts with a quote,
# a variable/command expansion, or a path. Prose ("eval failed", "post-eval
# page", "eval of a variable") does not, and used to be reported at HIGH.
SHELL_EVAL = re.compile(r"\beval\s+(?:\$|[\"'`]|\(|/|\./|~/)")
SHELL_EXEC = re.compile(r"\b(?:exec|source)\s+[^#\n]+")


@register
def detect_subprocess_shell(content: str, file_path: str, line: int) -> "Finding | None":
    if _is_comment_line(content):
        return None
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
    if _is_comment_line(content):
        return None
    m = OS_SYSTEM.search(content)
    if m and not _is_table_row_mention(content, m.start(), m.end()):
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
    if _is_comment_line(content):
        return None
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
    if _is_comment_line(content):
        return None
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
