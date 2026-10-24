"""Tests for ``veyra demo`` (T14).

The demo is a local, static walkthrough: it scans ``tests/fixtures/demo``
with the ordinary scanner and writes one HTML file. These tests pin down the
four promises that make it trustworthy:

* it touches no network and starts no process (counted, not asserted by
  absence of imports alone),
* the HTML is deterministic, self-contained and carries no absolute path,
* a partial read or an empty fixture is reported as ``UNKNOWN`` -- never as a
  clean result,
* it never overwrites an existing file or writes through a symlink without an
  explicit ``--force``/``--out``, and a failed run prints nothing on stdout.

None of them asserts a finding count: the fixture's classes are measured, so
a rule regression shows up as a smaller report, not as a test bent to match
it. Only the demo's own contract (at least three distinct classes) is checked.
"""

import ast
import io
import json
import os
import re
import socket
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

import veyra.demo as demo_mod
from veyra.cli import main
from veyra.demo import (
    DemoError,
    demo_verdict,
    finding_classes,
    render_demo_report,
    run_demo,
    scan_demo_fixture,
)
from veyra.models import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_SOURCE = Path(demo_mod.__file__).resolve()
MODULE_CHECKOUT = DEMO_SOURCE.parent.parent.parent
# The wheel ships src/veyra only; then the fixture can only come from the
# checkout that runs these tests, named explicitly (see locate_fixture).
INSTALLED_MODE = not (MODULE_CHECKOUT / "tests" / "fixtures" / "demo").is_dir()

# Top-level modules a demo must never need. Transitive scanner imports are
# out of scope: this checks the demo module's own source, so a future edit
# that reaches for the network or a shell is caught here.
FORBIDDEN_IMPORTS = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "requests",
    "httpx",
    "aiohttp",
    "subprocess",
    "multiprocessing",
    "ctypes",
}

# os.* entry points that launch something. The demo legitimately uses
# os.chdir/os.replace/os.chmod/os.fdopen/os.unlink.
FORBIDDEN_OS_CALLS = {
    "system",
    "popen",
    "execv",
    "execve",
    "execl",
    "execlp",
    "execvp",
    "spawnv",
    "spawnl",
    "fork",
    "posix_spawn",
}


def _run(argv, cwd):
    """Run the CLI in-process from ``cwd``; return (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    previous = Path.cwd()
    try:
        os.chdir(cwd)
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        os.chdir(previous)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _name_the_checkout_fixture(monkeypatch):
    """Only an installed package needs the explicit fixture override."""
    if INSTALLED_MODE:
        monkeypatch.setenv(
            demo_mod.DEMO_FIXTURE_ENV,
            str(REPO_ROOT / "tests" / "fixtures" / "demo"),
        )


# --- it runs, and it writes exactly one file -------------------------------


def test_demo_writes_html_and_exits_zero(tmp_path):
    code, out, err = _run(["demo"], tmp_path)

    assert code == 0, err
    assert err == ""
    assert (tmp_path / "veyra-demo.html").is_file()
    assert "HTML written: veyra-demo.html" in out
    assert "Coverage: full" in out


def test_demo_leaves_exactly_one_new_file_in_cwd(tmp_path):
    before = {p.name for p in tmp_path.iterdir()}
    code, _, err = _run(["demo"], tmp_path)
    after = {p.name for p in tmp_path.iterdir()}

    assert code == 0, err
    assert after - before == {"veyra-demo.html"}


def test_demo_out_option_names_the_file(tmp_path):
    code, out, err = _run(["demo", "--out", "custom-report.html"], tmp_path)

    assert code == 0, err
    assert (tmp_path / "custom-report.html").is_file()
    assert "HTML written: custom-report.html" in out


# --- offline and process-free ---------------------------------------------


def test_demo_makes_no_network_calls(tmp_path, monkeypatch):
    calls = []

    def _connect(self, *args, **kwargs):  # pragma: no cover - must not run
        calls.append(("connect", args))
        raise AssertionError("demo must not open a socket")

    def _create_connection(*args, **kwargs):  # pragma: no cover - must not run
        calls.append(("create_connection", args))
        raise AssertionError("demo must not open a connection")

    def _urlopen(*args, **kwargs):  # pragma: no cover - must not run
        calls.append(("urlopen", args))
        raise AssertionError("demo must not fetch a URL")

    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket, "create_connection", _create_connection)
    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)

    code, _, err = _run(["demo"], tmp_path)

    assert code == 0, err
    assert calls == []


def test_demo_starts_no_process(tmp_path, monkeypatch):
    import os
    import subprocess

    def _forbidden(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("demo must not start a process")

    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)

    code, _, err = _run(["demo"], tmp_path)

    assert code == 0, err


def test_demo_module_imports_no_network_or_process_module():
    tree = ast.parse(DEMO_SOURCE.read_text(encoding="utf-8"), str(DEMO_SOURCE))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import inside the package
                continue
            if node.module:
                imported.add(node.module.split(".")[0])

    assert imported & FORBIDDEN_IMPORTS == set()


def test_demo_module_calls_no_process_entry_points():
    tree = ast.parse(DEMO_SOURCE.read_text(encoding="utf-8"), str(DEMO_SOURCE))
    offenders = [
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
        and node.attr in FORBIDDEN_OS_CALLS
    ]
    assert offenders == []


# --- the HTML is deterministic, self-contained, path-free ----------------


def test_two_runs_produce_identical_bytes(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    assert _run(["demo"], first)[0] == 0
    assert _run(["demo"], second)[0] == 0

    a = (first / "veyra-demo.html").read_bytes()
    b = (second / "veyra-demo.html").read_bytes()
    assert a == b
    assert len(a) > 0


def test_html_is_self_contained_and_has_no_absolute_paths(tmp_path):
    code, _, err = _run(["demo"], tmp_path)
    assert code == 0, err

    document = (tmp_path / "veyra-demo.html").read_text(encoding="utf-8")

    assert "<script" not in document.lower()
    assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', document, re.I)
    assert not re.search(r"@import\s+url\(", document, re.I)
    assert "file://" not in document

    # No host context: the module's own root, the run's CWD, and any typical
    # absolute-path prefix are all absent. The report names the fixture with
    # a repo-relative path only.
    assert str(REPO_ROOT) not in document
    assert str(tmp_path) not in document
    assert not re.search(
        r"(?<![\w:/])/(?:home|Users|root|tmp|var|etc|opt|usr)/", document
    )
    assert "Target: tests/fixtures/demo" in document


# --- coverage and verdict -------------------------------------------------


def test_demo_scan_covers_the_whole_fixture():
    result = scan_demo_fixture()

    assert result.coverage_status == "full"
    assert result.files_scanned == 4
    assert result.files_skipped == []
    assert result.rule_errors == []
    assert result.decode_errors == []


def test_demo_fixture_exercises_at_least_three_finding_classes():
    result = scan_demo_fixture()
    classes = finding_classes(result)

    # The contract of the demo (3-4 classes), not a tuned finding count.
    assert len(classes) >= 3
    # Every class is a real active finding produced by the scanner.
    assert all(cls.count >= 1 for cls in classes)
    assert {cls.rule_id for cls in classes} <= {
        f.rule_id for f in result.findings
    }


def test_demo_verdict_is_unknown_on_a_partial_read():
    result = scan_demo_fixture()
    result.files_skipped.append({"path": "tests/fixtures/demo/broken.bin", "reason": "binary"})

    assert result.coverage_status == "partial"
    assert demo_verdict(result) == "UNKNOWN"

    report = render_demo_report(result, "veyra-demo.html")
    assert "Coverage: partial" in report
    assert "Verdict: UNKNOWN" in report
    assert "did not read the whole fixture" in report
    assert "SAFE" not in report
    assert "PASS" not in report


def test_demo_verdict_is_unknown_when_the_fixture_produces_nothing():
    result = ScanResult(target="tests/fixtures/demo", files_scanned=4)

    assert demo_verdict(result) == "UNKNOWN"
    report = render_demo_report(result, "veyra-demo.html")
    assert "Verdict: UNKNOWN" in report
    assert "regression signal" in report


def test_demo_terminal_output_never_claims_safe_or_pass(tmp_path):
    code, out, err = _run(["demo"], tmp_path)

    assert code == 0, err
    assert "SAFE" not in out
    assert "PASS" not in out
    assert "Verdict: " in out
    # A demo is not corpus coverage and says so.
    assert "not a corpus measurement" in out


# --- overwrite and symlink safety ----------------------------------------


def test_demo_refuses_to_overwrite_an_existing_file(tmp_path):
    target = tmp_path / "veyra-demo.html"
    target.write_text("someone else's report\n", encoding="utf-8")

    code, out, err = _run(["demo"], tmp_path)

    assert code == 2
    assert out == ""
    assert "already exists" in err
    assert "--force" in err
    assert target.read_text(encoding="utf-8") == "someone else's report\n"


def test_demo_force_replaces_an_existing_file(tmp_path):
    target = tmp_path / "veyra-demo.html"
    target.write_text("stale\n", encoding="utf-8")

    code, out, err = _run(["demo", "--force"], tmp_path)

    assert code == 0, err
    assert "HTML written" in out
    assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_demo_never_writes_through_a_symlink(tmp_path):
    real = tmp_path / "real-report.html"
    real.write_text("do not touch\n", encoding="utf-8")
    link = tmp_path / "veyra-demo.html"
    link.symlink_to(real)

    code, out, err = _run(["demo", "--force"], tmp_path)

    assert code == 2
    assert out == ""
    assert "symlink" in err
    assert real.read_text(encoding="utf-8") == "do not touch\n"
    assert link.is_symlink()


def test_demo_fails_loudly_without_a_fixture(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(demo_mod.DEMO_FIXTURE_ENV, raising=False)
    monkeypatch.setattr(demo_mod, "_repo_root", lambda: tmp_path)

    with pytest.raises(DemoError) as excinfo:
        run_demo(str(tmp_path / "veyra-demo.html"))

    assert "demo fixture not found" in str(excinfo.value)
    assert not (tmp_path / "veyra-demo.html").exists()


def test_demo_reports_a_missing_fixture_on_stderr_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(demo_mod.DEMO_FIXTURE_ENV, raising=False)
    monkeypatch.setattr(demo_mod, "_repo_root", lambda: tmp_path)

    code, out, err = _run(["demo"], tmp_path)

    assert code == 2
    assert out == ""
    assert "Error: demo fixture not found" in err
    assert not (tmp_path / "veyra-demo.html").exists()


def test_demo_rejects_an_override_that_is_not_the_fixture(tmp_path, monkeypatch):
    monkeypatch.setenv(demo_mod.DEMO_FIXTURE_ENV, str(tmp_path))

    with pytest.raises(DemoError) as excinfo:
        run_demo(str(tmp_path / "veyra-demo.html"))

    assert demo_mod.DEMO_FIXTURE_ENV in str(excinfo.value)
    assert not (tmp_path / "veyra-demo.html").exists()


def test_demo_reports_an_unwritable_destination_on_stderr_only(tmp_path):
    missing = tmp_path / "no-such-dir" / "veyra-demo.html"

    code, out, err = _run(["demo", "--out", str(missing)], tmp_path)

    assert code == 2
    assert out == ""
    assert "does not exist" in err
    assert not missing.exists()


# --- the demo content stays out of the production self-scan --------------


def test_self_scan_of_src_has_no_critical_or_high_findings():
    """The CI gate, run here: demo content must not leak into ``src/``."""
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(
            [
                "scan",
                str(REPO_ROOT / "src"),
                "--config",
                str(REPO_ROOT / ".veyra.toml"),
                "--format",
                "json",
            ]
        )

    report = json.loads(out.getvalue())
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0
    # The policy gate may still fail on self-referential chains; that is not
    # this test's claim.
    assert code in (0, 1)
