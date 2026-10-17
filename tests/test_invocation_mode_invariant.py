"""Invariant: `pytest -q` and `python -m pytest -q` must produce the same result
for tests/test_explanation.py::test_graph_visualization_intact.

Background: that test used `from tests.test_html_report import ...`. Under
`python -m pytest` the project root is on sys.path so `tests` resolves; under
bare `pytest -q` (default rootdir + conftest discovery) it did not, and the
test failed with `ModuleNotFoundError: No module named 'tests'` even when
everything else was green. This invariant makes sure a regression of that
shape cannot slip back in.

Scope: the check runs the *fixed* target test twice -- once via
`python -m pytest`, once via the `pytest` console script -- in fresh
subprocesses so sys.path state from one run cannot mask the other.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_TEST = "tests/test_explanation.py::test_graph_visualization_intact"


def _collect(cmd):
    return subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)


def _pytest_bin():
    p = subprocess.run(
        ["bash", "-lc", "command -v pytest || true"],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    return p.stdout.strip() or None


def _collected_ids(out: str):
    return sorted(
        line.strip()
        for line in out.splitlines()
        if line.strip().startswith("tests/test_explanation.py::")
    )


def test_both_invocation_modes_collect_the_same_tests():
    pb = _pytest_bin()
    assert pb, "pytest console script not available on PATH"

    a = _collect([sys.executable, "-m", "pytest", "--collect-only", "-q",
                  "tests/test_explanation.py"])
    b = _collect([pb, "--collect-only", "-q", "tests/test_explanation.py"])

    assert a.returncode == 0, (
        f"python -m pytest --collect-only failed (rc={a.returncode})\n"
        f"stdout:\n{a.stdout}\nstderr:\n{a.stderr}"
    )
    assert b.returncode == 0, (
        f"pytest --collect-only failed (rc={b.returncode})\n"
        f"stdout:\n{b.stdout}\nstderr:\n{b.stderr}"
    )

    a_ids = _collected_ids(a.stdout)
    b_ids = _collected_ids(b.stdout)
    assert a_ids == b_ids, (
        "collection differs between `pytest` and `python -m pytest`\n"
        f"python -m pytest:\n{a_ids}\npytest:\n{b_ids}"
    )
    assert any(t.endswith("test_graph_visualization_intact") for t in a_ids), (
        f"target test not collected: {a_ids}"
    )


def test_target_test_passes_via_python_m_pytest():
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", TARGET_TEST],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=os.environ,
    )
    assert proc.returncode == 0, (
        f"python -m pytest failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


def test_target_test_passes_via_pytest_console_script():
    pb = _pytest_bin()
    assert pb, "pytest console script not available on PATH"
    proc = subprocess.run(
        [pb, "-q", TARGET_TEST],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=os.environ,
    )
    assert proc.returncode == 0, (
        f"pytest console script failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
