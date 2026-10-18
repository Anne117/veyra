"""CLI tests for the read-only ``veyra threats`` subcommand.

Covers WU-4 (Trustworthy CI Gate): first read-only CLI access to the
``veyra.threats`` layer — list built-in threat-taxonomy catalogs and show a
single entry by id. No execution, no observations, no inference: the command
only walks static, immutable ThreatTaxonomy objects.

The tests run ``veyra.cli.main`` directly (no subprocess) for speed; a single
subprocess test pins the real entry-point contract against the installed
console script, just like other CLI test suites in this repo.
"""

import io
import json
import subprocess
import sys
from contextlib import redirect_stdout, redirect_stderr

from veyra.cli import main


def _run_capture(args):
    """Run ``main(args)`` and return (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = None
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(args)
    return rc, out.getvalue(), err.getvalue()


# ---------- list ----------


def test_threats_list_terminal_includes_owasp_catalog():
    rc, out, err = _run_capture(["threats", "list"])
    assert rc == 0, f"unexpected exit: {err}"
    assert "owasp-agentic-2026" in out
    # All 10 OWASP entries must be listed (id + name).
    for entry_id, name in [
        ("ASI01", "Agent Goal Hijack"),
        ("ASI05", "Unexpected Code Execution (RCE)"),
        ("ASI10", "Rogue Agents"),
    ]:
        assert entry_id in out, f"missing entry id {entry_id}"
        assert name in out, f"missing entry name {name}"


def test_threats_list_json_is_deterministic():
    rc, out, err = _run_capture(["threats", "list", "--format", "json"])
    assert rc == 0, f"unexpected exit: {err}"
    payload = json.loads(out)
    assert isinstance(payload, list)
    assert len(payload) >= 1
    taxonomy = payload[0]
    assert taxonomy["taxonomy_id"] == "owasp-agentic-2026"
    assert taxonomy["version"] == "2026"
    assert len(taxonomy["entries"]) == 10
    ids = [e["entry_id"] for e in taxonomy["entries"]]
    assert ids == [f"ASI{i:02d}" for i in range(1, 11)]
    # Determinism: same input -> same output bytes.
    rc2, out2, _ = _run_capture(["threats", "list", "--format", "json"])
    assert rc2 == 0
    assert out == out2


# ---------- show ----------


def test_threats_show_known_entry_terminal():
    rc, out, err = _run_capture(["threats", "show", "ASI05"])
    assert rc == 0, f"unexpected exit: {err}"
    assert "ASI05" in out
    assert "Unexpected Code Execution (RCE)" in out
    # Must include the source reference (provenance is part of the contract).
    assert "genai.owasp.org" in out


def test_threats_show_known_entry_json():
    rc, out, err = _run_capture(["threats", "show", "ASI05", "--format", "json"])
    assert rc == 0, f"unexpected exit: {err}"
    payload = json.loads(out)
    assert payload["entry"]["entry_id"] == "ASI05"
    assert payload["entry"]["name"] == "Unexpected Code Execution (RCE)"
    assert payload["taxonomy"]["taxonomy_id"] == "owasp-agentic-2026"
    # Source is included so the user can verify the entry against upstream.
    assert "reference" in payload["entry"]["source"]


def test_threats_show_unknown_entry_returns_2_and_does_not_silently_match():
    rc, out, err = _run_capture(["threats", "show", "ASI99"])
    assert rc == 2, f"unknown id must exit 2, got {rc}"
    assert "ASI99" in err
    # Negative case: prefix matches (e.g. "ASI") must NOT resolve.
    rc2, out2, err2 = _run_capture(["threats", "show", "ASI"])
    assert rc2 == 2
    assert "ASI" in err2


def test_threats_show_is_case_sensitive():
    rc, out, err = _run_capture(["threats", "show", "asi05"])
    assert rc == 2, "lowercase 'asi05' must NOT match canonical 'ASI05'"


# ---------- read-only contract ----------


def _threats_dispatch_block():
    """Extract the ``if args.command == "threats":`` dispatch from cli.py.

    Scopes the read-only contract check to the threats subcommand only; other
    subcommands (``scan``, ``attack-lab``) legitimately use other modules.
    """
    from pathlib import Path
    text = Path(__file__).parent.parent / "src" / "veyra" / "cli.py"
    text = text.read_text(encoding="utf-8")
    start = text.find('if args.command == "threats":')
    assert start != -1, "threats dispatch block not found in veyra/cli.py"
    # Grab up to the next ``if args.command ==`` block (or end of file).
    nxt = text.find('if args.command ==', start + 1)
    end = nxt if nxt != -1 else len(text)
    return text[start:end]


def test_threats_cli_dispatch_does_not_call_execution_modules():
    """The ``veyra threats`` dispatch must not call execution modules.

    WU-4 contract: the CLI exposes a read-only view over threat-taxonomy
    catalogs. The dispatch of the ``threats`` subcommand must not invoke
    :class:`BenchmarkRunner`, :class:`BenchmarkEvaluator`,
    :class:`BenchmarkExecutionEvaluator`, observation/adapter runtime paths,
    or any observation/adapter code that produces or modifies observations.

    Note: ``veyra.threats.__init__`` re-exports the whole package (execution
    modules included), so a module-level ``import veyra.cli`` loads them
    transitively. What matters for WU-4 is that the *dispatch* of the
    ``threats`` subcommand never reaches them.
    """
    block = _threats_dispatch_block()
    forbidden_symbols = [
        "BenchmarkRunner",
        "BenchmarkEvaluator",
        "BenchmarkExecutionEvaluator",
        "ObservationBenchmarkRunner",
        "SecurityAssertion",
        "BenchmarkObservation",
        "BenchmarkExecutionObservation",
        "BenchmarkExecutionBinding",
    ]
    for sym in forbidden_symbols:
        assert sym not in block, (
            f"threats dispatch references {sym!r}; the threats subcommand "
            f"must remain read-only"
        )


def test_threats_catalog_helper_returns_only_taxonomy_objects():
    """The catalog helper exposes only :class:`ThreatTaxonomy` objects.

    Prevents accidental promotion of evaluation/runner types into the
    read-only CLI surface.
    """
    from veyra.cli import _threat_catalogs
    from veyra.threats import ThreatTaxonomy

    catalogs = _threat_catalogs()
    assert len(catalogs) >= 1
    for c in catalogs:
        assert isinstance(c, ThreatTaxonomy)
        # Each catalog must have stable, non-empty identifiers.
        assert c.taxonomy_id
        assert c.version
        assert c.reference


# ---------- console-script entry point (subprocess) ----------


def test_threats_list_via_console_script():
    """Pin the real installed console-script contract.

    Runs the same command users would run, against the same entry point,
    so a packaging change cannot silently break the public surface.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "veyra.cli", "threats", "list", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert payload[0]["taxonomy_id"] == "owasp-agentic-2026"


def test_threats_show_via_console_script_unknown_entry():
    proc = subprocess.run(
        [sys.executable, "-m", "veyra.cli", "threats", "show", "NOPE"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "NOPE" in proc.stderr
