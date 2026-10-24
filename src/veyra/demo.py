"""``veyra demo`` -- scan one local fixture and write ``veyra-demo.html``.

Why a fixture on disk and not a string literal built into this module: the
demo must show a *real* scanner run over *real* input bytes. A built-in
string would be a fabricated input -- nothing on disk, nothing the walk
read, no coverage to account for -- and the report would look identical
whether or not the rules still work. The fixture therefore lives at
``tests/fixtures/demo/`` and is resolved from ``__file__`` exactly like the
Attack Lab corpus (``veyra.attack_lab.run_attack_lab``).

It cannot live under ``src/veyra/``: CI runs ``veyra scan src`` with
``.veyra.toml``, which does not suppress AS-005/AS-007, so demo content
there would turn the production self-scan red and raise Code Scanning
alerts. A wheel ships ``src/veyra`` only, so the fixture is resolved from
the checkout this module lives in (editable install), from the checkout the
caller stands in, or from an explicit ``VEYRA_DEMO_FIXTURE`` path -- and
when none of those exists the demo fails with an explicit message instead
of falling back to made-up input.

The scan is static and local: this module imports no network client and no
process launcher, and it never executes the fixture. It also never loads a
``.veyra.toml``: suppression describes a project's own accepted findings,
and this fixture is not a project. Nothing here compares the result against
an expected finding count: if a rule stops firing on the fixture, the demo
reports fewer findings and the terminal output says the verdict is UNKNOWN --
a regression signal, never something to paper over by weakening a rule or
editing the fixture to match the output.

The fixture holds four different classes of issue in four files:
``SKILL.md`` (prompt injection), ``install.sh`` (remote download piped into a
shell), ``run.py`` (a command handed to a shell) and ``.mcp.json`` (an MCP
server with a broad path and a secret-looking env var).

Output safety: an existing file is never overwritten silently and a symlink
is never written through. ``--out`` picks another path, ``--force``
authorises overwriting a regular file. The HTML is written atomically, from
a report that carries only repo-relative paths -- no CWD, no host name, no
absolute path.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from veyra.coverage import COVERAGE_FULL
from veyra.models import ScanResult
from veyra.reporters import render_html
from veyra.scanner import scan_path

# Repo-relative location of the fixture, resolved from this file (same rule
# as the Attack Lab corpus). The string form is what the scanner is handed,
# so every path in the report stays repo-relative.
DEMO_DIR_RELATIVE = Path("tests") / "fixtures" / "demo"
DEMO_TARGET = "tests/fixtures/demo"

# Explicit input for installations that do not ship the fixture: the tests and
# CI name a checkout's fixture directory with this variable. It is not a
# fallback -- an unusable value is an error, never a reason to scan nothing.
DEMO_FIXTURE_ENV = "VEYRA_DEMO_FIXTURE"

DEFAULT_OUTPUT = "veyra-demo.html"

# Severity order for the terminal summary: most dangerous first.
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class DemoError(RuntimeError):
    """A demo precondition failed. The message goes to stderr, exit is 2."""


@dataclass
class FindingClass:
    """One rule that fired on the fixture, with what it said."""

    rule_id: str
    severity: str
    title: str
    count: int


@dataclass
class DemoOutcome:
    """Everything ``veyra demo`` produced, after the HTML is on disk."""

    result: ScanResult
    output: Path
    report: str


def _repo_root() -> Path:
    """``<root>/src/veyra/demo.py`` -> ``<root>``, as in ``attack_lab``."""
    return Path(__file__).resolve().parent.parent.parent


def locate_fixture() -> Path:
    """Checkout that contains ``tests/fixtures/demo``, or an explicit failure.

    Order: an explicit ``VEYRA_DEMO_FIXTURE`` override (the fixture directory
    itself, used by the tests and CI when Veyra is installed as a wheel), the
    checkout this module lives in (editable install, exactly the Attack Lab
    rule), then the checkout the caller stands in.

    There is deliberately no silent alternative. Inventing input would make
    the demo prove nothing about the scanner.
    """
    override = os.environ.get(DEMO_FIXTURE_ENV)
    if override:
        fixture = Path(override).expanduser()
        if not fixture.is_dir() or fixture.parts[-3:] != (
            "tests",
            "fixtures",
            "demo",
        ):
            raise DemoError(
                f"{DEMO_FIXTURE_ENV}='{override}' is not a "
                "'.../tests/fixtures/demo' directory. Point it at the demo "
                "fixture of a source checkout, or unset it."
            )
        return fixture.parent.parent.parent

    cwd = Path.cwd()
    for candidate in [_repo_root(), cwd, *cwd.parents]:
        if (candidate / DEMO_DIR_RELATIVE).is_dir():
            return candidate
    raise DemoError(
        "demo fixture not found (looked next to the installed package and "
        "under the current directory). 'veyra demo' needs a source checkout: "
        "the wheel ships src/veyra, not tests/fixtures/demo. Clone the "
        "repository and run it from there, or set "
        f"{DEMO_FIXTURE_ENV}=<checkout>/tests/fixtures/demo."
    )


def demo_fixture_dir() -> Path:
    """Absolute path of the demo fixture, or an explicit failure."""
    return locate_fixture() / DEMO_DIR_RELATIVE


def scan_demo_fixture() -> ScanResult:
    """Scan the fixture through the ordinary scanner, with relative paths.

    The scan runs with the repository root as CWD so the target string --
    and therefore every finding path, attack-path node label and coverage
    record -- is repo-relative. The previous CWD is restored in ``finally``;
    a demo must not move the caller's working directory.
    """
    fixture = demo_fixture_dir()
    checkout = fixture.parent.parent.parent
    previous = Path.cwd()
    try:
        os.chdir(checkout)
        return scan_path(DEMO_TARGET)
    finally:
        os.chdir(previous)


def _active(result: ScanResult) -> List:
    return [f for f in result.findings if not f.suppressed]


def finding_classes(result: ScanResult) -> List[FindingClass]:
    """Group the active findings by rule id.

    Ordered by severity, then rule id, so two runs print the same text. This
    is a description of what the scan returned -- never a target count.
    """
    grouped: Dict[str, FindingClass] = {}
    for finding in _active(result):
        severity = finding.severity.value
        current = grouped.get(finding.rule_id)
        if current is None:
            grouped[finding.rule_id] = FindingClass(
                rule_id=finding.rule_id,
                severity=severity,
                title=finding.title,
                count=1,
            )
        else:
            current.count += 1
            # Keep the most severe label for the class, regardless of order.
            if _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index(current.severity):
                current.severity = severity

    return sorted(
        grouped.values(),
        key=lambda c: (_SEVERITY_ORDER.index(c.severity), c.rule_id),
    )


def demo_verdict(result: ScanResult) -> str:
    """The one word the demo may print about the fixture.

    ``UNKNOWN`` whenever the scan did not read the whole fixture, or read it
    and found nothing: "not checked" is not "clean", and a fixture that no
    longer fires is a regression to report, not a result to trust. With
    findings present and a full read, the scan's own risk level is printed --
    that word describes the fixture, not the user's project.
    """
    if result.coverage_status != COVERAGE_FULL:
        return "UNKNOWN"
    if not _active(result):
        return "UNKNOWN"
    level = result.risk_level
    return "UNKNOWN" if level == "SAFE" else level


def _coverage_line(result: ScanResult) -> str:
    if result.coverage_status == COVERAGE_FULL:
        return (
            f"Coverage: full ({result.files_scanned} of {result.files_scanned} "
            "files read, nothing skipped)"
        )
    bits = [f"{len(result.files_skipped)} skipped"]
    if result.decode_errors:
        bits.append(f"{len(result.decode_errors)} lossy")
    if result.rule_errors:
        bits.append(f"{len(result.rule_errors)} rule errors")
    if not result.files_scanned:
        bits.append("nothing was read")
    return f"Coverage: {result.coverage_status} ({', '.join(bits)})"


def render_demo_report(result: ScanResult, output_label: str) -> str:
    """The short terminal report. Pure formatting over an existing result.

    It never prints a "clean" verdict the scan did not earn: a partial read
    or an empty fixture is printed as ``UNKNOWN`` with the reason.
    """
    classes = finding_classes(result)
    lines = [
        "Veyra demo",
        "=" * 10,
        f"Fixture:  {result.target} (local static text, never executed)",
        _coverage_line(result),
        "",
    ]

    if classes:
        lines.append(
            f"Findings: {len(_active(result))} active, {len(classes)} rules fired"
        )
        width = max(len(c.rule_id) for c in classes)
        for cls in classes:
            lines.append(
                f"  {cls.severity:<8} {cls.rule_id:<{width}}  "
                f"x{cls.count}  {cls.title}"
            )
        per_severity = result.summary()
        lines.append(
            "  by severity: "
            + " ".join(
                f"{name}={per_severity[name.lower()]}"
                for name in _SEVERITY_ORDER
                if per_severity.get(name.lower())
            )
        )
    else:
        lines.append("Findings: none")

    lines.append("")
    lines.append(f"Score: {result.score} / 100")
    lines.append(f"Verdict: {demo_verdict(result)}")
    if result.coverage_status != COVERAGE_FULL:
        lines.append(
            "  why: the scan did not read the whole fixture, so this run "
            "answers nothing about the parts it skipped."
        )
    elif not classes:
        lines.append(
            "  why: the fixture produced no findings. That is a regression "
            "signal about the rules, not a clean bill of health."
        )
    lines.append(f"Policy violations: {result.policy_violation_count}")
    lines.append("")
    lines.append(f"HTML written: {output_label}")
    lines.append(
        "This is a fixture walkthrough, not a corpus measurement "
        "(attack-lab is the 113-case corpus) and not a verdict on your code."
    )
    return "\n".join(lines) + "\n"


def _resolve_output(out_path: str) -> Path:
    """Absolute output path, resolved before the scan changes CWD."""
    candidate = Path(out_path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate


def _check_writable(out: Path, force: bool) -> None:
    """Refuse to clobber: a symlink always, a regular file unless forced."""
    if out.is_symlink():
        raise DemoError(
            f"refusing to write through the symlink '{out}': a symlink would "
            "send the report to a file somewhere else. Pass a different "
            "--out path."
        )
    if out.exists():
        if out.is_dir():
            raise DemoError(
                f"'{out}' is a directory, not a file. Pass a different --out path."
            )
        if not force:
            raise DemoError(
                f"'{out}' already exists. Refusing to overwrite it: pass "
                "--force to replace this file, or --out to write elsewhere."
            )
    parent = out.parent
    if not parent.is_dir():
        raise DemoError(f"output directory '{parent}' does not exist.")


def _write_atomic(out: Path, document: str) -> None:
    """Write the document next to its destination, then rename into place.

    A reader never sees a half-written report, and a failure leaves the
    previous file untouched.
    """
    data = document.encode("utf-8")
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=".veyra-demo-", suffix=".html", dir=str(out.parent)
        )
    except OSError as e:
        raise DemoError(f"cannot write '{out}': {e.strerror or e}") from e
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        # mkstemp creates 0600; a report is ordinary output, so give it the
        # mode a plain open() would have produced under the caller's umask.
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, out)
    except OSError as e:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise DemoError(f"cannot write '{out}': {e.strerror or e}") from e


def run_demo(out_path: str = DEFAULT_OUTPUT, force: bool = False) -> DemoOutcome:
    """Scan the fixture, then write the HTML.

    The HTML is rendered and written *before* anything is returned, so the
    CLI can print a report only for a run that actually produced its file.
    """
    output = _resolve_output(out_path)
    _check_writable(output, force)
    result = scan_demo_fixture()
    document = render_html(result)
    _write_atomic(output, document)
    return DemoOutcome(
        result=result,
        output=output,
        report=render_demo_report(result, out_path),
    )
