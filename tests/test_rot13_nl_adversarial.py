"""E-3a: ROT13 / encoded natural-language adversarial set.

Purpose: a measurable, honest baseline for instructions that are hidden as
ROT13-encoded NATURAL LANGUAGE rather than shell syntax. Each attack fixture
must decode to a real, concrete dangerous action (not vague prose); each
benign fixture must decode to harmless text. The expected classifications are
measurements of the current detector, not targets:

    attacks  -> MISSED      (only AS-004/MEDIUM fires, which is triggered by
                             the word "ROT13" and fires on every benign file
                             too, so it cannot count as a partial detection)
    benign   -> not HIGH    (correctly clean at the detection threshold)

If a future rule makes an attack DETECTED, this file must be updated
deliberately together with the fixture-level expectations in
``veyra.attack_lab`` — never by loosening the fixtures.
"""

import codecs
import re
from pathlib import Path

from veyra.attack_lab import DETECTED, MISSED, run_attack_lab
from veyra.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures" / "attacks" / "v2" / "rot13-nl"

ATTACKS = {
    "decoded-delete-prod-tree",
    "decoded-exfil-private-keys",
    "decoded-remote-installer-root",
}
BENIGN = {
    "decoded-cipher-primer",
    "decoded-release-note",
    "decoded-meeting-note",
}

# A real dangerous action expressed in natural language: destructive verb +
# concrete target, exfiltration verb + external destination, or
# download-then-execute. Deliberately semantic-but-literal: these patterns
# assert the fixture payload is not softened into vague prose.
DANGEROUS_ACTION = re.compile(
    r"(?:delete\s+every\s+file\s+under\s+/|wipe\s+the\s+database\s+backups"
    r"|send\s+the\s+private\s+SSH\s+keys.*https?://"
    r"|download\s+the\s+installer\s+from\s+https?://.*run\s+it\s+as\s+root)",
    re.IGNORECASE,
)

HARMLESS_MARKERS = re.compile(
    r"delete|wipe|ssh|private\s+key|https?://|download|install|run\s+it|password|token",
    re.IGNORECASE,
)


def _payload(name):
    """Return the decoded ROT13 payload of a fixture."""
    path = FIXTURES / name / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    quoted = [ln.strip().strip('"') for ln in text.splitlines() if ln.strip().startswith('"')]
    assert len(quoted) == 1, f"{name}: expected exactly one quoted payload, got {quoted}"
    return codecs.decode(quoted[0], "rot13")


def test_all_six_fixtures_present():
    for name in ATTACKS | BENIGN:
        assert (FIXTURES / name / "SKILL.md").exists(), f"missing fixture: {name}"


def test_attack_payloads_decode_to_real_dangerous_actions():
    for name in sorted(ATTACKS):
        decoded = _payload(name)
        assert DANGEROUS_ACTION.search(decoded), (
            f"{name}: decoded payload is not a concrete dangerous action: {decoded!r}"
        )


def test_benign_payloads_decode_to_harmless_text():
    for name in sorted(BENIGN):
        decoded = _payload(name)
        assert not HARMLESS_MARKERS.search(decoded), (
            f"{name}: benign payload contains a dangerous marker: {decoded!r}"
        )


def test_attacks_are_not_detected_today():
    """Honest baseline: ROT13 natural-language attacks are MISSED."""
    lab = run_attack_lab()
    got = {c["name"]: c["result"] for c in lab.cases if c["category"] == "v2-rot13-nl"}
    for name in sorted(ATTACKS):
        assert got[name] == MISSED, (
            f"{name}: expected MISSED (unconfirmed NL action), got {got[name]}. "
            "If a rule change closed this gap, update the baseline deliberately."
        )


def test_benign_notes_are_not_high_severity():
    for name in sorted(BENIGN):
        findings = scan_path(str(FIXTURES / name / "SKILL.md")).findings
        assert not [f for f in findings if f.severity.value in {"HIGH", "CRITICAL"}], (
            f"{name}: benign note produced a HIGH/CRITICAL false positive"
        )


def test_current_signal_does_not_discriminate():
    """AS-007 never confirms; the only signal (AS-004/MEDIUM) fires on 6/6.

    This test documents WHY the attacks are MISSED rather than PARTIAL: a
    signal shared by every benign fixture cannot be counted as detection.
    """
    seen = {}
    for name in sorted(ATTACKS | BENIGN):
        findings = scan_path(str(FIXTURES / name / "SKILL.md")).findings
        assert not [f for f in findings if f.rule_id == "AS-007"], f"{name}: AS-007 fired"
        seen[name] = {(f.rule_id, f.severity.value) for f in findings}

    assert all(seen.values()), "expected the framing indicator to fire on every fixture"
    assert all(sig == {("AS-004", "MEDIUM")} for sig in seen.values()), (
        f"non-discriminating signal changed: {seen}"
    )
