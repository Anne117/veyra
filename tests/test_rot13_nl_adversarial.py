"""E-3a: ROT13 / encoded natural-language adversarial set.

Purpose: a measurable, honest baseline for instructions that are hidden as
ROT13-encoded NATURAL LANGUAGE rather than shell syntax. Each attack fixture
must decode to a real, concrete dangerous action — a literal shell command or
a specific prose instruction, never vague text; each benign fixture must
decode to harmless text. The expected classifications are
measurements of the current detector, not targets:

    attacks  -> MISSED for prose, DETECTED for shell syntax
                             (after the P-1 precision audit AS-004 no longer
                             raises on a bare mention of "ROT13"; R1 decodes a
                             quoted ROT13 PHRASE and still only raises when the
                             result is a destructive shell command — see
                             docs/obfuscation-audit.md)
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

# Prose instructions in ROT13. The rule deliberately does not judge natural
# language, so these stay MISSED until an NL path is designed and measured.
NL_ATTACKS = {
    "decoded-delete-prod-tree",
    "decoded-exfil-private-keys",
    "decoded-remote-installer-root",
}
# The one attack whose payload is a literal shell command. R1 (a quoted-phrase
# tokenizer in AS-007) reaches the decoder and confirms the command.
COMMAND_ATTACKS = {"decoded-real-shell-command"}
ATTACKS = NL_ATTACKS | COMMAND_ATTACKS
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
    r"|download\s+the\s+installer\s+from\s+https?://.*run\s+it\s+as\s+root"
    # N1: the same family also carries a LITERAL command, not prose. A command
    # that deletes a directory tree with flags is dangerous on its face, so the
    # fixture must spell the flags and the target out.
    r"|\brm\s+-[a-z]*[rf][a-z]*\s+(?:--[a-z-]+\s+)*/\S+)",
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


def test_all_fixtures_present():
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


def test_prose_attacks_are_not_detected_today():
    """Declared gap: ROT13 natural-language instructions are still MISSED."""
    lab = run_attack_lab()
    got = {c["name"]: c["result"] for c in lab.cases if c["category"] == "v2-rot13-nl"}
    for name in sorted(NL_ATTACKS):
        assert got[name] == MISSED, (
            f"{name}: expected MISSED (unconfirmed NL action), got {got[name]}. "
            "If a rule change closed this gap, update the baseline deliberately."
        )


def test_literal_command_attack_is_detected():
    """R1: a quoted ROT13 phrase that decodes to shell syntax is caught."""
    lab = run_attack_lab()
    got = {c["name"]: c["result"] for c in lab.cases if c["category"] == "v2-rot13-nl"}
    for name in sorted(COMMAND_ATTACKS):
        assert got[name] == DETECTED, f"{name}: expected DETECTED after R1, got {got[name]}"
    findings = scan_path(str(FIXTURES / "decoded-real-shell-command" / "SKILL.md")).findings
    assert any(f.rule_id == "AS-007" and f.severity.value == "CRITICAL" for f in findings), (
        "the literal-command fixture must be caught by AS-007 at CRITICAL"
    )


def test_benign_notes_are_not_high_severity():
    for name in sorted(BENIGN):
        findings = scan_path(str(FIXTURES / name / "SKILL.md")).findings
        assert not [f for f in findings if f.severity.value in {"HIGH", "CRITICAL"}], (
            f"{name}: benign note produced a HIGH/CRITICAL false positive"
        )


def test_no_rule_fires_on_the_prose_half():
    """The prose half of the family stays silent — silence is the baseline.

    Before the P-1 precision audit AS-004/MEDIUM fired on 6/6 purely because the
    fixtures mention "ROT13"; that signal was identical on benign and attack
    notes, so it carried no information. The rule now requires a decode-and-act
    directive, which these fixtures do not contain. A rule that starts firing
    here must be justified by confirming the decoded action, not the keyword.
    """
    seen = {}
    for name in sorted(NL_ATTACKS | BENIGN):
        findings = scan_path(str(FIXTURES / name / "SKILL.md")).findings
        seen[name] = {(f.rule_id, f.severity.value) for f in findings}

    assert all(sig == set() for sig in seen.values()), (
        f"a rule started firing on the ROT13 natural-language family: {seen}"
    )
