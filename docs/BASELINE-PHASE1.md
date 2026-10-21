# Phase 1 baseline (frozen 2026-10-21)

This file records the measured state of Veyra Phase 1 ("Detection Quality &
Explainability") at the point the autonomous engineering loop reached its
planned end. Every number below was produced by a command in this repository,
on this commit, and can be reproduced. It is a baseline, not a claim of
production readiness.

## Identity

- `HEAD`: `7861862` (`fix(network): a branch written twice is still one branch`)
- Branch: `master`, working tree clean
- CI: `test` and `scan` jobs green on this commit
- Test suite: **1793 passed** under both `pytest -q` and `python -m pytest -q`

## Attack Lab corpus

`veyra attack-lab --format json`

| Metric | Value |
|---|---|
| Total cases | 113 |
| Detected | 103 |
| Partially detected | 7 |
| Missed | 3 |
| False positives | 0 |
| Detection rate | 91.2% |

`expected == actual` for **113 of 113** cases: the corpus is a strict invariant,
not a "not worse than" comparison.

Findings across the corpus: 124, by rule —
AS-001 2, AS-002 11, AS-003 6, AS-004 20, AS-005 6, AS-006 17, AS-007 5,
AS-CHAIN-001 5, AS-CHAIN-002 11, AS-CHAIN-003 2, AS-CHAIN-004 8,
AS-MCP-001 4, AS-MCP-002 1, AS-MCP-003 2, AS-MCP-004 9, AS-MCP-005 5,
AS-MCP-006 5, AS-MCP-007 3, AS-MCP-008 2.

`DETECTED` requires a HIGH or CRITICAL finding; a MEDIUM-only result is
PARTIALLY_DETECTED by construction. This is why several cases whose rule
ceiling is MEDIUM stay partial on purpose.

## Attack paths

- Corpus scan: 3 `DATA_EXFILTRATION` paths, all distinct, each with real nodes,
  real edges (`READS → FLOWS_TO → SENDS_TO`) and breakpoints on the path.
- Explainability invariants (E-1/E-2) are enforced by tests: evidence refers to
  nodes/edges that exist on that path, provenance is parallel to nodes/edges,
  breakpoints exist, and explanations use only controlled vocabulary.
- SARIF: 119 results for 116 findings + 3 paths; every result carries a
  location; `properties.result_kind` distinguishes `finding` from
  `attack_path`; a chain finding superseded by a proven path is marked with
  `properties.superseded_by_path` and a SARIF suppression rather than deleted.
  JSON keeps both representations.

## Field measurements

Scanned with `veyra scan <dir> --format json` on the commit above:

| Slice | Findings | AS-003 | AS-006 | chains |
|---|---|---|---|---|
| `agent/` | 43 | 40 | 1 | 0 |
| `tools/` | 48 | 41 | 0 | 1 |
| `skills/` | 27 | 15 | 2 | 2 |
| `hermes_cli/` | 108 | 91 | 5 | 1 |

For comparison, at the start of the Phase 1 precision work the same slices
carried AS-003 749 and AS-006 99. Every reduction was measured before/after and
verified not to remove a real call site; the removed lines were prose,
annotations, imports superseded by a call, request *records* (`urllib Request`),
timeouts, constructions, and local-only `urllib` helpers.

## Known gaps

**7 partially detected.** All are MEDIUM-ceiling rules or NL intent:

- `rot13-exec`, `rot13-instruction` — ROT13 payloads decode to English intent,
  not shell syntax. AS-004 fires MEDIUM. AS-007 now decodes quoted ROT13
  phrases as a whole and would fire CRITICAL for a literal command (see
  `decoded-real-shell-command`, DETECTED), but not for prose.
- `unrelated-exec` — AS-004 MEDIUM; HIGH needs a proven install → run lineage.
- `remote-endpoint` — AS-MCP-001 MEDIUM; remote MCP is a legitimate topology.
- `dynamic-package` — AS-MCP-004 MEDIUM; scoped package from a known namespace.
- `shell-metachar` — AS-MCP-003 MEDIUM; HIGH needs parsing the hidden command.
- `js-child-process-exec` — AS-002 MEDIUM; HIGH needs env → exec data flow.

**3 missed.** `decoded-delete-prod-tree`, `decoded-exfil-private-keys`,
`decoded-remote-installer-root`: ROT13-encoded natural-language instructions.
No rule was shipped. The decision and its revisit conditions (≥15 distinct
phrasings per side, full-sentence decoding shown to raise no findings by
itself, severity justified without broadening `DANGEROUS_COMMAND` to ordinary
English verbs) are recorded in `docs/obfuscation-audit.md` (E-3b).

## Deliberate non-claims

- This is an internal adversarial corpus, not a measure of real-world
  detection accuracy.
- A clean scan does not prove a resource is safe.
- The 91.2% figure is not a target to maximise by relaxing severity: the
  remaining gaps are either MEDIUM ceilings that would over-alert if raised,
  or NL intent that has no deterministic detector.
- No LLM participates in any canonical security decision.
