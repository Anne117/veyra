# End-to-end traceability: file → finding → graph → path → policy → report

Audit of the claim chain for one attack fixture and one clean fixture. Docs only:
no code, rules, tests or fixtures were changed to produce this file.

Measured on HEAD `6917457` with

```
.venv/bin/veyra scan tests/fixtures/attacks/multi-stage/exfiltration-flow --format json    # exit 2
.venv/bin/veyra scan tests/fixtures/attacks/multi-stage/exfiltration-flow --format sarif   # exit 2
.venv/bin/veyra scan tests/fixtures/attacks/multi-stage/exfiltration-flow --format html    # exit 2
.venv/bin/veyra scan tests/fixtures/clean --format json|sarif|html                          # exit 0
```

Fixtures: `tests/fixtures/attacks/multi-stage/exfiltration-flow/SKILL.md` (13 lines,
steps at 7 / 10 / 13) and `tests/fixtures/clean/SKILL.md` (14 lines, no actions).

## 1. Where every reported value comes from

| Layer | Field (measured) | Produced by | Confirmed by |
|---|---|---|---|
| line | `7` = "Read the local data." | `step_sequence._classify_line` → `SOURCE`, `_extract_action` | the source line itself |
| `Finding` | `rule_id=AS-CHAIN-004`, `severity=CRITICAL` | `_detect_source_sink` (`step_sequence.py:444`), severity is a literal in the rule | code, not evidence |
| `Finding` | `line=7` (first proving line) | same call returns `(finding, first, last)` | `first = 7` from the actions |
| `Finding` | `evidence="Source-to-sink: report -> external destination"` | f-string over the sink action's object | the NETWORK action at line 13 |
| `Finding` | `file=<the SKILL.md path>` | created as `<step-sequence>`, rewritten at `step_sequence.py:555` | the file that produced the chain |
| `Finding` | `matched_text` = the evidence string | `scanner.py:179-180` (fill when empty) | nothing — see §3.2 |
| `Finding` | `confidence=HIGH` | `_confidence_for`: `AS-CHAIN*` → HIGH | rule family, not the match |
| graph | `SKILL:<file> --READS--> DATA:data` | `build_from_actions` (`SOURCE`) | the action at line 7 |
| graph | `DATA:data --FLOWS_TO--> DATA:report`, `SKILL --PRODUCES--> DATA:report` | `build_from_actions` (`TRANSFORM`), input/output extracted from line 10 | line 10 |
| graph | `DATA:report --SENDS_TO--> ENDPOINT:https://report.example.com/upload` | `build_from_actions` (`NETWORK`) | line 13 |
| graph | `provenance.nodes[*].components = [<file>]`, same for all 3 edges | builder attribution | the file that contributed the element |
| `AttackPath` | `nodes` (4), `edges` (3), contiguous walk | `PathAnalyzer._make_path` | the graph above |
| `AttackPath` | `path_id=fa9381827460…22b7aa` | `path_id_of` = sha256 of `canonical_path_identity(nodes, edges, assoc)` | recomputable from nodes+edges |
| `AttackPath` | `severity=MEDIUM`, `confidence=MEDIUM` | `_path_signals` **defaults** (action edges carry no `severity` attribute) | nothing — see §3.1 |
| `AttackPath` | `attack_type=DATA_EXFILTRATION`, `entry_node`, `asset_node=DATA:data`, `sink_node=ENDPOINT:…` | `classify_path` (requires READS → FLOWS_TO* → SENDS_TO) | the contiguous walk |
| `AttackPath` | `risk_severity=HIGH`, `risk_confidence=HIGH`, `risk_score=70` | `assess_risk` / `_risk_for`: 70 points × 1.0 | attack type + proven lineage |
| `AttackPath` | `evidence=[sensitive data read, data transformation, sensitive data flow, external network send]` | `_evidence_for`, one item per semantic signal | the same walk |
| `AttackPath` | `breakpoints` (3) = the 3 real edges | `PathAnalyzer`, impact from `BreakpointImpact` | edges exist in the walk |
| `AttackPath` | `explanation_details` (summary/steps/impact/breakpoints) | `build_explanation` over the finalized path | the fields above |
| `PolicyResult` | `DATA-EXFILTRATION-001 / fa93… / violated=true` | `PolicyEngine.evaluate`: `attack_type == DATA_EXFILTRATION` | the path's attack type |
| `PolicyResult` | `CORRELATED-… / fa93… / violated=false`, `SECRET-… / fa93… / violated=false` | same call, deterministic negative results | `_POLICY_TRIGGER` |
| `ScanResult` | `score=40` | `sum(SEVERITY_WEIGHTS[f.severity])` over unsuppressed findings: one CRITICAL = 40 | the finding list |
| `ScanResult` | `risk_level=MEDIUM` | `risk_level_for_score(40)` → 25 ≤ 40 < 50 | the score, nothing else |
| `ScanResult` | `summary.critical=1` | counting unsuppressed findings by severity | the finding list |
| `ScanResult` | `policy_status=FAIL` | `has_policy_violations` over `policy_results` | the violated result |
| JSON | all of the above; `findings[0].suppressed=false`; `policy_results` (3); `policy_status` | `ScanResult.to_dict` + `Finding.to_dict` | the objects above |
| SARIF | finding: `ruleId=AS-CHAIN-004`, `level=error`, `startLine=7`, `suppressions[inSource] "Superseded by proven attack path fa93… (DATA_EXFILTRATION, risk HIGH)"` | `reporters/sarif.py` (reporter-level annotation) | see §3.7 |
| SARIF | path: `level=error`, `properties.risk_*`, `provenance`, `explanation`, `location_provenance=entry_node_skill_file`, artifact = the SKILL.md, **no line** | `sarif.py` + `ScanResult.attack_path_entry_files` | entry node label |
| HTML | badge "Security status **MEDIUM**", Score 40, Highest attack risk 70, path badge HIGH, finding badge CRITICAL, Policies table: one row "Violated" | `_summary_html` (`risk_level`), `_highest_attack_risk`, per-entity badges | the fields above |
| exit code | `2` | CLI policy gate over `policy_status` | the FAIL result |

Clean fixture, same pass: `findings=[]`, `attack_paths` absent, `score=0`,
`risk_level=SAFE`, `policy_results=[]`, `policy_status=PASS`, SARIF `results: []`,
HTML badge `SAFE` and the Policies section prints "No policy evaluation results."

## 2. What the chain gets right

- Every graph element on the path is a real element of the merged graph built from
  parsed source; no edge on the walk is invented, and `provenance.components`
  points at the file that contributed each node and edge.
- `path_id` is a pure function of `nodes + edges + sorted associated_edges`, so it
  is recomputable by a third party from the reported walk.
- `attack_type` is assigned only from the edge sequence (READS → FLOWS_TO* →
  SENDS_TO); the policy layer reacts to that semantic and nothing else.
- A breakpoint is always an edge that exists on the walk.
- The clean fixture produces no findings, no paths, no policy results, and no
  SARIF results — nothing is emitted that the graph does not hold.

## 3. Statements without provenance

These are the places where a reported value cannot be checked against an artifact
of the scan. Each was observed in the outputs above.

1. **One incident, three severities.** `Finding.severity = CRITICAL` (literal in
   the rule), `AttackPath.severity = MEDIUM` (`_path_signals` default, because the
   action graph attaches no `severity` attribute to its edges),
   `AttackPath.risk_severity = HIGH` (semantic model). No field reconciles them and
   nothing states which one is authoritative. A consumer sorting by `severity` gets
   MEDIUM for the CRITICAL finding's own path.
2. **`matched_text` is not matched text.** For AS-CHAIN-004 it equals `evidence`
   (`scanner.py:179-180`): a synthesized sentence, while line 7 of the file reads
   "Read the local data.". The field name promises a source fragment; for chain
   findings it is a summary, and it cannot be located in the file.
3. **`line` under-covers the claim.** The chain spans lines 7–13.
   `analyze_file_chains` computes `last = 13` and the scanner keeps only the first
   line, so JSON reports `line: 7` and SARIF `startLine: 7` with no `endLine`. The
   region points at the read, not at the transmission that makes the claim true.
4. **`risk_level` is a score bucket, not a statement about the worst finding.**
   `summary.critical = 1` together with `risk_level = MEDIUM` follows only from
   `CRITICAL = 40` and the 25–49 band; the word MEDIUM is printed in HTML as
   "Security status". The score also saturates at `MAX_SCORE = 100`, so a fourth
   CRITICAL adds nothing observable.
5. **`SAFE` has no coverage evidence.** `ScanResult` carries no `files_scanned`,
   `files_skipped` or `rule_errors`, so `SAFE` means "score 0". The same badge is
   produced for a tree in which every file was skipped (binary, too large,
   unreadable, decode error) — the report cannot distinguish "clean" from "not
   looked at".
6. **`policy_status: PASS` is vacuous when nothing was evaluated.** With
   `policy_results: []` the clean scan still prints `PASS`, because PASS is
   `not has_policy_violations` over an empty list. HTML does not render
   `policy_status` at all, so the strongest-sounding word in the JSON has no
   in-page counterpart.
7. **JSON and SARIF disagree about suppression of the same finding.** SARIF
   attaches `suppressions[inSource]` with the justification "Superseded by proven
   attack path …", while `Finding.suppressed` stays `false` and the finding still
   contributes 40 to `score` and 1 to `summary.critical`. Either the incident is
   suppressed (SARIF) or it is counted (JSON); both are printed for one scan.
8. **The path has no line-level location.** `provenance.components` names a file,
   `entry_node` names a graph node, but no node or edge in the graph retains a
   source line. "`DATA:data` was read at line 7" is therefore inferable from the
   finding, never checkable from the path.
9. **Node identity is a bare object string.** `DATA:data` and `DATA:report` are
   names taken from the text, not resolved locations; per-component analysis and
   the explicit-`PRODUCES` rule for composition keep cross-file walks out, but the
   name itself proves nothing about which file's object it is.
10. **HTML shows four labels for one incident with no cross-reference.**
    "Security status MEDIUM", "Highest attack risk 70", path badge HIGH, finding
    badge CRITICAL. Nothing on the page says these describe the same artifact, or
    why they differ.
11. **Breakpoint reasons are fixed vocabulary, not remediation evidence.**
    "Breaks the proven data lineage." is a constant per `BreakpointImpact`; the
    edge is real, the consequence of removing it is not measured.

## 4. Scope and limits

- Static, offline, deterministic; no scanned code was executed and no LLM is
  involved in any step above.
- Only one attack fixture and one clean fixture were traced. Other rule families
  (`AS-001` secrets, MCP file rules, correlation chains) use the same scanner
  plumbing but were not part of this pass.
- This file changes no behaviour. Items 1–11 are inputs for T2–T7: coverage
  accounting (item 5), `SAFE`/`PASS` semantics (items 4–6), severity provenance
  (item 1), location completeness (items 3, 8), reporter agreement (item 7).

## 5. Same pass on the project's own tree (the CI self-scan)

`.venv/bin/veyra scan src --config .veyra.toml` (json and sarif, exit `1` on both):

- `score=0`, `risk_level=SAFE`, 38 findings all suppressed, **and** 12 attack paths,
  36 policy results of which 12 are violated → `policy_status=FAIL`. The same report
  says "SAFE" and "FAIL" about the same tree; neither field references the other
  (items 4–6 above, in production).
- All 12 paths are `CORRELATED_SECRET_EXECUTION`. Five of them walk
  `SKILL:<file> --EXECUTES--> ACTION:` — an ACTION node whose label is the empty
  string (`50e307d841f1`, `83a2cad6f11e`, `1803333e6f83`, `cad80f9a4513`,
  `e82930fba1d5`). The node exists in the graph, so the walk is real, but the
  execution it claims has no name to check.
- In the same five, the associated read is
  `SKILL --READS--> SECRET:extract a concrete sensitive-path secret identity or none`
  — a sentence from a docstring parsed as a SECRET object name. The correlation, the
  MEDIUM risk (`risk_score=38`) and the policy violation stand on a prose fragment
  plus a nameless action.
- These are real nodes and real edges; the defect is that their labels carry no
  evidence. Input for T6 (provenance invariant on every path), not fixed here.
