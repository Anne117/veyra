# Veyra Product & Architecture Audit

## 1. Executive summary

Veyra is a **local, static-analysis CLI** that scans AI agent skills and
MCP-related resources for security issues. It is a working MVP, not a SaaS
product. It runs entirely on the user's machine, never executes scanned code,
and never makes network requests during a scan.

**Implemented (verified against the repository):**
- Recursive static scanner over skill-relevant file types (markdown, YAML/JSON/
  TOML, Python/JS/TS, shell, config).
- Primitive rules: secrets (AS-001), shell execution (AS-002), network access
  (AS-003), prompt injection (AS-004), suspicious URLs (AS-005).
- MCP config analysis (AS-MCP-001…010) — parses `.mcp.json`/`mcp_servers.json`
  and structurally identifiable JSON/YAML.
- Sensitive credential file access (AS-006) — `.env`, `~/.aws`, `~/.ssh`,
  credential/private-key files, plus config-file + credential extraction.
- Obfuscation decoding (AS-007) — deterministic base64/ROT13, only flagged with
  execution/fetch context.
- Correlation chains (AS-CHAIN-001/002/003) — cross-signal attack chains.
- Intra-file step-sequence analysis with multi-action line splitting.
- Suppression system (`.veyra.toml`).
- Deterministic risk scoring (severity weights, capped at 100).
- Reporters: terminal, JSON, SARIF 2.1.0 (validated against the schema).
- MITRE ATT&CK metadata (5 approved public mappings).
- GitHub Action with SARIF upload to Code Scanning.
- Attack Lab: a 95-case adversarial corpus with an honest evaluator.

**Partially implemented:**
- Prompt injection detection is regex-based and misses semantic/indirect
  variants (role impersonation, hidden-in-docs).
- Obfuscation decoding covers only base64/ROT13 with execution/fetch context.
- MCP analysis is config-structural only; it does not analyze runtime behavior.

**Planned / not implemented:**
- No web UI, no SaaS, no registry/repository scanning, no runtime analysis, no
  supply-chain provenance, no cross-repository behavior, no semantic/AST/
  data-flow analysis, no arbitrary obfuscation decoding.

## 2. Current architecture

The analysis pipeline (verified in `scanner.py`):

```
input path
  → walk files (skip .git/node_modules/venv, skip >1MB, skip binary)
  → per file: decode UTF-8
      → line rules (AS-001..005, AS-006) on each line
      → file rules (MCP AS-MCP-*, obfuscation AS-007) on full text
  → collect all findings + file texts
  → correlation layer (AS-CHAIN-001/002/003) over all findings
  → step-sequence analysis per file (AS-CHAIN-001/002) with multi-action split
      (dedup against correlation-emitted chains)
  → attach MITRE metadata (mitre_for)
  → ScanResult
  → suppression (apply_suppression) in CLI
  → reporter (terminal / JSON / SARIF)
  → exit code (fail-on threshold)
```

**Ordering and dependencies:**
- Primitive rules → correlation → step-sequence → MITRE → suppression → report.
- Correlation and step-sequence both emit `AS-CHAIN-*`; the scanner dedups
  step-sequence chains already emitted by correlation.
- Suppression runs in the CLI (after scanning), not in the scanner.
- MITRE metadata is attached in the scanner (metadata only, no detection effect).

## 3. Detection coverage

| Capability | Rule/Component | Severity | Mechanism | Limitations | Attack Lab evidence |
|-----------|----------------|----------|-----------|-------------|---------------------|
| Hardcoded secrets | AS-001 | CRITICAL/HIGH | regex (OpenAI/Anthropic/GitHub/AWS/generic/private key/password) | placeholder-aware; not entropy-based | secrets fixtures DETECTED |
| Shell execution | AS-002 | CRITICAL/HIGH/MEDIUM | regex (subprocess shell=True, os.system, eval, curl\|bash) | line-based; no data-flow | shell-execution DETECTED |
| Network activity | AS-003 | HIGH/MEDIUM | regex (HTTP clients, download-and-execute) | HTTP alone not malicious | network DETECTED |
| Prompt injection | AS-004 | HIGH/MEDIUM | regex (ignore/reveal/send/disable/encoded) + negation | misses semantic/indirect variants | prompt-injection DETECTED; role-impersonation MISSED |
| Suspicious URLs | AS-005 | CRITICAL/MEDIUM/LOW | regex (raw IP, shortener, executable, URL→shell) | not C2 attribution | urls DETECTED |
| MCP risks | AS-MCP-001…010 | HIGH/MEDIUM/LOW/INFO | JSON/YAML structural parse | config-only, no runtime | mcp-attacks DETECTED |
| Sensitive credential access | AS-006 | HIGH | regex (sensitive paths + access verb; config + credential extraction) | generic config alone not flagged | sensitive-path DETECTED |
| Obfuscation | AS-007 | CRITICAL/HIGH | base64/ROT13 decode + execution/fetch context | only 2 encodings | encoded-shell/url DETECTED |
| Multi-stage behavior | AS-CHAIN-001/002 + step-sequence | CRITICAL | correlation + intra-file ordered steps | single-file only | multi-stage DETECTED |

## 4. Attack Lab assessment

Verified current numbers: **95 total, 86 detected, 7 partial, 2 missed, 0 FP,
90.5%.**

**What this metric proves:** Veyra detects 86 of 95 hand-crafted synthetic
fixtures at HIGH/CRITICAL severity with zero false positives on the 10 benign
lookalikes. It demonstrates the rules generalize across the fixture variations.

**What it does NOT prove:**
- **Not real-world attack coverage.** The 90.5% is a benchmark on a curated
  corpus, not a measure of real-world detection. Real skills are far more varied.
- **False negatives are understated.** The corpus is finite; many attack
  patterns (semantic prompt injection, arbitrary obfuscation, cross-file
  chains) are not represented.
- **False positives are understated.** The 10 benign lookalikes are narrow;
  real-world benign skills would likely trigger more FPs.
- **The evaluator counts any HIGH/CRITICAL finding as DETECTED**, including
  correlation/chain findings. This is a reasonable benchmark but not a
  precision/recall measurement.

**Distinction:** benchmark detection (90.5% on the corpus) ≠ real-world
security coverage (unknown, likely lower) ≠ false-positive rate (0 on the
corpus, unknown in the wild) ≠ false-negative rate (unknown).

## 5. CLI and developer experience audit

Verified in `cli.py`:
- **Installation:** `pip install -e ".[dev]"`; console script `veyra`.
- **Scan command:** `veyra scan <path>` with `--format terminal|json|sarif`,
  `--config`, `--fail-on`.
- **Output:** readable terminal report; JSON; SARIF.
- **Exit codes:** 0/1/2 based on `--fail-on` threshold.
- **Suppression:** `.veyra.toml` auto-discovered or `--config`.
- **Error handling:** `FileNotFoundError` → stderr + exit 2.

**Concrete usability gaps:**
1. **No `--version` flag** — users cannot check the installed version.
2. **No `--help` on subcommands beyond argparse defaults** — acceptable but minimal.
3. **No `--exclude`/`--include` path filters** — users cannot skip specific dirs
   beyond the hardcoded SKIP_DIRS.
4. **No `--output` file flag** — users must shell-redirect.
5. **No `--quiet`/`--summary-only`** — large scans always print full findings.
6. **No `--severity-filter`** — cannot show only HIGH+ findings.
7. **Path handling** — Windows backslashes are normalized in SARIF but terminal
   output shows raw OS paths (inconsistent across platforms).
8. **No config for default `--fail-on`** — threshold is CLI-only.

## 6. CI/CD integration audit

Verified in `.github/workflows/veyra.yml`:
- **Triggers:** push + pull_request.
- **Threshold:** fails on HIGH/CRITICAL (exit 1/2); configurable via `--fail-on`.
- **Artifacts:** JSON uploaded; SARIF uploaded to Code Scanning.
- **Permissions:** `contents: read`, `security-events: write`.
- **Pinning:** `actions/checkout@v4`, `actions/setup-python@v5`,
  `actions/upload-artifact@v4`, `github/codeql-action/upload-sarif@v3` — all pinned.

**Concrete improvements:**
1. **`pip install veyra` requires PyPI publication** — not yet published;
   the action would fail today. Should install from the repo (`pip install .`).
2. **No `--fail-on` configurability via workflow input** — the threshold is
   hardcoded in the scan step; a `workflow_dispatch` input or `with:` would help.
3. **No `paths`/`paths-ignore` filter** — scans the whole repo on every push.
4. **No caching** of the Python install.
5. **No `concurrency` group** — overlapping runs on rapid pushes.
6. **SARIF upload runs even when the scan fails** — acceptable, but the JSON
   artifact is only uploaded on success (upload-artifact default).

## 7. Finding quality audit

Verified in `models.py` and reporters:
- **rule_id, severity, title, description, file, line, evidence, remediation,
  suppressed, suppression_reason, mitre** — all present.
- **Consistency:** terminal shows `[SUPPRESSED]` + MITRE line; JSON includes
  `mitre` only when mapped; SARIF puts MITRE in rule `properties`.

**What a security engineer would still need:**
1. **Evidence is often generic** ("Access to sensitive credential path") rather
   than the exact matched text — hard to triage quickly.
2. **No CWE mapping** — security engineers expect CWE IDs alongside MITRE.
3. **No confidence score** per finding.
4. **No "how to reproduce"** — the finding doesn't show the exact line content.
5. **Remediation is generic** — not tailored to the specific rule instance.
6. **No finding deduplication** — the same rule can fire multiple times on one
   line (e.g. AS-004 MEDIUM twice on the benign helper).

## 8. Architecture quality

- **Determinism:** high — all rules are regex/structural; no randomness.
- **Explainability:** good — findings carry rule_id, severity, evidence,
  remediation, MITRE.
- **Testability:** excellent — 213 tests, 95-case Attack Lab.
- **Modularity:** good — rules split by concern; reporters separate.
- **Dependency footprint:** minimal — only PyYAML (dev) + stdlib.
- **Performance:** fine for small repos; line-by-line regex over every file is
  O(files × lines × rules); no parallelism.
- **Maintainability:** good — small, readable modules.
- **False-positive control:** strong — negation handling, placeholder lists,
  bounded fillers, context-required obfuscation.

**Technical debt:**
1. **Line-based rules** miss multi-line constructs (documented).
2. **Regex duplication** — negation patterns repeated across rules.
3. **No central rule registry** — rules are registered via decorators but there
   is no single metadata table (severity, MITRE, CWE) per rule.
4. **`file="<correlated>"`** for correlation findings is a placeholder, not a
   real location.
5. **No parallelism** for large scans.
6. **Evidence strings are not consistently the matched text.**

## 9. Security limitations

Veyra currently does **NOT** detect:
- **Semantic prompt injection** — role impersonation, hidden-in-docs, indirect
  wording (regex-only).
- **Advanced data-flow** — no taint tracking, no variable/function analysis.
- **Arbitrary obfuscation** — only base64/ROT13 with execution/fetch context.
- **Dynamic code execution** — no runtime behavior, no sandbox.
- **Malicious MCP server behavior** — config-structural only; no runtime.
- **Supply-chain provenance** — no package reputation, no dependency analysis.
- **Cross-file behavior** — step-sequence is intra-file only.
- **Cross-repository behavior** — no registry/repo scanning.
- **Runtime/network behavior** — static only by design.

## 10. Product maturity

| Component | Maturity |
|-----------|----------|
| Primitive rules (secrets/shell/network/URLs) | MVP |
| Prompt injection | Prototype (regex, misses semantic variants) |
| MCP config analysis | MVP |
| Sensitive credential access (AS-006) | MVP |
| Obfuscation (AS-007) | Prototype (2 encodings) |
| Correlation chains | MVP |
| Step-sequence + multi-action | MVP |
| Suppression | MVP |
| Risk scoring | MVP (heuristic) |
| Reporters (terminal/JSON/SARIF) | MVP |
| MITRE metadata | MVP (5 mappings) |
| GitHub Action | Prototype (requires PyPI publication) |
| Attack Lab | MVP (95 cases) |
| Web UI / SaaS / registry scanning | Not implemented |

## 11. Competitive/product differentiation

Based only on the current implementation:
- **AI Agent Skills focus** — Veyra targets `SKILL.md`/`AGENTS.md`/MCP
  config, a niche most security scanners ignore.
- **MCP security analysis** — structural parsing of MCP server configs
  (remote endpoints, dynamic exec, secrets, broad FS) is distinctive.
- **Attack-chain correlation** — combines primitive signals into higher-level
  chains (exfiltration, download-and-execute, remote MCP exec).
- **Deterministic explainability** — every finding is a static, explainable
  rule; no opaque ML.
- **Attack Lab** — a reproducible adversarial corpus with an honest evaluator
  is a differentiator for measuring and communicating coverage.

## 12. Technical debt / risks

- **Critical:** GitHub Action `pip install veyra` fails (not on PyPI).
- **High:** line-based rules miss multi-line/semantic attacks; no CWE mapping.
- **Medium:** no parallelism; evidence strings not always the matched text;
  correlation `file="<correlated>"` placeholder.
- **Low:** regex duplication; no `--version`/`--exclude`/`--output` CLI flags.

## 13. Next-step candidates

1. **CWE mapping + richer finding metadata** — add CWE IDs, confidence, and
   exact matched-text evidence. Security value: high (triage). Product value:
   high. Complexity: low. FP risk: none. Architectural impact: low (models +
   reporters). Dependencies: none. Priority: high.
2. **Baseline/diff scanning** — compare findings against a stored baseline to
   report only new/changed findings. Security value: high (CI). Product value:
   high. Complexity: medium. FP risk: low. Architectural impact: medium.
   Priority: high.
3. **Broader MCP security** — analyze MCP server manifests, tool schemas, and
   runtime config beyond the current structural parse. Security value: high.
   Product value: high (differentiation). Complexity: medium. FP risk: medium.
   Priority: medium.
4. **Skill/package supply-chain analysis** — flag unpinned/unknown packages in
   skills. Security value: high. Product value: high. Complexity: medium. FP
   risk: medium. Priority: medium.
5. **Improved risk scoring** — per-finding confidence and weighted scoring.
   Security value: medium. Product value: medium. Complexity: low. FP risk:
   none. Priority: medium.
6. **Finding remediation guidance** — richer, rule-specific remediation.
   Security value: medium. Product value: high. Complexity: low. FP risk: none.
   Priority: low.
7. **Registry/repository scanning** — scan a directory of skills or a repo
   tree. Security value: medium. Product value: medium. Complexity: medium.
   FP risk: low. Priority: low.

## 14. ONE recommended next step

**CWE mapping + richer finding metadata** (candidate 1).

Why:
- **Real security value:** security engineers triage by CWE and need exact
  matched text, not generic evidence. This directly improves finding quality.
- **User value:** makes findings actionable and consistent across terminal/JSON/
  SARIF.
- **Differentiation:** CWE + MITRE + confidence + exact evidence is a
  professional-grade finding model.
- **Low/moderate implementation risk:** touches models + reporters only; no
  detection logic change, no FP risk.
- **Compatibility:** fits the current architecture (add fields to `Finding`,
  populate in rules, expose in reporters).
- **Does not inflate Attack Lab score** — it improves real usability, which is
  the stated goal.

## 15. Definition of Done

For CWE mapping + richer finding metadata:
- **Tests:** unit tests asserting each rule carries the correct CWE ID and
  exact matched-text evidence; reporter tests for terminal/JSON/SARIF.
- **Attack Lab impact:** no change to detection metrics (86/7/2/0, 90.5%).
- **Regression:** all 213 existing tests remain green; no rule behavior changes.
- **FP requirements:** no new false positives; benign-lookalikes remain clean.
- **Documentation:** update README and a new `docs/finding-model.md`.
- **CLI/reporting:** terminal shows CWE + exact evidence; JSON includes `cwe`
  and `evidence`; SARIF maps CWE to rule `properties` (valid 2.1.0).
