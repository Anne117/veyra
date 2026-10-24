# 🛡️ Veyra

> Understand the attack path, not just the alert.

**Veyra** is a deterministic, static security analysis tool for AI-agent
components — Skills, tools, MCP servers, data, secrets, endpoints, and the
actions that connect them.

Its mission is to show **how** risky components combine into an attack path
through an agentic system, not just that a single component "looks risky".
Veyra builds a security graph, finds truthful contiguous attack paths, assigns
deterministic risk and evidence, and gates on policy violations.

> **Status: early MVP.** Veyra is a deterministic static scanner, not a complete
> malware detector and not a security standard. It does **not** detect all
> malicious skills and can produce false positives. Treat its output as a
> starting point for human review, not as a definitive verdict.

[![CI](https://github.com/Anne117/veyra/actions/workflows/veyra.yml/badge.svg?branch=master)](https://github.com/Anne117/veyra/actions/workflows/veyra.yml)

## 🎯 Why Veyra?

AI agents increasingly load third-party skills and configuration that instruct
them to take actions. A malicious or compromised skill can:

- Embed **hardcoded secrets** that get committed to source control.
- Instruct the agent to **execute arbitrary commands** (`curl | bash`).
- Make **unexpected network requests** or **exfiltrate local files**.
- Use **prompt injection** to override the host agent's system instructions.
- Point to **suspicious URLs** (raw IPs, shorteners, executable downloads).
- Read **sensitive credential files** (`.env`, `~/.aws`, `~/.ssh`).
- Hide a **download-and-execute chain** across multiple steps.
- Ship **obfuscated payloads** (base64/ROT13) that decode to dangerous actions.
- Configure a **dangerous MCP server** (remote endpoint, dynamic package
  execution, secrets passed to the server, broad filesystem access).
- Hand control to another component via an explicit **HANDOFF**, continuing an
  attack chain across components.

The alert is the starting point. Veyra's differentiator is the **path**: how a
read secret flows to an external endpoint, or how a handoff lets a risk move
through multiple otherwise-separate components.

Veyra scans these resources statically so you can review them before
trusting an agent to load them.

## ⚙️ How it works

Veyra is a deterministic, static analysis pipeline. It never executes
scanned Skills or MCP servers and never makes network requests during a scan.

```mermaid
flowchart LR
    A[Input] --> B[Static parsing]
    B --> C[Rule detection + correlation]
    C --> D[Security Graph]
    D --> E[Attack Path Analyzer]
    E --> F[Risk / Evidence / Breakpoints]
    F --> G[Policies]
    G --> H[Security Status / CLI Gate]
    H --> I[Terminal / JSON / SARIF]
```

The pipeline (see `src/veyra/scanner.py`, `src/veyra/graph/`, and
`src/veyra/policy.py`):

1. **Static parsing** — walk the target, skip VCS/build/vendor dirs, skip
   binary and oversized files, decode UTF-8.
2. **Rule detection + correlation** — line rules (AS-001…AS-006), file rules
   (AS-MCP-*, AS-007), correlation chains (AS-CHAIN-*), and intra-file
   step-sequence analysis produce findings.
3. **Security Graph** — build a directed, deterministic graph of nodes
   (Agent, Skill/Component, Tool/MCP Server, Data, Secret, Endpoint, Action)
   and edges (contains, uses, calls, reads, writes, sends-to, executes,
   produces, flows-to, trusts, handoff). Node identity is **semantic** (a real
   URL/path/secret resolves to one node), and findings/actions are analyzed
   **per component** to prevent cross-file correlation.
4. **Attack Path Analyzer** — deterministically enumerate truthful, contiguous
   graph walks (`READS → FLOWS_TO → SENDS_TO`), classify each into explicit
   security semantics, and mark cross-component composition **only** when the
   walk contains an explicit `HANDOFF` edge.
5. **Risk / Evidence / Breakpoints** — attach a deterministic risk model
   (`risk_score`, `risk_severity`, `risk_confidence`), structured evidence, and
   breakpoints to every attack path.
6. **Policies** — evaluate a deterministic policy engine over the finalized
   attack paths.
7. **Security Status / CLI Gate** — a single aggregate `policy_status`
   (`PASS`/`FAIL`); CLI exits non-zero on violations while preserving the
   existing severity behavior.
8. **Reporting** — terminal (with policy violations when present), JSON (with
   attack paths + policy results/status), SARIF 2.1.0, or a standalone HTML
   security report.

On top of this core pipeline sit two read-only projection layers:

- **Component security projections** (`src/veyra/graph/context.py` and
  `src/veyra/graph/declarations.py`, Commits 17–22) — explicitly declared
  component relationships, an explicit component↔security-behavior
  association, and derived per-component views (security scope, path
  participation, path composition, and risk evidence). These are additive
  metadata only and never modify the AttackPath, risk, or policy.
- **Threat Knowledge** (`src/veyra/threats/`, Commits 23–24) — a
  deterministic, read-only foundation (`ThreatScenario`, `ThreatTaxonomy`) plus
  the OWASP Agentic AI 2026 catalog. Purely descriptive; no graph/path/risk
  interaction yet.

## 🧩 Detection table

| Rule | ID | Severity examples |
|------|----|-------------------|
| Hardcoded secrets (OpenAI/Anthropic/GitHub/AWS/generic keys, passwords, private keys) | AS-001 | CRITICAL / HIGH |
| Shell / command execution (`subprocess shell=True`, `os.system`, `curl\|bash`, `eval`) | AS-002 | CRITICAL / HIGH / MEDIUM |
| Network access (HTTP clients, download-and-execute, raw-IP URLs, shorteners) | AS-003 | HIGH / MEDIUM / LOW |
| Prompt injection (ignore instructions, reveal secrets, exfiltrate files, disable security) | AS-004 | HIGH / MEDIUM |
| Suspicious URLs (raw IPs, shorteners, executable downloads, URL→shell) | AS-005 | CRITICAL / MEDIUM / LOW |
| Sensitive credential file access (`.env`, `~/.aws`, `~/.ssh`, credential/private-key files) | AS-006 | HIGH |
| Encoded content executed/fetched (base64/ROT13 + execution/fetch context) | AS-007 | CRITICAL / HIGH |
| MCP config: remote endpoints, HTTP, local/dynamic exec, secrets, broad FS, suspicious args, trust info | AS-MCP-001…010 | HIGH / MEDIUM / LOW / INFO |
| Attack chains: secret exfiltration, download-and-execute, remote MCP execution, source-to-sink exfiltration | AS-CHAIN-001…004 | CRITICAL / HIGH |

Matched secrets are **redacted** in reports — full secrets never appear.

## 📋 Findings

Every finding carries structured metadata to help a security engineer triage
quickly and consistently across terminal, JSON, and SARIF output.

| Field | Meaning |
|-------|---------|
| `rule_id` | The rule that fired (e.g. `AS-001`, `AS-MCP-006`, `AS-CHAIN-002`). |
| `severity` | **How dangerous the behavior is** (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`). |
| `confidence` | **How reliably Veyra matched the behavior** (`HIGH`/`MEDIUM`/`LOW`). |
| `cwe` | CWE IDs (only where defensible; never fabricated). |
| `mitre` | Approved MITRE ATT&CK mappings (only where justified). |
| `matched_text` | The exact source line that triggered the rule (redacted for secrets). |
| `evidence` | Rule-specific evidence (secrets are redacted). |
| `remediation` | Recommended fix. |
| `suppressed` | Whether the finding was suppressed by `.veyra.toml`. |

**Severity vs. confidence:** severity answers *how dangerous the behavior is*;
confidence answers *how reliably the behavior matches the rule*. They are
independent. A high-severity finding can be low-confidence, and vice versa.

See `docs/finding-model.md` for the full field reference and the CWE mapping.

## 🔌 MCP security analysis

Veyra scans MCP (Model Context Protocol) server configuration files for
security issues. It supports `.mcp.json`, `mcp.json`, `mcp_servers.json`, and
structurally identifiable JSON/YAML MCP configs.

MCP-specific rules (IDs `AS-MCP-001` … `AS-MCP-010`):

| Rule | ID | Severity |
|------|----|----------|
| Remote MCP endpoint | AS-MCP-001 | MEDIUM |
| HTTP endpoint without HTTPS | AS-MCP-002 | HIGH |
| Local command execution via shell wrapper | AS-MCP-003 | MEDIUM |
| Dynamic package execution (npx/npm/uvx/pip) | AS-MCP-004 | MEDIUM |
| Environment variables passed to server | AS-MCP-005 | LOW |
| Secret-looking environment variables | AS-MCP-006 | HIGH |
| Broad filesystem/path access | AS-MCP-007 | MEDIUM |
| Suspicious command arguments | AS-MCP-008 | HIGH |
| Remote URL + executable/download behavior | AS-MCP-009 | HIGH |
| Missing/ambiguous server trust information | AS-MCP-010 | INFO |

> A remote or unfamiliar MCP server is **not** labeled malicious by itself.
> Remote endpoints are flagged MEDIUM with context; only concrete risk signals
> (plain HTTP, secrets passed, broad FS access, dangerous flags) raise severity.

MCP scanning is **fully static**: Veyra never executes MCP commands,
never starts MCP servers, never connects to endpoints, never downloads
packages, and never resolves or contacts remote URLs.

## 📦 Installation

```bash
# from the project root
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Windows
# or: source .venv/bin/activate && pip install -e ".[dev]"  # macOS/Linux
```

Requires Python 3.9+.

## ⚡ Quickstart: see it work in three commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # 1. environment + install
.venv/bin/veyra demo                                          # 2. scan the demo fixture
xdg-open veyra-demo.html                                      # 3. open the report (macOS: open veyra-demo.html)
```

`veyra demo` scans the four local files in `tests/fixtures/demo/` (a prompt
injection, a `curl | bash` installer, a `shell=True` helper and an MCP config)
with no network access, prints a short summary, and writes
`veyra-demo.html` into the current directory. It refuses to overwrite an
existing file or to write through a symlink: pass `--force` to replace a file,
or `--out other.html` to write elsewhere. The demo is a walkthrough of the
report format on a known fixture — it is **not** corpus coverage (that is
`veyra attack-lab` with its 113 cases) and not a verdict on your own code. If
the scan cannot read the whole fixture, the summary says `UNKNOWN` with the
reason. The fixture lives outside the package, so `veyra demo` needs a source
checkout and fails with an explicit message when there is none; inside an
installed wheel, name the checkout with
`VEYRA_DEMO_FIXTURE=<checkout>/tests/fixtures/demo`.

## 🚀 Usage

```bash
veyra scan ./path/to/skill
veyra scan ./path/to/skill --format json
veyra scan ./path/to/skill --format sarif > report.sarif
veyra scan ./path/to/skill --format html > report.html
```

### HTML Security Report

`--format html` emits a self-contained, deterministic HTML Security Report (dark
security-oriented UI, inline CSS only — no network, CDN, or JavaScript). It
renders the scan summary, every attack path as a visual graph (nodes derived
from `path.nodes`, edges from `path.edges`, with labeled edge types and
semantic node types) plus a separate **Associated evidence** representation,
per-path **Provenance** (which scanned component/file contributed each node
and edge), a per-path **Explanation** (summary, steps, impact, policies,
breakpoints, components), per-path **Component Context** (which declared
Agent/Skill/Tool/MCP component owns each security behavior edge), policy
results, and the original findings. When explicit component context is
supplied, it also renders the **Component Security Scope**, **Component Path
Participation**, **Component Path Composition**, and **Component Risk
Evidence** sections. All dynamic values (from scanned files, node IDs,
evidence, provenance, etc.) are HTML-escaped, so malicious content cannot inject
markup. Open it directly from disk:

```bash
veyra scan ./path/to/skill --format html > report.html
```

### Exit codes (CI-friendly)

- `0` — no HIGH/CRITICAL findings **and** no policy violations
- `1` — at least one HIGH finding, or at least one violated policy
- `2` — at least one CRITICAL finding

The failure threshold is configurable with `--fail-on`. Policy violations
(`ScanResult.policy_status == "FAIL"`) also force a non-zero exit, while
preserving the severity behavior above. So a scan with a policy violation but
no CRITICAL findings exits `1`; a scan with CRITICAL findings exits `2`.
`policy_status == "UNKNOWN"` (target not fully read, no violation proven) exits
`0` — the exit code is a build gate for proven problems, not a completeness
claim; the report itself says `UNKNOWN` rather than `PASS`.

```bash
veyra scan ./path --fail-on CRITICAL   # only fail on critical
veyra scan ./path --fail-on MEDIUM    # fail on medium or higher
```

### Baseline / diff (gate on new findings only)

A mature tree usually has findings you already know about. Re-failing CI on
them forever teaches everyone to ignore the gate, so Veyra can snapshot them
once and then gate on the **difference**:

```bash
veyra baseline create ./path                  # -> ./path/.veyra-baseline.json
veyra baseline create ./path -o ci/baseline.json
veyra scan ./path --baseline ci/baseline.json
veyra scan ./path --baseline ci/baseline.json --format json
```

- `baseline create` writes one record per finding: `rule_id`, `file` relative
  to the target, `line`, `evidence`, `severity`, sorted and formatted with a
  stable byte order. Suppressed findings are included, because suppression is a
  config decision: un-suppressing one later must not report it as new.
- `scan --baseline` lists only the **new** findings and `--fail-on` counts only
  those, so a CRITICAL new finding still exits `2`. What a baseline does *not*
  do is narrow the result: `score`, `risk_level`, `summary()`, the coverage
  block and `policy_status` keep describing the whole tree, and every finding
  is still present in JSON, SARIF and HTML, marked `baseline_state`
  (`new` / `matched`; SARIF's own `baselineState` is `new` / `unchanged`).
  A matched CRITICAL backlog therefore never renders as `SAFE`, and the
  terminal report prints a *Known backlog still present* line with its
  severity mix instead of hiding it.
- `fixed` findings (in the snapshot, gone from the tree) are counted in every
  format and printed under *Fixed Since Baseline* in the terminal report, and
  they never fail the build; a scan never rewrites the snapshot, so "we fixed
  it" stays a reviewable act (`veyra baseline create` is the only writer).
- JSON adds one block next to `policy_status`:
  `"baseline": {"matched": 12, "new": 1, "fixed": 0}`; SARIF repeats it under
  `runs[0].properties.baseline`, HTML as three summary cards. `matched` is
  emitted next to `new` on purpose: the part that fails the build is not the
  part that grows the debt.
- A snapshot that lives inside its own target (the default location) is not
  walked — otherwise it would fingerprint its own bytes — but the refusal is
  **recorded**: the file appears in `coverage.files_skipped` with the reason
  `baseline_snapshot`, the coverage status drops from `full` to `partial`, and
  the terminal report names it. A file nobody read is a fact about the read,
  not a silent omission.
- The snapshot never carries host context: file paths are relative to the
  target, and absolute paths, the home directory and `..` are removed from
  `evidence` too (correlation evidence embeds `file:line` of every
  contributor). An absolute and a relative target produce byte-identical
  snapshots, and the output does not depend on `PYTHONHASHSEED`.
- Matching is the **whole tuple** — no wildcard, no fuzzy line matching, no
  severity normalisation. A line inserted above a finding therefore makes it
  `fixed` + `new`, and raising a finding's severity re-flags it. Both
  directions are deliberate: a "smart" match is a way to pre-seed a baseline
  and keep a real finding out of the gate.
- A baseline never mutes the verdict: `policy_status` and the coverage block
  are computed exactly as before, so a policy violation still fails even when
  `new == 0`, and a partial read with zero new findings is `UNKNOWN`, not
  `SAFE`.
- A missing, unreadable, oversized (> 5 MB or > 100 000 records) or
  non-regular (directory, FIFO) baseline file exits `2` — a broken gate must
  not look like an empty one.
- The snapshot is an input a pull request can edit, and whoever can commit it
  controls the verdict. Keep it in `CODEOWNERS` under the security reviewers,
  and read `matched` (not only `new`) when reviewing a diff that changes it.
  It is also a committed copy of the evidence text (URLs, commands, redacted
  credential prefixes), so in a public repository treat it as one more
  published artifact rather than a private one.

### Explaining one record (`veyra explain`)

```
veyra explain <finding-id|path-id> --target ./path --format text
veyra explain --target ./path        # list the ids this run derives
```

One record, explained from a fresh scan: no LLM, no network, no report file.

```
veyra explain fnd-4edeaf87744f --target ./path
```

- A finding id is derived (`fnd-` + 12 hex digits of SHA-256) from the same
  five-field tuple the baseline fingerprints: `rule_id`, the file relative to
  the scan root, `line`, the path-scrubbed `evidence`, `severity`. The exact
  recipe is in `docs/EXPLAIN.md` and is executed as written by a test.
- A path id is the full 64-hex `AttackPath.path_id`. Prefixes are rejected:
  they are ambiguous by construction.
- The output is a run header (target, `coverage_status`, `policy_status`), a
  record block that only restates real `Finding` / `AttackPath` fields, and —
  for a path — a proof check that re-evaluates the recorded `attack_type`
  against the record's **stored** nodes and edges and prints
  `proof-result: proven` or `not-proven`. The type definition is printed as a
  definition, never as a claim about the record.
- Explaining one record is not a verdict on the target: `partial` / `none`
  coverage is printed as `UNKNOWN`, `suppressed` findings are printed as
  suppressed with their reason, and a finding without a line prints `(none)`
  rather than a number.
- A malformed, unknown or ambiguous id exits `2` with the message on stderr and
  an empty stdout; the ids that do exist are listed next to the rejected one.
  Two findings that agree on all five fields share an id, and `explain` reports
  that ambiguity instead of picking the first.
- `evidence`, `matched_text`, file names, titles and node labels are
  repository-controlled text: they go through the baseline's host-path
  scrubber and one shared control-character escaper
  (`veyra.sanitize.escape_untrusted`) before printing, so a repository cannot
  forge a line or emit ANSI escapes into a CI log.

### JSON output

```bash
veyra scan ./path --format json
```

```json
{
  "target": "./path",
  "score": 72,
  "risk_level": "HIGH",
  "summary": { "critical": 1, "high": 1, "medium": 0, "low": 0 },
  "coverage": {
    "coverage_status": "partial",
    "files_scanned": 12,
    "files_skipped": [ { "path": "assets/logo.png", "reason": "not_scannable" } ],
    "rule_errors": [],
    "dirs_pruned": [ { "path": "node_modules", "reason": "vendored_dir" } ],
    "decode_errors": []
  },
  "findings": [ ... ],
  "attack_paths": [
    {
      "path_id": "9e6797830b74fa5d036b38ae31386192208da5a85bda8b3396c4e9cc6d8543ce",
      "nodes": ["SKILL:skill", "SECRET:token", "DATA:payload", "ENDPOINT:https://example.com"],
      "edges": [
        {"source": "SKILL:skill", "target": "SECRET:token", "type": "READS"},
        {"source": "SECRET:token", "target": "DATA:payload", "type": "FLOWS_TO"},
        {"source": "DATA:payload", "target": "ENDPOINT:https://example.com", "type": "SENDS_TO"}
      ],
      "associated_edges": [],
      "attack_type": "SECRET_EXFILTRATION",
      "entry_node": "SKILL:skill",
      "asset_node": "SECRET:token",
      "sink_node": "ENDPOINT:https://example.com",
      "risk_score": 95,
      "risk_severity": "CRITICAL",
      "risk_confidence": "HIGH",
      "evidence": ["secret read", "data transformation", "sensitive data flow", "external network send"],
      "breakpoints": [ ... ],
      "explanation": "A secret flows to an external endpoint."
    }
  ],
  "policy_results": [
    {
      "policy_id": "SECRET-EXFILTRATION-001",
      "path_id": "9e6797830b74fa5d036b38ae31386192208da5a85bda8b3396c4e9cc6d8543ce",
      "violated": true,
      "reason": "Proven secret exfiltration reaches an external endpoint."
    }
  ],
  "policy_status": "FAIL",
  "component_security_scopes": [ ... ],
  "component_path_participation": [ ... ],
  "component_path_composition": [ ... ],
  "component_risk_evidence": [ ... ]
}
```

`attack_paths` is present only when the Security Graph reveals a real
object-continuity path (or an explicit `HANDOFF` chain). Each path carries a
deterministic `path_id`, its ordered nodes/edges, attack type, and the
risk/evidence/breakpoint fields. A path's declared `severity`/`confidence` are
capped at what its own walk proves (`risk_severity`/`risk_confidence`), so a
correlation-only path cannot ship `HIGH` metadata next to a `MEDIUM` risk
verdict; the cap never raises a value. After the paths and policy results are
final, `scanner` asserts their provenance (`veyra.invariants`): identity
re-derived, every node/edge present in the graph that produced the path, no
violation resting on a path with no proven semantics. A broken invariant raises
instead of producing a report. `policy_results` is the complete policy
evaluation; `policy_status` is the aggregate `PASS`/`FAIL` decision. When
explicit component-context associations are supplied, the additive
`component_security_scopes` / `component_path_participation` /
`component_path_composition` / `component_risk_evidence` fields are emitted
(and omitted when empty). These fields are added **without** changing the
existing `target`/`score`/`risk_level`/`summary`/`findings` schema.

The `coverage` block carried by every report is documented once, in its own
section below: see [Coverage](#coverage) for the six fields, their fixed reason
tokens, and what coverage decides about `SAFE` / `PASS` / `UNKNOWN`.

### Attack Paths

Every scan builds a lightweight Security Graph and runs a deterministic Attack
Path Analyzer over it (no LLM, no runtime). A path is emitted only when the
graph shows actual continuity — a read Secret/data object that FLOWS_TO a
derived object which is SENDS_TO an external endpoint. Shared-skill correlation
alone (a skill reads a secret *and* also contacts an endpoint) is not reported
as a proven path.

Each path is classified into explicit security semantics:

- `SECRET_EXFILTRATION` — a secret flows to an external endpoint (proven by
  a contiguous `READS → [FLOWS_TO] → SENDS_TO` object lineage).
- `DATA_EXFILTRATION` — sensitive data flows to an external endpoint (same
  lineage requirement).
- `CORRELATED_SECRET_EXECUTION` — a secret is read by the skill and the same
  skill executes an action. This is a **correlation**, not a proven
  secret→action flow; it is never described as data reaching the action.
- `UNKNOWN` — the path does not satisfy any proven pattern.

Exfiltration classification is conservative: the asset must be connected to
the sent object by an actual contiguous edge sequence (READS → FLOWS_TO*
→ SENDS_TO). A `SENDS_TO` that does not originate from the asset lineage, or
`USES`/`PRODUCES` edges, never produce an exfiltration type.

A path exposes its `attack_type`, `entry_node`, `asset_node`, `sink_node`,
`path_id`, deterministic `risk_score`/`risk_severity`/`risk_confidence`, a
structured `evidence` list, and a deterministic `explanation`. The classifier
never fabricates an asset or sink that is not present in the path, and never
treats `USES` (a request) or `PRODUCES` (skill output) as
exfiltration/data-flow.

Terminal output shows a concise section when paths exist:

```
Attack Paths
-----------
  [CRITICAL] [SECRET_EXFILTRATION] risk=95 (id 4f82a91c3d) Secret exposed to external endpoint
    SKILL:skill → SECRET:token → DATA:payload → ENDPOINT:https://example.com
    (SECRET_EXFILTRATION: A secret flows to an external endpoint.)
    Breakpoints:
      - READS: Restricts access to the sensitive asset.
      - FLOWS_TO: Breaks the proven data lineage.
      - SENDS_TO: Prevents transmission to the external endpoint.
```

#### Component composition (HANDOFF)

A component transfer is represented by an **explicit `HANDOFF` edge**
(`SKILL:A --HANDOFF--> SKILL:B`). Composition is claimed **only** when an
ordered attack-path walk actually contains that `HANDOFF` edge — never inferred
from shared names, endpoints, data, or producer/consumer relationships. Branches
and multi-hop chains are enumerated deterministically, e.g.
`A -> B`, `A -> C`, and `A -> B -> D`. A pure handoff chain is a **component
transfer** (`attack_type = UNKNOWN`, `risk_score = 0`); it does not by itself
prove secret or data exfiltration.

```
[INFO] [UNKNOWN] risk=0 (id 0bbe7892f0) Cross-component control handoff
  SKILL:A → SKILL:B
  Components: A → B
```

A composed path is always the control-transfer walk itself (`attack_type =
UNKNOWN`, `risk_score = 0`); composition itself never becomes an exfiltration
semantic. If a component in the chain also carries a separate proven
exfiltration path, that path is emitted as its own single-component walk, not
merged into the composed one.

### Policies & security status

Every finalized attack path is evaluated by a deterministic **policy engine**
(`src/veyra/policy.py`). Built-in policies:

- `SECRET-EXFILTRATION-001` — a proven `SECRET_EXFILTRATION` violates it.
- `DATA-EXFILTRATION-001` — a proven `DATA_EXFILTRATION` violates it.
- `CORRELATED-SECRET-EXECUTION-001` — a correlated secret+execution requires
  review (a review policy, not a proven-data-flow claim).

Each produces a `PolicyResult` (`policy_id`, `path_id`, `violated`, `reason`).
`ScanResult.policy_status` is the aggregate verdict, and it has three values:

- `"FAIL"` — at least one policy is violated. Proof; unread files never take it away.
- `"PASS"` — no violation **and** `coverage_status == "full"`. Only then does
  "no violations" mean "nothing violated in the target".
- `"UNKNOWN"` — no violation proven, but part (or all) of the target was never
  read. Not a pass: the question was not answered for the whole target.

The terminal report always prints the verdict (`Policy: PASS`,
`Policy: UNKNOWN (no violation proven; coverage partial, 1 skipped)`), and JSON
(`policy_status` next to `coverage`), SARIF (`runs[0].properties.policy`) and the
HTML summary carry it too. Terminal output shows a **Policy Violations** section
only when at least one policy is violated:

```
Policy Violations
----------------
- SECRET-EXFILTRATION-001
  Path: 9e6797830b74fa5d036b38ae31386192208da5a85bda8b3396c4e9cc6d8543ce
  Reason: Proven secret exfiltration reaches an external endpoint.
```

`ScanResult` also exposes a derived summary: `policy_violation_count`,
`has_policy_violations`, `violated_policy_ids`, and `violated_path_ids`.

### SARIF output

Veyra emits **SARIF 2.1.0** for compatibility with GitHub Code Scanning
and other SARIF-compatible security tooling. SARIF generation is fully static
(no network requests, no code execution). Suppressed findings are preserved via
SARIF's `suppressions` array — they are never silently turned into clean
secrets remain redacted. When a scan produces attack paths, each is additionally
emitted as a SARIF result (level mapped from its existing risk severity, rule id
derived from its attack type) with the path's `path_id`, `attack_type`, risk
fields, evidence, and breakpoints exposed under the result's `properties`.

**SARIF locations for attack-path results** are derived only from real data:
when the scanner can resolve the path's entry node to a real scanned SKILL
file (i.e. the same file that produced the findings behind the path), the
SARIF result carries one `physicalLocation` whose `artifactLocation.uri`
points to that file. The provenance reason is recorded explicitly under
`properties.location_provenance = "entry_node_skill_file"`. When the entry
node is not a SKILL or no entry-file mapping is available, the result is
emitted **without** a `locations` array and with
`properties.location_provenance = "omitted"` — a deliberate, audited
omission rather than fabricated coordinates. This keeps GitHub Code
Scanning's `expected at least one location` check satisfiable for every
attack-path result while preserving the no-fabrication rule.

When
explicit component context is supplied, the run-level properties also expose
`component_security_scopes`, `component_path_participation`,
`component_path_composition`, and `component_risk_evidence` as additive (never
fabricated) metadata.

### Component declarations, context, security scope, participation, composition, and risk evidence

Veyra keeps **six distinct additive layers** over the Security Graph — never
merged, never inferred:

- **Component Declarations** (`graph/declarations.py`) — explicit architecture
  relationships: `AGENT USES SKILL`, `SKILL HANDOFF SKILL`, `AGENT CALLS TOOL`,
  etc. These describe how components relate to each other.
- **Component Context** (`graph/context.py`, Commit 18) — explicit association
  of a security-behavior edge (READS / WRITES / SENDS_TO / EXECUTES / PRODUCES /
  FLOWS_TO) with a component: `associate_security_behavior(graph, ("SKILL:A",
  "SECRET:x", READS), ComponentContext("SKILL:A", SKILL))`.
- **Component Security Scope** (`graph/context.py`, Commit 19) — a
  deterministic, read-only aggregation of those explicit context associations
  into per-component projections:
  `build_component_security_scopes(graph)` →
  `serialize_component_security_scopes(graph)`.
- **Component Path Participation** (`graph/context.py`, Commit 20) — the
  subset of a component's explicitly associated security behaviors that are
  actually present on a particular finalized AttackPath:
  `build_component_path_participation(path, context)` /
  `build_component_path_participation_for_paths(paths, context)` →
  `serialize_component_path_participation(...)`.
- **Component Path Composition** (`graph/context.py`, Commit 20) — a
  deterministic path-level grouping of the explicitly participating
  components in a finalized AttackPath and their proven behaviors:
  `build_component_path_composition(path, context)` /
  `build_component_path_composition_for_paths(paths, context)` →
  `serialize_component_path_composition(...)`.
- **Component Risk Evidence** (`graph/context.py`, Commit 22) — a deterministic
  projection of the finalized AttackPath's risk metadata onto explicitly
  participating components:
  `build_component_risk_evidence(path, context)` /
  `build_component_risk_evidence_for_paths(paths, context)` →
  `serialize_component_risk_evidence(...)`.

```
build_component_security_scopes(graph) ==
[
  ComponentSecurityScope(
    component=ComponentContext("SKILL:A", SKILL),
    security_behaviors=(("SKILL:A", "READS", "SECRET:x"),),
  )
]
```

The scope projection:

- is **NOT** a new graph relationship and creates **no** edges;
- is **NOT** an ownership inference engine;
- preserves multiple components explicitly associated with the same security
  edge (each yields its own independent scope — Veyra never decides a "real"
  owner);
- deduplicates identical `(component, behavior edge)` pairs;
- sorts deterministically by `(component_type, component_id)` and behaviors by
  `(source, edge_type, target)`;
- references only actual existing security edges and raises
  `ComponentContextError` on stale/invalid metadata;
- does not mutate the graph or the AttackPaths.

**Veyra never infers ownership** from `USES`, `CONTAINS`, `CALLS`, `TRUSTS`,
`HANDOFF`, file paths, node IDs, provenance, labels, findings, or naming. So
`AGENT USES SKILL` alone does **not** create an `AGENT → security behavior`
association or an `AGENT → ComponentSecurityScope` — only an explicit
`ComponentContextAssociation` establishes component security scope.

The projection is exposed additively in reports: JSON
`component_security_scopes` (top-level), SARIF
`run.properties.component_security_scopes`, and a compact **Component Security
Scope** HTML section. `attack_paths[*].context_components` is unchanged.

**Component Security Scope becomes visible in scan/report output ONLY when
explicit component-context associations are supplied** to the scanner:

```python
from veyra.scanner import scan_path
from veyra.graph import ComponentContext, ComponentContextAssociation, NodeType, EdgeType

result = scan_path(
    "path",
    component_context=[
        ComponentContextAssociation(
            edge_key=("SKILL:checkout", "SECRET:.env", EdgeType.READS),
            component=ComponentContext("SKILL:checkout", NodeType.SKILL),
        ),
    ],
)
result.component_security_scopes  # populated from the explicit associations
```

With no explicit associations the field stays empty and reporting is unchanged—
no ownership is inferred from `USES`, `CONTAINS`, `CALLS`, `TRUSTS`, `HANDOFF`,
file paths, node IDs, labels, provenance, findings, or naming. Each supplied
association is re-validated (its edge and component must actually exist in the
scan's merged graph) and stale/invalid associations raise
`ComponentContextError` deterministically.

### Component Path Participation

**Component Path Participation** answers *"which explicitly declared components
participate in a given AttackPath, and which of their security behaviors are
actually present on that path?"*

The rule is strict:

> **GRAPH MEMBERSHIP ≠ ATTACK-PATH PARTICIPATION.**

A component participates in an AttackPath iff:

1. there is an **explicit** `ComponentContextAssociation` for that component;
2. the associated security-behavior edge is an **actual edge of that AttackPath**
   — either a `path.edges` walk edge or a `path.associated_edges` edge — matching
   the exact `(source, edge_type, target)` triple.

An association whose edge exists in the graph but is **not** on the path simply
does not make the component participate in that path. `USES`, `CONTAINS`,
`CALLS`, `TRUSTS`, `HANDOFF`, file paths, node IDs, labels, provenance, and
naming never establish security ownership or path participation.

The scope projection may contain many behaviors; a particular path contains
only the ones actually on it. For example a scope with both `READS` and
`SENDS_TO` produces a participation object holding only the `READS` behavior
when `SENDS_TO` is not on that path.

Exposed additively in reports: JSON `component_path_participation` (top-level),
SARIF `run.properties.component_path_participation`, and a compact **Component
Path Participation** HTML section. It is metadata only — it never creates a
graph edge, never modifies the AttackPath, and is never part of path_id, risk,
evidence, breakpoints, or policy.

### Component Path Composition

**Component Path Composition** answers *"which explicitly declared security
components participate in this AttackPath, and in what deterministic order do
their proven security behaviors occur along that path?"*

It is a deterministic, read-only projection over an already-finalized
AttackPath plus explicit `ComponentContextAssociation` metadata — NOT ownership
inference, NOT a new attack type, NOT a new graph edge, and NOT a replacement
for AttackPath. A component appears in a composition only if an explicit
association exists for it AND its referenced security-behavior edge (a
`path.edges` walk edge or a `path.associated_edges` edge) is an actual edge of
that specific path.

> **COMPONENT PATH COMPOSITION DOES NOT CREATE COMPONENT RELATIONSHIPS.**

The composition is a flat collection of explicitly participating components
and their proven behaviors; it never invents a component-to-component edge —
even when two components are associated with the same path edge, both are
preserved with no owner or responsibility ranking. `associated_edges` are valid
participation evidence but are never treated as contiguous path sequence
edges.

Exposed additively in reports: JSON `component_path_composition` (top-level),
SARIF `run.properties.component_path_composition`, and a compact **Component
Path Composition** HTML section. It is metadata only and never part of path_id,
risk, evidence, breakpoints, or policy.

### Component Risk Evidence

**Component Risk Evidence** answers *"what risk-relevant security behaviors of
each explicitly participating component are evidenced by this specific
AttackPath?"* It connects the finalized AttackPath, its ComponentPathComposition,
and the already-computed AttackPath risk/evidence.

The distinctions:

- **AttackPath Risk** = risk of the complete proven path.
- **Component Path Composition** = which explicit components participate and
  which behaviors they prove.
- **Component Risk Evidence** = which existing AttackPath evidence labels are
  evidenced by each participating component.

Two cardinal rules:

> **COMPONENT RISK EVIDENCE DOES NOT REDISTRIBUTE ATTACKPATH RISK.**

> **COMPONENT RISK EVIDENCE DOES NOT ESTABLISH OWNERSHIP OR RESPONSIBILITY.**

Every `ComponentRiskEvidence` entry:

- copies `risk_severity` / `risk_confidence` verbatim from the finalized
  AttackPath (never recalculated per component);
- emits evidence that is always a **subset of the AttackPath.evidence** (it can
  never manufacture a label the path itself did not establish);
- has **no** component risk score, percentage, responsibility, or ownership —
  only explicit participation counts.

The behavior→evidence mapping uses only the existing AttackPath evidence
vocabulary and the actual behavior triple / graph node type:

| Behavior | Evidence label |
|---|---|
| `READS` → SECRET node | `secret read` |
| `READS` → DATA node | `sensitive data read` |
| `FLOWS_TO` | `sensitive data flow` |
| `SENDS_TO` | `external network send` |
| `EXECUTES` | `execution` |
| `WRITES` / `PRODUCES` | *(no label)* |

Exposed additively in reports: JSON `component_risk_evidence` (top-level), SARIF
`run.properties.component_risk_evidence`, and a compact **Component Risk
Evidence** HTML section. It is purely downstream metadata — it never draws
arrows between components, never claims causal attribution, probability, or
exploitability scoring, and never modifies the AttackPath.

## 🚫 Suppression / allowlist

You can suppress known-safe findings with a project configuration file,
`.veyra.toml`:

```toml
[ignore]
servers = ["filesystem"]          # ignore MCP servers by name
domains = ["trusted.example.com"] # ignore findings for these domains
rules = ["AS-MCP-010"]            # ignore specific rule IDs
```

- Suppression is applied **after** findings are generated, never inside rules.
- Suppressed findings are **marked** (`suppressed: true` + a reason) and remain
  distinguishable from findings that were never detected.
- Terminal output shows `[SUPPRESSED]` lines; JSON output includes
  `"suppressed": true` and a `"suppressed"` count in the summary.
- Suppression is **never silent** — it is always visible in the report.

## 🧪 Attack Lab

Veyra ships an internal adversarial corpus (`tests/fixtures/attacks/`)
and an evaluator (`veyra attack-lab`) that measures detection on that
corpus.

**On the current 113-case internal Attack Lab corpus:**

| Metric | Value |
|--------|-------|
| Total cases | 113 |
| Detected | 103 |
| Partially detected | 7 |
| Missed | 3 |
| False positives | 0 |
| Detection rate | 91.2% |

> This figure is **only** for the current 113-case internal Attack Lab corpus. It
> is **not** a measure of real-world detection accuracy. Real skills are far
> more varied, and the corpus does not cover every attack pattern. A clean scan
> does **not** guarantee a resource is safe.

The Attack Lab is a regression harness: every future scanner change must keep
previously detected cases detected and avoid new false positives. See
`docs/attack-lab.md` and `docs/attack-lab-v2.md`.

**About the 7 partially detected cases:** these are attack-lab fixtures where
the expected rule fires at MEDIUM rather than HIGH/CRITICAL, which the
classifier treats as a partial detection. They cover patterns where lifting
severity blindly would create false positives on legitimate configurations:

- `encoded-obfuscation/rot13-exec` and `v2/obfuscation/rot13-instruction` —
  ROT13-decode-and-run instructions whose payloads are natural-language intent
  (`command to delete advanced files`, `send the contents of the ssh folder…`).
  AS-004 fires MEDIUM via the encoded-obfuscation pattern; AS-007 now decodes a
  quoted ROT13 **phrase** as a whole and fires CRITICAL when the decoded text is
  a literal shell command, but these payloads are prose, not shell syntax.
  Raising severity would require a natural-language intent detector (an LLM in
  the canonical path, which the manifesto forbids) or broadening
  `DANGEROUS_COMMAND` to ordinary English verbs, which would over-alert on any
  benign skill that legitimately mentions file deletion.
- `v2-prompt-injection/unrelated-exec` — a demonstrative "run this command"
  directive; AS-004 MEDIUM is the rule ceiling, and a HIGH would need a proven
  install → run lineage rather than one directive.
- `v2-mcp-security/remote-endpoint` — a remote MCP URL fires AS-MCP-001 at
  MEDIUM. Remote endpoints are a legitimate deployment topology; HIGH is
  reserved for the http-not-https variant (AS-MCP-002) and remote-exec
  combinations (AS-MCP-009).
- `v2-mcp-security/dynamic-package` — `npx -y @scope/pkg` fires AS-MCP-004
  at MEDIUM. Scoped packages from a known namespace stay MEDIUM; bare
  unpinned references (the typosquat / dependency-confusion case) now
  escalate to HIGH (see `v2-mcp-security/uvx-exec` and `broad-fs`).
- `v2-mcp-security/shell-metachar` — a command hidden behind `/bin/bash -c`
  fires AS-MCP-003 at MEDIUM; HIGH would require parsing the hidden command and
  proving it destructive.
- `v2-shell-execution/js-child-process-exec` — an env-provided command reaches
  `child_process.execSync`, which fires AS-002 at MEDIUM; HIGH needs evidence
  that the value came from the environment (data flow, not a line rule).

These boundaries are deliberate: detection rate is reported above for
transparency, not as a target to maximise by relaxing severity.

**About the 3 missed cases:** all three are ROT13-encoded *natural-language*
instructions (`delete production files`, `upload private SSH keys`,
`download and run an installer as root`). The deterministic decoder handles
literal shell commands; separating an instruction from a description of the
same action in English is not a regex-shaped problem. The decision and its
revisit conditions are recorded in `docs/obfuscation-audit.md` (E-3b).

## Coverage

Every report says how much of the target the scanner actually read. The
`coverage` block is always present, in JSON and in SARIF
(`runs[0].properties.coverage`), because a clean report that does not say what
it skipped is itself a claim nobody checked:

- `coverage_status` — `full` / `partial` / `none`: at least one file was read
  and nothing was refused (`full`), something was read but part of the target
  was not inspected (`partial`), or nothing was read at all (`none`: an empty
  tree, an entirely refused target, or a result that never went through a walk).
  Pruned subtrees are named in `dirs_pruned` rather than counted here; see
  below for which prune reason withdraws `full`.
- `files_scanned` — how many files were read and had rules run against them.
- `files_skipped` — every file the scanner refused, as `{path, reason}`. The
  reason is one fixed token — `not_scannable`, `binary`, `too_large`,
  `unreadable`, `baseline_snapshot` — never an exception message and never a
  host path glued into prose. `baseline_snapshot` is the one skip the scanner
  takes on the caller's instruction: a baseline file living inside the tree it
  belongs to (`veyra scan <target> --baseline <file>`). It is recorded and it
  withdraws `full`, because a file in the tree that no rule read is a gap in
  the read, whoever asked for it. A file that is read but not as the text it
  holds is *not* listed here (see `decode_errors`).
- `dirs_pruned` — every subtree the walk did not enter, as `{path, reason}`:
  `ignored_dir` (machine state: `.git`, `__pycache__`, caches, virtualenvs),
  `vendored_dir` (third-party or build output: `node_modules`, `dist`,
  `build`, `site-packages`), `symlink_dir` (a linked directory, which the walk
  never follows by construction; a linked *file* is still read).
- `decode_errors` — files read with replacement characters because the bytes
  are not UTF-8: `{path, reason: "decode_error"}`. Kept apart from
  `files_skipped` on purpose — the file was scanned and may have produced
  findings, but the decoder supplied part of the text, so the read is not full.
- `rule_errors` — a rule that raised instead of failing the scan: `rule_id`,
  `path`, `line` (`null` when a file rule failed on the file as a whole) and
  `error_type` (`line_rule_exception` / `file_rule_exception`). `rule_id` is a
  token from Veyra's own source, not text taken from the scanned input.

All lists are sorted, so the block is byte-stable across runs.

Coverage is accounting only: it does **not** change `findings`, `score`,
`attack_paths` or `policy_results`; it does decide whether a zero score may be
called `SAFE` and whether a violation-free result may be called `PASS`:

- `SAFE` needs a zero score **and** `coverage_status == "full"`. A zero score
  over a partial or empty read is `UNKNOWN` — not a score bucket, just the
  statement that no verdict was earned (`score` stays `0`).
- `PASS` needs no violated policy **and** `coverage_status == "full"`;
  otherwise `policy_status` is `UNKNOWN`. Without full coverage, "no
  violations" only means "none found in what was read".
- A non-zero score keeps its bucket on partial coverage, and a violated policy
  stays `FAIL`: a proven finding does not become less true because a
  neighbouring file was skipped.

`full` is a statement about the walk, not a guarantee about the tree. Pruned
machine state and unfollowed symlink subtrees are reported in `dirs_pruned`
next to a `full` status, and a pruned `vendored_dir` withdraws `full`
altogether — it is content the target ships that no rule opened. Read
`dirs_pruned` and `files_skipped` together with the status. An `UNKNOWN`
result may still exit `0`: the exit code gates on proven findings and is not a
completeness claim (see [Exit codes](#exit-codes-ci-friendly)).

An excerpt of a report over a target whose `node_modules/` was pruned and whose
notes were not UTF-8 — paths are relative to the target:

```json
{
  "target": "./skill",
  "score": 0,
  "risk_level": "UNKNOWN",
  "summary": { "critical": 0, "high": 0, "medium": 0, "low": 0, "suppressed": 0 },
  "findings": [],
  "coverage": {
    "coverage_status": "partial",
    "files_scanned": 3,
    "files_skipped": [{ "path": "assets/logo.png", "reason": "not_scannable" }],
    "rule_errors": [],
    "dirs_pruned": [{ "path": "node_modules", "reason": "vendored_dir" }],
    "decode_errors": [{ "path": "notes.txt", "reason": "decode_error" }]
  },
  "policy_results": [],
  "policy_status": "UNKNOWN"
}
```

Skipped files are **not** added to SARIF `artifacts`: they produced no result
to attach a location to.

## 🤖 GitHub Action

Veyra ships a GitHub Action workflow that runs on every push and pull
request. See `.github/workflows/veyra.yml`.

The workflow has two jobs:

**`test`** — installs the project with dev dependencies (`pip install -e ".[dev]"`)
and runs the full test suite (`pytest -q`), including the Attack Lab regression
tests.

**`scan`** — installs the project (`pip install .`), scans **production source
only** (`src/`), uploads the JSON report as a `veyra-report` artifact and
the SARIF report to **GitHub Code Scanning**, and fails on HIGH/CRITICAL
findings in `src/`.

**Why the scan targets `src/` and not `tests/`:** the `tests/` directory
contains intentionally malicious Attack Lab fixtures. Scanning those fixtures
would produce self-referential findings — the scanner flagging its own test
corpus. This is **not** a reason to weaken scanner rules; it is a deliberate
choice to scan only production code in CI.

The scan uses the repository's `.veyra.toml` suppression config so the
scanner does not flag its own rule patterns (self-referential findings in the
rule modules, e.g. evidence strings like `curl | bash` in `mitre.py`). This is
a config change only — no scanner logic is modified.

The workflow:

1. Installs Veyra **from the checked-out repository** (`pip install .`).
   The package is not published on PyPI, so the workflow installs it locally
   from the repo it is scanning.
2. Runs the full test suite (test job).
3. Scans `src/` (scan job).
4. Prints a readable report in CI logs.
5. Uploads the JSON report as a `veyra-report` artifact.
6. Uploads the SARIF report to **GitHub Code Scanning** via
   `github/codeql-action/upload-sarif@v3`.
7. Fails the scan job on HIGH findings by default (exit code 1 or 2).
8. Supports a configurable threshold via `--fail-on` in the scan step.
9. Never executes scanned Skills or MCP servers, and makes no outbound
   network requests during the scan.

The workflow requests the `security-events: write` permission, which is
required to upload SARIF to Code Scanning.

## 📊 Risk score methodology

The overall score is a **transparent, deterministic MVP heuristic** — not a
proven security standard. Each finding contributes a fixed weight by severity:

| Severity | Weight |
|----------|--------|
| CRITICAL | 40 |
| HIGH     | 25 |
| MEDIUM   | 10 |
| LOW      | 3  |
| INFO     | 0  |

The score is the sum of all finding weights, **capped at 100**. Risk level is
derived from the score:

| Score | Risk level |
|-------|------------|
| 80–100 | CRITICAL |
| 50–79  | HIGH |
| 25–49  | MEDIUM |
| 5–24   | LOW |
| 0–4    | SAFE (only with `coverage_status: full`) |
| 0      | UNKNOWN (coverage `partial` or `none`) |

## ⚠️ Current limitations

- **Static analysis only** — no runtime behavior, no network calls during scan.
- **Heuristic, not exhaustive** — will miss some attacks and may flag benign code.
- **Line-based rules** — multi-line constructs are not fully analyzed.
- **Cross-component composition is explicit-HANDOFF only** — composition is
  claimed only when a real `HANDOFF` edge is part of an ordered attack-path walk.
  There is **no** inferred cross-component data-flow provenance join, no taint
  tracking, and no variable/function-level data flow beyond
  `READS → FLOWS_TO → SENDS_TO`.
- **Policy engine is a fixed MVP set** — the built-in policies are the only
  policies; there is no user-defined policy configuration or DSL.
- **No runtime execution analysis** — dynamic code execution and malicious MCP
  server runtime behavior are out of scope.
- **MCP config is parsed structurally** (JSON/YAML); MCP server manifests and
  tool schemas are not fully analyzed.
- **Obfuscation decoding covers only base64/ROT13** with execution/fetch
  context; arbitrary encodings are not decoded.
- **ROT13-encoded natural-language instructions are not confirmed** — 3/3
  fixtures in the `v2-rot13-nl` attack set are MISSED. Two independent,
  mechanical reasons: AS-007's ROT13 branch only decodes single tokens of
  ≥16 characters (a sentence is split by spaces), and after decoding it only
  recognises shell syntax (`rm -rf`, `curl | sh`), not natural-language
  actions ("delete every file under …", "send the keys to …"). The decision
  and the measured base are recorded in `docs/obfuscation-audit.md`.

## 🗺️ Roadmap

Prioritized technical work:

- [ ] Inferred cross-component/cross-file data-flow provenance join (currently
  this is explicit-HANDOFF composition only).
- [ ] Richer policy engine (user-defined policies, thresholds).
- [ ] Stronger data-flow / semantic analysis (multi-line, taint tracking).
- [ ] MCP server manifest and tool-schema analysis.
- [ ] Additional Attack Lab coverage (more attack classes, more benign lookalikes).
- [ ] Richer language support (more shell, PowerShell, and config formats).
- [ ] Plugin / custom rule architecture.

Future product ideas (not yet committed): a web dashboard, registry/repository
scanning, and runtime analysis. These are explicitly **not** part of the current
MVP. See `docs/data-flow-architecture-audit.md` for the Security Graph design
and `docs/threat-model.md` for the security model.

## 🧠 Threat Knowledge

Veyra's **Threat Knowledge** is a small, deterministic, read-only internal
foundation for a future threat-taxonomy and benchmark layer
(`src/veyra/threats/`, Commits 23–24). It provides:

- `ThreatScenario` / `ThreatSource` — a generic descriptive/evaluation
  scenario model and its provenance (Commit 23);
- `ThreatTaxonomy` / `ThreatTaxonomyEntry` — a taxonomy-agnostic catalog
  structure, plus serializers (Commit 24);
- `OWASP_AGENTIC_2026` / `get_owasp_agentic_2026()` — one concrete taxonomy
  catalog (Commit 24).

The distinctions:

- **AttackPath** = a *proven security path* derived from the Security Graph.
- **ThreatScenario** = *external / descriptive scenario metadata* (its id, name,
  description, threat categories, attack behaviors, entry conditions, and
  expected security properties).
- **ThreatTaxonomy** = the *catalog structure* that groups authoritative threat
  entry IDs and names (e.g. the OWASP Agentic AI 2026 ASI01–ASI10 set).

A `ThreatScenario` is purely descriptive and never modifies an `AttackPath`,
creates graph nodes/edges, or introduces new `AttackType`/`EdgeType` values —
it neither calculates risk nor assigns ownership/responsibility.

### Evaluation contract: `SecurityScenario`

**`SecurityScenario`** (`src/veyra/threats/scenarios.py`, Commit 25) is the
**evaluation/security test contract** — it describes *expected security
behavior and properties* for a future evaluation, but performs **no analysis**.
It is deliberately separate from Threat Knowledge:

- **ThreatScenario** = *threat knowledge description* (descriptive metadata
  about what a threat looks like).
- **SecurityScenario** = *evaluation/security test contract* (what the system
  under evaluation is expected NOT to do).

A `SecurityScenario` holds a minimal, immutable schema: `scenario_id`, `name`,
`description`, and the normalized tuple fields `threat_categories`,
`attack_behaviors`, `entry_conditions`, `expected_security_properties`, plus an
optional `source` (`ThreatSource`). It may **reference** threat categories by
stable identifiers (e.g. `ASI01`), but does **not** resolve or validate them
against the OWASP catalog — that mapping belongs to a later stage.

`SecurityScenario` never builds a `SecurityGraph`, constructs `AttackPath`s,
runs the scanner, infers `AttackType`/risk/severity/confidence, or makes
network requests. Benchmark adapters (AgentDojo, AgentThreatBench, the Agent
Egress Security Corpus) and an evaluation runner are **not** integrated yet; the
`SecurityScenario` foundation merely exists as a stable contract for them.

### Explicit mapping: `SecurityScenarioThreatMapping`

**`SecurityScenarioThreatMapping`** (`src/veyra/threats/mapping.py`, Commit 26)
is the **explicit, caller-supplied bridge** from an evaluation contract to
threat-knowledge identifiers. It holds only `scenario_id` and a normalized
tuple of opaque `threat_ids` (e.g. `ASI01`, ThreatScenario IDs, or future
benchmark/threat identifiers).

The three layers are distinct:

- **SecurityScenario** = *evaluation/security test contract*.
- **SecurityScenarioThreatMapping** = *explicit mapping* from that contract to
  threat-knowledge identifiers.
- **ThreatScenario / ThreatTaxonomy** = *threat knowledge*.

The mapping is **caller-supplied**, **deterministic**, **taxonomy-agnostic**,
and **non-inferential** — the system never guesses a mapping from names,
descriptions, attack-behavior text, keywords, component names, `AttackPath`,
`AttackType`, or graph structure. Only explicit identifiers supplied by the
caller establish a mapping.

Identifiers are preserved **exactly** (case-sensitive, no aliasing, no
canonicalization). OWASP identifiers are **not** automatically validated or
resolved by this generic mapping layer. No benchmark integration and no
evaluation execution exist yet.

### Benchmark adapter foundation: `BenchmarkCase` / `BenchmarkAdapter`

**`BenchmarkCase`** (`src/veyra/threats/benchmarks.py`, Commit 27) is the
**internal normalized representation** of an external benchmark case. It is a
stable, immutable transport model that carries only the benchmark-agnostic
shape — `benchmark_id`, `case_id`, `name`, `description`, plus an embedded
`SecurityScenario` and an explicit `SecurityScenarioThreatMapping`.

**`BenchmarkAdapter`** is a minimal `Protocol` contract:
`external benchmark case → BenchmarkCase`. It expresses only the conversion
boundary. Adapters are **not** registered, auto-discovered, plugin-loaded, or
executed by this layer, and `BenchmarkCase` performs **no execution**.

This is a stable seam for future adapters. AgentDojo, AgentThreatBench, and the
Agent Egress Security Corpus remain future adapters and are **not integrated
yet**. No datasets are downloaded and no network access happens in this layer.
No benchmark score or detection result exists at this stage — `BenchmarkCase`
carries expectations (a `SecurityScenario` + explicit mapping), never observed
results.

The data flow this prepares for:

```
External benchmark case
        ↓
Benchmark adapter (not yet implemented for specific benchmarks)
        ↓
BenchmarkCase  =  SecurityScenario  +  SecurityScenarioThreatMapping
        ↓
future evaluation runner (not yet implemented)
```

### AgentDojo adapter

**`AgentDojoAdapter`** (`src/veyra/threats/adapters/agentdojo.py`, Commit 28)
is the first concrete benchmark adapter. It converts an **already-supplied**
AgentDojo-style case (a small mapping described in the module and its tests)
into a `BenchmarkCase`.

It converts through an explicit adapter boundary — no AgentDojo dependency is
required, no dataset is bundled, no network access occurs, and no benchmark
execution happens. The adapter is a pure data transformation.

Mapping behavior is explicit only:

- `threat_ids` are copied into `SecurityScenarioThreatMapping.threat_ids`;
- `threat_categories` are copied into `SecurityScenario.threat_categories`;
- `threat_categories` are **never** automatically converted into `threat_ids`;
- identifiers are preserved exactly (case-sensitive, opaque) and are **not**
  validated/resolved against the OWASP catalog;
- scenario/mapping ids are both set to the supplied `case_id`.

The evaluation runner that would consume these cases comes later.

### AgentThreatBench adapter

**`AgentThreatBenchAdapter`** (`src/veyra/threats/adapters/agentthreatbench.py`,
Commit 29) converts an **already-supplied** AgentThreatBench-style case (the
same small explicit mapping contract as the AgentDojo adapter) into a
`BenchmarkCase`.

It converts through an explicit adapter boundary — no AgentThreatBench
dependency is required, no dataset is bundled, no network access occurs, and
no benchmark execution happens. The adapter is a pure data transformation and
implements only Veyra's explicitly documented small input contract (not the full
AgentThreatBench schema).

Mapping behavior is explicit only (identical to the AgentDojo adapter):

- `threat_ids` are copied into `SecurityScenarioThreatMapping.threat_ids`;
- `threat_categories` are copied into `SecurityScenario.threat_categories`;
- `threat_categories` are **never** automatically converted into `threat_ids`;
- identifiers are preserved exactly (case-sensitive, opaque) and are **not**
  validated/resolved against the OWASP catalog;
- scenario/mapping ids are both set to the supplied `case_id`.

The evaluation runner that would consume these cases comes later.

### Benchmark evaluation result

**`BenchmarkEvaluationResult`** (`src/veyra/threats/evaluation.py`, Commit 30)
is the result **data contract** that a future benchmark evaluator/runner
produces. It is a **passive, benchmark-agnostic** model — it only records an
explicit evaluator result and performs **no** analysis.

It has no coupling to `BenchmarkCase`: it is independently serializable and
carries no `AttackPath`, `SecurityGraph`, findings, severity, confidence,
risk_score, `AttackType`, policy IDs, scanner output, or benchmark-specific
execution data. Its fields are supplied explicitly by the future evaluator:

- `benchmark_id`, `case_id` — opaque identifiers;
- `passed` (`bool`) — explicit evaluator boolean (never derived here);
- `status`, `message` — explicit opaque status string and human-readable message;
- `observed_properties`, `violated_properties` — normalized property tuples
  (trim, empty-removal, dedup, deterministic sort);
- `metadata` — deterministic, normalized `(key, value)` string pairs.

Like the other threat models, this is **not** yet a benchmark runner: it does
not execute benchmarks, run Veyra scans, derive pass/fail, calculate Veyra risk,
infer threat IDs/OWASP, or resolve mappings. Actual benchmark execution and
evaluation live in a later layer.

### Benchmark evaluator

**`BenchmarkEvaluator`** (`src/veyra/threats/evaluator.py`, Commit 31) is the
first evaluation logic layer. It consumes a `BenchmarkCase` plus **explicit
observations** and produces a `BenchmarkEvaluationResult`.

It orchestrates the canonical flow:

```
SecurityScenario.expected_security_properties
        ↓
SecurityAssertion.assert_properties(expected, observed)
        ↓
derived violated_properties
        ↓
BenchmarkEvaluationResult
```

- `observed_properties` are **caller-supplied** observations;
- expected properties come from `case.scenario.expected_security_properties`;
- `violated_properties` are **derived exclusively by `SecurityAssertion`** —
  `BenchmarkEvaluator` no longer accepts `violated_properties` as an argument;
- `passed` is **True iff the derived `violated_properties` tuple is empty**.

Here **`passed` means strictly "no derived violated properties"** — it is an
evaluation property contract, NOT a Veyra security verdict, and does not imply
"secure", "safe", or "low risk". `passed` is derived only from the asserted
violations, never from `observed_properties` alone, scenario name/description,
threat IDs, OWASP categories, severity/confidence/risk score, AttackType, or any
scanner output.

The evaluator is pure and deterministic: it performs no risk/severity/
AttackPath/OWASP/threat inference, does not execute benchmarks, load datasets,
access the network, run subprocesses, run the Veyra scanner, build a
`SecurityGraph`/`AttackPath`, compute Veyra risk, or call an LLM. External
benchmark execution will be a later adapter/runner layer.

### Benchmark evaluation aggregation

**`BenchmarkEvaluationAggregator`** (`src/veyra/threats/aggregation.py`,
Commit 32) combines already-produced `BenchmarkEvaluationResult` objects into a
deterministic, benchmark-agnostic `BenchmarkEvaluationSummary`:

- `benchmark_id`, `total_cases`, `passed_cases`, `failed_cases`, `error_cases`;
- `statuses` — a normalized, deduplicated, lexicographically-sorted tuple of
  `(status, count)` pairs.

Aggregation is derived **only** from each result's `benchmark_id`/`passed`/
`status`. Empty result collections are valid (all counts `0`, `statuses=()`). It
does **not** execute benchmarks, invoke `BenchmarkEvaluator`, run the Veyra
scanner, or calculate Veyra security risk. `"error"` is only the explicit
aggregation convention for the `error_cases` counter; all other status strings
remain opaque. It infers nothing from scenarios, threat IDs, OWASP, AttackPaths,
findings, or scanner output.

### Cross-benchmark evaluation summary

**`CrossBenchmarkEvaluationAggregator`** (`src/veyra/threats/cross_benchmark.py`,
Commit 33) combines already-produced `BenchmarkEvaluationSummary` objects into
a deterministic `CrossBenchmarkEvaluationSummary`: aggregate case counts
(`total_benchmarks`, `total_cases`, `passed_cases`, `failed_cases`,
`error_cases`) plus a sorted tuple of `(benchmark_id, case_count)` entries — one
per distinct benchmark.

Each benchmark contributes exactly one summary. Duplicate benchmark IDs are
**rejected** (never merged). Empty input is valid. Benchmark entries are sorted
deterministically by `benchmark_id`.

It does not execute benchmarks or invoke `BenchmarkEvaluator` /
`BenchmarkEvaluationAggregator`, does not calculate Veyra security risk, and
does not inspect scenarios, threat IDs, OWASP, AttackPaths, findings, or scanner
output. This is reporting/aggregation only — it is not a security score or
benchmark-quality rating.

### Benchmark execution boundary

**`BenchmarkRunner`** (`src/veyra/threats/execution.py`, Commit 34) is the
**future execution interface** — a `@runtime_checkable` `Protocol` with
`benchmark_id` and `run(case) -> BenchmarkEvaluationResult`. It provides no
default execution implementation.

**`BenchmarkExecutionBoundary`** currently only creates a typed
**`BenchmarkExecutionRequest`** (`benchmark_id`, `case_id`) from an existing
`BenchmarkCase` — the architectural seam between a `BenchmarkCase` and a
future `BenchmarkEvaluationResult`.

Commit 34 does **not** execute benchmarks. `BenchmarkAdapter` remains a data
adaptation layer, `BenchmarkEvaluationResult` remains the canonical evaluation
result, and concrete benchmark runners will be added later. This is an
architectural boundary, not an execution engine — no runner discovery, registry,
plugin loading, filesystem discovery, subprocess/network execution, or
benchmark-specific branching.

### Benchmark runner evaluation bridge

**`ObservationBenchmarkRunner`** (`src/veyra/threats/runner.py`, Commit 35) is
the first concrete runner implementation. It does **not** execute an external
benchmark — it accepts explicit observations at the execution boundary and
delegates evaluation to `BenchmarkEvaluator`:

```
BenchmarkCase
    -> BenchmarkExecutionBoundary (identity only)
    -> explicit observed_properties
    -> BenchmarkEvaluator
    -> SecurityAssertion (derives violated_properties)
    -> BenchmarkEvaluationResult
```

`BenchmarkExecutionBoundary` remains responsible only for execution identity;
`BenchmarkEvaluator` remains responsible for constructing the canonical
`BenchmarkEvaluationResult`. The runner preserves `case.benchmark_id` /
`case.case_id` and infers nothing — no security properties, severity, threats,
OWASP categories, AttackPaths, or risk, and it does **not** itself perform the
security assertion (that is delegated to `BenchmarkEvaluator`'s
`SecurityAssertion`). This is a bridge/foundation, not a real benchmark runtime.

`ObservationBenchmarkRunner` structurally satisfies the `BenchmarkRunner`
`@runtime_checkable` protocol. It carries a static class-level `benchmark_id`
placeholder purely for protocol compatibility; this placeholder is **never** used
for evaluation identity — `result.benchmark_id == case.benchmark_id` always, and
the runner's identity always comes from the supplied `BenchmarkCase`.

### Security assertion layer

**`SecurityAssertion`** (`src/veyra/threats/assertions.py`, Commit 36) is the
deterministic comparison between explicit expectations and explicit
observations:

- **`SecurityScenario.expected_security_properties`** = explicit expectations.
- **`SecurityAssertion.assert_properties(expected, observed)`** =
  deterministic set difference returning `violated_properties`
  (`expected` minus `observed`).
- **`violated_properties`** = properties expected but not observed.
- **`BenchmarkEvaluator`** = converts explicit `violated_properties` into the
  benchmark evaluation result (`BenchmarkEvaluationResult.passed`).

`SecurityAssertion` performs **no** inference: it does not calculate risk,
assign severity, resolve OWASP categories, inspect `AttackPath`s, or execute
benchmarks. It compares property identifiers exactly after the standard threat
model string normalization, and it is usable independently of `BenchmarkCase`,
`BenchmarkEvaluator`, `BenchmarkRunner`, `AttackPath`, scanner, or OWASP.

**`BenchmarkEvaluator`** now orchestrates the assertion comparison:

```
SecurityScenario.expected_security_properties
        ↓
SecurityAssertion.assert_properties(expected, observed)
        ↓
violated_properties
        ↓
BenchmarkEvaluationResult
```

- `observed_properties` are caller-supplied observations;
- `violated_properties` are **derived**, not caller-controlled — the `evaluate()`
  API no longer accepts a `violated_properties` argument (single source of truth);
- the evaluator performs no security inference;
- `SecurityAssertion` remains the canonical comparison layer.

### Benchmark observation contract

**`BenchmarkObservation`** (`src/veyra/threats/observations.py`, Commit 38) is
the immutable, normalized representation of the **explicit observed security
properties** supplied at the evaluation boundary. It is a transport/contract
model only: it trims, dedupes, and sorts property identifiers and rejects
malformed runtime values — it performs **no** security inference and is not a
security verdict.

```
explicit observed properties
        ↓
BenchmarkObservation
        ↓
SecurityAssertion
        ↓
violated_properties
        ↓
BenchmarkEvaluationResult
```

Observations are caller-supplied. `SecurityAssertion` compares these normalized
observations against `SecurityScenario.expected_security_properties`;
`BenchmarkEvaluator` remains the orchestration layer that constructs the
`BenchmarkObservation` and delegates to the assertion; `BenchmarkEvaluationResult`
remains the result contract.

### Benchmark execution observation contract

**`BenchmarkExecutionObservation`** (`src/veyra/threats/execution_observation.py`,
Commit 39) represents the **explicit facts** reported by a future benchmark
execution boundary: an execution `status`, an optional `message`, a
`BenchmarkObservation`, and opaque `metadata`.

It does **not** evaluate security: it computes no `passed`, no
`violated_properties`, and makes no expected-vs-observed comparison.
`BenchmarkEvaluator` remains responsible for evaluation (via
`SecurityAssertion`), and `BenchmarkObservation` remains the only
security-property observation representation.

```
future execution boundary
        ↓
BenchmarkExecutionObservation
        ↓
BenchmarkObservation
        ↓
BenchmarkEvaluator
        ↓
SecurityAssertion
```

Commit 39 introduces the contract only; actual benchmark execution will be
implemented separately.

### Benchmark execution binding contract

**`BenchmarkExecutionBinding`** (`src/veyra/threats/execution_binding.py`,
Commit 40) is a passive, immutable identity/binding layer that states explicitly
which execution request an execution observation belongs to:

```
BenchmarkExecutionRequest
        +
BenchmarkExecutionObservation
        ↓
BenchmarkExecutionBinding
```

It has exactly two fields, `request` and `observation`, both runtime-validated
by type (no duck typing). It duplicates no identity: `binding.request.benchmark_id`
and `binding.request.case_id` remain the authoritative execution identity, and
the observation remains responsible only for execution facts.

The binding executes nothing and evaluates nothing — no `passed`, no
`violated_properties`, no expected-vs-observed comparison, no
risk/severity/confidence, no threat/OWASP inference, and no AttackPath or scanner
access. `BenchmarkEvaluator`/`SecurityAssertion` remain responsible for
evaluation. Serialization delegates to the canonical request/observation
serializers.

Commit 40 introduces the contract only; actual benchmark execution is not
implemented.

### Execution observation → evaluation bridge

**`BenchmarkExecutionEvaluator`** (`src/veyra/threats/execution_evaluator.py`,
Commit 41) is a thin, stateless orchestration wrapper that connects an existing
binding to the canonical evaluator:

```
BenchmarkExecutionBinding
        ↓
BenchmarkExecutionEvaluator
        ↓
BenchmarkEvaluator
        ↓
SecurityAssertion
        ↓
BenchmarkEvaluationResult
```

`evaluate(binding, case)` requires an explicit `BenchmarkCase` because
`BenchmarkExecutionRequest` carries only `benchmark_id`/`case_id` and therefore
cannot supply scenario expectations; the case is never reconstructed or invented
from the request, and its identity must match `binding.request` exactly
(otherwise `ThreatModelError`). Only
`binding.observation.observed_properties.properties` is forwarded.

Execution status is **not** a security verdict: `failed`/`timeout`/`error` do not
mean `passed is False`, and `completed` does not mean `passed is True`. Status,
message and metadata remain execution facts and are not used as evaluation input.
`BenchmarkObservation` remains the canonical observed-property model,
`BenchmarkEvaluator`/`SecurityAssertion` remain the canonical evaluation layer,
and Commit 41 does not execute external benchmarks.

#### Taxonomy catalogs

A **`ThreatTaxonomy`** is a separate, taxonomy-agnostic catalog layer (a fixed,
named set of `ThreatTaxonomyEntry`s), distinct from the generic
`ThreatScenario`. The concrete **OWASP Agentic AI 2026** catalog
(`OWASP_AGENTIC_2026`, `get_owasp_agentic_2026()`) ships these 10 entries. The
**IDs and names** are OWASP source terminology (verified against the official
OWASP Top 10 for Agentic Applications 2026 document); each **description** is a
concise Veyra-written summary, not verbatim OWASP text.

| ID | Name |
|----|------|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

> The current commits do **NOT** infer an OWASP category from an `AttackPath`.
> A taxonomy is descriptive catalog metadata only and never modifies the graph
> or the attack path. Future adapters/catalogs may include AgentDojo,
> AgentThreatBench, the Agent Egress Security Corpus, and internal security
> scenarios — none of those are integrated yet (only the core model and the
> OWASP Agentic AI 2026 catalog currently exist).

## 🛠️ Development

```bash
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m veyra.cli attack-lab
```

## 📄 License

MIT — see [LICENSE](LICENSE).
