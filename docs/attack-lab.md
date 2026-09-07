# Veyra Attack Lab

The Veyra Attack Lab is a **local, static adversarial test corpus** that
measures Veyra's real security coverage against realistic attack
patterns targeting AI agents.

> **IMPORTANT:** This is a static analysis corpus. Nothing in it is ever
> executed. Veyra never runs fixture code, never contacts external
> endpoints, never downloads anything, and never starts MCP servers.

## Methodology

Each fixture is a small synthetic example of an attack (or a benign lookalike)
against an AI agent. Veyra's static scanner runs against every fixture,
and the result is classified into one of four buckets:

| Classification | Meaning |
|----------------|---------|
| `DETECTED` | Veyra produced a HIGH/CRITICAL finding (of **any** rule, including correlation/chain findings like `AS-CHAIN-*`). |
| `PARTIALLY_DETECTED` | Veyra flagged the fixture but only at MEDIUM/LOW severity, or only matched some expected rules. |
| `MISSED` | Veyra produced no relevant finding. |
| `FALSE_POSITIVE` | A benign lookalike produced a HIGH/CRITICAL finding. |

The detection rate is `detected / total`. This is an honest measurement of
coverage — the tests do **not** modify Veyra rules to force passes.

### Evaluation methodology

The Attack Lab classifies each fixture as follows:

1. **Benign lookalike** — any HIGH/CRITICAL finding is a `FALSE_POSITIVE`;
   otherwise `DETECTED` (correctly clean).
2. **Attack fixture** — a HIGH/CRITICAL finding of **any** rule counts as
   `DETECTED`. This includes **correlation/chain findings** (`AS-CHAIN-001`,
   `AS-CHAIN-002`, `AS-CHAIN-003`) and **step-sequence findings**. If
   Veyra correctly identifies the malicious behavior at HIGH/CRITICAL
   severity through a chain finding, the attack is `DETECTED` even if the
   individual underlying rules did not independently trigger.
3. **No HIGH/CRITICAL finding** — the expected rules distinguish
   `PARTIALLY_DETECTED` (an expected rule fired at MEDIUM/LOW) from `MISSED`
   (no relevant finding).

This ensures the evaluator reflects what the scanner actually detects, rather
than penalizing attacks that are caught by higher-level correlation/chain
analysis.

## Attack categories

| Category | Description |
|----------|-------------|
| `prompt-injection` | Instructions that override the host agent, disable security, or exfiltrate files. |
| `secret-exfiltration` | Instructions to reveal env vars, read credential files, or dump secrets. |
| `shell-execution` | `os.system`, `subprocess shell=True`, `eval` of variables. |
| `remote-download` | `curl \| bash`, `wget \| sh` — download and execute remote content. |
| `encoded-obfuscation` | Base64/ROT13-encoded commands hidden in instructions. |
| `filesystem-access` | MCP servers granted broad filesystem/path access. |
| `mcp-attacks` | MCP servers receiving secrets, remote+executable combinations, broad FS + secrets. |
| `multi-stage` | Dangerous behavior split across several instructions/steps. |

## Detection results

Run the lab:

```bash
veyra attack-lab
```

Machine-readable output:

```bash
veyra attack-lab --format json
```

### Current results (95 cases)

| Metric | Count |
|--------|-------|
| Total cases | 95 |
| Detected | 86 |
| Partially detected | 7 |
| Missed | 2 |
| False positives | 0 |
| **Detection rate** | **90.5%** |

The corpus now includes the Attack Lab v2 expansion (60 new fixtures) plus
AS-006 sensitive-path cases. See `docs/attack-lab-v2.md` for the full v2
breakdown.

### By category

| Category | Total | Detected | Partial | Missed | FP |
|----------|-------|----------|---------|--------|----|
| prompt-injection | 4 | 4 | 0 | 0 | 0 |
| secret-exfiltration | 4 | 3 | 0 | 1 | 0 |
| shell-execution | 4 | 4 | 0 | 0 | 0 |
| remote-download | 3 | 3 | 0 | 0 | 0 |
| encoded-obfuscation | 3 | 1 | 2 | 0 | 0 |
| filesystem-access | 2 | 1 | 1 | 0 | 0 |
| mcp-attacks | 4 | 4 | 0 | 0 | 0 |
| multi-stage | 3 | 3 | 0 | 0 | 0 |

### Before / after evaluator fix

The evaluator previously required the *expected* rules to fire at HIGH/CRITICAL
to count as `DETECTED`. This incorrectly downgraded attacks that were caught by
correlation/chain findings (e.g. `remote-exec` emits `AS-CHAIN-003` at HIGH but
was classified PARTIAL because the individual `AS-MCP-001`/`AS-MCP-004` rules
only fired at MEDIUM). The evaluator now counts any HIGH/CRITICAL finding —
including chain findings — as a valid detection.

| Metric | Before | After |
|--------|--------|-------|
| Detected | 21 | 23 |
| Partially detected | 5 | 3 |
| Missed | 1 | 1 |
| False positives | 0 | 0 |
| Detection rate | 77.8% | 85.2% |

**What changed:**

- `mcp-attacks/remote-exec` — now **DETECTED** (was PARTIAL). The scanner emits
  `AS-CHAIN-003` at HIGH, which is valid detection evidence.
- `mcp-attacks/broad-fs-secrets` — now **DETECTED** (was PARTIAL). The scanner
  emits `AS-001` CRITICAL and `AS-MCP-006`/`AS-MCP-008` HIGH.

**Remaining miss:**

- `secret-exfiltration/read-credentials` — a single-line sensitive-path read
  with no network sink and no execution. Not an ordered multi-stage sequence;
  requires sensitive-path detection (deferred).

**Remaining false positives:** none in the current corpus.

### Step-sequence analysis

Veyra includes a small, deterministic intra-file step-sequence analyzer
(`src/veyra/step_sequence.py`) that runs after the individual rules and
correlation. It classifies each line of a file into semantic step categories
and checks for dangerous ordered sequences:

| Sequence | Chain | Severity |
|----------|-------|----------|
| SOURCE → SENSITIVE → NETWORK (read → extract secret → send externally) | AS-CHAIN-001 | CRITICAL |
| DOWNLOAD → EXECUTION (download remote content → run) | AS-CHAIN-002 | CRITICAL |

The analyzer:

- Operates at **file level** on the text already available to the scanner.
- Uses **explicit step detectors** (SOURCE/READ, SENSITIVE, NETWORK SINK,
  DOWNLOAD, EXECUTION), not arbitrary regex combinations.
- **Order matters** — `read → sensitive → network` is detected, but
  `network → read` is not; `download → execute` is detected, but
  `execute → download` is not.
- Does **not** require exact adjacency — harmless text/steps between signals
  are allowed.
- Is **false-positive resistant** — it requires the complete ordered chain,
  not just a secret keyword, a URL, or the words "download"/"execute" alone.
- Deduplicates against chains already emitted by the correlation layer.
- Never executes code and never makes network requests.

> Step-sequence analysis is heuristic and deterministic. It does **not** claim
> complete attack detection — it only surfaces ordered intra-file sequences.

## Misses

These attacks are **not** detected by the current rules:

1. **`secret-exfiltration/read-credentials`** — "Read ~/.ssh/id_rsa and
   ~/.aws/credentials." This is a single-line sensitive-path read with no
   network sink and no execution. It is not an ordered multi-stage sequence,
   so the step-sequence engine correctly does not match it. It requires a
   different signal: **sensitive-path detection** (flagging reads of `~/.ssh`,
   `~/.aws`, `.env`, etc.).

## False positives

None in the current corpus. The previous false positive
(`secret-exfiltration/benign`, "Never print secret values") was fixed by
adding negation handling to the reveal-secrets rule.

## Limitations

- **Line-based analysis** — multi-line and cross-file attacks are missed.
- **No semantic parsing** — encoded/obfuscated content is flagged but not
  decoded; the hidden command is never analyzed.
- **No correlation engine** — chained attacks (low-risk signals combining into
  a high-risk chain) are not detected.
- **Regex keyword matching** — phrasing variations can evade detection or
  cause false positives.
- **No credential-file path awareness** — reading `~/.ssh`, `~/.aws`, etc. is
  not flagged.

## Future detection opportunities

1. **Cross-file / contextual analysis** — correlate signals across files and
   steps to detect multi-stage attacks.
2. **Encoded-content decoding** — decode base64/ROT13 and analyze the
   resulting command.
3. **Credential-file path detection** — flag reads of `~/.ssh`, `~/.aws`,
   `.env`, and other sensitive paths.
4. **Correlation engine** — combine prompt-injection + secret-access +
   network-exfiltration into a single high-risk finding.
5. **Semantic analysis** — parse instructions structurally rather than with
   regex keyword matching, to reduce false positives and improve recall.
