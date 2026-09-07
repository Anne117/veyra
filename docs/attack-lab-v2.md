# Attack Lab v2

## Baseline

Original corpus (v1):

- 27 fixtures
- 23 detected
- 3 partial
- 1 missed
- 0 FP
- 85.2% detection rate

## Expanded corpus

Added **60 new fixtures** across 8 categories (A–H), bringing the total to **87**.

| Category | New fixtures |
|----------|--------------|
| v2-prompt-injection | 8 |
| v2-secret-access | 8 |
| v2-secret-exfiltration | 7 |
| v2-download-execution | 8 |
| v2-mcp-security | 9 |
| v2-obfuscation | 5 |
| v2-multi-stage | 5 |
| v2-benign-lookalikes | 10 |

## Results by category

| Category | Total | Detected | Partial | Missed | FP |
|----------|-------|----------|---------|--------|----|
| prompt-injection (v1) | 4 | 4 | 0 | 0 | 0 |
| secret-exfiltration (v1) | 4 | 3 | 0 | 1 | 0 |
| shell-execution (v1) | 4 | 4 | 0 | 0 | 0 |
| remote-download (v1) | 3 | 3 | 0 | 0 | 0 |
| encoded-obfuscation (v1) | 3 | 1 | 2 | 0 | 0 |
| filesystem-access (v1) | 2 | 1 | 1 | 0 | 0 |
| mcp-attacks (v1) | 4 | 4 | 0 | 0 | 0 |
| multi-stage (v1) | 3 | 3 | 0 | 0 | 0 |
| v2-prompt-injection | 8 | 3 | 0 | 5 | 0 |
| v2-secret-access | 8 | 2 | 0 | 6 | 0 |
| v2-secret-exfiltration | 7 | 4 | 0 | 3 | 0 |
| v2-download-execution | 8 | 6 | 0 | 2 | 0 |
| v2-mcp-security | 9 | 5 | 4 | 0 | 0 |
| v2-obfuscation | 5 | 1 | 2 | 2 | 0 |
| v2-multi-stage | 5 | 3 | 0 | 2 | 0 |
| v2-benign-lookalikes | 10 | 10 | 0 | 0 | 0 |

## Overall results

- **Total fixtures:** 95
- **Detected:** 86
- **Partial:** 7
- **Missed:** 2
- **False positives:** 0
- **Detection rate:** 90.5%

The expanded corpus is significantly harder than v1 (85.2% → 65.5% at v2
launch). After adding AS-006 (sensitive credential file access), broadening
the AS-004 reveal/send patterns (Bucket A), broadening the step-sequence
classifiers (Bucket C), adding multi-action line splitting, extending AS-006
to config-file + credential extraction, and adding AS-007 (obfuscation
decoding with execution/fetch context), the rate rose to 90.5% with 0 false
positives.

### AS-006 impact

AS-006 (Sensitive Credential File Access) was added to close the largest v2
gap. It detects actual read/access operations against `.env`, `~/.aws`,
`~/.ssh`, and credential/private-key files, while ignoring benign mentions
("never read ~/.aws/credentials", "do not expose .env").

| Metric | Before AS-006 | After AS-006 |
|--------|---------------|--------------|
| Total fixtures | 87 | 95 |
| Detected | 57 | 74 |
| Partial | 9 | 9 |
| Missed | 21 | 12 |
| False positives | 0 | 0 |
| Detection rate | 65.5% | 77.9% |

AS-006 fixed 6 v2-secret-access misses and the v1 `read-credentials` miss
(now DETECTED). All 8 v2-sensitive-path cases are detected, and all 10
benign-lookalikes remain clean (0 FP).

### Bucket A impact (AS-004 regex broadening)

The AS-004 reveal-secrets and send-files patterns were broadened with bounded
filler tolerance ("the value of", "the contents of", "of the local database
config") to fix 4 wording-gap misses.

| Metric | Before Bucket A | After Bucket A |
|--------|-----------------|----------------|
| Detected | 74 | 79 |
| Partial | 9 | 9 |
| Missed | 12 | 7 |
| False positives | 0 | 0 |
| Detection rate | 77.9% | 83.2% |

Fixed: `reveal-secrets-indirect`, `role-impersonation`, `send-data-external`,
`api-token` — all now DETECTED. All 10 benign-lookalikes remain clean, and the
negation handling still suppresses "never reveal secrets", "do not print API
keys", "must not send secrets externally".

### Bucket C impact (step-sequence broadening)

The step-sequence classifiers were broadened in a bounded way: EXECUTION now
recognizes "package" in an execution context and "run it"/"run the script";
DOWNLOAD recognizes "retrieve" when followed by a remote source; SENSITIVE
recognizes "find" when combined with a secret noun; SOURCE recognizes "data"
as a source noun.

| Metric | Before Bucket C | After Bucket C |
|--------|-----------------|----------------|
| Detected | 79 | 80 |
| Partial | 9 | 9 |
| Missed | 7 | 6 |
| False positives | 0 | 0 |
| Detection rate | 83.2% | 84.2% |

Fixed: `remote-package-execute` (now DETECTED). The other 3 target cases
(`read-transform-network`, `indirect-wording`, `discovery-secret-network`)
remain MISSED for structural reasons — see the remaining-misses section. All 10
benign-lookalikes remain clean (0 FP).

### Multi-action line splitting

The step-sequence analyzer now splits a single line into multiple logical
steps on deterministic separators (`and then`, `then`, `;`), preserving order.
This lets "Retrieve the script from the remote server and then run it." emit
DOWNLOAD → EXECUTION → AS-CHAIN-002.

| Metric | Before | After |
|--------|--------|-------|
| Detected | 80 | 81 |
| Partial | 9 | 9 |
| Missed | 6 | 5 |
| False positives | 0 | 0 |
| Detection rate | 84.2% | 85.3% |

Fixed: `indirect-wording` (now DETECTED). `read-transform-network` and
`discovery-secret-network` remain intentionally MISSED (see remaining-misses).
All 10 benign-lookalikes remain clean (0 FP).

### AS-006 config-file extension

AS-006 was extended to detect a generic config-file access when combined with
explicit credential extraction (password/token/secret/credential/API key).
Config-file access alone is still not flagged.

| Metric | Before | After |
|--------|--------|-------|
| Detected | 81 | 82 |
| Partial | 9 | 9 |
| Missed | 5 | 4 |
| False positives | 0 | 0 |
| Detection rate | 85.3% | 86.3% |

Fixed: `config-password` (now DETECTED). All 10 benign-lookalikes remain clean
(0 FP).

### AS-007 obfuscation decoding

AS-007 (Encoded content executed / fetched) decodes base64/ROT13 content
deterministically and only raises a finding when the decoded content is
combined with an execution context (`| base64 -d | bash`) or a fetch/execute
intent ("Fetch the content from this encoded URL"). Decoding alone is never a
signal.

| Metric | Before | After |
|--------|--------|-------|
| Detected | 82 | 86 |
| Partial | 9 | 7 |
| Missed | 4 | 2 |
| False positives | 0 | 0 |
| Detection rate | 86.3% | 90.5% |

Fixed: `encoded-shell-command`, `encoded-url` (both now DETECTED), plus
`base64-exec` and `base64-instruction` (improved from PARTIAL to DETECTED).
`rot13-exec`/`rot13-instruction` remain PARTIAL (ROT13 payloads without an
explicit indicator are not decoded). All 10 benign-lookalikes remain clean
(0 FP).

## Newly discovered detection gaps

The most important remaining misses (after AS-006, Bucket A, Bucket C,
multi-action line splitting, the AS-006 config-file extension, and AS-007):

1. **`v2-secret-exfiltration/read-transform-network`** — "read → transform →
   network" without an explicit secret step. The step-sequence SENSITIVE step
   is not triggered (no secret noun in the chain). **Intentionally MISSED** —
   the fixture's "local data" is not demonstrably sensitive.

2. **`v2-multi-stage/discovery-secret-network`** — "List the local files →
   find the secret file → send to https://". "List the local files" is
   deliberately NOT a SOURCE signal (FP risk); the chain cannot form.
   **Intentionally MISSED.**

## False positives

**0 false positives** in the expanded corpus. All 10 benign-lookalike fixtures
(secrets documentation, secure coding, never-reveal policies, legitimate
dependencies, local builds, legitimate MCP, env vars, HTTP requests, security
tutorials, incident response) were correctly classified as clean.

Notably, the negation fix holds: "never reveal secrets", "do not print API
keys", "must not disclose API keys" are all correctly treated as benign. AS-006
also correctly ignores benign mentions of sensitive paths ("never read
~/.aws/credentials", "do not expose .env").

## Architecture implications

The remaining gaps suggest the following requirements (analysis only — no
implementation proposed):

- **Improved reveal-secrets regex** (indirect wording, role impersonation,
  send-data-external): broader verb/noun coverage, or semantic parsing of
  instruction intent.
- **Config-file credential reads** (config-password, api-token): reading a
  generic config file that contains a password/token is not covered by AS-006
  (which targets `.env`/`~/.aws`/`~/.ssh`/credential files). A broader
  "credential-bearing config read" rule could close this.
- **Step-sequence SENSITIVE/EXECUTION broadening** (read-transform-network,
  remote-package-execute): the SENSITIVE and EXECUTION steps require specific
  verb/noun lists that miss some phrasings.
- **Encoded-content decoding** (encoded-shell-command, encoded-url): requires
  decoding base64/ROT13 and analyzing the result — semantic analysis, not a
  simple rule.
- **Cross-file / contextual analysis** (multi-stage variants): some multi-stage
  attacks split behavior across steps that do not individually produce the
  required signal combination.

## Intentionally out of scope

- **Obfuscation decoding** — requires semantic analysis; not a deterministic
  rule.
- **Role impersonation** — an AI-agent-specific manipulation vector that does
  not map cleanly to a keyword rule.
