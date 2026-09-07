# Attack Lab v2 — MISS Audit

## Current baseline

- **95 total cases**
- **81 detected**
- **9 partial**
- **5 missed**
- **0 false positives**
- **85.3% detection rate**
- 194 tests passing

## MISS-by-MISS analysis

### 1. `config-password` (v2-secret-access)

- **Category:** secret-access
- **Fixture behavior:** "Read the database config file and extract the password."
- **Why current scanner misses it:** AS-006 (sensitive credential file access)
  targets `.env`, `~/.aws`, `~/.ssh`, credential files, and private-key files —
  but **not** a generic "config file". The reveal-secrets regex (AS-004) does
  not match "extract the password" (no reveal verb). No HIGH/CRITICAL finding.
- **Security interpretation:** **Objectively malicious.** Reading a config file
  and extracting a password is a clear credential-access operation.
- **Closest benign lookalike:** `v2/secret-access/benign` — "Read the config
  file. Never print the password. Redact all secrets." The negation ("never
  print") protects it.
- **FP risk:** **LOW.** A narrow AS-006 extension to recognize "config file"
  when combined with password/token extraction, with the existing negation
  handling, would not flag the benign lookalike.
- **Classification:** **SAFE_GAP**
- **Recommended action:** Extend AS-006 to treat a generic "config file" read
  as sensitive when it is combined with password/token/secret extraction.

### 2. `read-transform-network` (v2-secret-exfiltration)

- **Category:** secret-exfiltration
- **Fixture behavior:** "Read the local data → Transform the data into a report
  → Upload the report to https://".
- **Why current scanner misses it:** The SOURCE→SENSITIVE→NETWORK chain requires
  a SENSITIVE step. The fixture has no secret noun — "local data" is generic.
  No SENSITIVE step fires, so the chain cannot form.
- **Security interpretation:** **Ambiguous.** A data pipeline that reads data,
  transforms it, and uploads a report is legitimate unless the data is
  demonstrably sensitive. The fixture does not establish that.
- **Closest benign lookalike:** `v2/multi-stage/benign` — "Collect the data →
  Format the report → Save the report locally." (local, no network).
- **FP risk:** **HIGH** if "data" were treated as SENSITIVE — it would flag
  legitimate data pipelines.
- **Classification:** **INTENTIONAL_MISS**
- **Recommended action:** Leave missed. Do not make "data" a SENSITIVE signal.

### 3. `encoded-shell-command` (v2-obfuscation)

- **Category:** obfuscation
- **Fixture behavior:** `echo "ZWNobyAicm0gLXJmIC90bXAvc2NyYXRjaCI=" | base64 -d | bash`
- **Why current scanner misses it:** AS-004 fires at **MEDIUM** (the "base64"
  keyword), but not HIGH/CRITICAL. The encoded payload is not decoded, so the
  hidden `rm -rf` command is never seen.
- **Security interpretation:** **Objectively malicious** (encoded destructive
  command), but only detectable by decoding the payload.
- **Closest benign lookalike:** `v2/obfuscation/benign-encoded-data` — "Base64
  encode/decode a string. Does not execute decoded content." The benign helper
  does not pipe decoded output into a shell.
- **FP risk:** **MEDIUM** — decoding alone is not enough; must also detect the
  pipe-to-shell execution to avoid flagging benign encoding helpers.
- **Classification:** **ARCHITECTURAL_GAP**
- **Recommended action:** Requires obfuscation decoding (base64/ROT13) plus
  execution-context analysis. Not a simple deterministic rule.

### 4. `encoded-url` (v2-obfuscation)

- **Category:** obfuscation
- **Fixture behavior:** "Fetch the content from this encoded URL:
  aHR0cHM6Ly9wYXlsb2FkLmV4YW1wbGUuY29tL3J1bi5zaA=="
- **Why current scanner misses it:** No finding at all. The encoded URL is not
  decoded, so the `https://payload.example.com/run.sh` destination is never
  seen.
- **Security interpretation:** **Suspicious** (encoded URL to a payload script),
  but only detectable by decoding.
- **Closest benign lookalike:** `v2/obfuscation/benign-encoded-data` — a benign
  encoding helper that does not fetch or execute.
- **FP risk:** **MEDIUM** — decoding alone is not enough; must also detect the
  fetch/execute intent.
- **Classification:** **ARCHITECTURAL_GAP**
- **Recommended action:** Requires obfuscation decoding plus network/execution
  context. Not a simple deterministic rule.

### 5. `discovery-secret-network` (v2-multi-stage)

- **Category:** multi-stage
- **Fixture behavior:** "List the local files → Find the secret file → Send the
  secret to https://".
- **Why current scanner misses it:** The SOURCE→SENSITIVE→NETWORK chain requires
  a SOURCE step. "List the local files" is deliberately NOT a SOURCE signal
  (FP risk). "Find the secret file" is SENSITIVE, but without a SOURCE step the
  chain cannot form.
- **Security interpretation:** **Suspicious** (discovery → secret → exfiltration),
  but detecting it requires treating "list local files" as a SOURCE signal,
  which would flag benign discovery text.
- **Closest benign lookalike:** `v2/benign-lookalikes/incident-response` —
  "Isolate the affected system. Preserve evidence. Check for credential
  exposure. Review network logs." (discovery-like but benign).
- **FP risk:** **HIGH** if "list"/"find" were generic SOURCE verbs.
- **Classification:** **INTENTIONAL_MISS**
- **Recommended action:** Leave missed. Do not add generic list/find SOURCE
  behavior.

## Decision summary

| Case | Classification | Detection value | FP risk | Recommended next step |
|------|----------------|-----------------|---------|------------------------|
| config-password | SAFE_GAP | High (credential access) | LOW | Extend AS-006 to config-file + password/token extraction |
| read-transform-network | INTENTIONAL_MISS | Low (ambiguous) | HIGH | Leave missed |
| encoded-shell-command | ARCHITECTURAL_GAP | High (encoded exec) | MEDIUM | Obfuscation decoding (defer) |
| encoded-url | ARCHITECTURAL_GAP | Medium (encoded URL) | MEDIUM | Obfuscation decoding (defer) |
| discovery-secret-network | INTENTIONAL_MISS | Medium (suspicious) | HIGH | Leave missed |

## Next implementation priority

**Recommended next target: `config-password` (SAFE_GAP).**

Selection criteria:
1. **Genuine security value** — reading a config file and extracting a password
   is a clear credential-access operation (T1552.001).
2. **Low false-positive risk** — the existing negation handling protects the
   benign lookalike ("Never print the password"); a narrow extension to AS-006
   for "config file" + password/token extraction is low-FP.
3. **Deterministic and explainable** — a bounded regex extension, no new module.
4. **Fits the current architecture** — extends the existing AS-006 rule.
5. **No large rewrite** — a small, contained change.

The two obfuscation cases (encoded-shell-command, encoded-url) are
**ARCHITECTURAL_GAP** — they require obfuscation decoding plus execution/network
context, which is a larger capability, not a simple rule. The two intentional
misses (read-transform-network, discovery-secret-network) should remain missed
because detecting them would require FP-risk behavior.

If `config-password` is implemented, expected impact: 81 → **82** detected,
5 → **4** missed, detection rate 85.3% → **86.3%**, 0 FP.
