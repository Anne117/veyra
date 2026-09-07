# Veyra Data-Flow Architecture Audit

## 1. Executive summary

Veyra is a deterministic, static, mostly line-based heuristic scanner for
AI agent Skills and MCP resources. It currently achieves 90.5% on its internal
95-case Attack Lab corpus with 0 false positives on the benign lookalikes.

The two remaining MISS cases (`read-transform-network`,
`discovery-secret-network`) and several PARTIAL cases share a common root cause:
the engine classifies **lines** into coarse step categories but does not track
**what data flows** between steps. The smallest safe next step is a **normalized
action model** — parse each line into a structured `Action` (verb + object +
destination) rather than a bare category string — and then a **lightweight
intra-file taint/source→sink correlation** over those actions.

This is deliberately NOT a full AST/data-flow framework. It is a bounded,
deterministic extension of the existing `step_sequence.py` architecture.

## 2. Current architecture

The pipeline (verified in `scanner.py`):

```
Input path
  → walk files (skip .git/node_modules/venv, skip >1MB, skip binary)
  → per file: decode UTF-8
      → line rules (AS-001..006) on each line
      → file rules (AS-MCP-*, AS-007) on full text
  → collect findings + file texts
  → correlation (AS-CHAIN-001/002/003) over all findings
  → step-sequence analysis per file (AS-CHAIN-001/002) with multi-action split
      (dedup against correlation-emitted chains)
  → attach MITRE/CWE/confidence/matched_text
  → ScanResult
  → suppression (in CLI)
  → reporter (terminal / JSON / SARIF)
  → exit code (fail-on threshold)
```

| Stage | Input | Output | Data structure | Scope | Assumptions / limitations |
|-------|-------|--------|----------------|-------|---------------------------|
| Parsing | path | file texts | list of (text, path) | per-file | skips binary/oversized; UTF-8 decode |
| Line rules | one line | findings | `Finding` | per-line | regex; misses multi-line constructs |
| File rules (MCP, obfuscation) | full text | findings | `Finding` | per-file | structural JSON/YAML parse; base64/ROT13 decode |
| Correlation | all findings | chain findings | `Finding` (AS-CHAIN-*) | across files | maps rule IDs to signals; no data-flow |
| Step-sequence | file text | chain findings | list of step category strings | per-file | classifies lines into coarse categories; no data tracking |
| Metadata | findings | enriched findings | `Finding` | per-finding | MITRE/CWE/confidence/matched_text |
| Suppression | findings | suppressed findings | `Finding` | per-finding | `.veyra.toml` allowlist |
| Scoring | findings | score/risk | int + level | per-scan | severity-weighted, capped 100 |
| Reporters | ScanResult | text/JSON/SARIF | — | per-scan | terminal/JSON/SARIF 2.1.0 |

**Key limitation:** `step_sequence.py` reduces each line to a single category
string (`SOURCE`, `SENSITIVE`, `NETWORK`, `DOWNLOAD`, `EXECUTION`) and then
searches for an ordered subsequence. It does **not** track which object a
`SOURCE` reads, which value a `SENSITIVE` extracts, or whether the `NETWORK`
sink sends that same value. This is the root cause of the two MISS cases.

## 3. Current Attack Lab gap analysis

| Case | Current result | Root cause | Required capability | Safe to add now? |
|------|----------------|-----------|---------------------|------------------|
| `read-transform-network` | MISSED | No SENSITIVE step; "local data" is generic, not a secret noun | intra-file data-flow: track that the data read is the data sent | Yes (bounded) |
| `discovery-secret-network` | MISSED | "List local files" is not a SOURCE (FP risk); chain needs SOURCE→SENSITIVE→NETWORK | intra-file data-flow: "find the secret file" → "send the secret" | Yes (bounded) |
| `rot13-exec` | PARTIAL | ROT13 payload not decoded without explicit indicator | obfuscation: decode ROT13 when a command context is present | Defer (FP risk) |
| `rot13-instruction` | PARTIAL | Same as above | obfuscation | Defer |
| `broad-fs` (v1) | PARTIAL | MCP MEDIUM findings only, no HIGH/CRITICAL | MCP semantic: broad FS + dynamic exec → HIGH | Yes (MCP) |
| `remote-endpoint` (v2) | PARTIAL | Remote MCP endpoint alone is MEDIUM (by design) | MCP semantic: endpoint + other risk signals | Yes (MCP) |
| `dynamic-package` (v2) | PARTIAL | MEDIUM findings only | MCP semantic | Yes (MCP) |
| `uvx-exec` (v2) | PARTIAL | MEDIUM findings only | MCP semantic | Yes (MCP) |
| `broad-fs` (v2) | PARTIAL | MEDIUM findings only | MCP semantic | Yes (MCP) |

**Signal classification:**
- `read-transform-network`: **C. intra-file data-flow** (the data read is the
  data sent, but no secret noun appears).
- `discovery-secret-network`: **C. intra-file data-flow** (the secret found is
  the secret sent).
- `rot13-*`: **A. lexical / obfuscation** (needs decoding).
- MCP PARTIALs: **F. MCP-specific semantics** (need risk-signal combination).

## 4. Semantic capability analysis

The next layer should normalize lines into structured **actions** rather than
bare category strings. Proposed action model:

```
Action(verb, object, destination, category)
```

Example normalization:

```
read ~/.aws/credentials   → Action(READ, SENSITIVE_PATH, None, SOURCE)
extract token             → Action(EXTRACT, CREDENTIAL, None, SENSITIVE)
base64 encode token       → Action(TRANSFORM, BASE64, None, TRANSFORM)
POST token to https://... → Action(NETWORK, CREDENTIAL, EXTERNAL, NETWORK)
```

Concepts to support:

| Concept | Needed? | Notes |
|---------|---------|-------|
| SOURCE | Yes | read/load/open/access of a source |
| SENSITIVE_DATA | Yes | token/password/secret/credential/API key |
| TRANSFORM | Yes | encode/transform/base64 |
| ENCODE | Yes | base64/ROT13 |
| NETWORK | Yes | send/upload/post to a destination |
| EXECUTION | Yes | run/execute/eval |
| SENSITIVE_PATH | Yes | `.env`, `~/.aws`, `~/.ssh` |
| CREDENTIAL | Yes | the sensitive value |
| EXTERNAL_DESTINATION | Yes | URL/endpoint/webhook |

The key improvement: an `Action` carries its **object** and **destination**, so
the correlation layer can ask "is the object sent to the destination the same
object that was read/extracted?" This is what the current string-category model
cannot answer.

## 5. Data-flow requirements

| Capability | Classification | Rationale |
|------------|----------------|-----------|
| Variable tracking | NOT NEEDED | Skills are instruction text, not imperative code with variables. |
| Taint tracking | USEFUL LATER | Would generalize source→sink, but overkill for the current corpus. |
| Source/sink analysis | **NEEDED NOW** | The two MISS cases are exactly source→sink (read→send, find→send). |
| Assignment tracking | NOT NEEDED | No variable assignments in the corpus. |
| Simple aliases | USEFUL LATER | "the data", "the secret", "it" refer to prior objects. |
| Function-level flow | NOT NEEDED | No function calls in the corpus. |
| Cross-file flow | USEFUL LATER | Current corpus is intra-file. |

**Recommendation:** implement a minimal **source→sink** correlation over
normalized actions, with **simple alias resolution** ("the data", "the secret",
"it" → the most recent matching object). This covers both MISS cases without a
full taint framework.

## 6. False-positive analysis

The benign lookalikes are the hard constraints. Any semantic expansion must not
turn these into findings:

| Benign fixture | Constraint |
|----------------|-----------|
| `never-reveal` | Negated instructions ("never reveal secrets", "do not expose credentials") must stay benign. |
| `secrets-doc` | Documentation about secrets ("store API keys in env vars") must stay benign. |
| `secure-coding` | "Never reveal secrets in logs", "do not print API keys" — negated. |
| `security-tutorial` | Educational text ("understand prompt injection", "study obfuscation") must stay benign. |
| `incident-response` | "Check for credential exposure", "review network logs" — discovery-like but benign. |
| `env-vars` | "Set the API_KEY environment variable" — config, not exfiltration. |
| `http-requests` | "Use requests to fetch data" — generic HTTP, no exfiltration. |

**FP risks of proposed capabilities:**

- **Generic "data" as SENSITIVE_DATA:** HIGH risk. `read-transform-network`
  uses "local data" — treating "data" as sensitive would flag legitimate data
  pipelines. **Mitigation:** do NOT make "data" sensitive by itself. Instead,
  track that the object read is the object sent (source→sink), regardless of
  whether it is named "secret".
- **Generic "read"/"find"/"list" as SOURCE:** HIGH risk. `incident-response`
  and `security-tutorial` contain discovery-like text. **Mitigation:** only
  treat "find X" as a source when X is a sensitive noun ("secret file",
  "credential"), and only treat "list" as a source when followed by a sensitive
  target. This is already the bounded approach in `step_sequence.py`.
- **"secret" in documentation:** MEDIUM risk. `secrets-doc` mentions secrets.
  **Mitigation:** require an access/read verb + sensitive path (AS-006 already
  does this) or a source→sink chain, not a bare keyword.
- **Negated instructions:** must remain benign. The existing negation handling
  in AS-004/AS-006 must be preserved in the action model.
- **Encoded strings not executed:** `benign-encoded-data` explicitly says "does
  not execute decoded content". AS-007 already requires execution/fetch context;
  the action model must preserve this.

**Bottom line:** the safe semantic expansion is **source→sink object tracking**
(which object is read vs. sent), NOT broadening the set of sensitive nouns or
verbs. This is the key FP-safe insight.

## 7. MCP architecture analysis

MCP is currently handled by file rules (`AS-MCP-001…010`) that parse the config
structurally and emit findings. The PARTIAL MCP cases all emit MEDIUM findings
but no HIGH/CRITICAL.

Options:

- **A. Extend inside the current rule architecture:** add combination logic so
  that e.g. `broad-fs` + `dynamic-package` → HIGH. Low complexity, fits current
  code. **Recommended.**
- **B. Represent as normalized capabilities:** model each server as a set of
  capabilities (remote, exec, secrets, fs) and combine them. Cleaner but a
  larger change.
- **C. Separate MCP analyzer:** overkill for the current corpus.

**Recommendation:** Option A — add a small MCP risk-combination step (either in
`mcp.py` or as a new chain) that raises severity when multiple risk signals
co-occur (e.g. remote + dynamic exec, or broad FS + secrets). This is
deterministic, low-FP, and fits the existing architecture.

## 8. Proposed target architecture

```
Raw resource
    ↓
Parser / normalizer
    ↓
Existing lexical rules (AS-001..006, AS-MCP-*, AS-007)
    ↓
Normalized actions (Action: verb, object, destination, category)
    ↓
Lightweight intra-file source→sink correlation
    ↓
Correlation / attack chains (AS-CHAIN-*)
    ↓
Metadata (MITRE/CWE/confidence/matched_text)
    ↓
Suppression
    ↓
Scoring / reporters
```

This preserves the existing lexical rules and adds a **normalized action layer**
between them and the correlation/chain stage. The action layer is a bounded
extension of `step_sequence.py` — it replaces the bare category string with a
structured `Action` while keeping the same chain-detection logic.

## 9. Incremental implementation plan

### Phase A: normalized action model
- **Files:** `src/veyra/step_sequence.py` (add `Action` dataclass),
  `tests/test_step_sequence.py`.
- **Tests:** action extraction from known lines; category mapping preserved.
- **Attack Lab impact:** none (behavior-preserving refactor).
- **FP risk:** none (no detection change).
- **Rollback:** revert the dataclass; keep the string-category path.

### Phase B: action extraction
- **Files:** `step_sequence.py` (parse each line into `Action`).
- **Tests:** parse `read ~/.aws/credentials`, `extract token`, `POST token to
  https://...` into structured actions.
- **Attack Lab impact:** none yet.
- **FP risk:** none (extraction only, no new findings).
- **Rollback:** revert extraction; keep string categories.

### Phase C: simple intra-file source→sink tracking
- **Files:** `step_sequence.py` (track object identity across actions),
  `tests/test_step_sequence.py`.
- **Tests:** `read data → transform → upload report` now detects that the
  object read is the object sent; `find secret file → send secret` detects the
  chain.
- **Attack Lab impact:** `read-transform-network` and `discovery-secret-network`
  MISSED → DETECTED (expected).
- **FP risk:** LOW — requires the same object to flow source→sink; benign
  lookalikes do not have this flow.
- **Rollback:** revert object tracking; keep string categories.

### Phase D: source → transform → sink correlation
- **Files:** `step_sequence.py`, `correlation.py`.
- **Tests:** transform (encode) between source and sink still correlates.
- **Attack Lab impact:** strengthens chain detection.
- **FP risk:** LOW.
- **Rollback:** revert correlation change.

### Phase E: MCP semantic analysis
- **Files:** `src/veyra/rules/mcp.py` (risk combination).
- **Tests:** broad-fs + dynamic-exec → HIGH.
- **Attack Lab impact:** MCP PARTIALs → DETECTED (expected).
- **FP risk:** LOW — requires multiple concrete risk signals.
- **Rollback:** revert combination logic.

## 10. Testing strategy

- **Regression gate:** the existing 95-case baseline must never regress
  (locked in `tests/test_attack_lab.py`).
- **New fixtures:** each new capability needs dedicated positive and benign
  fixtures.
- **FP gate:** all 10 benign lookalikes must remain clean (0 FP).
- **Determinism:** same input → same output (assert in tests).
- **Static-only:** no network/code execution during scanning (assert in tests).

## 11. Security invariants

- Existing 95-case baseline must never regress.
- False positives must remain 0 on the current benign corpus.
- Existing detected cases must remain detected.
- New detection capability must have dedicated fixtures.
- No network/code execution during scanning.
- Deterministic results.
- No rule weakening to inflate detection.

## 12. Recommendation for the single NEXT implementation step

**Phase A + B + C: normalized action model with lightweight intra-file
source→sink tracking.**

This is the smallest change that directly addresses the two MISS cases
(`read-transform-network`, `discovery-secret-network`) by tracking **which
object** is read vs. sent, without broadening the set of sensitive nouns or
verbs (which is the FP risk).

**Why preferable to the alternatives:**
- **Over more lexical rules:** the MISS cases are not lexical — they are about
  data flow. More regexes cannot see that "the data" read is "the report" sent.
- **Over a full AST/data-flow framework:** the corpus is instruction text, not
  imperative code. A full framework is overkill and high-risk.
- **Over MCP-only work:** MCP PARTIALs are lower-value (already MEDIUM) and
  higher-FP; the two MISS cases are the clearest gap.
- **Over obfuscation work:** ROT13 decoding is higher-FP and lower-value.

**Expected impact:** `read-transform-network` and `discovery-secret-network`
MISSED → DETECTED, raising detection to ~92.6% on the internal corpus, with 0
new false positives. This is a bounded, deterministic, explainable change that
fits the existing `step_sequence.py` architecture.

## Implementation status

Implemented (Phase A + B + C):

- **Structured `Action` model** (`verb`, `object`, `destination`, `category`,
  plus `output` for TRANSFORM) in `src/veyra/step_sequence.py`.
- **Action extraction** — each line/segment is parsed into an `Action` via
  `_extract_action`, with conservative object normalization
  (`_normalize_object`: lowercase, strip punctuation, collapse whitespace,
  remove leading determiners, strip trailing container words only when a base
  noun remains).
- **Lightweight intra-file source→sink tracking** — `_detect_source_sink`
  tracks which objects are produced by SOURCE/SENSITIVE actions and whether the
  same object (optionally through a TRANSFORM) flows to an external NETWORK
  sink. Emits **AS-CHAIN-004** (Potential data exfiltration chain).

**Result:** `read-transform-network` and `discovery-secret-network` are now
DETECTED. Attack Lab: **88 detected, 7 partial, 0 missed, 0 FP, 92.6%**. All 10
benign lookalikes remain clean. Production scan remains SAFE (score 0).

**Terminology note:** this is **lightweight intra-file source-to-sink
tracking**, not general data-flow analysis. It does not do variable tracking,
taint analysis, cross-file flow, or control-flow analysis.
