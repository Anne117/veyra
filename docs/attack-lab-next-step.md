# Attack Lab — Next Detection Architecture

## Current baseline

- **119 tests passing** (102 original + 17 correlation tests).
- Attack Lab: 27 cases, **19 detected, 5 partially detected, 3 missed, 0 false positives, 70.4% detection rate**.
- Correlation layer (`AS-CHAIN-001/002/003`) is implemented and deterministic.
- Existing rules must not be weakened.

## Remaining misses

| Fixture | Category | Current findings | Missing signal | Root cause |
|---------|----------|------------------|----------------|------------|
| `read-credentials` | secret-exfiltration | none | Reading `~/.ssh`, `~/.aws` credential-file paths | No rule models sensitive-path reads; regex keyword set has no path awareness |
| `data-sync` | multi-stage | none | "read config → extract key → send to URL" chain | Each step is individually low-risk; no single line matches; no cross-step data-flow |
| `download-run` | multi-stage | none | "download script → run script" chain | Download and run are split across steps; no single line matches download-and-execute |

## Partially detected cases

| Fixture | Category | Current findings | Why partial |
|---------|----------|------------------|-------------|
| `base64-exec` | encoded-obfuscation | AS-004 MEDIUM | Encoded content flagged, but the hidden command is never decoded/analyzed |
| `rot13-exec` | encoded-obfuscation | AS-004 MEDIUM | Same — obfuscation keyword flagged, payload not decoded |
| `broad-fs` | filesystem-access | AS-MCP-003/004/007 MEDIUM | Broad-FS rule fires but at MEDIUM; no HIGH/CRITICAL signal |
| `remote-exec` | mcp-attacks | AS-MCP-001/003/004 MEDIUM + **AS-CHAIN-003 HIGH** | **Actually detected** via the chain, but the harness only counts individual rules at HIGH/CRITICAL — a classification artifact, not a detection gap |
| `broad-fs-secrets` | mcp-attacks | AS-001 CRITICAL, AS-MCP-006/008 HIGH, others MEDIUM | Individual rules fire strongly, but the expected-rule set isn't fully matched at HIGH/CRITICAL |

## What the misses have in common

1. **Cross-step / cross-file sequences.** `data-sync` and `download-run` are
   the clearest: the dangerous behavior is a *sequence* of steps, each
   individually benign-looking. No single line or file contains the full
   attack.
2. **Sensitive-path awareness.** `read-credentials` requires knowing that
   `~/.ssh`, `~/.aws`, `.env` are sensitive paths — a semantic fact, not a
   keyword.
3. **Decoding hidden content.** `base64-exec`/`rot13-exec` require decoding
   the payload to see the real command.
4. **Severity escalation.** Several partial cases are *detected* but at MEDIUM
   severity; the harness wants HIGH/CRITICAL. This is partly a classification
   artifact (e.g. `remote-exec` is caught by AS-CHAIN-003).

## Candidate approaches

| Approach | Detection power | False-positive risk | Implementation complexity | Maintenance cost |
|----------|-----------------|---------------------|---------------------------|------------------|
| **More regex/rules** | Low for sequences; high for single-line patterns | Medium (keyword matching) | Low | Low |
| **Correlation (current)** | Good for co-occurring signals in one scan; **cannot see cross-step sequences** | Low (requires multiple signals) | Low | Low |
| **AST analysis** | High for code structure; **does not help markdown/instruction text** | Low | High (needs a parser per language) | High |
| **Intra-file data flow** | Medium; tracks variable/step flow within one file | Medium | Medium | Medium |
| **Cross-file data flow** | Highest for multi-stage attacks | High (needs taint/sink model) | High | High |

## Recommendation

**Chosen: lightweight intra-file sequence / step analysis (a "step-chain"
detector), not full AST or cross-file data flow.**

Rationale:

- The two multi-stage misses (`data-sync`, `download-run`) are **single-file,
  step-ordered** attacks. They do not cross files. A full cross-file data-flow
  engine is overkill and high-risk.
- AST analysis does not help: the attacks live in **markdown instruction
  text**, not code. Parsing Python/JS ASTs would not see `## Step 1 ... Step 3`.
- The smallest change that detects these is a **step-sequence rule**: within a
  single file, detect an ordered sequence of step markers whose combined
  semantics form a dangerous chain (e.g. "read/extract" → "send/upload" for
  exfiltration; "download" → "run/execute" for download-and-execute).
- This is a **file-level rule** (like the existing MCP file rules), so it fits
  the current architecture without a new framework or dependency.
- It is deterministic, low-FP (requires the full ordered sequence), and
  directly targets the two remaining multi-stage misses.

## Minimal implementation plan

1. Add a file-level rule `step_chain.py` (registered via the existing
   `register_file_rule` mechanism) that:
   - Detects step markers (`## Step N`, numbered lists) in a single file.
   - Classifies each step's verb into a semantic bucket:
     - **source/read**: read, load, extract, get, open
     - **sensitive**: api key, secret, token, credential, config
     - **sink/send**: send, upload, post, transmit, exfiltrate
     - **download**: download, fetch, curl, wget
     - **execute**: run, execute, install, eval, bash, sh
   - Emits `AS-CHAIN-004` (exfiltration sequence) when
     `read/extract + sensitive + send` appear in order.
   - Emits `AS-CHAIN-005` (download→execute sequence) when
     `download + execute` appear in order.
2. Add fixtures/tests for the two multi-stage cases.
3. Re-run the Attack Lab; expect `data-sync` and `download-run` to move from
   MISSED to DETECTED.

This is the smallest MVP that validates the recommendation without adding a
framework or dependency, and it does not weaken any existing rule.

## Status: implemented

The step-sequence analyzer was implemented in `src/veyra/step_sequence.py`
and integrated into the scanner. It detects:

- `AS-CHAIN-001` — SOURCE → SENSITIVE → NETWORK (secret exfiltration)
- `AS-CHAIN-002` — DOWNLOAD → EXECUTION (download-and-execute)

Attack Lab improved from **70.4% → 77.8%** (21 detected, 1 missed, 0 FP).
The two multi-stage misses (`data-sync`, `download-run`) are now DETECTED.

**Remaining miss:** `read-credentials` is a single-line sensitive-path read
with no network sink or execution — it is not an ordered multi-stage sequence,
so the step-sequence engine correctly does not match it. It requires a
different signal: **sensitive-path detection** (flagging reads of `~/.ssh`,
`~/.aws`, `.env`, etc.).
