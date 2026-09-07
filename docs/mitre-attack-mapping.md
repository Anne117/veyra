# MITRE ATT&CK Coverage

## Methodology

This document maps AgentShield's existing detections to MITRE ATT&CK Enterprise
techniques. Mappings are **behavior-based** and only applied where the existing
AgentShield behavior provides reasonable evidence for the technique.

Rules are **not** force-mapped just because a technique sounds similar. A
mapping is only proposed when the rule's detection semantics genuinely
correspond to the technique's definition. Confidence reflects how well the
rule's evidence supports the technique:

- **HIGH** — the rule directly detects the technique's core behavior.
- **MEDIUM** — the rule detects a behavior consistent with the technique, but
  with caveats (e.g. it is a static signal, not confirmed runtime behavior).
- **LOW** — the rule is tangentially related; mapping is speculative.

Mappings marked **internal** are useful for analysis but should not be shown to
users as a definitive ATT&CK attribution. Mappings marked **public** are safe to
expose in scanner output.

> Note: AgentShield is a **static** scanner. It detects code/config patterns,
> not confirmed runtime adversary behavior. All mappings are therefore
> indicative, not proof of an active attack.

## High-confidence mappings

| AgentShield Rule | MITRE ID | Technique | Confidence | Justification |
|------------------|----------|-----------|------------|---------------|
| AS-001 (hardcoded secrets) | T1552.001 | Unsecured Credentials: Credentials In Files | HIGH | Directly detects credentials (API keys, tokens, passwords, private keys) stored in files/config. Core behavior of T1552.001. **Public.** |
| AS-002 (subprocess shell=True, os.system, eval) | T1059 | Command and Scripting Interpreter | HIGH | Detects execution of shell/commands via subprocess/os.system/eval. Core behavior of T1059. **Public.** |
| AS-002 (curl\|bash, wget\|sh) | T1059.004 | Command and Scripting Interpreter: Unix Shell | HIGH | Detects piping remote content into a Unix shell. Directly matches T1059.004. **Public.** |
| AS-002 (eval of variable) | T1059.004 | Command and Scripting Interpreter: Unix Shell | HIGH | `eval` executes a string as shell code. Matches T1059.004. **Public.** |
| AS-CHAIN-002 (download → execute) | T1105 | Ingress Tool Transfer | HIGH | Correlates remote download followed by execution — the core of T1105 (transfer tool/script then run it). **Public.** |
| AS-CHAIN-001 (secret exfiltration) | T1041 | Exfiltration Over C2 Channel | MEDIUM | Correlates read-secret → send-externally. Reasonable exfiltration evidence, but the "C2 channel" framing is not confirmed (static). See caveat below. **Public.** |

## Medium-confidence mappings

| AgentShield Rule | MITRE ID | Technique | Confidence | Justification |
|------------------|----------|-----------|------------|---------------|
| AS-003 (HTTP client usage) | T1071.001 | Application Layer Protocol: Web Protocols | MEDIUM | Detects HTTP client usage (requests/urllib/httpx/fetch/axios). Consistent with web-protocol communication, but HTTP alone is not malicious. **Internal.** |
| AS-003 (download-and-execute) | T1105 | Ingress Tool Transfer | MEDIUM | Detects download-and-execute pattern. Matches T1105, but overlaps with AS-CHAIN-002; keep as supporting signal. **Public.** |
| AS-005 (executable/download URL) | T1105 | Ingress Tool Transfer | MEDIUM | Flags URLs pointing to executables/scripts. Consistent with tool transfer, but a URL alone is not proof. **Internal.** |
| AS-MCP-004 (dynamic package execution) | T1105 | Ingress Tool Transfer | MEDIUM | npx/npm/uvx fetch and execute packages at runtime. Consistent with tool transfer, but package registries are legitimate. **Internal.** |
| AS-MCP-007 (broad filesystem access) | T1083 | File and Directory Discovery | MEDIUM | Grants broad filesystem/path access. Consistent with discovery, but it is a permission grant, not confirmed discovery. **Internal.** |
| AS-MCP-006 (secret env passed to server) | T1552.001 | Unsecured Credentials: Credentials In Files | MEDIUM | Passes secret-looking env vars to a server. Consistent with credentials-in-config, but the value is not necessarily stored. **Public.** |
| AS-004 (reveal secrets / env dump) | T1552.001 | Unsecured Credentials: Credentials In Files | MEDIUM | Instruction to reveal secrets/env vars. Consistent with credential access, but it is an instruction, not confirmed access. **Internal.** |
| AS-004 (send local files externally) | T1041 | Exfiltration Over C2 Channel | MEDIUM | Instruction to send local files to an external destination. Consistent with exfiltration, but it is an instruction, not confirmed transfer. **Internal.** |
| AS-CHAIN-003 (remote MCP + dynamic exec) | T1105 | Ingress Tool Transfer | MEDIUM | Correlates remote MCP endpoint with dynamic package execution. Consistent with tool transfer, but remote MCP is not inherently malicious. **Public.** |

## Rules without a justified MITRE mapping

| AgentShield Rule | Reason |
|------------------|--------|
| AS-005 (raw IP URL) | A raw-IP URL is a suspicious pattern but not a specific ATT&CK technique. Not C2 by itself. |
| AS-005 (URL shortener) | URL shorteners are an evasion/obfuscation-adjacent pattern but not a defined Enterprise technique. |
| AS-MCP-001 (remote MCP endpoint) | A remote endpoint is not inherently malicious; no technique is justified. |
| AS-MCP-002 (HTTP without HTTPS) | Plain HTTP is a transport weakness, not an ATT&CK technique. |
| AS-MCP-003 (local command execution) | Overlaps T1059 but is a generic MCP launch; mapping would be redundant with AS-002. |
| AS-MCP-005 (env vars passed) | Passing env vars is a configuration pattern, not a technique. |
| AS-MCP-008 (suspicious args) | Flags like `--allow-all` are permission grants, not a defined technique. |
| AS-MCP-009 (remote URL + exec) | Overlaps T1105 via AS-CHAIN-002; standalone mapping is redundant. |
| AS-MCP-010 (missing trust info) | An INFO-level ambiguity, not an attack technique. |
| AS-004 (prompt injection) | Prompt injection does not map cleanly to a traditional Enterprise ATT&CK technique. It is an AI-agent-specific manipulation vector. |
| AS-004 (encoded/obfuscated content) | See T1027 discussion below. |
| AS-CHAIN-001 (secret exfiltration) | See T1041 caveat below. |

## Attack Lab coverage

For each relevant Attack Lab category, the MITRE techniques represented:

| Attack Lab category | MITRE techniques represented |
|---------------------|------------------------------|
| prompt-injection | None (prompt injection is not a clean Enterprise technique) |
| secret-exfiltration | T1552.001 (credentials in files), T1041 (exfiltration) |
| shell-execution | T1059, T1059.004 (command/scripting interpreter) |
| remote-download | T1105 (ingress tool transfer) |
| encoded-obfuscation | T1027 (obfuscated files or information) — see caveat |
| filesystem-access | T1083 (file/directory discovery) |
| mcp-attacks | T1105 (ingress tool transfer), T1552.001 (credentials) |
| multi-stage | T1041 (exfiltration), T1105 (ingress tool transfer) |

## Recommended public mapping

The minimal set of mappings that should actually appear in scanner output
(high-confidence, non-misleading):

| AgentShield Rule | MITRE ID | Technique |
|------------------|----------|-----------|
| AS-001 | T1552.001 | Unsecured Credentials: Credentials In Files |
| AS-002 | T1059 | Command and Scripting Interpreter |
| AS-002 (curl\|bash / eval) | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| AS-CHAIN-002 | T1105 | Ingress Tool Transfer |
| AS-MCP-006 | T1552.001 | Unsecured Credentials: Credentials In Files |

These five mappings are the safest to expose. Everything else should remain
internal or be omitted to avoid misleading users.

## Implementation

The approved public mappings are implemented as static, deterministic metadata
in `src/agentshield/mitre.py`. No MITRE API, database, or dynamic fetching is
used.

### Public mappings (implemented)

| AgentShield Rule | MITRE ID | Technique |
|------------------|----------|-----------|
| AS-001 | T1552.001 | Credentials In Files |
| AS-002 | T1059 | Command and Scripting Interpreter |
| AS-002 (Unix shell evidence) | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| AS-006 | T1552.001 | Credentials In Files |
| AS-CHAIN-002 | T1105 | Ingress Tool Transfer |
| AS-MCP-006 | T1552.001 | Credentials In Files |

AS-002 findings whose evidence indicates Unix shell execution (e.g. `curl | bash`,
`wget | sh`, `eval`) additionally map to T1059.004. AS-006 (sensitive credential
file access) maps to T1552.001 because reading credential files is the core
behavior of that technique.

### How MITRE metadata appears in findings

Each `Finding` carries a structured `mitre` field: a list of `{id, name}` dicts.
It is attached after scanning, purely as metadata — it does not affect rule
matching, severity, scoring, exit codes, suppression, correlation, or
step-sequence logic.

### JSON behavior

Findings with an approved mapping include a `mitre` array:

```json
{
  "rule_id": "AS-001",
  "severity": "HIGH",
  "mitre": [
    { "id": "T1552.001", "name": "Credentials In Files" }
  ]
}
```

Findings without an approved mapping do **not** emit an empty `mitre` key.

### SARIF behavior

MITRE metadata is exposed in the standard SARIF `properties` field on each rule
(valid SARIF 2.1.0, does not break schema validation):

```json
{
  "id": "AS-001",
  "properties": {
    "mitre": [ { "id": "T1552.001", "name": "Credentials In Files" } ]
  }
}
```

### Terminal behavior

Findings with an approved mapping print a concise line:

```
MITRE ATT&CK: T1552.001 — Credentials In Files
```

Findings without a mapping print no MITRE line.

### Suppression

Suppressed findings retain their MITRE metadata where the finding is retained.

### Medium-confidence mappings remain internal

The medium-confidence mappings (T1041, T1071.001, T1027, T1083, and others) are
**not** exposed in scanner output. They remain documented in this file for
analysis only.

## Caveats and deliberately excluded techniques

- **T1027 (Obfuscated Files or Information)** — AS-004 flags encoded/obfuscated
  content (base64/ROT13), but it does **not** decode or confirm obfuscation of
  malicious content. Mapping to T1027 would be speculative. **Excluded.**
- **T1041 (Exfiltration Over C2 Channel)** — AS-CHAIN-001 and AS-004 detect
  read-secret → send-externally, but the "C2 channel" framing is not confirmed
  by static analysis. The exfiltration behavior is real, but the C2 channel
  attribution is not. **Keep internal / MEDIUM.**
- **T1071.001 (Web Protocols)** — HTTP client usage is not automatically
  malicious. Mapping would over-attribute normal network use. **Internal only.**
- **T1189 (Drive-by Compromise)** — not applicable; AgentShield does not detect
  browser-based compromise. **Excluded.**
- **T1564.004 (NTFS File Attributes)** — not applicable; AgentShield does not
  detect file-hiding techniques. **Excluded.**
- **T1083 (File and Directory Discovery)** — AS-MCP-007 grants broad FS access
  but does not confirm discovery activity. **Internal only.**
- **Prompt injection** — does not map cleanly to a traditional Enterprise
  ATT&CK technique. It is an AI-agent-specific manipulation vector. **No
  mapping.**
