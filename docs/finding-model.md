# AgentShield Finding Model

Every AgentShield finding carries structured metadata to help a security
engineer triage quickly and consistently across terminal, JSON, and SARIF
output.

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | The rule that fired (e.g. `AS-001`, `AS-MCP-006`, `AS-CHAIN-002`). |
| `severity` | enum | How dangerous the behavior is: `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`. |
| `title` | string | Short human-readable title. |
| `description` | string | Longer explanation of the finding. |
| `file` | string | Source file path. |
| `line` | int | Source line number (when available). |
| `evidence` | string | Rule-specific evidence (secrets are redacted). |
| `remediation` | string | Recommended fix. |
| `suppressed` | bool | Whether the finding was suppressed by `.agentshield.toml`. |
| `suppression_reason` | string | Why it was suppressed. |
| `mitre` | list | Approved MITRE ATT&CK mappings (only where justified). |
| `cwe` | list | CWE IDs (only where defensible; never fabricated). |
| `confidence` | enum | How reliably the behavior matches the rule: `HIGH`/`MEDIUM`/`LOW`. |
| `matched_text` | string | The exact source line that triggered the rule (redacted for secrets). |

## Confidence vs. Severity

- **Severity** answers: *How dangerous is the behavior?*
- **Confidence** answers: *How confident are we that the detected behavior
  actually matches the rule?*

Confidence is deterministic and rule-derived:

- `HIGH` — correlation/step-sequence chains (multiple corroborating signals),
  obfuscation (decoded content + execution/fetch context), sensitive credential
  access, and strong secret patterns (OpenAI/Anthropic/GitHub/AWS/private key).
- `MEDIUM` — generic secrets, MCP structural findings, prompt injection,
  network, URL, and shell regex findings.

## CWE mappings

CWE IDs are only assigned where the rule behavior clearly matches the weakness.
Rules without a defensible mapping have an empty `cwe` list (never guessed).

| Rule | CWE |
|------|-----|
| AS-001 (hardcoded secrets) | CWE-798 |
| AS-002 (command execution) | CWE-78 |
| AS-006 (sensitive credential access) | CWE-522 |
| AS-007 (encoded content executed) | CWE-749 |
| AS-MCP-001 (remote endpoint) | CWE-749 |
| AS-MCP-004 (dynamic package exec) | CWE-749 |
| AS-MCP-006 (secrets in env) | CWE-798 |
| AS-MCP-007 (broad filesystem) | CWE-732 |

## MITRE + CWE relationship

- **MITRE ATT&CK** describes the *technique* an attacker uses (e.g. T1552.001
  Credentials In Files).
- **CWE** describes the *weakness* in the code/config that enables it (e.g.
  CWE-798 Use of Hard-coded Credentials).

A finding can carry both: MITRE for the attack technique, CWE for the
underlying weakness. Only approved MITRE mappings are exposed (see
`docs/mitre-attack-mapping.md`).

## Reporters

- **Terminal:** shows `Confidence:`, `CWE:`, `MITRE ATT&CK:`, and `Matched:`.
- **JSON:** exposes `confidence`, `cwe` (when mapped), `mitre` (when mapped),
  and `matched_text`.
- **SARIF:** exposes `confidence`, `cwe`, and `mitre` in the rule `properties`
  field; `matched_text` is appended to the result message. Valid SARIF 2.1.0.
