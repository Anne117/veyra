# AgentShield Threat Model

This document describes AgentShield's security model based on the actual
implementation. It is a static-analysis scanner for AI agent Skills and MCP
resources; it does **not** provide runtime protection.

## 1. Assets

AgentShield is concerned with protecting the assets an AI agent can touch:

- **API keys** and **credentials** (OpenAI, Anthropic, GitHub, AWS, generic).
- **Local files** — including sensitive credential files (`.env`, `~/.aws`,
  `~/.ssh`, private keys).
- **Environment variables** — which often hold secrets.
- **Agent execution capability** — the agent can run shell commands, scripts,
  and downloaded content.
- **Network access** — the agent can make HTTP requests and exfiltrate data.

## 2. Threat actors

- **Malicious Skill author** — writes a Skill that instructs the agent to
  exfiltrate secrets, execute dangerous commands, or connect to attacker
  infrastructure.
- **Compromised dependency** — a legitimate Skill or package that has been
  tampered with to include malicious instructions.
- **Malicious MCP server / configuration** — an MCP config that points to a
  remote endpoint, executes dynamic packages, passes secrets, or grants broad
  filesystem access.
- **Attacker-controlled remote payload** — a URL or downloaded script that the
  agent is instructed to fetch and execute.
- **Prompt injection embedded in agent resources** — instructions hidden in
  otherwise legitimate documentation that override the host agent's system
  prompt.

## 3. Trust boundaries

```
Untrusted Skill / MCP config
        |
        v
   Agent runtime
        |
   +----+----+
   |         |
 Files     Network
   |
Secrets
```

- **Untrusted input** (Skills, MCP configs, remote payloads) crosses into the
  **agent runtime**.
- The agent runtime can read **files** (including **secrets**) and reach the
  **network**.
- AgentShield inspects the untrusted input **before** it is loaded, to surface
  instructions that would abuse the agent's file/network/execution capabilities.

## 4. Attack paths AgentShield currently detects

| Attack path | Rule(s) |
|-------------|---------|
| Hardcoded secret in source | AS-001 |
| Sensitive credential file access (`.env`, `~/.aws`, `~/.ssh`) | AS-006 |
| Shell / command execution | AS-002 |
| Download + execute chain | AS-CHAIN-002, AS-002, AS-003 |
| Secret + network exfiltration chain | AS-CHAIN-001 |
| Encoded payload + execution/fetch context | AS-007 |
| Dangerous MCP configuration | AS-MCP-001…010 |
| Prompt injection patterns | AS-004 |
| Suspicious URLs | AS-005 |
| Network access | AS-003 |

## 5. What AgentShield does NOT guarantee

- **No complete malware detection.** AgentShield is a heuristic static scanner;
  it will miss attacks.
- **No runtime behavioral analysis.** It never executes Skills or MCP servers
  and cannot observe runtime behavior.
- **No guarantee that a clean scan means a resource is safe.** A resource with
  no findings may still be malicious in ways the scanner does not model.
- **No complete semantic understanding.** Detection is regex/structural, not
  semantic.
- **No complete cross-file data-flow analysis.** Step-sequence analysis is
  intra-file only; there is no taint tracking across files or functions.

## 6. Security philosophy

AgentShield prefers **deterministic, explainable findings** over opaque
"AI says this is malicious" judgments. Every finding is produced by a
deterministic rule and carries:

- a **rule ID** and **severity** (how dangerous),
- a **confidence** (how reliably the behavior matches the rule),
- **CWE** and **MITRE ATT&CK** metadata where defensible,
- the **matched source text** (redacted for secrets),
- a **remediation** suggestion.

This makes findings auditable, reproducible, and actionable. A security
engineer can trace exactly why a finding fired and decide whether it is a real
issue or a false positive. This is preferable to a black-box model whose
judgments cannot be inspected or challenged.
