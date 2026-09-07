# AgentShield

**Security scanner for AI agent skills and MCP-related resources.**

AgentShield is an early-stage (MVP) static-analysis tool that inspects AI agent
skills — `SKILL.md` files, markdown, YAML/JSON/TOML config, Python/JS/TS code,
and shell scripts — for security issues such as hardcoded secrets, dangerous
command execution, network access, prompt injection, and suspicious URLs.

> **Status: early MVP.** AgentShield is a heuristic scanner, not a proven
> security standard. It does **not** detect all malicious skills and can
> produce false positives. Treat its output as a starting point for review,
> not as a definitive verdict.

## Why AI agent skills need security scanning

AI agents increasingly load third-party skills and configuration that instruct
them to take actions. A malicious or compromised skill can:

- Embed **hardcoded secrets** that get committed to source control.
- Instruct the agent to **execute arbitrary commands** (`curl | bash`).
- Make **unexpected network requests** or exfiltrate local files.
- Use **prompt injection** to override the host agent's system instructions.
- Point to **suspicious URLs** (raw IPs, shorteners, executable downloads).

AgentShield scans these resources statically so you can review them before
trusting an agent to load them.

## What the MVP detects

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

|Matched secrets are **redacted** in reports — full secrets never appear.

Findings with an approved mapping also carry **MITRE ATT&CK** metadata
(e.g. `AS-001 → T1552.001 Credentials In Files`), shown in terminal output,
JSON, and SARIF. See `docs/mitre-attack-mapping.md` for the full mapping.

Every finding also carries:
- **CWE** IDs (where defensible) — see `docs/finding-model.md`.
- **Confidence** (HIGH/MEDIUM/LOW) — how reliably the behavior matches the rule
  (distinct from severity, which is how dangerous it is).
- **Matched text** — the exact source line that triggered the rule (redacted
  for secrets).

## MCP security analysis

AgentShield scans MCP (Model Context Protocol) server configuration files for
security issues. It supports `.mcp.json`, `mcp.json`, `mcp_servers.json`, and
structurally identifiable JSON/YAML MCP configs.

MCP-specific rules (IDs `AS-MCP-001` … `AS-MCP-010`):

| Rule | ID | Severity |
|------|----|----------|
| Remote MCP endpoint | AS-MCP-001 | MEDIUM |
| HTTP endpoint without HTTPS | AS-MCP-002 | HIGH |
| Local command execution | AS-MCP-003 | MEDIUM |
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

### MCP example

```bash
agentshield scan ./project/.mcp.json
```

```
AgentShield Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target: ./project/.mcp.json
Risk: HIGH
Score: 60/100

MEDIUM    AS-MCP-001  Remote MCP endpoint
          .mcp.json:3
          MCP server 'remote' connects to a remote endpoint. ...
          Evidence: Remote endpoint: https://api.example.com/mcp

HIGH      AS-MCP-002  HTTP endpoint without HTTPS
          .mcp.json:3
          MCP server 'http_server' uses plain HTTP, which transmits data unencrypted.
          Evidence: Plain HTTP endpoint: http://api.example.com/mcp

HIGH      AS-MCP-006  Secret passed to MCP server
          .mcp.json:3
          MCP server 'filesystem' receives 'API_KEY', which looks like a secret.
          Evidence: Secret-like env var: API_KEY
```

MCP scanning is **fully static**: AgentShield never executes MCP commands,
never starts MCP servers, never connects to endpoints, never downloads
packages, and never resolves or contacts remote URLs.

## Installation

```bash
# from the project root
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Windows
# or: source .venv/bin/activate && pip install -e ".[dev]"  # macOS/Linux
```

Requires Python 3.9+.

## Usage

```bash
agentshield scan ./path/to/skill
agentshield scan ./path/to/skill --format json
```

### Example output

```
AgentShield Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target: ./example-skill
Risk: HIGH
Score: 72/100

CRITICAL  AS-001  Hardcoded secret
          example/SKILL.md:42
          API credential detected
          Evidence: sk-proj-********

HIGH      AS-002  Remote command execution
          scripts/install.py:18
          Remote content is downloaded and executed

MEDIUM    AS-003  External network access
          scripts/main.py:31
          HTTP request detected

Summary
-------
Critical: 1
High:     1
Medium:   0
Low:      0
```

### JSON output

```bash
agentshield scan ./path --format json
```

```json
{
  "target": "./path",
  "score": 72,
  "risk_level": "HIGH",
  "summary": { "critical": 1, "high": 1, "medium": 0, "low": 0 },
  "findings": [ ... ]
}
```

### SARIF output

AgentShield emits **SARIF 2.1.0** for compatibility with GitHub Code Scanning
and other SARIF-compatible security tooling:

```bash
agentshield scan ./path --format sarif > agentshield-report.sarif
```

SARIF mapping:

| AgentShield | SARIF |
|-------------|-------|
| `rule_id` | `rule.id` / `result.ruleId` |
| `title` | `rule.name` / `result.message` |
| `description` | `rule.shortDescription` / `rule.fullDescription` |
| `severity` | `result.level` (CRITICAL/HIGH→`error`, MEDIUM→`warning`, LOW/INFO→`note`) |
| `file` | `artifactLocation.uri` |
| `line` | `region.startLine` |
| `remediation` | `rule.help` |

Suppressed findings are preserved via SARIF's `suppressions` array — they are
never silently turned into clean results. Secrets remain redacted. SARIF
generation is fully static (no network requests, no code execution).

### Exit codes (CI-friendly)

- `0` — no HIGH/CRITICAL findings
- `1` — at least one HIGH finding
- `2` — at least one CRITICAL finding

The failure threshold is configurable with `--fail-on`:

```bash
agentshield scan ./path --fail-on CRITICAL   # only fail on critical
agentshield scan ./path --fail-on MEDIUM    # fail on medium or higher
```

## Suppression / allowlist

You can suppress known-safe findings with a project configuration file,
`.agentshield.toml`:

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
- Suppression only affects matching findings; unrelated findings are untouched.

## GitHub Action

AgentShield ships a GitHub Action workflow that scans a repository on every
push and pull request. See `.github/workflows/agentshield.yml`.

To enable it in your repository, copy the workflow file into your repo:

```bash
mkdir -p .github/workflows
cp agentshield/.github/workflows/agentshield.yml .github/workflows/
```

The workflow:

1. Installs AgentShield **from the checked-out repository** (`pip install .`).
   The package is not published on PyPI, so the workflow installs it locally
   from the repo it is scanning.
2. Scans the repository.
3. Prints a readable report in CI logs.
4. Uploads the JSON report as a `agentshield-report` artifact.
5. Uploads the SARIF report to **GitHub Code Scanning** via
   `github/codeql-action/upload-sarif@v3`.
6. Fails the workflow on HIGH findings by default (exit code 1 or 2).
7. Supports a configurable threshold via `--fail-on` in the scan step.
8. Never executes scanned Skills or MCP servers, and makes no outbound
   network requests during the scan.

The workflow requests the `security-events: write` permission, which is
required to upload SARIF to Code Scanning.

## Risk score methodology

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
| 0–4    | SAFE |

## Current limitations

- **Static analysis only** — no runtime behavior, no network calls during scan.
- **Heuristic, not exhaustive** — will miss some attacks and may flag benign code.
- **Line-based** — multi-line constructs are not fully analyzed.
- **MCP config is parsed structurally** (JSON/YAML), but other formats are matched on raw text.
- **No MCP server manifest parsing** beyond the config file itself.
- **No allowlist/ignore configuration** yet.

## Roadmap

- [ ] MCP server manifest (`mcp_servers`) analysis
- [ ] Semantic parsing for YAML/JSON/TOML
- [ ] Allowlist / ignore rules
- [ ] SARIF output for CI integration
- [ ] Multi-line and cross-file analysis
- [ ] More secret formats and entropy-based detection
- [ ] Plugin architecture for custom rules

## Development

```bash
.venv/Scripts/python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
