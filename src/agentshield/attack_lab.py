"""AgentShield Attack Lab.

A local, static adversarial test corpus that measures AgentShield's real
security coverage. Each fixture is a small synthetic attack (or benign
lookalike) against an AI agent. The lab runs AgentShield's static scanner
against every fixture and classifies the result.

This module NEVER executes any fixture, never contacts external endpoints,
never downloads anything, and never runs MCP servers or commands contained
in the fixtures. It is pure static analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from agentshield.scanner import scan_path

# Classification of a fixture's detection result.
DETECTED = "DETECTED"
PARTIALLY_DETECTED = "PARTIALLY_DETECTED"
MISSED = "MISSED"
FALSE_POSITIVE = "FALSE_POSITIVE"

# Severity threshold: a finding at or above this is a "real" detection.
# We consider HIGH/CRITICAL as meaningful detections for attack fixtures.
DETECTION_SEVERITIES = {"HIGH", "CRITICAL"}


@dataclass
class AttackCase:
    """A single attack fixture and its expected/actual detection."""

    name: str
    category: str
    path: str
    expected: str  # DETECTED / PARTIALLY_DETECTED / MISSED / FALSE_POSITIVE
    description: str = ""
    # Rule IDs that, if present, count as a detection for this case.
    expected_rules: List[str] = field(default_factory=list)
    # Whether this is a benign lookalike (expected to produce no findings).
    is_benign: bool = False


# --- Attack corpus definition ----------------------------------------------
# Each entry: (name, category, relative_path, expected, expected_rules, is_benign)

ATTACK_CASES: List[AttackCase] = [
    # --- prompt-injection ---
    AttackCase(
        "override-instructions", "prompt-injection",
        "prompt-injection/override-instructions/SKILL.md",
        DETECTED, "Instruction asks agent to ignore previous instructions.",
        ["AS-004"],
    ),
    AttackCase(
        "disable-security", "prompt-injection",
        "prompt-injection/disable-security/SKILL.md",
        DETECTED, "Instruction asks agent to disable security controls.",
        ["AS-004"],
    ),
    AttackCase(
        "exfiltrate-files", "prompt-injection",
        "prompt-injection/exfiltrate-files/SKILL.md",
        DETECTED, "Instruction asks agent to send local files externally.",
        ["AS-004"],
    ),
    AttackCase(
        "benign", "prompt-injection",
        "prompt-injection/benign/SKILL.md",
        DETECTED, "Benign instructional text should produce no findings.",
        [], is_benign=True,
    ),
    # --- secret-exfiltration ---
    AttackCase(
        "env-dump", "secret-exfiltration",
        "secret-exfiltration/env-dump/SKILL.md",
        PARTIALLY_DETECTED,
        "Reveal env vars + send externally. Reveal is detected; the send may be partial.",
        ["AS-004"],
    ),
    AttackCase(
        "read-credentials", "secret-exfiltration",
        "secret-exfiltration/read-credentials/SKILL.md",
        MISSED,
        "Reading ~/.ssh and ~/.aws credentials is not covered by current rules.",
        [],
    ),
    AttackCase(
        "reveal-secrets", "secret-exfiltration",
        "secret-exfiltration/reveal-secrets/SKILL.md",
        DETECTED, "Instruction asks agent to reveal API keys.",
        ["AS-004"],
    ),
    AttackCase(
        "benign", "secret-exfiltration",
        "secret-exfiltration/benign/SKILL.md",
        DETECTED, "Benign config helper should produce no findings.",
        [], is_benign=True,
    ),
    # --- shell-execution ---
    AttackCase(
        "os-system-var", "shell-execution",
        "shell-execution/os-system-var/install.py",
        DETECTED, "os.system with a variable-built command.",
        ["AS-002"],
    ),
    AttackCase(
        "subprocess-shell", "shell-execution",
        "shell-execution/subprocess-shell/run.py",
        DETECTED, "subprocess with shell=True.",
        ["AS-002"],
    ),
    AttackCase(
        "benign", "shell-execution",
        "shell-execution/benign/run.py",
        DETECTED, "Benign subprocess with list args should produce no findings.",
        [], is_benign=True,
    ),
    AttackCase(
        "eval-var", "shell-execution",
        "shell-execution/eval-var/setup.sh",
        DETECTED, "eval of a variable.",
        ["AS-002"],
    ),
    # --- remote-download ---
    AttackCase(
        "curl-pipe-bash", "remote-download",
        "remote-download/curl-pipe-bash/install.sh",
        DETECTED, "curl piped into bash.",
        ["AS-002", "AS-003", "AS-005"],
    ),
    AttackCase(
        "wget-pipe-sh", "remote-download",
        "remote-download/wget-pipe-sh/install.sh",
        DETECTED, "wget piped into sh.",
        ["AS-002", "AS-003", "AS-005"],
    ),
    AttackCase(
        "benign", "remote-download",
        "remote-download/benign/fetch.sh",
        DETECTED, "Benign curl download (no execution) should produce no findings.",
        [], is_benign=True,
    ),
    # --- encoded-obfuscation ---
    AttackCase(
        "base64-exec", "encoded-obfuscation",
        "encoded-obfuscation/base64-exec/SKILL.md",
        PARTIALLY_DETECTED,
        "Encoded content detected, but the hidden command is not decoded/analyzed.",
        ["AS-004"],
    ),
    AttackCase(
        "rot13-exec", "encoded-obfuscation",
        "encoded-obfuscation/rot13-exec/SKILL.md",
        PARTIALLY_DETECTED,
        "Obfuscation keyword detected, but the hidden command is not decoded.",
        ["AS-004"],
    ),
    AttackCase(
        "benign", "encoded-obfuscation",
        "encoded-obfuscation/benign/SKILL.md",
        DETECTED, "Benign encoding helper should produce no findings.",
        [], is_benign=True,
    ),
    # --- filesystem-access ---
    AttackCase(
        "broad-fs", "filesystem-access",
        "filesystem-access/broad-fs/.mcp.json",
        DETECTED, "MCP server with broad filesystem access.",
        ["AS-MCP-007"],
    ),
    AttackCase(
        "benign", "filesystem-access",
        "filesystem-access/benign/.mcp.json",
        DETECTED, "Benign MCP server with scoped path should produce no broad-fs finding.",
        [], is_benign=True,
    ),
    # --- mcp-attacks ---
    AttackCase(
        "secrets-env", "mcp-attacks",
        "mcp-attacks/secrets-env/.mcp.json",
        DETECTED, "MCP server receiving secret env vars.",
        ["AS-MCP-006"],
    ),
    AttackCase(
        "remote-exec", "mcp-attacks",
        "mcp-attacks/remote-exec/.mcp.json",
        PARTIALLY_DETECTED,
        "Remote MCP + executable package. Remote detected; the exec combination is not correlated.",
        ["AS-MCP-001", "AS-MCP-004"],
    ),
    AttackCase(
        "broad-fs-secrets", "mcp-attacks",
        "mcp-attacks/broad-fs-secrets/.mcp.json",
        DETECTED, "MCP server with broad FS + secrets.",
        ["AS-MCP-006", "AS-MCP-007", "AS-MCP-008"],
    ),
    AttackCase(
        "benign", "mcp-attacks",
        "mcp-attacks/benign/.mcp.json",
        DETECTED, "Benign local MCP server should produce no high-risk findings.",
        [], is_benign=True,
    ),
    # --- multi-stage ---
    AttackCase(
        "data-sync", "multi-stage",
        "multi-stage/data-sync/SKILL.md",
        DETECTED,
        "Multi-stage: read config -> extract key -> send externally. Detected by intra-file step-sequence analysis (AS-CHAIN-001).",
        ["AS-CHAIN-001"],
    ),
    AttackCase(
        "download-run", "multi-stage",
        "multi-stage/download-run/SKILL.md",
        DETECTED,
        "Multi-stage: download -> run. Detected by intra-file step-sequence analysis (AS-CHAIN-002).",
        ["AS-CHAIN-002"],
    ),
    AttackCase(
        "benign", "multi-stage",
        "multi-stage/benign/SKILL.md",
        DETECTED, "Benign multi-step report generator should produce no findings.",
        [], is_benign=True,
    ),
    # ===================== Attack Lab v2 =====================
    # --- v2 prompt-injection ---
    AttackCase("reveal-secrets-direct", "v2-prompt-injection", "v2/prompt-injection/reveal-secrets-direct/SKILL.md", DETECTED, "Direct instruction to reveal API keys.", ["AS-004"]),
    AttackCase("reveal-secrets-indirect", "v2-prompt-injection", "v2/prompt-injection/reveal-secrets-indirect/SKILL.md", PARTIALLY_DETECTED, "Indirect instruction to output secret env vars.", ["AS-004"]),
    AttackCase("ignore-previous", "v2-prompt-injection", "v2/prompt-injection/ignore-previous/SKILL.md", DETECTED, "Instruction to disregard previous instructions.", ["AS-004"]),
    AttackCase("role-impersonation", "v2-prompt-injection", "v2/prompt-injection/role-impersonation/SKILL.md", PARTIALLY_DETECTED, "Role/authority impersonation to print password file.", ["AS-004"]),
    AttackCase("hidden-in-docs", "v2-prompt-injection", "v2/prompt-injection/hidden-in-docs/SKILL.md", PARTIALLY_DETECTED, "Malicious instruction hidden in documentation.", ["AS-004"]),
    AttackCase("access-credentials", "v2-prompt-injection", "v2/prompt-injection/access-credentials/SKILL.md", PARTIALLY_DETECTED, "Instruction to read .env and ~/.ssh credentials.", ["AS-004"]),
    AttackCase("send-data-external", "v2-prompt-injection", "v2/prompt-injection/send-data-external/SKILL.md", DETECTED, "Instruction to send local config externally.", ["AS-004"]),
    AttackCase("benign-prohibit", "v2-prompt-injection", "v2/prompt-injection/benign-prohibit/SKILL.md", DETECTED, "Benign skill that prohibits revealing secrets.", [], is_benign=True),
    # --- v2 secret-access ---
    AttackCase("env-file", "v2-secret-access", "v2/secret-access/env-file/SKILL.md", PARTIALLY_DETECTED, "Read .env and print contents.", ["AS-004"]),
    AttackCase("aws-credentials", "v2-secret-access", "v2/secret-access/aws-credentials/SKILL.md", PARTIALLY_DETECTED, "Read ~/.aws/credentials and display secret key.", ["AS-004"]),
    AttackCase("ssh-key", "v2-secret-access", "v2/secret-access/ssh-key/SKILL.md", PARTIALLY_DETECTED, "Read ~/.ssh/id_rsa and output private key.", ["AS-004"]),
    AttackCase("config-password", "v2-secret-access", "v2/secret-access/config-password/SKILL.md", PARTIALLY_DETECTED, "Read config and extract password.", ["AS-004"]),
    AttackCase("api-token", "v2-secret-access", "v2/secret-access/api-token/SKILL.md", PARTIALLY_DETECTED, "Print API token from config.", ["AS-004"]),
    AttackCase("private-key", "v2-secret-access", "v2/secret-access/private-key/SKILL.md", PARTIALLY_DETECTED, "Read private key file and show contents.", ["AS-004"]),
    AttackCase("env-dump", "v2-secret-access", "v2/secret-access/env-dump/SKILL.md", DETECTED, "Print all environment variables.", ["AS-004"]),
    AttackCase("benign", "v2-secret-access", "v2/secret-access/benign/SKILL.md", DETECTED, "Benign config helper that redacts secrets.", [], is_benign=True),
    # --- v2 secret-exfiltration ---
    AttackCase("read-extract-post", "v2-secret-exfiltration", "v2/secret-exfiltration/read-extract-post/SKILL.md", DETECTED, "read -> extract -> POST externally.", ["AS-CHAIN-001"]),
    AttackCase("read-extract-webhook", "v2-secret-exfiltration", "v2/secret-exfiltration/read-extract-webhook/SKILL.md", DETECTED, "read -> extract -> webhook.", ["AS-CHAIN-001"]),
    AttackCase("read-transform-network", "v2-secret-exfiltration", "v2/secret-exfiltration/read-transform-network/SKILL.md", PARTIALLY_DETECTED, "read -> transform -> network (no explicit secret).", ["AS-CHAIN-001"]),
    AttackCase("read-secret-upload", "v2-secret-exfiltration", "v2/secret-exfiltration/read-secret-upload/SKILL.md", DETECTED, "read secret -> upload.", ["AS-CHAIN-001"]),
    AttackCase("many-unrelated-lines", "v2-secret-exfiltration", "v2/secret-exfiltration/many-unrelated-lines/SKILL.md", DETECTED, "read -> extract -> send with many unrelated lines between.", ["AS-CHAIN-001"]),
    AttackCase("different-network-api", "v2-secret-exfiltration", "v2/secret-exfiltration/different-network-api/SKILL.md", DETECTED, "read -> extract -> urllib POST.", ["AS-CHAIN-001"]),
    AttackCase("benign-read-network", "v2-secret-exfiltration", "v2/secret-exfiltration/benign-read-network/SKILL.md", DETECTED, "Benign read + network without sensitive data.", [], is_benign=True),
    # --- v2 download-execution ---
    AttackCase("curl-shell", "v2-download-execution", "v2/download-execution/curl-shell/install.sh", DETECTED, "curl piped to bash.", ["AS-002", "AS-003"]),
    AttackCase("wget-shell", "v2-download-execution", "v2/download-execution/wget-shell/install.sh", DETECTED, "wget piped to sh.", ["AS-002", "AS-003"]),
    AttackCase("fetch-execute", "v2-download-execution", "v2/download-execution/fetch-execute/run.py", DETECTED, "fetch remote content then execute.", ["AS-002", "AS-003"]),
    AttackCase("download-run-script", "v2-download-execution", "v2/download-execution/download-run-script/SKILL.md", DETECTED, "download script -> run script.", ["AS-CHAIN-002"]),
    AttackCase("remote-package-execute", "v2-download-execution", "v2/download-execution/remote-package-execute/SKILL.md", DETECTED, "fetch remote package -> execute.", ["AS-CHAIN-002"]),
    AttackCase("indirect-wording", "v2-download-execution", "v2/download-execution/indirect-wording/SKILL.md", PARTIALLY_DETECTED, "Indirect wording: retrieve then run.", ["AS-CHAIN-002"]),
    AttackCase("benign-download-only", "v2-download-execution", "v2/download-execution/benign-download-only/fetch.sh", DETECTED, "Benign download-only.", [], is_benign=True),
    AttackCase("benign-execute-only", "v2-download-execution", "v2/download-execution/benign-execute-only/build.sh", DETECTED, "Benign execute-only build.", [], is_benign=True),
    # --- v2 mcp-security ---
    AttackCase("remote-endpoint", "v2-mcp-security", "v2/mcp-security/remote-endpoint/.mcp.json", PARTIALLY_DETECTED, "Remote MCP endpoint (MEDIUM).", ["AS-MCP-001"]),
    AttackCase("http-not-https", "v2-mcp-security", "v2/mcp-security/http-not-https/.mcp.json", DETECTED, "HTTP MCP endpoint without HTTPS.", ["AS-MCP-002"]),
    AttackCase("dynamic-package", "v2-mcp-security", "v2/mcp-security/dynamic-package/.mcp.json", PARTIALLY_DETECTED, "npx dynamic package execution (MEDIUM).", ["AS-MCP-004"]),
    AttackCase("uvx-exec", "v2-mcp-security", "v2/mcp-security/uvx-exec/.mcp.json", PARTIALLY_DETECTED, "uvx dynamic package execution (MEDIUM).", ["AS-MCP-004"]),
    AttackCase("secret-env", "v2-mcp-security", "v2/mcp-security/secret-env/.mcp.json", DETECTED, "MCP server receiving secret env vars.", ["AS-MCP-006"]),
    AttackCase("broad-fs", "v2-mcp-security", "v2/mcp-security/broad-fs/.mcp.json", PARTIALLY_DETECTED, "MCP server with broad filesystem access (MEDIUM).", ["AS-MCP-007"]),
    AttackCase("suspicious-args", "v2-mcp-security", "v2/mcp-security/suspicious-args/.mcp.json", DETECTED, "MCP server with dangerous flags.", ["AS-MCP-008"]),
    AttackCase("remote-exec-combo", "v2-mcp-security", "v2/mcp-security/remote-exec-combo/.mcp.json", DETECTED, "Remote MCP + dynamic exec combo.", ["AS-CHAIN-003"]),
    AttackCase("benign", "v2-mcp-security", "v2/mcp-security/benign/.mcp.json", DETECTED, "Benign local MCP server.", [], is_benign=True),
    # --- v2 obfuscation ---
    AttackCase("base64-instruction", "v2-obfuscation", "v2/obfuscation/base64-instruction/SKILL.md", PARTIALLY_DETECTED, "Base64-encoded instruction to execute.", ["AS-004"]),
    AttackCase("rot13-instruction", "v2-obfuscation", "v2/obfuscation/rot13-instruction/SKILL.md", PARTIALLY_DETECTED, "ROT13-encoded instruction to run command.", ["AS-004"]),
    AttackCase("encoded-shell-command", "v2-obfuscation", "v2/obfuscation/encoded-shell-command/run.sh", PARTIALLY_DETECTED, "Encoded shell command piped to bash.", ["AS-002"]),
    AttackCase("encoded-url", "v2-obfuscation", "v2/obfuscation/encoded-url/SKILL.md", PARTIALLY_DETECTED, "Encoded URL to fetch.", ["AS-004"]),
    AttackCase("benign-encoded-data", "v2-obfuscation", "v2/obfuscation/benign-encoded-data/SKILL.md", DETECTED, "Benign encoding helper that does not execute.", [], is_benign=True),
    # --- v2 multi-stage ---
    AttackCase("source-sensitive-network", "v2-multi-stage", "v2/multi-stage/source-sensitive-network/SKILL.md", DETECTED, "source -> sensitive -> network.", ["AS-CHAIN-001"]),
    AttackCase("download-execution", "v2-multi-stage", "v2/multi-stage/download-execution/SKILL.md", DETECTED, "download -> execution.", ["AS-CHAIN-002"]),
    AttackCase("sensitive-transform-network", "v2-multi-stage", "v2/multi-stage/sensitive-transform-network/SKILL.md", PARTIALLY_DETECTED, "sensitive -> transform -> network.", ["AS-CHAIN-001"]),
    AttackCase("discovery-secret-network", "v2-multi-stage", "v2/multi-stage/discovery-secret-network/SKILL.md", PARTIALLY_DETECTED, "discovery -> secret -> network.", ["AS-CHAIN-001"]),
    AttackCase("benign", "v2-multi-stage", "v2/multi-stage/benign/SKILL.md", DETECTED, "Benign multi-step report generator.", [], is_benign=True),
    # --- v2 benign-lookalikes ---
    AttackCase("secrets-doc", "v2-benign-lookalikes", "v2/benign-lookalikes/secrets-doc/SKILL.md", DETECTED, "Documentation about handling secrets.", [], is_benign=True),
    AttackCase("secure-coding", "v2-benign-lookalikes", "v2/benign-lookalikes/secure-coding/SKILL.md", DETECTED, "Secure coding instructions.", [], is_benign=True),
    AttackCase("never-reveal", "v2-benign-lookalikes", "v2/benign-lookalikes/never-reveal/SKILL.md", DETECTED, "Security policy prohibiting secret disclosure.", [], is_benign=True),
    AttackCase("legit-deps", "v2-benign-lookalikes", "v2/benign-lookalikes/legit-deps/install.sh", DETECTED, "Installing legitimate dependencies.", [], is_benign=True),
    AttackCase("local-build", "v2-benign-lookalikes", "v2/benign-lookalikes/local-build/build.sh", DETECTED, "Local build commands.", [], is_benign=True),
    AttackCase("legit-mcp", "v2-benign-lookalikes", "v2/benign-lookalikes/legit-mcp/.mcp.json", DETECTED, "Legitimate local MCP server.", [], is_benign=True),
    AttackCase("env-vars", "v2-benign-lookalikes", "v2/benign-lookalikes/env-vars/SKILL.md", DETECTED, "Setting environment variables.", [], is_benign=True),
    AttackCase("http-requests", "v2-benign-lookalikes", "v2/benign-lookalikes/http-requests/SKILL.md", DETECTED, "Using HTTP clients legitimately.", [], is_benign=True),
    AttackCase("security-tutorial", "v2-benign-lookalikes", "v2/benign-lookalikes/security-tutorial/SKILL.md", DETECTED, "Security tutorial content.", [], is_benign=True),
    AttackCase("incident-response", "v2-benign-lookalikes", "v2/benign-lookalikes/incident-response/SKILL.md", DETECTED, "Incident-response instructions.", [], is_benign=True),
    # --- v2 sensitive-path (AS-006) ---
    AttackCase("env-read", "v2-sensitive-path", "v2/sensitive-path/env-read/SKILL.md", DETECTED, "Read .env file.", ["AS-006"]),
    AttackCase("aws-read", "v2-sensitive-path", "v2/sensitive-path/aws-read/SKILL.md", DETECTED, "cat ~/.aws/credentials.", ["AS-006"]),
    AttackCase("ssh-read", "v2-sensitive-path", "v2/sensitive-path/ssh-read/SKILL.md", DETECTED, "cat ~/.ssh/id_rsa.", ["AS-006"]),
    AttackCase("credentials-read", "v2-sensitive-path", "v2/sensitive-path/credentials-read/SKILL.md", DETECTED, "open the credentials file.", ["AS-006"]),
    AttackCase("print-env", "v2-sensitive-path", "v2/sensitive-path/print-env/SKILL.md", DETECTED, "print the contents of .env.", ["AS-006"]),
    AttackCase("private-key-read", "v2-sensitive-path", "v2/sensitive-path/private-key-read/SKILL.md", DETECTED, "read the private key from ~/.ssh/id_ed25519.", ["AS-006"]),
    AttackCase("benign-docs", "v2-sensitive-path", "v2/sensitive-path/benign-docs/SKILL.md", DETECTED, "Benign docs mentioning sensitive paths without access.", [], is_benign=True),
    AttackCase("benign-normal-read", "v2-sensitive-path", "v2/sensitive-path/benign-normal-read/SKILL.md", DETECTED, "Benign read of a normal file.", [], is_benign=True),
]


def _classify(case: AttackCase, findings) -> str:
    """Classify a fixture's detection result against its expectation.

    Methodology:
    - Benign lookalike: any HIGH/CRITICAL finding is a FALSE_POSITIVE;
      otherwise DETECTED (correctly clean).
    - Attack fixture: a HIGH/CRITICAL finding of ANY rule (including
      correlation/chain findings like AS-CHAIN-*) counts as DETECTED. The
      attack is genuinely identified at high severity even if the individual
      underlying rules did not independently trigger.
    - If no HIGH/CRITICAL finding exists, expected_rules distinguishes
      PARTIALLY_DETECTED (an expected rule fired at lower severity) from
      MISSED (no relevant finding).
    """
    if case.is_benign:
        # Benign lookalike: any HIGH/CRITICAL finding is a false positive.
        if any(f.severity.value in DETECTION_SEVERITIES for f in findings):
            return FALSE_POSITIVE
        return DETECTED  # correctly clean

    # Attack fixture: any HIGH/CRITICAL finding is a valid detection.
    if any(f.severity.value in DETECTION_SEVERITIES for f in findings):
        return DETECTED

    # No HIGH/CRITICAL finding. Use expected_rules to distinguish partial
    # (an expected rule fired at lower severity) from missed.
    if case.expected_rules:
        any_rules = {f.rule_id for f in findings}
        if any_rules & set(case.expected_rules):
            return PARTIALLY_DETECTED
        return MISSED

    # No expected rules specified: any finding is partial, none is missed.
    if findings:
        return PARTIALLY_DETECTED
    return MISSED


@dataclass
class AttackLabResult:
    cases: List[Dict] = field(default_factory=list)

    def summary(self) -> Dict:
        counts = {
            "total": len(self.cases),
            "detected": 0,
            "partially_detected": 0,
            "missed": 0,
            "false_positives": 0,
        }
        # Map uppercase result labels to lowercase summary keys.
        key_map = {
            DETECTED: "detected",
            PARTIALLY_DETECTED: "partially_detected",
            MISSED: "missed",
            FALSE_POSITIVE: "false_positives",
        }
        for c in self.cases:
            key = key_map.get(c["result"])
            if key:
                counts[key] += 1
        detected = counts["detected"]
        total = counts["total"]
        counts["detection_percentage"] = round(100 * detected / total, 1) if total else 0.0
        return counts

    def categories(self) -> Dict[str, Dict]:
        cats: Dict[str, Dict] = {}
        key_map = {
            DETECTED: "detected",
            PARTIALLY_DETECTED: "partially_detected",
            MISSED: "missed",
            FALSE_POSITIVE: "false_positives",
        }
        for c in self.cases:
            cat = c["category"]
            if cat not in cats:
                cats[cat] = {"total": 0, "detected": 0, "partially_detected": 0, "missed": 0, "false_positives": 0}
            cats[cat]["total"] += 1
            key = key_map.get(c["result"])
            if key:
                cats[cat][key] += 1
        return cats

    def to_dict(self) -> Dict:
        return {
            "summary": self.summary(),
            "categories": self.categories(),
            "cases": self.cases,
        }


def run_attack_lab(corpus_dir: Optional[str] = None) -> AttackLabResult:
    """Run AgentShield against every attack fixture and classify results."""
    if corpus_dir is None:
        # __file__ = <root>/src/agentshield/attack_lab.py
        root_dir = Path(__file__).resolve().parent.parent.parent
        corpus_dir = str(root_dir / "tests" / "fixtures" / "attacks")
    root = Path(corpus_dir)

    result = AttackLabResult()
    for case in ATTACK_CASES:
        path = root / case.path
        if not path.exists():
            result.cases.append({
                "name": case.name,
                "category": case.category,
                "path": case.path,
                "result": "MISSED",
                "reason": "fixture not found",
                "findings": [],
            })
            continue

        scan = scan_path(str(path))
        findings = [f.to_dict() for f in scan.findings]
        classification = _classify(case, scan.findings)
        result.cases.append({
            "name": case.name,
            "category": case.category,
            "path": case.path,
            "expected": case.expected,
            "result": classification,
            "description": case.description,
            "is_benign": case.is_benign,
            "findings": findings,
        })

    return result
