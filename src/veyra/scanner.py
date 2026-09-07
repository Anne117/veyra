"""Core scanner: recursively inspects files relevant to AI agent skills.

Static analysis only. Never executes scanned code and never makes network
requests.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from veyra.correlation import correlate
from veyra.cwe import cwe_for
from veyra.mitre import mitre_for
from veyra.models import Confidence, Finding, ScanResult
from veyra.rules import load_file_rules, load_rules
from veyra.step_sequence import analyze_file

# File extensions we inspect. Everything else is skipped.
SCAN_EXTENSIONS = {
    ".md",
    ".markdown",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".txt",
    ".cfg",
    ".conf",
    ".ini",
    ".env",
}

# Files always inspected regardless of extension.
ALWAYS_SCAN = {"SKILL.md", "AGENTS.md", "CLAUDE.md", ".hermes.md", "HERMES.md"}

# Directories we never descend into.
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".eggs",
    "site-packages",
}

# Maximum file size to scan (bytes). Larger files are skipped as "binary/large".
MAX_FILE_SIZE = 1_000_000  # 1 MB


def _is_binary(data: bytes) -> bool:
    """Heuristic: a file is binary if it contains a NUL byte in the first chunk."""
    return b"\x00" in data[:8192]


def _should_scan(path: Path) -> bool:
    if path.name in ALWAYS_SCAN:
        return True
    return path.suffix.lower() in SCAN_EXTENSIONS


def scan_path(target: str) -> ScanResult:
    """Scan a file or directory and return a ScanResult."""
    rules = load_rules()
    file_rules = load_file_rules()
    findings: List[Finding] = []
    file_texts: List[str] = []  # (text, path) pairs for step-sequence analysis
    root = Path(target)

    if root.is_file():
        findings.extend(_scan_file(root, rules, file_rules, file_texts))
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                findings.extend(_scan_file(fpath, rules, file_rules, file_texts))
    else:
        raise FileNotFoundError(f"Path not found: {target}")

    # Run the contextual correlation layer over all findings.
    # Correlation findings are added separately; original findings are preserved.
    correlated = correlate(findings)
    findings.extend(correlated)

    # Run intra-file step-sequence analysis. This fills the gap when individual
    # steps are too benign to generate standalone findings. Deduplicate against
    # chains already emitted by correlation (same rule_id) to avoid duplicates.
    correlated_ids = {c.rule_id for c in correlated}
    for text, path in file_texts:
        for chain in analyze_file(text, path):
            if chain.rule_id in correlated_ids:
                continue
            findings.append(chain)

    # Attach approved public MITRE ATT&CK metadata, CWE IDs, and a
    # deterministic confidence estimate to findings.
    # This is metadata/reporting only — it does not change detection logic.
    for f in findings:
        f.mitre = mitre_for(f.rule_id, f.evidence)
        f.cwe = cwe_for(f.rule_id)
        f.confidence = _confidence_for(f)
        # Correlation/step-sequence findings have no single source line; use
        # the evidence as the smallest defensible source fragment.
        if not f.matched_text:
            f.matched_text = f.evidence or ""

    return ScanResult(target=target, findings=findings)


def _confidence_for(f: Finding) -> Confidence:
    """Deterministic confidence estimate based on rule semantics.

    Confidence reflects how reliably the detected behavior matches the rule,
    NOT how dangerous it is (that is Severity).
    """
    # Correlation/step-sequence chains are high-confidence by construction
    # (they require multiple corroborating signals).
    if f.rule_id.startswith("AS-CHAIN"):
        return Confidence.HIGH
    # Obfuscation findings require decoded content + execution/fetch context.
    if f.rule_id == "AS-007":
        return Confidence.HIGH
    # Sensitive credential access requires an access verb + sensitive path.
    if f.rule_id == "AS-006":
        return Confidence.HIGH
    # Hardcoded secrets with a strong pattern (OpenAI/Anthropic/GitHub/AWS/
    # private key) are high-confidence; generic key/password are medium.
    if f.rule_id == "AS-001":
        if "API credential detected" in f.evidence or "Private key block" in f.evidence:
            return Confidence.HIGH
        return Confidence.MEDIUM
    # MCP structural findings are medium-confidence (config-only, no runtime).
    if f.rule_id.startswith("AS-MCP"):
        return Confidence.MEDIUM
    # Prompt injection / network / URL / shell regex findings are medium.
    return Confidence.MEDIUM


def _scan_file(path: Path, rules, file_rules, file_texts) -> List[Finding]:
    if not _should_scan(path):
        return []

    try:
        size = path.stat().st_size
    except OSError:
        return []

    if size > MAX_FILE_SIZE:
        return []

    try:
        data = path.read_bytes()
    except OSError:
        return []

    if _is_binary(data):
        return []

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    file_texts.append((text, str(path)))

    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            try:
                finding = rule(line, str(path), lineno)
            except Exception:
                # A rule must never crash the whole scan.
                continue
            if finding is not None:
                # Preserve the exact source line that triggered the rule.
                # For secret findings, use the already-redacted evidence so
                # the raw secret never appears in reports.
                if not finding.matched_text:
                    if finding.rule_id == "AS-001":
                        finding.matched_text = finding.evidence or ""
                    else:
                        finding.matched_text = line.strip()
                findings.append(finding)

    # File-level rules (structured formats like MCP config).
    for frule in file_rules:
        try:
            for finding in frule(text, str(path)):
                # File-rule findings have no single line; use the evidence as
                # the smallest defensible source fragment.
                if not finding.matched_text:
                    finding.matched_text = finding.evidence or ""
                findings.append(finding)
        except Exception:
            continue

    return findings
