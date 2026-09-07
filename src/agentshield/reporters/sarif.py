"""SARIF 2.1.0 report renderer.

Generates a valid SARIF 2.1.0 document from a ScanResult, compatible with
GitHub Code Scanning and other SARIF-compatible security tooling.

Mapping:
  rule_id        -> rule.id
  title          -> rule.name / result.message
  description    -> rule.shortDescription / rule.fullDescription
  severity       -> result.level
  file           -> artifact location (uri)
  line number    -> region.startLine
  remediation    -> rule.help / helpUri guidance

Suppressed findings are preserved via SARIF's `suppressions` array on the
result, so they are never silently turned into clean results.

This renderer is fully static: it makes no network requests and never
executes scanned files.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from agentshield.models import ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Map AgentShield severity to SARIF result level.
# SARIF levels: "error", "warning", "note", "none".
_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _level(severity: Severity) -> str:
    return _SEVERITY_TO_LEVEL.get(severity, "note")


def _uri(file: str) -> str:
    """Convert a filesystem path to a SARIF artifact URI."""
    # Normalize backslashes to forward slashes for URI compatibility.
    return file.replace("\\", "/")


def _build_rules(result: ScanResult) -> List[Dict[str, Any]]:
    """Build the SARIF `rules` array, deduplicated by rule_id."""
    rules: Dict[str, Dict[str, Any]] = {}
    for f in result.findings:
        if f.rule_id in rules:
            continue
        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
        }
        if f.remediation:
            rules[f.rule_id]["help"] = {"text": f.remediation}
        # Expose approved MITRE metadata, CWE, and confidence in the standard
        # `properties` field. This is a valid SARIF 2.1.0 field.
        props: Dict[str, Any] = {}
        if f.mitre:
            props["mitre"] = f.mitre
        if f.cwe:
            props["cwe"] = f.cwe
        if f.confidence:
            props["confidence"] = f.confidence.value
        if props:
            rules[f.rule_id]["properties"] = props
    return list(rules.values())


def _build_artifacts(result: ScanResult) -> List[Dict[str, Any]]:
    """Build the SARIF `artifacts` array, deduplicated by file path."""
    seen: Dict[str, bool] = {}
    artifacts: List[Dict[str, Any]] = []
    for f in result.findings:
        if f.file in seen:
            continue
        seen[f.file] = True
        artifacts.append({"location": {"uri": _uri(f.file)}})
    return artifacts


def _build_results(result: ScanResult) -> List[Dict[str, Any]]:
    """Build the SARIF `results` array from findings."""
    results: List[Dict[str, Any]] = []
    for f in result.findings:
        r: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _level(f.severity),
            "message": {"text": f.title},
        }
        if f.matched_text:
            r["message"]["text"] = f"{f.title}: {f.matched_text}"
        if f.file:
            loc: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.file)},
                }
            }
            if f.line:
                loc["physicalLocation"]["region"] = {"startLine": f.line}
            r["locations"] = [loc]

        # Preserve suppression information in a standards-compatible way.
        if f.suppressed:
            r["suppressions"] = [
                {
                    "kind": "external",
                    "justification": f.suppression_reason or "suppressed by .agentshield.toml",
                }
            ]

        results.append(r)
    return results


def render_sarif(result: ScanResult) -> str:
    """Render a ScanResult as a SARIF 2.1.0 JSON document."""
    doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentShield",
                        "informationUri": "https://github.com/agentshield/agentshield",
                        "version": "0.1.0",
                        "rules": _build_rules(result),
                    }
                },
                "artifacts": _build_artifacts(result),
                "results": _build_results(result),
            }
        ],
    }
    return json.dumps(doc, indent=2)
