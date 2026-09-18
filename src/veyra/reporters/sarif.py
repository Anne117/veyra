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

from veyra.graph.path import AttackPath, AttackType
from veyra.models import ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Map Veyra severity to SARIF result level.
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


# Deterministic SARIF rule id for an attack path, derived from the existing
# AttackType semantics. This reuses the existing attack-type vocabulary as the
# semantic identity of the path result; it is NOT a policy id and does not
# introduce a new policy-id namespace.
_ATTACK_TYPE_RULE_IDS = {
    AttackType.SECRET_EXFILTRATION: "ATTACK-PATH-" + AttackType.SECRET_EXFILTRATION.value,
    AttackType.DATA_EXFILTRATION: "ATTACK-PATH-" + AttackType.DATA_EXFILTRATION.value,
    AttackType.CORRELATED_SECRET_EXECUTION: "ATTACK-PATH-" + AttackType.CORRELATED_SECRET_EXECUTION.value,
    AttackType.UNKNOWN: "ATTACK-PATH-" + AttackType.UNKNOWN.value,
}


def _attack_type_rule_id(attack_type: AttackType) -> str:
    """Stable SARIF rule id for an attack type."""
    return _ATTACK_TYPE_RULE_IDS.get(attack_type, "ATTACK-PATH-UNKNOWN")


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
                    "justification": f.suppression_reason or "suppressed by .veyra.toml",
                }
            ]

        results.append(r)
    return results


def _build_attack_rules(paths: List[AttackPath]) -> List[Dict[str, Any]]:
    """Build SARIF `rules` entries for attack paths, deduplicated by attack type."""
    rules: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        rule_id = _attack_type_rule_id(p.attack_type)
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": p.attack_type.value,
            "shortDescription": {"text": p.explanation or p.attack_type.value},
            "fullDescription": {"text": p.explanation or p.attack_type.value},
        }
    return list(rules.values())


def _attack_path_result(path: AttackPath) -> Dict[str, Any]:
    """Build a single SARIF result for one AttackPath.

    Only already-existing AttackPath fields are exposed, converted to their
    serialized representations (enum/objects are never placed directly into
    SARIF properties). ``path_id`` remains the stable deterministic identity.
    Locations are intentionally omitted: an AttackPath carries no trustworthy
    source file/line provenance, so nothing would be fabricated.
    """
    # Serialize to stable, JSON-safe values.
    path_dict = path.to_dict()
    properties = {
        "path_id": path_dict["path_id"],
        "attack_type": path_dict["attack_type"],
        "risk_severity": path_dict["risk_severity"],
        "risk_confidence": path_dict["risk_confidence"],
        "risk_score": path_dict["risk_score"],
        "evidence": list(path_dict["evidence"]),
    }
    # Expose existing breakpoint information, if present, in machine-readable form.
    breakpoints = [b.to_dict() for b in path.breakpoints]
    if breakpoints:
        properties["breakpoints"] = breakpoints

    # Expose the violated policy IDs for this specific path via the existing
    # `properties` mechanism (no new SARIF structure).
    if path_dict.get("policy_ids"):
        properties["policy_ids"] = list(path_dict["policy_ids"])

    # Expose provenance via the existing `properties` mechanism only. A
    # provenance component is metadata, NOT a SARIF location — we never fabricate
    # a physicalLocation from it.
    if path_dict.get("provenance"):
        properties["provenance"] = {
            "nodes": {str(n): list(p.get("components", [])) for n, p in path_dict["provenance"]["nodes"].items()},
            "edges": [e.get("components", []) for e in path_dict["provenance"]["edges"]],
            "associated_edges": [e.get("components", []) for e in path_dict["provenance"]["associated_edges"]],
        }

    # Expose the structured explanation under `properties` (additive; the SARIF
    # message remains the existing `path.explanation` string).
    if path_dict.get("explanation_details"):
        properties["explanation"] = path_dict["explanation_details"]

    # Expose explicit component-context metadata under `properties` (additive).
    # This is context/scope metadata only — it references an existing security
    # behavioral component and never fabricates a SARIF location or a new edge.
    if path_dict.get("context_components"):
        properties["security_behavior_context"] = path_dict["context_components"]

    return {
        "ruleId": _attack_type_rule_id(path.attack_type),
        "level": _level(path.risk_severity),
        "message": {"text": path.explanation or path.attack_type.value},
        "properties": properties,
    }


def _component_security_scopes(result: ScanResult) -> List[Dict[str, Any]]:
    """Expose the additive component-security-scope projection (JSON-safe)."""
    return list(getattr(result, "component_security_scopes", []))


def _component_path_participation(result: ScanResult) -> List[Dict[str, Any]]:
    """Expose the additive component-path-participation projection (JSON-safe)."""
    return list(getattr(result, "component_path_participation", []))


def _component_path_composition(result: ScanResult) -> List[Dict[str, Any]]:
    """Expose the additive component-path-composition projection (JSON-safe)."""
    return list(getattr(result, "component_path_composition", []))


def _build_attack_path_results(paths: List[AttackPath]) -> List[Dict[str, Any]]:
    """Build the SARIF `results` array from attack paths.

    Deterministic: paths are consumed in their existing (path_id-ordered) order
    and emitted as-is, so repeated rendering of the same ScanResult is stable.
    """
    return [_attack_path_result(p) for p in paths]


def render_sarif(result: ScanResult) -> str:
    """Render a ScanResult as a SARIF 2.1.0 JSON document."""
    scopes = _component_security_scopes(result)
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Veyra",
                "informationUri": "https://github.com/veyra/veyra",
                "version": "0.1.0",
                "rules": _build_rules(result) + _build_attack_rules(result.attack_paths),
            }
        },
        "artifacts": _build_artifacts(result),
        "results": _build_results(result) + _build_attack_path_results(result.attack_paths),
    }
    # Run-level additive component-security-scope projection. Present only when
    # the caller supplied explicit scope data; never fabricated.
    run_props: Dict[str, Any] = {}
    if scopes:
        run_props["component_security_scopes"] = scopes
    participation = _component_path_participation(result)
    if participation:
        run_props["component_path_participation"] = participation
    composition = _component_path_composition(result)
    if composition:
        run_props["component_path_composition"] = composition
    if run_props:
        run["properties"] = run_props
    doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    return json.dumps(doc, indent=2)
