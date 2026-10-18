"""Veyra command-line interface."""

from __future__ import annotations

import argparse
import json
import sys

from veyra.attack_lab import run_attack_lab
from veyra.models import Severity
from veyra.reporters import render_html, render_json, render_sarif, render_terminal
from veyra.scanner import scan_path
from veyra.suppress import apply_suppression, load_config
from veyra.threats import (
    OWASP_AGENTIC_2026,
    serialize_threat_taxonomy,
)

# Severity ordering for the failure threshold.
_SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veyra",
        description="Security scanner for AI agent skills and MCP-related resources.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("path", help="File or directory to scan.")
    scan.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "html"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    scan.add_argument(
        "--config",
        default=None,
        help="Path to a .veyra.toml config file (default: auto-discover).",
    )
    scan.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Minimum severity that causes a non-zero exit (default: HIGH).",
    )

    threats_p = sub.add_parser(
        "threats",
        help="Inspect built-in threat-taxonomy catalogs (read-only).",
    )
    threats_sub = threats_p.add_subparsers(dest="threats_command", required=True)

    tlist = threats_sub.add_parser(
        "list",
        help="List built-in threat-taxonomy catalogs and their entries.",
    )
    tlist.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal).",
    )

    tshow = threats_sub.add_parser(
        "show",
        help="Show one threat-taxonomy entry by ID (e.g. ASI05).",
    )
    tshow.add_argument(
        "entry_id",
        help="Taxonomy entry id (e.g. ASI05).",
    )
    tshow.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal).",
    )

    lab = sub.add_parser("attack-lab", help="Run the adversarial attack corpus.")
    lab.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    return parser


def _exit_code(result, fail_on: str) -> int:
    """Exit code based on the failure threshold.

    0 = no findings at or above the threshold.
    1 = findings at or above the threshold (but below CRITICAL).
    2 = CRITICAL findings.
    """
    threshold = _SEVERITY_ORDER[fail_on]
    active = [f for f in result.findings if not f.suppressed]

    if any(f.severity == Severity.CRITICAL for f in active):
        return 2
    for f in active:
        if _SEVERITY_ORDER[f.severity.value] >= threshold:
            return 1
    return 0




def _threat_catalogs():
    """Return the static list of available threat-taxonomy catalogs.

    Read-only: returns already-built immutable ThreatTaxonomy objects. Adding a
    new catalog here is the only step needed to expose it through the CLI.
    """
    # Static list of (taxonomy, get_taxonomy) tuples.
    return [
        OWASP_AGENTIC_2026,
    ]


def _find_entry(taxonomy, entry_id):
    for e in taxonomy.entries:
        if e.entry_id == entry_id:
            return e
    return None


def _render_threats_list(catalogs, fmt):
    if fmt == "json":
        payload = [serialize_threat_taxonomy(t) for t in catalogs]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    lines = ["Veyra Threat Taxonomies", "=" * 25, ""]
    for t in catalogs:
        lines.append(f"{t.taxonomy_id}  v{t.version}  ({len(t.entries)} entries)")
        lines.append(f"  Name:      {t.name}")
        lines.append(f"  Reference: {t.reference}")
        lines.append("  Entries:")
        for e in t.entries:
            lines.append(f"    {e.entry_id}  {e.name}")
        lines.append("")
    print("\n".join(lines))


def _render_threats_show(taxonomy, entry, fmt):
    if fmt == "json":
        from veyra.threats.taxonomy import _serialize_entry
        payload = {
            "taxonomy": {
                "taxonomy_id": taxonomy.taxonomy_id,
                "name": taxonomy.name,
                "version": taxonomy.version,
                "reference": taxonomy.reference,
            },
            "entry": _serialize_entry(entry),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    print(f"Veyra Threat Entry: {entry.entry_id}")
    print("=" * (20 + len(entry.entry_id)))
    print(f"Name:        {entry.name}")
    print(f"Description: {entry.description}")
    print(f"Taxonomy:    {taxonomy.name} (v{taxonomy.version})")
    print(f"Reference:   {entry.source.reference}")


def _render_attack_lab(lab) -> str:
    """Render the attack-lab results as a readable terminal report."""
    s = lab.summary()
    lines = []
    lines.append("Veyra Attack Lab")
    lines.append("=" * 30)
    lines.append("")
    lines.append(f"Total cases:        {s['total']}")
    lines.append(f"Detected:           {s['detected']}")
    lines.append(f"Partially detected: {s['partially_detected']}")
    lines.append(f"Missed:             {s['missed']}")
    lines.append(f"False positives:    {s['false_positives']}")
    lines.append(f"Detection rate:     {s['detection_percentage']}%")
    lines.append("")
    lines.append("By category:")
    for cat, c in lab.categories().items():
        lines.append(
            f"  {cat:<22} total={c['total']} detected={c['detected']} "
            f"partial={c['partially_detected']} missed={c['missed']} fp={c['false_positives']}"
        )
    lines.append("")
    lines.append("Cases:")
    for c in lab.cases:
        lines.append(f"  [{c['result']:<18}] {c['category']}/{c['name']}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            result = scan_path(args.path)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2

        config = load_config(args.config or args.path)
        result.findings = apply_suppression(result.findings, config)

        if args.format == "json":
            print(render_json(result))
        elif args.format == "sarif":
            print(render_sarif(result))
        elif args.format == "html":
            print(render_html(result))
        else:
            print(render_terminal(result))

        # Policy security gate: a policy violation (policy_status == "FAIL")
        # forces a non-zero exit (at least 1). The severity-based exit code is
        # preserved; policy failure never overrides a CRITICAL (2) but upgrades
        # a clean/low-severity (0) result to 1. The single source of truth for
        # the policy part is the finalized ScanResult policy status.
        severity_code = _exit_code(result, args.fail_on)
        policy_code = 1 if result.policy_status == "FAIL" else 0
        return max(severity_code, policy_code)

    if args.command == "threats":
        catalogs = _threat_catalogs()
        if args.threats_command == "list":
            _render_threats_list(catalogs, args.format)
            return 0
        if args.threats_command == "show":
            entry_id = args.entry_id
            for t in catalogs:
                entry = _find_entry(t, entry_id)
                if entry is not None:
                    _render_threats_show(t, entry, args.format)
                    return 0
            print(
                f"Error: entry id '{entry_id}' not found in any built-in catalog.",
                file=sys.stderr,
            )
            return 2

    if args.command == "attack-lab":
        lab = run_attack_lab()
        if args.format == "json":
            print(json.dumps(lab.to_dict(), indent=2))
        else:
            print(_render_attack_lab(lab))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
