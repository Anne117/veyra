"""AgentShield command-line interface."""

from __future__ import annotations

import argparse
import json
import sys

from agentshield.attack_lab import run_attack_lab
from agentshield.models import Severity
from agentshield.reporters import render_json, render_sarif, render_terminal
from agentshield.scanner import scan_path
from agentshield.suppress import apply_suppression, load_config

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
        prog="agentshield",
        description="Security scanner for AI agent skills and MCP-related resources.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("path", help="File or directory to scan.")
    scan.add_argument(
        "--format",
        choices=["terminal", "json", "sarif"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    scan.add_argument(
        "--config",
        default=None,
        help="Path to a .agentshield.toml config file (default: auto-discover).",
    )
    scan.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Minimum severity that causes a non-zero exit (default: HIGH).",
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


def _render_attack_lab(lab) -> str:
    """Render the attack-lab results as a readable terminal report."""
    s = lab.summary()
    lines = []
    lines.append("AgentShield Attack Lab")
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
        else:
            print(render_terminal(result))

        return _exit_code(result, args.fail_on)

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
