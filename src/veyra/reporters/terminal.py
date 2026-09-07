"""Terminal report renderer."""

from __future__ import annotations

from veyra.models import ScanResult, Severity

# Simple box-drawing separator (no external deps).
SEP = "\u2501" * 30


def render_terminal(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("Veyra Security Report")
    lines.append(SEP)
    lines.append("")
    lines.append(f"Target: {result.target}")
    lines.append(f"Risk: {result.risk_level}")
    lines.append(f"Score: {result.score}/100")
    lines.append("")

    for f in result.findings:
        sev = f.severity.value
        loc = f"{f.file}"
        if f.line:
            loc += f":{f.line}"
        if f.suppressed:
            lines.append(f"[SUPPRESSED] {f.rule_id}  {f.title}")
            lines.append(f"          {loc}")
            lines.append(f"          {f.description}")
            lines.append(f"          Suppressed: {f.suppression_reason}")
        else:
            lines.append(f"{sev:<8}  {f.rule_id}  {f.title}")
            lines.append(f"          {loc}")
            lines.append(f"          {f.description}")
            if f.evidence:
                lines.append(f"          Evidence: {f.evidence}")
        if f.confidence:
            lines.append(f"          Confidence: {f.confidence.value}")
        if f.cwe:
            lines.append(f"          CWE: {', '.join(f.cwe)}")
        if f.mitre:
            for m in f.mitre:
                lines.append(f"          MITRE ATT&CK: {m['id']} — {m['name']}")
        if f.matched_text:
            lines.append(f"          Matched: {f.matched_text}")
        lines.append("")

    s = result.summary()
    lines.append("Summary")
    lines.append("-------")
    lines.append(f"Critical: {s['critical']}")
    lines.append(f"High:     {s['high']}")
    lines.append(f"Medium:   {s['medium']}")
    lines.append(f"Low:      {s['low']}")
    lines.append(f"Suppressed: {s['suppressed']}")
    lines.append("")
    return "\n".join(lines)
