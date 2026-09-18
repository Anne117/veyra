"""Standalone, deterministic HTML security report renderer.

Turns an existing :class:`~veyra.models.ScanResult` into a single self-contained
HTML document (inline CSS, no network, no external assets) that makes the
Security Graph / Attack Paths readable by a security engineer.

This is a pure presentation layer: it only reads existing ScanResult /
AttackPath / Breakpoint / PolicyResult / Finding fields and renders them. It
recalculates nothing, detects nothing, and never re-runs the policy engine.

Determinism: the document contains no render-time timestamps, random ids, or
unordered set iteration. Attack paths are rendered in their existing (path_id
stable) order; findings and policy results in their existing orders.

Security: every dynamic value is HTML-escaped, so hostile content originating
from scanned files, node ids, evidence, or descriptions can never inject markup.
"""

from __future__ import annotations

import html as _html
from typing import Any, Dict, List

from veyra.models import ScanResult, Severity
from veyra.graph.path import AttackPath


def _esc(value) -> str:
    """Escape an arbitrary value as safe, printable HTML text.

    Any dynamic value coming from scan data is treated as untrusted input. None
    and empty values map to a neutral "not available".
    """
    if value is None:
        return _html.escape("(not available)", quote=True)
    return _html.escape(str(value), quote=True)


# ---------------------------------------------------------------------------
# Severity presentation
# ---------------------------------------------------------------------------

# Deterministic order: most to least dangerous.
_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _severity_badge(severity: Severity) -> str:
    """Render a severity value as a colored badge."""
    name = _esc(severity.value)
    return f'<span class="badge sev-{name.lower()}">{name}</span>'


def _highest_attack_risk(paths: List[AttackPath]) -> Dict[str, Any]:
    """The highest-risk attack path, derived only from existing fields.

    Deterministic: on equal risk we keep the first path encountered, iterating
    in the stable upstream order (no set/dict iteration).
    """
    if not paths:
        return {}
    best = paths[0]
    _rank = {s.value: i for i, s in enumerate(_SEVERITY_ORDER)}
    for p in paths[1:]:
        if p.risk_score > best.risk_score or (
            p.risk_score == best.risk_score
            and _rank.get(p.risk_severity.value, 99) < _rank.get(best.risk_severity.value, 99)
        ):
            best = p
    return {
        "attack_type": best.attack_type.value,
        "severity": best.risk_severity.value,
        "score": best.risk_score,
    }


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section(title: str, inner: str, cls: str = "") -> str:
    cls_attr = f' class="{cls}"' if cls else ""
    return f'<section{cls_attr}><h2>{_esc(title)}</h2>{inner}</section>'


def _summary_html(result: ScanResult) -> str:
    total_findings = len(result.findings)
    total_paths = len(result.attack_paths)
    highest = _highest_attack_risk(result.attack_paths)

    status = result.risk_level  # existing ScanResult field (never invented)
    status_cls = status.lower()

    cells = [
        ("Target", _esc(result.target)),
        ("Security status", f'<span class="badge sev-{_esc(status_cls)}">{_esc(status)}</span>'),
        ("Findings", _esc(total_findings)),
        ("Attack paths", _esc(total_paths)),
        ("Score", _esc(result.score)),
    ]
    if highest:
        cells.append(("Highest attack risk", _esc(highest["score"])))
        cells.append(("Highest attack type", _esc(highest["attack_type"])))

    cards = "".join(
        f'<div class="stat"><div class="stat-label">{_esc(label)}</div>'
        f'<div class="stat-value">{value}</div></div>'
        for label, value in cells
    )
    return f'<div class="grid">{cards}</div>'


def _chain_html(path: AttackPath) -> str:
    """Render the truthful contiguous walk derived from path.nodes + path.edges.

    The visual chain is driven strictly by the REAL ordered edge sequence on the
    AttackPath. Node i is joined to node i+1 by edge i's type. Nothing is
    inferred from node names and no edge is synthesized.
    """
    rows: List[str] = []
    edges = path.edges
    for i, node in enumerate(path.nodes):
        badge = f'<span class="node">{_esc(node)}</span>'
        rows.append(f'<div class="chain-node" data-i="{i}">{badge}</div>')
        if i < len(edges):
            edge_type = _esc(edges[i][2])
            rows.append(
                f'<div class="chain-edge"><span class="edge-arrow">↓</span>'
                f'<span class="edge-type">{edge_type}</span></div>'
            )
    return f'<div class="chain">{"".join(rows)}</div>'


# Known semantic node-type labels from the existing Security Graph vocabulary
# (veyra.graph.models.NodeType). Node ids follow the established '<TYPE>:<key>'
# convention (e.g. 'SKILL:payment', 'SECRET:.aws/credentials'). The type prefix
# is the existing semantic identity, not a guess. An id without a recognized
# prefix is shown as-is with no invented type.
_NODE_TYPE_LABELS = {
    "AGENT": "AGENT",
    "SKILL": "SKILL",
    "TOOL": "TOOL",
    "MCPSERVER": "MCP SERVER",
    "DATA": "DATA",
    "SECRET": "SECRET",
    "ENDPOINT": "ENDPOINT",
    "ACTION": "ACTION",
}


def _node_parts(node: str):
    """Split a semantic node id into (label, key).

    Uses the project's '<TYPE>:<key>' convention. Falls back to (None, node)
    when the prefix is not a recognized NodeType, so a node type is never
    guessed from arbitrary strings.
    """
    if ":" in node:
        prefix, _, rest = node.partition(":")
        if prefix in _NODE_TYPE_LABELS:
            return _NODE_TYPE_LABELS[prefix], rest
    return None, node


def _graph_node(node: str) -> str:
    """Render a single node card in the attack-path graph."""
    ntype, key = _node_parts(node)
    if ntype:
        type_badge = f'<span class="graph-node-type">{_esc(ntype)}</span>'
    else:
        type_badge = ""
    return (
        f'<div class="graph-node">{type_badge}'
        f'<span class="graph-node-key mono">{_esc(key if ntype else node)}</span></div>'
    )


def _graph_edge(edge_type: str) -> str:
    """Render a vertical connector labelled with the real edge type."""
    return (
        f'<div class="graph-edge" role="presentation">'
        f'<span class="graph-edge-label mono">{_esc(edge_type)}</span>'
        f'<span class="graph-edge-arrow" aria-hidden="true">&#8595;</span></div>'
    )


def _attack_graph_html(path: AttackPath) -> str:
    """Visualize the contiguous attack path as a vertical node/edge graph.

    The graph is built strictly from path.nodes + path.edges in their existing
    order: node i is joined to node i+1 by edge i's type. No edge is inferred or
    synthesized, and associated_edges are never merged into this walk.
    """
    parts: List[str] = []
    edges = path.edges
    for i, node in enumerate(path.nodes):
        parts.append(f'<div class="graph-step">{_graph_node(node)}</div>')
        if i < len(edges):
            parts.append(_graph_edge(edges[i][2]))
    return (
        '<div class="graph" aria-label="Contiguous attack path">'
        '<div class="graph-legend">Contiguous attack path</div>'
        + "".join(parts)
        + "</div>"
    )


def _associated_graph_html(path: AttackPath) -> str:
    """Visualize associated_edges as a clearly labelled, secondary graph.

    Each associated edge is rendered as its own dashed sub-graph (source ->
    target with its real edge type). It is never merged into the contiguous
    walk, so a fabricated edge (e.g. SECRET -> ACTION) can never appear.
    """
    if not path.associated_edges:
        return ""
    parts: List[str] = []
    for src, tgt, etype in path.associated_edges:
        parts.append('<div class="graph-assoc">')
        parts.append(f'<div class="graph-step">{_graph_node(src)}</div>')
        parts.append(_graph_edge(etype))
        parts.append(f'<div class="graph-step">{_graph_node(tgt)}</div>')
        parts.append("</div>")
    return (
        '<div class="graph graph-dashed" aria-label="Associated evidence">'
        + "".join(parts)
        + "</div>"
    )


def _associated_html(path: AttackPath) -> str:
    """Render associated_edges separately from the contiguous chain."""
    if not path.associated_edges:
        return ""
    rows: List[str] = []
    for src, tgt, etype in path.associated_edges:
        rows.append(
            f'<div class="assoc-edge"><span class="node">{_esc(src)}</span>'
            f'<span class="edge-type">{_esc(etype)}</span>'
            f'<span class="node">{_esc(tgt)}</span></div>'
        )
    body = "".join(rows)
    return (
        '<h4 class="assoc-title">Associated evidence</h4>'
        f'<p class="assoc-note">Edges correlated with this path but not part of '
        f"the contiguous chain.</p>{body}"
    )


def _path_policies_html(path: AttackPath) -> str:
    """Compact, honest policy display for one AttackPath.

    Shows only the policy IDs actually violated by this exact path. When none are
    associated, a neutral note is rendered — never a fabricated violation.
    """
    if not path.policy_ids:
        return (
            '<h4>Policies</h4>'
            '<p class="muted">No violated policies associated with this path.</p>'
        )
    items = "".join(f'<li class="mono">{_esc(pid)}</li>' for pid in path.policy_ids)
    return f'<h4>Policies <span class="pol-head">(violated)</span></h4><ul class="policies">{items}</ul>'


def _format_provenance_components(prov: Any) -> str:
    """Render a component list deterministically; empty => 'not available'."""
    if prov is None:
        return '<span class="muted">not available</span>'
    comps = getattr(prov, "components", None)
    if not comps:
        return '<span class="muted">not available</span>'
    return "".join(f'<code class="mono">{_esc(c)}</code>' for c in comps)


def _path_context_html(path: AttackPath) -> str:
    """Optional 'Component Context' section for one AttackPath.

    Each context association references an actual existing security edge on this
    path plus an explicitly declared component (AGENT/SKILL/TOOL/MCPSERVER). It
    is scope/context metadata only — it never creates a graph edge. All values
    are HTML-escaped. Renders nothing when there is no context association.
    """
    if not getattr(path, "context_components", None):
        return ""
    blocks = []
    for assoc in path.context_components:
        comp = assoc.get("component_id", "")
        ctype = assoc.get("component_type", "")
        beh = assoc.get("behavior", {})
        bsrc = beh.get("source", "")
        btype = beh.get("edge_type", "")
        btarget = beh.get("target", "")
        src = assoc.get("source")
        src_html = f'<span class="prov-label">Source:</span> <code class="mono">{_esc(src)}</code>' if src else ''
        blocks.append(
            f'<div class="expl-block context-item">'
            f'<span class="prov-label">Component:</span> <code class="mono">{_esc(comp)}</code> '
            f'<span class="prov-label">Type:</span> <code class="mono">{_esc(ctype)}</code> '
            f'<div><span class="prov-label">Behavior:</span> '
            f'<code class="mono">{_esc(bsrc)} --{_esc(btype)}--&gt; {_esc(btarget)}</code></div>'
            f'{src_html}'
            f'</div>'
        )
    return f'<h4>Component Context</h4>{"".join(blocks)}'


def _path_explanation_html(path: AttackPath) -> str:
    """Concise 'Explanation' section for one AttackPath card.

    Renders the structured explanation (summary, steps, associated evidence,
    risk impact, policies, breakpoints, components). Only presents already-proven
    facts; everything is HTML-escaped.
    """
    details = path.explanation_details
    if details is None:
        return '<h4>Explanation</h4><p class="muted">Not available.</p>'

    parts: List[str] = ['<h4>Explanation</h4>']

    parts.append(f'<p class="explanation">{_esc(details.summary)}</p>')

    # Entry / Asset / Sink — only present when the AttackPath field is populated.
    for label, val in (("Entry", details.entry), ("Asset", details.asset), ("Sink", details.sink)):
        if val:
            parts.append(f'<div class="expl-block"><span class="prov-label">{_esc(label)}</span>'
                         f'<p class="mono">{_esc(val)}</p></div>')
        else:
            parts.append(f'<div class="expl-block"><span class="prov-label">{_esc(label)}</span>'
                         f'<p class="muted">Not available.</p></div>')

    steps_list = details.steps
    if steps_list:
        items = "".join(f'<li class="mono">{_esc(s)}</li>' for s in steps_list)
        parts.append(f'<div class="expl-block"><span class="prov-label">Steps</span><ul class="expl-steps">{items}</ul></div>')

    if details.associated_evidence:
        items = "".join(f'<li class="mono">{_esc(s)}</li>' for s in details.associated_evidence)
        parts.append(f'<div class="expl-block prov-assoc"><span class="prov-label">Associated evidence</span><ul class="expl-steps">{items}</ul></div>')

    if details.impact:
        parts.append(f'<div class="expl-block"><span class="prov-label">Impact</span><p>{_esc(details.impact)}</p></div>')

    if details.policies:
        items = "".join(f'<li class="mono">{_esc(pid)}</li>' for pid in details.policies)
        parts.append(f'<div class="expl-block"><span class="prov-label">Policies</span><ul class="expl-steps">{items}</ul></div>')

    if details.breakpoints:
        items = "".join(f'<li class="mono">{_esc(b)}</li>' for b in details.breakpoints)
        parts.append(f'<div class="expl-block"><span class="prov-label">Breakpoints</span><ul class="expl-steps">{items}</ul></div>')

    if details.components:
        items = "".join(f'<li class="mono">{_esc(c)}</li>' for c in details.components)
        parts.append(f'<div class="expl-block"><span class="prov-label">Components</span><ul class="expl-steps">{items}</ul></div>')

    return "".join(parts)


def _path_provenance_html(path: AttackPath) -> str:
    """Compact provenance section for one AttackPath card.

    Displays the contributing component/file for each node and edge, using only
    real builder attribution that already exists on the path. Missing provenance
    is shown as neutral "not available" — never inferred.
    """
    prov = path.provenance
    if prov is None:
        return (
            '<h4>Provenance</h4>'
            '<p class="muted">Not available.</p>'
        )

    parts: List[str] = ['<h4>Provenance</h4>']

    node_rows: List[str] = []
    for nd, p in prov.nodes.items():
        node_rows.append(
            f'<div class="prov-row"><span class="prov-key mono">{_esc(nd)}</span>'
            f'<span>→</span><span class="prov-val">{_format_provenance_components(p)}</span></div>'
        )
    if node_rows:
        parts.append('<div class="prov-block"><span class="prov-label">Nodes</span>' + "".join(node_rows) + "</div>")

    edge_rows: List[str] = []
    prov_edges = prov.edges if isinstance(prov.edges, list) else list(prov.edges)
    for idx, ep in enumerate(prov_edges):
        et = path.edges[idx][2] if idx < len(path.edges) else ""
        edge_rows.append(
            f'<div class="prov-row"><span class="prov-key mono">{_esc(et)}</span>'
            f'<span>→</span><span class="prov-val">{_format_provenance_components(ep)}</span></div>'
        )
    if edge_rows:
        parts.append('<div class="prov-block"><span class="prov-label">Edges</span>' + "".join(edge_rows) + "</div>")

    assoc_rows: List[str] = []
    prov_assoc = prov.associated_edges if isinstance(prov.associated_edges, list) else list(prov.associated_edges)
    for idx, ep in enumerate(prov_assoc):
        et = path.associated_edges[idx][2] if idx < len(path.associated_edges) else ""
        assoc_rows.append(
            f'<div class="prov-row"><span class="prov-key mono">{_esc(et)}</span>'
            f'<span>→</span><span class="prov-val">{_format_provenance_components(ep)}</span></div>'
        )
    if assoc_rows:
        parts.append('<div class="prov-block prov-assoc"><span class="prov-label">Associated edges</span>' + "".join(assoc_rows) + "</div>")

    if not (node_rows or edge_rows or assoc_rows):
        parts.append('<p class="muted">No provenance recorded.</p>')
    return "".join(parts)


def _breakpoints_html(path: AttackPath) -> str:
    if not path.breakpoints:
        return '<p class="muted">No breakpoints recorded.</p>'
    head = "<thead><tr><th>Source</th><th>Target</th><th>Edge type</th><th>Impact</th><th>Reason</th></tr></thead>"
    rows: List[str] = []
    for b in path.breakpoints:
        rows.append(
            "<tr>"
            f"<td class=\"mono\">{_esc(b.source_node)}</td>"
            f"<td class=\"mono\">{_esc(b.target_node)}</td>"
            f"<td class=\"mono\">{_esc(b.edge_type)}</td>"
            f"<td class=\"mono\">{_esc(b.impact.value)}</td>"
            f"<td>{_esc(b.reason)}</td>"
            "</tr>"
        )
    return f'<table class="table">{head}<tbody>{"".join(rows)}</tbody></table>'


def _attack_path_card(path: AttackPath) -> str:
    path.ensure_path_id()
    short_id = path.path_id[:12]
    sev = path.risk_severity

    meta = f"""<div class="meta">
      <span>Type: <strong>{_esc(path.attack_type.value)}</strong></span>
      <span>ID: <code class="mono">{short_id}</code></span>
      <span>Confidence: <strong>{_esc(path.risk_confidence.value)}</strong></span>
      <span>Risk score: <strong>{_esc(path.risk_score)}</strong></span>
    </div>"""

    explanation = (
        f'<p class="explanation">{_esc(path.explanation)}</p>'
        if path.explanation
        else f'<p class="explanation">{_esc(path.attack_type.value)}</p>'
    )

    nodes_meta = ""
    if path.entry_node:
        nodes_meta += f"<span><strong>Entry</strong> {_esc(path.entry_node)}</span>"
    if path.asset_node:
        nodes_meta += f"<span><strong>Asset</strong> {_esc(path.asset_node)}</span>"
    if path.sink_node:
        nodes_meta += f"<span><strong>Sink</strong> {_esc(path.sink_node)}</span>"

    evidence = ""
    if path.evidence:
        items = "".join(f"<li>{_esc(e)}</li>" for e in path.evidence)
        evidence = f'<h4>Evidence</h4><ul class="evidence">{items}</ul>'

    chain = _chain_html(path)
    associated = _associated_html(path)
    graph = _attack_graph_html(path)
    associated_graph = _associated_graph_html(path)

    return f"""<article class="card">
    <div class="card-head">
      <div class="card-title"><span class="mono">{_esc(short_id)}</span></div>
      <div class="card-badges">{_severity_badge(sev)}</div>
    </div>
    {meta}
    {explanation}
    <div class="card-body">
      {nodes_meta and f'<div class="meta">{nodes_meta}</div>' or ""}
      <h4>Path</h4>
      {graph}
      {associated_graph}
      <h4>Chain</h4>
      {chain}
      {associated}
      {evidence}
      <h4>Breakpoints</h4>
      {_breakpoints_html(path)}
      {_path_policies_html(path)}
      {_path_provenance_html(path)}
      {_path_context_html(path)}
      {_path_explanation_html(path)}
    </div>
  </article>"""


def _policies_html(result: ScanResult) -> str:
    if not result.policy_results:
        return '<p class="muted">No policy evaluation results.</p>'
    head = (
        "<thead><tr><th>Policy</th><th>Path ID</th><th>Result</th><th>Reason</th></tr></thead>"
    )
    rows: List[str] = []
    for r in result.policy_results:
        status = "Violated" if r.violated else "Pass"
        cls = "status-violated" if r.violated else "status-pass"
        rows.append(
            "<tr>"
            f"<td class=\"mono\">{_esc(r.policy_id)}</td>"
            f"<td class=\"mono\">{_esc(r.path_id[:12])}</td>"
            f'<td><span class="pill {cls}">{_esc(status)}</span></td>'
            f"<td>{_esc(r.reason)}</td>"
            "</tr>"
        )
    return f'<table class="table">{head}<tbody>{"".join(rows)}</tbody></table>'


def _findings_html(result: ScanResult) -> str:
    if not result.findings:
        return '<p class="muted">No findings.</p>'
    head = (
        "<thead><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Title</th>"
        "<th>Location</th><th>Status</th></tr></thead>"
    )
    rows: List[str] = []
    for f in result.findings:
        loc = _esc(f.file)
        if f.line:
            loc += f":{_esc(f.line)}"
        status = "Suppressed" if f.suppressed else "Active"
        status_cls = "status-suppressed" if f.suppressed else "status-active"
        rows.append(
            "<tr>"
            f'<td class="mono">{_esc(f.rule_id)}</td>'
            f'<td>{_severity_badge(f.severity)}</td>'
            f'<td class="mono">{_esc(f.confidence.value)}</td>'
            f'<td>{_esc(f.title)}</td>'
            f'<td class="mono">{loc}</td>'
            f'<td><span class="pill {status_cls}">{_esc(status)}</span></td>'
            "</tr>"
        )
    table = f'<table class="table">{head}<tbody>{"".join(rows)}</tbody></table>'

    # Supplemental detail: description/evidence per finding, collapsed sections
    # to keep the table compact while preserving all existing finding data.
    details: List[str] = []
    for f in result.findings:
        bits: List[str] = []
        if f.description:
            bits.append(f"<p><strong>Description</strong>: {_esc(f.description)}</p>")
        if f.evidence:
            bits.append(f'<pre class="evidence-block">{_esc(f.evidence)}</pre>')
        if f.matched_text:
            bits.append(f"<p><strong>Matched</strong>: {_esc(f.matched_text)}</p>")
        if f.suppressed:
            bits.append(
                f'<p><strong>Suppressed</strong>: {_esc(f.suppression_reason)}</p>'
            )
        if f.cwe:
            bits.append(f'<p><strong>CWE</strong>: {_esc(", ".join(f.cwe))}</p>')
        if f.mitre:
            items = "".join(
                f'<li class="mono">{_esc(m.get("id", ""))} — {_esc(m.get("name", ""))}</li>'
                for m in f.mitre
            )
            bits.append(f"<p><strong>MITRE ATT&CK</strong></p><ul>{items}</ul>")
        if bits:
            details.append(
                f'<details><summary class="mono">{_esc(f.rule_id)} '
                f'({_esc(f.title)})</summary>{"".join(bits)}</details>'
            )
    det = f'<div class="finding-details">{"".join(details)}</div>' if details else ""
    return table + det


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #0d1117;
  --bg-soft: #161b22;
  --panel: #1c2128;
  --border: #2d333b;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #58a6ff;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --sev-critical: #f85149;
  --sev-high: #ff7b72;
  --sev-medium: #d29922;
  --sev-low: #58a6ff;
  --sev-info: #8b949e;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  font-size: 15px;
  padding: 0 0 48px;
}
.container { max-width: 1080px; margin: 0 auto; padding: 0 20px; }
header.hero {
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, #0d1117 0%, var(--bg-soft) 100%);
  padding: 28px 0 20px;
  margin-bottom: 24px;
}
.brand { font-size: 13px; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); }
h1 { margin: 4px 0 2px; font-size: 22px; font-weight: 600; }
.subtitle { color: var(--muted); font-size: 13px; }
.mono { font-family: var(--mono); }
a { color: var(--accent); }

.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.stat {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
}
.stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }
.stat-value { font-size: 20px; font-weight: 600; margin-top: 4px; word-break: break-word; }

h2 {
  font-size: 18px;
  margin: 28px 0 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
h4 { font-size: 14px; margin: 18px 0 8px; color: var(--accent); }

.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: .5px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
}
.badge.sev-critical { background: rgba(248,81,73,.14); color: var(--sev-critical); border-color: var(--sev-critical); }
.badge.sev-high    { background: rgba(255,123,114,.14); color: var(--sev-high); border-color: var(--sev-high); }
.badge.sev-medium  { background: rgba(210,153,34,.14); color: var(--sev-medium); border-color: var(--sev-medium); }
.badge.sev-low     { background: rgba(88,166,255,.12); color: var(--sev-low); border-color: var(--sev-low); }
.badge.sev-info    { background: rgba(139,148,158,.14); color: var(--sev-info); border-color: var(--sev-info); }

.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 18px;
  margin-bottom: 16px;
}
.card-head { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
.card-title { font-size: 15px; font-weight: 600; }
.meta { display: flex; flex-wrap: wrap; gap: 16px; color: var(--muted); font-size: 13px; margin: 8px 0; }
.explanation { color: var(--text); margin: 6px 0 4px; }

.chain { margin: 6px 0 10px; }
.chain-node { font-family: var(--mono); font-size: 13px; }
.node {
  display: inline-block;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 2px 8px;
  font-family: var(--mono);
  font-size: 13px;
  word-break: break-all;
}
.chain-edge { padding: 2px 0 2px 14px; color: var(--muted); font-size: 12px; }
.edge-arrow { color: var(--sev-critical); font-weight: 700; margin-right: 6px; }
.edge-type { font-family: var(--mono); }

.assoc-title { color: var(--accent); }
.assoc-note { color: var(--muted); font-size: 12px; margin: 0 0 8px; }
.assoc-edge { color: var(--text); margin: 6px 0; font-family: var(--mono); font-size: 13px; }
.assoc-edge .edge-type { color: var(--sev-medium); margin: 0 8px; }

/* Attack-path graph visualization */
.graph {
  margin: 4px 0 12px;
  padding: 12px 14px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  display: inline-block;
  min-width: 220px;
}
.graph-legend {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .8px;
  color: var(--accent);
  margin-bottom: 10px;
}
.graph-step { display: flex; justify-content: flex-start; }
.graph-node {
  display: inline-flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 6px 12px 7px;
  max-width: 100%;
}
.graph-node-type {
  font-size: 10px;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--muted);
  font-weight: 600;
}
.graph-node-key { font-size: 13px; word-break: break-all; line-height: 1.3; }
.graph-edge {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 3px 0 2px;
  width: 40px;
}
.graph-edge-label {
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .5px;
  margin-bottom: 2px;
}
.graph-edge-arrow { color: var(--sev-critical); font-size: 16px; line-height: 1; }
.graph.graph-dashed {
  border-style: dashed;
  margin-top: 14px;
}
.graph-dashed .graph-node { border-style: dashed; border-color: var(--muted); }
.graph-assoc { padding: 2px 0; }

.evidence li { font-family: var(--mono); font-size: 13px; }
ul.policies { padding-left: 18px; margin: 6px 0; }
ul.policies li { font-size: 13px; margin: 2px 0; }
.pol-head { color: var(--sev-critical); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
.prov-block { margin: 6px 0 10px; }
.prov-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; display: block; margin-bottom: 4px; }
.prov-row { display: flex; gap: 8px; align-items: baseline; font-size: 13px; margin: 3px 0; flex-wrap: wrap; }
.prov-key { color: var(--text); word-break: break-all; }
.prov-val { color: var(--muted); }
.prov-val code { color: var(--accent); background: var(--bg-soft); padding: 0 4px; border-radius: 3px; }
.prov-assoc { border-top: 1px dashed var(--border); padding-top: 8px; }
.expl-block { margin: 6px 0 10px; }
.expl-steps { padding-left: 18px; margin: 4px 0; }
.expl-steps li { font-size: 13px; margin: 2px 0; word-break: break-word; }

.table { width: 100%; border-collapse: collapse; font-size: 13px; }
.table th, .table td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.table th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .5px; }
.table td { word-break: break-word; }

.pill { padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.status-violated { background: rgba(248,81,73,.15); color: var(--sev-critical); }
.status-pass { background: rgba(88,166,255,.12); color: var(--sev-low); }
.status-suppressed { background: var(--bg-soft); color: var(--muted); }
.status-active { background: rgba(210,153,34,.14); color: var(--sev-medium); }

.muted { color: var(--muted); }
.evidence-block {
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 10px;
  font-family: var(--mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-word;
}
.finding-details { margin-top: 8px; }
details { margin: 6px 0; }
summary { cursor: pointer; color: var(--accent); }
@media (max-width: 640px) {
  .grid { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }
  body { padding: 0 0 32px; }
  .card { padding: 12px; }
}
"""


def _behavior_rows(behaviors: Any) -> List[str]:
    """Render a list of (source, edge_type, target) behavior dicts as rows."""
    rows: List[str] = []
    for b in behaviors or []:
        if not isinstance(b, dict):
            continue
        bsrc = b.get("source", "")
        btype = b.get("edge_type", "")
        btarget = b.get("target", "")
        rows.append(
            f'<div><span class="edge-type">{_esc(btype)}</span> '
            f'<code class="mono">{_esc(bsrc)}</code>'
            f'<span> &rarr; </span>'
            f'<code class="mono">{_esc(btarget)}</code></div>'
        )
    if not rows:
        rows.append('<span class="muted">No security behaviors.</span>')
    return rows


def _component_scope_html(result) -> str:
    """Compact 'Component Security Scope' section (aggregate projection).

    Shows the explicit per-component security-behavior scope derived from
    ComponentContextAssociation records. This is aggregation metadata only — it
    never creates a graph edge and never infers ownership. All dynamic values
    are HTML-escaped. Renders nothing when no scope data was supplied.
    """
    scopes = list(getattr(result, "component_security_scopes", []) or [])
    if not scopes:
        return ""
    blocks: List[str] = []
    for scope in scopes:
        comp = scope.get("component_id", "")
        ctype = scope.get("component_type", "")
        behaviors = scope.get("security_behaviors", [])
        rows = _behavior_rows(behaviors)
        blocks.append(
            f'<div class="expl-block context-item">'
            f'<span class="prov-label">Component:</span> <code class="mono">{_esc(comp)}</code> '
            f'<span class="prov-label">Type:</span> <code class="mono">{_esc(ctype)}</code> '
            f'<h4>Security Behaviors</h4>{"".join(rows)}'
            f'</div>'
        )
    return "".join(blocks)


def _component_participation_html(result) -> str:
    """Compact 'Component Path Participation' section.

    For each component-path participation shows Component, Type, Path ID, and
    the security behaviors actually present on that path. All dynamic values are
    HTML-escaped. Renders nothing when no participation data was supplied.
    """
    participation = list(getattr(result, "component_path_participation", []) or [])
    if not participation:
        return ""
    blocks: List[str] = []
    for item in participation:
        comp = item.get("component_id", "")
        ctype = item.get("component_type", "")
        pid = item.get("path_id", "")
        behaviors = item.get("security_behaviors", [])
        rows = _behavior_rows(behaviors)
        blocks.append(
            f'<div class="expl-block context-item">'
            f'<span class="prov-label">Component:</span> <code class="mono">{_esc(comp)}</code> '
            f'<span class="prov-label">Type:</span> <code class="mono">{_esc(ctype)}</code> '
            f'<div><span class="prov-label">Path ID:</span> <code class="mono">{_esc(pid)}</code></div>'
            f'<h4>Security Behaviors</h4>{"".join(rows)}'
            f'</div>'
        )
    return "".join(blocks)


def render_html(result: ScanResult) -> str:
    """Render a ScanResult as a complete, deterministic, standalone HTML report.

    The document is self-contained (inline CSS only) and contains no network,
    external asset, timestamp, or random identifier.
    """
    # Sections are built top-to-bottom; every value is HTML-escaped.
    if result.attack_paths:
        path_cards = "".join(
            _attack_path_card(p)
            for i, p in enumerate(result.attack_paths)
        )
        attack_section = _section("Attack Paths", path_cards)
    else:
        attack_section = _section(
            "Attack Paths", '<p class="muted">No attack paths detected.</p>'
        )

    policies = _section(
        "Policies",
        _policies_html(result),
    )
    findings = _section("Findings", _findings_html(result))

    # Additive aggregate projections; render only when data is present.
    scope_html = _component_scope_html(result)
    participation_html = _component_participation_html(result)

    body = (
        f"<header class=\"hero\"><div class=\"container\">"
        f"<div class=\"brand\">Veyra</div>"
        f"<h1>Security Report</h1>"
        f"<div class=\"subtitle\">Target: {_esc(result.target)}</div>"
        f"</div></header>"
        f"<main class=\"container\">"
        f"{_summary_html(result)}"
        f"{attack_section}"
        f"{scope_html and _section('Component Security Scope', scope_html) or ''}"
        f"{participation_html and _section('Component Path Participation', participation_html) or ''}"
        f"{policies}"
        f"{findings}"
        f"</main>"
    )

    doc = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>Veyra Security Report</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        f"<body>\n{body}\n</body>\n</html>"
    )
    return doc
