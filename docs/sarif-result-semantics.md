# SARIF result semantics: findings and attack paths

Veyra emits two kinds of SARIF result from one scan:

- `result_kind = "finding"` — a rule hit on a line (`AS-*`, `AS-MCP-*`).
- `result_kind = "attack_path"` — a proven graph path (`ATTACK-PATH-*`), carrying
  `path_id`, nodes, edges, breakpoints and risk fields.

They are not duplicates: a finding is an observation, a path is a lineage. But a
correlation finding (`AS-CHAIN-*`) and a path can describe **the same incident** in
the same artifact.

## Policy

When a proven path starts in an artifact, a `AS-CHAIN-*` finding in that artifact is
still emitted — evidence is never deleted — but it carries:

- `properties.superseded_by_path = <path_id>`
- `suppressions: [{kind: "inSource", justification: "Superseded by proven attack path …"}]`

The path result carries `properties.result_kind = "attack_path"`.

A consumer that counts incidents should count the path as canonical and ignore a
finding whose `properties.superseded_by_path` is set. A consumer that wants every
observation can read both; nothing is hidden.

## What is not claimed

- The suppression does not claim the finding is wrong; it says a stronger,
  evidence-backed representation of the same artifact exists.
- It applies only to `AS-CHAIN-*` findings whose file matches the path's entry
  artifact. Unrelated findings in the same file are untouched.
- JSON output is unchanged: both the finding and the path remain there.
