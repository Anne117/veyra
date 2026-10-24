# Explaining one record: `veyra explain`

```
veyra explain <finding-id|path-id> --target PATH [--config FILE] --format text
veyra explain --target PATH                     # list the ids this run derives
```

`explain` answers exactly one question — *what is this record, and what is it
made of?* — from a **fresh deterministic scan** of the target:

* for a finding: which rule fired, with which severity and confidence, on
  which file and line, with which evidence, and whether it is suppressed;
* for an attack path: its nodes, its edges, its breakpoints, and whether the
  stored edge sequence actually establishes its recorded `attack_type`.

It uses no LLM, no network and no report file. It reads nothing but the target
tree, exactly like `veyra scan`. There is no "trusted" or `json` mode in this
command, and it cannot be pointed at a report somebody may have edited; if a
future version learns to read one, it must validate the schema and say
`source: file, not run` on every line of output.

The explanation of one record is **not** a verdict on the rest of the target.
The run header repeats the coverage status (`coverage_status`) and the policy status for that
reason: `partial` / `none` coverage means the rest of the tree was not read,
and then "no violation proven" is `UNKNOWN`, not "clean".

## Finding ids

A finding id is derived, never stored. It is `fnd-` plus the first 12
hexadecimal digits of SHA-256 over the same five-field record tuple the
baseline already fingerprints:

```
(rule_id, file relative to the scan root, line, path-scrubbed evidence, severity)
```

The recipe, exactly as implemented:

```python
import hashlib

SEP = "\x1f"      # ASCII unit separator between fields
HEX = 12

def field(value):
    # A field must not be able to impersonate a separator.
    return value.replace("\\", "\\\\").replace("\x1f", "\\x1f")

def finding_id(rule_id, file, line, evidence, severity):
    parts = [
        field(rule_id),
        field(file),
        "" if line is None else str(line),
        field(evidence),
        field(severity),
    ]
    digest = hashlib.sha256(SEP.join(parts).encode("utf-8")).hexdigest()
    return "fnd-" + digest[:HEX]
```

Notes on the fields:

* `file` is the location relative to the scan root (`scan_root`: the target
  directory, or the parent of a file target), exactly as
  `veyra baseline create` records it. A finding outside the root is named
  `<outside>/<basename>`.
* `evidence` is the finding's evidence **after** the baseline's host-path
  scrubber (`veyra.baseline._sanitize_evidence`) has run, so ids do not depend
  on the machine that produced them.
* `line` is `""` when the finding has no line (a file-level finding).

Worked example — the record
`("AS-006", "SKILL.md", 7, "access", "HIGH")` is the byte string

```
AS-006 \x1f SKILL.md \x1f 7 \x1f access \x1f HIGH
```

whose SHA-256 begins `4edeaf87744f...`, so the id is **`fnd-4edeaf87744f`**.

Two findings that agree on all five fields produce the same id. `explain`
reports that as an ambiguity (exit 2) and names both records; it never
explains "the first match". The id is validated against
`\Afnd-[0-9a-f]{12}\Z` before the target is touched, and it never reaches a
filesystem path, a glob or a format string.

## Path ids

A path id is the existing `AttackPath.path_id`: the full 64 lowercase
hexadecimal digits of the SHA-256 of the canonical semantic identity (ordered
nodes, ordered walk edges, sorted associated edges — see
`veyra.graph.path.canonical_path_identity`). It is printed by
`veyra scan --format json` under `attack_paths[].path_id` and by
`veyra explain` with no id, and it is stable across insertion order and
unrelated metadata.

Only the full id is accepted (`\A[0-9a-f]{64}\Z`). A prefix is rejected on
purpose: a prefix is ambiguous by construction, so accepting one would mean
occasionally explaining a record the caller did not name.

## Output

The text is three blocks, in this order.

1. **Run header** — `target:`, `coverage_status:` with its counts, `policy_status:`
   with its meaning, and the fixed line

   ```
   scope: this explains one record of one run; it is not a verdict on the rest of the target
   ```

   The counts in this block describe the whole run and are the only numbers in
   the output that are not record fields.

2. **Record** — one `field: value` line per real field of the record, in a
   fixed order. Every value is taken from the `Finding` / `AttackPath` (or a
   nested `Breakpoint`) itself; no field is invented, no number is computed.
   A field with no value prints `(none)`, so a missing line is never read as
   a missing finding. `line` with no number prints `(none)` and no digits.
   `suppressed: yes` is printed next to `suppression_reason`, never as an
   absence.

3. **Proof check** (paths only) — `proof-definition:` states what the
   recorded `attack_type` *means*, then one `proof-check:` line per clause of
   that definition, evaluated against the stored `nodes` / `edges` /
   `associated_edges` of this very record, then the `proof-edge:` lines the
   verdict relies on, then `proof-result: proven` or `proof-result:
   not-proven`. A record whose stored edges do not satisfy its recorded type
   is reported as `not-proven`; the definition is never restated as a fact
   about the record.

## Untrusted text

`evidence`, `matched_text`, file names, titles and node labels are chosen by
the author of the scanned repository. Before printing, each of them goes
through the baseline's host-path scrubber and then through
`veyra.sanitize.escape_untrusted`, which renders every non-printable character
as `\xNN` / `\uNNNN` / `\UNNNNNNNN` and doubles backslashes. A repository
therefore cannot print a line of its own (a fake `suppressed: yes`), cannot
move the cursor with ANSI escapes, and cannot put the scanning machine's home
directory or working directory into a CI log.

## Exit codes

| code | meaning |
| ---- | ------- |
| 0 | the record was explained (or the id index was printed) |
| 2 | malformed id, unknown id, ambiguous id, or unreadable target |

On any failure the message goes to **stderr**, stdout stays **empty**, and no
traceback is printed. The rejected id is echoed back escaped, and the ids that
do exist in the run are listed next to it (at most 20, then a stated count of
the rest). `--format` accepts only `text`; anything else is an argparse error
(exit 2).
