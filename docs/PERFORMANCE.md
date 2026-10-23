# Where a scan spends its time (measured, no optimisations)

Status: measurement only. This document changes no code and promises no speedup;
T10/T11 own any change, and each of them must keep the JSON byte-identical.

- Date: 2026-10-23 · HEAD `31acf41` · box: 2 vCPU, 3 GiB RAM, Linux 7.0, ext4,
  Python 3.11.16 (`/home/ubuntu/veyra/.venv`), page cache warm.
- Targets: `/home/ubuntu/.hermes/hermes-agent/agent` (a foreign Python tree, the
  "big" case) and `src` (Veyra's own source, the CI case).
- Method: (1) three CLI runs of `veyra scan <target> --format json`, wall clock;
  (2) one in-process run of `scan_path()` with per-file/per-phase timers
  (~0.3 % overhead: instrumented 25.07 s vs uninstrumented 25.29 s on the same
  tree); (3) an isolated per-rule benchmark over the same file texts;
  (4) two `cProfile` runs for call counts and structure only — the profiler
  inflates wall time x1.45-x1.56, so its numbers are never quoted as time.

## Baseline (CLI wall clock, 3 runs each)

| target | files read | lines | findings | paths | runs (s) | median |
|---|---|---|---|---|---|---|
| `agent/` | 280 (of 516 in tree; 236 not scannable/ignored) | 111 083 | 43 | 1 | 25.49 / 25.55 / 26.24 | **25.55** |
| `src` | 56 | 12 917 | 38 | 12 | 2.54 / 2.72 / 2.65 | **2.65** |

Fixed cost outside the scan: interpreter + rule import 0.16 s (`veyra --help`).
Rendering, all four formats on the agent result: JSON 2.5 ms, SARIF 2.8 ms,
HTML 0.9 ms, terminal 0.3 ms — 0.02 % of the run. **Rendering is not a cost.**

## Phases (agent/, 25.07 s instrumented; shares of that total)

| phase | time (s) | share |
|---|---|---|
| file pass — walk, decide, read, line rules, file rules | 12.24 | 48.8 % |
| step sequence — `analyze_file_chains` over 280 files | 9.99 | 39.9 % |
| attack paths — per-component graph build + path search | 2.77 | 11.1 % |
| correlation, policy, provenance invariants, explanation, metadata | < 0.01 | ~0 % |
| walk bookkeeping, entry-file map, `ScanResult` assembly | 0.07 | 0.3 % |

Inside the file pass (12.24 s): reading 0.03 s · file rules (3 rules, 840 calls)
0.74 s · **Python tokenisation 3.29 s** · **line rules + per-call bookkeeping
8.34 s** (28 rules x 111 083 lines = 3 110 324 rule calls).

Inside the step sequence (9.99 s): **the same Python tokenisation again 3.33 s**
(`_code_only_lines`, 279 calls) · per-line `_split_actions` / `_classify_line` /
`_extract_action` about 6.6 s.

Inside the attack-path phase (2.77 s): `_split_actions` + `_extract_action` run
over every line *a second time* (a third pass over the same text, after the
step-sequence pass), then the per-component graphs and the path search.

`src` follows the same shape: file pass 1.39 s (52 %), step sequence 0.98 s
(37 %), attack paths 0.25 s (9 %), tokenisation 0.51 s over 112 calls
(56 files x 2), 361 676 rule calls.

## The single largest addressable block

`step_sequence._code_only_lines` (tokenise a file, blank comments and string
literals) is called **twice per `.py` file** on the same text:

1. `scanner._scan_file` (line 644) — to keep AS-003 MEDIUM off prose lines;
2. `step_sequence.analyze_file_chains` (line 479) — to classify code only.

279 files x 2 = 558 calls = **6.29 s, 25 % of the whole scan** — the largest
contiguous cost in the product, and the same string is tokenised both times.

## Rule-level cost (agent/, isolated benchmark, 7.98 s attributed)

| rule | s | share of rule time |
|---|---|---|
| `detect_http_client` | 2.145 | 26.9 % |
| `detect_sensitive_path_access` | 1.334 | 16.7 % |
| `detect_js_exec` | 0.489 | 6.1 % |
| `detect_encoded_obfuscated` | 0.314 | 3.9 % |
| `detect_reveal_secrets` | 0.290 | 3.6 % |
| `detect_generic_key` | 0.252 | 3.2 % |
| `detect_send_files` | 0.205 | 2.6 % |
| `detect_disable_security` | 0.205 | 2.6 % |
| `detect_unrelated_exec` | 0.201 | 2.5 % |
| `detect_ignore_instructions` | 0.194 | 2.4 % |
| remaining 18 rules | 2.15 | 27.0 % |

Two rules are 43.6 % of rule time. `detect_http_client` reaches
`network._live_match`, which calls `re.split` per line: 222 166 splits for
111 083 lines (cProfile `tottime` 4.8-5.7 s over two profiled runs).

**Measurement honesty.** The same 3.11 M rule calls cost 8.34 s by subtraction
from the instrumented file pass and 9.07 s when benchmarked in isolation — an
8 % disagreement between two defensible methods, not a different workload. A
per-call timer was priced separately: 0.772 us/call, i.e. 1.90 s of overhead
over 3.11 M calls. Numbers above are +/-10 %.

## What this means for T10/T11 (no change made here)

Ranked by ceiling, assuming byte-identical output:

1. Tokenise once per `.py` file and share the result between both call sites —
   ceiling **3.1 s (12 %)** of the agent scan, with the largest identity risk
   being that the two sites must keep receiving the same blanking.
2. Stop splitting and classifying every line twice (step-sequence pass and
   attack-path pass read the same texts) — ceiling **about 2.6 s (10 %)**.
3. `detect_http_client`: one `re.split` per line for a rule that is 27 % of rule
   time — ceiling **about 1.5 s**, but any prefilter must be a provable superset
   of the current matches, or the JSON moves.
4. Rule count per line (28 x 111 k lines) is the floor under the other 25 %:
   a file-type or keyword prefilter can only be used if it provably cannot drop
   a match.

Rendering (0.006 s for all formats) and interpreter startup (0.16 s) are already
noise: touching them cannot buy 10 %, so T10 should not start there.

## Reproduction

```sh
cd /home/ubuntu/veyra
for i in 1 2 3; do /usr/bin/time -f "%e" .venv/bin/veyra scan \
  /home/ubuntu/.hermes/hermes-agent/agent --format json > /dev/null; done
# structure and call counts (profiled timings are x1.45-x1.56, do not quote them)
.venv/bin/python -c "import cProfile, pstats; from veyra.scanner import scan_path; \
cProfile.run('scan_path(\"/home/ubuntu/.hermes/hermes-agent/agent\")', '/tmp/p.out'); \
pstats.Stats('/tmp/p.out').sort_stats('tottime').print_stats(20)"
```

## T10: one tokenisation per Python file, not one per phase

**Change (one topic).** `step_sequence._code_only_lines` was called twice for
every `.py` file on the same `str` object: `scanner._scan_file` needs it for the
AS-003/AS-006 line filters, `step_sequence.analyze_file_chains` needs it to
classify steps. The tokenise-and-blank step is now memoised
(`_scrubbed_python_lines`, `lru_cache(maxsize=1024)`); `_code_only_lines` returns
a fresh `list` so no caller can edit the answer the next caller reads. The memo
is cleared at the start and at the end of `scanner.scan_path`, so it holds at
most one scan's texts. Nothing else moved: no rule, no threshold, no output path.

**Why this is the right first cut.** It was the largest single item in the T9
profile (6.29 s of 25.55 s, 25 %) and the only one with **no detection risk**:
the second answer is provably the first answer, so byte-identity is a property of
the change, not a hope. (The other candidates -- one split/classify pass instead
of two, a prefilter for `detect_http_client` -- have to be argued as supersets
first.)

**Measurement** (3 CLI runs each, median, same machine, same day):

| tree | before | after | delta |
|---|---|---|---|
| `agent/` (516 files, 280 read) | 24.16 s (23.42/24.16/24.38) | **20.54 s** (20.06/20.54/20.77) | **-3.62 s = 15.0 %** |
| `src` (56 files) | 2.36 s (2.36/2.36/2.47) | **2.05 s** (2.00/2.05/2.34) | -0.31 s = 13.1 % |

The saved wall clock matches the profile's 3.1 s ceiling for this item: the two
calls became 112 calls / 56 ids on `src` → 56 tokenisations, and each hit is now
a dict lookup.

**Output identity.** `--format json` compared byte-for-byte on `agent/`,
`attack-lab` and `src`:

* `agent/` — identical bytes (43 findings, 1 path).
* `attack-lab` corpus — identical bytes (113 / 103 D / 7 P / 3 M / 0 FP).
* `src` — identical except two AS-006 `line` values **inside `scanner.py`**, the
  file this change edits (514 → 521, 625 → 632: eight added lines above them).
  Same rule, same file, same evidence, same count (38 findings, 12 paths); no
  other field on any other file moved.

**Cost.** +3 tests (`tokenises one text once`, `hands out a fresh list`,
`scan tokenises each file once and keeps no text afterwards`); 1864 passed.
CI-scan equivalent unchanged: `full`, 56 read / 0 skipped / 0 lossy,
`Policy: FAIL`, exit 1.

## T11: each per-line decision is made once, and the expensive rules ask first

**Change (one topic).** T10 bought 15 % by tokenising a file once. T11 takes
the rest of the ranked list from T9 — the repeated per-line decisions and the
two rules that are 43.6 % of rule time — and every item is *provable*, not
hoped for: a shortcut here may only skip work, never change an answer.

1. **`step_sequence._split_actions`** ran a regex split on every line of every
   file (`222 166` splits, 5.0 s). Every branch of the separator needs a literal
   `;` or `then` (any case), and so does the leading-`"then"` strip, so a line
   with neither is returned stripped, as one segment, without touching the
   regex.
2. **`step_sequence._classify_line`** is memoised per segment text
   (`_classify_cache`, capped at 32 768 entries, dropped together with the
   tokenisation memo at both ends of `scan_path`), and `_extract_action` now
   accepts the category its caller has just computed instead of running the six
   detectors a second time. Before: `244 257` calls for ~100 000 distinct
   segments, six regexes each (3.1 s). `_classify_uncached` also asks one cheap
   question first — every branch of the six detectors needs one of 38 verbs
   (`_STEP_STEMS`), tested as `in` on the lowercased line.
3. **`rules.network.detect_http_client`** (26.9 % of rule time). `HTTP_CLIENT`
   is a wide case-sensitive alternation and `HTTP_OBJECT_CALL` carries `(?i)`.
   One stem test in front of each: the client spellings the first branch names,
   and `http`/`session` + one of seven verbs + `(` for the second.
   `1.934 s -> 0.176 s` over the 111 083 lines of `agent/`; 805 lines reach the
   detectors.
4. **`rules.sensitive_paths.detect_sensitive_path_access`** (16.7 % of rule
   time). Eleven stems that every branch of `SENSITIVE_PATH` and every
   alternative of `CREDENTIAL_EXTRACTION` contains, in front of five regexes.
   `1.271 s -> 0.304 s`; 9 626 lines reach the detectors.
5. **`step_sequence._scrubbed_python_lines`**: the comment/string spans are
   collected per row and applied right-to-left on the original line strings,
   instead of copying every line of every file into a character list. On the
   279 `.py` files of `agent/` (5.5 M chars): `3.09 s -> 2.59 s`, byte-identical
   output on all 279.
6. **`scanner._scan_file`**: `str(path)` is computed once per file, not once
   per line per rule (3.1 M calls).

**Why the prefilters cannot move a finding.** Each stem set is a *superset* of
the literals and verbs its patterns require, so a line the prefilter drops is a
line no pattern could match. Checked twice: per rule, over every one of the
111 083 lines of `agent/`, 0 lines were dropped and then matched by the
pattern they were dropped from; and at the output, byte-for-byte (below). The
tests carry the same claim as a property (`_STEP_STEMS` / `_AS006_STEMS` /
`_HTTP_CLIENT_STEMS` each cover every branch of the patterns they front, over
the repository's own fixture corpus).

**What was not taken.** "One split/classify pass instead of three": the
attack-path pass builds its `Action`s from *raw* lines, the step-sequence pass
from *scrubbed* ones, so handing one pass's actions to the other would change
what a chain and a path read. The memo plus the category passthrough buy the
same seconds with no such risk. "Tokenise fewer files": exactly 1 of the 279
`.py` files in `agent/` contains no step verb at all, so a per-file skip buys
nothing.

**Measurement** (5 CLI runs each, *interleaved* with the baseline so both see
the same machine load; median; same box, same day, page cache warm):

| tree | before | after | delta |
|---|---|---|---|
| `agent/` (280 read) | **20.88 s** (20.61 / 20.65 / 20.88 / 20.95 / 21.48) | **10.63 s** (10.46 / 10.51 / 10.63 / 10.74 / 10.91) | **-10.25 s = 49.1 %** |
| `src` (56 files) | **2.25 s** (2.23 / 2.25 / 2.30) | **1.18 s** (1.14 / 1.18 / 1.23) | **-1.07 s = 47.6 %** |

The `agent/` target of T11 (12 s) is met with 12 % of headroom; the
interleaved baseline re-measured at 20.88 s, matching the 20.54 s T10 reported.

**Output identity.** `--format json` compared byte-for-byte:

* `agent/` — 10 runs (5 before, 5 after the change), one md5
  (`e6abe4538c27e1e48aac7ee69cebde58`): identical. 43 findings, 1 path.
* `src` — identical md5 before and after: 38 findings, 12 paths.
* Attack-Lab corpus — unchanged: **113 / 103 D / 7 P / 3 M / 0 FP**.
* CI-scan equivalent (`veyra scan src --config .veyra.toml`) — unchanged:
  exit 1, `Policy: FAIL`.

**Cost.** +60 tests (the fast split path against a reference splitter, the
memo's answer and its scan scope, the three prefilter superset properties, and
the scrubber against the character-list reference): **1924 passed** under both
`pytest -q` and `python -m pytest -q`. No rule, threshold, chain, path or
output path changed.

## T11, second cut: a line the scan has already read is not asked again

**Where the scan is after the first cut.** The first T11 commit took `agent/`
from 20.5 s to 10.6 s, and the profile moved with it: the line-rule loop was
still the largest block, **3 110 324 rule calls** (28 rules x 111 083 lines,
0.77 us of pure call overhead each on top of the regex work), but the rules
themselves were no longer the expensive ones -- the two that were 43.6 % of
rule time are prefiltered and the split/classify work is memoised. What was
left was the *shape* of the loop: every line asks all 28 rules, even the
34 985 lines (31 %) that are a repeat of a text the same scan already read.

**Change (one topic).** A line rule is a pure function of the text it is
handed: `file_path` and `line` are stamped onto the Finding it returns, they
never decide it. That was not assumed -- all 28 registered rules were run over
291 742 lines (the `agent/` tree, `src`, and the fixture corpus) twice, as
`a.py` line 1 and as `b.md` line 977, and every verdict was identical modulo
the two stamped fields. So `scanner._scan_file` now remembers, per line text,
the **indexes of the rules that were not quiet**: a rule that returned None for
a text returns None for it again and is not asked. A replay calls exactly
those rules with the current file path and line number, so every Finding is
still produced by the rule itself -- the cache can only skip a question, never
answer one. `3 110 324 -> 2 130 763` rule calls on `agent/`.

Three things keep it honest:

* a rule that **raised** is recorded as loud, never quiet: the loss is a fact
  about *this* file and line, so `coverage.rule_failed` still fires once per
  occurrence (`test_a_raising_rule_is_recorded_for_every_line_it_meets`);
* the entry is bound to the **rule list** it was learned with -- the indexes
  mean nothing against another list, so a caller scanning with a different rule
  set starts from an empty cache
  (`test_a_different_rule_list_never_replays_another_lists_answers`);
* the cache is **per scan**, capped at 100 000 texts, and dropped with the
  tokenisation memo at both ends of `scan_path`.

**Measurement** (7 CLI runs each, *interleaved* with the previous commit
(`f433070`) and with the pre-T10 baseline (`31acf41`) so all three see the same
machine load; median; same box, same day, page cache warm):

| tree | baseline 31acf41 | first cut f433070 | this commit |
|---|---|---|---|
| `agent/` (280 read) | **23.45 s** (22.64-24.27) | **10.58 s** (10.09-11.02) | **10.32 s** (9.84-10.44) |

`agent/` against the original T11 target (12 s): met with 14 % of headroom, and
2.3x against the 23.8 s the task started from. The second cut is worth **-2.5 %**
on this tree; it is worth much more on a tree with more repetition, because what
it removes is the per-line cost of the text that repeats.

**Output identity.** `--format json` compared byte for byte against the
pre-change baseline on three targets: `agent/`
(`e6abe4538c27e1e48aac7ee69cebde58`, 43 findings, 1 path), `tests/` and a copy
of `src/` scanned by both versions (identical md5; `src/` scanned from two
different working trees is not comparable, the text itself changed). Attack-Lab
corpus unchanged: **113 / 103 D / 7 P / 3 M / 0 FP**. CI-scan equivalent
(`veyra scan src --config .veyra.toml`): `coverage_status: full`, 0 active
HIGH/CRITICAL, `Policy: FAIL`, exit 1 -- unchanged.

**Cost.** +5 tests (a repeated line asks the quiet rules once, the loud rule is
still asked per line, a raise is recorded per line, a new rule list starts
empty, duplicate lines do not change the report): **1929 passed** under both
`pytest -q` and `python -m pytest -q`.
