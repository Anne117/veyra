"""Security Assertion layer (Commit 36).

A small, deterministic, benchmark-agnostic layer that compares explicit
observed security properties against the expected security properties declared
by ``SecurityScenario.expected_security_properties``.

The assertion layer determines property violations and returns them as an
immutable, deterministically-sorted tuple. It does NOT create a
:class:`BenchmarkEvaluationResult`, does NOT invoke the evaluator/runner, and
does NOT inspect scenarios, threat IDs, OWASP, AttackPaths, scanner findings,
or risk/severity/confidence.

Precise semantics (set difference on exact property identifiers):

- expected properties = properties the evaluated system is expected to satisfy;
- observed properties = properties explicitly supplied as observed;
- a property in ``expected`` absent from ``observed`` is violated;
- a property present in both is NOT violated;
- properties observed but not expected are NOT violations.

No fuzzy matching, no semantic similarity, no keyword inference. Identifiers are
compared exactly (case-sensitive) after the standard canonical string
normalization used by the threat models (trim, dedup, deterministic sort).
"""

from __future__ import annotations

from typing import Sequence, Tuple

from veyra.threats.scenarios import _require_str_tuple


class SecurityAssertion:
    """Deterministically compares expectations against explicit observations."""

    def assert_properties(
        self,
        expected_properties: Sequence[str],
        observed_properties: Sequence[str],
    ) -> Tuple[str, ...]:
        """Return the properties that are expected but not observed.

        Expected/observed are normalized (trim, dedup, sorted) via the existing
        threat-model convention; the result is the deterministic set difference
        ``expected - observed``, sorted.
        """
        expected = _require_str_tuple(expected_properties, "expected properties")
        observed = _require_str_tuple(observed_properties, "observed properties")
        observed_set = set(observed)
        return tuple(p for p in expected if p not in observed_set)
