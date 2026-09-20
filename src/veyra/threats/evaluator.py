"""Benchmark evaluator foundation (Commit 31; assertion integration Commit 37).

The first evaluation logic layer: converts a :class:`BenchmarkCase` plus explicit
evaluator observations into a :class:`BenchmarkEvaluationResult`.

It is pure and deterministic. It does NOT execute benchmarks, load datasets,
access the network, run subprocesses, run the Veyra scanner, build a
SecurityGraph/AttackPath, calculate Veyra risk, infer OWASP/threat IDs, call an
LLM, or do fuzzy matching. All evaluation facts are supplied explicitly.

Flow:

    SecurityScenario.expected_security_properties
        ↓
    SecurityAssertion.assert_properties(expected, observed)
        ↓
    explicit violated_properties
        ↓
    BenchmarkEvaluationResult

The ONLY evaluation rule here is the benchmark property contract:

    passed = (number of normalized violated_properties == 0)

This is NOT Veyra risk scoring and does NOT imply "secure"/"safe"/"low risk".
It means only "no explicitly supplied violated properties". observed_properties
are caller-supplied; violated_properties are DERIVED by SecurityAssertion and
are no longer caller-controlled.
"""

from __future__ import annotations

from typing import Sequence, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.assertions import SecurityAssertion
from veyra.threats.benchmarks import BenchmarkCase
from veyra.threats.evaluation import BenchmarkEvaluationResult

DEFAULT_MESSAGE = "Benchmark evaluation completed."
DEFAULT_STATUS = "completed"


class BenchmarkEvaluator:
    """Converts explicit observations into a deterministic evaluation result.

    violated_properties are derived by :class:`SecurityAssertion` from the
    scenario's expected properties versus the caller-supplied observations —
    there is exactly one source of truth for violations.
    """

    def __init__(self):
        self._assertion = SecurityAssertion()

    def evaluate(
        self,
        case: BenchmarkCase,
        *,
        observed_properties: Sequence[str] = (),
        status: str = DEFAULT_STATUS,
        message: str = "",
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> BenchmarkEvaluationResult:
        """Derive a BenchmarkEvaluationResult from a case and explicit facts."""
        if not isinstance(case, BenchmarkCase):
            raise ThreatModelError(
                f"case must be a BenchmarkCase, got {type(case).__name__}"
            )

        # BenchmarkEvaluationResult validates/normalizes status, message and
        # metadata. Empty message maps to a deterministic default
        # (BenchmarkEvaluationResult requires a non-empty message).
        # Non-string message is passed through so the result model rejects it.
        if isinstance(message, str) and (message == "" or not message.strip()):
            message = DEFAULT_MESSAGE

        # Derive violated_properties via the canonical SecurityAssertion layer.
        asserted_violations = self._assertion.assert_properties(
            case.scenario.expected_security_properties,
            observed_properties,
        )
        passed = len(asserted_violations) == 0

        return BenchmarkEvaluationResult(
            benchmark_id=case.benchmark_id,
            case_id=case.case_id,
            passed=passed,
            status=status,
            message=message,
            observed_properties=observed_properties,
            violated_properties=asserted_violations,
            metadata=metadata,
        )
