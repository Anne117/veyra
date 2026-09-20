"""Benchmark runner evaluation bridge (Commit 35).

:class:`ObservationBenchmarkRunner` is the first concrete runner
implementation. It demonstrates the intended lifecycle WITHOUT executing an
external benchmark:

    BenchmarkCase
        -> BenchmarkExecutionBoundary (identity)
        -> explicit observations
        -> BenchmarkEvaluator.evaluate()
        -> BenchmarkEvaluationResult

EXECUTION and EVALUATION remain separate. The runner accepts explicit
observations as input but infers nothing (no security properties, severity,
threats, OWASP categories, AttackPaths, or risk). It does not compare
observations against ``scenario.expected_security_properties`` — that belongs
to a later Security Assertion layer.
"""

from __future__ import annotations

from typing import Sequence, Tuple

from veyra.threats._error import ThreatModelError
from veyra.threats.benchmarks import BenchmarkCase
from veyra.threats.evaluation import BenchmarkEvaluationResult
from veyra.threats.evaluator import BenchmarkEvaluator
from veyra.threats.execution import BenchmarkExecutionBoundary


class ObservationBenchmarkRunner:
    """Explicit observation-driven runner (the bridge to BenchmarkEvaluator).

    It accepts a BenchmarkEvaluator via constructor for dependency injection.
    One ``run()`` call produces exactly one BenchmarkEvaluationResult. Identity
    comes exclusively from the supplied BenchmarkCase.
    """

    def __init__(self, evaluator: BenchmarkEvaluator | None = None):
        if evaluator is None:
            evaluator = BenchmarkEvaluator()
        if not isinstance(evaluator, BenchmarkEvaluator):
            raise ThreatModelError(
                f"evaluator must be a BenchmarkEvaluator, "
                f"got {type(evaluator).__name__}"
            )
        self._evaluator = evaluator
        self._boundary = BenchmarkExecutionBoundary()

    def run(
        self,
        case: BenchmarkCase,
        *,
        observed_properties: Sequence[str] = (),
        violated_properties: Sequence[str] = (),
        status: str = "completed",
        message: str = "",
        metadata: Sequence[Tuple[str, str]] = (),
    ) -> BenchmarkEvaluationResult:
        if not isinstance(case, BenchmarkCase):
            raise ThreatModelError(
                f"case must be a BenchmarkCase, got {type(case).__name__}"
            )

        # Derive the (informational) execution request and verify identity.
        request = self._boundary.create_request(case)
        if request.benchmark_id != case.benchmark_id or request.case_id != case.case_id:
            raise ThreatModelError("execution request identity mismatch with case")

        # Delegate evaluation to the canonical evaluator path.
        return self._evaluator.evaluate(
            case,
            observed_properties=observed_properties,
            violated_properties=violated_properties,
            status=status,
            message=message,
            metadata=metadata,
        )
