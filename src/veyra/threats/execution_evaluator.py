"""Execution-observation → evaluation bridge (Commit 41).

A thin, passive orchestration wrapper that connects an already-created
:class:`BenchmarkExecutionBinding` to the canonical
:class:`BenchmarkEvaluator`::

    BenchmarkExecutionBinding
        ↓
    BenchmarkExecutionEvaluator
        ↓
    BenchmarkEvaluator
        ↓
    SecurityAssertion
        ↓
    BenchmarkEvaluationResult

Only the observed security properties travel across the bridge
(``binding.observation.observed_properties``, an existing
:class:`BenchmarkObservation`). Execution facts — ``status``, ``message`` and
``metadata`` — are NOT reinterpreted as security input: ``status == "failed"``,
``"timeout"`` or ``"error"`` does NOT mean ``passed is False``, and
``status == "completed"`` does NOT mean ``passed is True``.

A :class:`BenchmarkCase` is required alongside the binding because
:class:`BenchmarkExecutionRequest` carries only ``benchmark_id``/``case_id`` and
therefore cannot supply the scenario expectations the evaluator needs. The case
is NOT reconstructed or invented: the caller passes it explicitly and its
identity must match the request exactly.

All security evaluation stays inside BenchmarkEvaluator/SecurityAssertion. The
bridge calculates nothing: no ``passed``, no ``violated_properties``, no
expected-vs-observed comparison, no risk/severity/confidence, no threat/OWASP
inference, no AttackPath/scanner access. No benchmark is executed, no dataset is
loaded, and no network/subprocess/filesystem operation occurs.

Commit 41 adds the bridge only; benchmark execution is still not implemented.
"""

from __future__ import annotations

from dataclasses import dataclass

from veyra.threats._error import ThreatModelError
from veyra.threats.benchmarks import BenchmarkCase
from veyra.threats.evaluation import BenchmarkEvaluationResult
from veyra.threats.evaluator import BenchmarkEvaluator
from veyra.threats.execution_binding import BenchmarkExecutionBinding


@dataclass(frozen=True)
class BenchmarkExecutionEvaluator:
    """Thin orchestration wrapper: binding (+ case) -> evaluation result.

    Immutable and stateless: it holds one :class:`BenchmarkEvaluator` (the
    canonical evaluation layer) and stores no execution state or results.
    """

    evaluator: BenchmarkEvaluator

    def __post_init__(self):
        if not isinstance(self.evaluator, BenchmarkEvaluator):
            raise ThreatModelError(
                "evaluator must be a BenchmarkEvaluator, "
                f"got {type(self.evaluator).__name__}"
            )

    def evaluate(
        self,
        binding: BenchmarkExecutionBinding,
        case: BenchmarkCase,
    ) -> BenchmarkEvaluationResult:
        """Evaluate one bound execution observation through the evaluator.

        ``case`` is the authoritative source of scenario expectations; its
        identity must match ``binding.request`` exactly. Only
        ``binding.observation.observed_properties.properties`` is forwarded — the
        properties are already normalized by :class:`BenchmarkObservation` and
        are passed through unchanged.
        """
        if not isinstance(binding, BenchmarkExecutionBinding):
            raise ThreatModelError(
                "binding must be a BenchmarkExecutionBinding, "
                f"got {type(binding).__name__}"
            )
        if not isinstance(case, BenchmarkCase):
            raise ThreatModelError(
                f"case must be a BenchmarkCase, got {type(case).__name__}"
            )

        request = binding.request
        if (
            case.benchmark_id != request.benchmark_id
            or case.case_id != request.case_id
        ):
            raise ThreatModelError(
                "execution request identity mismatch with case: "
                f"request=({request.benchmark_id!r}, {request.case_id!r}) "
                f"case=({case.benchmark_id!r}, {case.case_id!r})"
            )

        # Delegate to the canonical evaluator. Execution status/message/metadata
        # are deliberately NOT forwarded: they are execution facts, not security
        # evaluation input, so the evaluator's own defaults apply.
        return self.evaluator.evaluate(
            case,
            observed_properties=binding.observation.observed_properties.properties,
        )
