"""Tests for the execution-observation -> evaluation bridge (Commit 41)."""

from __future__ import annotations

import ast
import dataclasses

import pytest

from veyra.threats import (
    BenchmarkCase,
    BenchmarkEvaluationResult,
    BenchmarkEvaluator,
    BenchmarkExecutionBinding,
    BenchmarkExecutionEvaluator,
    BenchmarkExecutionObservation,
    BenchmarkExecutionRequest,
    BenchmarkObservation,
    SecurityScenario,
    SecurityScenarioThreatMapping,
    ThreatModelError,
)
from veyra.threats import execution_evaluator as bridge_module


# ----------------------------------------------------------------------- helpers


def _scenario(expected=("no-exfiltration",)):
    return SecurityScenario(
        scenario_id="s-1",
        name="Scenario",
        description="Expected: no exfiltration.",
        threat_categories=("ASI02",),
        expected_security_properties=expected,
    )


def _case(benchmark_id="dummy", case_id="c-1", scenario=None):
    return BenchmarkCase(
        benchmark_id=benchmark_id,
        case_id=case_id,
        name="Secret Exfil",
        description="Ensure secrets stay confidential.",
        scenario=scenario if scenario is not None else _scenario(),
        threat_mapping=SecurityScenarioThreatMapping(
            scenario_id="s-1", threat_ids=("ASI02",)
        ),
    )


def _binding(status="completed", properties=(), message="", metadata=(),
             benchmark_id="dummy", case_id="c-1"):
    return BenchmarkExecutionBinding(
        request=BenchmarkExecutionRequest(
            benchmark_id=benchmark_id, case_id=case_id
        ),
        observation=BenchmarkExecutionObservation(
            status=status,
            message=message,
            observed_properties=BenchmarkObservation(properties=properties),
            metadata=metadata,
        ),
    )


def _bridge(evaluator=None):
    return BenchmarkExecutionEvaluator(
        evaluator if evaluator is not None else BenchmarkEvaluator()
    )


class _RecordingEvaluator(BenchmarkEvaluator):
    """Records delegation without changing evaluator semantics."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def evaluate(self, case, **kwargs):
        self.calls.append((case, kwargs))
        return super().evaluate(case, **kwargs)


# -------------------------------------------------------------- construction/model


def test_valid_construction_with_evaluator():
    evaluator = BenchmarkEvaluator()
    bridge = BenchmarkExecutionEvaluator(evaluator=evaluator)
    assert bridge.evaluator is evaluator


def test_frozen_immutability():
    bridge = _bridge()
    with pytest.raises(dataclasses.FrozenInstanceError):
        bridge.evaluator = BenchmarkEvaluator()


def test_dataclass_frozen_with_single_field():
    assert dataclasses.is_dataclass(BenchmarkExecutionEvaluator)
    assert BenchmarkExecutionEvaluator.__dataclass_params__.frozen is True
    assert [f.name for f in dataclasses.fields(BenchmarkExecutionEvaluator)] == [
        "evaluator"
    ]


def test_evaluator_none_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionEvaluator(evaluator=None)


def test_evaluator_wrong_type_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionEvaluator(evaluator="evaluator")


def test_evaluator_duck_typed_object_rejected():
    class FakeEvaluator:
        def evaluate(self, case, **kwargs):
            raise AssertionError("must not be called")

    with pytest.raises(ThreatModelError):
        BenchmarkExecutionEvaluator(evaluator=FakeEvaluator())


def test_bridge_stores_no_execution_state():
    bridge = _bridge()
    assert vars(bridge) == {"evaluator": bridge.evaluator}


# -------------------------------------------------------------- evaluation success


def test_evaluate_completed_observation():
    result = _bridge().evaluate(
        _binding(status="completed", properties=("no-exfiltration",)), _case()
    )
    assert isinstance(result, BenchmarkEvaluationResult)
    assert result.passed is True
    assert result.benchmark_id == "dummy"
    assert result.case_id == "c-1"


def test_evaluate_failed_execution_status():
    result = _bridge().evaluate(
        _binding(status="failed", properties=("no-exfiltration",)), _case()
    )
    assert isinstance(result, BenchmarkEvaluationResult)
    assert result.passed is True


def test_evaluate_timeout_execution_status():
    result = _bridge().evaluate(
        _binding(status="timeout", properties=("no-exfiltration",)), _case()
    )
    assert isinstance(result, BenchmarkEvaluationResult)
    assert result.passed is True


def test_evaluate_error_execution_status():
    result = _bridge().evaluate(
        _binding(status="error", properties=("no-exfiltration",)), _case()
    )
    assert isinstance(result, BenchmarkEvaluationResult)
    assert result.passed is True


def test_non_completed_statuses_with_no_observed_properties_still_fail():
    for status in ("failed", "timeout", "error"):
        result = _bridge().evaluate(_binding(status=status), _case())
        assert result.passed is False, status
        assert result.violated_properties == ("no-exfiltration",)


def test_result_identity_comes_from_case():
    result = _bridge().evaluate(
        _binding(benchmark_id="agentdojo", case_id="case-9"),
        _case(benchmark_id="agentdojo", case_id="case-9"),
    )
    assert (result.benchmark_id, result.case_id) == ("agentdojo", "case-9")


def test_result_satisfies_missing_expected_property():
    # One expected property, none observed -> the assertion derives a violation.
    result = _bridge().evaluate(_binding(properties=()), _case())
    assert result.violated_properties == ("no-exfiltration",)
    assert result.passed is False


def test_result_satisfies_expected_property():
    result = _bridge().evaluate(
        _binding(properties=("no-exfiltration",)), _case()
    )
    assert result.violated_properties == ()
    assert result.passed is True


# ------------------------------------------- execution status is not a verdict


def test_failed_status_alone_creates_no_violated_properties():
    result = _bridge().evaluate(
        _binding(status="failed", properties=("no-exfiltration",)), _case()
    )
    assert result.violated_properties == ()
    assert result.passed is True


def test_timeout_status_alone_creates_no_violated_properties():
    result = _bridge().evaluate(
        _binding(status="timeout", properties=("no-exfiltration",)), _case()
    )
    assert result.violated_properties == ()
    assert result.passed is True


def test_error_status_alone_creates_no_violated_properties():
    result = _bridge().evaluate(
        _binding(status="error", properties=("no-exfiltration",)), _case()
    )
    assert result.violated_properties == ()
    assert result.passed is True


def test_completed_status_alone_does_not_force_passed():
    result = _bridge().evaluate(
        _binding(status="completed", properties=()), _case()
    )
    assert result.passed is False


def test_status_does_not_determine_passed_across_all_statuses():
    outcomes = {
        status: _bridge().evaluate(_binding(status=status, properties=()), _case()).passed
        for status in ("completed", "failed", "timeout", "error")
    }
    assert outcomes == {
        "completed": False,
        "failed": False,
        "timeout": False,
        "error": False,
    }


def test_message_and_metadata_are_not_security_input():
    result = _bridge().evaluate(
        _binding(
            status="failed",
            message="no-exfiltration",
            metadata=(("observed_properties", "no-exfiltration"),),
            properties=(),
        ),
        _case(),
    )
    assert result.observed_properties == ()
    assert result.passed is False


def test_execution_status_not_copied_into_result_status():
    result = _bridge().evaluate(_binding(status="timeout"), _case())
    assert result.status != "timeout"
    assert result.status == "completed"


# ------------------------------------------------------------- properties pass-through


def test_observation_properties_passed_through_exactly():
    props = ("a-prop", "b-prop")
    recording = _RecordingEvaluator()
    _bridge(recording).evaluate(_binding(properties=props), _case())
    (case, kwargs), = recording.calls
    assert kwargs["observed_properties"] == props


def test_properties_passed_as_benchmark_observation_tuple_not_rewrapped():
    recording = _RecordingEvaluator()
    observation = BenchmarkObservation(properties=("z", "a", "z", " ", "a"))
    binding = BenchmarkExecutionBinding(
        request=BenchmarkExecutionRequest(benchmark_id="dummy", case_id="c-1"),
        observation=BenchmarkExecutionObservation(
            status="completed", observed_properties=observation
        ),
    )
    _bridge(recording).evaluate(binding, _case())
    (_, kwargs), = recording.calls
    assert kwargs["observed_properties"] is observation.properties
    assert kwargs["observed_properties"] == ("a", "z")


def test_bridge_matches_direct_evaluator_result():
    binding = _binding(
        status="error",
        properties=("no-exfiltration", "extra-prop"),
        metadata=(("k", "v"),),
    )
    case = _case()
    bridged = _bridge().evaluate(binding, case)
    direct = BenchmarkEvaluator().evaluate(
        case, observed_properties=binding.observation.observed_properties.properties
    )
    assert bridged == direct


def test_evaluator_remains_the_evaluation_source():
    recording = _RecordingEvaluator()
    result = _bridge(recording).evaluate(_binding(), _case())
    assert len(recording.calls) == 1
    assert isinstance(result, BenchmarkEvaluationResult)


def test_bridge_does_not_call_assertion_directly():
    assert not hasattr(_bridge(), "_assertion")
    assert "SecurityAssertion" not in vars(bridge_module)


# ------------------------------------------------------------------ validation


def test_binding_none_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(None, _case())


def test_binding_wrong_type_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate("binding", _case())


def test_binding_dict_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate({"request": 1}, _case())


def test_binding_observation_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding().observation, _case())


def test_case_none_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(), None)


def test_case_wrong_type_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(), "case")


def test_case_duck_typed_object_rejected():
    class FakeCase:
        benchmark_id = "dummy"
        case_id = "c-1"

    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(), FakeCase())


def test_benchmark_id_mismatch_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(benchmark_id="other"), _case())


def test_case_id_mismatch_rejected():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(case_id="other"), _case())


def test_mismatch_error_message_names_both_identities():
    with pytest.raises(ThreatModelError) as excinfo:
        _bridge().evaluate(
            _binding(benchmark_id="req-bench", case_id="req-case"),
            _case(benchmark_id="case-bench", case_id="case-case"),
        )
    text = str(excinfo.value)
    assert "req-bench" in text and "case-bench" in text


def test_mismatch_reports_threat_model_error_not_assertion():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(benchmark_id="x"), _case())


def test_mismatch_does_not_evaluate():
    recording = _RecordingEvaluator()
    with pytest.raises(ThreatModelError):
        _bridge(recording).evaluate(_binding(case_id="nope"), _case())
    assert recording.calls == []


def test_case_identity_is_not_normalized_to_match():
    with pytest.raises(ThreatModelError):
        _bridge().evaluate(_binding(benchmark_id=" DUMMY "), _case())


# ------------------------------------------------------------------ no extra logic


def test_no_security_field_or_verdict_attributes():
    bridge = _bridge()
    for name in (
        "passed",
        "violated_properties",
        "risk",
        "risk_score",
        "severity",
        "confidence",
        "threat_ids",
        "owasp_ids",
        "attack_path",
        "findings",
        "status",
        "message",
        "metadata",
    ):
        assert not hasattr(bridge, name)


def test_public_api_surface_is_evaluate_only():
    public = {n for n in dir(BenchmarkExecutionEvaluator) if not n.startswith("_")}
    assert public == {"evaluate"}
    assert hasattr(_bridge(), "evaluator")


def test_no_execution_or_scanning_methods():
    for name in ("run", "execute", "scan", "discover", "load_dataset"):
        assert not hasattr(_bridge(), name)


def test_bridge_does_not_import_assertions_or_scanner():
    names = set(vars(bridge_module))
    for forbidden in (
        "SecurityAssertion",
        "AttackPath",
        "SecurityGraph",
        "assertions",
        "scanner",
        "adapters",
    ):
        assert forbidden not in names


def test_bridge_imports_are_passive_only():
    with open(bridge_module.__file__, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    allowed_stdlib = {"__future__", "dataclasses", "typing", "ast"}
    for module in imported:
        if module in allowed_stdlib:
            continue
        assert module.startswith("veyra.threats"), module
        for forbidden in (
            "assertions",
            "scanner",
            "runner",
            "mapping",
            "taxonomy",
            "catalogs",
            "adapters",
        ):
            assert forbidden not in module, module
    for forbidden in ("subprocess", "socket", "urllib", "requests", "pathlib", "os"):
        assert forbidden not in imported


def test_bridge_does_not_construct_a_benchmark_observation():
    assert "BenchmarkObservation" not in vars(bridge_module)


# --------------------------------------------------------------------- public API


def test_public_api_exports():
    import veyra.threats as threats

    assert "BenchmarkExecutionEvaluator" in threats.__all__
    assert threats.BenchmarkExecutionEvaluator is BenchmarkExecutionEvaluator


def test_existing_exports_intact():
    import veyra.threats as threats

    for name in (
        "ThreatModelError",
        "SecurityScenario",
        "BenchmarkCase",
        "BenchmarkEvaluator",
        "BenchmarkEvaluationResult",
        "BenchmarkObservation",
        "BenchmarkExecutionObservation",
        "BenchmarkExecutionBinding",
        "BenchmarkExecutionRequest",
        "BenchmarkExecutionBoundary",
        "BenchmarkRunner",
        "ObservationBenchmarkRunner",
        "SecurityAssertion",
        "serialize_benchmark_execution_binding",
    ):
        assert name in threats.__all__
        assert hasattr(threats, name)


def test_exports_are_unique():
    import veyra.threats as threats

    assert len(threats.__all__) == len(set(threats.__all__))
