"""Tests for the benchmark execution binding contract (Commit 40)."""

from __future__ import annotations

import json

import pytest

from veyra.threats import (
    BenchmarkExecutionBinding,
    BenchmarkExecutionObservation,
    BenchmarkExecutionRequest,
    BenchmarkObservation,
    ThreatModelError,
    serialize_benchmark_execution_binding,
)
from veyra.threats import execution_binding as binding_module


def _request(**kwargs):
    params = {"benchmark_id": "agentdojo", "case_id": "case-1"}
    params.update(kwargs)
    return BenchmarkExecutionRequest(**params)


def _observation(**kwargs):
    params = {"status": "completed"}
    params.update(kwargs)
    return BenchmarkExecutionObservation(**params)


def _binding(**kwargs):
    params = {"request": _request(), "observation": _observation()}
    params.update(kwargs)
    return BenchmarkExecutionBinding(**params)


# ---------------------------------------------------------------- construction


def test_valid_construction():
    request = _request()
    observation = _observation()
    binding = BenchmarkExecutionBinding(request=request, observation=observation)
    assert binding.request is request
    assert binding.observation is observation


def test_request_identity_with_varied_ids():
    binding = _binding(
        request=_request(benchmark_id="agentthreatbench", case_id="c-42")
    )
    assert binding.request.benchmark_id == "agentthreatbench"
    assert binding.request.case_id == "c-42"


def test_observation_status_preserved():
    binding = _binding(observation=_observation(status="timeout", message="slow"))
    assert binding.observation.status == "timeout"
    assert binding.observation.message == "slow"


def test_bound_observation_with_properties_and_metadata():
    observation = BenchmarkExecutionObservation(
        status="completed",
        observed_properties=BenchmarkObservation(properties=("b", "a")),
        metadata=(("env", "ci"),),
    )
    binding = _binding(observation=observation)
    assert binding.observation.observed_properties.properties == ("a", "b")
    assert binding.observation.metadata == (("env", "ci"),)


def test_each_binding_is_independent():
    first = _binding()
    second = _binding(request=_request(case_id="case-2"))
    assert first.request.case_id != second.request.case_id
    assert first is not second


def test_default_observation_equality_is_structural():
    assert _binding() == _binding()


# ------------------------------------------------------------------ immutability


def test_frozen_request_assignment_rejected():
    binding = _binding()
    with pytest.raises(Exception):
        binding.request = _request()


def test_frozen_observation_assignment_rejected():
    binding = _binding()
    with pytest.raises(Exception):
        binding.observation = _observation()


def test_dataclass_is_frozen_and_has_no_extra_fields():
    import dataclasses

    assert dataclasses.is_dataclass(BenchmarkExecutionBinding)
    assert BenchmarkExecutionBinding.__dataclass_params__.frozen is True
    assert [f.name for f in dataclasses.fields(BenchmarkExecutionBinding)] == [
        "request",
        "observation",
    ]


# ------------------------------------------------------------ request validation


def test_request_none_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(request=None, observation=_observation())


def test_request_dict_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request={"benchmark_id": "a", "case_id": "b"},
            observation=_observation(),
        )


def test_request_list_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=["a", "b"], observation=_observation()
        )


def test_request_tuple_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=("a", "b"), observation=_observation()
        )


def test_request_string_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(request="agentdojo", observation=_observation())


def test_request_duck_typed_object_rejected():
    class FakeRequest:
        benchmark_id = "a"
        case_id = "b"

    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=FakeRequest(), observation=_observation()
        )


def test_request_observation_swap_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=_observation(), observation=_request()
        )


# -------------------------------------------------------- observation validation


def test_observation_none_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(request=_request(), observation=None)


def test_observation_dict_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=_request(),
            observation={"status": "completed"},
        )


def test_observation_list_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(request=_request(), observation=["completed"])


def test_observation_tuple_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=_request(), observation=("completed",)
        )


def test_observation_string_rejected():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=_request(), observation="completed"
        )


def test_observation_duck_typed_object_rejected():
    class FakeObservation:
        status = "completed"

    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=_request(), observation=FakeObservation()
        )


def test_benchmark_observation_is_not_an_execution_observation():
    with pytest.raises(ThreatModelError):
        BenchmarkExecutionBinding(
            request=_request(), observation=BenchmarkObservation()
        )


# ------------------------------------------------------------------- identity


def test_identity_remains_on_request():
    binding = _binding()
    assert binding.request.benchmark_id == "agentdojo"
    assert binding.request.case_id == "case-1"


def test_no_duplicated_identity_fields_on_binding():
    binding = _binding()
    for name in ("benchmark_id", "case_id", "scenario_id", "status"):
        assert not hasattr(binding, name)


def test_no_helper_properties_duplicating_identity():
    for name in ("benchmark_id", "case_id"):
        assert name not in vars(BenchmarkExecutionBinding)
        assert name not in vars(type(_binding()))


# ------------------------------------------------------------------ no evaluation


def test_no_security_verdict_fields():
    binding = _binding()
    for name in (
        "passed",
        "failed",
        "violated_properties",
        "risk",
        "risk_score",
        "severity",
        "confidence",
        "threat_ids",
        "owasp_ids",
        "attack_path",
        "findings",
    ):
        assert not hasattr(binding, name)


def test_no_evaluation_methods_exposed():
    for name in (
        "evaluate",
        "assert_",
        "compare",
        "run",
        "execute",
        "compute_passed",
    ):
        assert not hasattr(_binding(), name)


def test_binding_does_not_import_evaluator():
    assert "evaluator" not in vars(binding_module)


def test_binding_does_not_import_assertions():
    assert "SecurityAssertion" not in vars(binding_module)


def test_binding_does_not_import_scanner_or_graph():
    names = set(vars(binding_module))
    for forbidden in ("AttackPath", "SecurityGraph", "scanner", "ScanResult"):
        assert forbidden not in names


def test_binding_does_not_import_owasp_taxonomy():
    names = set(vars(binding_module))
    assert not any("owasp" in name.lower() for name in names)


def test_module_imports_are_passive_contracts_only():
    import ast

    with open(binding_module.__file__, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported, "expected explicit imports"
    allowed_stdlib = {"__future__", "dataclasses", "ast", "typing"}
    for module in imported:
        if module in allowed_stdlib:
            continue
        assert module.startswith("veyra.threats"), module
        for forbidden in (
            "evaluator",
            "assertions",
            "scanner",
            "runner",
            "graph",
            "adapters",
            "policies",
            "taxonomy",
            "catalogs",
        ):
            assert forbidden not in module, module
    for forbidden in (
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "pathlib",
        "shutil",
        "os",
    ):
        assert forbidden not in imported


# ------------------------------------------------------------------- serialization


def test_exact_serialization_schema():
    binding = _binding()
    assert serialize_benchmark_execution_binding(binding) == {
        "request": {"benchmark_id": "agentdojo", "case_id": "case-1"},
        "observation": {
            "status": "completed",
            "message": "",
            "observed_properties": {"properties": []},
            "metadata": [],
        },
    }


def test_exact_top_level_keys():
    payload = serialize_benchmark_execution_binding(_binding())
    assert sorted(payload.keys()) == ["observation", "request"]


def test_exact_request_sub_schema():
    payload = serialize_benchmark_execution_binding(_binding())
    assert sorted(payload["request"].keys()) == ["benchmark_id", "case_id"]


def test_exact_observation_sub_schema():
    payload = serialize_benchmark_execution_binding(_binding())
    assert sorted(payload["observation"].keys()) == [
        "message",
        "metadata",
        "observed_properties",
        "status",
    ]


def test_nested_observation_serialization():
    binding = _binding(
        observation=_observation(
            status="failed",
            message="boom",
            observed_properties=BenchmarkObservation(properties=("z", "a")),
        )
    )
    payload = serialize_benchmark_execution_binding(binding)
    assert payload["observation"] == {
        "status": "failed",
        "message": "boom",
        "observed_properties": {"properties": ["a", "z"]},
        "metadata": [],
    }


def test_nested_metadata_serialization():
    binding = _binding(
        observation=_observation(metadata=(("z", "2"), ("a", "1")))
    )
    payload = serialize_benchmark_execution_binding(binding)
    assert payload["observation"]["metadata"] == [["a", "1"], ["z", "2"]]


def test_serialization_delegates_to_canonical_serializers():
    from veyra.threats import (
        serialize_benchmark_execution_observation,
        serialize_benchmark_execution_request,
    )

    binding = _binding(
        observation=_observation(
            observed_properties=BenchmarkObservation(properties=("p",)),
            metadata=(("k", "v"),),
        )
    )
    payload = serialize_benchmark_execution_binding(binding)
    assert payload["request"] == serialize_benchmark_execution_request(
        binding.request
    )
    assert payload["observation"] == serialize_benchmark_execution_observation(
        binding.observation
    )


def test_deterministic_serialization():
    binding = _binding(
        observation=_observation(
            observed_properties=BenchmarkObservation(properties=("b", "a")),
            metadata=(("k2", "v2"), ("k1", "v1")),
        )
    )
    first = serialize_benchmark_execution_binding(binding)
    for _ in range(5):
        assert serialize_benchmark_execution_binding(binding) == first


def test_serialization_is_json_safe():
    binding = _binding(
        observation=_observation(
            observed_properties=BenchmarkObservation(properties=("a",)),
            metadata=(("k", "v"),),
        )
    )
    payload = serialize_benchmark_execution_binding(binding)
    assert json.loads(json.dumps(payload)) == payload


def test_serialization_contains_no_security_verdict_keys():
    payload = serialize_benchmark_execution_binding(_binding())
    flat = json.dumps(payload)
    for forbidden in (
        "passed",
        "violated_properties",
        "severity",
        "confidence",
        "risk",
        "owasp",
        "threat_id",
        "attack_path",
        "findings",
    ):
        assert forbidden not in flat


def test_serialization_does_not_mutate_binding():
    binding = _binding(
        observation=_observation(
            observed_properties=BenchmarkObservation(properties=("a",)),
            metadata=(("k", "v"),),
        )
    )
    before = (binding.request.benchmark_id, binding.observation.status)
    serialize_benchmark_execution_binding(binding)
    assert (binding.request.benchmark_id, binding.observation.status) == before


# ------------------------------------------------------------------ public API


def test_public_api_exports():
    import veyra.threats as threats

    assert "BenchmarkExecutionBinding" in threats.__all__
    assert "serialize_benchmark_execution_binding" in threats.__all__
    assert threats.BenchmarkExecutionBinding is BenchmarkExecutionBinding
    assert (
        threats.serialize_benchmark_execution_binding
        is serialize_benchmark_execution_binding
    )


def test_existing_exports_intact():
    import veyra.threats as threats

    for name in (
        "ThreatModelError",
        "SecurityScenario",
        "BenchmarkCase",
        "BenchmarkObservation",
        "serialize_benchmark_observation",
        "BenchmarkExecutionObservation",
        "serialize_benchmark_execution_observation",
        "BenchmarkExecutionRequest",
        "BenchmarkExecutionBoundary",
        "BenchmarkRunner",
        "ObservationBenchmarkRunner",
        "SecurityAssertion",
        "serialize_benchmark_execution_request",
    ):
        assert name in threats.__all__
        assert hasattr(threats, name)


def test_other_public_api_symbols_unchanged():
    import veyra.threats as threats

    assert len(threats.__all__) == len(set(threats.__all__))
    assert hasattr(threats, "BenchmarkExecutionRequest")
