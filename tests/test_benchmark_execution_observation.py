"""Tests for BenchmarkExecutionObservation (Commit 39).

An immutable data contract for explicit facts reported by a (future) benchmark
execution boundary. It contains only status/message/BenchmarkObservation/opaque
metadata. No security evaluation, no inference, no execution.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkObservation,
    BenchmarkExecutionObservation,
    ThreatModelError,
    serialize_benchmark_execution_observation,
)


def _obs(properties=("secret-read", "network-send")):
    return BenchmarkObservation(properties=properties)


def _eo(**kw):
    base = dict(status="completed", message="", observed_properties=_obs())
    base.update(kw)
    return BenchmarkExecutionObservation(**base)


# ---- A. Construction ----
def test_minimal_construction():
    o = BenchmarkExecutionObservation(status="completed")
    assert o.status == "completed"
    assert o.message == ""
    assert o.observed_properties == BenchmarkObservation()
    assert o.metadata == ()


def test_completed_status():
    assert _eo(status="completed").status == "completed"


def test_failed_status():
    assert _eo(status="failed").status == "failed"


def test_timeout_status():
    assert _eo(status="timeout").status == "timeout"


def test_error_status():
    assert _eo(status="error").status == "error"


def test_message_provided():
    assert _eo(message="observed a send").message == "observed a send"


def test_empty_message():
    assert _eo(message="").message == ""


def test_explicit_benchmark_observation():
    ob = BenchmarkObservation(properties=("a", "b"))
    o = _eo(observed_properties=ob)
    assert o.observed_properties is ob
    assert o.observed_properties.properties == ("a", "b")


def test_empty_benchmark_observation():
    o = _eo(observed_properties=BenchmarkObservation())
    assert o.observed_properties.properties == ()


def test_metadata():
    o = _eo(metadata=(("k", "v"),))
    assert o.metadata == (("k", "v"),)


# ---- B. Status validation ----
def test_status_none_rejected():
    with pytest.raises(ThreatModelError):
        _eo(status=None)  # type: ignore[arg-type]


def test_status_integer_rejected():
    with pytest.raises(ThreatModelError):
        _eo(status=123)


def test_status_empty_rejected():
    with pytest.raises(ThreatModelError):
        _eo(status="")


def test_status_whitespace_rejected():
    with pytest.raises(ThreatModelError):
        _eo(status="   ")


def test_status_whitespace_trimmed():
    assert _eo(status="  completed  ").status == "completed"


def test_status_case_preserved():
    assert _eo(status="Completed").status == "Completed"


def test_arbitrary_none_empty_status_accepted():
    assert _eo(status="arbitrary-custom-status").status == "arbitrary-custom-status"


# ---- C. Message validation ----
def test_message_none_rejected():
    with pytest.raises(ThreatModelError):
        _eo(message=None)  # type: ignore[arg-type]


def test_message_integer_rejected():
    with pytest.raises(ThreatModelError):
        _eo(message=123)


def test_message_whitespace_trimmed():
    assert _eo(message="  hi  ").message == "hi"


def test_message_empty_stays_empty():
    assert _eo(message="").message == ""


# ---- D. Observation validation ----
def test_benchmark_observation_accepted():
    o = _eo(observed_properties=_obs(("x",)))
    assert o.observed_properties.properties == ("x",)


def test_tuple_rejected():
    with pytest.raises(ThreatModelError):
        _eo(observed_properties=("a", "b"))  # type: ignore[arg-type]


def test_list_rejected():
    with pytest.raises(ThreatModelError):
        _eo(observed_properties=["a"])  # type: ignore[arg-type]


def test_dict_rejected():
    with pytest.raises(ThreatModelError):
        _eo(observed_properties={"properties": ["a"]})  # type: ignore[arg-type]


def test_properties_preserved_from_benchmark_observation():
    ob = BenchmarkObservation(properties=(" b ", "a", "b"))
    o = _eo(observed_properties=ob)
    assert o.observed_properties.properties == ("a", "b")


def test_no_duplicate_normalization_logic():
    # Normalization happens inside BenchmarkObservation, not here.
    ob = BenchmarkObservation(properties=(" a ", "a"))
    o = _eo(observed_properties=ob)
    assert o.observed_properties.properties == ("a",)


# ---- E. Metadata validation ----
def test_empty_metadata_accepted():
    assert _eo(metadata=()).metadata == ()


def test_valid_metadata_accepted():
    assert BenchmarkExecutionObservation(status="completed",
                                         metadata=(("k1", "v1"), ("k2", "v2"))).metadata == (
        ("k1", "v1"), ("k2", "v2"))


def test_metadata_keys_normalized():
    assert _eo(metadata=(("  k  ", "v"),)).metadata == (("k", "v"),)


def test_metadata_values_normalized():
    assert _eo(metadata=(("k", "  v  "),)).metadata == (("k", "v"),)


def test_invalid_metadata_key_rejected():
    with pytest.raises(ThreatModelError):
        _eo(metadata=((5, "v"),))  # type: ignore[list-item]


def test_invalid_metadata_value_rejected():
    with pytest.raises(ThreatModelError):
        _eo(metadata=(("k", 5),))  # type: ignore[list-item]


def test_malformed_pair_rejected():
    with pytest.raises(ThreatModelError):
        _eo(metadata=(("k",),))  # type: ignore[list-item]


def test_metadata_scalar_rejected():
    with pytest.raises(ThreatModelError):
        _eo(metadata="scalar")


# ---- F. Serialization ----
def test_exact_schema():
    ob = BenchmarkObservation(properties=("a",))
    o = _eo(status="completed", message="m", observed_properties=ob,
            metadata=(("k", "v"),))
    d = serialize_benchmark_execution_observation(o)
    assert d == {
        "status": "completed",
        "message": "m",
        "observed_properties": {"properties": ["a"]},
        "metadata": [["k", "v"]],
    }


def test_empty_observation_serialization():
    o = BenchmarkExecutionObservation(status="completed")
    d = serialize_benchmark_execution_observation(o)
    assert d == {
        "status": "completed",
        "message": "",
        "observed_properties": {"properties": []},
        "metadata": [],
    }


def test_nested_observed_properties_serialization():
    o = _eo(observed_properties=_obs(("x", "y")))
    d = serialize_benchmark_execution_observation(o)
    assert d["observed_properties"] == {"properties": ["x", "y"]}


def test_metadata_serialization():
    o = _eo(metadata=(("k2", "v2"), ("k1", "v1")))
    d = serialize_benchmark_execution_observation(o)
    assert d["metadata"] == [["k1", "v1"], ["k2", "v2"]]


def test_deterministic_serialization():
    o = _eo()
    assert serialize_benchmark_execution_observation(o) == \
        serialize_benchmark_execution_observation(o)


def test_no_extra_fields():
    o = _eo()
    d = serialize_benchmark_execution_observation(o)
    assert set(d.keys()) == {"status", "message", "observed_properties", "metadata"}


def test_json_safe():
    o = _eo()
    d = serialize_benchmark_execution_observation(o)
    assert json.loads(json.dumps(d)) == d


# ---- G. Isolation ----
def test_frozen_immutable():
    o = _eo()
    with pytest.raises(AttributeError):
        o.status = "x"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        o.observed_properties = _obs(("q",))  # type: ignore[misc]


def test_does_not_import_benchmark_evaluator():
    import veyra.threats.execution_observation as mod
    assert "BenchmarkEvaluator" not in mod.__dict__


def test_does_not_import_security_assertion():
    import veyra.threats.execution_observation as mod
    assert "SecurityAssertion" not in mod.__dict__


def test_does_not_import_benchmark_case():
    import veyra.threats.execution_observation as mod
    assert "BenchmarkCase" not in mod.__dict__


def test_does_not_import_attack_path():
    import veyra.threats.execution_observation as mod
    assert "AttackPath" not in mod.__dict__


def test_does_not_import_scanner():
    import veyra.threats.execution_observation as mod
    assert "scanner" not in mod.__dict__


def test_does_not_import_owasp():
    import veyra.threats.execution_observation as mod
    assert "OWASP_AGENTIC_2026" not in mod.__dict__


def test_no_network_subprocess_filesystem(monkeypatch):
    import socket, os, subprocess
    calls = []
    class Sock:
        def connect(self, *a):
            calls.append(a)
    monkeypatch.setattr(socket.socket, "connect", Sock().connect)
    monkeypatch.setattr(os, "listdir", lambda *a, **k: calls.append("ls"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess")))
    _eo()
    assert calls == []


def test_model_only_explicit_facts():
    o = _eo()
    assert set(vars(o).keys()) == {"status", "message", "observed_properties", "metadata"}
    for attr in ("passed", "violated_properties", "benchmark_id", "case_id",
                 "severity", "confidence", "risk_score", "attack_type", "findings"):
        assert not hasattr(o, attr)


def test_public_api_exports():
    from veyra import threats
    assert hasattr(threats, "BenchmarkExecutionObservation")
    assert threats.BenchmarkExecutionObservation is BenchmarkExecutionObservation
    assert hasattr(threats, "serialize_benchmark_execution_observation")


def test_existing_exports_intact():
    from veyra import threats
    for name in ("BenchmarkObservation", "BenchmarkEvaluator", "SecurityAssertion",
                 "BenchmarkCase", "BenchmarkEvaluationResult", "ObservationBenchmarkRunner"):
        assert hasattr(threats, name), f"missing {name}"
