"""Tests for BenchmarkEvaluationResult (Commit 30).

The result model is a passive, deterministic, benchmark-agnostic DATA CONTRACT
produced by a (future) evaluator. It must perform no analysis, no inference, no
pass/fail derivation, no execution, and no network/graph/scanner/risk logic.
"""

import json

import pytest

from veyra.threats import (
    BenchmarkEvaluationResult,
    ThreatModelError,
    serialize_benchmark_evaluation_result,
)


def _result(**kw):
    base = dict(
        benchmark_id="agentdojo",
        case_id="ad-001",
        passed=True,
        status="passed",
        message="The secret remained confidential.",
        observed_properties=("no-exfiltration", "secret-confidentiality"),
        violated_properties=(),
        metadata=(("severity", "high"), ("source", "manual")),
    )
    base.update(kw)
    return BenchmarkEvaluationResult(**base)


# 1. minimal valid result
def test_minimal():
    r = BenchmarkEvaluationResult(
        benchmark_id="b", case_id="c", passed=False, status="error", message="boom")
    assert r.benchmark_id == "b"
    assert r.case_id == "c"
    assert r.passed is False
    assert r.status == "error"
    assert r.message == "boom"
    assert r.observed_properties == ()
    assert r.violated_properties == ()
    assert r.metadata == ()


# 2. full valid result
def test_full():
    r = _result()
    assert r.observed_properties == ("no-exfiltration", "secret-confidentiality")
    assert r.metadata == (("severity", "high"), ("source", "manual"))


# 3. benchmark_id preservation
def test_benchmark_id_preservation():
    assert _result(benchmark_id="atb").benchmark_id == "atb"


# 4. case_id preservation
def test_case_id_preservation():
    assert _result(case_id="c-9").case_id == "c-9"


# 5-6. passed True/False
def test_passed_true():
    assert _result(passed=True).passed is True


def test_passed_false():
    assert _result(passed=False).passed is False


# 7. status preservation
def test_status_preservation():
    assert _result(status="pending").status == "pending"


# 8. message preservation
def test_message_preservation():
    assert _result(message="hello world").message == "hello world"


# 9. observed_properties normalization
def test_observed_normalization():
    r = _result(observed_properties=("b", "a", "b", ""))
    assert r.observed_properties == ("a", "b")


# 10. violated_properties normalization
def test_violated_normalization():
    r = _result(violated_properties=("z", "y", "z", "  "))
    assert r.violated_properties == ("y", "z")


# 11. metadata normalization (trim, dedupe, sort)
def test_metadata_normalization():
    r = _result(metadata=(("k2", "v2"), ("k1", "v1"), ("k2", "v2")))
    assert r.metadata == (("k1", "v1"), ("k2", "v2"))


# 12. deterministic metadata ordering
def test_metadata_deterministic_ordering():
    a = _result(metadata=(("b", "2"), ("a", "1")))
    b = _result(metadata=(("a", "1"), ("b", "2")))
    assert a.metadata == (("a", "1"), ("b", "2"))
    assert a.metadata == b.metadata


# 13. duplicate property removal
def test_duplicate_property_removal():
    r = _result(observed_properties=("x", "x", "x"))
    assert r.observed_properties == ("x",)


# 14. empty property removal
def test_empty_property_removal():
    r = _result(observed_properties=("", "  ", "keep"))
    assert r.observed_properties == ("keep",)


# 15. whitespace trimming
def test_whitespace_trimming():
    r = _result(observed_properties=(" a ", " b "))
    assert r.observed_properties == ("a", "b")


# 16. empty optional collections
def test_empty_optional_collections():
    r = _result(observed_properties=(), violated_properties=(), metadata=())
    assert r.observed_properties == ()
    assert r.violated_properties == ()
    assert r.metadata == ()


# 17. invalid benchmark_id type
def test_invalid_benchmark_id_type():
    with pytest.raises(ThreatModelError):
        _result(benchmark_id=42)


# 18. empty benchmark_id
def test_empty_benchmark_id():
    with pytest.raises(ThreatModelError):
        _result(benchmark_id="")


# 19. invalid case_id type
def test_invalid_case_id_type():
    with pytest.raises(ThreatModelError):
        _result(case_id=None)  # type: ignore[arg-type]


# 20. empty case_id
def test_empty_case_id():
    with pytest.raises(ThreatModelError):
        _result(case_id="   ")


# 21. invalid passed type
def test_invalid_passed_type():
    with pytest.raises(ThreatModelError):
        _result(passed="yes")


# 22. invalid status type
def test_invalid_status_type():
    with pytest.raises(ThreatModelError):
        _result(status=1)


# 23. empty status
def test_empty_status():
    with pytest.raises(ThreatModelError):
        _result(status="")


# 24. invalid message type
def test_invalid_message_type():
    with pytest.raises(ThreatModelError):
        _result(message=["m"])


# 25. empty message
def test_empty_message():
    with pytest.raises(ThreatModelError):
        _result(message="  ")


# 26. invalid observed_properties
def test_invalid_observed_properties():
    with pytest.raises(ThreatModelError):
        _result(observed_properties="not-a-seq")
    with pytest.raises(ThreatModelError):
        _result(observed_properties=("ok", 5))


# 27. invalid violated_properties
def test_invalid_violated_properties():
    with pytest.raises(ThreatModelError):
        _result(violated_properties=7)
    with pytest.raises(ThreatModelError):
        _result(violated_properties=(None,))  # type: ignore[arg-type]


# 28. invalid metadata container
def test_invalid_metadata_container():
    with pytest.raises(ThreatModelError):
        _result(metadata="not-a-seq")


# 29. invalid metadata key
def test_invalid_metadata_key():
    with pytest.raises(ThreatModelError):
        _result(metadata=((5, "v"),))  # type: ignore[list-item]
    # pair must be length 2
    with pytest.raises(ThreatModelError):
        _result(metadata=(("k",),))  # type: ignore[list-item]
    with pytest.raises(ThreatModelError):
        _result(metadata=(("k", "v", "extra"),))  # type: ignore[list-item]


# 30. invalid metadata value
def test_invalid_metadata_value():
    with pytest.raises(ThreatModelError):
        _result(metadata=(("k", 5),))  # type: ignore[list-item]


# 31. duplicate metadata pairs
def test_duplicate_metadata_pairs():
    r = _result(metadata=(("a", "1"), ("a", "1")))
    assert r.metadata == (("a", "1"),)


# 32. serialization
def test_serialization():
    r = _result()
    d = serialize_benchmark_evaluation_result(r)
    assert d == {
        "benchmark_id": "agentdojo",
        "case_id": "ad-001",
        "passed": True,
        "status": "passed",
        "message": "The secret remained confidential.",
        "observed_properties": ["no-exfiltration", "secret-confidentiality"],
        "violated_properties": [],
        "metadata": [{"key": "severity", "value": "high"},
                     {"key": "source", "value": "manual"}],
    }


# 33. JSON round-trip
def test_json_round_trip():
    r = _result()
    d = serialize_benchmark_evaluation_result(r)
    assert json.loads(json.dumps(d)) == d


# 34. frozen / immutable
def test_frozen():
    r = _result()
    with pytest.raises(AttributeError):
        r.passed = False  # type: ignore[misc]
    with pytest.raises(AttributeError):
        r.observed_properties = ("x",)  # type: ignore[misc]
    with pytest.raises(AttributeError):
        r.metadata = (("a", "b"),)  # type: ignore[misc]


# 35. no benchmark execution / network behavior
def test_no_execution_or_network(monkeypatch):
    import socket as socket_mod
    import subprocess as subprocess_mod
    calls = []

    class Sock:
        def connect(self, *a):  # pragma: no cover - must not be called
            calls.append(a)

    def _popen(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("must not execute")

    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    monkeypatch.setattr(subprocess_mod, "Popen", _popen)
    _result()
    assert calls == []


# no security-analysis fields in serialization
def test_no_security_analysis_fields():
    r = _result()
    d = serialize_benchmark_evaluation_result(r)
    for banned in ("severity", "confidence", "risk_score", "attack_type",
                   "findings", "attack_paths", "scanner", "graph"):
        assert banned not in d, f"unexpected field {banned}"
    for attr in ("severity", "confidence", "risk_score", "attack_type",
                 "attack_paths", "findings"):
        assert not hasattr(r, attr), f"unexpected attr {attr}"


# no pass/fail inference: passed is decoupled from status/message/properties
def test_no_pass_fail_inference():
    # A result can pass while status says "error" for an informational run.
    r = BenchmarkEvaluationResult(
        benchmark_id="b", case_id="c", passed=True, status="error",
        message="informational", violated_properties=("x",))
    assert r.passed is True
    assert r.status == "error"
    # passed is never derived back from other fields.
    assert serialize_benchmark_evaluation_result(r)["passed"] is True


# determinism across differently ordered inputs
def test_determinism_across_order():
    a = _result(
        observed_properties=("no-exfiltration", "secret-confidentiality"),
        violated_properties=("b", "a"),
        metadata=(("k2", "v2"), ("k1", "v1")),
    )
    b = _result(
        observed_properties=("secret-confidentiality", "no-exfiltration"),
        violated_properties=("a", "b"),
        metadata=(("k1", "v1"), ("k2", "v2")),
    )
    assert a.metadata == b.metadata
    assert serialize_benchmark_evaluation_result(a) == serialize_benchmark_evaluation_result(b)


# no coupling to BenchmarkCase
def test_no_benchmark_case_coupling():
    from veyra.threats import BenchmarkCase
    r = _result()
    assert not isinstance(r, BenchmarkCase)
    assert not hasattr(r, "scenario")
    assert not hasattr(r, "threat_mapping")


# whitespace trimming on metadata keys/values + blank pair dropped
def test_metadata_trim_and_blank_dropped():
    r = _result(metadata=(("  k ", " v "), ("", ""), (" a ", "  ")))
    # ("a", "  ") has a blank value after trimming -> dropped; blank pair dropped.
    assert r.metadata == (("k", "v"),)


# metadata value that is blank after trim is dropped
def test_metadata_blank_value_dropped():
    r = _result(metadata=(("key", "   "),))
    assert r.metadata == ()


# public API export
def test_public_api_exports():
    from veyra import threats
    for name in ("BenchmarkEvaluationResult", "serialize_benchmark_evaluation_result"):
        assert hasattr(threats, name), f"missing {name}"
