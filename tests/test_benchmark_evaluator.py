"""Tests for BenchmarkEvaluator + SecurityAssertion integration (Commit 37).

The evaluator now derives violated_properties from SecurityAssertion
(expected = scenario.expected_security_properties, observed = caller-supplied
observed_properties). violated_properties is no longer caller-controlled; the
old `violated_properties` keyword is removed from the API.

passed = (number of asserted violations == 0). observed_properties are explicit;
violated_properties come only from SecurityAssertion.
"""

import pytest

from veyra.threats import (
    SecurityScenario,
    SecurityScenarioThreatMapping,
    SecurityAssertion,
    BenchmarkCase,
    BenchmarkEvaluationResult,
    BenchmarkEvaluator,
    ThreatModelError,
    serialize_benchmark_evaluation_result,
)
from veyra.threats.adapters import AgentDojoAdapter, AgentThreatBenchAdapter


def _scenario(expected=("no-exfiltration",), threat_categories=("ASI02", "data-exfiltration")):
    return SecurityScenario(
        scenario_id="s-1",
        name="Scenario",
        description="Expected: no exfiltration.",
        threat_categories=threat_categories,
        expected_security_properties=expected,
    )


def _case(benchmark_id="dummy", case_id="c-1", scenario=None, **kw):
    base = dict(
        benchmark_id=benchmark_id,
        case_id=case_id,
        name="Secret Exfil",
        description="Ensure secrets stay confidential.",
        scenario=scenario if scenario is not None else _scenario(),
        threat_mapping=SecurityScenarioThreatMapping(scenario_id="s-1", threat_ids=("ASI02",)),
    )
    base.update(kw)
    return BenchmarkCase(**base)


def _no_expected_case():
    return _case(scenario=_scenario(expected=()))


EV = BenchmarkEvaluator()


def _case_from_adapter(benchmark_id, adapter):
    bc = adapter.adapt({"case_id": "c-x", "name": "n", "description": "d",
                        "threat_ids": ["ASI01"], "threat_categories": ["ASI01"]})
    return BenchmarkCase(benchmark_id=benchmark_id, case_id=bc.case_id, name=bc.name,
                         description=bc.description, scenario=bc.scenario,
                         threat_mapping=bc.threat_mapping)


# ---- A. Assertion integration ----
def test_missing_expected_is_violation():
    r = EV.evaluate(_case(), observed_properties=())
    assert r.violated_properties == ("no-exfiltration",)
    assert r.passed is False


def test_all_expected_observed_no_violations():
    r = EV.evaluate(_case(), observed_properties=("no-exfiltration",))
    assert r.violated_properties == ()
    assert r.passed is True


def test_observed_extra_ignored():
    r = EV.evaluate(_case(), observed_properties=("no-exfiltration", "extra-prop"))
    assert r.violated_properties == ()
    assert r.observed_properties == ("extra-prop", "no-exfiltration")


def test_multiple_expected_violations():
    sc = _scenario(expected=("a", "b", "c"))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("c",))
    assert r.violated_properties == ("a", "b")


def test_empty_expected_properties():
    r = EV.evaluate(_no_expected_case())
    assert r.violated_properties == ()
    assert r.passed is True


def test_empty_observed_properties():
    r = EV.evaluate(_case())
    assert r.violated_properties == ("no-exfiltration",)


def test_normalization_preserved():
    sc = _scenario(expected=(" a ", "b"))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("  a ",))
    assert r.violated_properties == ("b",)


def test_case_sensitive_matching():
    sc = _scenario(expected=("SecretRead",))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("secretread",))
    assert r.violated_properties == ("SecretRead",)


def test_no_fuzzy_matching():
    sc = _scenario(expected=("no-network-egress",))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("no-network-egres",))
    assert r.violated_properties == ("no-network-egress",)


def test_no_substring_matching():
    sc = _scenario(expected=("exfil",))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("secret-exfil",))
    assert r.violated_properties == ("exfil",)


# ---- B. Result semantics ----
def test_violations_from_security_assertion():
    r = EV.evaluate(_case(), observed_properties=())
    assert r.violated_properties == ("no-exfiltration",)


def test_passed_false_when_violation():
    assert EV.evaluate(_case(), observed_properties=()).passed is False


def test_passed_true_when_no_violation():
    assert EV.evaluate(_case(), observed_properties=("no-exfiltration",)).passed is True


def test_passed_true_minimal_no_expected():
    assert EV.evaluate(_no_expected_case()).passed is True


def test_benchmark_id_preserved():
    assert EV.evaluate(_case(benchmark_id="x")).benchmark_id == "x"


def test_case_id_preserved():
    assert EV.evaluate(_case(case_id="abc")).case_id == "abc"


def test_status_preserved():
    assert EV.evaluate(_case(), status="error").status == "error"


def test_message_preserved():
    assert EV.evaluate(_case(), message="all good").message == "all good"


def test_default_message():
    assert EV.evaluate(_case()).message == "Benchmark evaluation completed."


def test_metadata_preserved():
    r = EV.evaluate(_case(), metadata=(("k1", "v1"),))
    assert r.metadata == (("k1", "v1"),)


def test_result_frozen():
    r = EV.evaluate(_case())
    with pytest.raises(AttributeError):
        r.passed = True  # type: ignore[misc]


def test_result_immutable_fields():
    r = EV.evaluate(_case())
    with pytest.raises(AttributeError):
        r.observed_properties = ("x",)  # type: ignore[misc]


# ---- C. Source-of-truth behavior ----
def test_caller_cannot_override_violations():
    # observed that satisfies all expectations wins; no caller-supplied violations.
    r = EV.evaluate(_case(), observed_properties=("no-exfiltration",))
    assert r.violated_properties == ()
    assert r.passed is True


def test_old_violated_properties_keyword_raises_typeerror():
    with pytest.raises(TypeError):
        EV.evaluate(_case(), observed_properties=("a",),
                    violated_properties=("fake",))  # type: ignore[call-arg]


def test_no_independent_difference_calculation():
    # Evaluator relies on SecurityAssertion; it never computes expected-observed
    # itself. Verified by delegation test (assertion is the single source).
    r = EV.evaluate(_case(), observed_properties=())
    assert r.violated_properties == ("no-exfiltration",)


def test_no_inference_from_scenario_name():
    sc = _scenario(expected=("a",))
    sc2 = SecurityScenario(scenario_id="s", name="MUST PREVENT SECRET EXFIL",
                           description="d", expected_security_properties=("a",))
    r = EV.evaluate(_case(scenario=sc2), observed_properties=("a",))
    assert r.passed is True


def test_no_inference_from_description():
    sc = SecurityScenario(scenario_id="s", name="n", description="leak leak leak",
                          expected_security_properties=("a",))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("a",))
    assert r.passed is True


def test_no_inference_from_threat_categories():
    sc = _scenario(expected=("no-exfiltration",), threat_categories=("ASI02",))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("no-exfiltration",))
    assert r.passed is True


def test_no_inference_from_attack_behaviors():
    sc = SecurityScenario(scenario_id="s", name="n", description="d",
                          attack_behaviors=("secret-read", "sends-to-endpoint"),
                          expected_security_properties=())
    r = EV.evaluate(_case(scenario=sc), observed_properties=("secret-read",))
    assert r.passed is True


def test_no_inference_from_threat_mapping():
    case = _case()
    assert case.threat_mapping.threat_ids == ("ASI02",)
    r = EV.evaluate(case, observed_properties=("no-exfiltration",))
    assert r.passed is True


def test_no_inference_from_owasp():
    sc = _scenario(expected=("no-exfiltration",), threat_categories=("ASI02",))
    r = EV.evaluate(_case(scenario=sc), observed_properties=("no-exfiltration",))
    assert r.passed is True


def test_does_not_inspect_attack_path():
    from veyra.graph.path import AttackPath
    r = EV.evaluate(_case())
    assert not isinstance(r, AttackPath)
    assert not hasattr(r, "nodes")


# ---- D. Assertion delegation ----
def test_delegates_to_security_assertion(monkeypatch):
    calls = []
    real = SecurityAssertion()
    orig = SecurityAssertion.assert_properties

    def _spy(self, expected, observed):
        calls.append((expected, observed))
        return orig(self, expected, observed)

    monkeypatch.setattr(SecurityAssertion, "assert_properties", _spy)
    EV.evaluate(_case(), observed_properties=("no-exfiltration",))
    assert len(calls) == 1


def test_exact_expected_passed_to_assertion(monkeypatch):
    sc = _scenario(expected=("a", "b"))
    seen = {}
    def _spy(self, expected, observed):
        seen["expected"] = tuple(expected)
        seen["observed"] = tuple(observed)
        return ()
    monkeypatch.setattr(SecurityAssertion, "assert_properties", _spy)
    EV.evaluate(_case(scenario=sc), observed_properties=("a", "b"))
    assert seen["expected"] == ("a", "b")


def test_exact_observed_passed_to_assertion(monkeypatch):
    seen = {}
    def _spy(self, expected, observed):
        seen["observed"] = tuple(observed)
        return ()
    monkeypatch.setattr(SecurityAssertion, "assert_properties", _spy)
    EV.evaluate(_case(), observed_properties=("x", "y"))
    assert list(seen["observed"]) == ["x", "y"]


def test_assertion_output_becomes_violations(monkeypatch):
    def _spy(self, expected, observed):
        return ("made-up",)
    monkeypatch.setattr(SecurityAssertion, "assert_properties", _spy)
    r = EV.evaluate(_case(), observed_properties=("no-exfiltration",))
    assert r.violated_properties == ("made-up",)
    assert r.passed is False


def test_assertion_invoked_once(monkeypatch):
    calls = []
    orig = SecurityAssertion.assert_properties
    def _spy(self, expected, observed):
        calls.append(1)
        return orig(self, expected, observed)
    monkeypatch.setattr(SecurityAssertion, "assert_properties", _spy)
    EV.evaluate(_case(), observed_properties=("no-exfiltration",))
    assert len(calls) == 1


# ---- E. Isolation / regression ----
def test_no_expected_properties_case():
    r = EV.evaluate(_no_expected_case(), observed_properties=("whatever",))
    assert r.violated_properties == ()
    assert r.passed is True


def test_does_not_mutate_benchmark_case():
    case = _case()
    snap = (case.benchmark_id, case.case_id, case.name, case.description,
            case.scenario.expected_security_properties)
    EV.evaluate(case, observed_properties=())
    assert (case.benchmark_id, case.case_id, case.name, case.description,
            case.scenario.expected_security_properties) == snap


def test_does_not_mutate_security_scenario():
    sc = _scenario(expected=("a", "b"))
    case = _case(scenario=sc)
    snap = sc.expected_security_properties
    EV.evaluate(case, observed_properties=("a",))
    assert sc.expected_security_properties == snap


def test_does_not_mutate_observed_input():
    obs = ["z", "a"]
    before = list(obs)
    EV.evaluate(_case(), observed_properties=obs)
    assert list(obs) == before


# validation of remaining params
def test_invalid_case_type():
    with pytest.raises(ThreatModelError):
        EV.evaluate("not-a-case")


def test_invalid_observed_scalar():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), observed_properties="abc")


def test_invalid_observed_element():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), observed_properties=("ok", 5))


def test_invalid_status():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), status="")


def test_invalid_message_type():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), message=["x"])


def test_invalid_metadata():
    with pytest.raises(ThreatModelError):
        EV.evaluate(_case(), metadata=(("k", 5),))  # type: ignore[list-item]


def test_metadata_normalization_delegated():
    r = EV.evaluate(_case(), metadata=((" b ", "2"), (" a ", "1")))
    assert r.metadata == (("a", "1"), ("b", "2"))


def test_result_type():
    assert isinstance(EV.evaluate(_case()), BenchmarkEvaluationResult)


def test_result_is_deterministic():
    a = serialize_benchmark_evaluation_result(
        EV.evaluate(_case(), observed_properties=("no-exfiltration",)))
    b = serialize_benchmark_evaluation_result(
        EV.evaluate(_case(), observed_properties=("no-exfiltration",)))
    assert a == b


def test_agentdojo_case_agnostic():
    case = _case_from_adapter("agentdojo", AgentDojoAdapter())
    r = EV.evaluate(case)
    # adapter case has no expected_security_properties -> no violations
    assert r.benchmark_id == "agentdojo"
    assert r.passed is True


def test_agentthreatbench_case_agnostic():
    case = _case_from_adapter("agentthreatbench", AgentThreatBenchAdapter())
    r = EV.evaluate(case)
    assert r.benchmark_id == "agentthreatbench"
    assert r.passed is True


def test_no_risk_or_security_fields():
    r = EV.evaluate(_case(), observed_properties=())
    for attr in ("risk_score", "severity", "confidence", "attack_type", "findings"):
        assert not hasattr(r, attr)
    d = serialize_benchmark_evaluation_result(r)
    for banned in ("risk", "severity", "confidence", "attack_type", "findings",
                   "attack_paths", "scanner"):
        assert banned not in d


def test_no_network_subprocess(monkeypatch):
    import socket as socket_mod, subprocess as subprocess_mod
    calls = []
    class Sock:
        def connect(self, *a):
            calls.append(a)
    monkeypatch.setattr(socket_mod.socket, "connect", Sock().connect)
    monkeypatch.setattr(subprocess_mod, "Popen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no subprocess")))
    EV.evaluate(_case())
    assert calls == []


def test_public_api_exports():
    from veyra import threats
    assert hasattr(threats, "BenchmarkEvaluator")
    assert threats.BenchmarkEvaluator is BenchmarkEvaluator


def test_existing_other_exports_preserved():
    from veyra import threats
    for name in ("SecurityAssertion", "BenchmarkEvaluationResult", "BenchmarkCase",
                 "SecurityScenario", "ObservationBenchmarkRunner"):
        assert hasattr(threats, name), f"missing {name}"
