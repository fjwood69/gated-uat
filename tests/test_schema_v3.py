"""tests/test_schema_v3.py — the v3 enforcement schema + preregistration-relative admissibility.

Pure/fast (no podman): synthetic payloads exercise the provenance-typed, scenario-specific v3
schema and the expectation-vs-observation admissibility rule — the falsifiability core. Proves:

  * a well-formed receipt per scenario validates; the fabrication / omission / incoherence channels
    the dissents named FAIL (a fabricated plan_policy_id on a non_run, a missing seed-trace field,
    an admitted-only coord on a refusal, a scenario↔kind mismatch);
  * admissibility CONFIRMS a matched prediction (including a governance refusal / non-run), REFUTES
    a mismatch (a predicted block that comes back a different reason), and NEVER admits an
    infrastructure_failure even when predicted+matched.
"""

from __future__ import annotations

import unittest
from typing import Any

from nacl.signing import SigningKey

from orchestrator.evidence import (
    VerifiedChain,
    build_execution_receipt,
    build_index,
    build_receipt,
    build_teardown_receipt,
    verify_integrity,
)
from orchestrator.expectations import ScenarioId, expected_for
from orchestrator.schemas import (
    SchemaViolationError,
    validate_execution_payload_v3,
    validate_prereg_payload,
)

_HEX = "a" * 64
_HEX2 = "b" * 64
_SHA = "sha256:" + "c" * 64
_ISO = "2026-07-18T09:00:00Z"
_POLICY = "uat-enforce"
_SEED_TRACE = {
    "policy_id": _POLICY, "detector_id": "RetryCheck", "set_id": "default",
    "calibration_result_ref": "ref-1", "pinned_set_version": _HEX, "subject": _HEX2,
    "policy_head": _HEX,
}


def _prereg_payload(scenario: ScenarioId) -> dict[str, Any]:
    exp = expected_for(scenario)
    return {
        "schema_version": 3, "profile": "p1", "gated_commit": "1d75d54",
        "corpus_version": _HEX, "preregistered_at": _ISO, "scenario": scenario.value,
        "configured_policy_id": _POLICY, "code_sha": _HEX, "rc_event_digest": _HEX,
        "rc_image_ref": "localhost/mori:local", "rc_detector_id": "RetryCheck",
        "expected_kind": exp.kind, "expected_reason": exp.reason,
        "expected_sub_reason": exp.sub_reason,
    }


def _exec_common(scenario: ScenarioId, *, result_kind: str, result_reason: str,
                 outcome: str, gate_outcome: Any, plan_policy_id: Any) -> dict[str, Any]:
    return {
        "schema_version": 3, "profile": "p1", "gated_commit": "1d75d54", "outcome": outcome,
        "executed_at": _ISO, "canonical_digest_alg": "sha256", "canonical_digest_version": 1,
        # placeholder; build_execution_receipt overwrites it with the real prereg.digest at build.
        "prereg_digest": _HEX,
        "scenario": scenario.value, "configured_policy_id": _POLICY, "event_digest": _HEX,
        "result_kind": result_kind, "result_reason": result_reason, "result_sub_reason": "",
        "gate_outcome": gate_outcome, "plan_policy_id": plan_policy_id,
        "seed_trace": dict(_SEED_TRACE),
    }


def _exec_payload(scenario: ScenarioId) -> dict[str, Any]:
    """A well-formed execution payload for *scenario* (observed == expected)."""
    if scenario is ScenarioId.COMPLIANT_ADMIT:
        p = _exec_common(scenario, result_kind="admitted_run", result_reason="all_retried",
                         outcome="pass", gate_outcome="run_verdict", plan_policy_id=_POLICY)
        p.update({
            "bound_oracle_head": _HEX, "observed_policy_head_post_admission": _HEX,
            "artifact_tree_hash": _SHA, "image_digest": _SHA, "resolved_profile_digest": _HEX,
            "trust_policy_digest": _HEX, "guard_policy_digest": _HEX,
            "execution_identity_digest": _HEX,
        })
        return p
    if scenario is ScenarioId.NON_ENABLED_DEGRADED:
        return _exec_common(scenario, result_kind="non_run", result_reason="block_action_required",
                            outcome="error", gate_outcome="block_gate", plan_policy_id=None)
    if scenario is ScenarioId.ABA_GENERATION_MOVED:
        p = _exec_common(scenario, result_kind="blocking_refusal",
                         result_reason="policy_generation_moved", outcome="error",
                         gate_outcome="run_verdict", plan_policy_id=_POLICY)
        p["fault_injection"] = {
            "locus": "calibration-store scheduler", "mechanism": "append->transition->deprecate",
            "interleaving_point": "post-attestation/pre-generation-reread",
            "head_bound": _HEX, "head_moved": _HEX2, "head_returned": _HEX,
            "policy_head_pre": _HEX, "policy_head_post": _HEX2,
        }
        return p
    if scenario is ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE:
        p = _exec_common(scenario, result_kind="blocking_refusal", result_reason="subject_drift",
                         outcome="error", gate_outcome="run_verdict", plan_policy_id=_POLICY)
        p["drift_image_digest"] = _SHA
        return p
    # SHA_TAMPER
    p = _exec_common(scenario, result_kind="infrastructure_failure",
                     result_reason="artifact_integrity_mismatch", outcome="error",
                     gate_outcome=None, plan_policy_id=_POLICY)
    p["fault_injection"] = {
        "locus": "artifact_source", "mechanism": "post-hash mutation",
        "interleaving_point": "after tree-hash bind",
    }
    return p


class SchemaV3Tests(unittest.TestCase):
    def test_every_scenario_has_a_wellformed_prereg_and_execution(self) -> None:
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario):
                validate_prereg_payload(_prereg_payload(scenario))
                validate_execution_payload_v3(_exec_payload(scenario))

    def test_fabricated_plan_policy_id_on_a_non_run_is_rejected(self) -> None:
        p = _exec_payload(ScenarioId.NON_ENABLED_DEGRADED)
        p["plan_policy_id"] = _POLICY  # a non_run dispatched no plan — must be explicit null
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_missing_seed_trace_field_is_rejected(self) -> None:
        p = _exec_payload(ScenarioId.COMPLIANT_ADMIT)
        del p["seed_trace"]["subject"]
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_admitted_only_coord_on_a_refusal_is_rejected(self) -> None:
        p = _exec_payload(ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE)
        p["resolved_profile_digest"] = _HEX  # a refusal must not sign measured coords (amendment 4)
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_scenario_kind_incoherence_is_rejected(self) -> None:
        p = _exec_payload(ScenarioId.ABA_GENERATION_MOVED)
        p["result_kind"] = "admitted_run"  # scenario=aba cannot produce an admitted_run
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)


class AdmissibilityTests(unittest.TestCase):
    """Full signed chains (no podman) — preregistration-relative admissibility end to end."""

    def _chain(self, prereg_payload: dict[str, Any], exec_payload: dict[str, Any],
               *, failure: bool = False) -> VerifiedChain:
        sk = SigningKey.generate()
        prereg = build_receipt("prereg", "11111111-1111-4111-8111-111111111111",
                               prereg_payload, sk)
        execution = build_execution_receipt(prereg, exec_payload, sk)
        td = {"schema_version": 3, "profile": "p1", "failure": failure,
              "torn_down_at": _ISO, "runtime_pack_digest": _HEX}
        if failure:
            td["error"] = "teardown failed"
        teardown = build_teardown_receipt(execution, td, sk)
        index = build_index(prereg.run_id, prereg, execution, teardown, sk,
                            sk.verify_key.encode().hex())
        return verify_integrity(prereg, execution, teardown, index, sk.verify_key)

    def test_matched_prediction_is_admissible_incl_governance_refusal(self) -> None:
        for scenario in (ScenarioId.COMPLIANT_ADMIT, ScenarioId.NON_ENABLED_DEGRADED,
                         ScenarioId.ABA_GENERATION_MOVED, ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE):
            with self.subTest(scenario=scenario):
                chain = self._chain(_prereg_payload(scenario), _exec_payload(scenario))
                self.assertTrue(
                    chain.is_admitted, f"{scenario} matched prediction must be admitted")

    def test_refuted_prediction_is_not_admissible(self) -> None:
        # scenario=aba predicts policy_generation_moved; the run refused for a DIFFERENT reason
        # (same kind, schema-valid) — the prediction is REFUTED, so the chain is NOT admissible.
        exec_payload = _exec_payload(ScenarioId.ABA_GENERATION_MOVED)
        exec_payload["result_reason"] = "subject_drift"
        chain = self._chain(_prereg_payload(ScenarioId.ABA_GENERATION_MOVED), exec_payload)
        self.assertFalse(chain.is_admitted)

    def test_admitted_pass_predicted_but_fail_observed_is_not_admissible(self) -> None:
        exec_payload = _exec_payload(ScenarioId.COMPLIANT_ADMIT)
        exec_payload["outcome"] = "fail"  # predicted pass, observed fail — refuted
        chain = self._chain(_prereg_payload(ScenarioId.COMPLIANT_ADMIT), exec_payload)
        self.assertFalse(chain.is_admitted)

    def test_infrastructure_failure_is_never_admissible_even_when_matched(self) -> None:
        chain = self._chain(_prereg_payload(ScenarioId.SHA_TAMPER),
                            _exec_payload(ScenarioId.SHA_TAMPER))
        self.assertFalse(chain.is_admitted, "an infra chain is never enforcement evidence (amdt 3)")

    def test_failed_teardown_is_not_admissible(self) -> None:
        chain = self._chain(_prereg_payload(ScenarioId.COMPLIANT_ADMIT),
                            _exec_payload(ScenarioId.COMPLIANT_ADMIT), failure=True)
        self.assertFalse(chain.is_admitted)

    def test_scenario_mismatch_prereg_vs_execution_fails_integrity(self) -> None:
        # continuity: a run cannot attest a scenario it did not preregister.
        prereg_payload = _prereg_payload(ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE)
        exec_payload = _exec_payload(ScenarioId.ABA_GENERATION_MOVED)
        with self.assertRaises(Exception):
            self._chain(prereg_payload, exec_payload)


if __name__ == "__main__":
    unittest.main()
