"""tests/test_schema_v3.py — the v3 (scenario, observed_kind) MATRIX + prereg admissibility.

Pure/fast (no podman). The acceptance FLOOR is the SIGNED-REFUTATION ROUND-TRIP: a chain that
predicts X but observes Y (an ABA that admits, a degraded policy that admits or silently neutrals, a
tamper that admits) must ``verify_integrity`` PASS — an honest, well-formed record — and
``evaluate_admission`` FAIL — a recorded refutation. The prior cut could not serialise these at all
(the schema keyed fields to the predicted kind → a confirmation filter). This proves the harness can
write down its own falsification, plus: fabrication/omission rejected at integrity; the authored
expectation bound at prereg validation; continuity closes rebinding; ABA evidence is non-degenerate.
"""

from __future__ import annotations

import unittest
from typing import Any

from nacl.signing import SigningKey

from orchestrator.evidence import (
    SemanticContinuityError,
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
_SHA_RUN = "sha256:" + "c" * 64    # the run image (== rc_image_digest)
_SHA_SEED = "sha256:" + "d" * 64   # a DISTINCT seed image (subject_drift endpoint)
_ISO = "2026-07-18T09:00:00Z"
_POLICY = "uat-enforce"

# the kind each scenario is PREDICTED to produce (used only to build the matched/happy case; the
# schema no longer keys anything to it — that was the confirmation-filter defect).
_EXPECTED_KIND = {
    ScenarioId.COMPLIANT_ADMIT: "admitted_run",
    ScenarioId.NON_ENABLED_DEGRADED: "non_run",
    ScenarioId.ABA_GENERATION_MOVED: "blocking_refusal",
    ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE: "blocking_refusal",
    ScenarioId.SHA_TAMPER: "infrastructure_failure",
}


def _seed_trace(scenario: ScenarioId) -> dict[str, Any]:
    return {
        "policy_id": _POLICY, "detector_id": "RetryCheck", "set_id": "default",
        "calibration_result_ref": "ref-1", "pinned_set_version": _HEX, "subject": _HEX2,
        "policy_head": _HEX,
        # the seed endpoint of a drift is a DISTINCT image; elsewhere seed == run.
        "seed_image_digest": _SHA_SEED if scenario is ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE
        else _SHA_RUN,
    }


def _aba_fault_injection() -> dict[str, Any]:
    return {
        "locus": "calibration-store scheduler", "mechanism": "append->transition->deprecate",
        "interleaving_point": "post-attestation/pre-generation-reread",
        "head_bound": _HEX, "head_moved": _HEX2, "head_returned": _HEX,   # bound==returned
        "policy_head_pre": _HEX, "policy_head_post": _HEX2,               # generation moved
    }


def _tamper_fault_injection() -> dict[str, Any]:
    return {
        "locus": "artifact_source", "mechanism": "post-hash mutation",
        "interleaving_point": "after tree-hash bind",
    }


def _admitted_coords() -> dict[str, Any]:
    return {
        "bound_oracle_head": _HEX, "observed_policy_head_post_admission": _HEX,
        "artifact_tree_hash": _SHA_RUN, "image_digest": _SHA_RUN, "resolved_profile_digest": _HEX,
        "trust_policy_digest": _HEX, "guard_policy_digest": _HEX, "execution_identity_digest": _HEX,
    }


def _gate_outcome_for(kind: str) -> Any:
    if kind == "infrastructure_failure":
        return None
    if kind == "non_run":
        return "block_gate"
    return "run_verdict"


def _prereg(scenario: ScenarioId) -> dict[str, Any]:
    exp = expected_for(scenario)
    return {
        "schema_version": 3, "profile": "p1", "gated_commit": "1d75d54",
        "corpus_version": _HEX, "preregistered_at": _ISO, "scenario": scenario.value,
        "configured_policy_id": _POLICY, "code_sha": _HEX, "rc_event_digest": _HEX,
        "rc_image_ref": "localhost/mori:local", "rc_image_digest": _SHA_RUN,
        "rc_detector_id": "RetryCheck", "expected_kind": exp.kind, "expected_reason": exp.reason,
        "expected_sub_reason": exp.sub_reason,
    }


def _exec(scenario: ScenarioId, observed_kind: str, *, result_reason: str, outcome: str,
          gate_outcome: Any = "<auto>", plan: Any = "<auto>") -> dict[str, Any]:
    """An execution payload for ANY (scenario, observed_kind) cell — matched or refuting."""
    if gate_outcome == "<auto>":
        gate_outcome = _gate_outcome_for(observed_kind)
    if plan == "<auto>":
        plan = None if observed_kind == "non_run" else _POLICY
    p: dict[str, Any] = {
        "schema_version": 3, "profile": "p1", "gated_commit": "1d75d54", "outcome": outcome,
        "executed_at": _ISO, "canonical_digest_alg": "sha256", "canonical_digest_version": 1,
        "prereg_digest": _HEX,  # placeholder; build_execution_receipt overwrites it
        "scenario": scenario.value, "configured_policy_id": _POLICY, "event_digest": _HEX,
        "result_kind": observed_kind, "result_reason": result_reason, "result_sub_reason": "",
        "gate_outcome": gate_outcome, "plan_policy_id": plan, "seed_trace": _seed_trace(scenario),
    }
    # CONFIGURED / FAULT-INJECTION by scenario (what the harness did).
    if scenario is ScenarioId.ABA_GENERATION_MOVED:
        p["fault_injection"] = _aba_fault_injection()
    elif scenario is ScenarioId.SHA_TAMPER:
        p["fault_injection"] = _tamper_fault_injection()
    elif scenario is ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE:
        p["drift_image_digest"] = _SHA_RUN
    # OBSERVED by kind (what the SUT produced).
    if observed_kind == "admitted_run":
        p.update(_admitted_coords())
    return p


def _matched_exec(scenario: ScenarioId) -> dict[str, Any]:
    """The happy/matched execution for *scenario* (observed == expected)."""
    kind = _EXPECTED_KIND[scenario]
    if kind == "admitted_run":
        return _exec(scenario, kind, result_reason="all_retried", outcome="pass")
    return _exec(scenario, kind, result_reason=expected_for(scenario).reason, outcome="error")


def _chain(prereg_payload: dict[str, Any], exec_payload: dict[str, Any],
           *, failure: bool = False) -> VerifiedChain:
    sk = SigningKey.generate()
    prereg = build_receipt("prereg", "11111111-1111-4111-8111-111111111111", prereg_payload, sk)
    execution = build_execution_receipt(prereg, exec_payload, sk)
    td: dict[str, Any] = {"schema_version": 3, "profile": "p1", "failure": failure,
                          "torn_down_at": _ISO, "runtime_pack_digest": _HEX}
    if failure:
        td["error"] = "teardown failed"
    teardown = build_teardown_receipt(execution, td, sk)
    index = build_index(
        prereg.run_id, prereg, execution, teardown, sk, sk.verify_key.encode().hex())
    return verify_integrity(prereg, execution, teardown, index, sk.verify_key)


class SchemaMatrixTests(unittest.TestCase):
    def test_every_scenario_matched_validates(self) -> None:
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario):
                validate_prereg_payload(_prereg(scenario))
                validate_execution_payload_v3(_matched_exec(scenario))

    def test_every_cell_is_representable(self) -> None:
        # the WHOLE point of the matrix: every (scenario, observed_kind) serialises — no
        # confirmation filter. A refutation cell (aba × admitted_run) is a well-formed record.
        for scenario in ScenarioId:
            for kind in ("admitted_run", "blocking_refusal", "non_run", "infrastructure_failure"):
                with self.subTest(scenario=scenario, observed=kind):
                    outcome = "pass" if kind == "admitted_run" else "error"
                    validate_execution_payload_v3(
                        _exec(scenario, kind, result_reason="tok", outcome=outcome))

    def test_fabricated_plan_on_non_run_is_integrity_violation(self) -> None:
        p = _exec(ScenarioId.NON_ENABLED_DEGRADED, "non_run", result_reason="block_action_required",
                  outcome="error", plan=_POLICY)  # a non_run captured no plan
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_gate_outcome_on_infra_is_integrity_violation(self) -> None:
        p = _exec(ScenarioId.SHA_TAMPER, "infrastructure_failure",
                  result_reason="artifact_integrity_mismatch", outcome="error",
                  gate_outcome="run_verdict")  # infra carries no gate outcome
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_missing_seed_trace_field_is_rejected(self) -> None:
        p = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        del p["seed_trace"]["subject"]
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_non_canonical_seed_image_digest_is_rejected(self) -> None:
        p = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        p["seed_trace"]["seed_image_digest"] = "not-a-digest"
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)


class AbaEvidenceTests(unittest.TestCase):
    def test_degenerate_heads_rejected(self) -> None:
        p = _matched_exec(ScenarioId.ABA_GENERATION_MOVED)
        p["fault_injection"]["head_bound"] = "x"  # not hex64
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_head_bound_must_equal_head_returned(self) -> None:
        p = _matched_exec(ScenarioId.ABA_GENERATION_MOVED)
        p["fault_injection"]["head_returned"] = _HEX2  # != head_bound → not an ABA return
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_head_moved_must_differ_from_bound(self) -> None:
        p = _matched_exec(ScenarioId.ABA_GENERATION_MOVED)
        p["fault_injection"]["head_moved"] = _HEX  # == head_bound → no real movement
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)

    def test_policy_generation_must_move(self) -> None:
        p = _matched_exec(ScenarioId.ABA_GENERATION_MOVED)
        p["fault_injection"]["policy_head_post"] = _HEX  # == pre → generation did not move
        with self.assertRaises(SchemaViolationError):
            validate_execution_payload_v3(p)


class PreregCanonTests(unittest.TestCase):
    def test_matched_prereg_validates(self) -> None:
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario):
                validate_prereg_payload(_prereg(scenario))

    def test_doctored_expectation_is_rejected(self) -> None:
        # a prereg whose expected triple does not match the authored fixture is rejected — the
        # authored expectation module is load-bearing at validation, not decorative.
        p = _prereg(ScenarioId.NON_ENABLED_DEGRADED)
        p["expected_reason"] = "skip_neutral"  # doctored to expect the silent-fall-open
        with self.assertRaises(SchemaViolationError):
            validate_prereg_payload(p)


class RefutationRoundTripTests(unittest.TestCase):
    """Acceptance FLOOR: a signed refutation round-trips — integrity PASS, admission FAIL."""

    def _refutation(self, scenario: ScenarioId, exec_payload: dict[str, Any]) -> None:
        chain = _chain(_prereg(scenario), exec_payload)
        self.assertTrue(chain.prereg.digest, "prereg is a valid signed record")  # integrity passed
        self.assertFalse(chain.is_admitted, "a refuted prediction must NOT be admissible")

    def test_aba_unexpectedly_admits(self) -> None:
        self._refutation(ScenarioId.ABA_GENERATION_MOVED, _exec(
            ScenarioId.ABA_GENERATION_MOVED, "admitted_run", result_reason="all_retried",
            outcome="pass"))

    def test_degraded_unexpectedly_admits(self) -> None:
        self._refutation(ScenarioId.NON_ENABLED_DEGRADED, _exec(
            ScenarioId.NON_ENABLED_DEGRADED, "admitted_run", result_reason="all_retried",
            outcome="pass"))

    def test_degraded_silently_neutrals(self) -> None:
        # the security-relevant silent-fall-open: a DEGRADED policy that skip-neutrals instead of
        # blocking. Kind is still non_run, so kind-only compare would MISS it; the disposition token
        # (skip_neutral vs block_action_required) catches it.
        self._refutation(ScenarioId.NON_ENABLED_DEGRADED, _exec(
            ScenarioId.NON_ENABLED_DEGRADED, "non_run", result_reason="skip_neutral",
            outcome="error", gate_outcome="neutral_gate"))

    def test_tamper_unexpectedly_admits(self) -> None:
        self._refutation(ScenarioId.SHA_TAMPER, _exec(
            ScenarioId.SHA_TAMPER, "admitted_run", result_reason="all_retried", outcome="pass"))


class AdmissibilityTests(unittest.TestCase):
    def test_matched_predictions_are_admissible(self) -> None:
        for scenario in (ScenarioId.COMPLIANT_ADMIT, ScenarioId.NON_ENABLED_DEGRADED,
                         ScenarioId.ABA_GENERATION_MOVED, ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE):
            with self.subTest(scenario=scenario):
                self.assertTrue(_chain(_prereg(scenario), _matched_exec(scenario)).is_admitted)

    def test_matched_infra_is_never_admissible(self) -> None:
        chain = _chain(_prereg(ScenarioId.SHA_TAMPER), _matched_exec(ScenarioId.SHA_TAMPER))
        self.assertFalse(chain.is_admitted, "infra is never enforcement evidence (amdt 3)")

    def test_failed_teardown_is_not_admissible(self) -> None:
        chain = _chain(_prereg(ScenarioId.COMPLIANT_ADMIT),
                       _matched_exec(ScenarioId.COMPLIANT_ADMIT), failure=True)
        self.assertFalse(chain.is_admitted)


class ContinuityTests(unittest.TestCase):
    def test_event_digest_rebinding_fails(self) -> None:
        p = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        p["event_digest"] = _HEX2  # != prereg.rc_event_digest
        with self.assertRaises(SemanticContinuityError):
            _chain(_prereg(ScenarioId.COMPLIANT_ADMIT), p)

    def test_seed_policy_rebinding_fails(self) -> None:
        p = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        p["seed_trace"]["policy_id"] = "other-policy"
        with self.assertRaises(SemanticContinuityError):
            _chain(_prereg(ScenarioId.COMPLIANT_ADMIT), p)

    def test_run_image_rebinding_fails(self) -> None:
        p = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        p["image_digest"] = "sha256:" + "e" * 64  # != prereg.rc_image_digest
        with self.assertRaises(SemanticContinuityError):
            _chain(_prereg(ScenarioId.COMPLIANT_ADMIT), p)

    def test_subject_drift_requires_distinct_seed_image(self) -> None:
        p = _matched_exec(ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE)
        p["seed_trace"]["seed_image_digest"] = _SHA_RUN  # == run image → no drift endpoint
        with self.assertRaises(SemanticContinuityError):
            _chain(_prereg(ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE), p)

    def test_scenario_mismatch_prereg_vs_execution_fails(self) -> None:
        with self.assertRaises(SemanticContinuityError):
            _chain(_prereg(ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE),
                   _matched_exec(ScenarioId.ABA_GENERATION_MOVED))


if __name__ == "__main__":
    unittest.main()
