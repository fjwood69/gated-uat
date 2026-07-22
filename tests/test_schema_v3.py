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

from conftest import build_receipt_unchecked  # a signed receipt over a schema-invalid payload
from orchestrator.evidence import (
    ChainVerificationError,
    SemanticContinuityError,
    VerifiedChain,
    build_execution_receipt,
    build_index,
    build_receipt,
    build_teardown_receipt,
    validate_semantic_continuity,
    verify_integrity,
)
from orchestrator.expectations import (
    INJECTION_CLASS,
    InjectionClass,
    ScenarioId,
    assert_inducible,
    expected_for,
    injection_class_for,
)
from orchestrator.schemas import (
    SchemaCoherenceError,
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
    # slice 2.2a — post-run admission-currency refusals (all blocking_refusal).
    ScenarioId.SET_HEAD_STALE: "blocking_refusal",
    ScenarioId.ORACLE_UNAVAILABLE: "blocking_refusal",
    ScenarioId.LIVE_ATTESTATION_UNAVAILABLE: "blocking_refusal",
    # slice 2.2b — live-authorization rebind refusals (all blocking_refusal).
    ScenarioId.AUTHORIZED_SET_MOVED: "blocking_refusal",
    ScenarioId.AUTHORIZED_SUBJECT_MOVED: "blocking_refusal",
}

# scenarios whose fault_injection is the BASE triple (tamper + the three 2.2a currency injections).
_BASE_TRIPLE_FAULT = frozenset({
    ScenarioId.SHA_TAMPER, ScenarioId.SET_HEAD_STALE,
    ScenarioId.ORACLE_UNAVAILABLE, ScenarioId.LIVE_ATTESTATION_UNAVAILABLE,
    ScenarioId.AUTHORIZED_SET_MOVED, ScenarioId.AUTHORIZED_SUBJECT_MOVED,
})


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
          result_sub_reason: str = "", gate_outcome: Any = "<auto>",
          plan: Any = "<auto>") -> dict[str, Any]:
    """An execution payload for ANY (scenario, observed_kind) cell — matched or refuting.

    ``result_sub_reason`` is the OBSERVED forensic sub-token (default ""): load-bearing for the
    2.2a currency refusals whose admissibility forks on it (store_unreachable vs the None-return
    'unresolved'; attestation_absent). A matched cell must carry the AUTHORED sub_reason or the
    observed triple will not equal the preregistered expected triple (fail-closed non-admission)."""
    if gate_outcome == "<auto>":
        gate_outcome = _gate_outcome_for(observed_kind)
    if plan == "<auto>":
        plan = None if observed_kind == "non_run" else _POLICY
    p: dict[str, Any] = {
        "schema_version": 3, "profile": "p1", "gated_commit": "1d75d54", "outcome": outcome,
        "executed_at": _ISO, "canonical_digest_alg": "sha256", "canonical_digest_version": 1,
        "prereg_digest": _HEX,  # placeholder; build_execution_receipt overwrites it
        "scenario": scenario.value, "configured_policy_id": _POLICY, "event_digest": _HEX,
        "result_kind": observed_kind, "result_reason": result_reason,
        "result_sub_reason": result_sub_reason,
        "gate_outcome": gate_outcome, "plan_policy_id": plan, "seed_trace": _seed_trace(scenario),
    }
    # CONFIGURED / FAULT-INJECTION by scenario (what the harness did).
    if scenario is ScenarioId.ABA_GENERATION_MOVED:
        p["fault_injection"] = _aba_fault_injection()
    elif scenario in _BASE_TRIPLE_FAULT:
        p["fault_injection"] = _tamper_fault_injection()  # the base triple
    elif scenario is ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE:
        p["drift_image_digest"] = _SHA_RUN
    # OBSERVED by kind (what the SUT produced).
    if observed_kind == "admitted_run":
        p.update(_admitted_coords())
    return p


def _matched_exec(scenario: ScenarioId) -> dict[str, Any]:
    """The happy/matched execution for *scenario* (observed == expected) — built from the AUTHORED
    triple (kind + reason + sub_reason) so the observed triple equals the preregistered prediction
    exactly, including the load-bearing 2.2a sub_reasons. No hand-duplicated expectation."""
    exp = expected_for(scenario)
    if exp.kind == "admitted_run":  # an admitted run's observed reason is its OUTCOME (Q2), not exp
        return _exec(scenario, exp.kind, result_reason="all_retried",
                     result_sub_reason=exp.sub_reason, outcome="pass")
    return _exec(scenario, exp.kind, result_reason=exp.reason,
                 result_sub_reason=exp.sub_reason, outcome="error")


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
                    # non_run's reason must be a disposition token (coherent with its gate_outcome).
                    reason = "block_action_required" if kind == "non_run" else "tok"
                    validate_execution_payload_v3(
                        _exec(scenario, kind, result_reason=reason, outcome=outcome))

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


class KeyOmissionTests(unittest.TestCase):
    """UAT-1: a v3 MATRIX cell's key set is EXACT — every key is required-PRESENT. Omitting
    plan_policy_id or gate_outcome must be REJECTED. Previously a MISSING plan_policy_id passed for
    admitted/refusal/infra rows because ``payload.get(..., '<absent>')`` yielded a truthy string;
    continuity then read None and SKIPPED the plan==configured comparison — silently disabling the
    guarantee that the executed plan matched the configured policy. Omission negatives across EVERY
    result kind (via the per-scenario matched cells, which span admitted/non_run/refusal/infra)."""

    def test_omitted_plan_policy_id_rejected_across_every_kind(self) -> None:
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario, kind=_EXPECTED_KIND[scenario]):
                p = _matched_exec(scenario)
                del p["plan_policy_id"]  # even the non_run's explicit null must be PRESENT
                with self.assertRaises(SchemaViolationError):
                    validate_execution_payload_v3(p)

    def test_omitted_gate_outcome_rejected_across_every_kind(self) -> None:
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario, kind=_EXPECTED_KIND[scenario]):
                p = _matched_exec(scenario)
                del p["gate_outcome"]  # even infra's explicit null must be PRESENT
                with self.assertRaises(SchemaViolationError):
                    validate_execution_payload_v3(p)

    def test_signed_receipt_omitting_plan_policy_id_fails_verify_integrity(self) -> None:
        # The finding's EXACT threat: a faulty trusted producer SIGNS an execution receipt that
        # OMITS plan_policy_id (crypto-valid, schema-invalid). The signature stops an external
        # editor; it is the harness's OWN verify_integrity that must reject a PROHIBITED OMISSION at
        # schema validation — not accept it and let continuity skip. (build_execution_receipt now
        # rejects it at BUILD too; build_receipt_unchecked bypasses that to hit the verify gate.)
        sk = SigningKey.generate()
        rid = "22222222-2222-4222-8222-222222222222"
        prereg = build_receipt("prereg", rid, _prereg(ScenarioId.COMPLIANT_ADMIT), sk)
        exec_payload = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        del exec_payload["plan_policy_id"]
        exec_payload["prereg_digest"] = prereg.digest  # the binding build_execution_receipt injects
        execution = build_receipt_unchecked("execution", rid, exec_payload, sk)
        teardown = build_teardown_receipt(execution, {
            "schema_version": 3, "profile": "p1", "failure": False,
            "torn_down_at": _ISO, "runtime_pack_digest": _HEX}, sk)
        index = build_index(rid, prereg, execution, teardown, sk, sk.verify_key.encode().hex())
        with self.assertRaises(ChainVerificationError) as cm:
            verify_integrity(prereg, execution, teardown, index, sk.verify_key)
        self.assertIn("schema violation", str(cm.exception).lower())


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


class GateOutcomeCoherenceTests(unittest.TestCase):
    """gate_outcome must be COHERENT with (result_kind, result_reason) — the sealed account()
    pairing. A redundant field that can contradict the disposition it duplicates is the QM-2
    silent fall-open."""

    def test_degraded_block_paired_with_neutral_gate_is_rejected(self) -> None:
        # THE fall-open the re-validation caught: a block disposition wearing a neutral gate. Kind +
        # reason match the degraded expectation, so admissibility would pass — but no honest mapper
        # produces block_action_required + neutral_gate, so integrity rejects it.
        p = _exec(ScenarioId.NON_ENABLED_DEGRADED, "non_run", outcome="error",
                  result_reason="block_action_required", gate_outcome="neutral_gate")
        with self.assertRaises(SchemaCoherenceError):
            validate_execution_payload_v3(p)

    def test_neutral_disposition_paired_with_block_gate_is_rejected(self) -> None:
        p = _exec(ScenarioId.NON_ENABLED_DEGRADED, "non_run", result_reason="skip_neutral",
                  outcome="error", gate_outcome="block_gate")
        with self.assertRaises(SchemaCoherenceError):
            validate_execution_payload_v3(p)

    def test_admitted_run_requires_run_verdict(self) -> None:
        p = _exec(ScenarioId.COMPLIANT_ADMIT, "admitted_run", result_reason="all_retried",
                  outcome="pass", gate_outcome="block_gate")
        with self.assertRaises(SchemaCoherenceError):
            validate_execution_payload_v3(p)

    def test_blocking_refusal_gate_is_run_verdict_per_sealed_account(self) -> None:
        # gated's account() maps BlockingRefusal -> RUN_VERDICT (job_result.py:152); block_gate here
        # would reject the real map_job_result output, so run_verdict is the coherent value.
        p = _exec(ScenarioId.ABA_GENERATION_MOVED, "blocking_refusal", outcome="error",
                  result_reason="policy_generation_moved", gate_outcome="block_gate")
        with self.assertRaises(SchemaCoherenceError):
            validate_execution_payload_v3(p)

    def test_non_run_reason_must_be_a_disposition_token(self) -> None:
        p = _exec(ScenarioId.NON_ENABLED_DEGRADED, "non_run", result_reason="not_a_disposition",
                  outcome="error", gate_outcome="block_gate")
        with self.assertRaises(SchemaCoherenceError):
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
        # Every NON-infra scenario, incl. the three 2.2a currency refusals — the FAST tier must
        # independently prove the load-bearing sub_reasons (store_unreachable / attestation_absent)
        # admit only when the observed triple matches the signed prereg (previously podman-only).
        for scenario in (ScenarioId.COMPLIANT_ADMIT, ScenarioId.NON_ENABLED_DEGRADED,
                         ScenarioId.ABA_GENERATION_MOVED, ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE,
                         ScenarioId.SET_HEAD_STALE, ScenarioId.ORACLE_UNAVAILABLE,
                         ScenarioId.LIVE_ATTESTATION_UNAVAILABLE,
                         ScenarioId.AUTHORIZED_SET_MOVED, ScenarioId.AUTHORIZED_SUBJECT_MOVED):
            with self.subTest(scenario=scenario):
                self.assertTrue(_chain(_prereg(scenario), _matched_exec(scenario)).is_admitted)

    def test_currency_sub_reason_is_load_bearing_for_admission(self) -> None:
        # The CONVERSE of the matched-admits proof: an execution matching the currency refusal in
        # kind AND reason but carrying the WRONG (empty) sub_reason must NOT admit — proving the
        # sub_reason fork (store_unreachable / attestation_absent) is COMPARED, not decorative. This
        # is what makes admitting the matched cell meaningful (fast tier, no podman).
        for scenario in (ScenarioId.ORACLE_UNAVAILABLE, ScenarioId.LIVE_ATTESTATION_UNAVAILABLE):
            with self.subTest(scenario=scenario):
                self.assertTrue(
                    expected_for(scenario).sub_reason, "scenario must fork on sub_reason")
                wrong = _exec(scenario, "blocking_refusal",
                              result_reason=expected_for(scenario).reason,
                              result_sub_reason="", outcome="error")  # empty != authored sub_reason
                self.assertFalse(
                    _chain(_prereg(scenario), wrong).is_admitted,
                    "an empty sub_reason must refuse a currency refusal whose prereg forks on it")

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

    def test_missing_plan_policy_id_fails_closed(self) -> None:
        # UAT-1 belt: a v3 execution with the plan_policy_id KEY absent (a future schema regression)
        # must fail continuity CLOSED — not silently .get→None and skip the plan-binding comparison
        # (the exact bug UAT-1 closed at the schema layer; defence in depth at continuity).
        # build_receipt_unchecked bypasses the schema (which independently rejects the omission) so
        # the continuity gate is exercised directly.
        sk = SigningKey.generate()
        xp = _matched_exec(ScenarioId.COMPLIANT_ADMIT)
        del xp["plan_policy_id"]
        prereg = build_receipt(
            "prereg", "11111111-1111-4111-8111-111111111111",
            _prereg(ScenarioId.COMPLIANT_ADMIT), sk)
        execution = build_receipt_unchecked(
            "execution", prereg.run_id, {**xp, "prereg_digest": prereg.digest}, sk)
        teardown = build_teardown_receipt(
            execution, {"schema_version": 3, "profile": "p1", "failure": False,
                        "torn_down_at": _ISO, "runtime_pack_digest": _HEX}, sk)
        with self.assertRaises(SemanticContinuityError):
            validate_semantic_continuity(prereg, execution, teardown)


class TaxonomyTests(unittest.TestCase):
    """slice 2.2: the injection taxonomy is an ENFORCEABLE invariant, not a slogan. Every ScenarioId
    declares a non-FABRICATION class, and the guard rejects a FABRICATION-classed scenario."""

    def test_every_scenario_is_classified_and_inducible(self) -> None:
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario):
                # completeness: every id is in the table (KeyError otherwise) ...
                cls = injection_class_for(scenario)
                # ... and none is FABRICATION — the harness only drives gated's REAL path.
                self.assertIsNot(cls, InjectionClass.FABRICATION)
                assert_inducible(scenario)  # does not raise

    def test_assert_inducible_rejects_a_fabrication_classed_scenario(self) -> None:
        # the guard has TEETH: temporarily reclassify a scenario as FABRICATION and confirm the
        # loader refuses to run it (no FABRICATION ScenarioId exists, so this proves the check).
        victim = ScenarioId.COMPLIANT_ADMIT
        original = INJECTION_CLASS[victim]
        INJECTION_CLASS[victim] = InjectionClass.FABRICATION
        try:
            with self.assertRaises(ValueError):
                assert_inducible(victim)
        finally:
            INJECTION_CLASS[victim] = original


if __name__ == "__main__":
    unittest.main()
