"""tests/test_enforcement_negatives.py — the below-seam refusal mechanism (slice 2.1).

Two refusals that produce NO signed evidence chain (so they live here, not in the matrix evidence
suite) — each drives gated's REAL ``make_gated_job_runner`` directly, BELOW the 2.1b adapter seam:

  (b) a never-ENABLED (PENDING) policy   -> NonRunDecision(SKIP_NEUTRAL) — engine NEVER runs
  (e) a mis-routed WELL-FORMED plan      -> GateDecisionError (dispatch-time policy_id recheck)

These are engine-free: the refusal precedes the sandbox, so no podman is needed. (b) is the
NEUTRAL-tautology CONTRAST to the through-``enforce`` NON_ENABLED_DEGRADED scenario — a
never-enabled policy legitimately neutrals (it never controlled anything), which is why the DEGRADED
scenario, not this one, carries the "a revoked control keeps controlling" invariant. (e) produces no
JobResult at all (the plan is mis-routed before any run), so per the Q3 ruling it is a plain
``assertRaises`` — never a signed "raise record".

The through-``enforce`` matrix scenarios (COMPLIANT_ADMIT, ABA_GENERATION_MOVED,
NON_ENABLED_DEGRADED, SUBJECT_DRIFT_SECOND_IMAGE, SHA_TAMPER) — which DO emit signed chains judged
by admissibility — live in ``test_enforcement_evidence``. The ABA there is a REAL store-layer
injection (``_aba_scheduler``), superseding this file's former governance-wrapper ABA.
"""

from __future__ import annotations

import shutil
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from gate.calibration_store import CalibrationStore
from gate.policy_store import PolicyStore
from gate.queue import GatingEvent

from orchestrator.enforcement_driver import map_job_result
from orchestrator.gated_pin import ACCEPTED_RETRYCHECK_PROFILE_DIGEST

_IMAGE_REF = "localhost/mori:local"
_CORPUS = Path(__file__).resolve().parent.parent / "corpora" / "fixtures"


def _event() -> GatingEvent:
    return GatingEvent(
        delivery_id="uat-neg", repo_full_name="gated-uat/enforce", head_sha="a" * 40,
        action="synchronize", installation_id=1)


def _raising_source(event: Any, ws: Path) -> Any:
    raise AssertionError("artifact_source must NOT be called — the engine must never run here")


def _good_source(event: Any, ws: Path) -> Any:
    from gate.artifact import build_artifact_spec
    dest = ws / "src"
    shutil.copytree(_CORPUS / "retry-good-v1", dest)
    return build_artifact_spec(dest)


def _wire_runner(
    ps: PolicyStore, cs: CalibrationStore, policy_id: str, detector_id: str, image_ref: str,
    *, artifact_source: Any = None,
) -> Any:
    """Wire make_gated_job_runner EXACTLY as live_app.build()/the 2.1b adapter do (replica
    resolve_disposition closure, snapshot=None)."""
    from gate.gatekeeper import resolve_disposition
    from gate.live_app import _ProductionAdmissionGovernanceView
    from gate.pipeline import (
        DEFAULT_ENTRYPOINT,
        default_detector_registry,
        make_gated_job_runner,
    )

    def resolve_decision(event: Any) -> Any:
        return resolve_disposition(
            policy_id, store=ps, snapshot=None, snapshot_key=b"",
            now=time.time(), oracle_head_for=cs.set_head)

    src = artifact_source if artifact_source is not None else _good_source
    registry = default_detector_registry(
        detector_id=detector_id, entrypoint=DEFAULT_ENTRYPOINT,
        accepted_profile_digest=ACCEPTED_RETRYCHECK_PROFILE_DIGEST)
    return make_gated_job_runner(
        resolve_decision, src, policy_id=policy_id,
        governance=_ProductionAdmissionGovernanceView(ps, cs), image=image_ref,
        resolve=registry.resolve_bundle, detector_id=detector_id, trials=1, first_fail=True)


class NonEnforceablePolicyTests(unittest.TestCase):
    def test_non_enabled_policy_is_a_nonrun_decision_and_never_runs_the_engine(self) -> None:
        # (b): a policy that is NOT ENABLED (here PENDING_CALIBRATION — reached via the real
        # transition, no calibration) resolves to a non-RUN_ENFORCING disposition, so the runner
        # returns a typed NonRunDecision and the artifact_source (engine path) is NEVER reached.
        from gate.authority import GovernanceApproval
        from gate.policy_state import Disposition, PolicyState

        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-neg-b-"))
        ps = PolicyStore(tmp / "p.db")
        cs = CalibrationStore(tmp / "c.db")
        ps.transition(
            "uat-neg", PolicyState.PENDING_CALIBRATION,
            approval=GovernanceApproval(
                principals=("op",), purpose="uat-neg", rationale="stage a non-enabled policy",
                operation_id="uat-neg-pending"))

        runner = _wire_runner(
            ps, cs, "uat-neg", "RetryCheck", _IMAGE_REF, artifact_source=_raising_source)
        outcome = map_job_result(runner(_event()))

        self.assertEqual(outcome.result_kind, "non_run")
        # a never-enabled policy is a NEUTRAL non-run (SKIP_NEUTRAL) — the tautology contrast to the
        # DEGRADED (was-ENABLED) scenario, which BLOCKs. The engine did not run either way.
        self.assertEqual(outcome.reason, Disposition.SKIP_NEUTRAL.value)
        self.assertEqual(outcome.gate_outcome, "neutral_gate")


class MisRoutedPlanTests(unittest.TestCase):
    def test_wellformed_plan_for_another_policy_raises_gate_decision_error(self) -> None:
        # (e): a WELL-FORMED RUN_ENFORCING decision (a valid AuthorizedRunPlan — NOT a broken
        # biconditional; that stays a gated unit test) carrying a plan for policy-A reaches a runner
        # configured for policy-B. The dispatch-time policy_id recheck RAISES GateDecisionError
        # BEFORE the engine — the adapter must not invent an infra mapping for a mis-route.
        from gate.attestation import IDENTITY_CONTRACT_VERSION
        from gate.gatekeeper import GateDecision, GateDecisionError
        from gate.live_app import _ProductionAdmissionGovernanceView
        from gate.pipeline import (
            DEFAULT_ENTRYPOINT,
            default_detector_registry,
            make_gated_job_runner,
        )
        from gate.policy_state import Disposition, PolicyState
        from gate.run_admission import AuthorizedRunPlan

        plan_for_a = AuthorizedRunPlan(
            "policy-A", target_subject="subj",
            authorized_context=("set", "subj", IDENTITY_CONTRACT_VERSION))
        decision = GateDecision(
            Disposition.RUN_ENFORCING, PolicyState.ENABLED, "test mis-route", "live",
            plan=plan_for_a)

        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-neg-e-"))
        ps = PolicyStore(tmp / "p.db")
        cs = CalibrationStore(tmp / "c.db")
        registry = default_detector_registry(
            detector_id="RetryCheck", entrypoint=DEFAULT_ENTRYPOINT,
            accepted_profile_digest=ACCEPTED_RETRYCHECK_PROFILE_DIGEST)
        runner = make_gated_job_runner(
            lambda event: decision, _raising_source, policy_id="policy-B",
            governance=_ProductionAdmissionGovernanceView(ps, cs), image=_IMAGE_REF,
            resolve=registry.resolve_bundle, detector_id="RetryCheck", trials=1)

        with self.assertRaises(GateDecisionError):
            runner(_event())


if __name__ == "__main__":
    unittest.main()
