"""tests/test_enforcement_negatives.py — Phase 2 slice 2.1c: the live-enforcement REFUSAL matrix.

Each negative drives gated's REAL ``make_gated_job_runner`` (the same path 2.1b's adapter wires)
and asserts the fail-closed outcome ``map_job_result`` projects. The refusals are induced by REAL
state / REAL sequenced writes / a REAL second image — never a fabricated JobResult or a short read:

  (b) a non-ENABLED policy               -> NonRunDecision (engine NEVER runs)
  (e) a mis-routed WELL-FORMED plan      -> GateDecisionError (dispatch-time policy_id recheck)
  (c) a below-seam cross-store ABA       -> BlockingRefusal(POLICY_GENERATION_MOVED)
  (d) enforcement on a SECOND image      -> BlockingRefusal(SUBJECT_DRIFT)
  (f) a SHA-bind artifact tamper (TOCTOU) -> InfrastructureFailure(ARTIFACT_INTEGRITY_MISMATCH)

(b)+(e) need no engine (the refusal precedes the sandbox); (c)/(d)/(f) are podman-gated and seed a
real ENABLED policy first. Constructing the runner directly (rather than through the evidence-chain
adapter) tests gated's enforcement mechanism BELOW the 2.1b seam; the wiring-pin test in
test_enforcement_evidence keeps that direct wiring aligned with production.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from core import ResourceBudget
from core.calibration import Fixture, FixtureLabel
from gate.calibration_store import CalibrationStore
from gate.policy_store import PolicyStore
from gate.queue import GatingEvent

from orchestrator.enforcement_driver import (
    SeedProvenance,
    map_job_result,
    seed_enabled_policy,
)
from orchestrator.gated_pin import ACCEPTED_RETRYCHECK_PROFILE_DIGEST

_IMAGE_REF = "localhost/mori:local"
_IMAGE_REF_2 = "localhost/mori-uat:local"  # a DISTINCT image → a distinct execution identity
_CORPUS = Path(__file__).resolve().parent.parent / "corpora" / "fixtures"


def _podman_image_available(image_ref: str) -> bool:
    if not shutil.which("podman"):
        return False
    return subprocess.run(
        ["podman", "image", "exists", image_ref], capture_output=True
    ).returncode == 0


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


def _seed_enabled(tmp: Path, image_ref: str = _IMAGE_REF, policy_id: str = "uat-neg") -> tuple[
    PolicyStore, CalibrationStore, SeedProvenance
]:
    ps = PolicyStore(tmp / "p.db")
    cs = CalibrationStore(tmp / "c.db")
    good = (Fixture(
        fixture_id="good", label=FixtureLabel.KNOWN_GOOD,
        payload=(_CORPUS / "retry-good-v1" / "main.py").read_bytes(), evasion_class=None),)
    bad = (Fixture(
        fixture_id="bad", label=FixtureLabel.KNOWN_BAD,
        payload=(_CORPUS / "retry-swallow-v1" / "main.py").read_bytes(),
        evasion_class="exception-swallowing"),)
    prov = seed_enabled_policy(
        policy_store=ps, calibration_store=cs, policy_id=policy_id, detector_id="RetryCheck",
        image_ref=image_ref, known_good=good, known_bad=bad,
        budget=ResourceBudget(wall_clock_seconds=120.0), trials=1)
    return ps, cs, prov


def _wire_runner(
    ps: PolicyStore, cs: CalibrationStore, policy_id: str, detector_id: str, image_ref: str,
    *, governance: Any = None, artifact_source: Any = None,
) -> Any:
    """Wire make_gated_job_runner EXACTLY as live_app.build()/the 2.1b adapter do (replica
    resolve_disposition closure, snapshot=None), allowing a governance / artifact override."""
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

    gov = governance if governance is not None else _ProductionAdmissionGovernanceView(ps, cs)
    src = artifact_source if artifact_source is not None else _good_source
    registry = default_detector_registry(
        detector_id=detector_id, entrypoint=DEFAULT_ENTRYPOINT,
        accepted_profile_digest=ACCEPTED_RETRYCHECK_PROFILE_DIGEST)
    return make_gated_job_runner(
        resolve_decision, src, policy_id=policy_id, governance=gov, image=image_ref,
        resolve=registry.resolve_bundle, detector_id=detector_id, trials=1, first_fail=True)


# =====================================================================================
# (b) + (e): engine-free refusals (no podman) — the refusal precedes the sandbox.
# =====================================================================================


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
        # a not-yet-enforceable policy is a NEUTRAL non-run (SKIP_NEUTRAL) — the engine did not run.
        # (A DEGRADED policy — was-ENABLED, lost attestation — instead BLOCKs; that fail-closed edge
        # is gated's disposition-map guarantee, exercised by the ABA test below reaching DEGRADED.)
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


# =====================================================================================
# (c) + (d) + (f): podman-gated refusals — each seeds a REAL ENABLED policy first.
# =====================================================================================


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class CrossStoreAbaTests(unittest.TestCase):
    def test_below_seam_generation_move_is_refused_policy_generation_moved(self) -> None:
        # (c): a REAL cross-store ABA. A governance wrapper does the LIVE reads for real, then —
        # after current_attestation captured the bound generation and inside oracle_head_for (which
        # runs BEFORE the generation re-read) — commits a REAL ENABLED->DEGRADED transition that
        # MOVES the policy's monotonic generation. set_head is untouched (a policy-tier move, not a
        # fixture append), so the ABA bracket, not SET_HEAD_STALE, must catch it. admit_run_result's
        # post-oracle generation re-read then differs from the bound one -> POLICY_GENERATION_MOVED.
        from gate.authority import GovernanceApproval
        from gate.live_app import _ProductionAdmissionGovernanceView
        from gate.policy_state import PolicyState

        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-neg-c-"))
        ps, cs, prov = _seed_enabled(tmp)

        # A DELEGATING wrapper (composition, not subclassing) around the REAL production view: it
        # forwards every read to the real view unchanged, and — once, inside oracle_head_for (which
        # admit_run_result calls between capturing the bound generation and re-reading it) — commits
        # a REAL generation-moving transition. The reads it exposes are the real ones; only the
        # timing of a genuine write is injected.
        class _AbaGovernance:
            def __init__(self, inner: Any) -> None:
                self._inner = inner
                self._fired = False

            def current_attestation(self, policy_id: str) -> Any:
                return self._inner.current_attestation(policy_id)

            def oracle_head_for(self, set_id: str) -> Any:
                head = self._inner.oracle_head_for(set_id)
                if not self._fired:
                    self._fired = True
                    # a REAL write, sequenced through the real read path (never fabricated).
                    ps.transition(
                        prov.policy_id, PolicyState.DEGRADED,
                        approval=GovernanceApproval(
                            principals=("op",), purpose="uat-aba",
                            rationale="move the policy generation mid-admission",
                            operation_id="uat-aba-degrade"))
                return head

            def current_generation(self, policy_id: str) -> Any:
                return self._inner.current_generation(policy_id)

        governance = _AbaGovernance(_ProductionAdmissionGovernanceView(ps, cs))
        runner = _wire_runner(
            ps, cs, prov.policy_id, prov.detector_id, _IMAGE_REF, governance=governance)
        outcome = map_job_result(runner(_event()))

        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "policy_generation_moved")


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF) and _podman_image_available(_IMAGE_REF_2),
    f"{_IMAGE_REF} + {_IMAGE_REF_2} both required in the Podman image store",
)
class SubjectDriftTests(unittest.TestCase):
    def test_enforcement_on_a_second_image_is_refused_subject_drift(self) -> None:
        # (d): the artifact tree is SHA-bind-protected, so drift must be induced via the IMAGE
        # coordinate. Calibrate the policy on _IMAGE_REF, then enforce on a DISTINCT image
        # (_IMAGE_REF_2): the measured execution identity differs from the calibrated subject, so
        # the measured composite != plan.target_subject -> admit_run_result refuses (SUBJECT_DRIFT).
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-neg-d-"))
        ps, cs, prov = _seed_enabled(tmp, image_ref=_IMAGE_REF)

        runner = _wire_runner(ps, cs, prov.policy_id, prov.detector_id, _IMAGE_REF_2)
        outcome = map_job_result(runner(_event()))

        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "subject_drift")


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class ArtifactTamperTests(unittest.TestCase):
    def test_sha_bind_tamper_is_an_infrastructure_failure(self) -> None:
        # (f): a TOCTOU tamper — the artifact_source stages the tree, binds its tree_hash, then
        # MUTATES a file AFTER hashing. The sandbox re-verifies the SHA-bind in prepare() and raises
        # ArtifactHashMismatchError, which the runner maps to a blocking InfrastructureFailure —
        # never a silent pass on altered bytes.
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-neg-f-"))
        ps, cs, prov = _seed_enabled(tmp)

        def _tampering_source(event: Any, ws: Path) -> Any:
            from gate.artifact import build_artifact_spec
            dest = ws / "src"
            shutil.copytree(_CORPUS / "retry-good-v1", dest)
            spec = build_artifact_spec(dest)  # binds the CLEAN tree hash
            (dest / "main.py").write_text("# tampered after the tree hash was bound\n")
            return spec

        runner = _wire_runner(
            ps, cs, prov.policy_id, prov.detector_id, _IMAGE_REF, artifact_source=_tampering_source)
        outcome = map_job_result(runner(_event()))

        self.assertEqual(outcome.result_kind, "infrastructure_failure")
        self.assertEqual(outcome.reason, "artifact_integrity_mismatch")


if __name__ == "__main__":
    unittest.main()
