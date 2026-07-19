"""tests/_recal_schedulers.py — TEST-ONLY live-AUTHORIZATION rebind schedulers (slice 2.2b).

Two post-mint refusals, each induced by running gated's REAL PUBLIC operator RECALIBRATION LOOP
between plan-mint and admit — NOT a store-row fabrication and NOT a read-wrapper. The loop is the
legal edge sequence ENABLED -> ADVISORY -> PENDING_CALIBRATION -> CALIBRATING -> ENABLED, driven
ENTIRELY through gated's own governance APIs (``transition`` + ``run_calibration`` + ratify_enable):

  AUTHORIZED_SET_MOVED (Class A / store mutation): recalibrate the policy onto a DISTINCT second set
    (its own fixtures, appended via the store's admission primitive), so the live ENABLED
    attestation binds ``set2``. admit reads ``plan.authorized_set (set1) != live_set_id`` -> refuses
    check #3 (before set_head / subject / generation).

  AUTHORIZED_SUBJECT_MOVED (Class A / store mutation): recalibrate the policy on the SAME set but a
    SECOND IMAGE. Same fixtures => identical ``set_id`` + ``set_head`` (a sorted-membership digest,
    image-independent); a different image => a different measured ``execution_identity`` => a
    different calibrated SUBJECT, while profile/trust/guard (policy-derived) are unchanged so
    ``run_calibration``'s witness self-consistency check PASSES. admit reads set match + head match
    but ``plan.target_subject (subj1) != live_subject (subj2)`` -> refuses at #5 (not preempted).

The scheduler is a SINGLE-SHOT state machine (DISARMED -> FIRING -> COMPLETED | FAILED). Its
``artifact_source`` stages the compliant candidate tree AND — when armed — runs the whole loop,
committing the final ENABLED-on-new row BEFORE returning (so admit's single read never observes the
transient ADVISORY/CALIBRATING states — build pin #2). ``require_completed_disclosure`` returns the
induction record ONLY in COMPLETED; a half-done rebind leaves FAILED and raises, so ``enforce``
aborts evidence rather than serialising over a partial governance move. Unarmed, ``artifact_source``
stages only (the FULL negative control: same machinery, skip the loop -> admit).
"""

from __future__ import annotations

import shutil
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any

from core import ResourceBudget
from core.calibration import Fixture, FixtureLabel
from engine.retry import RetryCheck
from gate.authority import GovernanceApproval
from gate.backends import guarded_backend
from gate.calibration_store import AdmissionCapability, ChangeOp
from gate.detector_registry import DetectorRegistry
from gate.gatekeeper import ratify_enable, run_calibration
from gate.policy_state import PolicyState
from gate.trust_policy import resolve_trust_policy

from orchestrator.enforcement_driver import EnforcementEvidenceError, SeedProvenance
from orchestrator.gated_pin import ACCEPTED_RETRYCHECK_PROFILE_DIGEST


class _State(Enum):
    DISARMED = "disarmed"
    FIRING = "firing"
    COMPLETED = "completed"
    FAILED = "failed"


def _resolve_image_config_id(image_ref: str) -> str:
    """The immutable OCI image-config id ({{.Id}}) — the coordinate the execution identity binds."""
    r = subprocess.run(
        ["podman", "image", "inspect", "--format", "{{.Id}}", image_ref],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise EnforcementEvidenceError(
            f"recal scheduler could not resolve image config-id for {image_ref!r}: "
            f"{r.stderr.strip()}")
    image_id = str(r.stdout.strip())
    return image_id if image_id.startswith("sha256:") else "sha256:" + image_id


class _RecalScheduler:
    """Drive the REAL public recalibration loop as the injection. Subclasses set the target set +
    the recalibration image (+ optional new-set fixtures)."""

    def __init__(
        self, *, policy_store: Any, calibration_store: Any, seed: SeedProvenance,
        target_set_id: str, recal_image_ref: str, artifact_dir: Path, budget: ResourceBudget,
        new_set_fixtures: tuple[tuple[Fixture, ...], tuple[Fixture, ...]] | None = None,
        armed: bool = True, guard_policy: str = "trusted-backend", trials: int = 1,
    ) -> None:
        self._ps = policy_store
        self._cs = calibration_store
        self._seed = seed
        self._target_set_id = target_set_id
        self._recal_image_ref = recal_image_ref
        self._artifact_dir = artifact_dir
        self._budget = budget
        self._new_set_fixtures = new_set_fixtures  # (known_good, known_bad) for a DISTINCT new set
        self._armed = armed
        self._guard_policy = guard_policy
        self._trials = trials
        self._state = _State.DISARMED
        self._disclosure: dict[str, str] | None = None

    # --- the enforce() seams -------------------------------------------------------------------
    def artifact_source(self, event: Any, workspace: Path) -> Any:
        """Stage the compliant tree; when armed, run the whole recalibration loop and COMMIT it
        before returning (so admit sees only the final ENABLED-on-new row). Runs AFTER plan-mint, so
        the plan was minted against the OLD binding — the interleave that makes the plan stale."""
        from gate.artifact import build_artifact_spec

        dest = workspace / "src"
        shutil.copytree(self._artifact_dir, dest)
        spec = build_artifact_spec(dest)
        if self._armed:
            self._run_loop()  # DISARMED -> FIRING -> COMPLETED | FAILED (commits the rebind)
        return spec

    def require_completed_disclosure(self) -> dict[str, str]:
        if self._state is not _State.COMPLETED or self._disclosure is None:
            raise EnforcementEvidenceError(
                f"recal disclosure demanded but the loop is {self._state.value} (not COMPLETED) — "
                "refusing to serialise over a partial governance rebind")
        return dict(self._disclosure)

    # --- the real recalibration loop -----------------------------------------------------------
    def _appr(self, op: str) -> GovernanceApproval:
        # operator role: two DISTINCT principals — satisfies both the dual-principal demote
        # (ENABLED->ADVISORY, build pin #2) and every single-principal edge in the loop.
        return GovernanceApproval(
            principals=("uat-recal-1", "uat-recal-2"), purpose="uat-authz-rebind",
            rationale="publicly recalibrate an ENABLED policy onto a new authorized binding",
            operation_id=op)

    def _populate_new_set(self, set_id: str) -> None:
        """Append a DISTINCT new set's fixtures via the store's admission primitive (Scenario A)."""
        if self._new_set_fixtures is None:
            return
        good, bad = self._new_set_fixtures
        admit = AdmissionCapability()
        for fx in bad:
            self._cs.append(
                ChangeOp.ADD_KNOWN_BAD, admission=admit,
                approval=self._appr(f"set2-{fx.fixture_id}"), fixture_id=fx.fixture_id,
                set_id=set_id, label=FixtureLabel.KNOWN_BAD, payload=fx.payload,
                evasion_class=fx.evasion_class)
        for fx in good:
            self._cs.append(
                ChangeOp.ADD_KNOWN_GOOD, admission=admit,
                approval=self._appr(f"set2-{fx.fixture_id}"), fixture_id=fx.fixture_id,
                set_id=set_id, label=FixtureLabel.KNOWN_GOOD, payload=fx.payload,
                evasion_class=fx.evasion_class)

    def _run_loop(self) -> None:
        if self._state is not _State.DISARMED:
            raise EnforcementEvidenceError(
                f"recal scheduler cannot fire from {self._state.value} — single-shot violated")
        self._state = _State.FIRING
        try:
            pid = self._seed.policy_id
            detector_id = self._seed.detector_id
            set_id = self._target_set_id
            self._populate_new_set(set_id)

            # the real detector + guarded backend on the RECAL image (img2 for a subject move).
            registry = DetectorRegistry()
            retry_entry = ("python3", "/artifact/main.py")
            registry.register(
                detector_id, lambda: RetryCheck(retry_entry),
                accepted_profile_digest=ACCEPTED_RETRYCHECK_PROFILE_DIGEST)
            recal_image_id = _resolve_image_config_id(self._recal_image_ref)
            make_sb, backend_guard = guarded_backend(
                "observed", recal_image_id, guard_policy=self._guard_policy)
            trust_policy = resolve_trust_policy("trust-policy:completed-only")

            # the LEGAL public loop: ENABLED -> ADVISORY -> PENDING_CALIBRATION -> (run_calibration
            # enters CALIBRATING, seals+measures+persists a pass) -> ratify_enable -> ENABLED-new.
            self._ps.transition(pid, PolicyState.ADVISORY, approval=self._appr("demote"))
            self._ps.transition(
                pid, PolicyState.PENDING_CALIBRATION, approval=self._appr("pending"))
            outcome = run_calibration(
                pid, store=self._ps, calibration_store=self._cs, make_sandbox=make_sb,
                detector_id=detector_id, resolve=registry.resolve_bundle, budget=self._budget,
                approval=self._appr("recalibrate"), set_id=set_id, trials=self._trials,
                backend_guard=backend_guard, trust_policy=trust_policy)
            if not outcome.passed or outcome.calibration_result_ref is None:
                raise EnforcementEvidenceError(
                    f"recalibration did not PASS onto set {set_id!r} "
                    f"(breaking={outcome.breaking_fixtures}) — cannot induce a rebind from a "
                    "non-passing run")
            pinned = self._cs.set_head(set_id)
            ratify_enable(
                pid, store=self._ps, approval=self._appr("re-enable"),
                calibration_result_ref=outcome.calibration_result_ref, pinned_set_version=pinned)

            # the rebind MUST have committed to a fresh ENABLED-on-new row (build pin #2: never leak
            # a non-ENABLED state into admit). Read it back and assert the move actually took.
            att = self._ps.current_attestation(pid)
            if att is None:
                raise EnforcementEvidenceError(
                    f"policy {pid!r} is not ENABLED after the recalibration loop — the rebind did "
                    "not commit (a non-ENABLED leak would refuse LIVE_ATTESTATION_UNAVAILABLE)")
            live_set_id, live_head, live_subject = att
            self._assert_moved(live_set_id, live_head, live_subject)
            self._disclosure = self._build_disclosure(live_set_id, live_head, live_subject)
            self._state = _State.COMPLETED
        except Exception:
            self._state = _State.FAILED
            raise

    # --- subclass hooks ------------------------------------------------------------------------
    def _assert_moved(self, live_set_id: str, live_head: str, live_subject: str) -> None:
        raise NotImplementedError

    def _build_disclosure(
        self, live_set_id: str, live_head: str, live_subject: str) -> dict[str, str]:
        raise NotImplementedError


class SetMovedRecalScheduler(_RecalScheduler):
    """AUTHORIZED_SET_MOVED: recalibrate onto a DISTINCT second set → live_set_id != authorized."""

    def _assert_moved(self, live_set_id: str, live_head: str, live_subject: str) -> None:
        if live_set_id == self._seed.set_id:
            raise EnforcementEvidenceError(
                f"recalibration did not MOVE the set (live {live_set_id!r} == seed "
                f"{self._seed.set_id!r}) — no set drift to refuse")

    def _build_disclosure(
        self, live_set_id: str, live_head: str, live_subject: str) -> dict[str, str]:
        return {
            "locus": "admit_run_result.current_attestation(set_id)",
            "mechanism": "REAL public recalibration loop (ENABLED->ADVISORY->PENDING_CALIBRATION->"
                         f"CALIBRATING->ENABLED) onto a DISTINCT set {live_set_id!r} != the plan's "
                         f"authorized set {self._seed.set_id!r}",
            "interleaving_point":
                "between plan-mint and the live attestation read (in artifact_source)"}


class SubjectMovedRecalScheduler(_RecalScheduler):
    """AUTHORIZED_SUBJECT_MOVED: recalibrate the SAME set on a SECOND IMAGE → subject moves only."""

    def _assert_moved(self, live_set_id: str, live_head: str, live_subject: str) -> None:
        if live_set_id != self._seed.set_id:
            raise EnforcementEvidenceError(
                f"subject-move recalibration changed the SET (live {live_set_id!r} != seed "
                f"{self._seed.set_id!r}) — would refuse AUTHORIZED_SET_MOVED, not SUBJECT_MOVED")
        if live_head != self._seed.pinned_set_version:
            raise EnforcementEvidenceError(
                f"subject-move recalibration changed the SET_HEAD (live {live_head[:12]}.. != seed "
                f"{self._seed.pinned_set_version[:12]}..) — would refuse SET_HEAD_STALE")
        if live_subject == self._seed.subject:
            raise EnforcementEvidenceError(
                "second-image recalibration did NOT move the subject (live == seed) — the scenario "
                "premise (a different image measures a different execution identity) is false")

    def _build_disclosure(
        self, live_set_id: str, live_head: str, live_subject: str) -> dict[str, str]:
        return {
            "locus": "admit_run_result.current_attestation(subject)",
            "mechanism": "REAL public recalibration loop on the SAME set + a SECOND IMAGE → the "
                         "measured execution-identity coordinate moves the live-authorized subject "
                         f"{live_subject[:12]}.. off plan target {self._seed.subject[:12]}..; "
                         "set_id + set_head unchanged",
            "interleaving_point":
                "between plan-mint and the live attestation read (in artifact_source)"}


def uat_set2_fixtures(corpus: Path) -> tuple[tuple[Fixture, ...], tuple[Fixture, ...]]:
    """The DISTINCT second calibration set for AUTHORIZED_SET_MOVED — its own fixture ids (so it is
    a genuinely different set with its own set_head), passing the same RetryCheck detector."""
    good = (Fixture(
        fixture_id="set2-good", label=FixtureLabel.KNOWN_GOOD,
        payload=(corpus / "retry-good-v1" / "main.py").read_bytes(), evasion_class=None),)
    bad = (Fixture(
        fixture_id="set2-bad", label=FixtureLabel.KNOWN_BAD,
        payload=(corpus / "retry-swallow-v1" / "main.py").read_bytes(),
        evasion_class="exception-swallowing"),)
    return good, bad


__all__ = [
    "SetMovedRecalScheduler", "SubjectMovedRecalScheduler", "uat_set2_fixtures",
]
