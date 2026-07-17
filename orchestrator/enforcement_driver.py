"""orchestrator/enforcement_driver.py — EnforcementDriver seam + real-governance seed (slice 2.1).

The SECOND gate/engine import boundary, beside ``calibration_driver.py``. Every ``gate.*`` /
``engine.*`` / ``sandbox.*`` import for the live-enforcement path lives ONLY here, deferred into the
functions so the module imports without gated on ``sys.path``.

FIDELITY (board-ratified): NO behaviour substitution in the sealed path. The adapter injects
only RESOURCES (temp DB paths, fixtures, a seeded policy, the image, an adapter-owned store
wrapper), each disclosed + signed in the receipt. The seed brings a policy to ENABLED through
gated's REAL lifecycle (``run_calibration`` + ``ratify_enable``): the harness plays the OPERATOR
role, it does not MANUFACTURE governance inputs — no direct rows, no shortcut pass, no
hand-assembled subject or bound head.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core import ResourceBudget
from core.calibration import Fixture


class EnforcementSeedError(RuntimeError):
    """The real-governance seed could not bring a policy to ENABLED (calibration did not PASS, or
    the policy is not ENABLED after ratify). Fail-closed — never seed from a non-passing run."""


@dataclass(frozen=True)
class SeedProvenance:
    """How the seeded policy reached ENABLED — signed into the receipt so the evidence attests
    'gated enforced THIS policy, brought to ENABLED via the real lifecycle over a real
    calibration'. Every value is MEASURED by gated's real path, never harness-supplied."""

    policy_id: str
    detector_id: str
    set_id: str
    calibration_result_ref: str  # the persisted PASS ratify_enable anchored to
    pinned_set_version: str      # the sealed oracle head the pass is bound to
    subject: str                 # the measured detector identity the store RECOVERED and enabled
    policy_head: str             # the ENABLED tier-chain head (the monotonic generation)


def seed_enabled_policy(
    *,
    policy_store: Any,
    calibration_store: Any,
    policy_id: str,
    detector_id: str,
    image_ref: str,
    known_good: tuple[Fixture, ...],
    known_bad: tuple[Fixture, ...],
    budget: ResourceBudget,
    set_id: str = "default",
    trials: int = 5,
    guard_policy: str = "trusted-backend",
) -> SeedProvenance:
    """Bring ``policy_id`` to ENABLED through gated's REAL governance lifecycle (board amendment 1):

        append fixtures -> transition(PENDING_CALIBRATION) -> run_calibration -> ratify_enable

    ``run_calibration`` seals the set, runs the detector in an ObservedOCISandbox, persists the
    PASS, and records PENDING->CALIBRATING. ``ratify_enable`` grants CALIBRATING->ENABLED anchored
    to the persisted pass; the store RECOVERS the measured subject bound to that ref (the harness
    cannot rewrite the enabled identity). Registry / guarded-backend / trust-policy mirror the
    Phase-1 adapter.

    Returns ``SeedProvenance`` (all values measured). Raises ``EnforcementSeedError`` if the
    calibration did not PASS or the policy is not ENABLED afterwards.
    """
    from core.calibration import FixtureLabel
    from engine.retry import RetryCheck
    from gate.authority import GovernanceApproval
    from gate.backends import guarded_backend
    from gate.calibration_store import AdmissionCapability, ChangeOp
    from gate.detector_registry import DetectorRegistry, profile_of
    from gate.gatekeeper import ratify_enable, run_calibration
    from gate.policy_state import PolicyState
    from gate.trust_policy import resolve_trust_policy

    retry_entry = ("python3", "/artifact/main.py")
    detector = RetryCheck(retry_entry)
    registry = DetectorRegistry()
    registry.register(
        detector_id, lambda: RetryCheck(retry_entry),
        accepted_profile_digest=profile_of(detector_id, detector).digest(),
    )
    make_sb, backend_guard = guarded_backend("observed", image_ref, guard_policy=guard_policy)
    trust_policy = resolve_trust_policy("trust-policy:completed-only")

    def _appr(op: str) -> Any:
        # operator role: two distinct governance principals, as production requires.
        return GovernanceApproval(
            principals=("uat-operator-1", "uat-operator-2"), purpose="uat-enforcement-seed",
            rationale="seed a real ENABLED policy via gated's lifecycle", operation_id=op,
        )

    # Populate the set through the REAL admission path (dual approval + AdmissionCapability) so
    # run_calibration seals a GENUINE set. Known-bad first: the sealed set iterates (*bad, *good).
    admit = AdmissionCapability()
    for fx in known_bad:
        calibration_store.append(
            ChangeOp.ADD_KNOWN_BAD, admission=admit,
            approval=_appr(f"{policy_id}-fx-{fx.fixture_id}"), fixture_id=fx.fixture_id,
            set_id=set_id, label=FixtureLabel.KNOWN_BAD,
            payload=fx.payload, evasion_class=fx.evasion_class,
        )
    for fx in known_good:
        calibration_store.append(
            ChangeOp.ADD_KNOWN_GOOD, admission=admit,
            approval=_appr(f"{policy_id}-fx-{fx.fixture_id}"), fixture_id=fx.fixture_id,
            set_id=set_id, label=FixtureLabel.KNOWN_GOOD, payload=fx.payload,
        )

    policy_store.transition(
        policy_id, PolicyState.PENDING_CALIBRATION, approval=_appr(f"{policy_id}-pending"),
    )
    outcome = run_calibration(
        policy_id, store=policy_store, calibration_store=calibration_store, make_sandbox=make_sb,
        detector_id=detector_id, resolve=registry.resolve_bundle, budget=budget,
        approval=_appr(f"{policy_id}-calibrate"), set_id=set_id, trials=trials,
        backend_guard=backend_guard, trust_policy=trust_policy,
    )
    if not outcome.passed or outcome.calibration_result_ref is None:
        raise EnforcementSeedError(
            f"seed calibration did not PASS for {policy_id!r} "
            f"(breaking={outcome.breaking_fixtures}) — cannot seed ENABLED from a non-passing run",
        )
    pinned = calibration_store.set_head(set_id)
    ratify_enable(
        policy_id, store=policy_store, approval=_appr(f"{policy_id}-ratify"),
        calibration_result_ref=outcome.calibration_result_ref, pinned_set_version=pinned,
    )
    # Recover the ENABLED binding + generation from the store (measured, never harness-supplied).
    att = policy_store.current_attestation(policy_id)  # (set_id, oracle_head, subject) if ENABLED
    if att is None:
        raise EnforcementSeedError(
            f"{policy_id!r} is not ENABLED after ratify_enable — the seed did not take",
        )
    return SeedProvenance(
        policy_id=policy_id, detector_id=detector_id, set_id=att[0],
        calibration_result_ref=outcome.calibration_result_ref, pinned_set_version=pinned,
        subject=att[2], policy_head=policy_store.policy_head(policy_id),
    )
