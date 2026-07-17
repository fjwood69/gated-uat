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

import hashlib
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import ResourceBudget
from core.calibration import Fixture
from core.chain import canonical_digest
from nacl.signing import SigningKey, VerifyKey

from .evidence import (
    VerifiedChain,
    build_execution_receipt,
    build_index,
    build_receipt,
    build_teardown_receipt,
    verify_integrity,
)
from .isolation import Registry, RunState
from .runtime import compute_runtime_pack_digest, make_python_runtime_pack
from .schemas import SCHEMA_VERSION_ENFORCEMENT


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


# =====================================================================================
# EnforcementDriver — drive gated's LIVE make_gated_job_runner path over seeded stores,
# map the CLOSED JobResult union to a domain outcome, and emit a signed schema-v3 chain.
# =====================================================================================


@dataclass(frozen=True)
class EnforcementOutcome:
    """The harness-domain projection of the CLOSED gated JobResult union (admitted_run |
    blocking_refusal | non_run | infrastructure_failure), mapped TOTALLY: any value that
    ``map_job_result`` does not recognise as one of the four members is folded to a fail-closed
    infrastructure_failure ("unknown -> FAIL"), never dropped or silently passed. ``outcome`` is
    the pass|fail|error the
    signed receipt records; the admitted-only measured fields are populated ONLY for an admitted_run
    (a refusal / non-run / infra row measured no admitted verdict, so it binds none)."""

    result_kind: str            # one of schemas.VALID_RESULT_KINDS
    outcome: str                # pass | fail | error
    reason: str                 # stable audit token (verdict/refusal/disposition/infra reason)
    sub_reason: str             # admission sub_reason ("" for the non-admission kinds)
    gate_outcome: str | None    # run_verdict | block_gate | neutral_gate | None (infra)
    # admitted-only (None unless result_kind == "admitted_run")
    bound_oracle_head: str | None = None
    detector_id: str | None = None
    image_digest: str | None = None
    resolved_profile_digest: str | None = None
    trust_policy_digest: str | None = None
    guard_policy_digest: str | None = None
    execution_identity_digest: str | None = None

    @property
    def admitted(self) -> bool:
        return self.result_kind == "admitted_run"


def _fail_closed_infra(reason: str) -> EnforcementOutcome:
    """The "unknown -> FAIL" fold: a value that is not one of the four JobResult members becomes a
    blocking infrastructure_failure (error, no verdict, no gate outcome) — never a silent pass."""
    return EnforcementOutcome(
        result_kind="infrastructure_failure", outcome="error", reason=reason,
        sub_reason="", gate_outcome=None)


def map_job_result(result: Any) -> EnforcementOutcome:
    """TOTAL + CLOSED map from a gated ``JobResult`` to an ``EnforcementOutcome``. Uses gated's own
    exhaustive ``account`` mapper for the honest (status, gate_outcome) fields — which RAISES on any
    non-union type — and folds that rejection (and any unhandled member) to a fail-closed
    infrastructure_failure. Only an ``AdmittedRunResult`` yields the measured coordinates; the other
    members carry no measured fields (mirroring the v3 schema's admitted-only rule)."""
    from core import VerdictType
    from gate.job_result import (
        AdmittedRunResult,
        BlockingRefusal,
        GateOutcome,
        InfrastructureFailure,
        NonRunDecision,
        account,
    )

    try:
        persisted = account(result)  # rejects a bare Verdict / any non-JobResult type
    except TypeError:
        return _fail_closed_infra("unaccounted_result")

    gate_map = {
        GateOutcome.RUN_VERDICT: "run_verdict",
        GateOutcome.BLOCK_GATE: "block_gate",
        GateOutcome.NEUTRAL_GATE: "neutral_gate",
    }
    gate_outcome = (
        gate_map.get(persisted.gate_outcome) if persisted.gate_outcome is not None else None
    )

    if isinstance(result, AdmittedRunResult):
        report = result.report
        verdict = result.verdict
        outcome = {VerdictType.PASS: "pass", VerdictType.FAIL: "fail"}.get(verdict.status, "error")
        eid = report.execution_identity
        return EnforcementOutcome(
            result_kind="admitted_run", outcome=outcome, reason=verdict.reason.value,
            sub_reason="", gate_outcome=gate_outcome,
            bound_oracle_head=result.bound_oracle_head, detector_id=report.detector_id,
            image_digest=eid.image_ref if eid is not None else None,
            resolved_profile_digest=report.resolved_profile_digest,
            trust_policy_digest=report.trust_policy_digest,
            guard_policy_digest=report.guard_policy_digest,
            execution_identity_digest=eid.digest() if eid is not None else None)
    if isinstance(result, BlockingRefusal):
        return EnforcementOutcome(
            result_kind="blocking_refusal", outcome="error", reason=result.reason.value,
            sub_reason=result.sub_reason, gate_outcome=gate_outcome)
    if isinstance(result, NonRunDecision):
        return EnforcementOutcome(
            result_kind="non_run", outcome="error", reason=result.disposition.value,
            sub_reason="", gate_outcome=gate_outcome)
    if isinstance(result, InfrastructureFailure):
        return EnforcementOutcome(
            result_kind="infrastructure_failure", outcome="error", reason=result.reason.value,
            sub_reason="", gate_outcome=None)
    # account() accepted it but it is not one of the four members we handle — fail closed.
    return _fail_closed_infra("unaccounted_result")


@dataclass(frozen=True)
class EnforcementRunConfig:
    """One live-enforcement run over an ALREADY-SEEDED pair of governance stores (see
    ``seed_enabled_policy``). Everything gated's production ``build()`` binds from the environment
    is supplied here explicitly (``build()`` is env/const-bound and cannot be parameterised), so the
    harness hand-wires the SAME shape: the real ``_ProductionAdmissionGovernanceView``, a replica
    ``resolve_disposition`` closure (snapshot=None, exactly as production), and a local
    ArtifactSource that stages a candidate tree — a RESOURCE, not a behaviour substitution; the real
    sandbox still SHA-binds and re-verifies it."""

    policy_store: Any
    calibration_store: Any
    seed: SeedProvenance
    image_ref: str                  # OCI image the enforcement run executes (tag or digest)
    toolchain_image_digest: str     # sha256:<hex64> the caller resolved (podman inspect) — bound
    gated_commit: str               # short pin recorded in the receipts
    artifact_dir: Path              # local candidate source tree (the "PR head") to stage + run
    signing_key: SigningKey
    verify_key: VerifyKey
    registry: Registry
    head_sha: str
    repo_full_name: str = "gated-uat/enforce"
    delivery_id: str = "uat-enforce-1"
    action: str = "synchronize"
    installation_id: int = 1
    profile: str = "p1"
    trials: int = 1
    first_fail: bool = True
    budget: ResourceBudget = field(
        default_factory=lambda: ResourceBudget(wall_clock_seconds=120.0))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class GatedEnforcementAdapter:
    """The SECOND gate/engine seam (beside ``GatedCalibrationAdapter``): drive gated's LIVE
    ``make_gated_job_runner`` path exactly as ``live_app.build()`` wires it, then emit a signed
    schema-v3 evidence chain. All ``gate.*`` imports are deferred into ``enforce`` so the module
    imports without gated on ``sys.path``."""

    def enforce(self, config: EnforcementRunConfig) -> tuple[EnforcementOutcome, VerifiedChain]:
        """Run ONE delivery through the real job runner and return the mapped outcome + a VERIFIED
        signed v3 chain. Wiring replicates production: replica ``resolve_disposition`` closure
        (snapshot=None) capturing the immutable GateDecision for the receipt; local ArtifactSource
        capturing the staged tree hash; the REAL ``_ProductionAdmissionGovernanceView``; the
        reference detector registry (self-computed profile digest — matches the seed's profile)."""
        from gate.live_app import _ProductionAdmissionGovernanceView
        from gate.pipeline import (
            DEFAULT_ENTRYPOINT,
            default_detector_registry,
            make_gated_job_runner,
        )
        from gate.queue import GatingEvent

        ps, cs = config.policy_store, config.calibration_store
        policy_id = config.seed.policy_id
        captured: dict[str, Any] = {}

        def resolve_decision(event: Any) -> Any:
            # EXACTLY the production closure (snapshot=None); capture the GateDecision (return it
            # UNCHANGED, so behaviour is identical to production — capture is receipt-only).
            from gate.gatekeeper import resolve_disposition
            decision = resolve_disposition(
                policy_id, store=ps, snapshot=None, snapshot_key=b"",
                now=time.time(), oracle_head_for=cs.set_head)
            captured["decision"] = decision
            return decision

        def artifact_source(event: Any, ws: Path) -> Any:
            # inject a RESOURCE (the candidate tree) into the RAII workspace; the real sandbox
            # SHA-binds + re-verifies. Capture the tree hash for the run-context receipt.
            from gate.artifact import build_artifact_spec
            dest = ws / "src"
            shutil.copytree(config.artifact_dir, dest)
            spec = build_artifact_spec(dest)
            captured["tree_hash"] = spec.tree_hash
            return spec

        governance = _ProductionAdmissionGovernanceView(ps, cs)
        registry = default_detector_registry(
            detector_id=config.seed.detector_id, entrypoint=DEFAULT_ENTRYPOINT,
            accepted_profile_digest=None)
        job_runner = make_gated_job_runner(
            resolve_decision, artifact_source, policy_id=policy_id, governance=governance,
            image=config.image_ref, resolve=registry.resolve_bundle,
            detector_id=config.seed.detector_id, trials=config.trials, budget=config.budget,
            first_fail=config.first_fail)

        event = GatingEvent(
            delivery_id=config.delivery_id, repo_full_name=config.repo_full_name,
            head_sha=config.head_sha, action=config.action,
            installation_id=config.installation_id)
        result = job_runner(event)  # the CLOSED JobResult
        outcome = map_job_result(result)
        chain = self._build_chain(config, event, outcome, captured)
        return outcome, chain

    def _build_chain(
        self, config: EnforcementRunConfig, event: Any, outcome: EnforcementOutcome,
        captured: dict[str, Any],
    ) -> VerifiedChain:
        """Assemble the four-receipt signed v3 chain (prereg -> execution -> teardown -> index) and
        return it VERIFIED. The enforcement bindings live in the execution receipt; the
        admitted-only heads/coordinates/artifact are bound ONLY for an admitted_run."""
        seed = config.seed
        ps = config.policy_store
        corpus_version = seed.pinned_set_version
        corpus_digest = hashlib.sha256(corpus_version.encode()).hexdigest()
        pack = make_python_runtime_pack(
            toolchain_image_digest=config.toolchain_image_digest, corpus_digest=corpus_digest,
            run_command=f"enforce {seed.detector_id}")
        rpd = compute_runtime_pack_digest(pack)
        verify_key_hex = config.verify_key.encode().hex()
        run_id = config.registry.allocate()
        try:
            prereg_payload: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION_ENFORCEMENT, "profile": config.profile,
                "gated_commit": config.gated_commit, "corpus_version": corpus_version,
                "preregistered_at": _now_iso(), "policy_id": seed.policy_id}
            prereg = build_receipt("prereg", run_id, prereg_payload, config.signing_key)

            event_digest = canonical_digest("gated-uat-enforce-event", {
                "delivery_id": event.delivery_id, "repo_full_name": event.repo_full_name,
                "head_sha": event.head_sha, "action": event.action,
                "installation_id": event.installation_id,
                "head_repo_full_name": event.head_repo_full_name}, version=1)

            exec_payload: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION_ENFORCEMENT, "profile": config.profile,
                "gated_commit": config.gated_commit, "outcome": outcome.outcome,
                "executed_at": _now_iso(), "canonical_digest_alg": "sha256",
                "canonical_digest_version": 1, "plan_policy_id": seed.policy_id,
                "result_kind": outcome.result_kind, "result_reason": outcome.reason,
                "result_sub_reason": outcome.sub_reason, "event_digest": event_digest}
            if outcome.gate_outcome is not None:
                exec_payload["gate_outcome"] = outcome.gate_outcome
            if outcome.admitted:
                exec_payload.update({
                    "bound_oracle_head": outcome.bound_oracle_head,
                    "policy_generation": ps.policy_head(seed.policy_id),
                    "artifact_tree_hash": captured["tree_hash"],
                    "detector_id": outcome.detector_id, "image_digest": outcome.image_digest,
                    "resolved_profile_digest": outcome.resolved_profile_digest,
                    "trust_policy_digest": outcome.trust_policy_digest,
                    "guard_policy_digest": outcome.guard_policy_digest,
                    "execution_identity_digest": outcome.execution_identity_digest})
            execution = build_execution_receipt(prereg, exec_payload, config.signing_key)

            failed = outcome.result_kind == "infrastructure_failure"
            teardown_payload: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION_ENFORCEMENT, "profile": config.profile,
                "failure": failed, "torn_down_at": _now_iso(), "runtime_pack_digest": rpd}
            if failed:
                teardown_payload["error"] = outcome.reason
            teardown = build_teardown_receipt(execution, teardown_payload, config.signing_key)

            index = build_index(
                run_id, prereg, execution, teardown, config.signing_key, verify_key_hex)
            chain = verify_integrity(prereg, execution, teardown, index, config.verify_key)
            config.registry.release(run_id, state=RunState.COMPLETED)
            return chain
        except Exception:
            config.registry.release(run_id, state=RunState.FAILED)
            raise
