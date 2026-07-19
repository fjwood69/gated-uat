"""orchestrator/enforcement_driver.py — EnforcementDriver seam + real-governance seed (slice 2.1).

The SECOND gate/engine import boundary, beside ``calibration_driver.py``. Every ``gate.*`` /
``engine.*`` / ``sandbox.*`` import for the live-enforcement path lives ONLY here, deferred into the
functions so the module imports without gated on ``sys.path``.

FIDELITY (board-ratified): NO behaviour substitution in the sealed path. The adapter injects
only RESOURCES (temp DB paths, fixtures, a seeded policy, the image, an adapter-owned store
wrapper), each disclosed + signed in the receipt. The ENABLE decision is gated's, not the
harness's: the seed brings a policy to ENABLED through gated's REAL lifecycle (``run_calibration``
+ ``ratify_enable``) — no shortcut pass, no hand-assembled subject or bound head; the store
RECOVERS the enabled identity from the persisted calibration PASS. NARROWED claim (dissent P1):
the calibration SET is populated via the store's append primitive under a capability + dual
approval, NOT the full ``gate.admission.admit()`` fixture-admission ceremony — the seed stages a
set to reach ENABLED, it does not exercise (or attest) fixture admission.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
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
    receipt_to_dict,
    verify_integrity,
)
from .expectations import ScenarioId, assert_inducible, expected_for
from .gated_pin import ACCEPTED_RETRYCHECK_PROFILE_DIGEST, verify_gated_dependency
from .isolation import Registry, RunState
from .runtime import compute_runtime_pack_digest, make_python_runtime_pack
from .schemas import SCHEMA_VERSION_ENFORCEMENT

# The scenarios that inject a fault via a scheduler and disclose it (require_completed_disclosure):
# the ABA + tamper + the slice-2.2a admission-currency injections. A COMPLETED disclosure is
# DEMANDED after the run; a half-fired injection raises there and aborts evidence.
_FAULT_SCHEDULER_SCENARIOS: frozenset[ScenarioId] = frozenset({
    ScenarioId.ABA_GENERATION_MOVED, ScenarioId.SHA_TAMPER,
    ScenarioId.SET_HEAD_STALE, ScenarioId.ORACLE_UNAVAILABLE,
    ScenarioId.LIVE_ATTESTATION_UNAVAILABLE,
    # slice 2.2b — the recalibration-loop scenarios also own a COMPLETED-gated induction disclosure
    # (the real public ENABLED->ADVISORY->PENDING_CALIBRATION->CALIBRATING->ENABLED rebind record).
    ScenarioId.AUTHORIZED_SET_MOVED, ScenarioId.AUTHORIZED_SUBJECT_MOVED,
})


class EnforcementSeedError(RuntimeError):
    """The real-governance seed could not bring a policy to ENABLED (calibration did not PASS, or
    the policy is not ENABLED after ratify). Fail-closed — never seed from a non-passing run."""


class EnforcementEvidenceError(RuntimeError):
    """The signed enforcement chain could not be minted coherently (e.g. the dispatched plan's
    policy does not match the enforced one). Fail-closed — never sign incoherent enforcement
    evidence."""


@dataclass(frozen=True)
class SeedProvenance:
    """How the seeded policy reached ENABLED. Fields are typed BY PROVENANCE (dissent P1 — no
    blanket 'every value measured' claim):

      CONFIGURED (harness inputs, not measured): ``policy_id``, ``detector_id``, ``set_id``.
      MEASURED / STORE-DERIVED by gated's real lifecycle (the harness cannot author these): the
      persisted-pass ``calibration_result_ref``, the sealed ``pinned_set_version`` (oracle head),
      the RECOVERED ``subject`` (the enabled detector identity the store bound to the pass), and
      the ``policy_head`` (the ENABLED tier-chain head / monotonic generation).
    """

    # --- configured (harness inputs) ---
    policy_id: str
    detector_id: str
    set_id: str
    # --- measured / store-derived (gated's real lifecycle; not harness-authored) ---
    calibration_result_ref: str  # the persisted PASS ratify_enable anchored to
    pinned_set_version: str      # the sealed oracle head the pass is bound to
    subject: str                 # the measured detector identity the store RECOVERED and enabled
    policy_head: str             # the ENABLED tier-chain head (the monotonic generation)
    seed_image_digest: str       # the AUTHORITATIVE calibration-result execution image (sha256:...)


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

    Returns ``SeedProvenance`` (provenance-typed: CONFIGURED policy/set/detector IDs +
    MEASURED/store-derived ref/head/subject/generation — not "all measured"). Raises
    ``EnforcementSeedError`` if the calibration did not PASS or the policy is not ENABLED after.
    """
    from core.calibration import FixtureLabel
    from engine.retry import RetryCheck
    from gate.authority import GovernanceApproval
    from gate.backends import guarded_backend
    from gate.calibration_store import AdmissionCapability, ChangeOp
    from gate.detector_registry import DetectorRegistry
    from gate.gatekeeper import ratify_enable, run_calibration
    from gate.policy_state import PolicyState
    from gate.trust_policy import resolve_trust_policy

    retry_entry = ("python3", "/artifact/main.py")
    registry = DetectorRegistry()
    # INDEPENDENT acceptance (dissent P1): the accepted profile digest is the slice-2.0 golden
    # LITERAL, not profile_of(...).digest() self-computed and fed back to the same registry (which
    # proves only self-consistency). A runtime resolved-profile drift from this literal fails
    # detector resolution closed — exactly as production's externally-accepted digest does.
    registry.register(
        detector_id, lambda: RetryCheck(retry_entry),
        accepted_profile_digest=ACCEPTED_RETRYCHECK_PROFILE_DIGEST,
    )
    # UAT-2 (config-ID before seeding): resolve a possibly-MUTABLE tag to its immutable OCI
    # image-config id BEFORE calibration, mirroring the enforcement path's launch-by-config-ID.
    # Calibration already records + binds the image that actually executed (so a moved tag is not a
    # provenance bypass), but anchoring to the digest up front removes the mutable-tag intent-drift
    # window between seeding and the run.
    seed_image_id = _resolve_image_config_id(image_ref)
    make_sb, backend_guard = guarded_backend("observed", seed_image_id, guard_policy=guard_policy)
    trust_policy = resolve_trust_policy("trust-policy:completed-only")

    def _appr(op: str) -> Any:
        # operator role: two distinct governance principals, as production requires.
        return GovernanceApproval(
            principals=("uat-operator-1", "uat-operator-2"), purpose="uat-enforcement-seed",
            rationale="seed a real ENABLED policy via gated's lifecycle", operation_id=op,
        )

    # Populate the set via the CalibrationStore.append PRIMITIVE under an AdmissionCapability + dual
    # GovernanceApproval (dissent P1: this does NOT traverse gate.admission.admit() — the full
    # fixture-admission ceremony that validates each candidate executes cleanly, computes the
    # known-good merged-tree hash, revokes the fallback and fires the re-cal outbox). The seed does
    # not test fixture admission; it stages a set so run_calibration can seal + score it. Known-bad
    # first: the sealed set iterates (*bad, *good).
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
    # M3/QM-3: the SEED image is the AUTHORITATIVE calibration-result execution identity —
    # ``outcome.result.execution_identity.image_ref`` — NOT a caller string. Require a canonical
    # ``sha256:<hex64>`` before returning (fail-closed); it anchors the SEED endpoint of a drift.
    ei = outcome.result.execution_identity
    seed_image = ei.image_ref if ei is not None else None
    if not seed_image or not re.match(r"^sha256:[0-9a-f]{64}$", seed_image):
        raise EnforcementSeedError(
            f"seed calibration produced no canonical execution image digest (got {seed_image!r}) — "
            "cannot anchor the seed image")
    return SeedProvenance(
        policy_id=policy_id, detector_id=detector_id, set_id=att[0],
        calibration_result_ref=outcome.calibration_result_ref, pinned_set_version=pinned,
        subject=att[2], policy_head=policy_store.policy_head(policy_id),
        seed_image_digest=seed_image,
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

    # AdmittedRunResult / BlockingRefusal are runtime-public but absent from gate.job_result's
    # __all__, so mypy --strict's no-implicit-reexport flags them WHEN gated is on the path (the
    # typecheck CI). The unused-ignore code keeps this green in the OTHER mode too (gated absent ->
    # gate.* is Any via ignore_missing_imports -> no attr-defined error -> ignore would be unused).
    from gate.job_result import (  # type: ignore[attr-defined,unused-ignore]
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
    """One live-enforcement run under a SCENARIO over an ALREADY-SEEDED pair of governance stores.
    The harness hand-wires the SAME shape gated's env-bound ``build()`` does. Amendment 6: the
    ``gated_commit`` and the run-image digest are NOT caller inputs — ``enforce`` verifies the
    worktree and resolves the image config-ID itself, so the seam for a caller-supplied string does
    not exist. The scenario-specific injection seams default to the real production wiring (the
    COMPLIANT_ADMIT path); the non-compliant scenarios inject their fault machinery (a STORE-layer
    calibration wrapper for ABA [5], a tampering artifact_source, a distinct run image) and disclose
    via a scheduler-owned ``require_completed_disclosure()`` — a record of what the harness ACTUALLY
    did, gated on the injection having COMPLETED, not a free config literal."""

    scenario: ScenarioId
    policy_store: Any
    calibration_store: Any
    seed: SeedProvenance
    image_ref: str                  # the RUN image TAG; enforce() resolves its immutable config-ID
    artifact_dir: Path              # local candidate source tree (the "PR head") to stage + run
    runs_dir: Path                  # where the signed prereg is PERSISTED at mint (orphan audit)
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
    # scenario-specific injection seams (None => the real production wiring, COMPLIANT_ADMIT).
    # NO ``governance`` seam (correction [4].1): enforce() ALWAYS constructs the real
    # ``_ProductionAdmissionGovernanceView`` over the passed (possibly store-WRAPPED) stores — a
    # substituted governance object is never admissible. The ABA fault is injected at the STORE
    # layer (a calibration_store wrapper), which the real view reads THROUGH.
    artifact_source: Any = None     # tamper source; None => local staging source
    # the fault DISCLOSURE is NOT a free config literal (correction [4].2): a fault-injecting
    # scenario owns a ``fault_scheduler`` whose ``require_completed_disclosure()`` returns what it
    # ACTUALLY did — but ONLY once its state machine reached COMPLETED. A half-fired injection
    # raises there, aborting evidence rather than serialising a refusal over an unknown state.
    fault_scheduler: Any = None     # [5] owns require_completed_disclosure(); aba/tamper only


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_code_sha() -> str:
    """A DETERMINISTIC content digest of the harness SOURCE (orchestrator/*.py) — a sorted map of
    (filename -> sha256(source bytes)), hashed. Not the installed wheel (paths/.pyc are non-stable →
    theatre); reproducible from the source tree. Labelled NON-authz in the receipt: identifies the
    harness that made the prediction, it does not authorise anything."""
    pkg = Path(__file__).resolve().parent
    entries = [[p.name, hashlib.sha256(p.read_bytes()).hexdigest()]
               for p in sorted(pkg.glob("*.py"))]
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _resolve_image_config_id(image_ref: str) -> str:
    """Resolve *image_ref* to its immutable OCI image-config id (``sha256:<hex64>``, ``{{.Id}}``) —
    the SAME coordinate gated's execution_identity binds. Launching by THIS id (not the mutable tag)
    keeps the tag out of the trust path (correction 1 belt)."""
    r = subprocess.run(
        ["podman", "image", "inspect", "--format", "{{.Id}}", image_ref],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise EnforcementEvidenceError(
            f"could not resolve image config-id for {image_ref!r}: {r.stderr.strip()}")
    image_id = str(r.stdout.strip())
    return image_id if image_id.startswith("sha256:") else "sha256:" + image_id


def _event_digest(event: Any) -> str:
    return str(canonical_digest("gated-uat-enforce-event", {
        "delivery_id": event.delivery_id, "repo_full_name": event.repo_full_name,
        "head_sha": event.head_sha, "action": event.action,
        "installation_id": event.installation_id,
        "head_repo_full_name": event.head_repo_full_name}, version=1))


def _seed_trace(seed: SeedProvenance) -> dict[str, Any]:
    return {
        "policy_id": seed.policy_id, "detector_id": seed.detector_id, "set_id": seed.set_id,
        "calibration_result_ref": seed.calibration_result_ref,
        "pinned_set_version": seed.pinned_set_version, "subject": seed.subject,
        "policy_head": seed.policy_head, "seed_image_digest": seed.seed_image_digest}


class GatedEnforcementAdapter:
    """The SECOND gate/engine seam (beside ``GatedCalibrationAdapter``): drive gated's LIVE
    ``make_gated_job_runner`` path exactly as ``live_app.build()`` wires it, PREREG-FIRST, then emit
    a signed schema-v3 MATRIX evidence chain. All ``gate.*`` imports are deferred into ``enforce``
    the module imports without gated on ``sys.path``."""

    def enforce(self, config: EnforcementRunConfig) -> tuple[EnforcementOutcome, VerifiedChain]:
        """Run ONE delivery PREREG-FIRST and return the mapped outcome + a VERIFIED signed v3 chain.

        The prereg (the signed PREDICTION) is minted, signed, and PERSISTED before ``job_runner`` is
        invoked — so the observation can only confirm or refute a prior claim, and a crashed run
        leaves a durable orphan-prereg audit. gated_commit is derived from the verified pinned
        worktree; the run image is launched by its immutable config-ID (correction 1).
        ``observed_kind``
        comes SOLELY from the JobResult (``map_job_result``), never the scenario. teardown = the
        HARNESS cleanup, not the SUT (correction 2)."""
        import gate
        from gate.live_app import _ProductionAdmissionGovernanceView
        from gate.pipeline import (
            DEFAULT_ENTRYPOINT,
            default_detector_registry,
            make_gated_job_runner,
        )
        from gate.queue import GatingEvent

        # (0) the taxonomy GUARD (slice 2.2): refuse a FABRICATION-classed scenario before anything
        # runs — the harness only ever drives gated's REAL path, never a hand-built result.
        assert_inducible(config.scenario)

        ps, cs = config.policy_store, config.calibration_store
        seed = config.seed
        policy_id = seed.policy_id

        # (a) verify the pinned gated worktree AT ENTRY and derive gated_commit there (amendment 6 —
        # no caller-supplied commit string; the seam does not exist).
        gated_root = Path(gate.__file__).resolve().parent.parent
        gated_commit = verify_gated_dependency(gated_root)
        # (b) resolve the RUN image config-ID — launched by THIS immutable id, not the tag (belt).
        run_image_digest = _resolve_image_config_id(config.image_ref)
        # (c) the deterministic harness code identity (non-authz).
        code_sha = _compute_code_sha()

        event = GatingEvent(
            delivery_id=config.delivery_id, repo_full_name=config.repo_full_name,
            head_sha=config.head_sha, action=config.action,
            installation_id=config.installation_id,
            # UAT-3: set explicitly rather than relying on GatingEvent's default — _event_digest
            # hashes head_repo_full_name, so the digest must not silently move if the default moves.
            head_repo_full_name=None)
        event_digest = _event_digest(event)
        expected = expected_for(config.scenario)
        corpus_version = seed.pinned_set_version
        rpd = compute_runtime_pack_digest(make_python_runtime_pack(
            toolchain_image_digest=run_image_digest,
            corpus_digest=hashlib.sha256(corpus_version.encode()).hexdigest(),
            run_command=f"enforce {seed.detector_id}"))
        verify_key_hex = config.verify_key.encode().hex()

        run_id = config.registry.allocate()
        try:
            # (e) MINT + SIGN + PERSIST the prereg BEFORE the run (orphan-prereg audit at mint).
            prereg_payload: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION_ENFORCEMENT, "profile": config.profile,
                "gated_commit": gated_commit, "corpus_version": corpus_version,
                "preregistered_at": _now_iso(), "scenario": config.scenario.value,
                "configured_policy_id": policy_id, "code_sha": code_sha,
                "rc_event_digest": event_digest, "rc_image_ref": config.image_ref,
                "rc_image_digest": run_image_digest, "rc_detector_id": seed.detector_id,
                "expected_kind": expected.kind, "expected_reason": expected.reason,
                "expected_sub_reason": expected.sub_reason}
            prereg = build_receipt("prereg", run_id, prereg_payload, config.signing_key)
            self._persist_prereg(config, run_id, prereg)

            # (f) wire the REAL job runner, launched by the config-ID (belt).
            captured: dict[str, Any] = {}

            def resolve_decision(ev: Any) -> Any:
                from gate.gatekeeper import resolve_disposition
                decision = resolve_disposition(
                    policy_id, store=ps, snapshot=None, snapshot_key=b"",
                    now=time.time(), oracle_head_for=cs.set_head)
                captured["decision"] = decision
                return decision

            def default_source(ev: Any, ws: Path) -> Any:
                from gate.artifact import build_artifact_spec
                dest = ws / "src"
                shutil.copytree(config.artifact_dir, dest)
                return build_artifact_spec(dest)

            # P1 (assembly-layer refutability): CAPTURE the bound tree_hash at the source-SELECTION
            # seam — the ONE point every source flows through — NOT inside each source. A custom
            # artifact_source (the ABA wrapper, the tamper source) that forgot to populate
            # ``captured`` would kill receipt assembly with a KeyError on an ``admitted_run`` — the
            # single most important observation an injection scenario can produce (the gate
            # unexpectedly ADMITTING under the fault). Wrapping here makes tree_hash present by
            # construction for EVERY source, so a refutation always serialises.
            selected_source = config.artifact_source or default_source

            def capturing_source(ev: Any, ws: Path) -> Any:
                spec = selected_source(ev, ws)
                captured["tree_hash"] = spec.tree_hash
                return spec

            # correction [4].1: ALWAYS the real production view over the passed (possibly WRAPPED)
            # stores — never a substituted governance object. The ABA fault lives in the store
            # layer, so the real view reads THROUGH the wrapper's overridden accessor.
            gov = _ProductionAdmissionGovernanceView(ps, cs)
            src = capturing_source
            registry = default_detector_registry(
                detector_id=seed.detector_id, entrypoint=DEFAULT_ENTRYPOINT,
                accepted_profile_digest=ACCEPTED_RETRYCHECK_PROFILE_DIGEST)
            job_runner = make_gated_job_runner(
                resolve_decision, src, policy_id=policy_id, governance=gov,
                image=run_image_digest, resolve=registry.resolve_bundle,
                detector_id=seed.detector_id, trials=config.trials, budget=config.budget,
                first_fail=config.first_fail)

            # (g) run; an unexpected raise PROPAGATES (the persisted prereg is the orphan audit).
            result = job_runner(event)
            # (h) map — observed_kind comes SOLELY from the JobResult, never the scenario.
            outcome = map_job_result(result)

            # (h2) correction [4].2: for a fault-injecting scenario, DEMAND the scheduler's
            # completion disclosure NOW. ``require_completed_disclosure()`` returns what was
            # injected ONLY if its state machine reached COMPLETED; a half-fired injection RAISES,
            # propagating to the except (run FAILED) and aborting evidence — never serialising a
            # plausible refusal over an unknown-state fault.
            fault_disclosure: dict[str, str] | None = None
            if config.scenario in _FAULT_SCHEDULER_SCENARIOS:
                fault_disclosure = config.fault_scheduler.require_completed_disclosure()

            # (i) build the MATRIX execution receipt + (j) teardown + (k) index; verify.
            execution = self._execution_receipt(
                config, prereg, gated_commit, event_digest, run_image_digest, outcome,
                captured, fault_disclosure)
            # (j) correction 2: teardown records the HARNESS cleanup, which COMPLETED (the RAII
            # workspace was purged on every engine exit path). failure=False even for an
            # InfrastructureFailure JobResult (a completed SUT observation, NOT a dirty harness). A
            # cleanup exception would have propagated already, leaving no completed chain.
            teardown = build_teardown_receipt(execution, {
                "schema_version": SCHEMA_VERSION_ENFORCEMENT, "profile": config.profile,
                "failure": False, "torn_down_at": _now_iso(), "runtime_pack_digest": rpd},
                config.signing_key)
            index = build_index(
                run_id, prereg, execution, teardown, config.signing_key, verify_key_hex)
            chain = verify_integrity(prereg, execution, teardown, index, config.verify_key)
            config.registry.release(run_id, state=RunState.COMPLETED)
            return outcome, chain
        except Exception:
            config.registry.release(run_id, state=RunState.FAILED)
            raise

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        """fsync a DIRECTORY (a path string cannot be fsynced — open a read fd first) so its most
        recent entry change (a mkdir or a rename INTO it) is durable across a crash."""
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _mkdir_durable(self, path: Path) -> None:
        """``mkdir -p`` that fsyncs the PARENT of each directory it ACTUALLY creates — so every new
        directory ENTRY is durable link-by-link up to the deepest PRE-EXISTING (assumed-durable)
        ancestor. Fsyncing only the leaf is not enough: a directory is itself an entry in its
        parent, so a freshly created ``runs/`` or ``<run_id>/`` whose parent was never fsynced can
        vanish in a crash, taking the durably-written file inside it. An already-existing level is a
        no-op (nothing to make durable)."""
        to_create: list[Path] = []
        p = path
        while not p.exists():
            to_create.append(p)
            p = p.parent
        for d in reversed(to_create):  # shallowest → deepest
            d.mkdir()
            self._fsync_dir(d.parent)  # the parent just gained d's entry — make it durable

    def _persist_prereg(self, config: EnforcementRunConfig, run_id: str, prereg: Any) -> None:
        """Persist the SIGNED prereg to ``runs_dir/<run_id>/prereg.json`` at MINT. The CONTRACT (not
        a stronger, impossible claim): once ``_persist_prereg`` RETURNS, the prereg and its
        directory chain are durable on disk; before it returns, the run has NOT started. That is the
        orphan-audit property enforce() relies on — 'if execution began, the prediction is durably
        recorded' — and it is the SUFFICIENT one. It is NOT (and cannot be) a promise that a crash
        DURING persistence leaves a file: nothing guarantees that before ``os.replace`` lands, and a
        crash before it simply leaves no target — which is fine, the run had not begun, so there is
        nothing to audit.

        P2 (what makes RETURN mean durable, the whole way down the tree): every directory the
        harness creates is fsynced through its parent (``_mkdir_durable``), the file is written to a
        temp sibling + fsynced, ``os.replace``d (atomic on POSIX — no reader sees a TORN prereg),
        and ``<run_id>`` is fsynced so the rename INTO it is durable — link-by-link up to the
        pre-existing (assumed-durable) runs_dir parent. So AFTER return, neither the runs/ nor
        <run_id>/ directory entry nor the prereg can be lost to a crash."""
        d = config.runs_dir / run_id
        self._mkdir_durable(d)  # creates runs_dir + <run_id> as needed, parent-fsyncing each
        data = json.dumps(receipt_to_dict(prereg), sort_keys=True)
        tmp = d / "prereg.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, d / "prereg.json")  # atomic swap into place
        self._fsync_dir(d)  # the rename INTO <run_id> is now durable

    def _execution_receipt(
        self, config: EnforcementRunConfig, prereg: Any, gated_commit: str, event_digest: str,
        run_image_digest: str, outcome: EnforcementOutcome, captured: dict[str, Any],
        fault_disclosure: dict[str, str] | None,
    ) -> Any:
        """Build the signed MATRIX execution receipt (COMMON | configured(scenario) | observed).
        The observed fields are keyed by ``outcome.result_kind`` (the JobResult); the configured
        / fault-injection fields by the scenario. ``fault_disclosure`` is the scheduler's COMPLETED
        record of what the harness injected (aba/tamper), already demanded in ``enforce``.
        plan_policy_id is the CAPTURED dispatched plan's policy (explicit null for non_run)."""
        seed, ps, scenario = config.seed, config.policy_store, config.scenario
        # plan_policy_id — CAPTURED: the dispatched plan's policy, or explicit None for a non_run.
        decision = captured.get("decision")
        dispatched_plan = getattr(decision, "plan", None) if decision is not None else None
        if outcome.result_kind == "non_run":
            plan_policy_id: str | None = None
        else:
            plan_policy_id = (
                dispatched_plan.policy_id if dispatched_plan is not None else seed.policy_id)
            if plan_policy_id != seed.policy_id:
                raise EnforcementEvidenceError(
                    f"dispatched plan policy {plan_policy_id!r} != enforced {seed.policy_id!r}")

        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION_ENFORCEMENT, "profile": config.profile,
            "gated_commit": gated_commit, "outcome": outcome.outcome, "executed_at": _now_iso(),
            "canonical_digest_alg": "sha256", "canonical_digest_version": 1,
            "scenario": scenario.value, "configured_policy_id": seed.policy_id,
            "event_digest": event_digest, "result_kind": outcome.result_kind,
            "result_reason": outcome.reason, "result_sub_reason": outcome.sub_reason,
            "gate_outcome": outcome.gate_outcome, "plan_policy_id": plan_policy_id,
            "seed_trace": _seed_trace(seed)}
        # CONFIGURED / FAULT-INJECTION by scenario — disclosed from the REAL machinery.
        if scenario in _FAULT_SCHEDULER_SCENARIOS:
            if fault_disclosure is None:
                raise EnforcementEvidenceError(
                    f"scenario {scenario.value!r} requires a COMPLETED fault disclosure from the "
                    "scheduler (require_completed_disclosure produced nothing)")
            payload["fault_injection"] = dict(fault_disclosure)
        elif scenario is ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE:
            # the CONFIGURED run image (== rc_image_digest; a DISTINCT image vs the seed).
            payload["drift_image_digest"] = run_image_digest
        # OBSERVED by kind — only an admitted run measured coordinates (authoritative return).
        if outcome.result_kind == "admitted_run":
            payload.update({
                "bound_oracle_head": outcome.bound_oracle_head,
                "observed_policy_head_post_admission": ps.policy_head(seed.policy_id),
                "artifact_tree_hash": captured["tree_hash"], "image_digest": outcome.image_digest,
                "resolved_profile_digest": outcome.resolved_profile_digest,
                "trust_policy_digest": outcome.trust_policy_digest,
                "guard_policy_digest": outcome.guard_policy_digest,
                "execution_identity_digest": outcome.execution_identity_digest})
        return build_execution_receipt(prereg, payload, config.signing_key)
