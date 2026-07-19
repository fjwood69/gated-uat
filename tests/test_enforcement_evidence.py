"""tests/test_enforcement_evidence.py — Phase 2 slice 2.1b: the live-enforcement signed evidence.

Two guards:

1. LIVE ENFORCEMENT EVIDENCE (podman-gated). Seeds a REAL ENABLED policy (2.1a), then drives gated's
   real ``make_gated_job_runner`` over a COMPLIANT candidate tree via ``GatedEnforcementAdapter``.
   A compliant run is ADMITTED (real ``admit_run_result`` — measured subject == the seeded subject,
   set/generation current) and the adapter emits a schema-v3 signed chain that the harness's OWN
   public verification path (``verify_integrity`` + ``evaluate_admission``) accepts. Asserts the
   receipt binds the enforced policy (== the preregistered one), BOTH admission-bracket heads, and
   the run-context coordinates the sandbox measured — nothing harness-fabricated.

2. WIRING PIN (pure source inspection, always runs). Pins that gated's production ``live_app.build``
   still wires the tier decision as ``resolve_disposition(..., snapshot=None, ...,
   oracle_head_for=calibration_store.set_head)`` and reuses ``_ProductionAdmissionGovernanceView`` +
   ``make_gated_job_runner`` — the EXACT shape the adapter's replica closure mirrors. This is
   STRUCTURAL-MAINTENANCE evidence (it does not prove ``build()`` ran): if production re-wires the
   decision, this fails and forces the harness replica to be re-verified against the new shape.
"""

from __future__ import annotations

import inspect
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from core import ResourceBudget
from core.calibration import Fixture, FixtureLabel
from gate.calibration_store import CalibrationStore
from gate.policy_store import PolicyStore
from nacl.signing import SigningKey

from orchestrator.enforcement_driver import (
    EnforcementEvidenceError,
    EnforcementRunConfig,
    GatedEnforcementAdapter,
    seed_enabled_policy,
)
from orchestrator.expectations import ScenarioId, expected_for
from orchestrator.isolation import Registry
from orchestrator.schemas import (
    enforcement_expected_triple,
    enforcement_observed_triple,
)

from ._aba_scheduler import AbaInjectionScheduler
from ._currency_schedulers import (
    LiveAttestationUnavailableScheduler,
    OracleUnavailableScheduler,
    SetHeadStaleScheduler,
)
from ._tamper_scheduler import TamperInjectionScheduler

_IMAGE_REF = "localhost/mori:local"
_IMAGE_REF_2 = "localhost/mori-uat:local"  # a DISTINCT image → a distinct execution identity
_CORPUS = Path(__file__).resolve().parent.parent / "corpora" / "fixtures"


def _podman_image_available(image_ref: str) -> bool:
    if not shutil.which("podman"):
        return False
    return subprocess.run(
        ["podman", "image", "exists", image_ref], capture_output=True
    ).returncode == 0


def _resolve_image_digest(image_ref: str) -> str | None:
    """The image-config sha256 ({{.Id}}) the OCI backend measures at run time — the value the
    execution identity binds. Prefixed to the canonical ``sha256:`` form the backend prepends."""
    r = subprocess.run(
        ["podman", "image", "inspect", "--format", "{{.Id}}", image_ref],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    image_id = r.stdout.strip()
    return image_id if image_id.startswith("sha256:") else "sha256:" + image_id


def _seed(tmp: Path, image_ref: str = _IMAGE_REF) -> tuple[PolicyStore, CalibrationStore, Any]:
    """Bring ``uat-enforce`` to a REAL ENABLED policy on ``image_ref`` via gated's lifecycle — the
    shared preamble for every through-``enforce`` scenario below."""
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
        policy_store=ps, calibration_store=cs, policy_id="uat-enforce", detector_id="RetryCheck",
        image_ref=image_ref, known_good=good, known_bad=bad,
        budget=ResourceBudget(wall_clock_seconds=120.0), trials=1)
    return ps, cs, prov


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class EnforcementEvidenceTests(unittest.TestCase):
    def test_compliant_admit_yields_admitted_signed_matrix_chain(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-enfev-"))
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
            policy_store=ps, calibration_store=cs, policy_id="uat-enforce",
            detector_id="RetryCheck", image_ref=_IMAGE_REF, known_good=good, known_bad=bad,
            budget=ResourceBudget(wall_clock_seconds=120.0), trials=1)
        signing_key = SigningKey.generate()

        # [4]: prereg-first, scenario-driven; enforce() itself resolves the run-image config-ID and
        # derives gated_commit from the pinned worktree (no caller-supplied strings).
        config = EnforcementRunConfig(
            scenario=ScenarioId.COMPLIANT_ADMIT, policy_store=ps, calibration_store=cs, seed=prov,
            image_ref=_IMAGE_REF,
            # a COMPLIANT candidate tree: retry-good-v1 retries 3x → RetryCheck PASS.
            artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs", signing_key=signing_key,
            verify_key=signing_key.verify_key, registry=Registry(tmp / "registry.db"),
            head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0))

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # the run was ADMITTED with a PASS verdict (measured subject == the seeded subject).
        self.assertEqual(outcome.result_kind, "admitted_run")
        self.assertEqual(outcome.outcome, "pass")

        # the signed v3 chain verifies AND is admissible via the harness's own public path.
        self.assertTrue(chain.is_admitted)
        pp, ep = chain.prereg.payload, chain.execution.payload
        self.assertEqual(pp["schema_version"], 3)
        self.assertEqual(ep["schema_version"], 3)
        # the PREREG is the signed prediction: scenario + configured policy + committed expectation.
        self.assertEqual(pp["scenario"], "compliant_admit")
        self.assertEqual(pp["configured_policy_id"], "uat-enforce")
        self.assertEqual(pp["expected_kind"], "admitted_run")
        self.assertEqual(pp["expected_reason"], "pass")
        # the prereg was PERSISTED at mint (orphan-prereg audit).
        self.assertTrue((tmp / "runs" / chain.prereg.run_id / "prereg.json").exists())
        # continuity binds the execution to the preregistered context.
        self.assertEqual(ep["scenario"], "compliant_admit")
        self.assertEqual(ep["configured_policy_id"], "uat-enforce")
        self.assertEqual(ep["plan_policy_id"], "uat-enforce")
        self.assertEqual(ep["result_kind"], "admitted_run")
        self.assertEqual(ep["gate_outcome"], "run_verdict")
        self.assertEqual(ep["event_digest"], pp["rc_event_digest"])
        # observed heads (renamed; post-read, no bracket claim).
        self.assertEqual(ep["observed_policy_head_post_admission"], ps.policy_head("uat-enforce"))
        self.assertEqual(ep["bound_oracle_head"], prov.pinned_set_version)
        # the run image the sandbox measured == the preregistered config-ID (belt + alarm).
        self.assertEqual(ep["image_digest"], pp["rc_image_digest"])
        self.assertTrue(ep["image_digest"].startswith("sha256:"))
        # seed_trace binds the seed image (== run image here; distinct only for subject_drift).
        self.assertEqual(ep["seed_trace"]["policy_id"], "uat-enforce")
        self.assertEqual(ep["seed_trace"]["seed_image_digest"], prov.seed_image_digest)
        # measured coordinates (bare 64-hex) + the sha256:<hex64> artifact tree hash.
        for field_name in (
            "resolved_profile_digest", "trust_policy_digest",
            "guard_policy_digest", "execution_identity_digest",
        ):
            self.assertEqual(len(ep[field_name]), 64, field_name)
        self.assertEqual(len(ep["artifact_tree_hash"]), 71)


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class AbaScenarioEvidenceTests(unittest.TestCase):
    """The ABA_GENERATION_MOVED scenario end-to-end (slice 2.1 [5]): a TEST-ONLY store-layer
    scheduler injects a cross-store ``set_head`` ABA across an ENABLED->DEGRADED generation move at
    admission's live oracle read. Drives gated's REAL ``admit_run_result`` to a genuine
    POLICY_GENERATION_MOVED refusal (NOT a fabricated JobResult), and asserts the harness emits a
    signed schema-v3 refutation chain that its OWN admissibility path ACCEPTS — the prediction
    (blocking_refusal / policy_generation_moved) was CONFIRMED. The fault disclosure is the
    scheduler's COMPLETED induction record, demanded by ``enforce`` (a half-fired injection would
    have raised and aborted evidence)."""

    def test_aba_generation_move_yields_signed_admissible_refutation(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-aba-"))
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
            policy_store=ps, calibration_store=cs, policy_id="uat-enforce",
            detector_id="RetryCheck", image_ref=_IMAGE_REF, known_good=good, known_bad=bad,
            budget=ResourceBudget(wall_clock_seconds=120.0), trials=1)
        signing_key = SigningKey.generate()

        # the ABA excursion fixture: a DISTINCT known-bad (id != the seed's "bad") whose ADD moves
        # set_head H->H1 and whose DEPRECATE returns it H1->H — the genuine cross-store ABA.
        scheduler = AbaInjectionScheduler(
            real_cs=cs, policy_store=ps, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1",
            fresh_fixture=Fixture(
                fixture_id="aba-freshbad", label=FixtureLabel.KNOWN_BAD,
                payload=(_CORPUS / "retry-swallow-v1" / "main.py").read_bytes(),
                evasion_class="exception-swallowing"))

        config = EnforcementRunConfig(
            scenario=ScenarioId.ABA_GENERATION_MOVED, policy_store=ps,
            calibration_store=scheduler.calibration_store,  # WRAPPED; real view reads through it
            seed=prov, image_ref=_IMAGE_REF,
            artifact_dir=_CORPUS / "retry-good-v1",  # unused (artifact_source overrides); required
            runs_dir=tmp / "runs", signing_key=signing_key, verify_key=signing_key.verify_key,
            registry=Registry(tmp / "registry.db"), head_sha="a" * 40, trials=1,
            budget=ResourceBudget(wall_clock_seconds=120.0),
            artifact_source=scheduler.artifact_source, fault_scheduler=scheduler)

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # the below-seam ABA drove the REAL admission to POLICY_GENERATION_MOVED (a blocking
        # refusal, NOT a fabricated result) — the generation bracket caught what set_head could not.
        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "policy_generation_moved")

        # the scheduler COMPLETED a genuine ABA: real-read heads returned (H==H) after a real
        # excursion (H1) across a real generation move — all values are anti-self-attesting reads.
        disc = scheduler.require_completed_disclosure()
        self.assertEqual(disc["head_bound"], disc["head_returned"])
        self.assertNotEqual(disc["head_moved"], disc["head_bound"])
        self.assertNotEqual(disc["policy_head_post"], disc["policy_head_pre"])

        # the signed v3 chain verifies AND is ADMISSIBLE — the observed refutation CONFIRMS the
        # signed prediction (expected == observed): what makes it evidence, not a mirror.
        self.assertTrue(chain.is_admitted)
        pp, ep = chain.prereg.payload, chain.execution.payload
        self.assertEqual(pp["scenario"], "aba_generation_moved")
        self.assertEqual(pp["expected_kind"], expected_for(ScenarioId.ABA_GENERATION_MOVED).kind)
        self.assertEqual(pp["expected_reason"], "policy_generation_moved")
        self.assertEqual(ep["result_kind"], "blocking_refusal")
        self.assertEqual(ep["result_reason"], "policy_generation_moved")
        # coherence law (sealed): a blocking_refusal is a completed run rejected at admission → it
        # carries a real (admission) ERROR verdict, so gate_outcome is run_verdict not block_gate.
        self.assertEqual(ep["gate_outcome"], "run_verdict")
        # the fault disclosure in the receipt IS the scheduler's COMPLETED induction record (not a
        # free config literal): what the harness actually did, gated on the injection completing.
        self.assertEqual(ep["fault_injection"], disc)
        # the prereg was PERSISTED at mint (orphan-prereg audit survives even a refused run).
        self.assertTrue((tmp / "runs" / chain.prereg.run_id / "prereg.json").exists())


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class DegradedScenarioEvidenceTests(unittest.TestCase):
    """NON_ENABLED_DEGRADED end-to-end: a formerly-ENABLED policy transitioned to DEGRADED (a REAL
    revocation) must BLOCK — a non-run with block_action_required, never a silent neutral. The
    signed chain is ADMISSIBLE because the observed block CONFIRMS the prediction (the invariant "a
    revoked control keeps controlling": expecting BLOCK is what makes an observed SKIP_NEUTRAL a
    fail). The engine is never reached (the disposition refuses before the sandbox)."""

    def test_degraded_policy_yields_signed_admissible_nonrun_block(self) -> None:
        from gate.authority import GovernanceApproval
        from gate.policy_state import PolicyState

        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-degraded-"))
        ps, cs, prov = _seed(tmp)
        # revoke: ENABLED -> DEGRADED via gated's REAL transition (dual-principal approval).
        ps.transition(
            "uat-enforce", PolicyState.DEGRADED,
            approval=GovernanceApproval(
                principals=("uat-op-1", "uat-op-2"), purpose="uat-degrade",
                rationale="revoke a live control to prove it keeps blocking",
                operation_id="uat-degrade"))
        signing_key = SigningKey.generate()

        config = EnforcementRunConfig(
            scenario=ScenarioId.NON_ENABLED_DEGRADED, policy_store=ps, calibration_store=cs,
            seed=prov, image_ref=_IMAGE_REF, artifact_dir=_CORPUS / "retry-good-v1",
            runs_dir=tmp / "runs", signing_key=signing_key, verify_key=signing_key.verify_key,
            registry=Registry(tmp / "registry.db"), head_sha="a" * 40, trials=1,
            budget=ResourceBudget(wall_clock_seconds=120.0))

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # a DEGRADED policy BLOCKS (fail-closed) as a non-run — never falls silent to neutral.
        self.assertEqual(outcome.result_kind, "non_run")
        self.assertEqual(outcome.reason, "block_action_required")
        # predicted-and-observed block → admissible evidence.
        self.assertTrue(chain.is_admitted)
        pp, ep = chain.prereg.payload, chain.execution.payload
        self.assertEqual(pp["expected_kind"], "non_run")
        self.assertEqual(pp["expected_reason"], "block_action_required")
        self.assertEqual(ep["result_kind"], "non_run")
        # coherence law: a non_run carrying BLOCK_ACTION_REQUIRED is a block_gate, not neutral_gate.
        self.assertEqual(ep["gate_outcome"], "block_gate")
        # a non_run dispatched no plan → an EXPLICIT null plan policy (present-and-null, not gone).
        self.assertIsNone(ep["plan_policy_id"])
        self.assertTrue((tmp / "runs" / chain.prereg.run_id / "prereg.json").exists())


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF) and _podman_image_available(_IMAGE_REF_2),
    f"{_IMAGE_REF} + {_IMAGE_REF_2} both required in the Podman image store",
)
class SubjectDriftScenarioEvidenceTests(unittest.TestCase):
    """SUBJECT_DRIFT_SECOND_IMAGE end-to-end: the artifact tree is SHA-bind-protected, so drift is
    induced via the IMAGE coordinate. Calibrate on ``_IMAGE_REF``, enforce on a DISTINCT image
    (``_IMAGE_REF_2``): the measured execution identity differs from the calibrated subject → the
    measured composite != the dispatched target → admit refuses (SUBJECT_DRIFT). The signed chain is
    ADMISSIBLE (the drift was predicted) and continuity binds the seed image ≠ the run image."""

    def test_second_image_yields_signed_admissible_subject_drift(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-drift-"))
        ps, cs, prov = _seed(tmp, image_ref=_IMAGE_REF)  # calibrated on image 1
        signing_key = SigningKey.generate()

        config = EnforcementRunConfig(
            scenario=ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE, policy_store=ps, calibration_store=cs,
            seed=prov, image_ref=_IMAGE_REF_2,  # ENFORCE on image 2 — a distinct execution identity
            artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs", signing_key=signing_key,
            verify_key=signing_key.verify_key, registry=Registry(tmp / "registry.db"),
            head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0))

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # a second-image run measures a drifted subject → a blocking refusal, never a silent pass.
        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "subject_drift")
        self.assertTrue(chain.is_admitted)
        pp, ep = chain.prereg.payload, chain.execution.payload
        self.assertEqual(pp["expected_reason"], "subject_drift")
        self.assertEqual(ep["result_kind"], "blocking_refusal")
        self.assertEqual(ep["gate_outcome"], "run_verdict")  # a refused completed run
        # continuity: the configured RUN image == rc_image_digest, and the SEED image differs from
        # it (the drift endpoints) — the schema's subject_drift continuity binding, proven live.
        self.assertEqual(ep["drift_image_digest"], pp["rc_image_digest"])
        self.assertNotEqual(ep["seed_trace"]["seed_image_digest"], pp["rc_image_digest"])
        self.assertEqual(ep["seed_trace"]["seed_image_digest"], prov.seed_image_digest)


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class ShaTamperScenarioEvidenceTests(unittest.TestCase):
    """SHA_TAMPER end-to-end: a TOCTOU tamper (mutate the tree AFTER the SHA-bind) is caught by the
    sandbox re-verify → InfrastructureFailure(ARTIFACT_INTEGRITY_MISMATCH). The signed chain is a
    valid record whose observed triple CONFIRMS the prediction — yet it is NON-admissible (amendment
    3: infra proves the plumbing held, not that the gate judged; infra is never enforcement
    evidence, even when predicted+matched). The tamper is disclosed via the scheduler's COMPLETED
    record (demanded by ``enforce``)."""

    def test_sha_tamper_yields_signed_nonadmissible_infra_failure(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-tamper-"))
        ps, cs, prov = _seed(tmp)
        signing_key = SigningKey.generate()
        tamper = TamperInjectionScheduler(artifact_dir=_CORPUS / "retry-good-v1")

        config = EnforcementRunConfig(
            scenario=ScenarioId.SHA_TAMPER, policy_store=ps, calibration_store=cs, seed=prov,
            image_ref=_IMAGE_REF, artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs",
            signing_key=signing_key, verify_key=signing_key.verify_key,
            registry=Registry(tmp / "registry.db"), head_sha="a" * 40, trials=1,
            budget=ResourceBudget(wall_clock_seconds=120.0),
            artifact_source=tamper.artifact_source, fault_scheduler=tamper)

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # the SHA-bind caught the post-hash mutation → a blocking infra failure, never a pass.
        self.assertEqual(outcome.result_kind, "infrastructure_failure")
        self.assertEqual(outcome.reason, "artifact_integrity_mismatch")
        pp, ep = chain.prereg.payload, chain.execution.payload
        # the PREDICTION was correct (observed triple == expected triple) ...
        self.assertEqual(enforcement_observed_triple(ep), enforcement_expected_triple(pp))
        # ... yet the chain is NON-admissible: infra is never enforcement evidence (amendment 3).
        self.assertFalse(chain.is_admitted)
        # the tamper disclosure IS the scheduler's COMPLETED record — the sealed schema's base
        # disclosure triple (locus / mechanism / interleaving_point), all non-empty.
        disc = tamper.require_completed_disclosure()
        self.assertEqual(ep["fault_injection"], disc)
        self.assertEqual(set(disc), {"locus", "mechanism", "interleaving_point"})
        self.assertTrue((tmp / "runs" / chain.prereg.run_id / "prereg.json").exists())


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class CustomSourceAdmittedRefutationTests(unittest.TestCase):
    """The FIFTH permanent refutation fixture (P1 regression guard): the refutation channel must
    serialise END-TO-END through a CUSTOM ``artifact_source`` — the path the ABA/tamper scenarios
    use — on the single most important observation an injection scenario can produce: the gate
    UNEXPECTEDLY ADMITTING under the fault. A custom source that bypassed the
    ``captured['tree_hash']`` wiring the happy path populated would kill receipt ASSEMBLY with a
    KeyError on that admitted result — silently breaking refutability for exactly the observation
    that matters, while the other scenarios stay green (their expected refusal/infra shapes never
    demand ``artifact_tree_hash``). Capture now happens at the source-SELECTION seam, so this holds
    by construction.

    Realised HONESTLY: a refusal-predicting scenario (NON_ENABLED_DEGRADED) is run with a CUSTOM
    source but the policy left ENABLED (never degraded), so the REAL gate ADMITS. The prediction was
    wrong; the harness must record that as a VALID signed chain that FAILS admissibility — not die
    on a KeyError. (The four schema-layer round-trips proved refutations serialise per KIND; this
    proves it per SOURCE-PATH at the assembly layer.)"""

    def test_custom_source_admitted_result_is_a_valid_inadmissible_refutation(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-custom-admit-"))
        ps, cs, prov = _seed(tmp)  # ENABLED — deliberately NOT degraded, so the gate will ADMIT
        signing_key = SigningKey.generate()

        def _plain_custom_source(event: Any, ws: Path) -> Any:
            # a CUSTOM source that stages a compliant tree and does NOT touch ``captured`` — exactly
            # the bypass the central capturing-wrap must cover.
            from gate.artifact import build_artifact_spec
            dest = ws / "src"
            shutil.copytree(_CORPUS / "retry-good-v1", dest)
            return build_artifact_spec(dest)

        config = EnforcementRunConfig(
            # predicts non_run/block_action_required, but the ENABLED policy + compliant tree ADMIT
            scenario=ScenarioId.NON_ENABLED_DEGRADED, policy_store=ps, calibration_store=cs,
            seed=prov, image_ref=_IMAGE_REF, artifact_dir=_CORPUS / "retry-good-v1",
            runs_dir=tmp / "runs", signing_key=signing_key, verify_key=signing_key.verify_key,
            registry=Registry(tmp / "registry.db"), head_sha="a" * 40, trials=1,
            budget=ResourceBudget(wall_clock_seconds=120.0),
            artifact_source=_plain_custom_source)  # CUSTOM source; no fault_scheduler needed

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # the gate ADMITTED (ENABLED + compliant) — the scenario's prediction (block) was REFUTED.
        self.assertEqual(outcome.result_kind, "admitted_run")
        self.assertEqual(outcome.outcome, "pass")
        pp, ep = chain.prereg.payload, chain.execution.payload
        # the chain SERIALISED through the custom-source path — the admitted coordinate that a
        # tree_hash bypass would have KeyError'd is PRESENT (assembly-layer refutability holds).
        self.assertEqual(ep["result_kind"], "admitted_run")
        self.assertIn("artifact_tree_hash", ep)
        self.assertTrue(ep["artifact_tree_hash"].startswith("sha256:"))
        # ... and admissibility FAILS: admitted/pass != the predicted non_run/block_action_required.
        self.assertFalse(chain.is_admitted)
        self.assertEqual(pp["expected_kind"], "non_run")
        self.assertEqual(pp["expected_reason"], "block_action_required")
        self.assertTrue((tmp / "runs" / chain.prereg.run_id / "prereg.json").exists())


def _fresh_bad(fixture_id: str) -> Fixture:
    """A KNOWN_BAD fixture NOT already in the seeded set (the SET_HEAD_STALE excursion fixture)."""
    return Fixture(
        fixture_id=fixture_id, label=FixtureLabel.KNOWN_BAD,
        payload=(_CORPUS / "retry-swallow-v1" / "main.py").read_bytes(),
        evasion_class="exception-swallowing")


def _run_unarmed_compliant(
    tmp: Path, ps: PolicyStore, cs: Any, prov: Any) -> tuple[Any, Any]:
    """A FULL COMPLIANT_ADMIT run over the passed stores — used as each 2.2a scheduler's NEGATIVE
    CONTROL with the scheduler's WRAPPED store passed in but NEVER armed (no arming artifact_source,
    no fault_scheduler). The wrapped accessor is exercised at BOTH the plan-mint read AND the live
    admit read across the WHOLE enforce pipeline; disarmed it passes through, so the run ADMITS.
    This is the 'wrapper is transparent when not armed, end-to-end' half — proving the armed test's
    refusal is caused by the INJECTION, not the wrapper's mere presence (esp. Class-B: normal
    availability admits)."""
    sk = SigningKey.generate()
    config = EnforcementRunConfig(
        scenario=ScenarioId.COMPLIANT_ADMIT, policy_store=ps, calibration_store=cs, seed=prov,
        image_ref=_IMAGE_REF, artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs",
        signing_key=sk, verify_key=sk.verify_key, registry=Registry(tmp / "registry.db"),
        head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0))
    return GatedEnforcementAdapter().enforce(config)


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class SetHeadStaleScenarioEvidenceTests(unittest.TestCase):
    """SET_HEAD_STALE (slice 2.2a, Class A): a real fixture append between plan-mint and admit moves
    the live set_head off the bound head → admit refuses set_head_stale. A completed run rejected at
    admission (blocking_refusal, run_verdict), and the harness's own path judges it admissible."""

    def test_set_head_stale_yields_signed_admissible_refusal(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-stale-"))
        ps, cs, prov = _seed(tmp)
        signing_key = SigningKey.generate()
        sched = SetHeadStaleScheduler(
            real_cs=cs, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1", fresh_fixture=_fresh_bad("stale-freshbad"))
        # NEGATIVE CONTROL (disarmed passthrough): the wrapper is transparent until armed, so the
        # refusal comes from the ARMED injection at admit, not the wrapper's mere presence.
        self.assertEqual(sched.calibration_store.set_head(prov.set_id), cs.set_head(prov.set_id))

        config = EnforcementRunConfig(
            scenario=ScenarioId.SET_HEAD_STALE, policy_store=ps,
            calibration_store=sched.calibration_store, seed=prov, image_ref=_IMAGE_REF,
            artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs", signing_key=signing_key,
            verify_key=signing_key.verify_key, registry=Registry(tmp / "registry.db"),
            head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0),
            artifact_source=sched.artifact_source, fault_scheduler=sched)
        outcome, chain = GatedEnforcementAdapter().enforce(config)

        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "set_head_stale")
        self.assertEqual(outcome.sub_reason, "")
        self.assertTrue(chain.is_admitted)
        ep = chain.execution.payload
        self.assertEqual(ep["gate_outcome"], "run_verdict")  # a completed run refused at admission
        # the plan WAS minted (disarmed passthrough) — the injection fired POST-mint at admit
        self.assertEqual(ep["plan_policy_id"], "uat-enforce")
        disc = sched.require_completed_disclosure()  # INTERLEAVE PROOF: fired at the oracle read
        self.assertIn("oracle_head_for", disc["locus"])
        self.assertEqual(ep["fault_injection"], disc)

    def test_unarmed_wrapped_store_admits_full_run(self) -> None:
        # NEGATIVE CONTROL (full unarmed run): the SAME wrapped calibration store, never armed →
        # transparent through the whole pipeline → the run ADMITS. The armed test's set_head_stale
        # refusal is thus caused by the injected append, not the wrapper.
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-stale-neg-"))
        ps, cs, prov = _seed(tmp)
        sched = SetHeadStaleScheduler(
            real_cs=cs, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1", fresh_fixture=_fresh_bad("stale-neg"))
        outcome, chain = _run_unarmed_compliant(tmp, ps, sched.calibration_store, prov)
        self.assertEqual(outcome.result_kind, "admitted_run")
        self.assertEqual(outcome.outcome, "pass")
        self.assertTrue(chain.is_admitted)
        with self.assertRaises(EnforcementEvidenceError):  # never fired → never COMPLETED
            sched.require_completed_disclosure()


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class OracleUnavailableScenarioEvidenceTests(unittest.TestCase):
    """ORACLE_UNAVAILABLE (slice 2.2a, Class B fault simulation): the armed cs.set_head RAISES the
    exact ChainIntegrityError CalibrationStore.set_head raises on a real store fault; admit maps any
    oracle_head_for exception to oracle_unavailable / store_unreachable."""

    def test_oracle_unavailable_yields_signed_admissible_refusal(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-oracle-"))
        ps, cs, prov = _seed(tmp)
        signing_key = SigningKey.generate()
        sched = OracleUnavailableScheduler(
            real_cs=cs, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1")
        # NEGATIVE CONTROL (disarmed passthrough): disarmed set_head returns the real head, no fault
        # — transparent until armed.
        self.assertEqual(sched.calibration_store.set_head(prov.set_id), cs.set_head(prov.set_id))

        config = EnforcementRunConfig(
            scenario=ScenarioId.ORACLE_UNAVAILABLE, policy_store=ps,
            calibration_store=sched.calibration_store, seed=prov, image_ref=_IMAGE_REF,
            artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs", signing_key=signing_key,
            verify_key=signing_key.verify_key, registry=Registry(tmp / "registry.db"),
            head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0),
            artifact_source=sched.artifact_source, fault_scheduler=sched)
        outcome, chain = GatedEnforcementAdapter().enforce(config)

        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "oracle_unavailable")
        self.assertEqual(outcome.sub_reason, "store_unreachable")  # raise path, not unresolved
        self.assertTrue(chain.is_admitted)
        ep = chain.execution.payload
        self.assertEqual(ep["gate_outcome"], "run_verdict")
        self.assertEqual(ep["plan_policy_id"], "uat-enforce")
        disc = sched.require_completed_disclosure()
        self.assertIn("oracle_head_for", disc["locus"])
        self.assertEqual(ep["fault_injection"], disc)

    def test_unarmed_wrapped_store_admits_full_run(self) -> None:
        # NEGATIVE CONTROL (full unarmed run) — the mandatory Class-B honesty condition: when the
        # oracle store is AVAILABLE (the wrapper never raises because it is never armed), the SAME
        # setup ADMITS end-to-end. Proves oracle_unavailable/store_unreachable is the injected
        # RAISE, not an artifact of routing set_head through the wrapper.
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-oracle-neg-"))
        ps, cs, prov = _seed(tmp)
        sched = OracleUnavailableScheduler(
            real_cs=cs, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1")
        outcome, chain = _run_unarmed_compliant(tmp, ps, sched.calibration_store, prov)
        self.assertEqual(outcome.result_kind, "admitted_run")
        self.assertEqual(outcome.outcome, "pass")
        self.assertTrue(chain.is_admitted)
        with self.assertRaises(EnforcementEvidenceError):  # never raised → never COMPLETED
            sched.require_completed_disclosure()


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class LiveAttestationUnavailableScenarioEvidenceTests(unittest.TestCase):
    """LIVE_ATTESTATION_UNAVAILABLE (slice 2.2a, Class A): a real ENABLED→DEGRADED transition at the
    attestation read, then CALL THROUGH — the real snapshot returns None (policy no longer ENABLED),
    so admit refuses live_attestation_unavailable / attestation_absent."""

    def test_live_attestation_unavailable_yields_signed_admissible_refusal(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-liveattn-"))
        ps, cs, prov = _seed(tmp)
        signing_key = SigningKey.generate()
        sched = LiveAttestationUnavailableScheduler(
            real_ps=ps, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1")
        # NEGATIVE CONTROL (disarmed passthrough): disarmed snapshot returns the real ENABLED tuple.
        self.assertEqual(
            sched.policy_store.current_attestation_snapshot("uat-enforce"),
            ps.current_attestation_snapshot("uat-enforce"))

        config = EnforcementRunConfig(
            scenario=ScenarioId.LIVE_ATTESTATION_UNAVAILABLE, policy_store=sched.policy_store,
            calibration_store=cs, seed=prov, image_ref=_IMAGE_REF,
            artifact_dir=_CORPUS / "retry-good-v1", runs_dir=tmp / "runs", signing_key=signing_key,
            verify_key=signing_key.verify_key, registry=Registry(tmp / "registry.db"),
            head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0),
            artifact_source=sched.artifact_source, fault_scheduler=sched)
        outcome, chain = GatedEnforcementAdapter().enforce(config)

        self.assertEqual(outcome.result_kind, "blocking_refusal")
        self.assertEqual(outcome.reason, "live_attestation_unavailable")
        self.assertEqual(outcome.sub_reason, "attestation_absent")
        self.assertTrue(chain.is_admitted)
        ep = chain.execution.payload
        self.assertEqual(ep["gate_outcome"], "run_verdict")
        self.assertEqual(ep["plan_policy_id"], "uat-enforce")
        disc = sched.require_completed_disclosure()
        self.assertIn("current_attestation", disc["locus"])
        self.assertEqual(ep["fault_injection"], disc)

    def test_unarmed_wrapped_store_admits_full_run(self) -> None:
        # NEGATIVE CONTROL (full unarmed run): the SAME wrapped policy store, never armed → the
        # attestation read passes through the live ENABLED snapshot → the run ADMITS. The armed
        # test's live_attestation_unavailable/attestation_absent refusal is thus caused by the
        # injected ENABLED→DEGRADED transition, not by wrapping current_attestation_snapshot.
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-liveattn-neg-"))
        ps, cs, prov = _seed(tmp)
        sched = LiveAttestationUnavailableScheduler(
            real_ps=ps, policy_id="uat-enforce", set_id=prov.set_id,
            artifact_dir=_CORPUS / "retry-good-v1")
        outcome, chain = _run_unarmed_compliant(tmp, sched.policy_store, cs, prov)
        self.assertEqual(outcome.result_kind, "admitted_run")
        self.assertEqual(outcome.outcome, "pass")
        self.assertTrue(chain.is_admitted)
        with self.assertRaises(EnforcementEvidenceError):  # never transitioned → never COMPLETED
            sched.require_completed_disclosure()


class WiringPinTests(unittest.TestCase):
    """Structural-maintenance guard — no podman, no build() invocation. Pins production's decision
    wiring so a change forces re-verification of the adapter's replica closure."""

    def test_production_build_wires_the_decision_the_adapter_replicates(self) -> None:
        from gate import live_app

        src = inspect.getsource(live_app.build)
        # the production resolve_decision closure the adapter's replica mirrors EXACTLY.
        self.assertIn("resolve_disposition(", src)
        self.assertIn("snapshot=None", src)
        self.assertIn("oracle_head_for=calibration_store.set_head", src)
        # ... and the governance view + job runner the adapter reuses/drives.
        self.assertIn("_ProductionAdmissionGovernanceView(", src)
        self.assertIn("make_gated_job_runner(", src)

    def test_adapter_replica_uses_the_same_decision_call(self) -> None:
        # the adapter's replica must call resolve_disposition with snapshot=None and the live
        # set_head oracle — the same operands production binds (checked above). A drift here (e.g.
        # someone passes a snapshot) diverges from production and is caught.
        src = inspect.getsource(GatedEnforcementAdapter.enforce)
        self.assertIn("resolve_disposition(", src)
        self.assertIn("snapshot=None", src)
        self.assertIn("oracle_head_for=cs.set_head", src)


if __name__ == "__main__":
    unittest.main()
