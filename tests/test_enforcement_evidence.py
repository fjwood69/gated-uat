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
