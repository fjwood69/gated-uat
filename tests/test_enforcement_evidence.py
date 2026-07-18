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
from orchestrator.expectations import ScenarioId
from orchestrator.isolation import Registry

_IMAGE_REF = "localhost/mori:local"
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
