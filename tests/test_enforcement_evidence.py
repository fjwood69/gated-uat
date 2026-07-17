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
    def test_compliant_run_yields_admitted_signed_v3_chain(self) -> None:
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

        image_digest = _resolve_image_digest(_IMAGE_REF)
        self.assertIsNotNone(image_digest)
        assert image_digest is not None
        signing_key = SigningKey.generate()

        config = EnforcementRunConfig(
            policy_store=ps, calibration_store=cs, seed=prov, image_ref=_IMAGE_REF,
            toolchain_image_digest=image_digest, gated_commit="1d75d54",
            # a COMPLIANT candidate tree: retry-good-v1 retries 3x → RetryCheck PASS under the
            # observed backend (the same fixture the seed calibrated as known-good).
            artifact_dir=_CORPUS / "retry-good-v1", signing_key=signing_key,
            verify_key=signing_key.verify_key, registry=Registry(tmp / "registry.db"),
            head_sha="a" * 40, trials=1, budget=ResourceBudget(wall_clock_seconds=120.0))

        outcome, chain = GatedEnforcementAdapter().enforce(config)

        # the run was ADMITTED with a PASS verdict (measured subject == the seeded subject).
        self.assertEqual(outcome.result_kind, "admitted_run")
        self.assertEqual(outcome.outcome, "pass")

        # the signed v3 chain verifies AND is admissible via the harness's own public path.
        self.assertTrue(chain.is_admitted)
        ep = chain.execution.payload
        self.assertEqual(ep["schema_version"], 3)
        self.assertEqual(chain.prereg.payload["schema_version"], 3)
        # the enforced policy is the PREREGISTERED one (semantic continuity binds them).
        self.assertEqual(chain.prereg.payload["policy_id"], "uat-enforce")
        self.assertEqual(ep["plan_policy_id"], "uat-enforce")
        self.assertEqual(ep["result_kind"], "admitted_run")
        self.assertEqual(ep["result_sub_reason"], "")
        self.assertEqual(ep["gate_outcome"], "run_verdict")

        # BOTH admission-bracket heads bound to the live governance the run was admitted against.
        self.assertEqual(ep["policy_generation"], ps.policy_head("uat-enforce"))
        self.assertEqual(ep["bound_oracle_head"], cs.set_head("default"))
        self.assertEqual(ep["bound_oracle_head"], prov.pinned_set_version)

        # run-context coordinates the sandbox MEASURED (bare 64-hex digests).
        for field_name in (
            "resolved_profile_digest", "trust_policy_digest",
            "guard_policy_digest", "execution_identity_digest",
        ):
            self.assertEqual(len(ep[field_name]), 64, field_name)
        # the artifact tree hash + image are sha256:<hex64> content addresses (what actually ran).
        self.assertTrue(ep["artifact_tree_hash"].startswith("sha256:"))
        self.assertEqual(len(ep["artifact_tree_hash"]), 71)
        self.assertTrue(ep["image_digest"].startswith("sha256:"))
        self.assertEqual(ep["detector_id"], "RetryCheck")


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
