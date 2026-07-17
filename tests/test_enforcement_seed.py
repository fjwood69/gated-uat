"""tests/test_enforcement_seed.py — Phase 2 slice 2.1a: the real-governance enforcement seed.

Proves ``seed_enabled_policy`` brings a policy to ENABLED through gated's REAL lifecycle
(``run_calibration`` + ``ratify_enable``) such that the REAL ``resolve_disposition`` mints a
RUN_ENFORCING ``AuthorizedRunPlan`` over the seeded stores — the faithful precondition for the
live-enforcement path, with no harness-composed governance inputs (no direct rows, no shortcut pass,
no hand-assembled subject/head).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from core import ResourceBudget
from core.calibration import Fixture, FixtureLabel
from gate.calibration_store import CalibrationStore
from gate.gatekeeper import resolve_disposition
from gate.policy_state import Disposition, PolicyState
from gate.policy_store import PolicyStore

from orchestrator.enforcement_driver import SeedProvenance, seed_enabled_policy

_IMAGE_REF = "localhost/mori:local"
_CORPUS = Path(__file__).resolve().parent.parent / "corpora" / "fixtures"


def _podman_image_available(image_ref: str) -> bool:
    if not shutil.which("podman"):
        return False
    return subprocess.run(
        ["podman", "image", "exists", image_ref], capture_output=True
    ).returncode == 0


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF), f"{_IMAGE_REF} not present in Podman image store"
)
class EnforcementSeedTests(unittest.TestCase):
    def test_seed_yields_a_real_enabled_policy_that_mints_a_plan(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-uat-enf-"))
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
            budget=ResourceBudget(wall_clock_seconds=120.0), trials=1,
        )

        # the policy is REALLY ENABLED, every provenance value measured (never harness-supplied)
        self.assertIsInstance(prov, SeedProvenance)
        self.assertIs(ps.current_state("uat-enforce"), PolicyState.ENABLED)
        self.assertTrue(prov.subject and prov.calibration_result_ref and prov.policy_head)
        self.assertEqual(prov.policy_head, ps.policy_head("uat-enforce"))
        self.assertEqual(prov.pinned_set_version, cs.set_head("default"))

        # the REAL resolve_disposition mints a RUN_ENFORCING plan for the seeded subject — the
        # faithful precondition the enforcement adapter (2.1b) drives through make_gated_job_runner.
        decision = resolve_disposition(
            "uat-enforce", store=ps, snapshot=None, snapshot_key=b"",
            now=time.time(), oracle_head_for=cs.set_head,
        )
        self.assertIs(decision.disposition, Disposition.RUN_ENFORCING)
        assert decision.plan is not None
        self.assertEqual(decision.plan.policy_id, "uat-enforce")
        self.assertEqual(decision.plan.target_subject, prov.subject)


if __name__ == "__main__":
    unittest.main()
