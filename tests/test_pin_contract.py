"""tests/test_pin_contract.py — Phase 2 slice 2.0: the pin-boundary contract.

Two guards that make a `gated` pin bump SAFE rather than self-consistently green:

1. PIN PROVENANCE GOLDEN (podman-gated). Runs the real GatedCalibrationAdapter and
   asserts the five receipt-consumed provenance values equal the LITERALS in the pinned
   provenance contract ``goldens/pin_provenance.json`` (four captured at the prior pin
   628e5a3; ``execution_identity_digest`` rebaselined to 1d75d54 by board ruling — a
   legitimate observer-config change, documented in the golden). Because the goldens are
   fixed literals — never re-derived from the pinned code at test time — a pin bump
   that changes any provenance digest FAILS here instead of silently re-baselining the
   signed receipt contract. A failure is an explicit board decision (legitimate
   re-baseline + receipt-schema note, or regression), never an automatic update.

   The five digests are fixture-set- and trial-count-independent (all content/config
   derived), so the fast 2-fixture/trials=1 config is used and the golden is valid for
   any run shape. The OCI image is bound BY DIGEST two ways: the adapter receives the
   golden's immutable ``_image_digest`` as its execution reference (BELT — what runs is
   what's attested, the mutable tag is out of the trust path), AND a tag->digest preflight
   asserts ``localhost/mori:local`` currently resolves to that digest (ALARM — a local
   image rebuild surfaces as a loud mismatch at run start, never a confusing green).

2. STRUCTURAL CONTRACT (pure import, always runs). Freezes the exact gated
   ``CalibrationResult`` field set and the exact receipt provenance key set as literal
   frozensets. A future gated change that ADDS or REMOVES a provenance field trips at
   the pin boundary — forcing review (e.g. a new additive security field is a decision,
   not a silent drop from the receipt), rather than being absorbed unnoticed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from core import ResourceBudget
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from engine.calibration import CalibrationResult

from orchestrator.calibration_driver import CalibrationRequest, GatedCalibrationAdapter, GuardSpec
from orchestrator.schemas import _EXECUTION_KEYS_V2

_IMAGE_REF = "localhost/mori:local"
_CORPUS = Path(__file__).resolve().parent.parent / "corpora" / "fixtures"
_GOLDEN = Path(__file__).resolve().parent / "goldens" / "pin_provenance.json"

# The exact field set of gated's CalibrationResult, frozen at the ratified pin contract
# (verified identical at 628e5a3 and 1d75d54). ``identity_consistent`` is present-and-ignored
# by the adapter; it is part of the contract so an ADD/REMOVE trips this assertion.
_EXPECTED_CALIBRATION_RESULT_FIELDS: frozenset[str] = frozenset({
    "passed", "inadequate", "fn_failures", "fp_failures", "flaky", "harness_errors",
    "outcomes", "execution_identity", "identity_consistent",
    "resolved_profile_digest", "trust_policy_digest", "guard_policy_digest", "policies_consistent",
})

# The exact provenance keys the schema-v2 execution receipt binds. A change to gated's
# provenance surface must be a DECISION about the receipt, caught here.
_EXPECTED_RECEIPT_PROVENANCE_KEYS: frozenset[str] = frozenset({
    "resolved_profile_digest", "trust_policy_digest", "guard_policy_digest",
    "execution_identity_digest", "policies_consistent",
})

# The exact FULL schema-v2 execution-receipt key set, frozen as a literal and asserted for
# BOTH-DIRECTION equality (not subset): an ADDED receipt key is caught as well as a removed one,
# so a change to WHAT the receipt binds is a review decision, never silently absorbed.
_EXPECTED_EXECUTION_KEYS_V2: frozenset[str] = frozenset({
    "canonical_digest_alg", "canonical_digest_version", "executed_at", "execution_identity_digest",
    "gated_commit", "guard_policy_digest", "observer_log_digest", "observer_log_truncated",
    "outcome", "policies_consistent", "prereg_digest", "profile", "resolved_profile_digest",
    "runtime_pack_digest", "schema_version", "trust_policy_digest",
})


def _podman_image_available(image_ref: str) -> bool:
    if not shutil.which("podman"):
        return False
    return subprocess.run(
        ["podman", "image", "exists", image_ref], capture_output=True
    ).returncode == 0


class GatedContractStructureTests(unittest.TestCase):
    """Pure-import structural guards — always run, catch pin-boundary field drift."""

    def test_calibration_result_field_set_is_frozen(self) -> None:
        actual = frozenset(CalibrationResult.__dataclass_fields__)
        self.assertEqual(
            actual, _EXPECTED_CALIBRATION_RESULT_FIELDS,
            "gated CalibrationResult field set changed at the pin. This is a DECISION, not a "
            "silent absorption: a new field may be receipt-relevant (add it to the receipt + "
            "golden) or ignorable (extend the frozenset). Do not auto-pass.",
        )

    def test_accepted_profile_digest_matches_the_slice_2_0_golden(self) -> None:
        # dissent P1 (independent acceptance): the digest the seed + enforcement registries inject
        # as accepted_profile_digest MUST be the slice-2.0 golden literal, not a runtime
        # self-computed value. Cross-check the two so a change to either is a caught board decision,
        # and acceptance stays independent of the value the registry itself computes.
        from orchestrator.gated_pin import ACCEPTED_RETRYCHECK_PROFILE_DIGEST

        golden = json.loads(_GOLDEN.read_text())
        self.assertEqual(
            ACCEPTED_RETRYCHECK_PROFILE_DIGEST, golden["resolved_profile_digest"],
            "the injected accepted RetryCheck profile digest drifted from the slice-2.0 provenance "
            "contract — reconcile gated_pin.ACCEPTED_RETRYCHECK_PROFILE_DIGEST with the golden "
            "(a board decision, not an auto-update).")

    def test_receipt_execution_key_set_is_frozen(self) -> None:
        # BOTH-DIRECTION equality against the full literal set: catches an ADDED receipt key (a
        # subset/presence check would silently miss it) as well as a removed one. A change to the
        # execution-receipt contract is a review decision, never silently shipped.
        self.assertEqual(
            _EXECUTION_KEYS_V2, _EXPECTED_EXECUTION_KEYS_V2,
            "the schema-v2 execution receipt key set changed — the receipt contract moved; a new "
            "key may be receipt/golden-relevant. Review before relying on the pin.",
        )
        # the five goldened provenance keys must remain within that receipt contract.
        self.assertLessEqual(_EXPECTED_RECEIPT_PROVENANCE_KEYS, _EXPECTED_EXECUTION_KEYS_V2)


@unittest.skipUnless(
    _podman_image_available(_IMAGE_REF),
    f"{_IMAGE_REF} not present in Podman image store",
)
class PinProvenanceGoldenTests(unittest.TestCase):
    """The cross-pin differential: a real adapter run vs the pinned provenance CONTRACT (literals;
    four captured at the prior pin 628e5a3, execution_identity_digest rebaselined to 1d75d54 by
    board ruling — see the golden's documentation)."""

    def _assert_tag_resolves_to_pinned_digest(self, expected_digest: str) -> None:
        # ALARM: the mutable tag must currently resolve to the golden's pinned image digest.
        # Without this, a local rebuild of localhost/mori:local moves the tag while every run
        # keeps binding the old digest — a confusing green attesting an image that never ran.
        proc = subprocess.run(
            ["podman", "image", "inspect", "--format", "{{.Id}}", _IMAGE_REF],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, f"podman inspect {_IMAGE_REF} failed: {proc.stderr}")
        # Canonicalize: podman's .Id may or may not carry the "sha256:" prefix across versions —
        # strip any existing one, prepend exactly one (tighten to the canonical form, never loosen).
        resolved = "sha256:" + proc.stdout.strip().removeprefix("sha256:")
        self.assertEqual(
            resolved, expected_digest,
            f"{_IMAGE_REF} resolves to {resolved}, not the pinned {expected_digest} — the local "
            "image was rebuilt; restore the pinned image or re-capture the goldens (a decision).",
        )

    def _run_outcome(self, image_digest: str) -> object:
        good = (Fixture(
            fixture_id="good", label=FixtureLabel.KNOWN_GOOD,
            payload=(_CORPUS / "retry-good-v1" / "main.py").read_bytes(), evasion_class=None),)
        bad = (Fixture(
            fixture_id="bad", label=FixtureLabel.KNOWN_BAD,
            payload=(_CORPUS / "retry-swallow-v1" / "main.py").read_bytes(),
            evasion_class="exception-swallowing"),)
        request = CalibrationRequest(
            calibration_set=CalibrationSet(known_good=good, known_bad=bad),
            detector_id="RetryCheck",
            # BELT: run binds the immutable digest, not the tag — what runs is what's attested.
            guard_spec=GuardSpec(backend_kind="observed", image_ref=image_digest),
            budget=ResourceBudget(wall_clock_seconds=120.0),
            trials=1,
        )
        return GatedCalibrationAdapter().run(request)

    def test_provenance_digests_match_the_pinned_contract(self) -> None:
        golden = json.loads(_GOLDEN.read_text())
        image_digest = golden["_image_digest"]
        self._assert_tag_resolves_to_pinned_digest(image_digest)  # ALARM
        out = self._run_outcome(image_digest)                     # BELT
        for field in ("resolved_profile_digest", "trust_policy_digest", "guard_policy_digest",
                      "execution_identity_digest", "policies_consistent"):
            self.assertEqual(
                getattr(out, field), golden[field],
                f"{field} drifted from the {golden.get('_current_pin', '?')} golden — a BOARD "
                "DECISION, not an auto-rebaseline: legitimate semantic change (re-baseline the "
                "golden + note the receipt-schema version) or a regression.",
            )


if __name__ == "__main__":
    unittest.main()
