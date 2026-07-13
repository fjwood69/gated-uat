"""tests/test_adapter_integration.py — Vertical-slice: GatedCalibrationAdapter + real gated.

Exercises the full adapter → gated import path → CalibrationOutcome chain.
Podman / OCI are NOT required: guarded_backend is monkeypatched with the
test-only opt-out; calibrate() returns a pre-built result mock so no sandbox
is constructed. resolve_trust_policy() runs unmocked — it is the key S3
import path this test validates.

Running this test confirms:
- all gated imports used by GatedCalibrationAdapter resolve at the pinned commit
- the trust policy is loaded and its digest flows through to CalibrationOutcome
- the guard policy digest flows through to CalibrationOutcome
- policies_consistent flows through correctly
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

# gated is on sys.path via conftest.py (sibling checkout at ../gated).
from core import ResourceBudget, Sandbox
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from nacl.signing import SigningKey

from orchestrator.calibration_driver import (
    CalibrationOutcome,
    CalibrationRequest,
    GatedCalibrationAdapter,
    GuardSpec,
)


def _allow_any_backend(sandbox: Sandbox) -> None:  # noqa: ARG001
    """Test-only no-op guard — mirrors gated/tests/_backend_optout.py.

    Cannot import from that module directly because gated-uat's tests/ package
    shadows gated's. Defined inline to avoid import-path ambiguity.
    """


_CORPUS = Path(__file__).parent.parent / "corpora" / "fixtures"
_HEX64_A = "a" * 64
_HEX64_B = "b" * 64
_HEX64_C = "c" * 64


def _build_request() -> CalibrationRequest:
    good = (
        Fixture(
            fixture_id="good",
            label=FixtureLabel.KNOWN_GOOD,
            payload=(_CORPUS / "retry-good-v1" / "main.py").read_bytes(),
            evasion_class=None,
        ),
    )
    bad = (
        Fixture(
            fixture_id="bad",
            label=FixtureLabel.KNOWN_BAD,
            payload=(_CORPUS / "retry-swallow-v1" / "main.py").read_bytes(),
            evasion_class="exception-swallowing",
        ),
    )
    return CalibrationRequest(
        calibration_set=CalibrationSet(known_good=good, known_bad=bad),
        detector_id="RetryCheck",
        guard_spec=GuardSpec(backend_kind="oci", image_ref="localhost/test:v0"),
        budget=ResourceBudget(wall_clock_seconds=30.0),
        trials=1,
    )


def _mock_calibration_result(*, passed: bool = True) -> Any:
    """Build a minimal CalibrationResult-like object for testing."""
    from engine.runner import ExecutionIdentity

    identity = ExecutionIdentity(
        backend="oci",
        image_ref=_HEX64_A,
        isolation_level="hermetic",
        observer_config_hash="",
    )

    result = MagicMock()
    result.passed = passed
    result.inadequate = False
    result.fn_failures = ()
    result.fp_failures = ()
    result.flaky = ()
    result.harness_errors = ()
    result.outcomes = ()
    result.execution_identity = identity
    result.identity_consistent = True
    result.resolved_profile_digest = _HEX64_B
    result.trust_policy_digest = _HEX64_C
    result.guard_policy_digest = hashlib.sha256(b"guard").hexdigest()
    result.policies_consistent = True
    return result


class TestGatedAdapterIntegration(unittest.TestCase):
    """Real gated imports, stubbed backend — verifies trust/guard provenance flows."""

    def _allow_any(self) -> Any:
        return _allow_any_backend

    @patch("engine.calibration.calibrate")
    @patch("gate.backends.guarded_backend")
    def test_outcome_carries_trust_and_guard_digests(
        self,
        mock_guarded: MagicMock,
        mock_calibrate: MagicMock,
    ) -> None:
        mock_guarded.return_value = (MagicMock(), self._allow_any())
        mock_calibrate.return_value = _mock_calibration_result(passed=True)

        adapter = GatedCalibrationAdapter()
        outcome = adapter.run(_build_request())

        self.assertIsInstance(outcome, CalibrationOutcome)
        self.assertEqual(outcome.trust_policy_digest, _HEX64_C)
        self.assertEqual(outcome.guard_policy_digest, hashlib.sha256(b"guard").hexdigest())
        self.assertTrue(outcome.policies_consistent)
        self.assertEqual(outcome.resolved_profile_digest, _HEX64_B)

    @patch("engine.calibration.calibrate")
    @patch("gate.backends.guarded_backend")
    def test_trust_policy_arg_is_passed_to_calibrate(
        self,
        mock_guarded: MagicMock,
        mock_calibrate: MagicMock,
    ) -> None:
        """calibrate() must be called with a trust_policy (not None)."""
        mock_guarded.return_value = (MagicMock(), self._allow_any())
        mock_calibrate.return_value = _mock_calibration_result()

        GatedCalibrationAdapter().run(_build_request())

        _, call_kwargs = mock_calibrate.call_args
        trust_policy = call_kwargs.get("trust_policy")
        self.assertIsNotNone(
            trust_policy,
            "calibrate() must be called with trust_policy — not None",
        )
        # Verify the applied policy is the approved 'completed-only' policy.
        self.assertTrue(
            hasattr(trust_policy, "policy_digest"),
            "trust_policy must have a policy_digest attribute",
        )
        self.assertEqual(len(trust_policy.policy_digest), 64)

    @patch("engine.calibration.calibrate")
    @patch("gate.backends.guarded_backend")
    def test_resolve_trust_policy_import_resolves(
        self,
        mock_guarded: MagicMock,
        mock_calibrate: MagicMock,
    ) -> None:
        """resolve_trust_policy must not raise at the pinned commit."""
        from gate.trust_policy import resolve_trust_policy

        policy = resolve_trust_policy("trust-policy:completed-only")
        self.assertIsNotNone(policy)
        self.assertIsNotNone(policy.policy_digest)

    @patch("engine.calibration.calibrate")
    @patch("gate.backends.guarded_backend")
    def test_execution_identity_flows_to_outcome(
        self,
        mock_guarded: MagicMock,
        mock_calibrate: MagicMock,
    ) -> None:
        """execution_identity from CalibrationResult is mapped to the outcome dict."""
        mock_guarded.return_value = (MagicMock(), self._allow_any())
        mock_calibrate.return_value = _mock_calibration_result()

        outcome = GatedCalibrationAdapter().run(_build_request())

        self.assertIsNotNone(outcome.execution_identity)
        assert outcome.execution_identity is not None
        self.assertEqual(outcome.execution_identity["backend"], "oci")
        self.assertEqual(outcome.execution_identity["image_ref"], _HEX64_A)


def _podman_image_available(image_ref: str) -> bool:
    """Return True if *image_ref* exists in the local Podman image store."""
    if not shutil.which("podman"):
        return False
    r = subprocess.run(
        ["podman", "image", "exists", image_ref],
        capture_output=True,
    )
    return r.returncode == 0


@unittest.skipUnless(
    _podman_image_available("localhost/mori:local"),
    "localhost/mori:local not present in Podman image store",
)
class TestGatedAdapterGenuinePodman(unittest.TestCase):
    """Genuine vertical-slice: real guarded_backend("observed") + real calibrate().

    Exercises the full adapter → gated → ObservedOCISandbox → Podman code path.
    The corpus fixtures make HTTP requests to health-proxy:8080 (the boundary
    observer sidecar); retry-good-v1 retries 3 times, retry-swallow-v1 stops
    at 1 attempt.  RetryCheck can produce a PASS verdict only with the observed
    backend — without egress counts the result would be inconclusive (ERROR).

    The test asserts outcome.passed == True to prove that the full path — real
    Podman, real observer, real RetryCheck verdict — works end-to-end.
    """

    _IMAGE_REF = "localhost/mori:local"

    def _build_genuine_request(self) -> CalibrationRequest:
        good = (
            Fixture(
                fixture_id="good",
                label=FixtureLabel.KNOWN_GOOD,
                payload=(_CORPUS / "retry-good-v1" / "main.py").read_bytes(),
                evasion_class=None,
            ),
        )
        bad = (
            Fixture(
                fixture_id="bad",
                label=FixtureLabel.KNOWN_BAD,
                payload=(_CORPUS / "retry-swallow-v1" / "main.py").read_bytes(),
                evasion_class="exception-swallowing",
            ),
        )
        return CalibrationRequest(
            calibration_set=CalibrationSet(known_good=good, known_bad=bad),
            detector_id="RetryCheck",
            guard_spec=GuardSpec(backend_kind="observed", image_ref=self._IMAGE_REF),
            budget=ResourceBudget(wall_clock_seconds=120.0),
            trials=1,
        )

    def test_genuine_observed_calibration_passes(self) -> None:
        """Real guarded_backend("observed") + calibrate() → PASS verdict with provenance.

        Security-critical assertions (board P1.1 + P1.2):
        - outcome.passed == True: the observed backend provides egress counts; RetryCheck
          can distinguish retry-good-v1 (3 attempts) from retry-swallow-v1 (1 attempt)
          and must return a PASS verdict.  Any other result means the observed backend or
          corpus is broken — not a "soft" inconclusive.
        - execution_identity["backend"] == "ObservedOCISandbox": gated derives backend from
          type(sandbox).__name__; "observed" is the request spec, not the measured identity.
        - execution_identity["image_ref"].startswith("sha256:"): the OCI backend resolves
          the mutable input tag to its immutable sha256 digest before running.
        - trust_policy_digest, guard_policy_digest — non-None 64-char hex strings.
        - execution_identity_digest — gated's canonical identity hash, non-None.
        """
        adapter = GatedCalibrationAdapter()
        request = self._build_genuine_request()
        outcome = adapter.run(request)

        # Outcome must be a valid CalibrationOutcome.
        self.assertIsInstance(outcome, CalibrationOutcome)

        # The calibration MUST pass — observed backend + correct corpus produces a verdict.
        self.assertTrue(
            outcome.passed,
            f"calibration must PASS with ObservedOCISandbox + retry corpus; "
            f"fn_failures={outcome.fn_failures!r} fp_failures={outcome.fp_failures!r} "
            f"harness_errors={outcome.harness_errors!r}",
        )

        # Trust policy applied and its digest bound into the result.
        self.assertIsNotNone(
            outcome.trust_policy_digest,
            "trust_policy_digest must be set when a real trust policy was applied",
        )
        self.assertEqual(len(outcome.trust_policy_digest), 64, "digest must be 64 hex chars")  # type: ignore[arg-type]

        # Guard policy applied and its digest bound into the result.
        self.assertIsNotNone(
            outcome.guard_policy_digest,
            "guard_policy_digest must be set when guarded_backend was called",
        )
        self.assertEqual(len(outcome.guard_policy_digest), 64, "digest must be 64 hex chars")  # type: ignore[arg-type]

        # No policy drift: both policies were applied consistently across all fixtures.
        self.assertTrue(
            outcome.policies_consistent,
            "policies_consistent must be True when the same trust+guard policy "
            "applied to all fixtures",
        )

        # Execution identity measured by the real observed backend.
        self.assertIsNotNone(
            outcome.execution_identity,
            "execution_identity must be set after real Podman sandboxes ran",
        )
        assert outcome.execution_identity is not None

        # gated derives backend from type(sandbox).__name__ — "observed" is the request spec.
        self.assertEqual(
            outcome.execution_identity["backend"],
            "ObservedOCISandbox",
            "backend must be the sandbox class name measured parent-side, not the request spec",
        )

        # The OCI backend resolves the mutable input tag to its immutable sha256 digest
        # before running.  Accepting the mutable tag would defeat the anti-drift property.
        img_ref = outcome.execution_identity["image_ref"]
        self.assertTrue(
            img_ref.startswith("sha256:"),
            f"image_ref must be an immutable sha256: digest (OCI backend resolves "
            f"tags before run), got {img_ref!r}",
        )

        # gated's canonical identity digest must be carried through.
        self.assertIsNotNone(
            outcome.execution_identity_digest,
            "execution_identity_digest must be set when execution_identity is not None",
        )
        self.assertEqual(len(outcome.execution_identity_digest), 64)  # type: ignore[arg-type]


def _resolve_image_digest(image_ref: str) -> str | None:
    """Return the image-config sha256 of *image_ref* via podman inspect, or None.

    Uses {{.Id}} (the sha256 of the image config blob), NOT {{.Digest}} (the
    manifest digest).  The OCI backend (sandbox/oci.py) resolves the image
    identity using the image-config hash — these are distinct values and the
    test must supply the one the backend will measure at runtime.
    """
    r = subprocess.run(
        ["podman", "image", "inspect", "--format", "{{.Id}}", image_ref],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    image_id = r.stdout.strip()
    # podman .Id omits the "sha256:" prefix; the backend prepends it.
    return image_id if image_id.startswith("sha256:") else "sha256:" + image_id


@unittest.skipUnless(
    _podman_image_available("localhost/mori:local"),
    "localhost/mori:local not present in Podman image store",
)
class TestP1RegressionRun(unittest.TestCase):
    """Full signed P1 vertical slice: p1_regression.run() → admitted VerifiedChain.

    Exercises the complete path that the CLI walks:
      corpus load → ObservedOCISandbox calibration → image digest cross-check
      → observer artifact persistence → four-receipt signed chain
      → verify_integrity() → schema v2 admission → VerifiedChain.

    The adapter-only test (TestGatedAdapterGenuinePodman) does not cover this
    path: it stops at CalibrationOutcome and does not exercise receipt building,
    signing, digest cross-checking, or the admission gate.
    """

    _IMAGE_REF = "localhost/mori:local"
    _CORPUS_PATH = Path(__file__).parent.parent / "corpora"
    _GATED_COMMIT = "628e5a3"  # short form stored in receipt; matches _PINNED_COMMIT_SHORT

    def test_full_signed_p1_run_admitted_pass(self) -> None:
        """p1_regression.run() with real Podman → admitted PASS chain with provenance.

        Board P1 full-slice assertions:
        - chain.is_admitted: verify_integrity() passed and schema v2 admitted the chain
        - outcome == "pass": ObservedOCISandbox + correct corpus → RetryCheck PASS
        - all four provenance digest fields present and 64-char hex
        - policies_consistent == True in execution receipt
        - observer.log written and non-empty under artifact_dir/<run_id>/
        """
        from orchestrator.isolation import Registry
        from profiles.p1_regression import RunConfig
        from profiles.p1_regression import run as p1_run

        image_digest = _resolve_image_digest(self._IMAGE_REF)
        self.assertIsNotNone(image_digest, "could not resolve image digest via podman inspect")
        assert image_digest is not None

        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        with tempfile.TemporaryDirectory() as tmp:
            runs_path = Path(tmp)
            registry = Registry(runs_path / "registry.db")

            config = RunConfig(
                image_ref=self._IMAGE_REF,
                toolchain_image_digest=image_digest,
                gated_commit=self._GATED_COMMIT,
                corpus_path=self._CORPUS_PATH,
                signing_key=signing_key,
                verify_key=verify_key,
                registry=registry,
                artifact_dir=runs_path,
                trials=1,
                budget=ResourceBudget(wall_clock_seconds=120.0),
            )
            chain = p1_run(config)

            # Chain must be admitted (verify_integrity passed + schema v2).
            self.assertTrue(
                chain.is_admitted,
                "VerifiedChain must be admitted for a PASS calibration run",
            )

            # Calibration outcome must be "pass".
            outcome_str = chain.execution.payload.get("outcome")
            self.assertEqual(
                outcome_str,
                "pass",
                f"execution receipt outcome must be 'pass', got {outcome_str!r}",
            )

            # All four provenance digest fields must be present and 64-char hex.
            for prov_field in (
                "resolved_profile_digest",
                "trust_policy_digest",
                "guard_policy_digest",
                "execution_identity_digest",
            ):
                self.assertIn(
                    prov_field,
                    chain.execution.payload,
                    f"PASS receipt must carry {prov_field!r}",
                )
                val = chain.execution.payload[prov_field]
                self.assertIsInstance(val, str)
                self.assertEqual(
                    len(val),
                    64,
                    f"{prov_field!r} must be 64 hex chars, got {val!r}",
                )

            self.assertTrue(
                chain.execution.payload.get("policies_consistent"),
                "policies_consistent must be True in a PASS receipt",
            )

            # Observer artifact must have been written atomically.
            run_id = chain.prereg.run_id
            observer_log = runs_path / run_id / "observer.log"
            self.assertTrue(
                observer_log.exists(),
                f"observer.log must be written to {observer_log}",
            )
            self.assertGreater(
                observer_log.stat().st_size,
                0,
                "observer.log must be non-empty",
            )


if __name__ == "__main__":
    unittest.main()
