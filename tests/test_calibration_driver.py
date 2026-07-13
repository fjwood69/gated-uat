"""tests/test_calibration_driver.py — CalibrationDriver types and observer artifact.

Exercises the driver domain types and observer canonicalisation without
touching gated's gate/engine imports. GatedCalibrationAdapter is not tested
here (it requires a live gated checkout + sandbox — covered by integration tests).

Coverage:
- CalibrationRequest / CalibrationOutcome / GuardSpec are frozen dataclasses.
- canonical_observer_bytes: correct length-framing (u64be prefix), JSON content.
- observer_log_truncated: False for small outcomes, True when either stream exceeds cap.
- compute_observer_log_digest: deterministic SHA-256 of the canonical bytes.
- CalibrationDriver Protocol: a stub adapter satisfies the interface.
"""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from typing import Any

from core import ResourceBudget
from core.calibration import CalibrationSet, Fixture, FixtureLabel

from orchestrator.calibration_driver import (
    CalibrationDriver,
    CalibrationOutcome,
    CalibrationRequest,
    GuardSpec,
    canonical_observer_bytes,
    compute_observer_log_digest,
    observer_log_truncated,
)

_MAX_OBSERVER_BYTES = 256 * 1024  # mirrors module constant


def _minimal_outcome(
    passed: bool = True,
    fixture_outcomes: list[dict[str, Any]] | None = None,
    timing_ms: int = 42,
) -> CalibrationOutcome:
    return CalibrationOutcome(
        passed=passed,
        inadequate=False,
        fn_failures=(),
        fp_failures=(),
        flaky=(),
        harness_errors=(),
        fixture_outcomes=fixture_outcomes
        or [
            {
                "fixture_id": "retry-good-v1",
                "label": "KNOWN_GOOD",
                "verdict_status": "pass",
                "verdict_reason": None,
                "classification": "true_negative",
            }
        ],
        timing_ms=timing_ms,
        execution_identity=None,
        execution_identity_digest=None,
        resolved_profile_digest=None,
        trust_policy_digest=None,
        guard_policy_digest=None,
        policies_consistent=True,
    )


def _minimal_request() -> CalibrationRequest:
    known_good = (
        Fixture(
            fixture_id="retry-good-v1",
            label=FixtureLabel.KNOWN_GOOD,
            payload=b"# good",
            evasion_class=None,
        ),
    )
    known_bad = (
        Fixture(
            fixture_id="retry-bad-v1",
            label=FixtureLabel.KNOWN_BAD,
            payload=b"# bad",
            evasion_class="no-retry",
        ),
    )
    return CalibrationRequest(
        calibration_set=CalibrationSet(known_good=known_good, known_bad=known_bad),
        detector_id="RetryCheck",
        guard_spec=GuardSpec(backend_kind="oci", image_ref="localhost/test:latest"),
        budget=ResourceBudget(wall_clock_seconds=60.0),
        trials=3,
    )


class _StubDriver:
    """Minimal CalibrationDriver implementation for protocol checks."""

    def run(self, request: CalibrationRequest) -> CalibrationOutcome:
        return _minimal_outcome()


class TestDomainTypes(unittest.TestCase):
    def test_guard_spec_is_frozen(self) -> None:
        spec = GuardSpec(backend_kind="oci", image_ref="localhost/img:tag")
        with self.assertRaises(Exception):
            spec.backend_kind = "other"  # type: ignore[misc]

    def test_guard_spec_default_policy(self) -> None:
        spec = GuardSpec(backend_kind="oci", image_ref="ref")
        self.assertEqual(spec.guard_policy, "trusted-backend")

    def test_calibration_request_is_frozen(self) -> None:
        req = _minimal_request()
        with self.assertRaises(Exception):
            req.detector_id = "other"  # type: ignore[misc]

    def test_calibration_outcome_is_frozen(self) -> None:
        outcome = _minimal_outcome()
        with self.assertRaises(Exception):
            outcome.passed = False  # type: ignore[misc]

    def test_calibration_request_default_trials(self) -> None:
        known_good = (Fixture("g1", FixtureLabel.KNOWN_GOOD, b"", None),)
        known_bad = (Fixture("b1", FixtureLabel.KNOWN_BAD, b"", None),)
        req = CalibrationRequest(
            calibration_set=CalibrationSet(known_good=known_good, known_bad=known_bad),
            detector_id="D",
            guard_spec=GuardSpec(backend_kind="oci", image_ref="ref"),
            budget=ResourceBudget(wall_clock_seconds=10.0),
        )
        self.assertEqual(req.trials, 5)


class TestCanonicalObserverBytes(unittest.TestCase):
    def _parse_frame(self, data: bytes) -> tuple[bytes, bytes]:
        """Parse u64be(len) || payload || u64be(len) || payload."""
        stdout_len = struct.unpack(">Q", data[:8])[0]
        stdout = data[8 : 8 + stdout_len]
        offset = 8 + stdout_len
        stderr_len = struct.unpack(">Q", data[offset : offset + 8])[0]
        stderr = data[offset + 8 : offset + 8 + stderr_len]
        return stdout, stderr

    def test_length_framing_format(self) -> None:
        """canonical_observer_bytes uses u64be length prefix for both streams."""
        outcome = _minimal_outcome()
        raw = canonical_observer_bytes(outcome)
        stdout_len = struct.unpack(">Q", raw[:8])[0]
        self.assertGreater(stdout_len, 0)
        self.assertGreater(len(raw), 16)  # at least two 8-byte length prefixes

    def test_stdout_slot_contains_fixture_outcomes(self) -> None:
        """The stdout slot carries JSON fixture outcomes."""
        outcome = _minimal_outcome(fixture_outcomes=[{"fixture_id": "x", "verdict_status": "pass"}])
        raw = canonical_observer_bytes(outcome)
        stdout, _ = self._parse_frame(raw)
        parsed = json.loads(stdout)
        self.assertEqual(parsed[0]["fixture_id"], "x")

    def test_stderr_slot_contains_timing(self) -> None:
        """The stderr slot carries timing/summary JSON."""
        outcome = _minimal_outcome(timing_ms=999)
        raw = canonical_observer_bytes(outcome)
        _, stderr = self._parse_frame(raw)
        parsed = json.loads(stderr)
        self.assertEqual(parsed["timing_ms"], 999)

    def test_deterministic_for_same_input(self) -> None:
        """Same outcome → identical bytes."""
        outcome = _minimal_outcome()
        self.assertEqual(canonical_observer_bytes(outcome), canonical_observer_bytes(outcome))

    def test_different_outcomes_produce_different_bytes(self) -> None:
        a = _minimal_outcome(timing_ms=1)
        b = _minimal_outcome(timing_ms=2)
        self.assertNotEqual(canonical_observer_bytes(a), canonical_observer_bytes(b))


class TestObserverLogTruncated(unittest.TestCase):
    def test_small_outcome_not_truncated(self) -> None:
        self.assertFalse(observer_log_truncated(_minimal_outcome()))

    def test_large_fixture_outcomes_truncated(self) -> None:
        """fixture_outcomes that exceed 256 KiB when serialised → truncated=True."""
        big_fixtures = [{"fixture_id": "x" * 1000, "data": "y" * 1000}] * 300
        outcome = _minimal_outcome(fixture_outcomes=big_fixtures)
        self.assertTrue(observer_log_truncated(outcome))

    def test_truncated_outcome_still_produces_bytes(self) -> None:
        """canonical_observer_bytes handles truncation without raising."""
        big_fixtures = [{"data": "y" * 1000}] * 300
        outcome = _minimal_outcome(fixture_outcomes=big_fixtures)
        raw = canonical_observer_bytes(outcome)
        stdout_len = struct.unpack(">Q", raw[:8])[0]
        self.assertLessEqual(stdout_len, _MAX_OBSERVER_BYTES)


class TestComputeObserverLogDigest(unittest.TestCase):
    def test_digest_is_sha256_hex(self) -> None:
        digest = compute_observer_log_digest(_minimal_outcome())
        self.assertEqual(len(digest), 64)
        int(digest, 16)  # must be valid hex

    def test_digest_matches_canonical_bytes(self) -> None:
        outcome = _minimal_outcome()
        expected = hashlib.sha256(canonical_observer_bytes(outcome)).hexdigest()
        self.assertEqual(compute_observer_log_digest(outcome), expected)

    def test_digest_is_deterministic(self) -> None:
        outcome = _minimal_outcome()
        self.assertEqual(compute_observer_log_digest(outcome), compute_observer_log_digest(outcome))


class TestCalibrationDriverProtocol(unittest.TestCase):
    def test_stub_satisfies_protocol(self) -> None:
        """A class with run(request) -> CalibrationOutcome satisfies CalibrationDriver."""
        driver: CalibrationDriver = _StubDriver()
        req = _minimal_request()
        outcome = driver.run(req)
        self.assertIsInstance(outcome, CalibrationOutcome)
        self.assertTrue(outcome.passed)

    def test_stub_outcome_fields(self) -> None:
        outcome = _StubDriver().run(_minimal_request())
        self.assertFalse(outcome.inadequate)
        self.assertEqual(outcome.fn_failures, ())
        self.assertEqual(outcome.fp_failures, ())
        self.assertIsNone(outcome.execution_identity)


if __name__ == "__main__":
    unittest.main()
