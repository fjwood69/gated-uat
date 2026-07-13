"""orchestrator/calibration_driver.py — CalibrationDriver port + GatedCalibrationAdapter.

The CalibrationDriver is the single seam between gated-uat and gated's gate/engine
layers. Profiles speak the gated-uat domain types (CalibrationRequest, CalibrationOutcome);
all gated-specific imports live ONLY in GatedCalibrationAdapter, so a future backend
change or gated API evolution requires editing one adapter, not every profile.

Board ratification (Phase 1 design):
- CalibrationRequest carries the full CalibrationSet, detector_id, GuardSpec,
  budget, and trials — the adapter calls guarded_backend() and calibrate() exactly once.
- The adapter is responsible for building the DetectorRegistry and resolving RetryCheck.
  The accepted_profile_digest is derived from the live module bytes at the pinned gated
  commit — hygiene, not a deploy-tier security boundary.
- Profiles must NOT import gate.backends, engine.calibration, or gate.detector_registry
  directly; use this adapter.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol

from core import ResourceBudget
from core.calibration import CalibrationSet


class CalibrationDriverError(RuntimeError):
    """Adapter-level failure (mis-configuration, gated API error, etc.)."""


# ------------------------------------------------------------------
# Domain types spoken by profiles
# ------------------------------------------------------------------


@dataclass(frozen=True)
class GuardSpec:
    """Which backend kind + image + guard policy to use for this calibration run."""

    backend_kind: str  # e.g. "oci"
    image_ref: str  # e.g. "localhost/mori:local"
    guard_policy: str = "trusted-backend"


@dataclass(frozen=True)
class CalibrationRequest:
    """Everything the adapter needs to execute one calibration run.

    One request = one guarded_backend() call + one calibrate() call.
    The adapter must not split these across multiple calls (atomicity).
    """

    calibration_set: CalibrationSet
    detector_id: str
    guard_spec: GuardSpec
    budget: ResourceBudget
    trials: int = 5


@dataclass(frozen=True)
class CalibrationOutcome:
    """The result of one calibration run, including observer data for receipt binding."""

    passed: bool
    inadequate: bool
    fn_failures: tuple[str, ...]  # known_bad fixtures the detector missed
    fp_failures: tuple[str, ...]  # known_good fixtures that false-positived
    flaky: tuple[str, ...]  # non-deterministic fixtures
    harness_errors: tuple[str, ...]  # inconclusive fixtures (ERROR)
    fixture_outcomes: list[dict[str, Any]]  # serialisable per-fixture records
    timing_ms: int
    execution_identity: dict[str, Any] | None   # from CalibrationResult.execution_identity
    execution_identity_digest: str | None        # gated's canonical content_digest of identity
    resolved_profile_digest: str | None          # detector's profile digest this run
    trust_policy_digest: str | None              # digest of the applied trust policy
    guard_policy_digest: str | None              # digest of the applied guard policy
    policies_consistent: bool                    # all fixtures saw the same policy


class CalibrationDriver(Protocol):
    """Port for running a calibration. Profiles depend on this interface, not gated."""

    def run(self, request: CalibrationRequest) -> CalibrationOutcome: ...


# ------------------------------------------------------------------
# Canonical observer artifact
# ------------------------------------------------------------------

# Maximum bytes captured per stream before truncation (applies to encoded outcome JSON).
_MAX_OBSERVER_BYTES = 256 * 1024  # 256 KiB


def canonical_observer_bytes(outcome: CalibrationOutcome) -> bytes:
    """Return the canonical bytes of the observer artifact for digest binding.

    Uses length framing (board amendment D4):
        u64be(stdout_len) || stdout_bytes || u64be(stderr_len) || stderr_bytes

    For programmatic calibration there are no stdout/stderr streams; the
    "stdout" slot carries the JSON-serialised fixture outcomes, the "stderr"
    slot carries the timing record. Each is capped at _MAX_OBSERVER_BYTES.
    observer_log_truncated is True if either was truncated.
    """
    stdout_raw = json.dumps(
        outcome.fixture_outcomes, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    stderr_raw = json.dumps(
        {
            "timing_ms": outcome.timing_ms,
            "passed": outcome.passed,
            "inadequate": outcome.inadequate,
            "fn_failures": list(outcome.fn_failures),
            "fp_failures": list(outcome.fp_failures),
            "flaky": list(outcome.flaky),
            "harness_errors": list(outcome.harness_errors),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    stdout_bytes = stdout_raw[:_MAX_OBSERVER_BYTES]
    stderr_bytes = stderr_raw[:_MAX_OBSERVER_BYTES]

    import struct

    frame = (
        struct.pack(">Q", len(stdout_bytes))
        + stdout_bytes
        + struct.pack(">Q", len(stderr_bytes))
        + stderr_bytes
    )
    return frame


def observer_log_truncated(outcome: CalibrationOutcome) -> bool:
    """True if the canonical observer artifact was truncated."""
    stdout_raw = json.dumps(
        outcome.fixture_outcomes, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    stderr_raw = json.dumps(
        {
            "timing_ms": outcome.timing_ms,
            "passed": outcome.passed,
            "inadequate": outcome.inadequate,
            "fn_failures": list(outcome.fn_failures),
            "fp_failures": list(outcome.fp_failures),
            "flaky": list(outcome.flaky),
            "harness_errors": list(outcome.harness_errors),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return len(stdout_raw) > _MAX_OBSERVER_BYTES or len(stderr_raw) > _MAX_OBSERVER_BYTES


def compute_observer_log_digest(outcome: CalibrationOutcome) -> str:
    """Return the SHA-256 hex digest of the canonical observer artifact."""
    return hashlib.sha256(canonical_observer_bytes(outcome)).hexdigest()


# ------------------------------------------------------------------
# Adapter: wraps gated's gate + engine layers
# ------------------------------------------------------------------


class GatedCalibrationAdapter:
    """Wraps gate.backends.guarded_backend() + engine.calibration.calibrate().

    All gated imports are deferred to run() so the module is importable even
    when gated is not on sys.path (e.g. in unit tests using a stub adapter).
    """

    def run(self, request: CalibrationRequest) -> CalibrationOutcome:
        """Execute one calibration: guarded_backend() + calibrate(), atomically."""
        from engine.calibration import CalibrationResult, calibrate
        from engine.retry import RetryCheck
        from gate.backends import guarded_backend
        from gate.detector_registry import DetectorRegistry, profile_of
        from gate.trust_policy import resolve_trust_policy

        # The entry command is always ("python3", "/artifact/main.py") for RetryCheck.
        retry_entry = ("python3", "/artifact/main.py")
        detector = RetryCheck(retry_entry)

        # Build a single-use registry pinned to the live RetryCheck module bytes.
        # The accepted_profile_digest is derived from the current code at the pinned
        # gated commit — a drift check, not a deploy-tier security guarantee.
        prof = profile_of(request.detector_id, detector)
        accepted_digest = prof.digest()
        registry = DetectorRegistry()
        registry.register(
            request.detector_id,
            lambda: RetryCheck(retry_entry),
            accepted_profile_digest=accepted_digest,
        )

        make_sb, guard_policy = guarded_backend(
            request.guard_spec.backend_kind,
            request.guard_spec.image_ref,
            guard_policy=request.guard_spec.guard_policy,
        )

        # B1: apply the approved completed-only trust policy so gated binds and
        # signs its policy provenance into CalibrationResult.trust_policy_digest.
        trust_policy = resolve_trust_policy("trust-policy:completed-only")

        t0 = time.monotonic()
        result: CalibrationResult = calibrate(
            make_sb,
            request.detector_id,
            registry.resolve_bundle,
            request.calibration_set,
            request.budget,
            trials=request.trials,
            backend_guard=guard_policy,
            trust_policy=trust_policy,
        )
        timing_ms = int((time.monotonic() - t0) * 1000)

        fixture_outcomes = [
            {
                "fixture_id": o.fixture_id,
                "label": o.label.value,
                "verdict_status": o.verdict.status.value,
                "verdict_reason": o.verdict.reason.value if o.verdict.reason else None,
                "classification": o.classification.value,
            }
            for o in result.outcomes
        ]

        exec_identity: dict[str, Any] | None = None
        ei_digest: str | None = None
        if result.execution_identity is not None:
            ei = result.execution_identity
            exec_identity = {
                "backend": ei.backend,
                "image_ref": ei.image_ref,  # immutable digest the sandbox resolved
                "isolation_level": ei.isolation_level,
                "observer_config_hash": ei.observer_config_hash,
            }
            # Use gated's canonical content_digest (not a local re-derivation).
            ei_digest = ei.digest()

        return CalibrationOutcome(
            passed=result.passed,
            inadequate=result.inadequate,
            fn_failures=result.fn_failures,
            fp_failures=result.fp_failures,
            flaky=result.flaky,
            harness_errors=result.harness_errors,
            fixture_outcomes=fixture_outcomes,
            timing_ms=timing_ms,
            execution_identity=exec_identity,
            execution_identity_digest=ei_digest,
            resolved_profile_digest=result.resolved_profile_digest,
            trust_policy_digest=result.trust_policy_digest,
            guard_policy_digest=result.guard_policy_digest,
            policies_consistent=result.policies_consistent,
        )
