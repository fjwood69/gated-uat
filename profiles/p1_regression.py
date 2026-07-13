"""profiles/p1_regression.py — P1 regression profile.

Executes a programmatic calibration of gated's RetryCheck detector against
the gated-uat-owned corpus (corpora/manifest.json + fixture files), produces
a four-receipt signed evidence chain, and returns a VerifiedChain.

Board-ratified design (Phase 1):
- Programmatic calibrate() is the authoritative signed path (Option B).
- GatedCalibrationAdapter is the only permitted import from gated's gate/engine.
- Empty corpus is a configuration refusal, not a signed detector failure.
- observer_log_digest binds the execution receipt to the canonical observer
  artifact (length-framed fixture outcomes + timing).
- RunConfig is a frozen dataclass; profiles use module-level run() functions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core import ResourceBudget
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from nacl.signing import SigningKey, VerifyKey

from orchestrator.calibration_driver import (
    CalibrationOutcome,
    CalibrationRequest,
    GatedCalibrationAdapter,
    GuardSpec,
    canonical_observer_bytes,
    compute_observer_log_digest,
    observer_log_truncated,
)
from orchestrator.evidence import (
    VerifiedChain,
    build_execution_receipt,
    build_index,
    build_receipt,
    build_teardown_receipt,
    verify_integrity,
)
from orchestrator.isolation import Registry, RunState
from orchestrator.runtime import compute_runtime_pack_digest, make_python_runtime_pack
from orchestrator.schemas import SCHEMA_VERSION


class CorpusConfigError(RuntimeError):
    """Corpus is absent, incomplete, or its manifest hashes do not match on-disk files."""


class ImageDigestMismatchError(RuntimeError):
    """Caller-supplied toolchain image digest does not match the backend-measured digest."""


# ------------------------------------------------------------------
# Corpus loading
# ------------------------------------------------------------------


_LABEL_MAP = {
    "KNOWN_GOOD": FixtureLabel.KNOWN_GOOD,
    "KNOWN_BAD": FixtureLabel.KNOWN_BAD,
}


@dataclass(frozen=True)
class _CorpusData:
    fixtures: tuple[Fixture, ...]
    manifest_digest: str  # SHA-256 of the manifest JSON bytes

    def to_calibration_set(self) -> CalibrationSet:
        known_good = tuple(f for f in self.fixtures if f.label is FixtureLabel.KNOWN_GOOD)
        known_bad = tuple(f for f in self.fixtures if f.label is FixtureLabel.KNOWN_BAD)
        return CalibrationSet(known_good=known_good, known_bad=known_bad)


def _load_corpus(corpus_path: Path) -> _CorpusData:
    """Load and validate the corpus from *corpus_path*.

    Raises CorpusConfigError if:
    - manifest.json is missing
    - no fixtures are listed
    - no KNOWN_GOOD or no KNOWN_BAD fixture is present (vacuity guard)
    - any fixture file is missing or its SHA-256 does not match the manifest
    """
    manifest_file = corpus_path / "manifest.json"
    if not manifest_file.exists():
        raise CorpusConfigError(f"Corpus manifest not found: {manifest_file}")

    manifest_bytes = manifest_file.read_bytes()
    manifest = json.loads(manifest_bytes)
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

    raw_fixtures = manifest.get("fixtures", [])
    if not raw_fixtures:
        raise CorpusConfigError(
            "Corpus is empty — P1 must not run until the fixture corpus is seeded. "
            "See corpora/manifest.json and corpora/fixtures/."
        )

    fixtures_dir = corpus_path / "fixtures"
    loaded: list[Fixture] = []

    for entry in raw_fixtures:
        fixture_id: str = entry["fixture_id"]
        label_str: str = entry["label"]
        expected_digest: str = entry["payload_digest"]  # "sha256:<hex64>"
        evasion_class: str | None = entry.get("evasion_class")

        label = _LABEL_MAP.get(label_str)
        if label is None:
            raise CorpusConfigError(
                f"Fixture {fixture_id!r}: unknown label {label_str!r}; "
                f"must be KNOWN_GOOD or KNOWN_BAD"
            )

        fixture_file = fixtures_dir / fixture_id / "main.py"
        if not fixture_file.exists():
            raise CorpusConfigError(f"Fixture {fixture_id!r}: file not found at {fixture_file}")

        payload = fixture_file.read_bytes()
        actual_hex = hashlib.sha256(payload).hexdigest()
        expected_hex = expected_digest.removeprefix("sha256:")
        if actual_hex != expected_hex:
            raise CorpusConfigError(
                f"Fixture {fixture_id!r}: payload digest mismatch — "
                f"manifest={expected_digest!r} actual=sha256:{actual_hex!r}"
            )

        loaded.append(
            Fixture(
                fixture_id=fixture_id,
                label=label,
                payload=payload,
                evasion_class=evasion_class,
            )
        )

    cal_set = CalibrationSet(
        known_good=tuple(f for f in loaded if f.label is FixtureLabel.KNOWN_GOOD),
        known_bad=tuple(f for f in loaded if f.label is FixtureLabel.KNOWN_BAD),
    )
    if not cal_set.is_adequate:
        raise CorpusConfigError(
            "Corpus lacks both KNOWN_GOOD and KNOWN_BAD fixtures — "
            "inadequate corpus is a configuration refusal (vacuity guard)."
        )

    return _CorpusData(fixtures=tuple(loaded), manifest_digest=manifest_digest)


# ------------------------------------------------------------------
# Profile configuration
# ------------------------------------------------------------------


@dataclass(frozen=True)
class RunConfig:
    """All parameters for a single P1 regression run.

    The caller is responsible for resolving the toolchain image digest (e.g.
    via ``podman image inspect``) before invoking run(). The image_ref is the
    tag/name used to construct the sandbox; toolchain_image_digest is the
    pinned sha256:<hex> bound into the RuntimePack evidence.
    """

    image_ref: str  # OCI image reference (e.g. "localhost/mori:local")
    toolchain_image_digest: str  # sha256:<hex64> — pinned image bytes
    gated_commit: str  # 7-char commit prefix of the pinned gated checkout
    corpus_path: Path  # path to the corpora/ directory
    signing_key: SigningKey
    verify_key: VerifyKey
    registry: Registry
    artifact_dir: Path | None = None  # when set, write RUNS/<run_id>/observer.log here
    detector_id: str = "RetryCheck"
    guard_policy: str = "trusted-backend"
    trials: int = 5
    budget: ResourceBudget = field(default_factory=lambda: ResourceBudget(wall_clock_seconds=60.0))


# ------------------------------------------------------------------
# Profile entry point
# ------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_atomic(dest: Path, data: bytes) -> None:
    """Write *data* to *dest* with durability guarantees.

    Strategy: write to a .tmp sibling, fsync the file, os.replace into place
    (atomic on POSIX), then fsync the parent directory so the rename is durable.
    """
    import os

    tmp = dest.with_suffix(".tmp")
    with tmp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, dest)
    parent_fd = os.open(str(dest.parent), os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _map_outcome(outcome: CalibrationOutcome) -> str:
    if outcome.inadequate or outcome.harness_errors:
        return "error"
    if outcome.passed:
        return "pass"
    return "fail"


def run(config: RunConfig) -> VerifiedChain:
    """Execute a P1 regression calibration and return a signed VerifiedChain.

    Sequence:
    1. Load corpus — CorpusConfigError if empty/invalid (no run allocated).
    2. Build RuntimePack + compute its digest.
    3. allocate() run_id from registry.
    4. Build and sign prereg receipt.
    5. Run programmatic calibration via GatedCalibrationAdapter.
    6. Compute observer_log_digest from CalibrationOutcome.
    7. Build and sign execution receipt (binds prereg + runtime_pack + observer).
    8. Build and sign teardown receipt (binds execution + runtime_pack).
    9. Build and sign index receipt.
    10. verify_integrity() — raises on any chain failure.
    11. release() run_id as COMPLETED or FAILED.
    12. Return VerifiedChain.
    """
    # 1. Corpus — refuse before touching the registry if it's absent/broken.
    corpus = _load_corpus(config.corpus_path)
    cal_set = corpus.to_calibration_set()

    # 2. RuntimePack.
    pack = make_python_runtime_pack(
        toolchain_image_digest=config.toolchain_image_digest,
        corpus_digest=corpus.manifest_digest,
    )
    rpd = compute_runtime_pack_digest(pack)

    verify_key_hex = config.verify_key.encode().hex()
    run_id = config.registry.allocate()

    try:
        # 4. Preregistration receipt.
        prereg_payload = {
            "schema_version": SCHEMA_VERSION,
            "profile": "p1",
            "gated_commit": config.gated_commit,
            "corpus_version": corpus.manifest_digest,
            "preregistered_at": _now_iso(),
        }
        prereg = build_receipt("prereg", run_id, prereg_payload, config.signing_key)

        # 5. Run calibration.
        driver = GatedCalibrationAdapter()
        request = CalibrationRequest(
            calibration_set=cal_set,
            detector_id=config.detector_id,
            guard_spec=GuardSpec(
                backend_kind="observed",
                image_ref=config.image_ref,
                guard_policy=config.guard_policy,
            ),
            budget=config.budget,
            trials=config.trials,
        )
        outcome: CalibrationOutcome = driver.run(request)
        gated_outcome = _map_outcome(outcome)

        # 5a. Identity checks — fail-closed: PASS/FAIL without measured identity is impossible.
        if outcome.execution_identity is None and gated_outcome in ("pass", "fail"):
            raise ImageDigestMismatchError(
                "calibration produced a PASS/FAIL verdict without measured execution identity — "
                "gated internal inconsistency; rejecting evidence"
            )
        if outcome.execution_identity is not None:
            measured = outcome.execution_identity.get("image_ref", "")
            if measured != config.toolchain_image_digest:
                raise ImageDigestMismatchError(
                    f"toolchain_image_digest mismatch — "
                    f"supplied={config.toolchain_image_digest!r} "
                    f"measured={measured!r}"
                )

        # 6. Observer log digest.
        obs_digest = compute_observer_log_digest(outcome)
        obs_truncated = observer_log_truncated(outcome)

        # 6a. Persist canonical observer artifact atomically under artifact_dir.
        if config.artifact_dir is not None:
            run_artifact_dir = config.artifact_dir / run_id
            run_artifact_dir.mkdir(parents=True, exist_ok=True)
            _write_atomic(run_artifact_dir / "observer.log", canonical_observer_bytes(outcome))

        # 7. Execution receipt — carry provenance fields from CalibrationOutcome.
        # For PASS/FAIL: all four provenance digests are required by the schema.
        # For ERROR: include them when available, omit gracefully when absent.
        exec_payload: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "profile": "p1",
            "gated_commit": config.gated_commit,
            "outcome": gated_outcome,
            "executed_at": _now_iso(),
            "canonical_digest_alg": "sha256",
            "canonical_digest_version": 1,
            "runtime_pack_digest": rpd,
            "observer_log_digest": obs_digest,
            "observer_log_truncated": obs_truncated,
        }
        if gated_outcome in ("pass", "fail"):
            # All four required — schema validates these for PASS/FAIL.
            exec_payload["resolved_profile_digest"] = outcome.resolved_profile_digest
            exec_payload["trust_policy_digest"] = outcome.trust_policy_digest
            exec_payload["guard_policy_digest"] = outcome.guard_policy_digest
            exec_payload["execution_identity_digest"] = outcome.execution_identity_digest
            exec_payload["policies_consistent"] = outcome.policies_consistent
        else:
            # ERROR: include when available.
            if outcome.resolved_profile_digest is not None:
                exec_payload["resolved_profile_digest"] = outcome.resolved_profile_digest
            if outcome.trust_policy_digest is not None:
                exec_payload["trust_policy_digest"] = outcome.trust_policy_digest
            if outcome.guard_policy_digest is not None:
                exec_payload["guard_policy_digest"] = outcome.guard_policy_digest
            if outcome.execution_identity_digest is not None:
                exec_payload["execution_identity_digest"] = outcome.execution_identity_digest
            exec_payload["policies_consistent"] = outcome.policies_consistent
        execution = build_execution_receipt(prereg, exec_payload, config.signing_key)

        # 8. Teardown receipt — programmatic calibration has no container to clean up.
        teardown_payload = {
            "schema_version": SCHEMA_VERSION,
            "profile": "p1",
            "failure": False,
            "torn_down_at": _now_iso(),
            "runtime_pack_digest": rpd,
        }
        teardown = build_teardown_receipt(execution, teardown_payload, config.signing_key)

        # 9. Index receipt.
        index = build_index(run_id, prereg, execution, teardown, config.signing_key, verify_key_hex)

        # 10. Chain integrity.
        chain = verify_integrity(prereg, execution, teardown, index, config.verify_key)

        config.registry.release(run_id, state=RunState.COMPLETED)
        return chain

    except Exception:
        config.registry.release(run_id, state=RunState.FAILED)
        raise
