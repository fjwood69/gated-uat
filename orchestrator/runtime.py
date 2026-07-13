"""orchestrator/runtime.py — RuntimePack abstraction.

RuntimePack pins the runtime/toolchain configuration for a UAT run.
Phase 1 adds ``make_python_runtime_pack()``, the concrete factory for
Python/RetryCheck calibration runs, plus image digest validation.

Evidence binding: execution and teardown receipts must include
``runtime_pack_digest`` (required from schema v2) to bind a run to its
exact runtime configuration. The digest is SHA-256 of the canonical JSON
serialisation produced by ``compute_runtime_pack_digest()``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuntimePackError(ValueError):
    """RuntimePack validation failure."""


@dataclass(frozen=True)
class RuntimePack:
    """Pinned runtime configuration for a single UAT run (Phase 0 stub).

    All fields are required strings or tuples so Phase 1 cannot silently
    omit any. Use an empty string as a placeholder for fields not yet
    implemented; the validator enforces non-empty only for the identity fields.

    Phase 1 will replace string placeholders with typed implementations:
    image digests, lockfile hashes, Podman spec objects, etc.
    """

    runtime_id: str  # unique identifier for this runtime configuration
    version: str  # semver or commit-derived version string
    toolchain_image_digest: str  # sha256:<hex> or empty in Phase 0
    accepted_source_forms: tuple[str, ...]  # e.g. ("sdist", "wheel")
    isolated_build_plan: str  # human-readable plan or empty in Phase 0
    frozen_run_command: str  # exact command string to execute
    dependency_policy: str  # e.g. "lockfile-pinned" or empty in Phase 0
    observer_capabilities: tuple[str, ...]  # e.g. ("stdout", "stderr", "exit_code")
    resource_budget: str  # e.g. "2cpu-4gb" or empty in Phase 0


def validate_image_digest(digest: str) -> None:
    """Raise RuntimePackError if *digest* is not a valid sha256:<hex64> string."""
    if not _IMAGE_DIGEST_RE.match(digest):
        raise RuntimePackError(
            f"toolchain_image_digest must be 'sha256:<64 hex chars>', got {digest!r}"
        )


def validate_runtime_pack(pack: RuntimePack) -> None:
    """Raise RuntimePackError if *pack* has invalid fields."""
    required_non_empty = ("runtime_id", "version", "frozen_run_command")
    for attr in required_non_empty:
        val = getattr(pack, attr)
        if not val:
            raise RuntimePackError(f"RuntimePack.{attr} must be non-empty")
    if pack.toolchain_image_digest:
        validate_image_digest(pack.toolchain_image_digest)


def make_python_runtime_pack(
    *,
    toolchain_image_digest: str,
    corpus_digest: str,
    run_command: str = "calibrate RetryCheck",
) -> RuntimePack:
    """Return a concrete RuntimePack for a Python/RetryCheck calibration run.

    Args:
        toolchain_image_digest: OCI image digest of the form sha256:<hex64>,
            obtained from the sandbox at runtime (e.g. via podman image inspect).
        corpus_digest: SHA-256 of the canonical corpus manifest JSON, used as
            the dependency policy pin for this run.
        run_command: the frozen command description recorded in evidence.
    """
    validate_image_digest(toolchain_image_digest)
    return RuntimePack(
        runtime_id="python-retrycheck-podman",
        version="1.0.0",
        toolchain_image_digest=toolchain_image_digest,
        accepted_source_forms=("bytes",),
        isolated_build_plan="podman-calibrate-hermetic",
        frozen_run_command=run_command,
        dependency_policy=f"corpus-pinned:sha256:{corpus_digest}",
        observer_capabilities=("egress_count", "trial_report", "calibration_result"),
        resource_budget="5trials-hermetic-60s",
    )


def compute_runtime_pack_digest(pack: RuntimePack) -> str:
    """Return the SHA-256 digest of the canonical JSON serialisation.

    The digest is deterministic: dict keys are sorted, no whitespace, UTF-8.
    Tuples are serialised as lists (JSON has no tuple type).
    """
    canonical: dict[str, Any] = {
        "runtime_id": pack.runtime_id,
        "version": pack.version,
        "toolchain_image_digest": pack.toolchain_image_digest,
        "accepted_source_forms": list(pack.accepted_source_forms),
        "isolated_build_plan": pack.isolated_build_plan,
        "frozen_run_command": pack.frozen_run_command,
        "dependency_policy": pack.dependency_policy,
        "observer_capabilities": list(pack.observer_capabilities),
        "resource_budget": pack.resource_budget,
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
