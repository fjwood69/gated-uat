"""orchestrator/runtime.py — RuntimePack abstraction (stub, Phase 0).

RuntimePack pins the interface for runtime/toolchain isolation.
Phase 0 defines the dataclass and schema validator only — no Podman or
execution implementation. Phase 1 will implement the Python runtime pack
and fill in the concrete types.

Evidence binding: execution and teardown receipts may include a
``runtime_pack_digest`` field (optional in Phase 0, required from Phase 1+)
to bind a run to its exact runtime configuration. The digest is SHA-256 of
the canonical JSON serialisation produced by runtime_pack_digest().
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


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

    runtime_id: str           # unique identifier for this runtime configuration
    version: str              # semver or commit-derived version string
    toolchain_image_digest: str    # sha256:<hex> or empty in Phase 0
    accepted_source_forms: tuple[str, ...]   # e.g. ("sdist", "wheel")
    isolated_build_plan: str       # human-readable plan or empty in Phase 0
    frozen_run_command: str        # exact command string to execute
    dependency_policy: str         # e.g. "lockfile-pinned" or empty in Phase 0
    observer_capabilities: tuple[str, ...]   # e.g. ("stdout", "stderr", "exit_code")
    resource_budget: str           # e.g. "2cpu-4gb" or empty in Phase 0


def validate_runtime_pack(pack: RuntimePack) -> None:
    """Raise RuntimePackError if *pack* has invalid fields.

    Phase 0 validates only that identity fields are non-empty.
    Phase 1+ will add format/digest validation for all fields.
    """
    required_non_empty = ("runtime_id", "version", "frozen_run_command")
    for attr in required_non_empty:
        val = getattr(pack, attr)
        if not val:
            raise RuntimePackError(f"RuntimePack.{attr} must be non-empty")


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
