"""orchestrator/schemas.py — versioned payload schemas for each receipt kind.

Signature validity and evidence completeness are separate concerns (§0.4).
A chain can have valid signatures over incomplete evidence; schema validation
is the admission gate that rejects it independently.

Schema version 1 is frozen here. Bump SCHEMA_VERSION for any change and
provide a migration path — old receipts should remain verifiable.
"""
from __future__ import annotations

import re
from typing import Any

SCHEMA_VERSION = 1
VALID_PROFILES: frozenset[str] = frozenset({"p1", "p2", "p3"})
VALID_OUTCOMES: frozenset[str] = frozenset({"pass", "fail", "error"})
SIGNER_ROLE = "EvidenceSigner"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class SchemaViolationError(ValueError):
    """Payload fails schema requirements for its receipt kind.

    Raised independently of signature verification — both must pass for
    a receipt to be admitted as evidence.
    """


def _require(payload: dict[str, Any], key: str, *, types: tuple[type, ...]) -> Any:
    if key not in payload:
        raise SchemaViolationError(f"Missing required field: {key!r}")
    value = payload[key]
    if not isinstance(value, types):
        raise SchemaViolationError(
            f"Field {key!r}: expected {types}, got {type(value).__name__}"
        )
    return value


def _require_hex64(payload: dict[str, Any], key: str) -> str:
    value = _require(payload, key, types=(str,))
    if not _HEX64_RE.match(value):
        raise SchemaViolationError(
            f"Field {key!r}: must be 64 lowercase hex chars, got {value!r}"
        )
    return str(value)


def _require_iso_timestamp(payload: dict[str, Any], key: str) -> str:
    value = _require(payload, key, types=(str,))
    if not _ISO_RE.match(value):
        raise SchemaViolationError(
            f"Field {key!r}: must be an ISO timestamp, got {value!r}"
        )
    return str(value)


def validate_prereg_payload(payload: dict[str, Any]) -> None:
    """Validate a preregistration receipt payload (schema v1).

    Required provenance: schema_version, profile, gated_commit,
    corpus_version, preregistered_at.
    """
    sv = _require(payload, "schema_version", types=(int,))
    if sv != SCHEMA_VERSION:
        raise SchemaViolationError(f"schema_version: expected {SCHEMA_VERSION}, got {sv}")

    profile = _require(payload, "profile", types=(str,))
    if profile not in VALID_PROFILES:
        raise SchemaViolationError(
            f"profile: must be one of {sorted(VALID_PROFILES)}, got {profile!r}"
        )

    gated_commit = _require(payload, "gated_commit", types=(str,))
    if not gated_commit:
        raise SchemaViolationError("gated_commit: must be non-empty")

    corpus_version = _require(payload, "corpus_version", types=(str,))
    if not corpus_version:
        raise SchemaViolationError("corpus_version: must be non-empty")

    _require_iso_timestamp(payload, "preregistered_at")


def validate_execution_payload(payload: dict[str, Any]) -> None:
    """Validate an execution receipt payload (schema v1).

    Required provenance: schema_version, profile, gated_commit, outcome,
    executed_at, canonical_digest_alg, canonical_digest_version.
    """
    sv = _require(payload, "schema_version", types=(int,))
    if sv != SCHEMA_VERSION:
        raise SchemaViolationError(f"schema_version: expected {SCHEMA_VERSION}, got {sv}")

    profile = _require(payload, "profile", types=(str,))
    if profile not in VALID_PROFILES:
        raise SchemaViolationError(
            f"profile: must be one of {sorted(VALID_PROFILES)}, got {profile!r}"
        )

    gated_commit = _require(payload, "gated_commit", types=(str,))
    if not gated_commit:
        raise SchemaViolationError("gated_commit: must be non-empty")

    outcome = _require(payload, "outcome", types=(str,))
    if outcome not in VALID_OUTCOMES:
        raise SchemaViolationError(
            f"outcome: must be one of {sorted(VALID_OUTCOMES)}, got {outcome!r}"
        )

    _require_iso_timestamp(payload, "executed_at")

    alg = _require(payload, "canonical_digest_alg", types=(str,))
    if alg != "sha256":
        raise SchemaViolationError(f"canonical_digest_alg: expected 'sha256', got {alg!r}")

    cdv = _require(payload, "canonical_digest_version", types=(int,))
    if cdv != 1:
        raise SchemaViolationError(f"canonical_digest_version: must be exactly 1, got {cdv}")


def validate_teardown_payload(payload: dict[str, Any]) -> None:
    """Validate a teardown receipt payload (schema v1).

    Required provenance: schema_version, profile, failure, torn_down_at.
    When failure=True, error must be present and non-empty.
    """
    sv = _require(payload, "schema_version", types=(int,))
    if sv != SCHEMA_VERSION:
        raise SchemaViolationError(f"schema_version: expected {SCHEMA_VERSION}, got {sv}")

    profile = _require(payload, "profile", types=(str,))
    if profile not in VALID_PROFILES:
        raise SchemaViolationError(
            f"profile: must be one of {sorted(VALID_PROFILES)}, got {profile!r}"
        )

    failure = _require(payload, "failure", types=(bool,))

    _require_iso_timestamp(payload, "torn_down_at")

    if failure:
        if "error" not in payload:
            raise SchemaViolationError("failure=True requires 'error' field")
        error = payload["error"]
        if not isinstance(error, str) or not error:
            raise SchemaViolationError("error: must be a non-empty string when failure=True")


def validate_index_payload(payload: dict[str, Any]) -> None:
    """Validate an index receipt payload (schema v1).

    Required provenance: schema_version, prereg/execution/teardown digests,
    verify_key_hex (64-char Ed25519 public key hex), signer_role.
    """
    sv = _require(payload, "schema_version", types=(int,))
    if sv != SCHEMA_VERSION:
        raise SchemaViolationError(f"schema_version: expected {SCHEMA_VERSION}, got {sv}")

    for field in ("prereg", "execution", "teardown"):
        _require_hex64(payload, field)

    _require_hex64(payload, "verify_key_hex")

    role = _require(payload, "signer_role", types=(str,))
    if role != SIGNER_ROLE:
        raise SchemaViolationError(f"signer_role: expected {SIGNER_ROLE!r}, got {role!r}")


_VALIDATORS = {
    "prereg": validate_prereg_payload,
    "execution": validate_execution_payload,
    "teardown": validate_teardown_payload,
    "index": validate_index_payload,
}


def validate_payload(kind: str, payload: dict[str, Any]) -> None:
    """Dispatch to the validator for *kind*. Raises SchemaViolationError on failure."""
    validator = _VALIDATORS.get(kind)
    if validator is None:
        raise SchemaViolationError(f"Unknown receipt kind: {kind!r}")
    validator(payload)
