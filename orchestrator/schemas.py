"""orchestrator/schemas.py — versioned payload schemas for each receipt kind.

Signature validity and evidence completeness are separate concerns (§0.4).
A chain can have valid signatures over incomplete evidence; schema validation
is the admission gate that rejects it independently.

Schema version 1 is frozen here. Bump SCHEMA_VERSION for any change and
provide a migration path — old receipts should remain verifiable.

Phase-0 closure strictness rules:
  - Integer fields reject booleans (bool is a subclass of int; excluded explicitly).
  - ISO timestamps must include a timezone offset (Z or ±HH:MM) and no trailing text.
  - Exact key sets: unknown keys are rejected so no field is silently ignored.
  - Evidence continuity: execution payloads must include prereg_digest (hex64);
    teardown payloads must include execution_digest (hex64).
  - runtime_pack_digest is optional in Phase 0 (required from Phase 1+); when
    present it must be a 64-char lowercase hex string.
"""
from __future__ import annotations

import re
from typing import Any

SCHEMA_VERSION = 1
VALID_PROFILES: frozenset[str] = frozenset({"p1", "p2", "p3"})
VALID_OUTCOMES: frozenset[str] = frozenset({"pass", "fail", "error"})
SIGNER_ROLE = "EvidenceSigner"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
# Require timezone (Z or ±HH:MM); reject trailing garbage with the $ anchor.
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

# Exact allowed key sets for each payload kind (schema v1).
_PREREG_KEYS: frozenset[str] = frozenset({
    "schema_version", "profile", "gated_commit", "corpus_version", "preregistered_at",
})
_EXECUTION_KEYS: frozenset[str] = frozenset({
    "schema_version", "profile", "gated_commit", "outcome", "executed_at",
    "canonical_digest_alg", "canonical_digest_version",
    "prereg_digest",        # required: binds this receipt to its preregistration
    "runtime_pack_digest",  # optional in Phase 0; required from Phase 1+
})
_TEARDOWN_KEYS: frozenset[str] = frozenset({
    "schema_version", "profile", "failure", "torn_down_at",
    "error",                # conditional: required when failure=True
    "execution_digest",     # required: binds this receipt to its execution
    "runtime_pack_digest",  # optional in Phase 0; required from Phase 1+
})
_INDEX_KEYS: frozenset[str] = frozenset({
    "schema_version", "prereg", "execution", "teardown", "verify_key_hex", "signer_role",
})


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
    # bool is a subclass of int; reject booleans when an integer is expected.
    if int in types and isinstance(value, bool):
        raise SchemaViolationError(f"Field {key!r}: expected int, got bool")
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
            f"Field {key!r}: must be an ISO timestamp with timezone "
            f"(e.g. '...Z' or '...+HH:MM'), got {value!r}"
        )
    return str(value)


def _check_unknown_keys(
    payload: dict[str, Any], allowed: frozenset[str], kind: str
) -> None:
    unknown = set(payload.keys()) - allowed
    if unknown:
        raise SchemaViolationError(
            f"{kind!r} payload has unknown keys: {sorted(unknown)}"
        )


def validate_prereg_payload(payload: dict[str, Any]) -> None:
    """Validate a preregistration receipt payload (schema v1).

    Required: schema_version, profile, gated_commit, corpus_version, preregistered_at.
    """
    _check_unknown_keys(payload, _PREREG_KEYS, "prereg")

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

    Required: schema_version, profile, gated_commit, outcome, executed_at,
    canonical_digest_alg, canonical_digest_version, prereg_digest.
    Optional: runtime_pack_digest (required from Phase 1+).
    """
    _check_unknown_keys(payload, _EXECUTION_KEYS, "execution")

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

    _require_hex64(payload, "prereg_digest")

    if "runtime_pack_digest" in payload:
        _require_hex64(payload, "runtime_pack_digest")


def validate_teardown_payload(payload: dict[str, Any]) -> None:
    """Validate a teardown receipt payload (schema v1).

    Required: schema_version, profile, failure, torn_down_at, execution_digest.
    When failure=True, error must be present and non-empty.
    Optional: runtime_pack_digest (required from Phase 1+).
    """
    _check_unknown_keys(payload, _TEARDOWN_KEYS, "teardown")

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

    _require_hex64(payload, "execution_digest")

    if "runtime_pack_digest" in payload:
        _require_hex64(payload, "runtime_pack_digest")

    if failure:
        if "error" not in payload:
            raise SchemaViolationError("failure=True requires 'error' field")
        error = payload["error"]
        if not isinstance(error, str) or not error:
            raise SchemaViolationError("error: must be a non-empty string when failure=True")


def validate_index_payload(payload: dict[str, Any]) -> None:
    """Validate an index receipt payload (schema v1).

    Required: schema_version, prereg/execution/teardown digests,
    verify_key_hex (64-char Ed25519 public key hex), signer_role.
    """
    _check_unknown_keys(payload, _INDEX_KEYS, "index")

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
