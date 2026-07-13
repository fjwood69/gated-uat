"""orchestrator/schemas.py — versioned payload schemas for each receipt kind.

Signature validity and evidence completeness are separate concerns (§0.4).
A chain can have valid signatures over incomplete evidence; schema validation
is the admission gate that rejects it independently.

Schema versions:
  v1 (Phase 0): exact key sets, bool exclusion, TZ timestamps, prereg_digest
      and execution_digest required for continuity, runtime_pack_digest optional.
  v2 (Phase 1): runtime_pack_digest REQUIRED in execution and teardown;
      observer_log_digest and observer_log_truncated REQUIRED in execution.

Version dispatch:
  validate_payload(kind, payload) reads schema_version from the payload and
  routes to the matching version validator. v1 receipts remain integrity-
  verifiable; admission requires schema_version >= SCHEMA_VERSION_MIN_ADMIT.

Bump SCHEMA_VERSION for new breaking changes; keep old validators so archived
receipts can still be cryptographically verified.
"""

from __future__ import annotations

import re
from typing import Any

SCHEMA_VERSION = 2  # current / latest version produced by this harness
SCHEMA_VERSION_MIN_ADMIT = 2  # minimum schema_version for admission (evaluate_admission)

VALID_PROFILES: frozenset[str] = frozenset({"p1", "p2", "p3"})
VALID_OUTCOMES: frozenset[str] = frozenset({"pass", "fail", "error"})
SIGNER_ROLE = "EvidenceSigner"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
# Require timezone (Z or ±HH:MM); reject trailing garbage with the $ anchor.
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")

# ------------------------------------------------------------------
# Exact allowed key sets — one frozenset per kind per version
# ------------------------------------------------------------------

_PREREG_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "profile",
        "gated_commit",
        "corpus_version",
        "preregistered_at",
    }
)

# v1 execution keys (runtime_pack_digest optional → whitelisted but not required)
_EXECUTION_KEYS_V1: frozenset[str] = frozenset(
    {
        "schema_version",
        "profile",
        "gated_commit",
        "outcome",
        "executed_at",
        "canonical_digest_alg",
        "canonical_digest_version",
        "prereg_digest",
        "runtime_pack_digest",  # optional in v1
    }
)
# v2 execution keys: runtime_pack_digest + observer fields always required;
# provenance fields required for PASS/FAIL, may be absent for ERROR.
_EXECUTION_KEYS_V2: frozenset[str] = frozenset(
    {
        "schema_version",
        "profile",
        "gated_commit",
        "outcome",
        "executed_at",
        "canonical_digest_alg",
        "canonical_digest_version",
        "prereg_digest",
        "runtime_pack_digest",        # required in v2
        "observer_log_digest",        # required in v2: SHA-256 of canonical observer artifact
        "observer_log_truncated",     # required in v2: bool, True when streams were truncated
        "resolved_profile_digest",    # required for PASS/FAIL; may be absent for ERROR
        "trust_policy_digest",        # required for PASS/FAIL; may be absent for ERROR
        "guard_policy_digest",        # required for PASS/FAIL; may be absent for ERROR
        "execution_identity_digest",  # required for PASS/FAIL; gated's canonical identity digest
        "policies_consistent",        # required for PASS/FAIL (True); absent ok for ERROR
    }
)

_TEARDOWN_KEYS_V1: frozenset[str] = frozenset(
    {
        "schema_version",
        "profile",
        "failure",
        "torn_down_at",
        "error",
        "execution_digest",
        "runtime_pack_digest",  # optional in v1
    }
)
_TEARDOWN_KEYS_V2: frozenset[str] = frozenset(
    {
        "schema_version",
        "profile",
        "failure",
        "torn_down_at",
        "error",
        "execution_digest",
        "runtime_pack_digest",  # required in v2
    }
)

_INDEX_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "prereg",
        "execution",
        "teardown",
        "verify_key_hex",
        "signer_role",
    }
)


class SchemaViolationError(ValueError):
    """Payload fails schema requirements for its receipt kind."""


# ------------------------------------------------------------------
# Shared primitive validators
# ------------------------------------------------------------------


def _require(payload: dict[str, Any], key: str, *, types: tuple[type, ...]) -> Any:
    if key not in payload:
        raise SchemaViolationError(f"Missing required field: {key!r}")
    value = payload[key]
    if not isinstance(value, types):
        raise SchemaViolationError(f"Field {key!r}: expected {types}, got {type(value).__name__}")
    # bool is a subclass of int; reject booleans when an integer is expected.
    if int in types and isinstance(value, bool):
        raise SchemaViolationError(f"Field {key!r}: expected int, got bool")
    return value


def _require_hex64(payload: dict[str, Any], key: str) -> str:
    value = _require(payload, key, types=(str,))
    if not _HEX64_RE.match(value):
        raise SchemaViolationError(f"Field {key!r}: must be 64 lowercase hex chars, got {value!r}")
    return str(value)


def _require_iso_timestamp(payload: dict[str, Any], key: str) -> str:
    value = _require(payload, key, types=(str,))
    if not _ISO_RE.match(value):
        raise SchemaViolationError(
            f"Field {key!r}: must be an ISO timestamp with timezone "
            f"(e.g. '...Z' or '...+HH:MM'), got {value!r}"
        )
    return str(value)


def _check_unknown_keys(payload: dict[str, Any], allowed: frozenset[str], kind: str) -> None:
    unknown = set(payload.keys()) - allowed
    if unknown:
        raise SchemaViolationError(f"{kind!r} payload has unknown keys: {sorted(unknown)}")


def _validate_schema_version(payload: dict[str, Any], expected: int) -> None:
    sv = _require(payload, "schema_version", types=(int,))
    if sv != expected:
        raise SchemaViolationError(f"schema_version: expected {expected}, got {sv}")


def _validate_profile(payload: dict[str, Any]) -> None:
    profile = _require(payload, "profile", types=(str,))
    if profile not in VALID_PROFILES:
        raise SchemaViolationError(
            f"profile: must be one of {sorted(VALID_PROFILES)}, got {profile!r}"
        )


def _validate_gated_commit(payload: dict[str, Any]) -> None:
    gated_commit = _require(payload, "gated_commit", types=(str,))
    if not gated_commit:
        raise SchemaViolationError("gated_commit: must be non-empty")


def _validate_outcome(payload: dict[str, Any]) -> None:
    outcome = _require(payload, "outcome", types=(str,))
    if outcome not in VALID_OUTCOMES:
        raise SchemaViolationError(
            f"outcome: must be one of {sorted(VALID_OUTCOMES)}, got {outcome!r}"
        )


def _validate_canonical_digest_fields(payload: dict[str, Any]) -> None:
    alg = _require(payload, "canonical_digest_alg", types=(str,))
    if alg != "sha256":
        raise SchemaViolationError(f"canonical_digest_alg: expected 'sha256', got {alg!r}")
    cdv = _require(payload, "canonical_digest_version", types=(int,))
    if cdv != 1:
        raise SchemaViolationError(f"canonical_digest_version: must be exactly 1, got {cdv}")


# ------------------------------------------------------------------
# Preregistration (version-independent — no new fields in v2)
# ------------------------------------------------------------------


def validate_prereg_payload(payload: dict[str, Any]) -> None:
    """Validate a preregistration receipt payload (any schema version).

    Required: schema_version (1 or 2), profile, gated_commit, corpus_version,
    preregistered_at. Key set is the same in v1 and v2.
    """
    _check_unknown_keys(payload, _PREREG_KEYS, "prereg")
    sv = _require(payload, "schema_version", types=(int,))
    if sv not in (1, 2):
        raise SchemaViolationError(f"schema_version: unsupported version {sv}")
    _validate_profile(payload)
    _validate_gated_commit(payload)
    corpus_version = _require(payload, "corpus_version", types=(str,))
    if not corpus_version:
        raise SchemaViolationError("corpus_version: must be non-empty")
    _require_iso_timestamp(payload, "preregistered_at")


# ------------------------------------------------------------------
# Execution — v1 and v2
# ------------------------------------------------------------------


def _validate_execution_common(payload: dict[str, Any]) -> None:
    """Fields shared by execution v1 and v2."""
    _validate_profile(payload)
    _validate_gated_commit(payload)
    _validate_outcome(payload)
    _require_iso_timestamp(payload, "executed_at")
    _validate_canonical_digest_fields(payload)
    _require_hex64(payload, "prereg_digest")


def validate_execution_payload_v1(payload: dict[str, Any]) -> None:
    """Validate an execution receipt payload (schema v1).

    runtime_pack_digest is optional in v1 — validated only when present.
    """
    _check_unknown_keys(payload, _EXECUTION_KEYS_V1, "execution")
    _validate_schema_version(payload, 1)
    _validate_execution_common(payload)
    if "runtime_pack_digest" in payload:
        _require_hex64(payload, "runtime_pack_digest")


def validate_execution_payload_v2(payload: dict[str, Any]) -> None:
    """Validate an execution receipt payload (schema v2).

    runtime_pack_digest, observer_log_digest, and observer_log_truncated are
    required for all v2 receipts.

    Provenance fields are REQUIRED for PASS and FAIL outcomes (the gate produced
    a verdict under measured conditions) and may be absent for ERROR (infrastructure
    failure before a verdict was possible):
    - resolved_profile_digest, trust_policy_digest, guard_policy_digest,
      execution_identity_digest — all hex64.
    - policies_consistent — bool, must be True for PASS/FAIL.
    """
    _check_unknown_keys(payload, _EXECUTION_KEYS_V2, "execution")
    _validate_schema_version(payload, 2)
    _validate_execution_common(payload)
    _require_hex64(payload, "runtime_pack_digest")
    _require_hex64(payload, "observer_log_digest")
    _require(payload, "observer_log_truncated", types=(bool,))

    outcome = payload.get("outcome", "")
    if outcome in ("pass", "fail"):
        # Provenance is mandatory for a verdict — no verdict without measured identity.
        for _field in (
            "resolved_profile_digest",
            "trust_policy_digest",
            "guard_policy_digest",
            "execution_identity_digest",
        ):
            _require_hex64(payload, _field)
        pc = _require(payload, "policies_consistent", types=(bool,))
        if not pc:
            raise SchemaViolationError(
                "policies_consistent: must be True for PASS/FAIL evidence "
                "(a mixed-policy run must not produce a verdict)"
            )
    else:
        # ERROR: validate provenance fields if present, but do not require them.
        for _field in (
            "resolved_profile_digest",
            "trust_policy_digest",
            "guard_policy_digest",
            "execution_identity_digest",
        ):
            if _field in payload:
                _require_hex64(payload, _field)
        if "policies_consistent" in payload:
            _require(payload, "policies_consistent", types=(bool,))


def validate_execution_payload(payload: dict[str, Any]) -> None:
    """Dispatch to the correct version validator based on schema_version."""
    sv = payload.get("schema_version")
    if sv == 1:
        validate_execution_payload_v1(payload)
    elif sv == 2:
        validate_execution_payload_v2(payload)
    else:
        raise SchemaViolationError(f"schema_version: unsupported version {sv!r}")


# ------------------------------------------------------------------
# Teardown — v1 and v2
# ------------------------------------------------------------------


def _validate_teardown_common(payload: dict[str, Any]) -> None:
    """Fields shared by teardown v1 and v2."""
    _validate_profile(payload)
    failure = _require(payload, "failure", types=(bool,))
    _require_iso_timestamp(payload, "torn_down_at")
    _require_hex64(payload, "execution_digest")
    if failure:
        if "error" not in payload:
            raise SchemaViolationError("failure=True requires 'error' field")
        error = payload["error"]
        if not isinstance(error, str) or not error:
            raise SchemaViolationError("error: must be a non-empty string when failure=True")


def validate_teardown_payload_v1(payload: dict[str, Any]) -> None:
    """Validate a teardown receipt payload (schema v1).

    runtime_pack_digest is optional in v1.
    """
    _check_unknown_keys(payload, _TEARDOWN_KEYS_V1, "teardown")
    _validate_schema_version(payload, 1)
    _validate_teardown_common(payload)
    if "runtime_pack_digest" in payload:
        _require_hex64(payload, "runtime_pack_digest")


def validate_teardown_payload_v2(payload: dict[str, Any]) -> None:
    """Validate a teardown receipt payload (schema v2).

    runtime_pack_digest is required in v2.
    """
    _check_unknown_keys(payload, _TEARDOWN_KEYS_V2, "teardown")
    _validate_schema_version(payload, 2)
    _validate_teardown_common(payload)
    _require_hex64(payload, "runtime_pack_digest")


def validate_teardown_payload(payload: dict[str, Any]) -> None:
    """Dispatch to the correct version validator based on schema_version."""
    sv = payload.get("schema_version")
    if sv == 1:
        validate_teardown_payload_v1(payload)
    elif sv == 2:
        validate_teardown_payload_v2(payload)
    else:
        raise SchemaViolationError(f"schema_version: unsupported version {sv!r}")


# ------------------------------------------------------------------
# Index (version-independent)
# ------------------------------------------------------------------


def validate_index_payload(payload: dict[str, Any]) -> None:
    """Validate an index receipt payload (any schema version).

    Required: schema_version, prereg/execution/teardown digests,
    verify_key_hex (64-char Ed25519 public key hex), signer_role.
    """
    _check_unknown_keys(payload, _INDEX_KEYS, "index")
    sv = _require(payload, "schema_version", types=(int,))
    if sv not in (1, 2):
        raise SchemaViolationError(f"schema_version: unsupported version {sv}")
    for field in ("prereg", "execution", "teardown"):
        _require_hex64(payload, field)
    _require_hex64(payload, "verify_key_hex")
    role = _require(payload, "signer_role", types=(str,))
    if role != SIGNER_ROLE:
        raise SchemaViolationError(f"signer_role: expected {SIGNER_ROLE!r}, got {role!r}")


# ------------------------------------------------------------------
# Top-level dispatch
# ------------------------------------------------------------------


_V1_VALIDATORS = {
    "prereg": validate_prereg_payload,
    "execution": validate_execution_payload_v1,
    "teardown": validate_teardown_payload_v1,
    "index": validate_index_payload,
}

_VALIDATORS = {
    "prereg": validate_prereg_payload,
    "execution": validate_execution_payload,
    "teardown": validate_teardown_payload,
    "index": validate_index_payload,
}


def validate_payload(kind: str, payload: dict[str, Any]) -> None:
    """Dispatch to the version-aware validator for *kind*.

    Reads schema_version from the payload and routes to the appropriate
    version. Raises SchemaViolationError on failure.
    """
    validator = _VALIDATORS.get(kind)
    if validator is None:
        raise SchemaViolationError(f"Unknown receipt kind: {kind!r}")
    validator(payload)
