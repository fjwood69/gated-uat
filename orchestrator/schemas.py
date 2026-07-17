"""orchestrator/schemas.py — versioned payload schemas for each receipt kind.

Signature validity and evidence completeness are separate concerns (§0.4).
A chain can have valid signatures over incomplete evidence; schema validation
is the admission gate that rejects it independently.

Schema versions:
  v1 (Phase 0): exact key sets, bool exclusion, TZ timestamps, prereg_digest
      and execution_digest required for continuity, runtime_pack_digest optional.
  v2 (Phase 1): runtime_pack_digest REQUIRED in execution and teardown;
      observer_log_digest and observer_log_truncated REQUIRED in execution.
  v3 (Phase 2, slice 2.1 — LIVE ENFORCEMENT): the execution receipt records a real
      make_gated_job_runner enforcement run (not a calibration). It binds the CLOSED
      JobResult discriminator (``result_kind`` + ``result_reason`` + ``result_sub_reason``
      + ``gate_outcome``), the enforced ``plan_policy_id`` (which MUST equal the policy
      preregistered in the prereg receipt — a run cannot post-hoc choose its policy), BOTH
      governance heads the admission bracket read (``bound_oracle_head`` + ``policy_generation``),
      and the run-context digests (``event_digest`` + ``artifact_tree_hash`` + ``detector_id``
      + ``image_digest`` + the four measured calibration coordinates). The prereg receipt
      gains ``policy_id``; teardown/index are structurally the v2 shape at version 3.

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

SCHEMA_VERSION = 2  # current / latest CALIBRATION receipt version (Phase 1)
SCHEMA_VERSION_ENFORCEMENT = 3  # LIVE-ENFORCEMENT execution receipt (Phase 2, slice 2.1)
SCHEMA_VERSION_MIN_ADMIT = 2  # minimum schema_version for admission (evaluate_admission)
SUPPORTED_SCHEMA_VERSIONS: frozenset[int] = frozenset({1, 2, 3})

VALID_PROFILES: frozenset[str] = frozenset({"p1", "p2", "p3"})
VALID_OUTCOMES: frozenset[str] = frozenset({"pass", "fail", "error"})
# The CLOSED enforcement JobResult discriminator (mirrors gate.job_result's union). A v3
# execution receipt's ``result_kind`` MUST be one of these — an unknown kind is a fail-closed
# schema violation, never silently admitted.
VALID_RESULT_KINDS: frozenset[str] = frozenset(
    {"admitted_run", "blocking_refusal", "non_run", "infrastructure_failure"}
)
# The CLOSED gate-outcome discriminator (mirrors gate.job_result.GateOutcome); an infra row
# carries no gate outcome (serialised as the JSON null → absent/None here).
VALID_GATE_OUTCOMES: frozenset[str] = frozenset({"run_verdict", "block_gate", "neutral_gate"})
SIGNER_ROLE = "EvidenceSigner"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
# ``sha256:<hex64>`` content-address form (gated's core.tree_hash + OCI image-config id) — distinct
# from a bare 64-hex digest; the prefix is part of the value gated produces and must be preserved.
_SHA256_PREFIXED_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
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
# v3 prereg (enforcement): the SAME keys plus ``policy_id`` — the enforced policy is
# PREREGISTERED, so the execution receipt's ``plan_policy_id`` must equal it (a run cannot
# post-hoc pick which policy its evidence attests to; checked in validate_semantic_continuity).
_PREREG_KEYS_V3: frozenset[str] = _PREREG_KEYS | {"policy_id"}

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

# v3 execution (LIVE ENFORCEMENT): records a real make_gated_job_runner run. The COMMON execution
# fields (schema_version/profile/gated_commit/outcome/executed_at/canonical_digest/prereg_digest)
# plus the CLOSED JobResult discriminator, the enforced policy, BOTH admission-bracket heads, and
# the run-context digests. Fields that only an ADMITTED run can produce (a real verdict under a
# measured identity: the heads + the four calibration coordinates + the artifact/detector/image the
# sandbox ran) are REQUIRED when result_kind == "admitted_run" and ABSENT otherwise (a
# refusal/non-run/infra row never measured them). ``event_digest`` + the closed discriminators are
# ALWAYS present.
_EXECUTION_KEYS_V3: frozenset[str] = frozenset(
    {
        # common execution envelope
        "schema_version",
        "profile",
        "gated_commit",
        "outcome",                    # pass|fail|error, mapped from the JobResult (unknown→error)
        "executed_at",
        "canonical_digest_alg",
        "canonical_digest_version",
        "prereg_digest",
        # CLOSED JobResult discriminator (always present)
        "result_kind",                # one of VALID_RESULT_KINDS
        "result_reason",              # stable audit token (verdict/refusal/disposition/infra)
        "result_sub_reason",          # admission sub_reason ("" for the non-admission kinds)
        "gate_outcome",               # one of VALID_GATE_OUTCOMES, or absent for an infra row
        # the enforced policy — MUST equal prereg.policy_id (semantic continuity)
        "plan_policy_id",
        # run context — always bound (every enforcement run has an event)
        "event_digest",               # digest of the GatingEvent (delivery/repo/head_sha/action)
        # ADMITTED-only: the run measured these; a non-run/refusal/infra row omits them
        "bound_oracle_head",          # the calibration head the run was ADMITTED against (head #1)
        "policy_generation",          # the policy tier head record_hash (head #2 — the ABA bracket)
        "artifact_tree_hash",         # the ArtifactSpec.tree_hash the sandbox verified (what ran)
        "detector_id",                # the enforced detector
        "image_digest",               # the OCI image BY DIGEST that executed
        "resolved_profile_digest",    # measured calibration coordinate 1
        "trust_policy_digest",        # measured calibration coordinate 2
        "guard_policy_digest",        # measured calibration coordinate 3
        "execution_identity_digest",  # measured calibration coordinate 4
    }
)
# The ADMITTED-only fields — required iff result_kind == "admitted_run", forbidden otherwise.
_EXECUTION_V3_ADMITTED_FIELDS: frozenset[str] = frozenset(
    {
        "bound_oracle_head",
        "policy_generation",
        "artifact_tree_hash",
        "detector_id",
        "image_digest",
        "resolved_profile_digest",
        "trust_policy_digest",
        "guard_policy_digest",
        "execution_identity_digest",
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


def _require_sha256_prefixed(payload: dict[str, Any], key: str) -> str:
    value = _require(payload, key, types=(str,))
    if not _SHA256_PREFIXED_RE.match(value):
        raise SchemaViolationError(
            f"Field {key!r}: must be 'sha256:<64 lowercase hex>', got {value!r}"
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

    Required: schema_version (1, 2 or 3), profile, gated_commit, corpus_version,
    preregistered_at. v3 additionally REQUIRES ``policy_id`` (the enforced policy is
    preregistered; the execution receipt's ``plan_policy_id`` must equal it).
    """
    sv = payload.get("schema_version")
    allowed = _PREREG_KEYS_V3 if sv == 3 else _PREREG_KEYS
    _check_unknown_keys(payload, allowed, "prereg")
    sv = _require(payload, "schema_version", types=(int,))
    if sv not in SUPPORTED_SCHEMA_VERSIONS:
        raise SchemaViolationError(f"schema_version: unsupported version {sv}")
    _validate_profile(payload)
    _validate_gated_commit(payload)
    corpus_version = _require(payload, "corpus_version", types=(str,))
    if not corpus_version:
        raise SchemaViolationError("corpus_version: must be non-empty")
    _require_iso_timestamp(payload, "preregistered_at")
    if sv == 3:
        policy_id = _require(payload, "policy_id", types=(str,))
        if not policy_id:
            raise SchemaViolationError("policy_id: must be non-empty in a v3 (enforcement) prereg")


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


def _validate_result_discriminator(payload: dict[str, Any]) -> str:
    """Validate the CLOSED JobResult discriminator on a v3 execution receipt and return the
    ``result_kind``. ``result_kind`` must be a known kind; ``result_reason`` a non-empty token;
    ``result_sub_reason`` a str (may be empty). ``gate_outcome`` — when present and non-None — must
    be a known gate outcome; it is ABSENT/None only for an infrastructure_failure row."""
    kind = _require(payload, "result_kind", types=(str,))
    if kind not in VALID_RESULT_KINDS:
        raise SchemaViolationError(
            f"result_kind: must be one of {sorted(VALID_RESULT_KINDS)}, got {kind!r}"
        )
    reason = _require(payload, "result_reason", types=(str,))
    if not reason:
        raise SchemaViolationError("result_reason: must be a non-empty audit token")
    _require(payload, "result_sub_reason", types=(str,))  # may be empty
    gate_outcome = payload.get("gate_outcome")
    if kind == "infrastructure_failure":
        if gate_outcome is not None:
            raise SchemaViolationError(
                "gate_outcome: an infrastructure_failure row carries no gate outcome (must be null)"
            )
    else:
        go = _require(payload, "gate_outcome", types=(str,))
        if go not in VALID_GATE_OUTCOMES:
            raise SchemaViolationError(
                f"gate_outcome: must be one of {sorted(VALID_GATE_OUTCOMES)}, got {go!r}"
            )
    return str(kind)


def validate_execution_payload_v3(payload: dict[str, Any]) -> None:
    """Validate an execution receipt payload (schema v3 — LIVE ENFORCEMENT).

    Common execution envelope (profile/gated_commit/outcome/executed_at/canonical_digest/
    prereg_digest) + the CLOSED JobResult discriminator + the enforced ``plan_policy_id`` +
    ``event_digest`` (always). The ADMITTED-only fields (both heads, artifact/detector/image, the
    four calibration coordinates) are REQUIRED iff ``result_kind == "admitted_run"`` and FORBIDDEN
    otherwise — a refusal/non-run/infra row never measured them, and asserting one would fabricate a
    measurement that never happened.
    """
    _check_unknown_keys(payload, _EXECUTION_KEYS_V3, "execution")
    _validate_schema_version(payload, 3)
    _validate_execution_common(payload)  # profile/gated_commit/outcome/executed_at/digest/prereg
    kind = _validate_result_discriminator(payload)
    plan_policy_id = _require(payload, "plan_policy_id", types=(str,))
    if not plan_policy_id:
        raise SchemaViolationError("plan_policy_id: must be non-empty")
    _require_hex64(payload, "event_digest")

    present_admitted = _EXECUTION_V3_ADMITTED_FIELDS & set(payload)
    if kind == "admitted_run":
        missing = _EXECUTION_V3_ADMITTED_FIELDS - set(payload)
        if missing:
            raise SchemaViolationError(
                f"an admitted_run execution receipt requires {sorted(missing)} — an admitted "
                "verdict was produced under a measured identity, so its heads/coordinates/artifact "
                "must be bound"
            )
        # the two heads + the four measured calibration coordinates are bare 64-hex digests.
        for _field in (
            "bound_oracle_head", "policy_generation",
            "resolved_profile_digest", "trust_policy_digest", "guard_policy_digest",
            "execution_identity_digest",
        ):
            _require_hex64(payload, _field)
        # the artifact tree hash + the image are ``sha256:<hex64>`` content addresses
        # (core.tree_hash + the OCI image-config id) — the prefix is part of what actually ran.
        _require_sha256_prefixed(payload, "artifact_tree_hash")
        _require_sha256_prefixed(payload, "image_digest")
        detector_id = _require(payload, "detector_id", types=(str,))
        if not detector_id:
            raise SchemaViolationError("detector_id: must be non-empty for an admitted_run")
        # outcome is the real engine aggregate: pass|fail is admissible evidence; error (a measured
        # but errored run) is integrity-valid but non-admissible (evaluate_admission drops it). No
        # further constraint here — the admitted verdict is what the engine measured.
    elif present_admitted:
        raise SchemaViolationError(
            f"result_kind {kind!r} must NOT carry admitted-only fields "
            f"{sorted(present_admitted)} — only an admitted_run measured "
            "heads/coordinates/artifact (no fabricated measurement)"
        )
    elif payload.get("outcome") != "error":
        raise SchemaViolationError(
            f"result_kind {kind!r} did not admit a verdict — its outcome must be 'error' "
            "(fail-closed)"
        )


def validate_execution_payload(payload: dict[str, Any]) -> None:
    """Dispatch to the correct version validator based on schema_version."""
    sv = payload.get("schema_version")
    if sv == 1:
        validate_execution_payload_v1(payload)
    elif sv == 2:
        validate_execution_payload_v2(payload)
    elif sv == 3:
        validate_execution_payload_v3(payload)
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


def validate_teardown_payload_v3(payload: dict[str, Any]) -> None:
    """Validate a teardown receipt payload (schema v3 — enforcement). Structurally the v2 shape at
    version 3: runtime_pack_digest required; ``failure``/``error`` record whether the sandbox torn
    down cleanly (a failed teardown makes the whole enforcement chain inadmissible)."""
    _check_unknown_keys(payload, _TEARDOWN_KEYS_V2, "teardown")
    _validate_schema_version(payload, 3)
    _validate_teardown_common(payload)
    _require_hex64(payload, "runtime_pack_digest")


def validate_teardown_payload(payload: dict[str, Any]) -> None:
    """Dispatch to the correct version validator based on schema_version."""
    sv = payload.get("schema_version")
    if sv == 1:
        validate_teardown_payload_v1(payload)
    elif sv == 2:
        validate_teardown_payload_v2(payload)
    elif sv == 3:
        validate_teardown_payload_v3(payload)
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
    if sv not in SUPPORTED_SCHEMA_VERSIONS:
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
