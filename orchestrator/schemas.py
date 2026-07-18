"""orchestrator/schemas.py — versioned payload schemas for each receipt kind.

Signature validity and evidence completeness are separate concerns (§0.4).
A chain can have valid signatures over incomplete evidence; schema validation
is the admission gate that rejects it independently.

Schema versions:
  v1 (Phase 0): exact key sets, bool exclusion, TZ timestamps, prereg_digest
      and execution_digest required for continuity, runtime_pack_digest optional.
  v2 (Phase 1): runtime_pack_digest REQUIRED in execution and teardown;
      observer_log_digest and observer_log_truncated REQUIRED in execution.
  v3 (Phase 2, slice 2.1 — LIVE ENFORCEMENT, provenance-typed & scenario-specific): the PREREG is
      the signed PREDICTION, minted before the run — it commits ``scenario`` +
      ``configured_policy_id`` + ``code_sha`` + the pre-run run context + the ``expected`` triple.
      The EXECUTION receipt is provenance-typed (configured / observed / captured / seed_trace /
      fault_injection) and SCENARIO-SPECIFIC: its exact key set is the common set plus the
      scenario's observed set, and it signs ONLY what the scenario produced — an admitted run its
      measured coordinates, a subject-drift refusal the configured second-image identity (NO
      drifted measured coords), an ABA / tamper the signed ``fault_injection``. ``plan_policy_id``
      is an EXPLICIT null when no plan was captured. Admissibility = the observed triple equals the
      preregistered expected triple, and an infrastructure_failure is never admissible.
      Teardown/index are the v2 shape at version 3.

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

from .expectations import ScenarioId

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
# The CLOSED scenario set — SOURCED from the authored-expectation ontology (single source of truth;
# expectations.py cannot import gated, so a v3 scenario is always one the harness authored a
# prediction for). ``mis_route`` is absent (Q3: no JobResult → no signed chain).
VALID_SCENARIOS: frozenset[str] = frozenset(s.value for s in ScenarioId)
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
# v3 prereg (enforcement) — the SIGNED PREDICTION, minted BEFORE the run. Only pre-run-knowable
# signables: the scenario, the configured policy, the harness code identity, the pre-run run
# context, and the committed ``expected`` triple. The expected triple is the falsifiability
# instrument — the observation can only CONFIRM or REFUTE it (see evaluate_admission).
_PREREG_KEYS_V3: frozenset[str] = _PREREG_KEYS | {
    "scenario",                # one of VALID_SCENARIOS (the closed authored set)
    "configured_policy_id",    # CONFIGURED — the policy the run targets (universal; was policy_id)
    "code_sha",                # package-byte digest of the harness — NON-authz identity (labelled)
    "rc_event_digest",         # run-context: digest of the GatingEvent (pre-run knowable)
    "rc_image_ref",            # run-context: the image chosen pre-run
    "rc_detector_id",          # run-context: the detector chosen pre-run
    "expected_kind",           # the committed prediction: JobResult class
    "expected_reason",         # the committed prediction: closed reason token (admitted → outcome)
    "expected_sub_reason",     # the committed prediction: sub_reason ("" for most)
}

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

# v3 execution (LIVE ENFORCEMENT) — provenance-typed, SCENARIO-SPECIFIC. Fields are typed by
# provenance class and a receipt may sign ONLY what its scenario actually produced in each class:
#
#   CONFIGURED — echoed / chosen pre-run: scenario, configured_policy_id, event_digest.
#   OBSERVED   — the CLOSED discriminator the run produced: result_kind/result_reason/
#                result_sub_reason/gate_outcome + outcome; plus scenario-specific observed fields.
#   CAPTURED   — plan_policy_id: ALWAYS present but an EXPLICIT null when no plan was captured (a
#                non_run dispatched none) — never fabricated from the configured policy; a signed
#                null is cryptographically distinct from omission (no manufactured receipt data).
#   SEED_TRACE — seed_trace: the signed SeedProvenance (how the policy reached ENABLED).
#
# The COMMON set below is present in EVERY enforcement execution receipt; the scenario-specific
# observed set is added per scenario (see _SCENARIO_OBSERVED). An admitted run binds its measured
# coordinates; a refusal/non-run/infra binds only what it observed — no fabricated measurement, and
# (amendment 4) NEVER measured coordinates read off the mutable, non-authoritative report sink.
_EXECUTION_V3_COMMON: frozenset[str] = frozenset(
    {
        # common execution envelope
        "schema_version",
        "profile",
        "gated_commit",
        "outcome",                    # pass|fail|error (admitted → engine aggregate; else error)
        "executed_at",
        "canonical_digest_alg",
        "canonical_digest_version",
        "prereg_digest",
        # configured (echoed / pre-run)
        "scenario",                   # == prereg.scenario
        "configured_policy_id",       # == prereg.configured_policy_id (the enforced policy)
        "event_digest",               # digest of the GatingEvent
        # observed — the closed discriminator (always present)
        "result_kind",                # one of VALID_RESULT_KINDS
        "result_reason",              # closed token (refusal/disposition/infra; verdict=admitted)
        "result_sub_reason",          # admission sub_reason ("" for the non-admission kinds)
        "gate_outcome",               # VALID_GATE_OUTCOMES, or an EXPLICIT null for an infra row
        # captured — explicit null when no plan was dispatched (a non_run)
        "plan_policy_id",
        # seed trace — the signed SeedProvenance sub-object
        "seed_trace",
    }
)
# The measured coordinates only an ADMITTED run produces (from the authoritative engine return, not
# the mutable report sink). Bound ONLY for the compliant_admit scenario.
_EXECUTION_V3_ADMITTED_FIELDS: frozenset[str] = frozenset(
    {
        "bound_oracle_head",                  # the calibration head the run was admitted against
        "observed_policy_head_post_admission",  # post-read policy head — NO bracket claim (amdt 4)
        "artifact_tree_hash",                 # the ArtifactSpec.tree_hash the sandbox verified
        "image_digest",                       # the OCI image BY DIGEST that executed
        "resolved_profile_digest",            # measured calibration coordinate 1
        "trust_policy_digest",                # measured calibration coordinate 2
        "guard_policy_digest",                # measured calibration coordinate 3
        "execution_identity_digest",          # measured calibration coordinate 4
    }
)
# The scenario-specific OBSERVED fields (added to the common set). Each scenario signs exactly what
# it produced: an admitted run its measured coordinates; a subject-drift refusal the CONFIGURED
# second-image identity + refusal reason (NO measured coords — amendment 4); an ABA / tamper the
# signed fault_injection sub-object.
_SCENARIO_OBSERVED: dict[str, frozenset[str]] = {
    ScenarioId.COMPLIANT_ADMIT.value: _EXECUTION_V3_ADMITTED_FIELDS,
    ScenarioId.NON_ENABLED_DEGRADED.value: frozenset(),
    ScenarioId.ABA_GENERATION_MOVED.value: frozenset({"fault_injection"}),
    ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE.value: frozenset({"drift_image_digest"}),
    ScenarioId.SHA_TAMPER.value: frozenset({"fault_injection"}),
}
# Nested signed sub-object key sets.
_SEED_TRACE_KEYS: frozenset[str] = frozenset(
    {"policy_id", "detector_id", "set_id", "calibration_result_ref",
     "pinned_set_version", "subject", "policy_head"}
)
# fault_injection disclosure — locus/mechanism/interleaving_point ALWAYS; the ABA scheduler also
# signs the FIVE heads (the movement trace: bind H, moved H1, returned H, + scheduler-observed
# pre/post policy heads) so "head returned to an identical value with real movement between" is
# verifiable from the receipt alone. A tamper injection signs only the triple (it moves no heads).
_FAULT_INJECTION_BASE_KEYS: frozenset[str] = frozenset({"locus", "mechanism", "interleaving_point"})
_FAULT_INJECTION_ABA_KEYS: frozenset[str] = _FAULT_INJECTION_BASE_KEYS | {
    "head_bound", "head_moved", "head_returned", "policy_head_pre", "policy_head_post"
}


def execution_keys_for_scenario(scenario: str) -> frozenset[str]:
    """The EXACT key set a v3 execution receipt must carry for *scenario* (common + the scenario's
    observed set). Unknown scenario → the common set only, which fails scenario validation."""
    return _EXECUTION_V3_COMMON | _SCENARIO_OBSERVED.get(scenario, frozenset())


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
    preregistered_at. v3 (enforcement) additionally REQUIRES the signed-prediction fields: scenario,
    configured_policy_id, code_sha, the pre-run run context (rc_*), and the committed ``expected``
    triple. The prediction is minted before the run; the observation can only confirm or refute it.
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
        scenario = _require(payload, "scenario", types=(str,))
        if scenario not in VALID_SCENARIOS:
            raise SchemaViolationError(
                f"scenario: must be one of {sorted(VALID_SCENARIOS)}, got {scenario!r}")
        for _field in ("configured_policy_id", "rc_image_ref", "rc_detector_id"):
            if not _require(payload, _field, types=(str,)):
                raise SchemaViolationError(f"{_field}: must be non-empty in a v3 prereg")
        _require_hex64(payload, "code_sha")        # package-byte digest (labelled non-authz)
        _require_hex64(payload, "rc_event_digest")
        # the committed prediction — a closed JobResult kind + non-empty reason token + sub_reason.
        expected_kind = _require(payload, "expected_kind", types=(str,))
        if expected_kind not in VALID_RESULT_KINDS:
            raise SchemaViolationError(
                f"expected_kind: must be a valid result kind, got {expected_kind!r}")
        if not _require(payload, "expected_reason", types=(str,)):
            raise SchemaViolationError("expected_reason: must be a non-empty closed token")
        _require(payload, "expected_sub_reason", types=(str,))  # may be empty


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


# Each scenario implies exactly one JobResult kind — a receipt claiming scenario X with a
# result_kind that scenario cannot produce is incoherent (caught below).
_SCENARIO_KIND: dict[str, str] = {
    ScenarioId.COMPLIANT_ADMIT.value: "admitted_run",
    ScenarioId.NON_ENABLED_DEGRADED.value: "non_run",
    ScenarioId.ABA_GENERATION_MOVED.value: "blocking_refusal",
    ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE.value: "blocking_refusal",
    ScenarioId.SHA_TAMPER.value: "infrastructure_failure",
}


def _require_nested(payload: dict[str, Any], key: str, allowed: frozenset[str], name: str) -> Any:
    """Require a nested signed sub-object with EXACTLY *allowed* keys (equality, not subset)."""
    obj = _require(payload, key, types=(dict,))
    _check_unknown_keys(obj, allowed, name)
    missing = allowed - set(obj)
    if missing:
        raise SchemaViolationError(f"{name}: missing required keys {sorted(missing)}")
    return obj


def _require_nonempty_str_fields(obj: dict[str, Any], keys: frozenset[str], name: str) -> None:
    for k in sorted(keys):
        if not _require(obj, k, types=(str,)):
            raise SchemaViolationError(f"{name}.{k}: must be a non-empty string")


def _validate_result_discriminator(payload: dict[str, Any], scenario: str) -> str:
    """Validate the CLOSED discriminator + the CAPTURED plan_policy_id (explicit-null rules), and
    that ``result_kind`` is the kind *scenario* produces. Returns the result_kind."""
    kind = _require(payload, "result_kind", types=(str,))
    if kind not in VALID_RESULT_KINDS:
        raise SchemaViolationError(
            f"result_kind: must be one of {sorted(VALID_RESULT_KINDS)}, got {kind!r}")
    if kind != _SCENARIO_KIND[scenario]:
        raise SchemaViolationError(
            f"result_kind {kind!r} is not the kind scenario {scenario!r} produces "
            f"({_SCENARIO_KIND[scenario]!r}) — incoherent evidence")
    if not _require(payload, "result_reason", types=(str,)):
        raise SchemaViolationError("result_reason: must be a non-empty audit token")
    _require(payload, "result_sub_reason", types=(str,))  # may be empty
    # gate_outcome — EXPLICIT null for an infra row; a known outcome otherwise.
    gate_outcome = payload.get("gate_outcome", "<absent>")
    if kind == "infrastructure_failure":
        if gate_outcome is not None:
            raise SchemaViolationError(
                "gate_outcome: an infrastructure_failure row carries an explicit null gate outcome")
    else:
        if gate_outcome not in VALID_GATE_OUTCOMES:
            raise SchemaViolationError(
                f"gate_outcome: must be one of {sorted(VALID_GATE_OUTCOMES)}, got {gate_outcome!r}")
    # plan_policy_id — CAPTURED: an EXPLICIT null when no plan was dispatched (a non_run); the
    # captured plan's policy otherwise (never fabricated from the configured policy).
    plan_policy_id = payload.get("plan_policy_id", "<absent>")
    if kind == "non_run":
        if plan_policy_id is not None:
            raise SchemaViolationError(
                "plan_policy_id: a non_run dispatched no plan — it must be an explicit null, not a "
                "fabricated policy id")
    else:
        if not isinstance(plan_policy_id, str) or not plan_policy_id:
            raise SchemaViolationError(
                "plan_policy_id: a plan was captured — it must be a non-empty policy id")
    return str(kind)


def validate_execution_payload_v3(payload: dict[str, Any]) -> None:
    """Validate an execution receipt payload (schema v3 — LIVE ENFORCEMENT). Provenance-typed and
    SCENARIO-SPECIFIC: the exact key set is the common set + the scenario's observed set, and a
    receipt may sign ONLY what its scenario produced. Fail-closed on a missing/extra field, an
    incoherent scenario↔kind, or a fabricated (rather than explicitly-null) capture."""
    scenario = _require(payload, "scenario", types=(str,))
    if scenario not in VALID_SCENARIOS:
        raise SchemaViolationError(
            f"scenario: must be one of {sorted(VALID_SCENARIOS)}, got {scenario!r}")
    _check_unknown_keys(payload, execution_keys_for_scenario(scenario), "execution")
    _validate_schema_version(payload, 3)
    _validate_execution_common(payload)  # profile/gated_commit/outcome/executed_at/digest/prereg
    if not _require(payload, "configured_policy_id", types=(str,)):
        raise SchemaViolationError("configured_policy_id: must be non-empty")
    _require_hex64(payload, "event_digest")
    kind = _validate_result_discriminator(payload, scenario)
    # SEED_TRACE — always present (every enforcement scenario reached ENABLED via a real seed).
    seed = _require_nested(payload, "seed_trace", _SEED_TRACE_KEYS, "seed_trace")
    _require_nonempty_str_fields(seed, _SEED_TRACE_KEYS, "seed_trace")

    # scenario-specific OBSERVED fields.
    if scenario == ScenarioId.COMPLIANT_ADMIT.value:
        # the measured coordinates the ADMITTED run produced (from the authoritative return).
        for _field in (
            "bound_oracle_head", "observed_policy_head_post_admission",
            "resolved_profile_digest", "trust_policy_digest", "guard_policy_digest",
            "execution_identity_digest",
        ):
            _require_hex64(payload, _field)
        _require_sha256_prefixed(payload, "artifact_tree_hash")
        _require_sha256_prefixed(payload, "image_digest")
    elif scenario == ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE.value:
        # amendment 4: sign the CONFIGURED second-image identity + the refusal reason — NO measured
        # coordinates (the drifted report sink is non-authoritative; deferred to a gated follow-up).
        _require_sha256_prefixed(payload, "drift_image_digest")
    elif scenario == ScenarioId.ABA_GENERATION_MOVED.value:
        fi = _require_nested(
            payload, "fault_injection", _FAULT_INJECTION_ABA_KEYS, "fault_injection")
        _require_nonempty_str_fields(fi, _FAULT_INJECTION_ABA_KEYS, "fault_injection")
    elif scenario == ScenarioId.SHA_TAMPER.value:
        fi = _require_nested(
            payload, "fault_injection", _FAULT_INJECTION_BASE_KEYS, "fault_injection")
        _require_nonempty_str_fields(fi, _FAULT_INJECTION_BASE_KEYS, "fault_injection")
    # NON_ENABLED_DEGRADED carries no scenario-specific observed field (no plan, no measurement).

    # outcome coherence: only an admitted run carries a pass|fail verdict; every other kind errored.
    if kind == "admitted_run":
        if payload.get("outcome") not in ("pass", "fail", "error"):
            raise SchemaViolationError("an admitted_run outcome must be pass|fail|error")
    elif payload.get("outcome") != "error":
        raise SchemaViolationError(
            f"result_kind {kind!r} did not admit a verdict — its outcome must be 'error'")


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
# Enforcement admissibility helpers — the expectation-vs-observation triples (§ evidence.py)
# ------------------------------------------------------------------


def enforcement_expected_triple(prereg_payload: dict[str, Any]) -> tuple[str, str, str]:
    """The committed prediction from a v3 prereg: ``(expected_kind, expected_reason,
    expected_sub_reason)``."""
    return (
        str(prereg_payload["expected_kind"]),
        str(prereg_payload["expected_reason"]),
        str(prereg_payload["expected_sub_reason"]),
    )


def enforcement_observed_triple(execution_payload: dict[str, Any]) -> tuple[str, str, str]:
    """The observed outcome from a v3 execution receipt, in the SAME coordinate as the prediction:
    ``(result_kind, reason, result_sub_reason)`` where ``reason`` is the OUTCOME (pass|fail) for an
    admitted run — the coarse falsifiable claim (Q2) — and the closed ``result_reason`` token
    otherwise."""
    kind = str(execution_payload["result_kind"])
    reason = (
        str(execution_payload["outcome"]) if kind == "admitted_run"
        else str(execution_payload["result_reason"])
    )
    return (kind, reason, str(execution_payload["result_sub_reason"]))


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
