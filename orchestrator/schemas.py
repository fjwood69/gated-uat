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
      The EXECUTION receipt is provenance-typed via the (scenario, observed_kind) MATRIX: its exact
      key set is COMMON | configured(scenario) | observed(result_kind). The SCENARIO governs the
      configured / fault-injection fields (what the harness did); the OBSERVED result_kind governs
      the observed-result fields (what the SUT produced) — so EVERY kind is representable under
      EVERY scenario and a refutation (an ABA that unexpectedly admits) is a well-formed record, not
      an unrepresentable one. ``plan_policy_id`` is an EXPLICIT null iff non_run;
      ``gate_outcome`` an
      explicit null iff infra. Integrity checks provenance consistency; admissibility (the observed
      triple == the preregistered expected triple, and never an infra failure) is the SOLE
      value-vs-prediction check. Teardown/index are the v2 shape at version 3.

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

from .expectations import ScenarioId, expected_for

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
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
# B1 board sides — a tempting-task row (target: gauntlet-green, gate-BLOCKED) and its preregistered
# clean-counterpart (target: green across all stages). Two-sidedness is a build requirement (§1).
VALID_SIDES: frozenset[str] = frozenset({"tempting", "clean"})
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
    "rc_image_ref",            # run-context: the image tag chosen pre-run
    "rc_image_digest",         # run-context: the RESOLVED sha256:<hex64> run image (continuity)
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
# observed set is added per the matrix (see _OBSERVED_FIELDS). An admitted run binds its measured
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
# --- the (scenario, observed_kind) MATRIX (re-validation redesign) ------------------------------
# The prior cut keyed required fields to the scenario's PREDICTED kind — a CONFIRMATION FILTER that
# could not serialise a refutation (an ABA that unexpectedly admits). The two axes are now SEPARATE:
#   SCENARIO   -> the CONFIGURED + FAULT-INJECTION fields (what the HARNESS did).
#   OBSERVED   -> the OBSERVED-RESULT fields (what the SUT PRODUCED), keyed by result_kind.
# Exact key set = COMMON | configured(scenario) | observed(result_kind). EVERY closed kind is
# representable under EVERY scenario; the schema does NOT check scenario<->kind coherence (that WAS
# the defect). Integrity = a well-formed, provenance-consistent record; evaluate_admission ALONE
# compares observed-vs-expected.

# CONFIGURED / FAULT-INJECTION fields, keyed by SCENARIO (present whatever the SUT then did).
_SCENARIO_CONFIGURED: dict[str, frozenset[str]] = {
    ScenarioId.COMPLIANT_ADMIT.value: frozenset(),
    ScenarioId.NON_ENABLED_DEGRADED.value: frozenset(),
    ScenarioId.ABA_GENERATION_MOVED.value: frozenset({"fault_injection"}),
    ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE.value: frozenset({"drift_image_digest"}),
    ScenarioId.SHA_TAMPER.value: frozenset({"fault_injection"}),
    # slice 2.2a — each injecting scenario discloses a base-triple fault_injection (like tamper):
    # the scheduler's COMPLETED induction record of what was done at what interleave.
    ScenarioId.SET_HEAD_STALE.value: frozenset({"fault_injection"}),
    ScenarioId.ORACLE_UNAVAILABLE.value: frozenset({"fault_injection"}),
    ScenarioId.LIVE_ATTESTATION_UNAVAILABLE.value: frozenset({"fault_injection"}),
    # slice 2.2b — the recalibration-loop scenarios disclose the same base-triple induction record.
    ScenarioId.AUTHORIZED_SET_MOVED.value: frozenset({"fault_injection"}),
    ScenarioId.AUTHORIZED_SUBJECT_MOVED.value: frozenset({"fault_injection"}),
}

# slice 2.2a: the scenarios whose fault_injection is the BASE triple (locus/mechanism/interleave) —
# the tamper + the three admission-currency injections. ABA uses the richer 5-head shape (M4).
_BASE_TRIPLE_FAULT_SCENARIOS: frozenset[str] = frozenset({
    ScenarioId.SHA_TAMPER.value, ScenarioId.SET_HEAD_STALE.value,
    ScenarioId.ORACLE_UNAVAILABLE.value, ScenarioId.LIVE_ATTESTATION_UNAVAILABLE.value,
    ScenarioId.AUTHORIZED_SET_MOVED.value, ScenarioId.AUTHORIZED_SUBJECT_MOVED.value,
})

# The measured coordinates only an ADMITTED run produces (from the authoritative engine return, not
# the mutable report sink). OBSERVED-RESULT fields, keyed by the OBSERVED result_kind.
_ADMITTED_COORDS: frozenset[str] = frozenset(
    {
        "bound_oracle_head",                  # the calibration head the run was admitted against
        "observed_policy_head_post_admission",  # post-read policy head — NO bracket claim (amdt 4)
        "artifact_tree_hash",                 # the bound ArtifactSpec.tree_hash captured at binding
        "image_digest",                       # the OCI image BY DIGEST that executed
        "resolved_profile_digest",            # measured calibration coordinate 1
        "trust_policy_digest",                # measured calibration coordinate 2
        "guard_policy_digest",                # measured calibration coordinate 3
        "execution_identity_digest",          # measured calibration coordinate 4
    }
)
_OBSERVED_FIELDS: dict[str, frozenset[str]] = {
    "admitted_run": _ADMITTED_COORDS,       # measured coordinates from the authoritative return
    "blocking_refusal": frozenset(),        # a refusal exposes NO authoritative report (amdt 4)
    "non_run": frozenset(),                 # nothing ran
    "infrastructure_failure": frozenset(),  # the machinery failed before a verdict
}

# Nested signed sub-object key sets. seed_image_digest (from the calibration result's
# execution_identity) anchors the SEED endpoint of a drift (M3/QM-3).
_SEED_TRACE_KEYS: frozenset[str] = frozenset(
    {"policy_id", "detector_id", "set_id", "calibration_result_ref",
     "pinned_set_version", "subject", "policy_head", "seed_image_digest"}
)
# fault_injection disclosure — locus/mechanism/interleaving_point ALWAYS; the ABA scheduler also
# signs the FIVE heads (the movement trace: bind H, moved H1, returned H, + scheduler-observed
# pre/post policy heads) so "head returned to an identical value with real movement between" is
# verifiable from the receipt alone. A tamper injection signs only the triple (it moves no heads).
_FAULT_INJECTION_BASE_KEYS: frozenset[str] = frozenset({"locus", "mechanism", "interleaving_point"})
_FAULT_INJECTION_ABA_KEYS: frozenset[str] = _FAULT_INJECTION_BASE_KEYS | {
    "head_bound", "head_moved", "head_returned", "policy_head_pre", "policy_head_post"
}


def execution_keys_for(scenario: str, observed_kind: str) -> frozenset[str]:
    """The EXACT key set a v3 execution receipt must carry for (scenario, observed_kind): the common
    set + the scenario's configured/fault fields + the observed kind's result fields. Every closed
    kind is representable under every scenario (no confirmation filter)."""
    return (
        _EXECUTION_V3_COMMON
        | _SCENARIO_CONFIGURED.get(scenario, frozenset())
        | _OBSERVED_FIELDS.get(observed_kind, frozenset())
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

# --- B1 board manifest (the anchored, complete-denominator board preregistration) ----------------
# The manifest is the board's SIGNED EXPECTATION, minted before any agent/API call. Amendment 1:
# it hash-anchors the whole board (its digest is referenced by every downstream cell receipt).
# Amendment 2: ``cells`` is the COMPLETE ORDERED denominator — the exact planned run_id set, not
# merely N; the render gate (manifest.py) requires exactly one terminal receipt per planned cell.
_MANIFEST_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "manifest_version",
        "gated_commit",
        "code_sha",           # package-byte digest of the harness (labelled non-authz identity)
        "corpus_version",
        "preregistered_at",   # descriptive only (order = the hash-anchor, not this)
        "tasks",              # task specs (prompt+hash, invariant, gauntlet, side)
        "denominator",        # n_replicates, seed, temperature, params, retry, infra
        "cells",              # the COMPLETE ORDERED list of planned cells (the denominator)
        "toolchain",          # the SIGNED static-toolchain pin (dissent gap 4) — committed here
    }
)
# The static toolchain pinned IN the signed manifest (dissent gap 4): the render + the static stage
# enforce against THIS, so an operator can't silently swap the analyser. env_digest is, SPECIFICALLY
# (amendment C, gap-1), the static OCI image's RESOLVED CONFIG DIGEST — the ``sha256:<{{.Id}}>`` the
# sandbox resolves and runs (== the coordinate the enforcement side binds). static_stage ASSERTS the
# sandbox's observed image config digest == this value, so pinning the image pins ruff + mypy
# (subsumes per-exe digests). NB: this is an anti-drift IDENTITY (which bytes were presented), NOT a
# runtime-behaviour assurance; the version strings are descriptive.
_TOOLCHAIN_KEYS: frozenset[str] = frozenset(
    {"python_version", "ruff_version", "mypy_version", "env_digest"})
_TASK_KEYS: frozenset[str] = frozenset(
    {
        "task_id",
        "prompt",             # verbatim, as given to producers (anti-entrapment: published)
        "prompt_hash",        # hex64 digest of the exact prompt bytes
        "side",               # tempting | clean
        "counterpart_task_id",  # the clean-counterpart task_id (points back)
        "detector_id",        # the invariant enforced at the gate
        "invariant_corpus_version",  # the calibrated corpus version that judges it
        "review_prompt_hash",  # hex64 of the fixed, published LLM-review prompt
    }
)
_DENOMINATOR_KEYS: frozenset[str] = frozenset(
    {
        "n_replicates",       # runs per (task, lineage) — declared upfront
        "seed",
        "temperature",
        "params",             # dict of any additional generation params (frozen at manifest time)
        "retry_policy",       # must be "none" (no silent reruns; a fail = ERROR row)
        "infra_failure_disposition",  # must be "error_and_publish" (amendment: infra-fail is a row)
    }
)
_CELL_KEYS: frozenset[str] = frozenset(
    {
        "cell_id",            # stable deterministic id (task_id/lineage/replicate)
        "task_id",
        "lineage",            # producing model/agent lineage (DISCLOSURE, never a ranking)
        "side",               # tempting | clean (== the task's side)
        "replicate",          # 0..n_replicates-1 within (task, lineage)
        "planned_run_id",     # UUID4 minted at manifest time; every cell receipt references it
        "reviewer_lineage",   # the deterministically-assigned reviewer; MUST differ from lineage
    }
)

# ------------------------------------------------------------------
# B1 step 2 — the gauntlet cell_stage receipt (one signed OBSERVATION per stage of one cell)
# ------------------------------------------------------------------

# The ordered gauntlet stages. A cell_stage receipt's ``stage`` MUST be one of these.
VALID_STAGES: frozenset[str] = frozenset({"static", "own_tests", "llm_review", "gate"})
# Cell-stage outcomes. ``blocked`` is the gate's BlockingRefusal projection — the payload of a
# demonstration row (green-green-green-BLOCKED) and is VALID ONLY on the ``gate`` stage.
VALID_CELL_OUTCOMES: frozenset[str] = frozenset({"pass", "fail", "error", "blocked"})
# Reserved sentinel bound on a cell-level ERROR receipt when the artifact could NOT be safely
# materialised or hashed. All-zeros is not a mathematically impossible sha256 output — it is a
# RESERVED value made UNREACHABLE for a normal receipt BY SCHEMA LAW (the sentinel law below forces
# outcome=error + harness_error), never by cryptographic accident.
UNMEASURABLE_TREE_DIGEST: str = "sha256:" + "0" * 64
# Own-tests pytest status (derived OUT-OF-BAND from the container exit code, never producer output).
VALID_PYTEST_STATUS: frozenset[str] = frozenset({"passed", "failed", "no_tests", "error"})
# LLM reviewer's structured verdict (measurement, not a security boundary): strict approve → PASS.
VALID_REVIEW_VERDICTS: frozenset[str] = frozenset({"approve", "request_changes"})

# --- CANONICAL stage outcome maps (single source; orchestrator.gauntlet imports these) ------------
# Coherence is SCHEMA LAW on EVERY stage, not just the gate — a signed receipt whose outcome does
# not
# match its observed measurement is unrepresentable (swept across all four producers, not one).
# own_tests: the OUT-OF-BAND container exit code fixes the status; the status fixes the cell
# outcome.
PYTEST_STATUS_BY_EXIT: dict[int, str] = {0: "passed", 1: "failed", 5: "no_tests"}
OWN_TESTS_CELL_OUTCOME: dict[str, str] = {
    "passed": "pass", "failed": "fail", "no_tests": "error", "error": "error"}
# gate: the cell outcome for a non-admitted kind (admitted -> its own verdict pass|fail).
GATE_CELL_OUTCOME_BY_KIND: dict[str, str] = {
    "blocking_refusal": "blocked", "non_run": "error", "infrastructure_failure": "error"}
# gate: the account()-COHERENT gate_outcome per result_kind. The schema cannot import gated, so this
# re-encodes gate.job_result.account(); tests/test_gauntlet_coherence.py binds it to the REAL
# account() output (a parity test) so the re-encoding cannot silently drift (unbound-reader guard).
# NB (dissent catch): a BlockingRefusal carries gate_outcome=run_verdict (a real admission verdict
# was
# produced), NOT block_gate.
GATE_OUTCOME_BY_RESULT_KIND: dict[str, frozenset[str | None]] = {
    "admitted_run": frozenset({"run_verdict"}),
    "blocking_refusal": frozenset({"run_verdict"}),
    "non_run": frozenset({"block_gate", "neutral_gate"}),
    "infrastructure_failure": frozenset({None}),
}
# non_run binds TIGHTER than the kind: the disposition (== result_reason) FIXES the gate_outcome —
# a non_run may not pair either way (gap 3). == gate.job_result.account() over NonRunDecision.
NON_RUN_GATE_OUTCOME_BY_REASON: dict[str, str] = {
    "block_action_required": "block_gate",
    "skip_neutral": "neutral_gate",
}


def expected_pytest_status(container_exit_code: int | None) -> str:
    """The pytest status the OUT-OF-BAND container exit code fixes (null -> error)."""
    if container_exit_code is None:
        return "error"
    return PYTEST_STATUS_BY_EXIT.get(container_exit_code, "error")

_CELL_STAGE_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "manifest_digest",      # hex64 — the signed manifest receipt digest (the board anchor)
        "cell_id",              # == a manifest cell_id (task_id/lineage/replicate)
        "lineage",              # producing lineage (== manifest cell)
        "reviewer_lineage",     # cross-lineage reviewer (== manifest cell; != lineage)
        "side",                 # tempting | clean (== manifest cell)
        "stage",                # one of VALID_STAGES
        "artifact_tree_digest",  # sha256:<hex64> — the ONE digest every cell stage is bound to
        "outcome",              # VALID_CELL_OUTCOMES ('blocked' only on the gate stage)
        "executed_at",
        "code_sha",             # harness identity (labelled non-authz), package-byte digest
        "observation",          # stage-specific signed sub-record (exact keys per stage)
    }
)
# Exact observation key sets, keyed by stage. The observation is what the ORCHESTRATOR observed —
# not a producer claim: own_tests is the OUT-OF-BAND container exit code; llm_review records the
# provider/model + raw req/resp digests of a MEASUREMENT; gate carries the digest the enforcement
# adapter ACTUALLY measured (measured_tree_digest), which MUST equal artifact_tree_digest (P1).
# static runs IN the hermetic sandbox (gap-1): toolchain identity is the sandbox's resolved image
# config digest (``env_digest``, asserted == manifest env_digest, subsumes tool digests); the ONLY
# measured signal is the out-of-band exit code (stdout is DEVNULL); ``invocation_digest`` binds WHAT
# ran (FOLD-C) so a neutered invocation is auditable. (No tool_versions/findings_count — parsing
# stdout would re-trust the very output the sandbox discards.)
_OBS_KEYS_STATIC: frozenset[str] = frozenset(
    {"env_digest", "ruff_exit", "mypy_exit", "invocation_digest"})
_OBS_KEYS_OWN_TESTS: frozenset[str] = frozenset(
    {"sandbox_isolation_level", "image_digest", "container_exit_code", "pytest_status",
     "invocation_digest"})
# llm_review binds ``source_digest`` (the canonical sealed-source bytes, reconstructable to
# artifact_tree_digest — FOLD-B) in addition to the raw request/response digests.
_OBS_KEYS_LLM_REVIEW: frozenset[str] = frozenset(
    {"provider_id", "model_id", "review_prompt_hash", "source_digest", "request_digest",
     "response_digest", "verdict"})
_OBS_KEYS_GATE: frozenset[str] = frozenset(
    {"result_kind", "result_reason", "result_sub_reason", "gate_outcome", "measured_tree_digest"})
_OBS_KEYS_BY_STAGE: dict[str, frozenset[str]] = {
    "static": _OBS_KEYS_STATIC,
    "own_tests": _OBS_KEYS_OWN_TESTS,
    "llm_review": _OBS_KEYS_LLM_REVIEW,
    "gate": _OBS_KEYS_GATE,
}


class SchemaViolationError(ValueError):
    """Payload fails schema requirements for its receipt kind."""


class SchemaCoherenceError(SchemaViolationError):
    """A field-PAIR is internally contradictory within one observation — a record no honest mapper
    could produce (e.g. gate_outcome contradicts the result_kind/result_reason the account()
    union fixes). Integrity fails; NOT a value-vs-prediction mismatch (that is admissibility)."""


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


def _require_uuid4(payload: dict[str, Any], key: str) -> str:
    value = _require(payload, key, types=(str,))
    if not _UUID4_RE.match(value):
        raise SchemaViolationError(f"Field {key!r}: must be a canonical UUID4, got {value!r}")
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


def _check_exact_keys(payload: dict[str, Any], allowed: frozenset[str], kind: str) -> None:
    """EXACT key-set equality: reject BOTH unknown (extra) AND missing (required) keys. A v3 MATRIX
    cell's key set is exhaustive — every key is required-PRESENT — so an OMITTED key is a malformed
    record, never a permissible default (UAT-1: a missing plan_policy_id must not slip through a
    truthy '<absent>' fallback and then silently disable the downstream continuity comparison). Used
    ONLY for the v3 execution matrix; the legacy/teardown/prereg validators keep _check_unknown_keys
    because they carry genuinely-optional fields and enforce presence per-field via _require."""
    present = set(payload.keys())
    unknown = present - allowed
    missing = allowed - present
    if unknown or missing:
        parts = []
        if missing:
            parts.append(f"missing required keys: {sorted(missing)}")
        if unknown:
            parts.append(f"unknown keys: {sorted(unknown)}")
        raise SchemaViolationError(f"{kind!r} payload {'; '.join(parts)}")


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
        _require_sha256_prefixed(payload, "rc_image_digest")  # the resolved run-image anchor
        # the committed prediction — a closed JobResult kind + non-empty reason token + sub_reason.
        expected_kind = _require(payload, "expected_kind", types=(str,))
        if expected_kind not in VALID_RESULT_KINDS:
            raise SchemaViolationError(
                f"expected_kind: must be a valid result kind, got {expected_kind!r}")
        if not _require(payload, "expected_reason", types=(str,)):
            raise SchemaViolationError("expected_reason: must be a non-empty closed token")
        _require(payload, "expected_sub_reason", types=(str,))  # may be empty
        # M2 — BIND THE AUTHORED CANON: the committed prediction MUST equal the authored fixture for
        # this scenario, so a doctored prereg with a convenient expected triple is rejected. This
        # is the fixture-canon check at PREREG validation; admissibility compares the observation
        # against the SIGNED FROZEN prereg (never recomputes expected_for) — no self-confirmation.
        canon = expected_for(ScenarioId(scenario))
        got = (payload["expected_kind"], payload["expected_reason"], payload["expected_sub_reason"])
        if got != (canon.kind, canon.reason, canon.sub_reason):
            raise SchemaViolationError(
                f"expected triple {got} != the authored fixture "
                f"{(canon.kind, canon.reason, canon.sub_reason)} for scenario {scenario!r} "
                "(the prereg was not authored from the canonical expectation)")


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


def _validate_result_discriminator(payload: dict[str, Any]) -> str:
    """Validate the CLOSED discriminator + the CAPTURED plan_policy_id / gate_outcome explicit-null
    rules. NO scenario↔kind coherence check — every kind is representable under every scenario (the
    matrix records what the SUT DID, agreement or not). These are PROVENANCE-consistency checks
    (integrity), not expected-value checks: a captured plan under a non_run, or a gate outcome under
    an infra row, are malformed records; value mismatches are admissibility's job. Returns the
    result_kind."""
    kind = _require(payload, "result_kind", types=(str,))
    if kind not in VALID_RESULT_KINDS:
        raise SchemaViolationError(
            f"result_kind: must be one of {sorted(VALID_RESULT_KINDS)}, got {kind!r}")
    if not _require(payload, "result_reason", types=(str,)):
        raise SchemaViolationError("result_reason: must be a non-empty audit token")
    reason = str(payload["result_reason"])
    _require(payload, "result_sub_reason", types=(str,))  # may be empty
    # gate_outcome COHERENCE with (result_kind, result_reason) — the closed gated ``account()``
    # pairing written as schema law (total, no else-branch). gate_outcome DUPLICATES the disposition
    # already in result_reason; a redundant field that is present-and-free is attack surface — an
    # unbound copy could contradict the original (QM-2 silent fall-open: non_run +
    # block_action_required paired with neutral_gate). Derived from the SEALED account() mapper
    # (job_result.py: AdmittedRunResult/BlockingRefusal -> RUN_VERDICT; NonRunDecision ->
    # BLOCK_GATE|NEUTRAL_GATE by disposition; InfrastructureFailure -> None) so any real
    # map_job_result output validates and no honest observation is rejected.
    # PRESENCE required (UAT-1): no '<absent>' default — a missing gate_outcome is malformed. (The
    # coherence check below already fails an absent value closed; requiring presence is explicit.)
    if "gate_outcome" not in payload:
        raise SchemaViolationError("gate_outcome: required (a run_verdict|block_gate|neutral_gate "
                                   "token, or an explicit null for infrastructure_failure)")
    gate_outcome = payload["gate_outcome"]
    if kind == "non_run":
        want: str | None = {
            "block_action_required": "block_gate", "skip_neutral": "neutral_gate"}.get(reason)
        if want is None:
            raise SchemaCoherenceError(
                f"non_run result_reason {reason!r} must be block_action_required or skip_neutral")
    else:
        want = {
            "admitted_run": "run_verdict", "blocking_refusal": "run_verdict",
            "infrastructure_failure": None}[kind]
    if gate_outcome != want:
        raise SchemaCoherenceError(
            f"gate_outcome {gate_outcome!r} incoherent with {kind!r}/{reason!r} — account() "
            f"requires {want!r}")
    # plan_policy_id — CAPTURED: an EXPLICIT null iff non_run (the SUT did not execute, so no plan
    # was captured); the captured plan's policy otherwise (never fabricated from the configured
    # policy). A captured plan under a non_run is a provenance contradiction (integrity fail).
    # PRESENCE required (UAT-1): NO '<absent>' default. A missing key previously became the truthy
    # string "<absent>", passing the "non-empty policy id" check for admitted/refusal/infra — and
    # continuity then saw None and SKIPPED the plan==configured comparison. Require the key present,
    # then validate an explicit null (iff non_run) or a non-empty policy id.
    if "plan_policy_id" not in payload:
        raise SchemaViolationError(
            "plan_policy_id: required — an explicit null iff non_run, else the captured policy id")
    plan_policy_id = payload["plan_policy_id"]
    if kind == "non_run":
        if plan_policy_id is not None:
            raise SchemaViolationError(
                "plan_policy_id: a non_run did not execute — it must be an explicit null, not a "
                "captured/fabricated policy id")
    elif not isinstance(plan_policy_id, str) or not plan_policy_id:
        raise SchemaViolationError(
            "plan_policy_id: a plan was captured — it must be a non-empty policy id")
    return str(kind)


def _validate_seed_trace(payload: dict[str, Any]) -> None:
    """The signed SeedProvenance sub-object: every field non-empty; seed_image_digest is the
    canonical ``sha256:<hex64>`` calibration image (the SEED endpoint of a drift, M3/QM-3)."""
    seed = _require_nested(payload, "seed_trace", _SEED_TRACE_KEYS, "seed_trace")
    _require_nonempty_str_fields(seed, _SEED_TRACE_KEYS, "seed_trace")
    if not _SHA256_PREFIXED_RE.match(seed["seed_image_digest"]):
        raise SchemaViolationError(
            "seed_trace.seed_image_digest: must be 'sha256:<64 hex>', got "
            f"{seed['seed_image_digest']!r}")


def _validate_aba_fault_injection(payload: dict[str, Any]) -> None:
    """The ABA fault_injection sub-object: the disclosure triple (locus/mechanism/interleave)
    + the FIVE heads as hex64 digests, and (M4) the ABA SHAPE asserted STRUCTURALLY (not against any
    expected value): head_bound == head_returned (the set-head returned to an identical value),
    head_moved != head_bound (real movement between), policy_head_pre != policy_head_post (policy
    generation actually moved). Non-degenerate — "x" five times cannot pass."""
    fi = _require_nested(payload, "fault_injection", _FAULT_INJECTION_ABA_KEYS, "fault_injection")
    _require_nonempty_str_fields(fi, _FAULT_INJECTION_BASE_KEYS, "fault_injection")
    for _h in ("head_bound", "head_moved", "head_returned", "policy_head_pre", "policy_head_post"):
        _require_hex64(fi, _h)
    if fi["head_bound"] != fi["head_returned"]:
        raise SchemaViolationError(
            "fault_injection: ABA requires head_bound == head_returned (returned identical)")
    if fi["head_moved"] == fi["head_bound"]:
        raise SchemaViolationError(
            "fault_injection: ABA requires head_moved != head_bound (real movement between)")
    if fi["policy_head_pre"] == fi["policy_head_post"]:
        raise SchemaViolationError(
            "fault_injection: ABA requires policy_head_pre != policy_head_post (generation moved)")


def validate_execution_payload_v3(payload: dict[str, Any]) -> None:
    """Validate an execution receipt payload (schema v3 — LIVE ENFORCEMENT). Provenance-typed by the
    (scenario, observed_kind) MATRIX: the exact key set is the common set + the scenario's
    configured/fault fields + the OBSERVED kind's result fields. EVERY closed kind is representable
    under EVERY scenario, so a refutation (e.g. an ABA that unexpectedly admits) is a well-formed
    record — integrity checks provenance consistency, admissibility checks value-vs-prediction. Fail
    closed on a missing/extra field or a provenance contradiction."""
    scenario = _require(payload, "scenario", types=(str,))
    if scenario not in VALID_SCENARIOS:
        raise SchemaViolationError(
            f"scenario: must be one of {sorted(VALID_SCENARIOS)}, got {scenario!r}")
    result_kind = _require(payload, "result_kind", types=(str,))
    if result_kind not in VALID_RESULT_KINDS:
        raise SchemaViolationError(
            f"result_kind: must be one of {sorted(VALID_RESULT_KINDS)}, got {result_kind!r}")
    # EXACT key-set (UAT-1): every matrix-cell key is required-PRESENT (not just no-extras), so a
    # missing plan_policy_id / gate_outcome cannot pass on a truthy default and disable continuity.
    _check_exact_keys(payload, execution_keys_for(scenario, result_kind), "execution")
    _validate_schema_version(payload, 3)
    _validate_execution_common(payload)  # profile/gated_commit/outcome/executed_at/digest/prereg
    if not _require(payload, "configured_policy_id", types=(str,)):
        raise SchemaViolationError("configured_policy_id: must be non-empty")
    _require_hex64(payload, "event_digest")
    kind = _validate_result_discriminator(payload)
    _validate_seed_trace(payload)

    # CONFIGURED / FAULT-INJECTION fields, keyed by SCENARIO (what the harness did).
    if scenario == ScenarioId.ABA_GENERATION_MOVED.value:
        _validate_aba_fault_injection(payload)
    elif scenario in _BASE_TRIPLE_FAULT_SCENARIOS:
        fi = _require_nested(
            payload, "fault_injection", _FAULT_INJECTION_BASE_KEYS, "fault_injection")
        _require_nonempty_str_fields(fi, _FAULT_INJECTION_BASE_KEYS, "fault_injection")
    elif scenario == ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE.value:
        # the CONFIGURED second (drift) image identity — bound to prereg.rc_image_digest in
        # continuity; the refusal proves measured subject drift, not the exact executed image.
        _require_sha256_prefixed(payload, "drift_image_digest")

    # OBSERVED-RESULT fields, keyed by the OBSERVED result_kind (what the SUT produced). Only an
    # admitted run measured coordinates — present whatever the scenario predicted (refutations bind
    # them too).
    if kind == "admitted_run":
        for _field in (
            "bound_oracle_head", "observed_policy_head_post_admission",
            "resolved_profile_digest", "trust_policy_digest", "guard_policy_digest",
            "execution_identity_digest",
        ):
            _require_hex64(payload, _field)
        _require_sha256_prefixed(payload, "artifact_tree_hash")
        _require_sha256_prefixed(payload, "image_digest")

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
# B1 board manifest — the anchored, complete-denominator board preregistration
# ------------------------------------------------------------------


def _validate_task(task: dict[str, Any], idx: int) -> None:
    _check_exact_keys(task, _TASK_KEYS, f"tasks[{idx}]")
    if not _require(task, "task_id", types=(str,)):
        raise SchemaViolationError(f"tasks[{idx}].task_id: must be non-empty")
    if not _require(task, "prompt", types=(str,)):
        raise SchemaViolationError(f"tasks[{idx}].prompt: must be non-empty (published verbatim)")
    _require_hex64(task, "prompt_hash")
    _require_hex64(task, "review_prompt_hash")
    side = _require(task, "side", types=(str,))
    if side not in VALID_SIDES:
        raise SchemaViolationError(f"tasks[{idx}].side: must be one of {sorted(VALID_SIDES)}")
    for _f in ("counterpart_task_id", "detector_id", "invariant_corpus_version"):
        if not _require(task, _f, types=(str,)):
            raise SchemaViolationError(f"tasks[{idx}].{_f}: must be non-empty")


def _validate_denominator(denom: dict[str, Any]) -> int:
    """Amendment 2 + Q4: the whole denominator is committed. retry_policy MUST be 'none' (no silent
    reruns) and infra_failure_disposition MUST be 'error_and_publish' (an infra-failed run is an
    ERROR row, never dropped) — so cherry-picking is unrepresentable by construction. Returns
    n_replicates."""
    _check_exact_keys(denom, _DENOMINATOR_KEYS, "denominator")
    n = _require(denom, "n_replicates", types=(int,))
    if n < 1:
        raise SchemaViolationError("denominator.n_replicates: must be >= 1")
    _require(denom, "seed", types=(int,))
    # temperature is an exact preregistered value carried as a STRING — gated's canonical_digest
    # rejects floats (ambiguous representation), and the exact generation temperature must sign
    # identically every time. params values must likewise be canonical (str/int/bool/null); a float
    # there fails closed at mint.
    if not _require(denom, "temperature", types=(str,)):
        raise SchemaViolationError(
            "denominator.temperature: must be a non-empty string (exact value)")
    _require(denom, "params", types=(dict,))
    retry = _require(denom, "retry_policy", types=(str,))
    if retry != "none":
        raise SchemaViolationError(
            "denominator.retry_policy: must be 'none' — a silent rerun is a cherry-pick vector; a "
            "failed run is published as an ERROR row (amendment: complete ordered denominator)")
    disp = _require(denom, "infra_failure_disposition", types=(str,))
    if disp != "error_and_publish":
        raise SchemaViolationError(
            "denominator.infra_failure_disposition: must be 'error_and_publish' — an infra failure "
            "is an ERROR row on the board, never dropped or rerun (the gate's UNATTESTABLE reflex)")
    return int(n)


def _validate_toolchain(tc: dict[str, Any]) -> None:
    """The signed static-toolchain pin (dissent gap 4). env_digest is the AUTHORITATIVE coordinate
    (dependency-lock digest or pinned OCI image id, ``sha256:<hex64>``); the version strings are
    descriptive. Committed in the manifest so the static stage + the render enforce against it."""
    _check_exact_keys(tc, _TOOLCHAIN_KEYS, "toolchain")
    for k in ("python_version", "ruff_version", "mypy_version"):
        if not _require(tc, k, types=(str,)):
            raise SchemaViolationError(f"toolchain.{k}: must be non-empty")
    _require_sha256_prefixed(tc, "env_digest")


def validate_manifest_payload(payload: dict[str, Any]) -> None:
    """Validate a B1 board-manifest receipt payload — the anchored, complete-denominator board
    preregistration. Integrity checks that make the ratified amendments true-by-construction:
      * COMPLETE ORDERED DENOMINATOR (amendment 2): ``cells`` enumerates, for every (task, lineage)
        present, EXACTLY replicates 0..n-1 — no omission, no duplicate; every planned_run_id and
        cell_id is unique board-wide. The render gate (manifest.py) then requires exactly one
        terminal receipt per planned_run_id, so a cherry-picked board cannot render.
      * REVIEWER INDEPENDENCE (§4.1, checkable from the receipt alone): every cell's
        reviewer_lineage != its producing lineage.
      * every cell references a DECLARED task, and its side matches that task's side.
    Timestamps are descriptive; order is proven by the hash-anchor, not preregistered_at.
    """
    _check_exact_keys(payload, _MANIFEST_KEYS, "manifest")
    _validate_schema_version(payload, 1)
    mv = _require(payload, "manifest_version", types=(int,))
    if mv != 1:
        raise SchemaViolationError(f"manifest_version: expected 1, got {mv}")
    _validate_gated_commit(payload)
    _require_hex64(payload, "code_sha")
    if not _require(payload, "corpus_version", types=(str,)):
        raise SchemaViolationError("corpus_version: must be non-empty")
    _require_iso_timestamp(payload, "preregistered_at")

    tasks = _require(payload, "tasks", types=(list,))
    if not tasks:
        raise SchemaViolationError("tasks: must be a non-empty list")
    task_sides: dict[str, str] = {}
    for i, task in enumerate(tasks):
        if not isinstance(task, dict):
            raise SchemaViolationError(f"tasks[{i}]: must be an object")
        _validate_task(task, i)
        tid = str(task["task_id"])
        if tid in task_sides:
            raise SchemaViolationError(f"tasks: duplicate task_id {tid!r}")
        task_sides[tid] = str(task["side"])

    denom = _require(payload, "denominator", types=(dict,))
    n_replicates = _validate_denominator(denom)

    _validate_toolchain(_require(payload, "toolchain", types=(dict,)))

    cells = _require(payload, "cells", types=(list,))
    if not cells:
        raise SchemaViolationError("cells: must be a non-empty list (the complete denominator)")
    seen_cell_ids: set[str] = set()
    seen_run_ids: set[str] = set()
    # (task_id, lineage) -> the set of replicate indices seen (must end == {0..n-1}, no dupes)
    group_reps: dict[tuple[str, str], set[int]] = {}
    for i, cell in enumerate(cells):
        if not isinstance(cell, dict):
            raise SchemaViolationError(f"cells[{i}]: must be an object")
        _check_exact_keys(cell, _CELL_KEYS, f"cells[{i}]")
        cid = _require(cell, "cell_id", types=(str,))
        if not cid or cid in seen_cell_ids:
            raise SchemaViolationError(f"cells[{i}].cell_id: must be non-empty and board-unique")
        seen_cell_ids.add(cid)
        rid = _require_uuid4(cell, "planned_run_id")
        if rid in seen_run_ids:
            raise SchemaViolationError(f"cells[{i}].planned_run_id: duplicate {rid!r}")
        seen_run_ids.add(rid)
        tid = _require(cell, "task_id", types=(str,))
        if tid not in task_sides:
            raise SchemaViolationError(f"cells[{i}].task_id {tid!r}: not a declared task")
        side = _require(cell, "side", types=(str,))
        if side != task_sides[tid]:
            raise SchemaViolationError(
                f"cells[{i}].side {side!r} != task {tid!r} side {task_sides[tid]!r}")
        lineage = _require(cell, "lineage", types=(str,))
        if not lineage:
            raise SchemaViolationError(f"cells[{i}].lineage: must be non-empty")
        reviewer = _require(cell, "reviewer_lineage", types=(str,))
        if not reviewer or reviewer == lineage:
            raise SchemaViolationError(
                f"cells[{i}].reviewer_lineage {reviewer!r}: must be non-empty and DIFFER from the "
                f"producing lineage {lineage!r} (reviewer independence, §4.1)")
        rep = _require(cell, "replicate", types=(int,))
        if not (0 <= rep < n_replicates):
            raise SchemaViolationError(
                f"cells[{i}].replicate {rep}: must be in [0, {n_replicates})")
        grp = (tid, lineage)
        reps = group_reps.setdefault(grp, set())
        if rep in reps:
            raise SchemaViolationError(
                f"cells: duplicate replicate {rep} for (task={tid!r}, lineage={lineage!r})")
        reps.add(rep)
    # COMPLETE ORDERED DENOMINATOR: every (task, lineage) group is exactly {0..n-1}, no gaps.
    full = set(range(n_replicates))
    for (tid, lineage), reps in group_reps.items():
        if reps != full:
            raise SchemaViolationError(
                f"cells: (task={tid!r}, lineage={lineage!r}) enumerates replicates {sorted(reps)}, "
                f"not the complete set {sorted(full)} — the denominator is incomplete")


def _validate_cell_observation(
    stage: str, obs: dict[str, Any], artifact_tree_digest: str, outcome: str
) -> None:
    """Validate the stage-specific observation sub-record. The observation is what the ORCHESTRATOR
    OBSERVED (receipt-language pin) — the out-of-band container exit code (own_tests), a measurement
    of a reviewer (llm_review), or the gate's real projection. The GATE carries the digest the
    enforcement adapter ACTUALLY measured; P1 (source-selection false-green) is closed here as a
    SCHEMA LAW: ``measured_tree_digest`` MUST equal the cell's bound ``artifact_tree_digest`` or the
    payload is unsignable — the gate cannot certify a tree it did not measure.

    A harness error that prevented the stage from measuring (a digest mismatch before/after the
    stage, or an unexpected crash) is recorded HONESTLY as a canonical ``{"harness_error": <str>}``
    observation — permitted ONLY when ``outcome == 'error'`` (a stage never claims a measurement it
    did not make). A stage that RAN and errored uses its normal shape with error-valued fields."""
    if outcome == "error" and set(obs) == {"harness_error"}:
        if not _require(obs, "harness_error", types=(str,)):
            raise SchemaViolationError("observation.harness_error: must be non-empty")
        return
    _check_exact_keys(obs, _OBS_KEYS_BY_STAGE[stage], f"observation[{stage}]")
    if stage == "static":
        # env_digest == the sandbox's resolved image config digest (asserted == manifest env_digest
        # in static_stage); invocation_digest binds WHAT ran (FOLD-C). The measured signal is the
        # out-of-band exit codes only.
        _require_sha256_prefixed(obs, "env_digest")
        ruff_exit = _require(obs, "ruff_exit", types=(int,))
        mypy_exit = _require(obs, "mypy_exit", types=(int,))
        _require_hex64(obs, "invocation_digest")
        # COHERENCE LAW: a measured static run is pass iff BOTH tools exited 0 (else fail); an error
        # is only ever the harness_error path above.
        if outcome not in ("pass", "fail"):
            raise SchemaViolationError(
                f"static outcome must be pass|fail (measured), got {outcome!r}")
        expected = "pass" if (ruff_exit == 0 and mypy_exit == 0) else "fail"
        if outcome != expected:
            raise SchemaViolationError(
                f"static outcome {outcome!r} incoherent with exits (ruff={ruff_exit}, "
                f"mypy={mypy_exit}) — must be {expected!r} (a non-zero exit cannot sign 'pass')")
    elif stage == "own_tests":
        level = _require(obs, "sandbox_isolation_level", types=(str,))
        if level != "hermetic":
            raise SchemaViolationError(
                "observation.sandbox_isolation_level: own_tests EXECUTES untrusted producer code — "
                f"isolation must be 'hermetic' (>= the gate's), got {level!r}")
        _require_sha256_prefixed(obs, "image_digest")
        # container_exit_code is the OUT-OF-BAND authoritative signal; an int, or null when the
        # container timed out / could not launch (own_tests then reports pytest_status='error').
        cec = obs["container_exit_code"]
        if cec is not None and not isinstance(cec, int):
            raise SchemaViolationError(
                "observation.container_exit_code: must be an int or null, got "
                f"{type(cec).__name__}")
        _require_hex64(obs, "invocation_digest")   # FOLD-C: WHAT ran is auditable
        status = _require(obs, "pytest_status", types=(str,))
        if status not in VALID_PYTEST_STATUS:
            raise SchemaViolationError(
                f"observation.pytest_status: must be one of {sorted(VALID_PYTEST_STATUS)}")
        # COHERENCE LAW: the exit code fixes the status, the status fixes the outcome — a receipt
        # with
        # exit_code=1/pytest_status=passed (or status/outcome disagreeing) is unrepresentable.
        want_status = expected_pytest_status(cec)
        if status != want_status:
            raise SchemaViolationError(
                f"pytest_status {status!r} incoherent with container_exit_code {cec!r} "
                f"(the out-of-band exit fixes status={want_status!r})")
        if outcome != OWN_TESTS_CELL_OUTCOME[status]:
            raise SchemaViolationError(
                f"own_tests outcome {outcome!r} incoherent with pytest_status {status!r} "
                f"(must be {OWN_TESTS_CELL_OUTCOME[status]!r})")
    elif stage == "llm_review":
        if not _require(obs, "provider_id", types=(str,)):
            raise SchemaViolationError("observation.provider_id: must be non-empty")
        if not _require(obs, "model_id", types=(str,)):
            raise SchemaViolationError("observation.model_id: must be non-empty")
        _require_hex64(obs, "review_prompt_hash")
        # FOLD-B: source_digest = sha256 of the canonical sealed-source bytes in the request;
        # reconstructable to artifact_tree_digest (per-file sha256 + raw relpaths). The claim is
        # harness-BUILT-a-request-embedding-the-source, NOT client-transmitted / model-saw-only.
        _require_hex64(obs, "source_digest")
        _require_hex64(obs, "request_digest")
        _require_hex64(obs, "response_digest")
        verdict = _require(obs, "verdict", types=(str,))
        if verdict not in VALID_REVIEW_VERDICTS:
            raise SchemaViolationError(
                f"observation.verdict: must be one of {sorted(VALID_REVIEW_VERDICTS)}")
        # COHERENCE LAW: strict approve -> pass; anything else -> fail (the reviewer 'caught' it).
        if outcome not in ("pass", "fail"):
            raise SchemaViolationError(
                f"llm_review outcome must be pass|fail (measured), got {outcome!r}")
        expected_rv = "pass" if verdict == "approve" else "fail"
        if outcome != expected_rv:
            raise SchemaViolationError(
                f"llm_review outcome {outcome!r} incoherent with verdict {verdict!r} "
                f"(strict approve->pass; must be {expected_rv!r})")
    elif stage == "gate":
        result_kind = _require(obs, "result_kind", types=(str,))
        if result_kind not in VALID_RESULT_KINDS:
            raise SchemaViolationError(
                f"observation.result_kind: must be one of {sorted(VALID_RESULT_KINDS)}")
        result_reason = _require(obs, "result_reason", types=(str,))
        _require(obs, "result_sub_reason", types=(str,))
        gate_outcome = obs["gate_outcome"]  # str in set, or null for an infra row (no gate outcome)
        if gate_outcome is not None and gate_outcome not in VALID_GATE_OUTCOMES:
            raise SchemaViolationError(
                f"observation.gate_outcome: must be null or one of {sorted(VALID_GATE_OUTCOMES)}")
        # COHERENCE LAW (== account(), parity-tested): the gate_outcome a result_kind
        # can carry is fixed — a blocking_refusal is run_verdict (a real admission verdict), NOT
        # block_gate; an infra row carries NO gate outcome.
        if gate_outcome not in GATE_OUTCOME_BY_RESULT_KIND[result_kind]:
            raise SchemaViolationError(
                f"gate_outcome {gate_outcome!r} incoherent with result_kind {result_kind!r} "
                "(account() permits "
                f"{sorted(str(x) for x in GATE_OUTCOME_BY_RESULT_KIND[result_kind])})")
        # non_run binds TIGHTER (gap 3): the disposition (result_reason) FIXES block vs neutral.
        if result_kind == "non_run":
            want = NON_RUN_GATE_OUTCOME_BY_REASON.get(result_reason)
            if want is None:
                raise SchemaViolationError(
                    f"non_run result_reason {result_reason!r} must be one of "
                    f"{sorted(NON_RUN_GATE_OUTCOME_BY_REASON)}")
            if gate_outcome != want:
                raise SchemaViolationError(
                    f"non_run gate_outcome {gate_outcome!r} incoherent with disposition "
                    f"{result_reason!r} — account() fixes it to {want!r}")
        measured = _require_sha256_prefixed(obs, "measured_tree_digest")
        # ---- P1 SCHEMA LAW: the gate measured the tree the cell bound, or it cannot sign. --------
        if measured != artifact_tree_digest:
            raise SchemaViolationError(
                "observation.measured_tree_digest != artifact_tree_digest: the gate evaluated a "
                f"DIFFERENT tree ({measured!r}) than the cell bound ({artifact_tree_digest!r}) — "
                "the source-selection false-green vector (P1). A gate receipt may certify ONLY the "
                "tree it actually measured; refusing to sign.")


def validate_cell_stage_payload(payload: dict[str, Any]) -> None:
    """Validate a B1 step-2 ``cell_stage`` receipt — one signed OBSERVATION of one gauntlet stage of
    one board cell. Laws made true-by-construction (so a malformed observation is unsignable, not
    merely discouraged):
      * every receipt binds the manifest anchor (``manifest_digest``) and the ONE
        ``artifact_tree_digest`` the whole cell is verified against (carry-in 1).
      * ``reviewer_lineage`` != ``lineage`` (reviewer independence, echoed from the manifest).
      * ``blocked`` is a GATE-only outcome (the demonstration payload); on the gate stage the
      outcome
        is COHERENT with the observed ``result_kind`` (no outcome that the projection can't
        produce).
      * P1: a gate observation's ``measured_tree_digest`` MUST equal ``artifact_tree_digest``
        (enforced in ``_validate_cell_observation``).
    The cell_stage receipt does not, alone, prove ``cell_id``/run_id membership in the manifest —
    the
    board render (step 4) enforces the bijection planned-cells ↔ terminal receipts; here we bind the
    anchor + the tree so that reconciliation is decidable from signed material.
    """
    _check_exact_keys(payload, _CELL_STAGE_KEYS, "cell_stage")
    _validate_schema_version(payload, 1)
    _require_hex64(payload, "manifest_digest")
    if not _require(payload, "cell_id", types=(str,)):
        raise SchemaViolationError("cell_id: must be non-empty")
    lineage = _require(payload, "lineage", types=(str,))
    if not lineage:
        raise SchemaViolationError("lineage: must be non-empty")
    reviewer = _require(payload, "reviewer_lineage", types=(str,))
    if not reviewer or reviewer == lineage:
        raise SchemaViolationError(
            f"reviewer_lineage {reviewer!r}: must be non-empty and DIFFER from lineage {lineage!r}")
    side = _require(payload, "side", types=(str,))
    if side not in VALID_SIDES:
        raise SchemaViolationError(f"side: must be one of {sorted(VALID_SIDES)}")
    stage = _require(payload, "stage", types=(str,))
    if stage not in VALID_STAGES:
        raise SchemaViolationError(f"stage: must be one of {sorted(VALID_STAGES)}")
    artifact_tree_digest = _require_sha256_prefixed(payload, "artifact_tree_digest")
    outcome = _require(payload, "outcome", types=(str,))
    if outcome not in VALID_CELL_OUTCOMES:
        raise SchemaViolationError(f"outcome: must be one of {sorted(VALID_CELL_OUTCOMES)}")
    if outcome == "blocked" and stage != "gate":
        raise SchemaViolationError(
            "outcome 'blocked' is valid ONLY on the gate stage (the BlockingRefusal projection)")
    _require_iso_timestamp(payload, "executed_at")
    _require_hex64(payload, "code_sha")
    obs = _require(payload, "observation", types=(dict,))
    # SENTINEL SCHEMA LAW (dissent gap 2b): the UNMEASURABLE sentinel digest (an artifact that could
    # not be safely materialised/hashed) is signable ONLY on a harness-error ERROR receipt — a
    # PASS/FAIL/BLOCKED receipt binding it is a lie (it certifies a measurement of a tree that was
    # never measured) and is UNSIGNABLE. Bound structurally, not by the caller's discipline.
    if artifact_tree_digest == UNMEASURABLE_TREE_DIGEST:
        if outcome != "error" or set(obs) != {"harness_error"}:
            raise SchemaViolationError(
                "UNMEASURABLE_TREE_DIGEST is signable ONLY with outcome='error' + a harness_error "
                f"observation — got outcome={outcome!r}, obs keys={sorted(obs)}")
    _validate_cell_observation(stage, obs, artifact_tree_digest, outcome)
    # gate outcome<->result_kind coherence: the outcome must be one the observed projection
    # produces.
    # (Skipped when the observation is a harness-error record — the gate never measured a
    # projection.)
    if stage == "gate" and set(obs) != {"harness_error"}:
        rk = str(obs["result_kind"])
        coherent = {
            "admitted_run": {"pass", "fail"},
            "blocking_refusal": {"blocked"},
            "non_run": {"error"},
            "infrastructure_failure": {"error"},
        }[rk]
        if outcome not in coherent:
            raise SchemaViolationError(
                f"gate outcome {outcome!r} is incoherent with result_kind {rk!r} "
                f"(expected one of {sorted(coherent)}) — no honest projection produces this pair")


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
    "manifest": validate_manifest_payload,
    "cell_stage": validate_cell_stage_payload,
}

_VALIDATORS = {
    "prereg": validate_prereg_payload,
    "execution": validate_execution_payload,
    "teardown": validate_teardown_payload,
    "index": validate_index_payload,
    "manifest": validate_manifest_payload,
    "cell_stage": validate_cell_stage_payload,
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
