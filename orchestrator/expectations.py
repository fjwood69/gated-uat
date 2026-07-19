"""orchestrator/expectations.py — the closed scenario ontology + AUTHORED expectations.

THE falsifiability control (dissent P1 + rebuild amendment 1). This module holds each scenario's
committed expected outcome as LITERAL, hand-authored data, and MUST NOT import gated
(``gate.*`` / ``engine.*`` / ``sandbox.*`` / ``core.*``) — enforced by ``test_expectation_closure``.

Why the import ban is load-bearing: a UAT harness is a falsifier only if its prediction cannot be
derived from the observation. If the expected ``{kind, reason, sub_reason}`` were computed by any
code that can call the gate (``resolve_disposition`` / ``map_job_result`` / a gated enum), the
harness would be a mirror — it would "predict" whatever the gate just did and self-confirm. So:

  * runtime configuration selects ONLY a closed ``ScenarioId`` (no runtime path composes an
    expectation);
  * the expected triple is looked up HERE, from literals a human wrote and reviewed as part of the
    test case;
  * the reason vocabulary is a CLOSED set of literal tokens — deliberately hand-copied to match
    gated's emitted values, never imported from gated. If gated renames a token, the observation's
    reason changes but this literal does not → the admissibility comparison FAILS (a caught change),
    which is the correct fail-closed behaviour, not a bug.

``mis_route`` is deliberately absent: it produces no ``JobResult`` and no evidence chain (Q3 ruling
— plain ``assertRaises(GateDecisionError)``, no signed "raise record"; the SUT emitted nothing).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ScenarioId(Enum):
    """The CLOSED set of enforcement scenarios that produce a signed evidence chain. Runtime config
    selects one of these ids and nothing else — the expectation is not composed at runtime."""

    COMPLIANT_ADMIT = "compliant_admit"
    # amendment 2: a DEGRADED (was-ENABLED) policy, NOT a never-enabled PENDING one.
    NON_ENABLED_DEGRADED = "non_enabled_degraded"
    ABA_GENERATION_MOVED = "aba_generation_moved"
    SUBJECT_DRIFT_SECOND_IMAGE = "subject_drift_second_image"
    SHA_TAMPER = "sha_tamper"
    # slice 2.2a — more of gated's admission-currency refusal modes. All fire INSIDE
    # admit_run_result (post-run), so all are blocking_refusal with gate_outcome run_verdict.
    SET_HEAD_STALE = "set_head_stale"
    ORACLE_UNAVAILABLE = "oracle_unavailable"
    LIVE_ATTESTATION_UNAVAILABLE = "live_attestation_unavailable"


class InjectionClass(Enum):
    """How a scenario induces its outcome — the taxonomy that keeps 'drive gated's REAL path' an
    ENFORCEABLE invariant, not a slogan (slice 2.2). Every ScenarioId declares one; the harness
    REFUSES to run a FABRICATION-classed scenario (there are none — the member exists so the guard
    has teeth). The classes:

      REAL_INPUT       — no injected fault; a real (possibly distinct) input drives the outcome
                         (a compliant run; a second real image).
      STORE_MUTATION   — real writes through the real store APIs at a real interleave (the ABA;
                         a real ENABLED→DEGRADED transition; a real fixture append).
      FAULT_SIMULATION — a wrapper reproducing the EXACT failure a real component is contractually
                         allowed to exhibit (e.g. CalibrationStore.set_head raising) — honest only
                         with a fault-contract justification + a negative control.
      FABRICATION      — hand-built JobResult/plan/report, or a value the real component's type
                         cannot produce (e.g. set_head returning None). EXCLUDED — never an id.
    """

    REAL_INPUT = "real_input"
    STORE_MUTATION = "store_mutation"
    FAULT_SIMULATION = "fault_simulation"
    FABRICATION = "fabrication"


# The CLOSED expected-outcome vocabulary — literal tokens, hand-authored to match gated's emitted
# values (NOT imported). ``kind`` is the JobResult class; ``reason`` is the coarse discriminating
# token (Q2: for an admitted run it is the expected OUTCOME pass|fail, not the engine's internal
# verdict-reason; for the others it is the closed refusal/disposition/infra token).
_KIND_ADMITTED = "admitted_run"
_KIND_REFUSAL = "blocking_refusal"
_KIND_NONRUN = "non_run"
_KIND_INFRA = "infrastructure_failure"


@dataclass(frozen=True)
class Expected:
    """A scenario's committed prediction — signed into the prereg BEFORE the run. ``kind`` +
    ``reason`` + ``sub_reason`` are all closed literal tokens."""

    kind: str
    reason: str
    sub_reason: str = ""


# The authored expectations. Each is a deliberate claim about what the gate MUST do, committed
# before the run. Changing one is a test-design decision, reviewed as such.
EXPECTATIONS: dict[ScenarioId, Expected] = {
    # a compliant candidate under a genuinely-ENABLED policy is ADMITTED with a PASS verdict.
    ScenarioId.COMPLIANT_ADMIT: Expected(_KIND_ADMITTED, "pass", ""),
    # a formerly-ENABLED, now DEGRADED policy must BLOCK (fail closed), never fall silent to
    # neutral. The invariant "a revoked control must keep controlling": expecting BLOCK is what
    # makes an observed SKIP_NEUTRAL a FAIL (a never-enabled PENDING policy legitimately neutrals —
    # a tautology that could never exercise the invariant).
    ScenarioId.NON_ENABLED_DEGRADED: Expected(_KIND_NONRUN, "block_action_required", ""),
    # a below-seam cross-store ABA (set-head H→H1→H with a real policy transition between) must be
    # caught by the generation bracket, not the set-head equality check.
    ScenarioId.ABA_GENERATION_MOVED: Expected(_KIND_REFUSAL, "policy_generation_moved", ""),
    # enforcement on a DISTINCT image measures a different execution identity than the policy was
    # calibrated under → the measured subject drifts from the dispatched target → refused.
    ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE: Expected(_KIND_REFUSAL, "subject_drift", ""),
    # a TOCTOU tamper (mutate the tree after the SHA-bind) is caught by the sandbox re-verify → a
    # blocking infrastructure failure (never a silent pass).
    ScenarioId.SHA_TAMPER: Expected(_KIND_INFRA, "artifact_integrity_mismatch", ""),
    # slice 2.2a — post-run admission-currency refusals. sub_reason is LOAD-BEARING: it forks each
    # coarse reason (attestation_absent vs other; store_unreachable vs the None-return 'unresolved'
    # path), so an empty sub_reason would blind the admissibility comparison to the forensic split.
    # A real fixture append between mint and admit moves the live set_head off the bound head.
    ScenarioId.SET_HEAD_STALE: Expected(_KIND_REFUSAL, "set_head_stale", ""),
    # a real store fault at the live oracle read (set_head raises) — admit maps ANY oracle exception
    # to oracle_unavailable/store_unreachable (the None-return path is a DISTINCT 'unresolved' sub).
    ScenarioId.ORACLE_UNAVAILABLE: Expected(
        _KIND_REFUSAL, "oracle_unavailable", "store_unreachable"),
    # a real ENABLED→DEGRADED transition between mint and the attestation read → the REAL snapshot
    # returns None (policy no longer ENABLED) → admit refuses live_attestation_unavailable/absent.
    ScenarioId.LIVE_ATTESTATION_UNAVAILABLE: Expected(
        _KIND_REFUSAL, "live_attestation_unavailable", "attestation_absent"),
}


# Every ScenarioId's INDUCTION class (slice 2.2). No FABRICATION entry — those modes are not
# ScenarioIds; the guard (injection_class_for + assert_inducible) exists so the invariant has teeth.
INJECTION_CLASS: dict[ScenarioId, InjectionClass] = {
    ScenarioId.COMPLIANT_ADMIT: InjectionClass.REAL_INPUT,
    ScenarioId.SUBJECT_DRIFT_SECOND_IMAGE: InjectionClass.REAL_INPUT,
    ScenarioId.NON_ENABLED_DEGRADED: InjectionClass.STORE_MUTATION,
    ScenarioId.ABA_GENERATION_MOVED: InjectionClass.STORE_MUTATION,
    ScenarioId.SHA_TAMPER: InjectionClass.STORE_MUTATION,  # a real post-hash artifact mutation
    ScenarioId.SET_HEAD_STALE: InjectionClass.STORE_MUTATION,
    ScenarioId.LIVE_ATTESTATION_UNAVAILABLE: InjectionClass.STORE_MUTATION,
    ScenarioId.ORACLE_UNAVAILABLE: InjectionClass.FAULT_SIMULATION,
}


def expected_for(scenario: ScenarioId) -> Expected:
    """The authored expectation for ``scenario`` — the ONLY way to obtain a prediction. Raises
    KeyError for an unknown scenario (a closed set; no default, no composition)."""
    return EXPECTATIONS[scenario]


def injection_class_for(scenario: ScenarioId) -> InjectionClass:
    """The induction class ``scenario`` declares. An unclassified scenario fails CLOSED with an
    explicit error (not a bare KeyError) — a completeness test pins every ScenarioId here, so this
    only fires if a NEW id is added without declaring how it drives the gate."""
    try:
        return INJECTION_CLASS[scenario]
    except KeyError:
        raise ValueError(
            f"scenario {scenario.value!r} declares no InjectionClass — every ScenarioId MUST be "
            "classified; refusing to run an unclassified scenario") from None


def assert_inducible(scenario: ScenarioId) -> None:
    """The load-time GUARD (slice 2.2): refuse to run a FABRICATION-classed scenario — the harness
    drives gated's REAL path, so a hand-built JobResult/plan/report is never admissible evidence."""
    if injection_class_for(scenario) is InjectionClass.FABRICATION:
        raise ValueError(
            f"scenario {scenario.value!r} is FABRICATION-classed — the harness refuses to run it; "
            "a fabricated JobResult/plan/report is not a real gate decision")


__all__ = [
    "ScenarioId", "Expected", "EXPECTATIONS", "expected_for",
    "InjectionClass", "INJECTION_CLASS", "injection_class_for", "assert_inducible",
]
