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
}


def expected_for(scenario: ScenarioId) -> Expected:
    """The authored expectation for ``scenario`` — the ONLY way to obtain a prediction. Raises
    KeyError for an unknown scenario (a closed set; no default, no composition)."""
    return EXPECTATIONS[scenario]


__all__ = ["ScenarioId", "Expected", "EXPECTATIONS", "expected_for"]
