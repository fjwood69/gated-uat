"""tests/_currency_schedulers.py — TEST-ONLY admission-currency injection schedulers (slice 2.2a).

Three post-run admission refusals, each induced at the REAL interleave INSIDE gated's
``admit_run_result`` via a store-layer wrapper — the ABA scheduler's DNA: DISARMED through the
plan-mint read, armed by the scheduler's OWN ``artifact_source`` after staging (so the mint read
passes disarmed), and the FIRST armed admission read fires ONCE. Every head/generation is a REAL
store read (anti-self-attestation); the wrappers construct nothing fabricated.

  SET_HEAD_STALE (Class A / store mutation): the armed ``cs.set_head`` APPENDS a fresh known-bad
    fixture (moves the live head H→H1) and returns H1 — NO policy transition (a transition would
    move the generation bracket and fire POLICY_GENERATION_MOVED instead: the wrong-guard trap).
    admit's oracle read then sees live_head H1 != bound_head H → SET_HEAD_STALE.

  ORACLE_UNAVAILABLE (Class B / fault simulation): the armed ``cs.set_head`` RAISES
    ``ChainIntegrityError`` — the EXACT exception ``CalibrationStore.set_head`` raises on a
    chain-verification failure (its contract is str-or-raise; it never returns None). admit maps ANY
    ``oracle_head_for`` exception to ORACLE_UNAVAILABLE / store_unreachable. Fault-contract:
    gate/calibration_store.py set_head raises ChainIntegrityError; gate/run_admission.py
    oracle_head_for except → sub_reason=store_unreachable. (The None-return path is a DISTINCT
    'unresolved' sub_reason and a value set_head's ``str`` return type cannot produce — Class C, not
    this scenario.)

  LIVE_ATTESTATION_UNAVAILABLE (Class A / store mutation): a PolicyStore wrapper whose armed
    ``current_attestation_snapshot`` does a REAL ENABLED→DEGRADED transition then CALLS THROUGH —
    the real snapshot returns None because the policy is no longer ENABLED (NOT a fabricated None; a
    non-None here would mean the scenario premise is false, and we want to know). admit reads None →
    LIVE_ATTESTATION_UNAVAILABLE / attestation_absent.

Each ``require_completed_disclosure()`` returns the base triple {locus, mechanism,
interleaving_point}, available ONLY in COMPLETED; a half-fired injection leaves FAILED and raises,
so ``enforce`` aborts evidence rather than serialising a plausible refusal.
"""

from __future__ import annotations

import shutil
from enum import Enum
from pathlib import Path
from typing import Any

from core.calibration import Fixture, FixtureLabel
from gate.authority import GovernanceApproval
from gate.calibration_store import AdmissionCapability, ChainIntegrityError, ChangeOp
from gate.policy_state import PolicyState

from orchestrator.enforcement_driver import EnforcementEvidenceError


class _State(Enum):
    DISARMED = "disarmed"
    ARMED = "armed"
    FIRING = "firing"
    COMPLETED = "completed"
    FAILED = "failed"


class _ArmedScheduler:
    """Shared machinery: the single-shot state machine, post-stage arming via an owned
    ``artifact_source``, dual-principal approvals, and the COMPLETED-gated disclosure."""

    def __init__(self, *, policy_id: str, set_id: str, artifact_dir: Path) -> None:
        self._policy_id = policy_id
        self._set_id = set_id
        self._artifact_dir = artifact_dir
        self._state = _State.DISARMED
        self._disclosure: dict[str, str] | None = None

    def artifact_source(self, event: Any, workspace: Path) -> Any:
        """Stage the compliant tree, build its spec, THEN arm — so arming strictly follows plan-mint
        and the first ARMED admission read is the interleave point."""
        from gate.artifact import build_artifact_spec

        dest = workspace / "src"
        shutil.copytree(self._artifact_dir, dest)
        spec = build_artifact_spec(dest)
        if self._state is not _State.DISARMED:
            raise EnforcementEvidenceError(
                f"scheduler cannot arm from {self._state.value} — single-shot violated")
        self._state = _State.ARMED
        return spec

    def _appr(self, op: str) -> GovernanceApproval:
        return GovernanceApproval(
            principals=("uat-currency-1", "uat-currency-2"), purpose="uat-currency-injection",
            rationale="induce an admission-currency refusal at the live read", operation_id=op)

    def require_completed_disclosure(self) -> dict[str, str]:
        if self._state is not _State.COMPLETED or self._disclosure is None:
            raise EnforcementEvidenceError(
                f"fault disclosure demanded but the injection is {self._state.value} (not "
                "COMPLETED) — refusing to serialise over a half-fired injection")
        return dict(self._disclosure)


class _CalibrationSetHeadWrapper:
    """Delegates every CalibrationStore attribute EXCEPT ``set_head``, which routes through the
    scheduler's interleaving injection (the real production view reads THROUGH it)."""

    def __init__(self, real: Any, on_set_head: Any) -> None:
        self._real = real
        self._on_set_head = on_set_head

    def set_head(self, set_id: str) -> str:
        return self._on_set_head(set_id)  # type: ignore[no-any-return]

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_real"), name)


class _PolicyAttestationWrapper:
    """Delegates every PolicyStore attribute EXCEPT ``current_attestation_snapshot``, which routes
    through the scheduler's interleaving injection (admit's current_attestation reads through)."""

    def __init__(self, real: Any, on_attestation: Any) -> None:
        self._real = real
        self._on_attestation = on_attestation

    def current_attestation_snapshot(self, policy_id: str) -> Any:
        return self._on_attestation(policy_id)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_real"), name)


class SetHeadStaleScheduler(_ArmedScheduler):
    """Class A: append a fresh fixture at the live oracle read → live head != bound head."""

    def __init__(self, *, real_cs: Any, policy_id: str, set_id: str, artifact_dir: Path,
                 fresh_fixture: Fixture) -> None:
        super().__init__(policy_id=policy_id, set_id=set_id, artifact_dir=artifact_dir)
        self._real = real_cs
        self._fresh = fresh_fixture

    @property
    def calibration_store(self) -> _CalibrationSetHeadWrapper:
        return _CalibrationSetHeadWrapper(self._real, self.on_set_head)

    def on_set_head(self, set_id: str) -> str:
        if self._state is not _State.ARMED:
            return str(self._real.set_head(set_id))
        self._state = _State.FIRING
        try:
            head_bound = str(self._real.set_head(set_id))
            self._real.append(
                ChangeOp.ADD_KNOWN_BAD, admission=AdmissionCapability(),
                approval=self._appr("stale-add"), fixture_id=self._fresh.fixture_id, set_id=set_id,
                label=FixtureLabel.KNOWN_BAD, payload=self._fresh.payload,
                evasion_class=self._fresh.evasion_class)
            head_moved = str(self._real.set_head(set_id))
            if head_moved == head_bound:
                raise EnforcementEvidenceError(
                    "ADD_KNOWN_BAD did not move set_head — no drift to make the bound head stale")
            self._disclosure = {
                "locus": "admit_run_result.oracle_head_for(set_head)",
                "mechanism": "append a fresh KNOWN_BAD (set_head H->H1), NO policy transition — a "
                             "monotonic forward move that leaves the bound head stale",
                "interleaving_point": "the live oracle read, after the attestation captured the "
                                      "bound head"}
            self._state = _State.COMPLETED
            return head_moved  # live head H1 != bound head H -> SET_HEAD_STALE
        except Exception:
            self._state = _State.FAILED
            raise


class OracleUnavailableScheduler(_ArmedScheduler):
    """Class B: raise the real set_head chain-verification exception at the live oracle read."""

    def __init__(self, *, real_cs: Any, policy_id: str, set_id: str, artifact_dir: Path) -> None:
        super().__init__(policy_id=policy_id, set_id=set_id, artifact_dir=artifact_dir)
        self._real = real_cs

    @property
    def calibration_store(self) -> _CalibrationSetHeadWrapper:
        return _CalibrationSetHeadWrapper(self._real, self.on_set_head)

    def on_set_head(self, set_id: str) -> str:
        if self._state is not _State.ARMED:
            return str(self._real.set_head(set_id))
        # the FIRE is the RAISE — the exact exception CalibrationStore.set_head raises on a
        # chain-verification failure (str-or-raise contract; never None). Record + COMPLETE, then
        # raise (nothing can fail before it, so no failure-catch is needed). COMPLETED-before-raise
        # is fail-closed BOTH ways (dissent): the scheduler does not resume after the raise (it
        # unwinds through admit's oracle_head_for); if admit CATCHES it (the real contract) ->
        # ORACLE_UNAVAILABLE + require_completed_disclosure finds COMPLETED; if a future refactor
        # let it ESCAPE admit, it propagates out of enforce BEFORE any chain is built (no admissible
        # chain), and the observed outcome would not match the predicted blocking_refusal anyway.
        self._state = _State.FIRING
        self._disclosure = {
            "locus": "admit_run_result.oracle_head_for(set_head)",
            "mechanism": "raise ChainIntegrityError — the real set_head fault; admit maps any "
                         "oracle_head_for exception to oracle_unavailable/store_unreachable",
            "interleaving_point": "the live oracle read"}
        self._state = _State.COMPLETED
        raise ChainIntegrityError(
            "calibration chain unreadable at the live oracle read (injected store fault)")


class LiveAttestationUnavailableScheduler(_ArmedScheduler):
    """Class A: a real ENABLED->DEGRADED transition at the attestation read, then call through — the
    real snapshot returns None because the policy is no longer ENABLED."""

    def __init__(self, *, real_ps: Any, policy_id: str, set_id: str, artifact_dir: Path) -> None:
        super().__init__(policy_id=policy_id, set_id=set_id, artifact_dir=artifact_dir)
        self._real = real_ps

    @property
    def policy_store(self) -> _PolicyAttestationWrapper:
        return _PolicyAttestationWrapper(self._real, self.on_attestation)

    def on_attestation(self, policy_id: str) -> Any:
        if self._state is not _State.ARMED:
            return self._real.current_attestation_snapshot(policy_id)
        self._state = _State.FIRING
        try:
            head_pre = str(self._real.policy_head(policy_id))
            self._real.transition(
                policy_id, PolicyState.DEGRADED, approval=self._appr("attn-degrade"))
            head_post = str(self._real.policy_head(policy_id))
            if head_post == head_pre:
                raise EnforcementEvidenceError(
                    "ENABLED->DEGRADED did not move policy_head — the transition did not take")
            snap = self._real.current_attestation_snapshot(policy_id)  # REAL read, post-degrade
            if snap is not None:
                raise EnforcementEvidenceError(
                    "current_attestation_snapshot did NOT return None after ENABLED->DEGRADED — "
                    "the scenario premise (a degraded policy has no live attestation) is false")
            self._disclosure = {
                "locus": "admit_run_result.current_attestation",
                "mechanism": "real ENABLED->DEGRADED transition then CALL THROUGH — the real "
                             "snapshot returns None (policy no longer ENABLED), not fabricated",
                "interleaving_point": "the live attestation read (admit's first governance read)"}
            self._state = _State.COMPLETED
            return snap  # None -> LIVE_ATTESTATION_UNAVAILABLE / attestation_absent
        except Exception:
            self._state = _State.FAILED
            raise
