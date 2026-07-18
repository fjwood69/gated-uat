"""tests/_aba_scheduler.py — TEST-ONLY store-layer ABA injection scheduler (slice 2.1 [5]).

The ABA_GENERATION_MOVED scenario needs a cross-store ABA injected at the ONE interleaving point
that drives gated's REAL ``admit_run_result`` to POLICY_GENERATION_MOVED: the live oracle read
(``set_head``) inside admission, which sits BETWEEN the attestation snapshot (that captured the
bound generation while ENABLED) and the post-oracle generation re-read. A ``CalibrationStore``
wrapper delegates EVERY method to the real store via ``__getattr__`` and overrides ONLY
``set_head``.

Arming is post-plan-mint (correction): the scheduler's OWN ``artifact_source`` stages the compliant
tree and THEN arms, so the plan-mint ``set_head`` (fired by ``resolve_disposition`` before the
source runs) passes through DISARMED, and the first ARMED ``set_head`` is admission's
``oracle_head_for``.

On that first armed call the scheduler:

  1. runs a DETERMINISM PROBE on an independent SQLite ONLINE-BACKUP clone (ADD a fresh known-bad +
     DEPRECATE it, assert ``set_head`` is byte-identical before/after) — proving the ABA is a
     genuine no-net-change in ISOLATION, so the real-store H==H confirms rather than sole-witnesses;
  2. on the REAL store, in order: reads ``head_bound``; ADD_KNOWN_BAD a fresh fixture (head H→H1);
     reads ``policy_head_pre``; transitions the policy ENABLED→DEGRADED (the generation moves);
     DEPRECATE_KNOWN_BAD the fixture (head H1→H); reads ``head_returned``; ASSERTS
     ``head_bound == head_returned`` (the set_head ABA'd back, so SET_HEAD_STALE cannot fire —
     POLICY_GENERATION_MOVED is the only check left that can catch it) AND that the ADD actually
     moved the head AND that the transition actually moved the generation.

State machine DISARMED → ARMED → FIRING → COMPLETED | FAILED, SINGLE-SHOT even on failure. The
completion disclosure (real-read heads + generations + the interleaving locus) is available ONLY in
COMPLETED via ``require_completed_disclosure``; a half-fired injection leaves FAILED and RAISES, so
``enforce`` aborts evidence rather than serialising a plausible refusal over an unknown-state fault.
Every head/generation in the disclosure is a REAL store read (anti-self-attestation): the scheduler
attests only what it INDUCED, never the SUT's verdict — the observed refusal is judged separately by
the harness's own admissibility path.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any

from core.calibration import Fixture, FixtureLabel
from gate.authority import GovernanceApproval
from gate.calibration_store import AdmissionCapability, CalibrationStore, ChangeOp
from gate.policy_state import PolicyState

from orchestrator.enforcement_driver import EnforcementEvidenceError


class _State(Enum):
    DISARMED = "disarmed"
    ARMED = "armed"
    FIRING = "firing"
    COMPLETED = "completed"
    FAILED = "failed"


class AbaInjectionScheduler:
    """Owns the ABA injection + its single-shot state machine + the completion disclosure. Hand the
    ``calibration_store`` (a wrapper) and ``artifact_source`` into ``EnforcementRunConfig``, and the
    scheduler itself as ``fault_scheduler``."""

    def __init__(
        self,
        *,
        real_cs: CalibrationStore,
        policy_store: Any,
        policy_id: str,
        set_id: str,
        artifact_dir: Path,
        fresh_fixture: Fixture,
    ) -> None:
        self._real = real_cs
        self._ps = policy_store
        self._policy_id = policy_id
        self._set_id = set_id
        self._artifact_dir = artifact_dir
        self._fresh = fresh_fixture  # a KNOWN_BAD not yet in the set (the ABA excursion fixture)
        self._state = _State.DISARMED
        self._disclosure: dict[str, str] | None = None

    # --- objects wired into EnforcementRunConfig ---------------------------------------------

    @property
    def calibration_store(self) -> "_AbaCalibrationStoreWrapper":
        """The store handed to ``enforce`` in place of the real cs: delegates all reads/writes to
        the real store, but routes ``set_head`` through the scheduler's interleaving injection."""
        return _AbaCalibrationStoreWrapper(self._real, self)

    def artifact_source(self, event: Any, workspace: Path) -> Any:
        """The scheduler's OWN source: stage the compliant tree, build its spec, THEN arm — so
        arming strictly follows plan-mint and the first ARMED ``set_head`` is admission's oracle
        read."""
        from gate.artifact import build_artifact_spec

        dest = workspace / "src"
        shutil.copytree(self._artifact_dir, dest)
        spec = build_artifact_spec(dest)
        self._arm()
        return spec

    # --- state machine -----------------------------------------------------------------------

    def _arm(self) -> None:
        if self._state is not _State.DISARMED:
            # single-shot: arming twice (a source called more than once) is a harness fault.
            raise EnforcementEvidenceError(
                f"ABA scheduler cannot arm from {self._state.value} — single-shot violated")
        self._state = _State.ARMED

    def _appr(self, op: str) -> GovernanceApproval:
        # two distinct principals — dual control, as the ADD/DEPRECATE/transition ops require.
        return GovernanceApproval(
            principals=("uat-aba-1", "uat-aba-2"), purpose="uat-aba-injection",
            rationale="induce a cross-store set_head ABA across an ENABLED->DEGRADED generation",
            operation_id=op)

    def on_set_head(self, set_id: str) -> str:
        """The ``set_head`` override. DISARMED (plan-mint) or already-fired → pass through to the
        real head. The FIRST ARMED call fires the ABA once; any failure → FAILED and re-raise."""
        if self._state is not _State.ARMED:
            return str(self._real.set_head(set_id))
        self._state = _State.FIRING
        try:
            self._probe_determinism(set_id)
            head_bound = str(self._real.set_head(set_id))
            self._real.append(
                ChangeOp.ADD_KNOWN_BAD, admission=AdmissionCapability(),
                approval=self._appr("aba-add"), fixture_id=self._fresh.fixture_id, set_id=set_id,
                label=FixtureLabel.KNOWN_BAD, payload=self._fresh.payload,
                evasion_class=self._fresh.evasion_class)
            head_moved = str(self._real.set_head(set_id))
            policy_head_pre = str(self._ps.policy_head(self._policy_id))
            self._ps.transition(
                self._policy_id, PolicyState.DEGRADED, approval=self._appr("aba-degrade"))
            policy_head_post = str(self._ps.policy_head(self._policy_id))
            self._real.append(
                ChangeOp.DEPRECATE_KNOWN_BAD, approval=self._appr("aba-deprecate"),
                fixture_id=self._fresh.fixture_id, set_id=set_id)
            head_returned = str(self._real.set_head(set_id))
            # the ABA must be a genuine no-net-change over the oracle read (else SET_HEAD_STALE, not
            # POLICY_GENERATION_MOVED, would catch it — a different, weaker proof).
            if head_bound != head_returned:
                raise EnforcementEvidenceError(
                    f"ABA did not return to the bound head ({head_bound[:12]}.. != "
                    f"{head_returned[:12]}..) — set_head is not a genuine ABA; refusing the claim")
            if head_moved == head_bound:
                raise EnforcementEvidenceError(
                    "ADD_KNOWN_BAD did not move set_head — no ABA excursion actually occurred")
            if policy_head_post == policy_head_pre:
                raise EnforcementEvidenceError(
                    "ENABLED->DEGRADED did not move policy_head — no generation move for the "
                    "bracket to catch")
            self._disclosure = {
                "locus": "admit_run_result.oracle_head_for(set_head)",
                "mechanism": "ADD_KNOWN_BAD -> DEPRECATE_KNOWN_BAD (set_head H->H1->H) across an "
                             "ENABLED->DEGRADED policy transition",
                "interleaving_point": "the live oracle read, between the attestation snapshot and "
                                      "the post-oracle generation re-read",
                "head_bound": head_bound, "head_moved": head_moved, "head_returned": head_returned,
                "policy_head_pre": policy_head_pre, "policy_head_post": policy_head_post}
            self._state = _State.COMPLETED
            return head_returned
        except Exception:
            self._state = _State.FAILED
            raise

    def require_completed_disclosure(self) -> dict[str, str]:
        """The scheduler-owned completion accessor ``enforce`` demands for a fault scenario. Returns
        the induced-injection record ONLY in COMPLETED; raises otherwise so a half-fired injection
        aborts evidence rather than being serialised as a plausible refusal."""
        if self._state is not _State.COMPLETED or self._disclosure is None:
            raise EnforcementEvidenceError(
                f"fault disclosure demanded but the ABA injection is {self._state.value} (not "
                "COMPLETED) — refusing to serialise a disclosure over a half-fired injection")
        return dict(self._disclosure)

    # --- determinism probe -------------------------------------------------------------------

    def _probe_determinism(self, set_id: str) -> None:
        """Clone the real calibration DB via the SQLite ONLINE-BACKUP API and run the SAME
        ADD->DEPRECATE on the clone, asserting ``set_head`` returns byte-identical. Proves the ABA
        is deterministic in ISOLATION, before the real store is touched — a disclosed manipulation
        check, not a self-attestation.

        WAL fidelity (dissent): the real store is ``journal_mode=WAL``, so committed membership can
        live in un-checkpointed ``-wal`` frames. TRUNCATE-checkpoint the source FIRST (folds every
        committed frame into the main db) so the online backup cannot capture a stale membership and
        pass ``before == after`` trivially on the wrong baseline. The clone is removed on every exit
        (it holds a copy of the calibration membership — evidence hygiene, not just a disk leak)."""
        clone_dir = Path(tempfile.mkdtemp(prefix="mv-aba-probe-"))
        clone_path = clone_dir / "clone.db"
        try:
            src = sqlite3.connect(self._real._path)
            try:
                src.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # committed WAL frames -> main db
                dst = sqlite3.connect(str(clone_path))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
            clone = CalibrationStore(clone_path)
            before = str(clone.set_head(set_id))
            clone.append(
                ChangeOp.ADD_KNOWN_BAD, admission=AdmissionCapability(),
                approval=self._appr("probe-add"), fixture_id=self._fresh.fixture_id, set_id=set_id,
                label=FixtureLabel.KNOWN_BAD, payload=self._fresh.payload,
                evasion_class=self._fresh.evasion_class)
            moved = str(clone.set_head(set_id))
            clone.append(
                ChangeOp.DEPRECATE_KNOWN_BAD, approval=self._appr("probe-deprecate"),
                fixture_id=self._fresh.fixture_id, set_id=set_id)
            after = str(clone.set_head(set_id))
            if before != after:
                raise EnforcementEvidenceError(
                    f"determinism probe FAILED: ADD->DEPRECATE did not restore set_head "
                    f"({before[:12]}.. != {after[:12]}..) on an independent clone — not determ.")
            if moved == before:
                raise EnforcementEvidenceError(
                    "determinism probe: ADD_KNOWN_BAD did not move the clone set_head (no excurs.)")
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)


class _AbaCalibrationStoreWrapper:
    """Delegates every attribute to the real ``CalibrationStore`` EXCEPT ``set_head``, which routes
    through the scheduler's interleaving injection. ``__getattr__`` covers the full store surface
    (``append``, ``policy_head`` peers, ``_path``, ``current_*``, ...) so the real production
    governance view reads THROUGH this wrapper unchanged."""

    def __init__(self, real: CalibrationStore, scheduler: AbaInjectionScheduler) -> None:
        self._real: CalibrationStore = real
        self._scheduler: AbaInjectionScheduler = scheduler

    def set_head(self, set_id: str) -> str:
        return self._scheduler.on_set_head(set_id)

    def __getattr__(self, name: str) -> Any:
        # only reached when normal lookup fails — ``_real``/``_scheduler``/``set_head`` resolve
        # first, everything else (append, current_*, _path, ...) delegates to the real store.
        return getattr(object.__getattribute__(self, "_real"), name)
