"""tests/_tamper_scheduler.py — TEST-ONLY artifact-tamper fault scheduler (slice 2.1 [6]).

The SHA_TAMPER scenario induces a TOCTOU: the artifact_source stages the candidate tree, binds its
``tree_hash`` via ``build_artifact_spec`` (the SHA-bind), THEN overwrites a file. gated's sandbox
re-verifies the bound hash at mount and raises ``ArtifactHashMismatchError`` →
``InfrastructureFailure(ARTIFACT_INTEGRITY_MISMATCH)`` — never a silent pass on altered bytes.

Like the ABA scheduler, the disclosure is scheduler-owned and gated on COMPLETED (correction [4].2):
``enforce`` demands ``require_completed_disclosure`` after the run, so a tamper that never fired
(the source not reached) RAISES rather than serialising a fabricated tamper record. The tamper here
FIRES during the source, so COMPLETED is reached before the mismatch propagates. The disclosure is a
genuine record of what the harness mutated (bound hash + mutated path + the mutation's own digest) —
an INDUCTION record; the observed ``infrastructure_failure`` outcome is judged separately (and, per
amendment 3, is NEVER admissible even when predicted+matched: infra proves the plumbing held, not
that the gate judged)."""

from __future__ import annotations

import shutil
from enum import Enum
from pathlib import Path
from typing import Any

from orchestrator.enforcement_driver import EnforcementEvidenceError


class _State(Enum):
    DISARMED = "disarmed"
    FIRING = "firing"
    COMPLETED = "completed"
    FAILED = "failed"


class TamperInjectionScheduler:
    """Owns the post-SHA-bind tamper + its single-shot state machine + the completion disclosure.
    Wire ``artifact_source`` into ``EnforcementRunConfig.artifact_source`` and the scheduler itself
    as ``fault_scheduler``."""

    def __init__(
        self,
        *,
        artifact_dir: Path,
        mutated_rel: str = "main.py",
        mutation: bytes = b"# tampered after the tree hash was bound\n",
    ) -> None:
        self._artifact_dir = artifact_dir
        self._mutated_rel = mutated_rel
        self._mutation = mutation
        self._state = _State.DISARMED
        self._disclosure: dict[str, str] | None = None

    def artifact_source(self, event: Any, workspace: Path) -> Any:
        """Stage the tree, BIND its hash, then mutate a file — the TOCTOU. Single-shot: a second
        entry is a harness fault (fail closed)."""
        from gate.artifact import build_artifact_spec

        if self._state is not _State.DISARMED:
            raise EnforcementEvidenceError(
                f"tamper source re-entered from {self._state.value} — single-shot violated")
        self._state = _State.FIRING
        try:
            dest = workspace / "src"
            shutil.copytree(self._artifact_dir, dest)
            spec = build_artifact_spec(dest)  # binds the CLEAN tree hash
            # mutate AFTER the bind (the TOCTOU). Independent no-op guard (dissent): assert the
            # write ACTUALLY changed the bytes — a mutation equal to the original would leave the
            # hash matching the mounted tree (a silent pass), so FAIL LOUD here rather than emit a
            # tamper disclosure for a tamper that did not alter anything.
            target = dest / self._mutated_rel
            before = target.read_bytes()
            target.write_bytes(self._mutation)
            if target.read_bytes() == before:
                raise EnforcementEvidenceError(
                    f"tamper was a no-op: {self._mutated_rel} already equals the mutation, so the "
                    "SHA-bind would still match the mounted tree — refusing to claim a tamper")
            # the sealed schema's fault_injection contract is the base disclosure TRIPLE
            # (locus / mechanism / interleaving_point) — all non-empty strings, no extra keys.
            self._disclosure = {
                "locus": "artifact_source (post-SHA-bind, pre-mount)",
                "mechanism": f"overwrite {self._mutated_rel} after build_artifact_spec bound the "
                             "tree hash (TOCTOU)",
                "interleaving_point": "between the SHA-bind and the sandbox mount re-verify"}
            self._state = _State.COMPLETED
            return spec
        except Exception:
            self._state = _State.FAILED
            raise

    def require_completed_disclosure(self) -> dict[str, str]:
        """The scheduler-owned completion accessor ``enforce`` demands. Returns the tamper record
        ONLY in COMPLETED; raises otherwise so a tamper that never fired aborts evidence."""
        if self._state is not _State.COMPLETED or self._disclosure is None:
            raise EnforcementEvidenceError(
                f"tamper disclosure demanded but the injection is {self._state.value} (not "
                "COMPLETED) — refusing to serialise a disclosure over a tamper that did not fire")
        return dict(self._disclosure)
