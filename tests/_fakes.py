"""tests/_fakes.py — shared gauntlet stage-runner test doubles (B1 gap-1 capability-deletion).

Two sandbox doubles, deliberately different in fidelity:

  * ``FakeSandbox`` — records the ``spec.tree_hash`` it was HANDED and returns canned per-run
    results. Fast; proves harness logic (exit-code mapping, env_digest assertion, teardown, fresh
    object per cell). It does NOT copytree/re-hash, so it cannot prove capability-deletion.

  * ``RealisticSandbox`` — MIMICS the pin's ``prepare()`` contract: copytree the view into a
    snapshot, RE-HASH, and raise ``ArtifactHashMismatchError`` if it != ``spec.tree_hash``
    (like the pin). This lets a FOLD-A test mutate the view and prove
    end-to-end that the stage bound ``sealed.digest`` (not ``tree_hash(view)``) — WITHOUT podman.

Plus deterministic review-client / gate-runner factories matching the new seams.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from core import ExecutionResult, IsolationLevel, tree_hash
from core.artifact_hash import ArtifactHashMismatchError

from orchestrator.gauntlet import GateMeasurement, ReviewOutcome

_DEF_IMAGE_DIGEST = "sha256:" + "d" * 64


class FakeHandle:
    def __init__(self, tree_hash_val: str | None, image_id: str) -> None:
        self.id = "fake"
        self.artifact_hash = tree_hash_val
        self.image_id = image_id


class FakeSandbox:
    """Records ``spec.tree_hash``; returns canned per-run results (a list of (outcome, exit_code) or
    a single repeated pair). Configurable image_digest + isolation level; teardown flag."""

    def __init__(
        self,
        *,
        results: list[tuple[str, int | None]] | None = None,
        outcome: str = "completed",
        exit_code: int | None = 0,
        isolation_level: IsolationLevel = IsolationLevel.HERMETIC,
        image_digest: str = _DEF_IMAGE_DIGEST,
    ) -> None:
        self.isolation_level = isolation_level
        self._results = list(results) if results is not None else None
        self._outcome = outcome
        self._exit_code = exit_code
        self._image_digest = image_digest
        self.prepared = False
        self.run_count = 0
        self.torn_down = False
        self.spec_tree_hash: str | None = None
        self.ran_argvs: list[tuple[str, ...]] = []

    def prepare(self, spec: Any, fixtures: Any) -> FakeHandle:
        self.prepared = True
        self.spec_tree_hash = getattr(spec, "tree_hash", None)
        return FakeHandle(self.spec_tree_hash, self._image_digest)

    def run(self, handle: Any, command: Any, budget: Any) -> ExecutionResult:
        self.run_count += 1
        self.ran_argvs.append(tuple(getattr(command, "argv", ())))
        if self._results is not None:
            outcome, ec = self._results[min(self.run_count - 1, len(self._results) - 1)]
        else:
            outcome, ec = self._outcome, self._exit_code
        return ExecutionResult(
            outcome=outcome, exit_code=ec, isolation_level=self.isolation_level,
            artifact_hash=self.spec_tree_hash or "", raw_return_code=ec,
            image_digest=self._image_digest)

    def teardown(self, handle: Any) -> None:
        self.torn_down = True


class RealisticSandbox:
    """Copytrees the view into a snapshot, RE-HASHES it, and raises ArtifactHashMismatchError if it
    != spec.tree_hash — the pin's real TOCTOU-close contract, without podman. Lets a FOLD-A test
    mutate the view and prove the stage bound sealed.digest end-to-end."""

    def __init__(
        self,
        *,
        exit_code: int = 0,
        image_digest: str = _DEF_IMAGE_DIGEST,
        isolation_level: IsolationLevel = IsolationLevel.HERMETIC,
    ) -> None:
        self.isolation_level = isolation_level
        self._exit_code = exit_code
        self._image_digest = image_digest
        self.spec_tree_hash: str | None = None
        self.run_count = 0
        self.torn_down = False
        self._snap: Path | None = None

    def prepare(self, spec: Any, fixtures: Any) -> FakeHandle:
        self.spec_tree_hash = spec.tree_hash
        snap = Path(tempfile.mkdtemp(prefix="realistic-snap-"))
        shutil.copytree(spec.path, snap, dirs_exist_ok=True)
        staged = tree_hash(snap)
        if staged != spec.tree_hash:
            shutil.rmtree(snap, ignore_errors=True)
            raise ArtifactHashMismatchError(f"staged {staged} != claimed {spec.tree_hash}")
        self._snap = snap
        return FakeHandle(spec.tree_hash, self._image_digest)

    def run(self, handle: Any, command: Any, budget: Any) -> ExecutionResult:
        self.run_count += 1
        return ExecutionResult(
            outcome="completed", exit_code=self._exit_code, isolation_level=self.isolation_level,
            artifact_hash=self.spec_tree_hash or "", raw_return_code=self._exit_code,
            image_digest=self._image_digest)

    def teardown(self, handle: Any) -> None:
        self.torn_down = True
        if self._snap is not None:
            shutil.rmtree(self._snap, ignore_errors=True)


def review_client(
    verdict: str = "approve", *, provider: str = "bifrost", model: str = "gpt-y-1",
    response: bytes = b"RESP",
):  # noqa: ANN202 — returns the injected ReviewClient callable
    """A deterministic ReviewClient over the new (request_bytes, lineage, prompt_hash) seam."""
    def client(request_bytes: bytes, reviewer_lineage: str, prompt_hash: str) -> ReviewOutcome:
        return ReviewOutcome(
            verdict=verdict, provider_id=provider, model_id=model,
            raw_response=response + b":" + verdict.encode())
    return client


def gate_runner(
    result_kind: str, *, admitted: str | None = None, measured: str | None = None,
    reason: str = "invariant_violation", gate_outcome: str | None = None,
):  # noqa: ANN202 — returns the injected GateRunner callable
    """A GateRunner whose gate_outcome comes from the REAL account() (the fake never re-encodes),
    measuring the tree it is handed unless ``measured`` overrides (to simulate the seam bug)."""
    from tests._gate_account import real_gate_outcome
    _key = {
        "admitted_run": "admitted_run", "blocking_refusal": "blocking_refusal",
        "non_run": "non_run_block", "infrastructure_failure": "infrastructure_failure"}

    def run(view: Path) -> GateMeasurement:
        go = gate_outcome if gate_outcome is not None else real_gate_outcome(_key[result_kind])
        return GateMeasurement(
            result_kind=result_kind, result_reason=reason, result_sub_reason="",
            gate_outcome=go, admitted_outcome=admitted,
            measured_tree_digest=measured if measured is not None else tree_hash(view))
    return run
