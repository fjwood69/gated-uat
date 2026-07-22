"""tests/test_gauntlet_own_tests.py — B1 step 2: the own_tests stage (the security-sensitive one).

The hermetic sandbox itself is gated's OCISandbox — its isolation is covered by the pin's
test_oci_sandbox.py; here we prove the STAGE logic over an injected fake sandbox:
  * the ONLY observation is the out-of-band container EXIT CODE (0->pass, 1->fail,
  5->no_tests-error,
    timeout/error->error) — the stage never inspects the producer's stdout or WHAT the tests assert;
  * own-tests GREEN on an evasion is intentional (exit 0 -> pass regardless of content) — the
  thesis;
  * P2: a FRESH sandbox object is constructed per cell (never reused);
  * teardown is always called (the confirm-destroy contract);
  * a sandbox reporting a non-'hermetic' isolation level fails closed at receipt build (the law).
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from core import ExecutionResult, IsolationLevel, tree_hash

from orchestrator.gauntlet import (
    CellContext,
    own_tests_stage,
    run_stage,
    seal_artifact,
)
from orchestrator.schemas import validate_payload
from orchestrator.trust import generate_signer

_MANIFEST_DIGEST = "a" * 64
_RUN_ID = "22222222-2222-4222-8222-222222222222"


def _cell() -> CellContext:
    return CellContext(
        manifest_digest=_MANIFEST_DIGEST, planned_run_id=_RUN_ID,
        cell_id="retry-swallow/claude-x/0", lineage="claude-x",
        reviewer_lineage="gpt-y", side="tempting")


class _FakeHandle:
    def __init__(self, artifact_hash: str) -> None:
        self.id = "fake"
        self.artifact_hash = artifact_hash


class _FakeSandbox:
    """Mimics the OCISandbox interface; returns a canned ExecutionResult. Records
    prepare/run/teardown
    so the test can assert the contract (fresh object, teardown-always, isolation level)."""

    def __init__(
        self, *, outcome: str, exit_code: int | None,
        isolation_level: IsolationLevel = IsolationLevel.HERMETIC,
        image_digest: str = "sha256:" + "d" * 64,
    ) -> None:
        self.isolation_level = isolation_level
        self._outcome = outcome
        self._exit_code = exit_code
        self._image_digest = image_digest
        self.prepared = False
        self.ran = False
        self.torn_down = False

    def prepare(self, spec: object, fixtures: object) -> _FakeHandle:
        self.prepared = True
        self._artifact_hash = getattr(spec, "tree_hash", "sha256:" + "0" * 64)
        return _FakeHandle(self._artifact_hash)

    def run(self, handle: object, command: object, budget: object) -> ExecutionResult:
        self.ran = True
        self.ran_argv = getattr(command, "argv", ())
        return ExecutionResult(
            outcome=self._outcome, exit_code=self._exit_code,
            isolation_level=self.isolation_level, artifact_hash=self._artifact_hash,
            raw_return_code=self._exit_code, image_digest=self._image_digest)

    def teardown(self, handle: object) -> None:
        self.torn_down = True


@contextlib.contextmanager
def _snap(tmp_path: Path):  # noqa: ANN202 — test helper: a view dir + its digest
    (tmp_path / "main.py").write_text("x = 1\n")
    yield tmp_path, tree_hash(tmp_path)


def test_exit0_is_pass_the_thesis(tmp_path: Path) -> None:
    # own-tests GREEN on the evasion is the demonstration — exit 0 -> pass, content never inspected.
    sb = _FakeSandbox(outcome="completed", exit_code=0)
    with _snap(tmp_path) as (snap, _d):
        obs = own_tests_stage(snap, image="img", make_sandbox=lambda: sb)
    assert obs.outcome == "pass"
    assert obs.observation["pytest_status"] == "passed"
    assert obs.observation["container_exit_code"] == 0
    assert obs.observation["sandbox_isolation_level"] == "hermetic"
    assert sb.prepared and sb.ran and sb.torn_down  # teardown always


def test_exit1_is_fail(tmp_path: Path) -> None:
    sb = _FakeSandbox(outcome="completed", exit_code=1)
    with _snap(tmp_path) as (snap, _d):
        obs = own_tests_stage(snap, image="img", make_sandbox=lambda: sb)
    assert obs.outcome == "fail"
    assert obs.observation["pytest_status"] == "failed"


def test_exit5_no_tests_is_error(tmp_path: Path) -> None:
    sb = _FakeSandbox(outcome="completed", exit_code=5)
    with _snap(tmp_path) as (snap, _d):
        obs = own_tests_stage(snap, image="img", make_sandbox=lambda: sb)
    assert obs.observation["pytest_status"] == "no_tests"
    assert obs.outcome == "error"


def test_timeout_is_error_null_exit(tmp_path: Path) -> None:
    sb = _FakeSandbox(outcome="timeout", exit_code=None)
    with _snap(tmp_path) as (snap, _d):
        obs = own_tests_stage(snap, image="img", make_sandbox=lambda: sb)
    assert obs.outcome == "error"
    assert obs.observation["container_exit_code"] is None
    assert obs.observation["pytest_status"] == "error"


def test_fresh_sandbox_per_call_p2(tmp_path: Path) -> None:
    made: list[_FakeSandbox] = []

    def factory() -> _FakeSandbox:
        sb = _FakeSandbox(outcome="completed", exit_code=0)
        made.append(sb)
        return sb

    with _snap(tmp_path) as (snap, _d):
        own_tests_stage(snap, image="img", make_sandbox=factory)
        own_tests_stage(snap, image="img", make_sandbox=factory)
    assert len(made) == 2 and made[0] is not made[1]  # never reuse the sandbox object


def test_pytest_argv_is_hermetic_shape(tmp_path: Path) -> None:
    sb = _FakeSandbox(outcome="completed", exit_code=0)
    with _snap(tmp_path) as (snap, _d):
        own_tests_stage(snap, image="img", make_sandbox=lambda: sb)
    # -B (no __pycache__ into ro /artifact) + no cache plugin; runs over /artifact
    assert sb.ran_argv[:4] == ("python3", "-B", "-m", "pytest")
    assert "/artifact" in sb.ran_argv
    assert "no:cacheprovider" in sb.ran_argv


def test_receipt_integration_and_hermetic_law(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "main.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        # a hermetic sandbox -> a valid signed own_tests receipt
        good = _FakeSandbox(outcome="completed", exit_code=0)
        r = run_stage(_cell(), sealed, sealed.digest, "own_tests",
                      lambda p: own_tests_stage(p, image="img", make_sandbox=lambda: good),
                      s.signing_key)
        assert r.payload["stage"] == "own_tests"
        assert r.payload["outcome"] == "pass"
        validate_payload("cell_stage", r.payload)

        # a NON-hermetic sandbox -> the isolation law rejects the receipt -> published ERROR
        weak = _FakeSandbox(outcome="completed", exit_code=0,
                            isolation_level=IsolationLevel.WEAK)
        r2 = run_stage(_cell(), sealed, sealed.digest, "own_tests",
                       lambda p: own_tests_stage(p, image="img", make_sandbox=lambda: weak),
                       s.signing_key)
        assert r2.payload["outcome"] == "error"
        assert "harness_error" in r2.payload["observation"]
