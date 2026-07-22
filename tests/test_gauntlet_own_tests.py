"""tests/test_gauntlet_own_tests.py — B1 step 2 (gap-1): the own_tests stage (security-sensitive).

The hermetic sandbox itself is gated's OCISandbox — its isolation is covered by the pin's
test_oci_sandbox.py; here we prove the STAGE logic over an injected fake sandbox:
  * the stage takes the SEALED artifact and provisions a fresh view internally (extract_view);
  * it binds the SEALED digest into the sandbox spec (FOLD-A) — never a re-measure of the view;
  * the ONLY observation is the out-of-band container EXIT CODE (0->pass, 1->fail,
    5->no_tests-error, timeout/error->error) — the stage never inspects stdout or WHAT tests assert;
  * own-tests GREEN on an evasion is intentional (exit 0 -> pass) — the thesis;
  * invocation_digest binds WHAT ran; a FRESH sandbox object is constructed per cell (P2);
  * teardown is always called; a non-'hermetic' isolation level fails closed at receipt build.
"""

from __future__ import annotations

from pathlib import Path

from core import IsolationLevel

from orchestrator.gauntlet import (
    CellContext,
    own_tests_stage,
    run_stage,
    seal_artifact,
)
from orchestrator.schemas import validate_payload
from orchestrator.trust import generate_signer
from tests._fakes import FakeSandbox

_MANIFEST_DIGEST = "a" * 64
_RUN_ID = "22222222-2222-4222-8222-222222222222"
_HEX64 = 64


def _cell() -> CellContext:
    return CellContext(
        manifest_digest=_MANIFEST_DIGEST, planned_run_id=_RUN_ID,
        cell_id="retry-swallow/claude-x/0", lineage="claude-x",
        reviewer_lineage="gpt-y", side="tempting")


def _seal(tmp_path: Path):  # noqa: ANN202 — a sealed one-file artifact context
    (tmp_path / "main.py").write_text("x = 1\n")
    return seal_artifact(tmp_path)


def test_exit0_is_pass_the_thesis(tmp_path: Path) -> None:
    # own-tests GREEN on the evasion is the demonstration — exit 0 -> pass, content never inspected.
    sb = FakeSandbox(outcome="completed", exit_code=0)
    with _seal(tmp_path) as sealed:
        obs = own_tests_stage(sealed, image="img", make_sandbox=lambda: sb)
    assert obs.outcome == "pass"
    assert obs.observation["pytest_status"] == "passed"
    assert obs.observation["container_exit_code"] == 0
    assert obs.observation["sandbox_isolation_level"] == "hermetic"
    assert len(obs.observation["invocation_digest"]) == _HEX64      # FOLD-C: WHAT ran is bound
    assert sb.prepared and sb.run_count == 1 and sb.torn_down       # teardown always


def test_binds_sealed_digest_not_view_remeasure(tmp_path: Path) -> None:
    # FOLD-A: the spec handed to the sandbox carries the SEALED digest.
    sb = FakeSandbox(outcome="completed", exit_code=0)
    with _seal(tmp_path) as sealed:
        own_tests_stage(sealed, image="img", make_sandbox=lambda: sb)
        assert sb.spec_tree_hash == sealed.digest


def test_exit1_is_fail(tmp_path: Path) -> None:
    sb = FakeSandbox(outcome="completed", exit_code=1)
    with _seal(tmp_path) as sealed:
        obs = own_tests_stage(sealed, image="img", make_sandbox=lambda: sb)
    assert obs.outcome == "fail"
    assert obs.observation["pytest_status"] == "failed"


def test_exit5_no_tests_is_error(tmp_path: Path) -> None:
    sb = FakeSandbox(outcome="completed", exit_code=5)
    with _seal(tmp_path) as sealed:
        obs = own_tests_stage(sealed, image="img", make_sandbox=lambda: sb)
    assert obs.observation["pytest_status"] == "no_tests"
    assert obs.outcome == "error"


def test_timeout_is_error_null_exit(tmp_path: Path) -> None:
    sb = FakeSandbox(outcome="timeout", exit_code=None)
    with _seal(tmp_path) as sealed:
        obs = own_tests_stage(sealed, image="img", make_sandbox=lambda: sb)
    assert obs.outcome == "error"
    assert obs.observation["container_exit_code"] is None
    assert obs.observation["pytest_status"] == "error"


def test_fresh_sandbox_per_call_p2(tmp_path: Path) -> None:
    made: list[FakeSandbox] = []

    def factory() -> FakeSandbox:
        sb = FakeSandbox(outcome="completed", exit_code=0)
        made.append(sb)
        return sb

    with _seal(tmp_path) as sealed:
        own_tests_stage(sealed, image="img", make_sandbox=factory)
        own_tests_stage(sealed, image="img", make_sandbox=factory)
    assert len(made) == 2 and made[0] is not made[1]  # never reuse the sandbox object


def test_pytest_argv_is_hermetic_shape(tmp_path: Path) -> None:
    sb = FakeSandbox(outcome="completed", exit_code=0)
    with _seal(tmp_path) as sealed:
        own_tests_stage(sealed, image="img", make_sandbox=lambda: sb)
    argv = sb.ran_argvs[0]
    assert argv[:4] == ("python3", "-B", "-m", "pytest")   # -B: no __pycache__ into ro /artifact
    assert "/artifact" in argv
    assert "no:cacheprovider" in argv


def test_receipt_integration_and_hermetic_law(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "main.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        good = FakeSandbox(outcome="completed", exit_code=0)
        r = run_stage(_cell(), sealed, sealed.digest, "own_tests",
                      lambda sl: own_tests_stage(sl, image="img", make_sandbox=lambda: good),
                      s.signing_key)
        assert r.payload["stage"] == "own_tests"
        assert r.payload["outcome"] == "pass"
        validate_payload("cell_stage", r.payload)

        # a NON-hermetic sandbox -> the isolation law rejects the receipt -> published ERROR
        weak = FakeSandbox(outcome="completed", exit_code=0, isolation_level=IsolationLevel.WEAK)
        r2 = run_stage(_cell(), sealed, sealed.digest, "own_tests",
                       lambda sl: own_tests_stage(sl, image="img", make_sandbox=lambda: weak),
                       s.signing_key)
        assert r2.payload["outcome"] == "error"
        assert "harness_error" in r2.payload["observation"]
