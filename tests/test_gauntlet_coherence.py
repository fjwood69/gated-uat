"""tests/test_gauntlet_coherence.py — B1 step 2 remediation (dissent-fold) proofs.

  * PARITY: the schema's re-encoded gate_outcome<->result_kind map == the REAL gate.job_result
    account() (so the re-encoding cannot drift — the catch was blocking_refusal=run_verdict, NOT
    block_gate);
  * COHERENCE swept across ALL FOUR stages: a signed receipt whose outcome contradicts its
    measurement is unrepresentable (own_tests exit!=status, static nonzero-exit 'pass', reviewer
    request_changes 'pass', gate_outcome incoherent with result_kind);
  * CELL-LEVEL FAILURE PATH: an unsafe-tree cell publishes an ERROR receipt for EVERY stage (the
    denominator bijection holds — no cell vanishes);
  * TOOLCHAIN PIN: a pinned static toolchain digest is enforced (a drift fails closed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    StageObservation,
    StaticTools,
    _exe_digest,
    default_static_tools,
    run_gauntlet,
    static_stage,
)
from orchestrator.schemas import (
    GATE_OUTCOME_BY_RESULT_KIND,
    SchemaViolationError,
    validate_payload,
)
from orchestrator.trust import generate_signer
from tests._gate_account import real_gate_outcome

_MD = "a" * 64
_RUN_ID = "77777777-7777-4777-8777-777777777777"
_TREE = "sha256:" + "b" * 64


def _cell() -> CellContext:
    return CellContext(
        manifest_digest=_MD, planned_run_id=_RUN_ID, cell_id="retry/claude-x/0",
        lineage="claude-x", reviewer_lineage="gpt-y", side="tempting")


def _receipt(stage: str, outcome: str, obs: dict) -> None:
    from orchestrator.gauntlet import build_cell_stage_receipt
    build_cell_stage_receipt(_cell(), stage, outcome, obs, _TREE, generate_signer().signing_key)


# ---- PARITY: schema map == real account() ----

def test_gate_outcome_schema_matches_real_account() -> None:
    assert real_gate_outcome("blocking_refusal") == "run_verdict"  # THE catch: not block_gate
    assert real_gate_outcome("blocking_refusal") in GATE_OUTCOME_BY_RESULT_KIND["blocking_refusal"]
    assert real_gate_outcome("admitted_run") in GATE_OUTCOME_BY_RESULT_KIND["admitted_run"]
    assert real_gate_outcome("non_run_block") in GATE_OUTCOME_BY_RESULT_KIND["non_run"]
    assert real_gate_outcome("non_run_neutral") in GATE_OUTCOME_BY_RESULT_KIND["non_run"]
    assert real_gate_outcome("infrastructure_failure") in GATE_OUTCOME_BY_RESULT_KIND[
        "infrastructure_failure"]
    assert GATE_OUTCOME_BY_RESULT_KIND["non_run"] == frozenset({"block_gate", "neutral_gate"})
    assert GATE_OUTCOME_BY_RESULT_KIND["infrastructure_failure"] == frozenset({None})


# ---- COHERENCE swept across all four stages ----

def test_own_tests_exit_status_incoherent_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # exit 1 cannot be 'passed'
        _receipt("own_tests", "fail", {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
                                       "container_exit_code": 1, "pytest_status": "passed"})


def test_own_tests_status_outcome_incoherent_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # passed cannot sign outcome 'fail'
        _receipt("own_tests", "fail", {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
                                       "container_exit_code": 0, "pytest_status": "passed"})


def test_static_nonzero_exit_pass_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # a ruff finding cannot sign 'pass'
        _receipt("static", "pass",
                 {"tool_versions": {}, "ruff_exit": 1, "mypy_exit": 0, "findings_count": 3})


def test_llm_review_request_changes_pass_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # request_changes cannot sign 'pass'
        _receipt("llm_review", "pass",
                 {"provider_id": "p", "model_id": "m", "review_prompt_hash": "d" * 64,
                  "request_digest": "e" * 64, "response_digest": "f" * 64,
                  "verdict": "request_changes"})


def test_gate_outcome_incoherent_with_result_kind_rejected() -> None:
    # blocking_refusal with block_gate (the OLD fake's value) is now unrepresentable — account()
    # law.
    with pytest.raises(SchemaViolationError):
        _receipt("gate", "blocked",
                 {"result_kind": "blocking_refusal", "result_reason": "x", "result_sub_reason": "",
                  "gate_outcome": "block_gate", "measured_tree_digest": _TREE})


# ---- CELL-LEVEL FAILURE PATH: an unsafe cell still publishes every stage ----

def test_unsafe_tree_publishes_error_for_every_stage(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")  # unsafe -> seal refuses

    def never(_v: Path) -> StageObservation:  # must never be called
        raise AssertionError("stage ran despite an unsafe tree")

    stage_fns = {stg: never for stg in GAUNTLET_STAGES}
    receipts = run_gauntlet(_cell(), tmp_path, stage_fns, s.signing_key)
    # the bijection holds: one terminal receipt per planned stage, all ERROR, all bound + signed.
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.payload["outcome"] == "error" for r in receipts)
    assert all(r.run_id == _RUN_ID for r in receipts)
    assert all("cell_failure" in r.payload["observation"]["harness_error"] for r in receipts)
    for r in receipts:
        validate_payload("cell_stage", r.payload)


# ---- TOOLCHAIN PIN: enforced, not just recorded ----

def test_static_toolchain_digest_pin_enforced(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("x: int = 1\n")
    base = default_static_tools()
    # a WRONG pinned ruff digest -> the stage fails closed (RuntimeError -> harness error upstream).
    wrong = StaticTools(ruff_argv=base.ruff_argv, mypy_argv=base.mypy_argv,
                        python_version=base.python_version,
                        expected_ruff_digest="sha256:" + "0" * 64)
    with pytest.raises(RuntimeError):
        static_stage(tmp_path, wrong)
    # the CORRECT pinned digest (recorded == enforced) passes.
    right = StaticTools(ruff_argv=base.ruff_argv, mypy_argv=base.mypy_argv,
                        python_version=base.python_version,
                        expected_ruff_digest=_exe_digest(base.ruff_argv[0]),
                        expected_mypy_digest=_exe_digest(base.mypy_argv[0]))
    obs = static_stage(tmp_path, right)
    assert obs.outcome == "pass"
    assert obs.observation["tool_versions"]["ruff_exe_digest"] == _exe_digest(base.ruff_argv[0])
