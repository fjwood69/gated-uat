"""tests/test_gauntlet_coherence.py — B1 step 2 (gap-1) remediation proofs.

  * PARITY: the schema's re-encoded gate_outcome<->result_kind map == the REAL gate.job_result
    account() (so the re-encoding cannot drift — the catch was blocking_refusal=run_verdict, NOT
    block_gate);
  * COHERENCE swept across ALL FOUR stages: a signed receipt whose outcome contradicts its
    measurement is unrepresentable (own_tests exit!=status, static nonzero-exit 'pass', reviewer
    request_changes 'pass', gate_outcome incoherent with result_kind);
  * CELL-LEVEL FAILURE PATH: an unsafe-tree / harness-misconfig cell publishes an ERROR receipt for
    EVERY stage (the denominator bijection holds — no cell vanishes);
  * TOOLCHAIN PIN (gap-1 form): the static stage ASSERTS the sandbox's observed image config digest
    == the manifest env_digest; a drift fails closed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from orchestrator.gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    SealedArtifact,
    StageObservation,
    build_cell_stage_receipt,
    run_gauntlet,
    seal_artifact,
    static_stage,
)
from orchestrator.schemas import (
    GATE_OUTCOME_BY_RESULT_KIND,
    SchemaViolationError,
    validate_payload,
)
from orchestrator.trust import generate_signer
from tests._fakes import FakeSandbox
from tests._gate_account import real_gate_outcome

_MD = "a" * 64
_RUN_ID = "77777777-7777-4777-8777-777777777777"
_TREE = "sha256:" + "b" * 64
_ENV = "sha256:" + "d" * 64            # == tests._fakes default image_digest


def _cell() -> CellContext:
    return CellContext(
        manifest_digest=_MD, planned_run_id=_RUN_ID, cell_id="retry/claude-x/0",
        lineage="claude-x", reviewer_lineage="gpt-y", side="tempting")


def _receipt(stage: str, outcome: str, obs: dict[str, Any]) -> None:
    build_cell_stage_receipt(_cell(), stage, outcome, obs, _TREE, generate_signer().signing_key)


def _ok_static_obs() -> dict[str, Any]:
    return {"env_digest": _ENV, "ruff_exit": 0, "mypy_exit": 0, "invocation_digest": "e" * 64}


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
                                       "container_exit_code": 1, "pytest_status": "passed",
                                       "invocation_digest": "e" * 64})


def test_own_tests_status_outcome_incoherent_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # passed cannot sign outcome 'fail'
        _receipt("own_tests", "fail", {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
                                       "container_exit_code": 0, "pytest_status": "passed",
                                       "invocation_digest": "e" * 64})


def test_static_nonzero_exit_pass_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # a ruff finding cannot sign 'pass'
        _receipt("static", "pass",
                 {"env_digest": _ENV, "ruff_exit": 1, "mypy_exit": 0,
                  "invocation_digest": "e" * 64})


def test_llm_review_request_changes_pass_rejected() -> None:
    with pytest.raises(SchemaViolationError):  # request_changes cannot sign 'pass'
        _receipt("llm_review", "pass",
                 {"provider_id": "p", "model_id": "m", "review_prompt_hash": "d" * 64,
                  "source_digest": "a" * 64, "request_digest": "e" * 64,
                  "response_digest": "f" * 64,
                  "verdict": "request_changes"})


def test_gate_outcome_incoherent_with_result_kind_rejected() -> None:
    # blocking_refusal with block_gate is now unrepresentable — account() law.
    with pytest.raises(SchemaViolationError):
        _receipt("gate", "blocked",
                 {"result_kind": "blocking_refusal", "result_reason": "x", "result_sub_reason": "",
                  "gate_outcome": "block_gate", "measured_tree_digest": _TREE})


def test_non_run_disposition_binds_gate_outcome() -> None:
    # gap 3: the disposition (result_reason) FIXES block vs neutral — no loose pairing.
    def go(reason: str, gate_outcome: str) -> None:
        _receipt("gate", "error",
                 {"result_kind": "non_run", "result_reason": reason, "result_sub_reason": "",
                  "gate_outcome": gate_outcome, "measured_tree_digest": _TREE})
    go("block_action_required", "block_gate")   # coherent
    go("skip_neutral", "neutral_gate")           # coherent
    with pytest.raises(SchemaViolationError):     # block_action_required cannot be neutral_gate
        go("block_action_required", "neutral_gate")
    with pytest.raises(SchemaViolationError):     # skip_neutral cannot be block_gate
        go("skip_neutral", "block_gate")


# ---- CELL-LEVEL FAILURE PATH: an unsafe / misconfig cell still publishes every stage ----

def test_unsafe_tree_publishes_error_for_every_stage(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")  # unsafe -> seal refuses

    def never(_s: SealedArtifact) -> StageObservation:
        raise AssertionError("stage ran despite an unsafe tree")

    stage_fns = {stg: never for stg in GAUNTLET_STAGES}
    receipts = run_gauntlet(_cell(), tmp_path, stage_fns, s.signing_key)
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.payload["outcome"] == "error" for r in receipts)
    assert all(r.run_id == _RUN_ID for r in receipts)
    assert all("cell_failure" in r.payload["observation"]["harness_error"] for r in receipts)
    for r in receipts:
        validate_payload("cell_stage", r.payload)


def test_harness_misconfig_publishes_error_for_every_stage(tmp_path: Path) -> None:
    # a missing stage_fns entry is harness misconfig -> 4 ERROR receipts, not a raise that lets the
    # cell escape the denominator (dissent gap 2a).
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")

    def ok(_s: SealedArtifact) -> StageObservation:
        return StageObservation("static", "pass", _ok_static_obs())

    incomplete = {"static": ok, "own_tests": ok, "llm_review": ok}  # 'gate' missing
    receipts = run_gauntlet(_cell(), tmp_path, incomplete, s.signing_key)
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.payload["outcome"] == "error" for r in receipts)
    assert all("HarnessMisconfigError" in r.payload["observation"]["harness_error"]
               for r in receipts)
    for r in receipts:
        validate_payload("cell_stage", r.payload)


def test_unmeasurable_sentinel_signable_only_with_error() -> None:
    # gap 2b: the UNMEASURABLE sentinel binds ONLY to outcome=error + harness_error.
    from orchestrator.schemas import UNMEASURABLE_TREE_DIGEST
    key = generate_signer().signing_key
    build_cell_stage_receipt(_cell(), "static", "error", {"harness_error": "unmeasurable"},
                             UNMEASURABLE_TREE_DIGEST, key)
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(_cell(), "static", "pass", _ok_static_obs(),
                                 UNMEASURABLE_TREE_DIGEST, key)


# ---- TOOLCHAIN PIN (gap-1): env_digest == image config id, enforced ----

def test_static_env_digest_pin_enforced(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("x: int = 1\n")
    with seal_artifact(tmp_path) as sealed:
        # matching image config digest -> the stage proceeds (recorded == enforced)
        ok = FakeSandbox(results=[("completed", 0), ("completed", 0)], image_digest=_ENV)
        obs = static_stage(sealed, image="img", env_digest=_ENV, make_sandbox=lambda: ok)
        assert obs.outcome == "pass"
        assert obs.observation["env_digest"] == _ENV
        # a DRIFTED image (config id != manifest env_digest) -> fails closed
        drift = FakeSandbox(results=[("completed", 0), ("completed", 0)],
                            image_digest="sha256:" + "e" * 64)
        with pytest.raises(RuntimeError):
            static_stage(sealed, image="img", env_digest=_ENV, make_sandbox=lambda: drift)
