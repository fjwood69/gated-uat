"""tests/test_gauntlet_foundation.py — B1 step 2: the gauntlet foundation + schema laws + static.

Proves the structural laws are true-by-construction:
  * a cell_stage receipt signs + schema-validates; every receipt binds
    (manifest_digest, planned_run_id == run_id, artifact_tree_digest);
  * P1: a gate observation whose measured_tree_digest != the bound artifact_tree_digest is
  UNSIGNABLE;
  * 'blocked' is a gate-only outcome; gate outcome<->result_kind coherence is enforced;
  * a harness-error observation is allowed ONLY with outcome=error;
  * the before/after digest guard turns a mismatch (or a mid-stage tamper) into a published ERROR
    receipt, never a silent rerun;
  * assert_safe_artifact_tree rejects symlinks (uniform with the gate's tarball policy);
  * run_gauntlet emits exactly one receipt per ordered stage;
  * static_stage passes a clean tree and fails a lint-dirty one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    DigestMismatchError,
    StageObservation,
    UnsafeArtifactError,
    assert_safe_artifact_tree,
    build_cell_stage_receipt,
    immutable_snapshot,
    run_gauntlet,
    run_stage,
    stage_guard,
    static_stage,
)
from orchestrator.schemas import SchemaViolationError, validate_payload
from orchestrator.trust import generate_signer, verify_receipt_sig

_MANIFEST_DIGEST = "a" * 64
_RUN_ID = "11111111-1111-4111-8111-111111111111"
_TREE = "sha256:" + "b" * 64
_OTHER_TREE = "sha256:" + "c" * 64


def _cell(side: str = "tempting") -> CellContext:
    return CellContext(
        manifest_digest=_MANIFEST_DIGEST, planned_run_id=_RUN_ID,
        cell_id="retry-swallow/claude-x/0", lineage="claude-x",
        reviewer_lineage="gpt-y", side=side)


# ---- cell_stage receipt signs + verifies + binds the anchor triple ----

def test_cell_stage_receipt_signs_and_validates() -> None:
    s = generate_signer()
    obs = {"tool_versions": {"ruff": "0", "mypy": "0", "python": "3.12"},
           "ruff_exit": 0, "mypy_exit": 0, "findings_count": 0}
    r = build_cell_stage_receipt(_cell(), "static", "pass", obs, _TREE, s.signing_key)
    assert r.kind == "cell_stage"
    assert r.run_id == _RUN_ID                      # binds planned_run_id (envelope-signed)
    assert r.payload["manifest_digest"] == _MANIFEST_DIGEST
    assert r.payload["artifact_tree_digest"] == _TREE
    validate_payload("cell_stage", r.payload)       # standalone schema check
    verify_receipt_sig(r.kind, r.digest, r.signature, s.verify_key)  # signature good


# ---- P1: the gate cannot certify a tree it did not measure ----

def test_gate_measured_tree_must_equal_bound_digest() -> None:
    s = generate_signer()
    good = {"result_kind": "blocking_refusal", "result_reason": "invariant_violation",
            "result_sub_reason": "", "gate_outcome": "block_gate", "measured_tree_digest": _TREE}
    # equal -> signs
    build_cell_stage_receipt(_cell(), "gate", "blocked", good, _TREE, s.signing_key)
    # different measured tree -> UNSIGNABLE (P1 false-green vector closed)
    bad = dict(good, measured_tree_digest=_OTHER_TREE)
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(_cell(), "gate", "blocked", bad, _TREE, s.signing_key)


def test_blocked_is_gate_only() -> None:
    s = generate_signer()
    obs = {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
           "container_exit_code": 0, "pytest_status": "passed"}
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(_cell(), "own_tests", "blocked", obs, _TREE, s.signing_key)


def test_gate_outcome_result_kind_coherence() -> None:
    s = generate_signer()
    # admitted_run cannot be 'blocked'
    incoherent = {"result_kind": "admitted_run", "result_reason": "pass", "result_sub_reason": "",
                  "gate_outcome": "run_verdict", "measured_tree_digest": _TREE}
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(_cell(), "gate", "blocked", incoherent, _TREE, s.signing_key)


def test_harness_error_obs_only_with_error_outcome() -> None:
    s = generate_signer()
    # allowed with outcome=error
    build_cell_stage_receipt(
        _cell(), "static", "error", {"harness_error": "boom"}, _TREE, s.signing_key)
    # NOT allowed with a non-error outcome
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(
            _cell(), "static", "pass", {"harness_error": "boom"}, _TREE, s.signing_key)


# ---- the before/after digest guard ----

def test_stage_guard_passes_clean(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    with immutable_snapshot(tmp_path) as (snap, digest):
        with stage_guard(snap, digest) as s:
            assert s == snap  # no raise: before + after match


def test_stage_guard_after_tamper_raises(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    with immutable_snapshot(tmp_path) as (snap, digest):
        with pytest.raises(DigestMismatchError):
            with stage_guard(snap, digest):
                (snap / "injected.py").write_text("evil = 1\n")  # mutate mid-stage -> after fails


def test_run_stage_mismatch_publishes_error_receipt(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with immutable_snapshot(tmp_path) as (snap, digest):
        def tamper(_snap: Path) -> StageObservation:
            (snap / "injected.py").write_text("evil = 1\n")  # trips the after-check
            return StageObservation("static", "pass", {
                "tool_versions": {}, "ruff_exit": 0, "mypy_exit": 0, "findings_count": 0})
        r = run_stage(_cell(), snap, digest, "static", tamper, s.signing_key)
    assert r.payload["outcome"] == "error"
    assert set(r.payload["observation"]) == {"harness_error"}
    assert "digest_guard" in r.payload["observation"]["harness_error"]
    validate_payload("cell_stage", r.payload)  # the ERROR receipt is itself well-formed + signed


def test_run_stage_crash_publishes_error_receipt(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with immutable_snapshot(tmp_path) as (snap, digest):
        def boom(_snap: Path) -> StageObservation:
            raise RuntimeError("stage exploded")
        r = run_stage(_cell(), snap, digest, "own_tests", boom, s.signing_key)
    assert r.payload["outcome"] == "error"
    assert "RuntimeError: stage exploded" in r.payload["observation"]["harness_error"]


# ---- safe-tree policy (P1 hardening) ----

def test_assert_safe_rejects_symlink(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    with pytest.raises(UnsafeArtifactError):
        assert_safe_artifact_tree(tmp_path)


def test_immutable_snapshot_rejects_symlink(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    with pytest.raises(UnsafeArtifactError):
        with immutable_snapshot(tmp_path) as _:
            pass


# ---- run_gauntlet: one receipt per ordered stage ----

def test_run_gauntlet_one_receipt_per_stage(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")

    def fake(stage: str, outcome: str, obs: dict) -> object:
        def fn(_snap: Path) -> StageObservation:
            return StageObservation(stage, outcome, obs)
        return fn

    stage_fns = {
        "static": fake("static", "pass",
                       {"tool_versions": {}, "ruff_exit": 0, "mypy_exit": 0, "findings_count": 0}),
        "own_tests": fake("own_tests", "pass",
                          {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
                           "container_exit_code": 0, "pytest_status": "passed"}),
        "llm_review": fake("llm_review", "pass",
                           {"provider_id": "p", "model_id": "m", "review_prompt_hash": "d" * 64,
                            "request_digest": "e" * 64, "response_digest": "f" * 64,
                            "verdict": "approve"}),
        "gate": fake("gate", "blocked",
                     {"result_kind": "blocking_refusal", "result_reason": "invariant_violation",
                      "result_sub_reason": "", "gate_outcome": "block_gate",
                      "measured_tree_digest": None}),  # filled below per-cell
    }
    # the gate stage must bind the REAL measured digest == the cell digest; capture it at run time.
    with immutable_snapshot(tmp_path) as (_snap, digest):
        stage_fns["gate"] = fake("gate", "blocked",
                                 {"result_kind": "blocking_refusal",
                                  "result_reason": "invariant_violation", "result_sub_reason": "",
                                  "gate_outcome": "block_gate", "measured_tree_digest": digest})
    receipts = run_gauntlet(_cell(), tmp_path, stage_fns, s.signing_key)
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.payload["outcome"] in {"pass", "blocked"} for r in receipts)
    assert all(r.run_id == _RUN_ID for r in receipts)


# ---- static stage: real ruff+mypy over a clean vs dirty tree ----

def test_static_stage_clean_tree_passes(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("x: int = 1\n")
    with immutable_snapshot(tmp_path) as (snap, _digest):
        obs = static_stage(snap)
    assert obs.stage == "static"
    assert obs.observation["ruff_exit"] == 0
    assert obs.outcome == "pass"


def test_static_stage_lint_dirty_tree_fails(tmp_path: Path) -> None:
    # an unused import is an F401 ruff finding -> ruff_exit != 0 -> outcome fail
    (tmp_path / "m.py").write_text("import os\n")
    with immutable_snapshot(tmp_path) as (snap, _digest):
        obs = static_stage(snap)
    assert obs.observation["ruff_exit"] != 0
    assert obs.observation["findings_count"] >= 1
    assert obs.outcome == "fail"
