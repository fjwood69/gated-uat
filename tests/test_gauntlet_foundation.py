"""tests/test_gauntlet_foundation.py — B1 step 2: the gauntlet foundation + schema laws + static.

Proves the structural laws are true-by-construction:
  * a cell_stage receipt signs + schema-validates; every receipt binds
    (manifest_digest, planned_run_id == run_id, artifact_tree_digest);
  * P1: a gate observation whose measured_tree_digest != the bound artifact_tree_digest is
  UNSIGNABLE;
  * 'blocked' is a gate-only outcome; the gate_outcome<->result_kind coherence is account()-law;
  * a harness-error observation is allowed ONLY with outcome=error;
  * seal_artifact + materialise give a FRESH verified view per stage (immutability by construction);
    a corrupt seal -> DigestMismatchError -> published ERROR receipt (never a silent rerun);
  * assert_safe_artifact_tree rejects symlinks AND hardlinks (uniform with the gate's tarball path);
  * run_gauntlet emits exactly one receipt per ordered stage; static_stage passes clean / fails
  dirty.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from core import tree_hash

from orchestrator.gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    DigestMismatchError,
    StageObservation,
    UnsafeArtifactError,
    assert_safe_artifact_tree,
    build_cell_stage_receipt,
    materialise,
    run_gauntlet,
    run_stage,
    seal_artifact,
    static_stage,
)
from orchestrator.schemas import SchemaViolationError, validate_payload
from orchestrator.trust import generate_signer, verify_receipt_sig
from tests._gate_account import real_gate_outcome

_MANIFEST_DIGEST = "a" * 64
_RUN_ID = "11111111-1111-4111-8111-111111111111"
_TREE = "sha256:" + "b" * 64
_OTHER_TREE = "sha256:" + "c" * 64


def _cell(side: str = "tempting") -> CellContext:
    return CellContext(
        manifest_digest=_MANIFEST_DIGEST, planned_run_id=_RUN_ID,
        cell_id="retry-swallow/claude-x/0", lineage="claude-x",
        reviewer_lineage="gpt-y", side=side)


def _gate_obs(result_kind: str, measured: str) -> dict:
    """A gate observation with the account()-coherent gate_outcome for result_kind."""
    reason = "invariant_violation" if result_kind == "blocking_refusal" else "clean"
    return {"result_kind": result_kind, "result_reason": reason, "result_sub_reason": "",
            "gate_outcome": real_gate_outcome(result_kind), "measured_tree_digest": measured}


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
    validate_payload("cell_stage", r.payload)
    verify_receipt_sig(r.kind, r.digest, r.signature, s.verify_key)


# ---- P1: the gate cannot certify a tree it did not measure ----

def test_gate_measured_tree_must_equal_bound_digest() -> None:
    s = generate_signer()
    build_cell_stage_receipt(  # equal -> signs
        _cell(), "gate", "blocked", _gate_obs("blocking_refusal", _TREE), _TREE, s.signing_key)
    with pytest.raises(SchemaViolationError):  # different measured tree -> UNSIGNABLE (P1)
        build_cell_stage_receipt(
            _cell(), "gate", "blocked", _gate_obs("blocking_refusal", _OTHER_TREE), _TREE,
            s.signing_key)


def test_blocked_is_gate_only() -> None:
    s = generate_signer()
    obs = {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
           "container_exit_code": 0, "pytest_status": "passed"}
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(_cell(), "own_tests", "blocked", obs, _TREE, s.signing_key)


def test_harness_error_obs_only_with_error_outcome() -> None:
    s = generate_signer()
    build_cell_stage_receipt(  # allowed with outcome=error
        _cell(), "static", "error", {"harness_error": "boom"}, _TREE, s.signing_key)
    with pytest.raises(SchemaViolationError):  # NOT allowed with a non-error outcome
        build_cell_stage_receipt(
            _cell(), "static", "pass", {"harness_error": "boom"}, _TREE, s.signing_key)


# ---- seal + materialise: fresh verified view; corrupt seal fails closed ----

def test_materialise_yields_verified_view(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        with materialise(sealed) as view:
            assert tree_hash(view) == sealed.digest      # the view IS the sealed bytes
        with materialise(sealed) as view2:               # each materialise is a FRESH copy
            assert tree_hash(view2) == sealed.digest


def test_materialise_digest_mismatch_raises(tmp_path: Path) -> None:
    # materialise verifies the extracted view == the sealed digest; a seal whose digest does not
    # match
    # its archive bytes (the on-extraction integrity check) fails closed.
    from orchestrator.gauntlet import SealedArtifact
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        wrong = SealedArtifact(archive=sealed.archive, digest="sha256:" + "9" * 64)
        with pytest.raises(DigestMismatchError):
            with materialise(wrong):
                pass


def test_run_stage_materialise_failure_publishes_error(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        os.chmod(sealed.archive, 0o644)
        sealed.archive.write_bytes(b"not a tar")  # materialise will fail

        def ok(_v: Path) -> StageObservation:
            return StageObservation("static", "pass", {
                "tool_versions": {}, "ruff_exit": 0, "mypy_exit": 0, "findings_count": 0})
        r = run_stage(_cell(), sealed, sealed.digest, "static", ok, s.signing_key)
    assert r.payload["outcome"] == "error"
    assert set(r.payload["observation"]) == {"harness_error"}
    validate_payload("cell_stage", r.payload)


def test_run_stage_crash_publishes_error_receipt(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        def boom(_v: Path) -> StageObservation:
            raise RuntimeError("stage exploded")
        r = run_stage(_cell(), sealed, sealed.digest, "own_tests", boom, s.signing_key)
    assert r.payload["outcome"] == "error"
    assert "RuntimeError: stage exploded" in r.payload["observation"]["harness_error"]


def test_stage_mutating_its_view_does_not_change_bound_digest(tmp_path: Path) -> None:
    # dissent P1: a stage mutating its OWN fresh view cannot affect the bound (sealed) digest, and
    # the
    # next stage gets a fresh unmutated view — mutate->measure->restore has nothing to attack.
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        def mutate(view: Path) -> StageObservation:
            (view / "injected.py").write_text("evil = 1\n")  # mutate the ephemeral view
            return StageObservation("static", "pass", {
                "tool_versions": {}, "ruff_exit": 0, "mypy_exit": 0, "findings_count": 0})
        r = run_stage(_cell(), sealed, sealed.digest, "static", mutate, s.signing_key)
        assert r.payload["artifact_tree_digest"] == sealed.digest  # bound to the seal, not the view
        with materialise(sealed) as view2:                          # the next view is clean
            assert not (view2 / "injected.py").exists()
            assert tree_hash(view2) == sealed.digest


# ---- safe-tree policy (P1 hardening): symlinks AND hardlinks ----

def test_assert_safe_rejects_symlink(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    with pytest.raises(UnsafeArtifactError):
        assert_safe_artifact_tree(tmp_path)


def test_assert_safe_rejects_hardlink(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n")
    os.link(tmp_path / "real.py", tmp_path / "hard.py")  # a true hardlink (st_nlink=2)
    with pytest.raises(UnsafeArtifactError):
        assert_safe_artifact_tree(tmp_path)


def test_seal_rejects_unsafe_tree(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    with pytest.raises(UnsafeArtifactError):
        with seal_artifact(tmp_path):
            pass


# ---- run_gauntlet: one receipt per ordered stage ----

def test_run_gauntlet_one_receipt_per_stage(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    digest = tree_hash(tmp_path)

    def fake(stage: str, outcome: str, obs: dict):  # noqa: ANN202
        def fn(_v: Path) -> StageObservation:
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
        "gate": fake("gate", "blocked", _gate_obs("blocking_refusal", digest)),
    }
    receipts = run_gauntlet(_cell(), tmp_path, stage_fns, s.signing_key)
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.run_id == _RUN_ID for r in receipts)
    assert {r.payload["artifact_tree_digest"] for r in receipts} == {digest}
    for r in receipts:
        validate_payload("cell_stage", r.payload)


# ---- static stage: real ruff+mypy over a clean vs dirty tree ----

def test_static_stage_clean_tree_passes(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("x: int = 1\n")
    obs = static_stage(tmp_path)
    assert obs.stage == "static"
    assert obs.observation["ruff_exit"] == 0
    assert obs.outcome == "pass"
    assert obs.observation["tool_versions"]["ruff_exe_digest"].startswith("sha256:")


def test_static_stage_lint_dirty_tree_fails(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("import os\n")  # F401 unused import
    obs = static_stage(tmp_path)
    assert obs.observation["ruff_exit"] != 0
    assert obs.observation["findings_count"] >= 1
    assert obs.outcome == "fail"
