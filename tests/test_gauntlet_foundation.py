"""tests/test_gauntlet_foundation.py — B1 step 2 (gap-1): foundation + schema laws + FOLD-A.

Proves the structural laws are true-by-construction:
  * a cell_stage receipt signs + schema-validates; every receipt binds
    (manifest_digest, planned_run_id == run_id, artifact_tree_digest); the binding is CRYPTOGRAPHIC
    (a flipped observation/digest bit fails signature verification), not merely schema-shaped;
  * P1: a gate observation whose measured_tree_digest != the artifact_tree_digest is UNSIGNABLE;
  * 'blocked' is a gate-only outcome; a harness-error obs is allowed ONLY with outcome=error;
  * FOLD-A (capability-deletion, FALSIFIABLE): a stage binds the SEALED digest — a RealisticSandbox
    that re-hashes its snapshot (like the pin) raises on a divergent view, and the stage passed
    sealed.digest, NOT tree_hash(view). A revert to tree_hash(view) fails this test;
  * extract_view gives a FRESH verified view (no chmod theater); a corrupt seal -> published ERROR;
  * seal forbids symlink/hardlink trees AND a file-root / symlink-root; empty trees seal;
  * run_gauntlet emits exactly one receipt per ordered stage; static runs IN a hermetic sandbox
    (exit-code-only + env_digest assertion + invocation_digest), drift -> ERROR.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any

import pytest
from core import tree_hash

from orchestrator import gauntlet
from orchestrator.gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    DigestMismatchError,
    SealedArtifact,
    StageObservation,
    UnsafeArtifactError,
    _invocation_digest,
    assert_safe_artifact_tree,
    build_cell_stage_receipt,
    extract_view,
    run_gauntlet,
    run_stage,
    seal_artifact,
    static_stage,
)
from orchestrator.schemas import SchemaViolationError, validate_payload
from orchestrator.trust import generate_signer, verify_receipt_sig
from tests._fakes import FakeSandbox, RealisticSandbox
from tests._gate_account import real_gate_outcome

_MANIFEST_DIGEST = "a" * 64
_RUN_ID = "11111111-1111-4111-8111-111111111111"
_TREE = "sha256:" + "b" * 64
_OTHER_TREE = "sha256:" + "c" * 64
_ENV = "sha256:" + "d" * 64            # == tests._fakes default image_digest
_HEX64 = 64


def _cell(side: str = "tempting") -> CellContext:
    return CellContext(
        manifest_digest=_MANIFEST_DIGEST, planned_run_id=_RUN_ID,
        cell_id="retry-swallow/claude-x/0", lineage="claude-x",
        reviewer_lineage="gpt-y", side=side)


def _static_obs(ruff: int = 0, mypy: int = 0) -> dict[str, Any]:
    return {"env_digest": _ENV, "ruff_exit": ruff, "mypy_exit": mypy, "invocation_digest": "e" * 64}


def _gate_obs(result_kind: str, measured: str) -> dict[str, Any]:
    reason = "invariant_violation" if result_kind == "blocking_refusal" else "clean"
    return {"result_kind": result_kind, "result_reason": reason, "result_sub_reason": "",
            "gate_outcome": real_gate_outcome(result_kind), "measured_tree_digest": measured}


# ---- cell_stage receipt signs + verifies + binds the anchor triple (cryptographically) ----

def test_cell_stage_receipt_signs_and_validates() -> None:
    s = generate_signer()
    r = build_cell_stage_receipt(_cell(), "static", "pass", _static_obs(), _TREE, s.signing_key)
    assert r.kind == "cell_stage"
    assert r.run_id == _RUN_ID                      # binds planned_run_id (envelope-signed)
    assert r.payload["manifest_digest"] == _MANIFEST_DIGEST
    assert r.payload["artifact_tree_digest"] == _TREE
    validate_payload("cell_stage", r.payload)
    verify_receipt_sig(r.kind, r.digest, r.signature, s.verify_key)


def test_receipt_binding_is_cryptographic_not_schema() -> None:
    # a flipped bit in the signed content must fail verification against the receipt's signature.
    s = generate_signer()
    r = build_cell_stage_receipt(_cell(), "static", "pass", _static_obs(), _TREE, s.signing_key)
    verify_receipt_sig(r.kind, r.digest, r.signature, s.verify_key)             # honest -> verifies
    tampered_digest = ("0" if r.digest[0] != "0" else "1") + r.digest[1:]
    with pytest.raises(Exception):  # noqa: B017,PT011 — any verification failure is acceptable
        verify_receipt_sig(r.kind, tampered_digest, r.signature, s.verify_key)


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
           "container_exit_code": 0, "pytest_status": "passed", "invocation_digest": "e" * 64}
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(_cell(), "own_tests", "blocked", obs, _TREE, s.signing_key)


def test_harness_error_obs_only_with_error_outcome() -> None:
    s = generate_signer()
    build_cell_stage_receipt(  # allowed with outcome=error
        _cell(), "static", "error", {"harness_error": "boom"}, _TREE, s.signing_key)
    with pytest.raises(SchemaViolationError):  # NOT allowed with a non-error outcome
        build_cell_stage_receipt(
            _cell(), "static", "pass", {"harness_error": "boom"}, _TREE, s.signing_key)


# ---- FOLD-A: capability-deletion, FALSIFIABLE (stage binds sealed, not the view) ----

def test_fold_a_stage_binds_sealed_digest_not_view(tmp_path: Path, monkeypatch: Any) -> None:
    # A RealisticSandbox mimics the pin: copytree the view, RE-HASH, raise on drift. We monkeypatch
    # extract_view -> a DIVERGENT dir. Because the stage binds sealed.digest, prepare() re-hashes
    # the divergent view, mismatches, and the cell publishes an ERROR — AND the sandbox was handed
    # sealed.digest, not the divergent view's hash. A revert to tree_hash(view) makes prepare() NOT
    # raise (self-consistent) and the bound digest would be the divergent one -> this test fails.
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    divergent = tmp_path.parent / "divergent"
    divergent.mkdir()
    (divergent / "a.py").write_text("TAMPERED = True\n")
    assert tree_hash(divergent) != tree_hash(tmp_path)

    @contextlib.contextmanager
    def fake_extract_view(_sealed: SealedArtifact):  # noqa: ANN202
        yield divergent

    sb = RealisticSandbox(image_digest=_ENV)
    with seal_artifact(tmp_path) as sealed:
        monkeypatch.setattr(gauntlet, "extract_view", fake_extract_view)
        r = run_stage(_cell(), sealed, sealed.digest, "static",
                      lambda sl: static_stage(sl, image="img", env_digest=_ENV,
                                              make_sandbox=lambda: sb), s.signing_key)
        assert r.payload["outcome"] == "error"                      # prepare() re-hash caught it
        assert sb.spec_tree_hash == sealed.digest                   # bound SEALED, not view
        assert sb.spec_tree_hash != tree_hash(divergent)


# ---- extract_view: fresh verified view; corrupt seal fails closed; view purged ----

def test_extract_view_yields_verified_view(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        seen: list[Path] = []
        with extract_view(sealed) as view:
            assert tree_hash(view) == sealed.digest      # the view IS the sealed bytes
            seen.append(view)
        assert not seen[0].exists()                      # purged after the stage
        with extract_view(sealed) as view2:              # each extract is a FRESH copy
            assert tree_hash(view2) == sealed.digest


def test_extract_view_wrong_digest_raises(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        wrong = SealedArtifact(archive=sealed.archive, digest="sha256:" + "9" * 64)
        with pytest.raises(DigestMismatchError), extract_view(wrong):
            pass


def test_run_stage_extract_failure_publishes_error(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        os.chmod(sealed.archive, 0o644)
        sealed.archive.write_bytes(b"not a tar")  # extract_view will fail inside the stage

        def stage(sl: SealedArtifact) -> StageObservation:
            with extract_view(sl):
                return StageObservation("static", "pass", _static_obs())
        r = run_stage(_cell(), sealed, sealed.digest, "static", stage, s.signing_key)
    assert r.payload["outcome"] == "error"
    assert set(r.payload["observation"]) == {"harness_error"}
    validate_payload("cell_stage", r.payload)


def test_run_stage_crash_publishes_error_receipt(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        def boom(_s: SealedArtifact) -> StageObservation:
            raise RuntimeError("stage exploded")
        r = run_stage(_cell(), sealed, sealed.digest, "own_tests", boom, s.signing_key)
    assert r.payload["outcome"] == "error"
    assert "RuntimeError: stage exploded" in r.payload["observation"]["harness_error"]


def test_fifo_artifact_does_not_hang_and_publishes_errors(tmp_path: Path) -> None:
    # a FIFO is rejected by the lstat preflight BEFORE hashing blocks — 4 ERRORs, no hang.
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    os.mkfifo(tmp_path / "pipe")

    def never(_s: SealedArtifact) -> StageObservation:
        raise AssertionError("stage ran despite a FIFO artifact")

    receipts = run_gauntlet(_cell(), tmp_path, {s2: never for s2 in GAUNTLET_STAGES}, s.signing_key)
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.payload["outcome"] == "error" for r in receipts)
    assert all("cell_failure" in r.payload["observation"]["harness_error"] for r in receipts)


# ---- safe-tree policy (P1 hardening): symlink, hardlink, file-root, symlink-root, empty ----

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


def test_seal_rejects_symlink_tree(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    with pytest.raises(UnsafeArtifactError), seal_artifact(tmp_path):
        pass


def test_seal_rejects_file_root(tmp_path: Path) -> None:
    solo = tmp_path / "solo.py"
    solo.write_text("x = 1\n")
    with pytest.raises(UnsafeArtifactError), seal_artifact(solo):
        pass


def test_seal_rejects_symlink_root(tmp_path: Path) -> None:
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "a.py").write_text("x = 1\n")
    link = tmp_path / "linkdir"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(UnsafeArtifactError), seal_artifact(link):
        pass


def test_seal_empty_tree(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with seal_artifact(empty) as sealed:
        assert sealed.digest == tree_hash(empty)
        with extract_view(sealed) as view:
            assert tree_hash(view) == sealed.digest


def test_second_cell_seal_independence(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.py").write_text("x = 1\n")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "x.py").write_text("y = 2\n")
    with seal_artifact(tmp_path / "a") as sa, seal_artifact(tmp_path / "b") as sb:
        assert sa.digest != sb.digest
        assert sa.archive != sb.archive


# ---- run_gauntlet: one receipt per ordered stage ----

def test_run_gauntlet_one_receipt_per_stage(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    digest = tree_hash(tmp_path)

    def fake(stage: str, outcome: str, obs: dict[str, Any]):  # noqa: ANN202
        def fn(_s: SealedArtifact) -> StageObservation:
            return StageObservation(stage, outcome, obs)
        return fn

    stage_fns = {
        "static": fake("static", "pass", _static_obs()),
        "own_tests": fake("own_tests", "pass",
                          {"sandbox_isolation_level": "hermetic", "image_digest": _TREE,
                           "container_exit_code": 0, "pytest_status": "passed",
                           "invocation_digest": "e" * 64}),
        "llm_review": fake("llm_review", "pass",
                           {"provider_id": "p", "model_id": "m", "review_prompt_hash": "d" * 64,
                            "source_digest": "a" * 64, "request_digest": "e" * 64,
                            "response_digest": "f" * 64, "verdict": "approve"}),
        "gate": fake("gate", "blocked", _gate_obs("blocking_refusal", digest)),
    }
    receipts = run_gauntlet(_cell(), tmp_path, stage_fns, s.signing_key)
    assert [r.payload["stage"] for r in receipts] == list(GAUNTLET_STAGES)
    assert all(r.run_id == _RUN_ID for r in receipts)
    assert {r.payload["artifact_tree_digest"] for r in receipts} == {digest}
    for r in receipts:
        validate_payload("cell_stage", r.payload)


# ---- static stage: in-sandbox, exit-code-only, env_digest assertion, invocation_digest ----

def test_static_clean_tree_passes(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("x: int = 1\n")
    with seal_artifact(tmp_path) as sealed:
        sb = FakeSandbox(results=[("completed", 0), ("completed", 0)], image_digest=_ENV)
        obs = static_stage(sealed, image="img", env_digest=_ENV, make_sandbox=lambda: sb)
    assert obs.outcome == "pass"
    assert obs.observation["env_digest"] == _ENV
    assert obs.observation["ruff_exit"] == 0 and obs.observation["mypy_exit"] == 0
    assert len(obs.observation["invocation_digest"]) == _HEX64
    assert set(obs.observation) == {"env_digest", "ruff_exit", "mypy_exit", "invocation_digest"}


def test_static_dirty_tree_fails(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("import os\n")
    with seal_artifact(tmp_path) as sealed:
        sb = FakeSandbox(results=[("completed", 1), ("completed", 0)], image_digest=_ENV)
        obs = static_stage(sealed, image="img", env_digest=_ENV, make_sandbox=lambda: sb)
    assert obs.observation["ruff_exit"] == 1
    assert obs.outcome == "fail"


def test_static_env_digest_mismatch_is_error(tmp_path: Path) -> None:
    # the sandbox ran a DIFFERENT image than the manifest pinned -> ERROR (never a 'fail' pass-off).
    s = generate_signer()
    (tmp_path / "m.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        sb = FakeSandbox(results=[("completed", 0), ("completed", 0)],
                         image_digest="sha256:" + "e" * 64)   # != _ENV
        r = run_stage(_cell(), sealed, sealed.digest, "static",
                      lambda sl: static_stage(sl, image="img", env_digest=_ENV,
                                              make_sandbox=lambda: sb), s.signing_key)
    assert r.payload["outcome"] == "error"
    assert "image drift" in r.payload["observation"]["harness_error"]


def test_static_timeout_is_error(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "m.py").write_text("x = 1\n")
    with seal_artifact(tmp_path) as sealed:
        sb = FakeSandbox(results=[("timeout", None), ("completed", 0)], image_digest=_ENV)
        r = run_stage(_cell(), sealed, sealed.digest, "static",
                      lambda sl: static_stage(sl, image="img", env_digest=_ENV,
                                              make_sandbox=lambda: sb), s.signing_key)
    assert r.payload["outcome"] == "error"


def test_invocation_digest_deterministic_and_argv_sensitive() -> None:
    a = (("ruff", "check", "/artifact"),)
    b = (("ruff", "check", "--select", "NOTHING", "/artifact"),)
    assert _invocation_digest(_ENV, a) == _invocation_digest(_ENV, a)   # deterministic
    assert _invocation_digest(_ENV, a) != _invocation_digest(_ENV, b)   # binds WHAT ran
    assert _invocation_digest(_ENV, a) != _invocation_digest(_OTHER_TREE, a)  # binds the image
