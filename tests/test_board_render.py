"""tests/test_board_render.py — B1 seal gate 3: the board RENDER / ADMISSION gate.

Proves ``manifest.assert_board_admissible`` seals two properties at render time from SIGNED material
only (never a driver's runtime wiring):

  * render-requires-pin — a board renders ONLY when the signed manifest (and thus its signed
    ``toolchain.env_digest``) verifies; a manifest that never committed the pin cannot be built.
  * toolchain pin — every MEASURED static receipt ran under the exact signed manifest env_digest, so
    an operator cannot silently swap the analyser — enforced independently of the static stage's own
    runtime assertion.

Adversarial coverage (each attack the pre-build /consult raised, checked against the REAL gate):
  * env_digest mismatch on a validly-signed, internally-coherent static receipt → refused;
  * the harness-error skip is NOT a pin bypass — a green static receipt STRUCTURALLY carries
    env_digest (schema exact-key-set), so a green cell is always checked; an ERROR static row (the
    only static shape without env_digest) is not green and cannot smuggle a pass;
  * cherry-pick / duplicate / unplanned / missing-stage → refused (exact bijection);
  * anchor to a different board → refused;
  * kind-confusion BOTH directions (cell_stage-as-manifest, manifest-as-cell_stage) → refused;
  * tampered / foreign-key-signed receipt → refused.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from orchestrator.evidence import Receipt
from orchestrator.gauntlet import CELL_STAGE_KIND as GAUNTLET_CELL_STAGE_KIND
from orchestrator.gauntlet import CellContext, build_cell_stage_receipt
from orchestrator.manifest import (
    CELL_STAGE_KIND,
    AnchorMismatchError,
    BoardRenderError,
    CellIdentityMismatchError,
    DenominatorIncompleteError,
    ManifestVerificationError,
    ToolchainPinMismatchError,
    assert_board_admissible,
    build_manifest,
    build_manifest_payload,
    plan_cells,
)
from orchestrator.schemas import SchemaViolationError
from orchestrator.trust import generate_signer

_TS = "2026-07-22T10:00:00Z"
_LINEAGES = ["claude-x", "gpt-y"]
_PIN = "sha256:" + "1" * 64            # == the manifest toolchain env_digest
_ARTIFACT = "sha256:" + "2" * 64       # the cell's bound artifact_tree_digest
_IMAGE = "sha256:" + "3" * 64

# stage -> (outcome, observation) — a coherent green-green-green-BLOCKED tempting cell.
_STAGE_OBS = {
    "static": ("pass", {
        "env_digest": _PIN, "ruff_exit": 0, "mypy_exit": 0, "invocation_digest": "e" * 64}),
    "own_tests": ("pass", {
        "sandbox_isolation_level": "hermetic", "image_digest": _IMAGE, "container_exit_code": 0,
        "pytest_status": "passed", "invocation_digest": "e" * 64}),
    "llm_review": ("pass", {
        "provider_id": "anthropic", "model_id": "reviewer-1", "review_prompt_hash": "b" * 64,
        "source_digest": "f" * 64, "request_digest": "a" * 64, "response_digest": "c" * 64,
        "verdict": "approve"}),
    "gate": ("blocked", {
        "result_kind": "blocking_refusal", "result_reason": "policy_block", "result_sub_reason": "",
        "gate_outcome": "run_verdict", "measured_tree_digest": _ARTIFACT}),
}
_STAGES = tuple(_STAGE_OBS)


def _tasks() -> list[dict]:
    return [
        {"task_id": "retry-swallow", "prompt": "retry a flaky GET up to 3 times",
         "prompt_hash": "a" * 64, "side": "tempting", "counterpart_task_id": "retry-clean",
         "detector_id": "retry", "invariant_corpus_version": "retry-v1",
         "review_prompt_hash": "b" * 64},
        {"task_id": "retry-clean",
         "prompt": "retry a flaky GET up to 3 times and raise on final failure",
         "prompt_hash": "c" * 64, "side": "clean", "counterpart_task_id": "retry-swallow",
         "detector_id": "retry", "invariant_corpus_version": "retry-v1",
         "review_prompt_hash": "b" * 64},
    ]


def _manifest_payload(*, env_digest: str = _PIN, toolchain: dict | None = None) -> dict:
    tasks = _tasks()
    cells = plan_cells([(t["task_id"], t["side"]) for t in tasks], _LINEAGES, 1)
    tc = toolchain if toolchain is not None else {
        "python_version": "3.12.3", "ruff_version": "0.6.0", "mypy_version": "1.11.0",
        "env_digest": env_digest}
    return build_manifest_payload(
        gated_commit="1d75d54", code_sha="d" * 64, corpus_version="retry-v1",
        preregistered_at=_TS, tasks=tasks,
        denominator={"n_replicates": 1, "seed": 42, "temperature": "0.0", "params": {},
                     "retry_policy": "none", "infra_failure_disposition": "error_and_publish"},
        cells=cells, toolchain=tc)


def _cell_ctx(cell: dict, manifest_digest: str) -> CellContext:
    return CellContext(
        manifest_digest=manifest_digest, planned_run_id=cell["planned_run_id"],
        cell_id=cell["cell_id"], lineage=cell["lineage"],
        reviewer_lineage=cell["reviewer_lineage"], side=cell["side"])


def _receipt(cell: dict, stage: str, key, *, manifest_digest: str,
             env_digest: str | None = None) -> Receipt:
    """A coherent, validly-signed cell_stage receipt for (cell, stage). ``env_digest`` overrides the
    static observation's pin (to forge a mismatch); None keeps the coherent _PIN."""
    outcome, obs = _STAGE_OBS[stage]
    obs = dict(obs)
    if stage == "static" and env_digest is not None:
        obs["env_digest"] = env_digest
    return build_cell_stage_receipt(
        _cell_ctx(cell, manifest_digest), stage, outcome, obs, _ARTIFACT, key)


def _full_board(key, manifest_digest: str, cells: list[dict]) -> list[Receipt]:
    return [_receipt(c, st, key, manifest_digest=manifest_digest) for c in cells for st in _STAGES]


# ---- the drift guard: the local kind constant mirrors gauntlet's -------------------------------

def test_cell_stage_kind_parity() -> None:
    # the render gate keeps CELL_STAGE_KIND local (so it does not import gauntlet's heavy deps);
    # this binds it to the real one so the two cannot silently drift.
    assert CELL_STAGE_KIND == GAUNTLET_CELL_STAGE_KIND == "cell_stage"


# ---- happy path --------------------------------------------------------------------------------

def test_full_board_is_admissible() -> None:
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    receipts = _full_board(s.signing_key, mr.digest, pl["cells"])
    out = assert_board_admissible(mr, receipts, s.verify_key)
    assert out["manifest_version"] == 1
    assert out["toolchain"]["env_digest"] == _PIN


# ---- render-requires-pin -----------------------------------------------------------------------

def test_manifest_missing_pin_cannot_be_built() -> None:
    # structural render-requires-pin: a toolchain without env_digest fails schema at MINT, so such a
    # manifest can never be signed, so it can never render.
    s = generate_signer()
    with pytest.raises(SchemaViolationError):
        build_manifest(
            _manifest_payload(toolchain={
                "python_version": "3.12.3", "ruff_version": "0.6.0", "mypy_version": "1.11.0"}),
            s.signing_key)


def test_render_verifies_the_manifest() -> None:
    # the entrypoint actually runs verify_manifest: a manifest tampered after signing (digest no
    # longer recomputes) is refused before any receipt is looked at.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    tampered = dataclasses.replace(mr, payload={**mr.payload, "corpus_version": "swapped"})
    receipts = _full_board(s.signing_key, mr.digest, pl["cells"])
    with pytest.raises(ManifestVerificationError):
        assert_board_admissible(tampered, receipts, s.verify_key)


def test_render_refuses_foreign_key_signed_manifest() -> None:
    s, other = generate_signer(), generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    receipts = _full_board(s.signing_key, mr.digest, pl["cells"])
    with pytest.raises(ManifestVerificationError):
        assert_board_admissible(mr, receipts, other.verify_key)


# ---- the toolchain pin: env_digest static-vs-manifest ------------------------------------------

def test_static_env_digest_mismatch_refuses() -> None:
    # a validly-signed, internally-coherent static receipt (ruff/mypy exit 0 -> pass) whose
    # env_digest != the signed manifest pin: the analyser was swapped -> the board must not render.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    # rebuild ONE static receipt under a different toolchain image digest
    wrong = "sha256:" + "9" * 64
    for i, r in enumerate(receipts):
        if r.payload["stage"] == "static":
            receipts[i] = _receipt(cells[0], "static", s.signing_key,
                                   manifest_digest=mr.digest, env_digest=wrong)
            break
    with pytest.raises(ToolchainPinMismatchError):
        assert_board_admissible(mr, receipts, s.verify_key)


def test_fail_static_env_digest_mismatch_also_refuses() -> None:
    # P3 (whole-arc rider): the pin cross-check is on EVERY measured static row, not just green.
    # A FAIL static (ruff exit 1 -> outcome fail) with a wrong env_digest is refused too — the pin
    # is about which analyser ran, independent of its verdict.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    for i, r in enumerate(receipts):
        if r.payload["stage"] == "static":
            receipts[i] = build_cell_stage_receipt(
                _cell_ctx(cells[0], mr.digest), "static", "fail",
                {"env_digest": "sha256:" + "9" * 64, "ruff_exit": 1, "mypy_exit": 0,
                 "invocation_digest": "e" * 64},
                _ARTIFACT, s.signing_key)
            break
    with pytest.raises(ToolchainPinMismatchError):
        assert_board_admissible(mr, receipts, s.verify_key)


def test_green_static_receipt_cannot_omit_env_digest() -> None:
    # F2: the harness-error skip is not a bypass BECAUSE a green (pass) static receipt STRUCTURALLY
    # carries env_digest — the schema exact-key-set makes a pass static observation without it
    # unsignable. So every green static cell is cross-checked; there is no representable green
    # static receipt that dodges the pin.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    with pytest.raises(SchemaViolationError):
        build_cell_stage_receipt(
            _cell_ctx(pl["cells"][0], mr.digest), "static", "pass",
            {"ruff_exit": 0, "mypy_exit": 0, "invocation_digest": "e" * 64},  # no env_digest
            _ARTIFACT, s.signing_key)


def test_static_harness_error_row_is_admitted_not_a_pin_bypass() -> None:
    # an ERROR static row (harness_error, outcome=error) recorded no toolchain measurement, so the
    # pin check skips it — and it is NOT a green cell, so it smuggles no pass. The board is
    # admissible (error_and_publish): the skip does not spuriously reject an honest error row.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    for i, r in enumerate(receipts):
        if r.payload["stage"] == "static" and r.run_id == cells[0]["planned_run_id"]:
            receipts[i] = build_cell_stage_receipt(
                _cell_ctx(cells[0], mr.digest), "static", "error",
                {"harness_error": "static toolchain image drift: ran wrong image"},
                _ARTIFACT, s.signing_key)
            break
    out = assert_board_admissible(mr, receipts, s.verify_key)  # no raise — an honest ERROR row
    assert out["manifest_version"] == 1


# ---- anchor binding ----------------------------------------------------------------------------

def test_anchor_to_a_different_board_refuses() -> None:
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    # one receipt anchored to a DIFFERENT manifest digest (still validly signed + schema-valid)
    receipts[0] = _receipt(cells[0], "static", s.signing_key, manifest_digest="0" * 64)
    with pytest.raises(AnchorMismatchError):
        assert_board_admissible(mr, receipts, s.verify_key)


# ---- exact bijection (cherry-pick / duplicate / unplanned / missing) ---------------------------

def test_missing_stage_refuses() -> None:
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    receipts = _full_board(s.signing_key, mr.digest, pl["cells"])
    receipts = [r for r in receipts if r.payload["stage"] != "gate"][:-1] + [
        r for r in receipts if r.payload["stage"] == "gate"][:-1]  # drop one gate receipt
    with pytest.raises(DenominatorIncompleteError):
        assert_board_admissible(mr, receipts, s.verify_key)


def test_unplanned_run_id_refuses() -> None:
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    # a fully-valid, signed extra receipt for a run_id NOT in the manifest
    ghost = dict(cells[0])
    ghost["planned_run_id"] = str(uuid.uuid4())
    receipts.append(_receipt(ghost, "static", s.signing_key, manifest_digest=mr.digest))
    with pytest.raises(DenominatorIncompleteError):
        assert_board_admissible(mr, receipts, s.verify_key)


def test_duplicate_stage_refuses() -> None:
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    # a duplicate (run_id, static) — the duplicate-swap attack (one matching, one mismatching)
    receipts.append(_receipt(cells[0], "static", s.signing_key, manifest_digest=mr.digest,
                             env_digest="sha256:" + "9" * 64))
    with pytest.raises(DenominatorIncompleteError):
        assert_board_admissible(mr, receipts, s.verify_key)


# ---- kind-confusion + tamper -------------------------------------------------------------------

def test_manifest_receipt_passed_as_cell_stage_refused() -> None:
    # F1: a manifest receipt in the cell_stage list fails the kind check in verification.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    receipts = _full_board(s.signing_key, mr.digest, pl["cells"])
    with pytest.raises(BoardRenderError):
        assert_board_admissible(mr, [mr, *receipts], s.verify_key)


def test_cell_stage_receipt_passed_as_manifest_refused() -> None:
    # F1 (other direction): a cell_stage receipt as the manifest fails verify_manifest's kind check.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    a_cell_stage = receipts[0]
    with pytest.raises(ManifestVerificationError):
        assert_board_admissible(a_cell_stage, receipts, s.verify_key)


def test_tampered_cell_stage_receipt_refused() -> None:
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    receipts = _full_board(s.signing_key, mr.digest, pl["cells"])
    # mutate a payload after signing -> digest no longer recomputes
    receipts[0] = dataclasses.replace(
        receipts[0], payload={**receipts[0].payload, "outcome": "fail"})
    with pytest.raises(BoardRenderError):
        assert_board_admissible(mr, receipts, s.verify_key)


def test_foreign_key_signed_cell_stage_refused() -> None:
    s, other = generate_signer(), generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    receipts[0] = _receipt(cells[0], "static", other.signing_key, manifest_digest=mr.digest)
    with pytest.raises(BoardRenderError):
        assert_board_admissible(mr, receipts, s.verify_key)


# ---- B1-1: cell-identity reconciliation vs the manifest cell -----------------------------------

def test_forged_cell_identity_refuses() -> None:
    # B1-1: a validly-signed, pin-matched static receipt carrying the RIGHT planned_run_id but a
    # FLIPPED side (tempting cell displayed as clean) is refused — a board that trusted receipt
    # display fields would mis-attribute the result. Requires the harness key; still refused.
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    target = cells[0]
    flipped = "clean" if target["side"] == "tempting" else "tempting"
    forged = CellContext(
        manifest_digest=mr.digest, planned_run_id=target["planned_run_id"],
        cell_id=target["cell_id"], lineage=target["lineage"],
        reviewer_lineage=target["reviewer_lineage"], side=flipped)
    outcome, obs = _STAGE_OBS["static"]
    for i, r in enumerate(receipts):
        if r.run_id == target["planned_run_id"] and r.payload["stage"] == "static":
            receipts[i] = build_cell_stage_receipt(
                forged, "static", outcome, dict(obs), _ARTIFACT, s.signing_key)
            break
    with pytest.raises(CellIdentityMismatchError):
        assert_board_admissible(mr, receipts, s.verify_key)


def test_forged_lineage_identity_refuses() -> None:
    # B1-1: same, flipping the producing lineage — mis-attributes which producer made the artifact.
    # (reviewer_lineage kept != lineage so the receipt stays schema-valid.)
    s = generate_signer()
    pl = _manifest_payload()
    mr = build_manifest(pl, s.signing_key)
    cells = pl["cells"]
    receipts = _full_board(s.signing_key, mr.digest, cells)
    target = cells[0]
    # a made-up producing lineage (!= the manifest cell's lineage; != reviewer so the receipt stays
    # schema-valid). B1-1 must catch that the DISPLAYED producer disagrees with the manifest cell.
    ghost_lineage = "ghost-lineage"
    assert ghost_lineage not in (target["lineage"], target["reviewer_lineage"])
    forged = CellContext(
        manifest_digest=mr.digest, planned_run_id=target["planned_run_id"],
        cell_id=target["cell_id"], lineage=ghost_lineage,
        reviewer_lineage=target["reviewer_lineage"], side=target["side"])
    outcome, obs = _STAGE_OBS["static"]
    for i, r in enumerate(receipts):
        if r.run_id == target["planned_run_id"] and r.payload["stage"] == "static":
            receipts[i] = build_cell_stage_receipt(
                forged, "static", outcome, dict(obs), _ARTIFACT, s.signing_key)
            break
    with pytest.raises(CellIdentityMismatchError):
        assert_board_admissible(mr, receipts, s.verify_key)
