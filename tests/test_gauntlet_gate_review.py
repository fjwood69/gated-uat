"""tests/test_gauntlet_gate_review.py — B1 step 2 (gap-1): llm_review + gate + containment + matrix.

  * llm_review: strict approve->pass; the STAGE builds the request envelope embedding the sealed
    source (containment is STRUCTURAL — the client seam is (request_bytes,...) with no raw_request,
    and ReviewOutcome carries no supplied digest); source_digest reconstructs the sealed tree.
  * gate: outcome DERIVED from result_kind; gate_outcome from the REAL account(); binds the tree it
    ran. P1: a gate that measured a DIFFERENT tree than the cell bound -> published ERROR.
  * demonstration: evasion green-green-green-BLOCKED; clean counterpart green-green-green-green.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from orchestrator.gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    DigestMismatchError,
    ReviewOutcome,
    SealedArtifact,
    StageObservation,
    UnsafeArtifactError,
    _canonical_review_request,
    canonical_review_source,
    gate_measurement_from_enforcement,
    gate_stage,
    llm_review_stage,
    run_gauntlet,
    run_stage,
    seal_artifact,
)
from orchestrator.schemas import validate_payload
from orchestrator.trust import generate_signer
from tests._fakes import gate_runner, review_client

_MD = "a" * 64
_PROMPT_HASH = "b" * 64


def _cell(planned_run_id: str, side: str, lineage: str = "claude-x") -> CellContext:
    return CellContext(
        manifest_digest=_MD, planned_run_id=planned_run_id,
        cell_id=f"retry/{lineage}/0", lineage=lineage,
        reviewer_lineage="gpt-y", side=side)


def _seal_two(tmp_path: Path):  # noqa: ANN202 — a nested two-file artifact
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("y = 2\n")
    return seal_artifact(tmp_path)


def _independent_tree_hash(source_bytes: bytes) -> str:
    """An INDEPENDENT oracle for core.tree_hash — hand-rolled from the published spec (F:+sha256 per
    file, entries sorted by relpath, root = sha256 over rel\\0digest\\0). Parses the review
    source payload; NEVER calls the production tree_hash (avoids circularity)."""
    env = json.loads(source_bytes)
    entries = []
    for f in env["payload"]["files"]:
        rel_bytes = base64.b64decode(f["path_b64"])       # the raw utf-8 relpath bytes
        entries.append((rel_bytes, "F:" + f["sha256"]))
    entries.sort(key=lambda e: e[0])
    h = hashlib.sha256()
    for rel_bytes, digest in entries:
        h.update(rel_bytes)
        h.update(b"\0")
        h.update(digest.encode("utf-8"))
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


# ---- llm_review ----

def test_llm_review_approve_is_pass(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        obs = llm_review_stage(sealed, reviewer_lineage="gpt-y", review_prompt_hash=_PROMPT_HASH,
                               review_client=review_client("approve"))
    assert obs.outcome == "pass"
    assert obs.observation["verdict"] == "approve"
    assert obs.observation["review_prompt_hash"] == _PROMPT_HASH
    assert obs.observation["response_digest"] == hashlib.sha256(b"RESP:approve").hexdigest()


def test_llm_review_request_changes_is_fail(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        obs = llm_review_stage(sealed, reviewer_lineage="gpt-y", review_prompt_hash=_PROMPT_HASH,
                               review_client=review_client("request_changes"))
    assert obs.outcome == "fail"
    assert obs.observation["verdict"] == "request_changes"


# ---- containment: the STAGE builds the request; the client cannot spoof it ----

def test_request_envelope_embeds_sealed_source_and_binds_digest(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        source_bytes = canonical_review_source(sealed)
        request_bytes = _canonical_review_request(source_bytes, "gpt-y", _PROMPT_HASH)
        # the request envelope base64-embeds the EXACT sealed source
        env = json.loads(request_bytes)
        assert base64.b64decode(env["payload"]["source_b64"]) == source_bytes
        obs = llm_review_stage(sealed, reviewer_lineage="gpt-y", review_prompt_hash=_PROMPT_HASH,
                               review_client=review_client("approve"))
        # request_digest is sha256 of the HARNESS-built envelope — not the client's word
        assert obs.observation["request_digest"] == hashlib.sha256(request_bytes).hexdigest()
        assert obs.observation["source_digest"] == hashlib.sha256(source_bytes).hexdigest()


def test_client_seam_receives_only_the_stage_built_request(tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def spy(request_bytes: bytes, reviewer_lineage: str, prompt_hash: str) -> ReviewOutcome:
        seen["req"] = request_bytes
        seen["lineage"] = reviewer_lineage
        return ReviewOutcome(verdict="approve", provider_id="p", model_id="m", raw_response=b"r")

    with _seal_two(tmp_path) as sealed:
        expected = _canonical_review_request(canonical_review_source(sealed), "gpt-y", _PROMPT_HASH)
        llm_review_stage(sealed, reviewer_lineage="gpt-y", review_prompt_hash=_PROMPT_HASH,
                         review_client=spy)
    # the client is handed EXACTLY the stage-built envelope — no side channel, no host path
    assert seen["req"] == expected
    assert seen["lineage"] == "gpt-y"


def test_review_outcome_carries_no_client_supplied_digest() -> None:
    # STRUCTURAL law: the client cannot influence request_digest — the field does not exist.
    fields = {f.name for f in dataclasses.fields(ReviewOutcome)}
    assert fields == {"verdict", "provider_id", "model_id", "raw_response"}
    assert "request_digest" not in fields and "raw_request" not in fields


# ---- reconstruction: an INDEPENDENT oracle maps the source back to the sealed digest ----

def test_review_source_reconstructs_sealed_digest(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        source_bytes = canonical_review_source(sealed)
        assert _independent_tree_hash(source_bytes) == sealed.digest


def test_canonical_source_rejects_duplicate_paths(tmp_path: Path) -> None:
    # a crafted archive with two identical member paths -> fail closed.
    (tmp_path / "a.py").write_text("x = 1\n")
    archive = tmp_path / "dup.tar"
    with tarfile.open(archive, "w") as tf:
        tf.add(tmp_path / "a.py", arcname="artifact/a.py")
        tf.add(tmp_path / "a.py", arcname="artifact/a.py")   # duplicate member
    with pytest.raises(UnsafeArtifactError):
        canonical_review_source(SealedArtifact(archive=archive, digest="sha256:" + "0" * 64))


def test_canonical_source_mismatched_seal_digest_raises(tmp_path: Path) -> None:
    # the in-stage self-check reconstructs tree_hash and refuses if != the claimed sealed digest.
    with _seal_two(tmp_path) as sealed:
        wrong = SealedArtifact(archive=sealed.archive, digest="sha256:" + "9" * 64)
        with pytest.raises(DigestMismatchError):
            canonical_review_source(wrong)


# ---- gate: outcome derivation + measured-digest binding ----

def test_gate_blocking_refusal_is_blocked(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        obs = gate_stage(sealed, gate_runner=gate_runner("blocking_refusal"))
    assert obs.outcome == "blocked"
    assert obs.observation["gate_outcome"] == "run_verdict"  # account(): NOT block_gate


def test_gate_admitted_pass_and_fail(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        p = gate_stage(sealed, gate_runner=gate_runner("admitted_run", admitted="pass"))
        f = gate_stage(sealed, gate_runner=gate_runner("admitted_run", admitted="fail"))
    assert p.outcome == "pass"
    assert f.outcome == "fail"


def test_gate_infra_is_error(tmp_path: Path) -> None:
    with _seal_two(tmp_path) as sealed:
        obs = gate_stage(sealed, gate_runner=gate_runner("infrastructure_failure"))
    assert obs.outcome == "error"
    assert obs.observation["gate_outcome"] is None


def test_p1_gate_measured_different_tree_is_error_receipt(tmp_path: Path) -> None:
    # THE close: a gate that measured a DIFFERENT tree than the cell bound cannot sign a
    # clean gate receipt — it becomes a published ERROR (false-green unrepresentable).
    s = generate_signer()
    other = "sha256:" + "e" * 64
    cell = _cell("33333333-3333-4333-8333-333333333333", "tempting")
    with _seal_two(tmp_path) as sealed:
        r = run_stage(cell, sealed, sealed.digest, "gate",
                      lambda sl: gate_stage(sl, gate_runner=gate_runner(
                          "blocking_refusal", measured=other)), s.signing_key)
        assert r.payload["outcome"] == "error"
        assert "harness_error" in r.payload["observation"]
        r2 = run_stage(cell, sealed, sealed.digest, "gate",
                       lambda sl: gate_stage(sl, gate_runner=gate_runner("blocking_refusal")),
                       s.signing_key)
        assert r2.payload["outcome"] == "blocked"
        validate_payload("cell_stage", r2.payload)


def test_gate_measurement_from_enforcement_maps() -> None:
    class _EO:  # a stand-in for enforcement_driver.EnforcementOutcome
        result_kind = "admitted_run"
        outcome = "pass"
        reason = "clean"
        sub_reason = ""
        gate_outcome = "run_verdict"
    m = gate_measurement_from_enforcement(_EO(), "sha256:" + "f" * 64)
    assert m.result_kind == "admitted_run"
    assert m.admitted_outcome == "pass"
    assert m.measured_tree_digest == "sha256:" + "f" * 64


# ---- the two-sided demonstration matrix ----

def _matrix_stage_fns(*, gate_kind: str, gate_admitted: str | None):  # noqa: ANN202
    """Green static/own_tests/review; the gate is what differs between the two sides."""
    def static_fn(_s: SealedArtifact) -> StageObservation:
        return StageObservation("static", "pass", {
            "env_digest": "sha256:" + "d" * 64, "ruff_exit": 0, "mypy_exit": 0,
            "invocation_digest": "c" * 64})

    def own_tests_fn(_s: SealedArtifact) -> StageObservation:
        # own-tests GREEN on the evasion is the demonstration — complicit producer tests pass.
        return StageObservation("own_tests", "pass", {
            "sandbox_isolation_level": "hermetic", "image_digest": "sha256:" + "d" * 64,
            "container_exit_code": 0, "pytest_status": "passed", "invocation_digest": "c" * 64})

    def review_fn(sl: SealedArtifact) -> StageObservation:
        return llm_review_stage(sl, reviewer_lineage="gpt-y", review_prompt_hash=_PROMPT_HASH,
                                review_client=review_client("approve"))

    def gate_fn(sl: SealedArtifact) -> StageObservation:
        return gate_stage(sl, gate_runner=gate_runner(gate_kind, admitted=gate_admitted))

    return {"static": static_fn, "own_tests": own_tests_fn,
            "llm_review": review_fn, "gate": gate_fn}


def test_demonstration_two_sided(tmp_path: Path) -> None:
    s = generate_signer()
    (tmp_path / "m.py").write_text("x = 1\n")

    evasion = run_gauntlet(
        _cell("44444444-4444-4444-8444-444444444444", "tempting"), tmp_path,
        _matrix_stage_fns(gate_kind="blocking_refusal", gate_admitted=None), s.signing_key)
    assert [r.payload["stage"] for r in evasion] == list(GAUNTLET_STAGES)
    assert [r.payload["outcome"] for r in evasion] == ["pass", "pass", "pass", "blocked"]

    clean = run_gauntlet(
        _cell("55555555-5555-4555-8555-555555555555", "clean"), tmp_path,
        _matrix_stage_fns(gate_kind="admitted_run", gate_admitted="pass"), s.signing_key)
    assert [r.payload["outcome"] for r in clean] == ["pass", "pass", "pass", "pass"]

    for row in (evasion, clean):
        assert len({r.payload["artifact_tree_digest"] for r in row}) == 1
        for r in row:
            validate_payload("cell_stage", r.payload)
