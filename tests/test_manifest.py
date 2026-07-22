"""tests/test_manifest.py — B1 step 1: the anchored board manifest.

Proves the three ratified amendments are STRUCTURAL:
  * the manifest is signed + schema-validated at mint (before any agent runs);
  * the COMPLETE ORDERED DENOMINATOR is committed and the render gate refuses any
    omission / duplicate / unplanned cell (cherry-picking unrepresentable);
  * no silent reruns (retry_policy='none', infra_failure_disposition='error_and_publish');
  * reviewer independence holds for every cell and is checkable from the signed manifest alone.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from orchestrator.manifest import (
    BOARD_MANIFEST_VERSION,
    DenominatorIncompleteError,
    ManifestVerificationError,
    assert_denominator_complete,
    build_manifest,
    build_manifest_payload,
    plan_cells,
    planned_run_ids,
    verify_manifest,
)
from orchestrator.schemas import SchemaViolationError, validate_payload
from orchestrator.trust import generate_signer

_TS = datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
_LINEAGES = ["claude-x", "gpt-y", "gemini-z"]


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


def _denom(n: int = 2) -> dict:
    return {"n_replicates": n, "seed": 42, "temperature": "0.0", "params": {},
            "retry_policy": "none", "infra_failure_disposition": "error_and_publish"}


def _payload(tasks=None, denom=None, cells=None, n: int = 2) -> dict:
    tasks = tasks if tasks is not None else _tasks()
    denom = denom if denom is not None else _denom(n)
    cells = cells if cells is not None else plan_cells(
        [(t["task_id"], t["side"]) for t in tasks], _LINEAGES, n)
    return build_manifest_payload(
        gated_commit="1d75d54", code_sha="d" * 64, corpus_version="retry-v1",
        preregistered_at=_TS, tasks=tasks, denominator=denom, cells=cells)


# ---- planning -------------------------------------------------------

def test_plan_cells_complete_enumeration() -> None:
    tasks = _tasks()
    cells = plan_cells([(t["task_id"], t["side"]) for t in tasks], _LINEAGES, 2)
    assert len(cells) == len(tasks) * len(_LINEAGES) * 2
    # every cell reviewer differs from producer (checkable from the manifest alone)
    assert all(c["reviewer_lineage"] != c["lineage"] for c in cells)
    # planned_run_ids are unique; cell_ids are the deterministic slugs
    assert len({c["planned_run_id"] for c in cells}) == len(cells)
    assert {c["cell_id"] for c in cells} == {
        f"{t['task_id']}/{lin}/{r}" for t in tasks for lin in _LINEAGES for r in (0, 1)}


def test_plan_cells_requires_two_lineages() -> None:
    with pytest.raises(ValueError):
        plan_cells([("t", "tempting")], ["only-one"], 1)


# ---- sign + verify (the anchor) -------------------------------------

def test_manifest_signs_verifies_and_schema_validates() -> None:
    s = generate_signer()
    receipt = build_manifest(_payload(), s.signing_key)
    assert receipt.kind == "manifest"
    vp = verify_manifest(receipt, s.verify_key)
    assert vp["manifest_version"] == BOARD_MANIFEST_VERSION
    validate_payload("manifest", vp)  # standalone schema check


def test_manifest_tamper_fails_verification() -> None:
    s = generate_signer()
    receipt = build_manifest(_payload(), s.signing_key)
    bad = copy.deepcopy(receipt.payload)
    bad["gated_commit"] = "deadbeef"  # mutate a signed field
    tampered = type(receipt)(kind=receipt.kind, run_id=receipt.run_id, payload=bad,
                             digest=receipt.digest, signature=receipt.signature)
    with pytest.raises(ManifestVerificationError):
        verify_manifest(tampered, s.verify_key)


# ---- the render gate: complete ordered denominator ------------------

def test_render_gate_accepts_complete_denominator() -> None:
    vp = _payload()
    assert_denominator_complete(vp, sorted(planned_run_ids(vp)))  # no raise


def test_render_gate_refuses_missing_duplicate_unplanned() -> None:
    vp = _payload()
    planned = sorted(planned_run_ids(vp))
    with pytest.raises(DenominatorIncompleteError):  # missing
        assert_denominator_complete(vp, planned[:-1])
    with pytest.raises(DenominatorIncompleteError):  # duplicate
        assert_denominator_complete(vp, planned + [planned[0]])
    with pytest.raises(DenominatorIncompleteError):  # unplanned
        assert_denominator_complete(vp, planned + ["00000000-0000-4000-8000-000000000000"])


# ---- schema integrity: the amendment guarantees are validation laws -

def test_no_silent_reruns_enforced_at_mint() -> None:
    s = generate_signer()
    with pytest.raises(SchemaViolationError):
        build_manifest(_payload(denom=dict(_denom(), retry_policy="on_error")), s.signing_key)
    with pytest.raises(SchemaViolationError):
        build_manifest(
            _payload(denom=dict(_denom(), infra_failure_disposition="drop")), s.signing_key)


def test_reviewer_equals_producer_rejected() -> None:
    vp = _payload()
    vp["cells"][0]["reviewer_lineage"] = vp["cells"][0]["lineage"]  # break independence
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)


def test_incomplete_denominator_rejected_at_schema() -> None:
    # drop one replicate from one (task, lineage) group -> the enumeration is no longer complete
    vp = _payload(n=2)
    vp["cells"] = [c for c in vp["cells"]
                   if not (c["task_id"] == "retry-swallow" and c["lineage"] == "claude-x"
                           and c["replicate"] == 1)]
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)


def test_duplicate_planned_run_id_rejected() -> None:
    vp = _payload()
    vp["cells"][1]["planned_run_id"] = vp["cells"][0]["planned_run_id"]
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)


def test_cell_referencing_undeclared_task_rejected() -> None:
    vp = _payload()
    vp["cells"][0]["task_id"] = "no-such-task"
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)


def test_cell_side_must_match_task_side() -> None:
    vp = _payload()
    # retry-swallow is a 'tempting' task; a cell claiming 'clean' is incoherent
    for c in vp["cells"]:
        if c["task_id"] == "retry-swallow":
            c["side"] = "clean"
            break
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)
