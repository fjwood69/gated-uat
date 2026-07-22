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
import uuid
from datetime import datetime, timezone

import pytest

from orchestrator.manifest import (
    BOARD_MANIFEST_VERSION,
    DenominatorIncompleteError,
    ManifestVerificationError,
    assert_denominator_complete,
    assert_stage_denominator_complete,
    build_manifest,
    build_manifest_payload,
    plan_cells,
    planned_run_ids,
    verify_manifest,
)
from orchestrator.schemas import VALID_STAGES, SchemaViolationError, validate_payload
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


def _toolchain() -> dict:
    return {"python_version": "3.12.3", "ruff_version": "0.6.0", "mypy_version": "1.11.0",
            "env_digest": "sha256:" + "1" * 64}


def _payload(tasks=None, denom=None, cells=None, n: int = 2, toolchain=None) -> dict:
    tasks = tasks if tasks is not None else _tasks()
    denom = denom if denom is not None else _denom(n)
    cells = cells if cells is not None else plan_cells(
        [(t["task_id"], t["side"]) for t in tasks], _LINEAGES, n)
    return build_manifest_payload(
        gated_commit="1d75d54", code_sha="d" * 64, corpus_version="retry-v1",
        preregistered_at=_TS, tasks=tasks, denominator=denom, cells=cells,
        toolchain=toolchain if toolchain is not None else _toolchain())


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


# ---- dissent gap 4: the toolchain pin is REQUIRED in the signed manifest ----

def test_manifest_requires_toolchain() -> None:
    vp = _payload()
    del vp["toolchain"]
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)


def test_manifest_toolchain_env_digest_must_be_sha256() -> None:
    vp = _payload(toolchain={"python_version": "3.12", "ruff_version": "0.6",
                             "mypy_version": "1.11", "env_digest": "not-a-digest"})
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", vp)


# ---- dissent gap 5: the render gate is the CROSS-PRODUCT (planned_run_id x stage) ----

def test_stage_denominator_complete_bijection() -> None:
    vp = _payload()
    rids = sorted(planned_run_ids(vp))
    stages = sorted(VALID_STAGES)
    # exactly the 4 stages for every planned cell -> complete
    complete = [(rid, st) for rid in rids for st in stages]
    assert_stage_denominator_complete(vp, complete)  # no raise
    # drop one (run_id, stage) -> missing
    with pytest.raises(DenominatorIncompleteError):
        assert_stage_denominator_complete(vp, complete[:-1])
    # duplicate a (run_id, stage) -> duplicate
    with pytest.raises(DenominatorIncompleteError):
        assert_stage_denominator_complete(vp, complete + [complete[0]])
    # an unplanned run_id -> unplanned
    with pytest.raises(DenominatorIncompleteError):
        assert_stage_denominator_complete(
            vp, complete + [("00000000-0000-4000-8000-000000000000", "gate")])


def test_stage_denominator_rejects_four_identical_run_ids_naively() -> None:
    # the four stage receipts share the cell's run_id; the per-cell gate would (correctly) call it a
    # duplicate — the stage gate is the right one for cell_stage receipts.
    vp = _payload()
    rid = sorted(planned_run_ids(vp))[0]
    with pytest.raises(DenominatorIncompleteError):
        assert_denominator_complete(vp, [rid, rid, rid, rid])


# ---- B1-2: mint-time denominator completeness (task ⊆ cells + full task×lineage product) ----

def _bare_cell(task_id: str, lineage: str, side: str, reviewer: str, rep: int = 0) -> dict:
    return {"cell_id": f"{task_id}/{lineage}/{rep}", "task_id": task_id, "lineage": lineage,
            "side": side, "replicate": rep, "planned_run_id": str(uuid.uuid4()),
            "reviewer_lineage": reviewer}


def test_orphan_declared_task_rejected() -> None:
    # B1-2: a task DECLARED in tasks[] but given NO cells is unsignable — the board advertises a
    # task it never runs (the "100 hard / 10 trivial" cherry-pick). Enforced at mint, not render.
    tasks = _tasks()  # retry-swallow (tempting) + retry-clean (clean)
    only_first = plan_cells([(tasks[0]["task_id"], tasks[0]["side"])], _LINEAGES, 2)
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", _payload(tasks=tasks, cells=only_first))


def test_asymmetric_lineage_coverage_rejected() -> None:
    # B1-2: both tasks present, but task A only on lineage X and task B only on lineage Y — the
    # (task × lineage) product is incomplete ((A,Y),(B,X) missing). Unsignable.
    tasks = _tasks()
    cells = [_bare_cell(tasks[0]["task_id"], "claude-x", tasks[0]["side"], "gpt-y"),
             _bare_cell(tasks[1]["task_id"], "gpt-y", tasks[1]["side"], "claude-x")]
    with pytest.raises(SchemaViolationError):
        validate_payload("manifest", _payload(tasks=tasks, denom=_denom(1), cells=cells, n=1))
