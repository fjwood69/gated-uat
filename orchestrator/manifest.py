"""orchestrator/manifest.py — the anchored BOARD MANIFEST (B1 step 1).

The demonstration board is a gate whose artifact is the experiment: the manifest is the signed
EXPECTATION (a ``prereg`` one layer up), the per-cell stage receipts are the signed OBSERVATIONS,
and a rendered board is admissible iff every planned cell has exactly one terminal receipt.

Three ratified amendments are STRUCTURAL here:

  1. Manifest-anchoring over timestamps — the COMPLETE manifest is signed (Ed25519, via the same
     ``build_receipt`` machinery, domain-separated ``manifest`` kind) BEFORE any agent/API call. Its
     digest (``manifest_digest``) is the anchor every downstream cell-stage receipt references
     (enforced in step 2). ``preregistered_at`` is descriptive only — ORDER is proven by the
     hash-anchor + the empty receipt store at manifest time, not a bare timestamp.

  2. Complete ordered denominator — ``cells`` commits the EXACT ORDERED set of planned cells (each a
     unique ``planned_run_id``), not merely N. ``assert_denominator_complete`` is the RENDER GATE: a
     board renders iff the terminal receipts are a BIJECTION with the planned run_ids — no omission,
     no duplicate, no unplanned cell. Cherry-picking is unrepresentable, not merely forbidden; and
     (schema) ``retry_policy='none'`` + ``infra_failure_disposition='error_and_publish'`` mean a
     failed run is an ERROR row, never a silent rerun (the UNATTESTABLE reflex).

  3. (enforced in step 2) one immutable artifact per row, digest-mounted read-only, verified
     before+after each stage; a digest mismatch is a published ERROR, never a rerun.

Reviewer independence (§4.1) is committed here and checkable from the signed manifest alone: a
deterministic cyclic rotation assigns each cell a ``reviewer_lineage`` that differs from its
producing ``lineage`` (requires >= 2 lineages), and the schema validator rejects any cell where they
are equal.
"""

from __future__ import annotations

import uuid
from typing import Any

from core.chain import canonical_digest
from nacl.signing import SigningKey, VerifyKey

from .evidence import (
    CANONICAL_DIGEST_VERSION,
    DOMAIN_PREFIX,
    Receipt,
    build_receipt,
    canonical_envelope,
)
from .schemas import VALID_STAGES, SchemaViolationError, validate_payload
from .trust import BadSignatureError, verify_receipt_sig

MANIFEST_KIND = "manifest"
BOARD_MANIFEST_VERSION = 1


class DenominatorIncompleteError(ValueError):
    """The set of terminal receipts is not a bijection with the manifest's planned cells — a board
    with an incomplete/duplicated/unplanned denominator MUST NOT render (amendment 2)."""


class ManifestVerificationError(ValueError):
    """The manifest receipt failed signature, digest, or schema verification (fail-closed)."""


# ------------------------------------------------------------------
# Planning — the deterministic, COMPLETE cell enumeration (the denominator)
# ------------------------------------------------------------------


def plan_cells(
    task_sides: list[tuple[str, str]],
    lineages: list[str],
    n_replicates: int,
) -> list[dict[str, Any]]:
    """Enumerate the COMPLETE ordered set of planned cells: every (task, lineage, replicate).

    ``task_sides`` is the ordered ``(task_id, side)`` list; ``lineages`` the ordered producing
    lineages (>= 2, so a cross-lineage reviewer always exists). Reviewer assignment is
    a deterministic cyclic rotation (``lineages[(i+1) % len]``) — signed into every cell,
    guaranteed to differ from the producer. ``planned_run_id`` is a fresh UUID4 per
    cell; ``cell_id`` is the ``task/lineage/replicate`` slug. Order: task, lineage, rep.
    """
    if len(lineages) < 2:
        raise ValueError("plan_cells requires >= 2 lineages (cross-lineage review has no assignee "
                         "with a single lineage)")
    if len(set(lineages)) != len(lineages):
        raise ValueError(f"lineages must be distinct, got {lineages!r}")
    if n_replicates < 1:
        raise ValueError("n_replicates must be >= 1")
    cells: list[dict[str, Any]] = []
    for task_id, side in task_sides:
        for li, lineage in enumerate(lineages):
            reviewer = lineages[(li + 1) % len(lineages)]
            for rep in range(n_replicates):
                cells.append({
                    "cell_id": f"{task_id}/{lineage}/{rep}",
                    "task_id": task_id,
                    "lineage": lineage,
                    "side": side,
                    "replicate": rep,
                    "planned_run_id": str(uuid.uuid4()),
                    "reviewer_lineage": reviewer,
                })
    return cells


def build_manifest_payload(
    *,
    gated_commit: str,
    code_sha: str,
    corpus_version: str,
    preregistered_at: str,
    tasks: list[dict[str, Any]],
    denominator: dict[str, Any],
    cells: list[dict[str, Any]],
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the board-manifest payload dict (validated by schemas.validate_manifest_payload at
    build time). Kept schema-shaped (a plain dict) to reuse the receipt machinery verbatim.
    ``toolchain`` is the SIGNED static-toolchain pin (dissent gap 4) — required, never defaulted."""
    return {
        "schema_version": 1,
        "manifest_version": BOARD_MANIFEST_VERSION,
        "gated_commit": gated_commit,
        "code_sha": code_sha,
        "corpus_version": corpus_version,
        "preregistered_at": preregistered_at,
        "tasks": tasks,
        "denominator": denominator,
        "cells": cells,
        "toolchain": toolchain,
    }


# ------------------------------------------------------------------
# Building + verifying the signed manifest (the anchor)
# ------------------------------------------------------------------


def build_manifest(payload: dict[str, Any], signing_key: SigningKey) -> Receipt:
    """Sign the board manifest. The receipt's ``run_id`` is a fresh UUID4 board id; its ``digest``
    (``receipt.digest``) is the anchor every downstream cell receipt binds to. build_receipt
    validates the payload (schema) + signs — so a malformed / incomplete-denominator manifest is
    rejected at mint time, before any agent runs."""
    board_id = str(uuid.uuid4())
    return build_receipt(MANIFEST_KIND, board_id, payload, signing_key)


def verify_manifest(receipt: Receipt, verify_key: VerifyKey) -> dict[str, Any]:
    """Verify the manifest receipt standalone (it is not part of the per-run 4-link chain): kind,
    digest recompute, signature, schema. Returns the payload. Fail-closed."""
    if receipt.kind != MANIFEST_KIND:
        raise ManifestVerificationError(
            f"expected a {MANIFEST_KIND!r} receipt, got {receipt.kind!r}")
    domain = f"{DOMAIN_PREFIX}-{receipt.kind}"
    try:
        expected = canonical_digest(
            domain,
            canonical_envelope(receipt.kind, receipt.run_id, receipt.payload),
            version=CANONICAL_DIGEST_VERSION,
        )
    except Exception as exc:  # noqa: BLE001 — any digest error is a fail-closed verification error
        raise ManifestVerificationError("error recomputing manifest digest") from exc
    if receipt.digest != expected:
        raise ManifestVerificationError(
            f"manifest digest mismatch: stored={receipt.digest!r} recomputed={expected!r}")
    try:
        verify_receipt_sig(receipt.kind, receipt.digest, receipt.signature, verify_key)
    except BadSignatureError as exc:
        raise ManifestVerificationError("manifest signature invalid") from exc
    try:
        validate_payload(receipt.kind, receipt.payload)
    except SchemaViolationError as exc:
        raise ManifestVerificationError(f"manifest schema violation: {exc}") from exc
    return receipt.payload


# ------------------------------------------------------------------
# The render gate — amendment 2 made a render-time invariant
# ------------------------------------------------------------------


def planned_run_ids(manifest_payload: dict[str, Any]) -> set[str]:
    """The complete set of planned cell run_ids committed by the manifest — the denominator."""
    return {str(c["planned_run_id"]) for c in manifest_payload["cells"]}


def assert_denominator_complete(
    manifest_payload: dict[str, Any],
    terminal_run_ids: list[str],
) -> None:
    """RENDER GATE (amendment 2): a board may render ONLY when its terminal receipts are a BIJECTION
    with the manifest's planned cells. Raises ``DenominatorIncompleteError`` on any omission,
    duplicate, or unplanned run_id. Because ``retry_policy='none'`` and
    ``infra_failure_disposition='error_and_publish'`` are committed in the manifest, "one terminal
    receipt per planned cell" already includes ERROR rows — so a cherry-picked board (a dropped
    failed run, an unplanned favourable run) cannot pass this gate, so cannot render.
    """
    planned = planned_run_ids(manifest_payload)
    terminals: list[str] = [str(r) for r in terminal_run_ids]
    seen: set[str] = set()
    duplicates: set[str] = set()
    for r in terminals:
        if r in seen:
            duplicates.add(r)
        seen.add(r)
    missing = planned - seen
    unplanned = seen - planned
    if missing or unplanned or duplicates:
        parts = []
        if missing:
            parts.append(f"missing (no terminal receipt): {sorted(missing)}")
        if unplanned:
            parts.append(f"unplanned (not in the manifest): {sorted(unplanned)}")
        if duplicates:
            parts.append(f"duplicate terminal receipts: {sorted(duplicates)}")
        raise DenominatorIncompleteError(
            "board denominator is not complete — refusing to render. " + "; ".join(parts))


def assert_stage_denominator_complete(
    manifest_payload: dict[str, Any],
    terminal_stage_receipts: list[tuple[str, str]],
) -> None:
    """RENDER GATE for the step-2 cell_stage model (dissent gap 5). Each cell emits ONE receipt PER
    STAGE that shares the cell's ``planned_run_id``, so the denominator is the CROSS-PRODUCT
    (planned_run_id x gauntlet stage), NOT one receipt per run_id. A board renders ONLY when, for
    EVERY planned cell, EXACTLY the full set of stages is present — no missing stage, no duplicate
    (run_id, stage), no unplanned run_id, no unknown stage. ``terminal_stage_receipts`` is the list
    of ``(run_id, stage)`` pairs of the terminal cell_stage receipts. Passing four identical run_ids
    to the per-cell ``assert_denominator_complete`` would (correctly) look like duplicates; THIS is
    the gate for cell_stage receipts."""
    planned = planned_run_ids(manifest_payload)
    stages = frozenset(VALID_STAGES)
    seen: dict[str, set[str]] = {}
    duplicates: set[tuple[str, str]] = set()
    unplanned: set[tuple[str, str]] = set()
    unknown_stage: set[tuple[str, str]] = set()
    for rid_raw, stage_raw in terminal_stage_receipts:
        rid, stage = str(rid_raw), str(stage_raw)
        if stage not in stages:
            unknown_stage.add((rid, stage))
            continue
        if rid not in planned:
            unplanned.add((rid, stage))
            continue
        cell_stages = seen.setdefault(rid, set())
        if stage in cell_stages:
            duplicates.add((rid, stage))
        cell_stages.add(stage)
    missing = {(rid, st) for rid in planned for st in stages if st not in seen.get(rid, set())}
    if missing or unplanned or duplicates or unknown_stage:
        parts = []
        if missing:
            parts.append(f"missing (run_id,stage): {sorted(missing)}")
        if unplanned:
            parts.append(f"unplanned run_id: {sorted(unplanned)}")
        if duplicates:
            parts.append(f"duplicate (run_id,stage): {sorted(duplicates)}")
        if unknown_stage:
            parts.append(f"unknown stage: {sorted(unknown_stage)}")
        raise DenominatorIncompleteError(
            "stage denominator is not complete — refusing to render. " + "; ".join(parts))
