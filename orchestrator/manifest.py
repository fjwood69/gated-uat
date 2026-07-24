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


def build_manifest(
    payload: dict[str, Any], signing_key: SigningKey, *, board_id: str | None = None,
) -> Receipt:
    """Sign the board manifest. The receipt's ``run_id`` is the board id — a fresh UUID4 by default,
    or the caller-pre-minted ``board_id`` (so a LIVE board can PUBLISH its board_id in the pre-run
    commitment before any live call; a cherry-picked re-run then carries a different board_id). Its
    ``digest`` is the anchor every cell receipt binds to. build_receipt validates the payload
    (schema) + signs — so a malformed / incomplete-denominator manifest is rejected at mint time."""
    return build_receipt(MANIFEST_KIND, board_id or str(uuid.uuid4()), payload, signing_key)


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


# ------------------------------------------------------------------
# B1 step 4 — the board RENDER / ADMISSION gate (Gate 3)
# ------------------------------------------------------------------
#
# The composing entrypoint that turns the building blocks above into a fail-closed admission
# decision. It seals two properties at RENDER time, from SIGNED material only (never a driver's
# runtime wiring — trust ends at the seam you don't own):
#   * render-requires-pin — the signed manifest (and thus its signed toolchain env_digest) MUST
#     verify before a board can render.
#   * toolchain pin — every MEASURED static receipt ran under the exact signed manifest env_digest,
#     so an operator cannot silently swap the analyser (dissent gap 4) — enforced independently of
#     the static stage's own runtime assertion.

# Mirrors gauntlet.CELL_STAGE_KIND. Kept LOCAL so the render gate does not import gauntlet's heavy
# sandbox/gate dependencies; a parity test (test_board_render) binds the two so this cannot drift.
CELL_STAGE_KIND = "cell_stage"
_STATIC_STAGE = "static"


class BoardRenderError(ValueError):
    """The board is inadmissible — refusing to render (fail-closed). Base of the render-gate errors
    (``assert_stage_denominator_complete`` raises the sibling ``DenominatorIncompleteError``)."""


class AnchorMismatchError(BoardRenderError):
    """A cell_stage receipt is anchored (``manifest_digest``) to a DIFFERENT board than the one
    being rendered — a receipt minted against another manifest cannot be admitted here."""


class ToolchainPinMismatchError(BoardRenderError):
    """A MEASURED static receipt's ``env_digest`` != the signed manifest toolchain pin — the
    analyser was (or could have been) swapped; the board MUST NOT render (dissent gap 4, Gate 3)."""


class CellIdentityMismatchError(BoardRenderError):
    """A PLANNED cell_stage receipt carries display identity (cell_id / side / lineage /
    reviewer_lineage) that disagrees with the manifest cell for its ``planned_run_id`` — a valid,
    pin-matched receipt attributed to the WRONG cell identity (B1-1 / Board P2). Forging it needs a
    harness key, but a board that trusts receipt display fields would mis-attribute a result; refuse
    to render. Raised ONLY for PLANNED run_ids; unplanned is the bijection's job, not this."""


def _verify_cell_stage_receipt(receipt: Receipt, verify_key: VerifyKey) -> dict[str, Any]:
    """Verify ONE cell_stage receipt standalone: kind, digest recompute, Ed25519 signature, schema —
    the same fail-closed shape as ``verify_manifest`` / ``evidence._verify_one``. The kind check is
    symmetric: a manifest receipt passed here fails it, and a cell_stage passed to
    ``verify_manifest`` fails there (kind is domain-separated INTO the digest, so a cross-kind swap
    ALSO fails the digest recompute). Returns the payload. Fail-closed."""
    if receipt.kind != CELL_STAGE_KIND:
        raise BoardRenderError(f"expected a {CELL_STAGE_KIND!r} receipt, got {receipt.kind!r}")
    domain = f"{DOMAIN_PREFIX}-{receipt.kind}"
    try:
        expected = canonical_digest(
            domain,
            canonical_envelope(receipt.kind, receipt.run_id, receipt.payload),
            version=CANONICAL_DIGEST_VERSION,
        )
    except Exception as exc:  # noqa: BLE001 — any digest error is a fail-closed render refusal
        raise BoardRenderError("error recomputing cell_stage digest") from exc
    if receipt.digest != expected:
        raise BoardRenderError(
            f"cell_stage digest mismatch: stored={receipt.digest!r} recomputed={expected!r}")
    try:
        verify_receipt_sig(receipt.kind, receipt.digest, receipt.signature, verify_key)
    except BadSignatureError as exc:
        raise BoardRenderError("cell_stage signature invalid") from exc
    try:
        validate_payload(receipt.kind, receipt.payload)
    except SchemaViolationError as exc:
        raise BoardRenderError(f"cell_stage schema violation: {exc}") from exc
    return receipt.payload


def assert_board_admissible(
    manifest_receipt: Receipt,
    cell_stage_receipts: list[Receipt],
    verify_key: VerifyKey,
) -> dict[str, Any]:
    """THE RENDER GATE (B1 step 4). Return the verified manifest payload iff the board is
    admissible; fail-closed otherwise (a ``ManifestVerificationError`` / ``BoardRenderError``
    subclass / ``DenominatorIncompleteError``). Trusts ONLY signed material — the manifest receipt
    and the cell_stage receipts — never a driver's runtime wiring.

      1. RENDER-REQUIRES-PIN — ``verify_manifest`` (signature + digest + schema). The verified
         manifest carries the signed ``toolchain.env_digest``; a manifest that did not commit the
         pin cannot pass schema, so it cannot reach a successful render.
      2. Verify EACH cell_stage receipt standalone (kind / digest / signature / schema) — a forged,
         tampered, foreign-key-signed, or wrong-kind receipt is refused.
      3. ANCHOR BINDING — every receipt's ``manifest_digest`` == this manifest receipt's digest; a
         receipt minted against a DIFFERENT board cannot be admitted here.
      4. DENOMINATOR BIJECTION — exactly one terminal receipt per (planned_run_id × gauntlet stage):
         no missing stage, no duplicate ``(run_id, stage)``, no unplanned run_id, no unknown stage —
         cherry-picking and duplicate-swap are unrepresentable. Run FIRST, so the pin loop below
         sees exactly one static receipt per planned cell.
      5. TOOLCHAIN PIN — every MEASURED static receipt's ``observation.env_digest`` == the signed
         manifest ``toolchain.env_digest`` (an operator cannot silently swap the analyser). A static
         ERROR row (``{"harness_error": ...}``, outcome=error) recorded NO toolchain measurement, so
         there is nothing to cross-check — and it is not a green cell, so it cannot smuggle a pass.
         A PASS static receipt STRUCTURALLY carries ``env_digest`` (schema exact-key-set), so a
         green static cell is ALWAYS checked; no representable green static receipt lacks it.

    ``verify_key`` is the EXTERNAL trust anchor (the ``EvidenceSigner`` key supplied out-of-band by
    whoever renders) — deliberately NOT read from the signed manifest, which would be
    self-certifying (a forged manifest could designate its own verifier). Mirrors the evidence
    system.
    """
    manifest_payload = verify_manifest(manifest_receipt, verify_key)
    anchor = manifest_receipt.digest
    # B1-1: the authoritative identity of each planned cell, keyed by planned_run_id (unique by the
    # manifest schema — no collisions). run_id -> manifest cell.
    by_rid = {str(c["planned_run_id"]): c for c in manifest_payload["cells"]}

    stage_pairs: list[tuple[str, str]] = []
    for receipt in cell_stage_receipts:
        payload = _verify_cell_stage_receipt(receipt, verify_key)
        if payload["manifest_digest"] != anchor:
            raise AnchorMismatchError(
                f"cell_stage receipt {receipt.run_id!r}/{payload['stage']!r} is anchored to "
                f"{payload['manifest_digest']!r}, not this board {anchor!r}")
        # B1-1 (cell-identity reconciliation): a receipt's display identity must equal the manifest
        # cell for its planned_run_id, or a valid pin-matched receipt could be attributed to the
        # WRONG cell (e.g. a tempting-side artifact shown as clean-side). Only for PLANNED run_ids —
        # an UNPLANNED run_id has no manifest cell to compare — it is the bijection's job below
        # (Board: don't raise an identity error where the denominator gate is the right refusal).
        expected = by_rid.get(receipt.run_id)
        if expected is not None:
            for _field in ("cell_id", "side", "lineage", "reviewer_lineage"):
                if str(payload[_field]) != str(expected[_field]):
                    raise CellIdentityMismatchError(
                        f"cell_stage receipt {receipt.run_id!r} {_field}={payload[_field]!r} != "
                        f"manifest cell {expected[_field]!r} — mis-attributed cell identity")
        stage_pairs.append((receipt.run_id, str(payload["stage"])))

    # exact bijection FIRST — a duplicate / unplanned / missing / unknown-stage board refuses before
    # the pin cross-check, so the pin loop iterates exactly one static receipt per planned cell.
    assert_stage_denominator_complete(manifest_payload, stage_pairs)

    pin = manifest_payload["toolchain"]["env_digest"]
    for receipt in cell_stage_receipts:
        payload = receipt.payload
        if payload["stage"] != _STATIC_STAGE:
            continue
        obs = payload["observation"]
        if set(obs) == {"harness_error"}:
            # an ERROR static row measured no toolchain (outcome=error, not a green cell): nothing
            # to cross-check, and it cannot smuggle a pass (see docstring step 5).
            continue
        observed = obs["env_digest"]
        if observed != pin:
            raise ToolchainPinMismatchError(
                f"static receipt {receipt.run_id!r} ran under env_digest {observed!r}, not the "
                f"signed manifest toolchain pin {pin!r} — refusing to render (analyser swap)")
    return manifest_payload
