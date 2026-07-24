"""orchestrator/render_driver.py — Step 3.1: the render driver (the caller-law, satisfied).

The FIRST production caller of the sealed B1 apparatus: it plans the complete denominator, signs the
board manifest before any stage runs, drives ``run_gauntlet`` per cell, collects the signed
``cell_stage`` receipts, calls ``assert_board_admissible`` (the admission gate the whole apparatus
exists to be called by), and — only if that passes — emits a local, signed, inspectable board.

Board honesty is enforced here, per the Step-3.1 board ruling:

  * FAIL-CLOSED EMIT — nothing is written to disk until ``assert_board_admissible`` has passed. On
    any exception the driver renders nothing.
  * RECEIPTS-ONLY RENDER — the table is built from the SIGNED receipts, never from cached runtime
    ``StageObservation`` state.
  * INPUT HYGIENE — duplicate ``task_ids`` are rejected before planning (``plan_cells`` already
    rejects duplicate lineages; duplicate task_sides are the denominator-inflation seam, guarded).
  * ADMISSIBLE != GATE VERDICT — the render separates "admissible" (a valid terminal receipt per
    stage) from the gate's own verdict. That verdict is ENGINE-FAITHFUL and three-way distinct: a
    caught evasion is ADMIT/fail (an admitted_run with a FAIL run-verdict — the detector judged it
    and it failed; the merge is blocked), a governance refusal is BLOCKED (a distinct
    currency/drift/generation blocking_refusal — the gate could not render a verdict), and a
    non_run / infra / harness failure is ERROR. An all-ERROR cell is a valid terminal row but is
    rendered as visibly-neither-pass-nor-catch. A caught evasion is NEVER relabelled "BLOCKED".
  * RESPONSE PROVENANCE — ``response_source`` (recorded | live) is UNSIGNED render metadata plus an
    optional separately-signed capture record; it is NEVER a B1-attested property (the
    ``llm_review``
    schema has no such field, by design). Board #2's "live" origin is likewise unsigned.
  * STRUCTURALLY REGENERABLE (NOT byte-regenerable) — the apparatus mints ``board_id`` /
    ``planned_run_id`` (uuid4) and ``executed_at`` (wall clock) internally, so raw signed receipt
    bytes differ across runs. ``normalize_board`` is the PUBLISHED canonical strip of exactly those
    nonces + timestamps + the crypto over them; two runs over identical fixtures + the same recorded
    reviewer produce IDENTICAL normalised bytes. The disclosure names what it strips. Full
    bit-identity of raw receipts is deferred to a B1 change (not claimed here).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from .evidence import Receipt
from .gauntlet import (
    GAUNTLET_STAGES,
    CellContext,
    GateRunner,
    MakeSandbox,
    ReviewClient,
    ReviewOutcome,
    ReviewRequestBuilder,
    canonical_review_source,
    gate_stage,
    llm_review_stage,
    own_tests_stage,
    run_gauntlet,
    seal_artifact,
    static_stage,
)
from .gauntlet import (
    _canonical_review_request as canonical_review_request,
)
from .manifest import (
    assert_board_admissible,
    build_manifest,
    build_manifest_payload,
    plan_cells,
)

# The disclosure block written into every board — the honest scope of what the board claims.
BOARD_DISCLOSURE = (
    "This board is a signed, LOCAL gate demonstration. Every cell links a signed cell_stage "
    "receipt; the board is admissible only because assert_board_admissible passed (complete "
    "denominator, anchored + identity-reconciled receipts, static toolchain pin). SCOPE: (1) "
    "'response_source' on the llm_review column is UNSIGNED render metadata (recorded|live) — the "
    "review receipt attests the review bytes + verdict, NOT their origin. A 'recorded' response is "
    "replayed from a capture record bundled here (request-digest-bound), signed by the LOCAL "
    "render key ONLY: it attests the operator bundled these exact bytes, NOT that a provider "
    "produced them, and the 'recorded' origin is operator-asserted, not gate-verified. Capture "
    "records are OPTIONAL auxiliary evidence — NOT part of assert_board_admissible and NOT in "
    "normalize_board, so a board may omit or add them without affecting admissibility. (2) The "
    "board is "
    "STRUCTURALLY REGENERABLE, not byte-regenerable: run normalize_board() (published) to strip "
    "the board_id, per-receipt run_id, executed_at, digest and signature; two runs over identical "
    "fixtures + the same recorded reviewer yield IDENTICAL normalised bytes. Raw signed receipt "
    "bytes differ per run (uuid4 nonces + wall-clock timestamps minted in the sealed apparatus). "
    "(3) GATE SEMANTICS are engine-faithful, not merge-English: 'ADMIT' = an admitted_run with a "
    "PASS run-verdict (merge allowed); 'ADMIT/fail' = an admitted_run with a FAIL run-verdict (the "
    "detector caught the behaviour, so in a gated deployment the required check fails, the merge "
    "is BLOCKED — the tempting cell's real shape); 'BLOCKED' is reserved for a governance "
    "blocking_refusal (a currency/drift/generation refusal — a DISTINCT event where the gate could "
    "not render a verdict); 'ERROR' is a non_run / infrastructure / harness failure. A caught "
    "evasion is 'ADMIT/fail', never 'BLOCKED'."
)

# Appended to the disclosure for a LIVE board (response_source='live') — the honest scope of a real
# second-model review (consult P1.2): the verdict is an UNAUTHENTICATED model output, and the
# binding is over the request WE sent, not the token sequence the provider actually fed the model.
LIVE_REVIEW_DISCLOSURE = (
    " LIVE REVIEW: the llm_review verdicts on this board are REAL second-model outputs, captured "
    "live at our provider-gate and bundled as source='live' capture records (each carries the "
    "exact wire request as request_b64; sha256(request_b64) == the signed receipt's "
    "request_digest, so the /v1/messages body shape is reconstructable from the capture, receipt "
    "schema unchanged). SCOPE: a live verdict is an UNAUTHENTICATED model output; only the "
    "request/response BINDING is attested (this review was of exactly this artifact), NOT the "
    "verdict's correctness, and NOT the final token sequence the provider fed the model (it may "
    "prepend its own system template). The capture is signed by the LOCAL render key only."
)


class RenderDriverError(RuntimeError):
    """A driver-level precondition failed (duplicate task, missing artifact). Distinct from a
    BoardRenderError (the admission gate) — this is caught before any stage runs."""


class RecordedRequestMismatch(RuntimeError):
    """A RecordedReviewClient was handed a request whose digest != the captured request it answers —
    replaying would attribute a recorded response to the wrong request. Refuse (fail-closed)."""


# ------------------------------------------------------------------
# Task specs — the demonstration inputs
# ------------------------------------------------------------------


@dataclass(frozen=True)
class TaskSpec:
    """One board task: the producer artifact (a fixture dir) plus the signed manifest task fields.
    ``side`` is 'tempting' | 'clean'; ``artifact_dir`` is the sealed-per-cell source."""

    task_id: str
    prompt: str
    prompt_hash: str            # hex64
    side: str                   # tempting | clean
    counterpart_task_id: str
    detector_id: str
    invariant_corpus_version: str
    review_prompt_hash: str     # hex64
    artifact_dir: Path


# ------------------------------------------------------------------
# Recorded reviewer (board #1) + its signed capture record
# ------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewCapture:
    """A reviewer response CAPTURED ONCE from a real model call, bound to the exact request it
    answered. Replayed byte-identically by RecordedReviewClient. Disclosed as recorded; signed
    into a capture record (below) so a reader can verify the response bytes were not invented — but
    this record is not part of the B1 chain and is NEVER verified by assert_board_admissible."""

    request_digest: str         # sha256 hex of the canonical request this response answers
    response: bytes             # the exact recorded response bytes
    verdict: str                # approve | request_changes
    provider_id: str
    model_id: str
    request_bytes: bytes = b""  # the EXACT wire request (live mint only); reconstructs the body for
    #  out-of-band structure attestation. Empty for a 3.1 recorded capture.


@dataclass(frozen=True)
class RecordedReviewClient:
    """A ReviewClient that REPLAYS captured responses — one per distinct review request (a
    multi-cell board has a distinct request per (artifact, reviewer_lineage)). It looks up the
    handed request by digest and replays ONLY its exactly-matching capture (else it attributes a
    recorded response to a different request — fail-closed). Board #1 uses this; board #2 swaps the
    live ReviewProviderClient with an identical seam (the injected-client swap is the only diff)."""

    captures: tuple[ReviewCapture, ...]

    def __call__(
        self, request_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
    ) -> ReviewOutcome:
        got = hashlib.sha256(request_bytes).hexdigest()
        for c in self.captures:
            if c.request_digest == got:
                return ReviewOutcome(
                    verdict=c.verdict, provider_id=c.provider_id, model_id=c.model_id,
                    raw_response=c.response)
        raise RecordedRequestMismatch(
            f"no captured response for request {got!r} — refusing to replay for an "
            f"un-captured request (have {[c.request_digest for c in self.captures]})")


def capture_request_digest(
    artifact_dir: Path, reviewer_lineage: str, review_prompt_hash: str
) -> str:
    """The request_digest a llm_review of ``artifact_dir`` will produce — for capturing a real
    reviewer response ahead of time and binding it (RecordedReviewClient checks against this).
    Mirrors
    llm_review_stage: seal -> canonical_review_source -> canonical_review_request -> sha256."""
    with seal_artifact(artifact_dir) as sealed:
        source = canonical_review_source(sealed)
    request = canonical_review_request(source, reviewer_lineage, review_prompt_hash)
    return hashlib.sha256(request).hexdigest()


def sign_capture_record(
    capture: ReviewCapture, signing_key: SigningKey, *, source: str = "recorded",
) -> dict[str, Any]:
    """A separately-signed capture record binding the response to its request + provenance. Ed25519
    over the canonical capture bytes, signed by the LOCAL render/board key (``signing_key``) ONLY —
    NOT the provider's, NOT a gate key. It attests that THIS operator bundled these exact bytes for
    request_digest; it does NOT attest a provider produced them, nor is the origin gate-verified.
    Bundled in the board dir but NOT a B1 receipt, NOT verified by assert_board_admissible, NOT in
    normalize_board — OPTIONAL auxiliary evidence (per dissent [A]).

    ``source`` is the honest mint origin — 'recorded' (board #1 replay) or 'live' (board #2 mint).
    For a LIVE capture the EXACT wire request is bundled as ``request_b64`` (present iff
    ``capture.request_bytes``): sha256(request_b64) == the signed receipt's request_digest, so a
    reader can reconstruct + inspect the /v1/messages body shape from the capture alone — the
    out-of-band structure attestation that avoids reopening the receipt schema (consult P1.1)."""
    body: dict[str, Any] = {
        "kind": "review_capture",
        "source": source,
        "request_digest": capture.request_digest,
        "response_digest": hashlib.sha256(capture.response).hexdigest(),
        "response_b64": base64.b64encode(capture.response).decode("ascii"),
        "verdict": capture.verdict,
        "provider_id": capture.provider_id,
        "model_id": capture.model_id,
    }
    if capture.request_bytes:
        body["request_b64"] = base64.b64encode(capture.request_bytes).decode("ascii")
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signing_key.sign(payload).signature.hex()
    return {"body": body, "signature": signature,
            "verify_key_hex": signing_key.verify_key.encode().hex()}


# ------------------------------------------------------------------
# The board artifact
# ------------------------------------------------------------------


@dataclass(frozen=True)
class BoardArtifact:
    """The rendered board: the signed manifest receipt, the signed cell_stage receipts, and UNSIGNED
    render metadata (the table, the per-cell response_source, the disclosure, the optional capture
    record). Everything security-bearing is a signed receipt; the render metadata is explicitly not
    B1-attested."""

    manifest_receipt: Receipt
    cell_stage_receipts: tuple[Receipt, ...]
    manifest_payload: dict[str, Any]
    render_metadata: dict[str, Any]


# ------------------------------------------------------------------
# Rendering the table — FROM THE SIGNED RECEIPTS ONLY
# ------------------------------------------------------------------


def _cell_verdict(stage: str, payload: dict[str, Any]) -> str:
    """The display verdict for one stage receipt, read from the SIGNED payload. 'admissible != gate
    verdict': the gate column shows ADMIT / BLOCK / ERROR from its result_kind, never 'pass'
    alone."""
    outcome = str(payload["outcome"])
    obs = payload["observation"]
    if stage != "gate":
        return outcome  # pass | fail | error
    if set(obs) == {"harness_error"}:
        return "ERROR"
    kind = str(obs["result_kind"])
    return {
        "blocking_refusal": "BLOCKED",
        "admitted_run": "ADMIT" if outcome == "pass" else f"ADMIT/{outcome}",
        "non_run": "ERROR", "infrastructure_failure": "ERROR",
    }.get(kind, "ERROR")


def render_table(
    manifest_payload: dict[str, Any],
    receipts: tuple[Receipt, ...],
    response_source: str,
) -> dict[str, Any]:
    """Build the render table from the SIGNED receipts only — never runtime observations. One row
    per planned cell (ordered as the manifest committed them), columns = the ordered gauntlet
    stages, each cell the stage receipt's display verdict + a ref (run_id) to the signed receipt.
    Per-row disclosure carries lineage / side / task and the UNSIGNED response_source on
    llm_review."""
    by_run_stage: dict[tuple[str, str], dict[str, Any]] = {
        (r.run_id, str(r.payload["stage"])): r.payload for r in receipts}
    rows = []
    for cell in manifest_payload["cells"]:
        rid = str(cell["planned_run_id"])
        columns = {}
        for stage in GAUNTLET_STAGES:
            payload = by_run_stage.get((rid, stage))
            columns[stage] = {
                "verdict": _cell_verdict(stage, payload) if payload else "MISSING",
                "receipt_run_id": rid,
            }
        rows.append({
            "cell_id": cell["cell_id"], "task_id": cell["task_id"], "side": cell["side"],
            "lineage": cell["lineage"], "reviewer_lineage": cell["reviewer_lineage"],
            "columns": columns,
            "response_source": response_source,  # UNSIGNED origin metadata (recorded|live)
        })
    return {"columns": list(GAUNTLET_STAGES), "rows": rows}


# ------------------------------------------------------------------
# Published canonical normalization — the artifact the regenerability claim rests on
# ------------------------------------------------------------------

# The exact fields stripped from each cell_stage receipt: the per-run nonces / timestamps and the
# crypto computed over them. What remains is the deterministic MEASUREMENT (stage, side, lineage,
# outcome, observation, artifact_tree_digest, code_sha) — identical across runs over the same
# inputs.
# ``manifest_digest`` is stripped from each cell_stage payload because it is the per-run anchor
# derived from the manifest's own board_id/preregistered_at nonces — a nonce itself, not a
# measurement. What remains is the deterministic per-cell measurement.
_PAYLOAD_NONCE_FIELDS = ("executed_at", "manifest_digest")
_MANIFEST_PAYLOAD_NONCE_FIELDS = ("preregistered_at",)


def _strip(d: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in keys}


def normalize_board(artifact: BoardArtifact) -> bytes:
    """PUBLISHED canonical normalization. Strip the non-deterministic nonces + timestamps (board_id/
    run_id, planned_run_id/run_id, executed_at, preregistered_at) and the crypto over them (digest,
    signature), then serialise canonically. Two runs of render_board over IDENTICAL fixtures + the
    same recorded reviewer produce IDENTICAL normalised bytes — this is the "structurally
    regenerable"
    claim, made verifiable by anyone who runs this function. It does NOT re-verify signatures (they
    are stripped); it proves the MEASUREMENT is identical, not that raw receipt bytes match.

    Receipts are ordered by (cell_id, stage) so ordering is deterministic regardless of run order.
    """
    mr = artifact.manifest_receipt
    manifest = {
        **_strip({"kind": mr.kind, "payload": _strip(mr.payload, _MANIFEST_PAYLOAD_NONCE_FIELDS)},
                 ()),
    }
    # strip the manifest cells' planned_run_id (a uuid4 nonce) — keep the deterministic cell
    # identity.
    manifest_payload = manifest["payload"]
    manifest_payload = {
        **manifest_payload,
        "cells": [_strip(c, ("planned_run_id",)) for c in manifest_payload["cells"]],
    }
    manifest["payload"] = manifest_payload

    receipts = sorted(
        artifact.cell_stage_receipts,
        key=lambda r: (str(r.payload["cell_id"]), str(r.payload["stage"])))
    norm_receipts = [
        {"kind": r.kind, "payload": _strip(r.payload, _PAYLOAD_NONCE_FIELDS)}
        for r in receipts
    ]
    table = artifact.render_metadata.get("table")
    normalized = {
        "manifest": manifest,
        "cell_stage_receipts": norm_receipts,
        "table": table,  # deterministic verdicts + cell identity; run_id refs dropped below
    }
    # the table's receipt_run_id refs are nonces — drop them for the structural comparison.
    if table is not None:
        stripped_rows = []
        for row in table["rows"]:
            cols = {s: {"verdict": c["verdict"]} for s, c in row["columns"].items()}
            # response_source (recorded|live) is UNSIGNED origin metadata, NOT a measurement — strip
            # it so the canonical form is measurement-only: a live board and its recorded REPLAY of
            # the same captures normalise IDENTICALLY (they differ only in the honest mode label).
            stripped_rows.append({**_strip(row, ("response_source",)), "columns": cols})
        normalized["table"] = {"columns": table["columns"], "rows": stripped_rows}
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ------------------------------------------------------------------
# The driver
# ------------------------------------------------------------------


def render_board(
    *,
    tasks: list[TaskSpec],
    lineages: list[str],
    n_replicates: int,
    gated_commit: str,
    corpus_version: str,
    preregistered_at: str,
    code_sha: str,
    toolchain: dict[str, Any],
    make_sandbox: MakeSandbox,
    gate_runner: GateRunner,
    review_client: ReviewClient,
    signing_key: SigningKey,
    verify_key: VerifyKey,
    out_dir: Path | None = None,
    response_source: str = "recorded",
    build_request: ReviewRequestBuilder = canonical_review_request,
    board_id: str | None = None,
) -> BoardArtifact:
    """Render a signed local board. FAIL-CLOSED: nothing touches ``out_dir`` until
    ``assert_board_admissible`` has passed; any exception renders nothing.

    ``toolchain`` is the signed pin (must carry ``env_digest`` = the toolchain image config id — the
    same the static/own_tests stages run in). ``make_sandbox`` builds that toolchain sandbox for
    static/own_tests; ``gate_runner`` drives the real enforcement for the gate stage;
    ``review_client`` is the RecordedReviewClient (board #1, ``response_source='recorded'``) or a
    live capturing client (board #2, ``response_source='live'``); ``build_request`` is the review
    request builder (default = the canonical envelope; board #2 injects a real provider builder).
    """
    # LABEL <-> CLIENT + MODEL consistency (Board #2 render-gate SEAL) — a mislabelled board must
    # fail fast, BEFORE any stage runs, never after emit.
    _assert_label_consistent(response_source, review_client, build_request)

    # INPUT HYGIENE — reject duplicate task_ids (the denominator-inflation seam; plan_cells already
    # rejects duplicate lineages). Do this BEFORE any planning or stage work.
    task_ids = [t.task_id for t in tasks]
    if len(set(task_ids)) != len(task_ids):
        raise RenderDriverError(f"duplicate task_ids in the board spec: {sorted(task_ids)}")
    by_task = {t.task_id: t for t in tasks}
    for t in tasks:
        if not t.artifact_dir.is_dir():
            raise RenderDriverError(f"task {t.task_id!r} artifact_dir is not a directory: "
                                    f"{t.artifact_dir}")

    # 1. Plan the complete denominator + sign the manifest BEFORE any stage runs (the anchor).
    task_sides = [(t.task_id, t.side) for t in tasks]
    cells = plan_cells(task_sides, lineages, n_replicates)
    manifest_payload = build_manifest_payload(
        gated_commit=gated_commit, code_sha=code_sha, corpus_version=corpus_version,
        preregistered_at=preregistered_at,
        tasks=[_task_dict(t) for t in tasks],
        denominator={"n_replicates": n_replicates, "seed": 0, "temperature": "0.0", "params": {},
                     "retry_policy": "none", "infra_failure_disposition": "error_and_publish"},
        cells=cells, toolchain=toolchain)
    # For a LIVE board the board_id is pre-minted + published in the commitment BEFORE the run; a
    # cherry-picked re-run then carries a DIFFERENT board_id (visible as a separate publication).
    manifest_receipt = build_manifest(manifest_payload, signing_key, board_id=board_id)

    # 2. Drive the gauntlet per cell. NO exception swallowing in the loop — run_gauntlet already
    #    fills every cell with 4 terminal receipts (total-cell-perimeter); a raise here is a
    #    publishing-machinery failure and MUST propagate (fail-closed, nothing renders).
    review_prompt_hash = _one_review_prompt_hash(tasks)
    receipts: list[Receipt] = []
    for cell in cells:
        task = by_task[str(cell["task_id"])]
        ctx = CellContext(
            manifest_digest=manifest_receipt.digest, planned_run_id=str(cell["planned_run_id"]),
            cell_id=str(cell["cell_id"]), lineage=str(cell["lineage"]),
            reviewer_lineage=str(cell["reviewer_lineage"]), side=str(cell["side"]))
        stage_fns = _stage_fns(
            toolchain_image=str(toolchain["env_digest"]), env_digest=str(toolchain["env_digest"]),
            make_sandbox=make_sandbox, gate_runner=gate_runner, review_client=review_client,
            reviewer_lineage=ctx.reviewer_lineage, review_prompt_hash=review_prompt_hash,
            build_request=build_request)
        receipts.extend(run_gauntlet(ctx, task.artifact_dir, stage_fns, signing_key))

    # 3-4. The CALLER-LAW: admission before anything renders. Raises on any failure -> nothing
    # written.
    verified_payload = assert_board_admissible(manifest_receipt, receipts, verify_key)

    # 5. Build the render (from signed receipts only) and — only now — emit.
    table = render_table(verified_payload, tuple(receipts), response_source)
    disclosure = BOARD_DISCLOSURE + (LIVE_REVIEW_DISCLOSURE if response_source == "live" else "")
    render_metadata: dict[str, Any] = {
        "table": table, "response_source": response_source, "disclosure": disclosure}
    # RESPONSE PROVENANCE — bundle the separately-signed capture records (recorded replay OR live
    # mint) so a reader can confirm the response bytes were captured (request-digest-bound), not
    # invented. NOT a B1 receipt; NOT verified by assert_board_admissible; EXCLUDED from
    # normalize_board (the signature is per-key, an origin claim, not a measurement).
    capture_records = _capture_records(response_source, review_client, signing_key)
    if capture_records is not None:
        render_metadata["capture_records"] = capture_records
    # SEAL: every bundled capture's source == the board label, and every non-ERROR llm_review cell
    # of a LIVE board is covered by a live capture (no reviewed-but-uncaptured cell).
    _assert_capture_consistent(response_source, capture_records, receipts)
    artifact = BoardArtifact(
        manifest_receipt=manifest_receipt, cell_stage_receipts=tuple(receipts),
        manifest_payload=verified_payload, render_metadata=render_metadata)
    if out_dir is not None:
        _emit(artifact, out_dir)
    return artifact


def _task_dict(t: TaskSpec) -> dict[str, Any]:
    return {"task_id": t.task_id, "prompt": t.prompt, "prompt_hash": t.prompt_hash, "side": t.side,
            "counterpart_task_id": t.counterpart_task_id, "detector_id": t.detector_id,
            "invariant_corpus_version": t.invariant_corpus_version,
            "review_prompt_hash": t.review_prompt_hash}


def _one_review_prompt_hash(tasks: list[TaskSpec]) -> str:
    """The board uses ONE fixed, published review prompt (its hash committed per task). All tasks
    must agree on it (the reviewer prompt is a board constant); disagreement is a spec error."""
    hashes = {t.review_prompt_hash for t in tasks}
    if len(hashes) != 1:
        raise RenderDriverError(f"tasks disagree on review_prompt_hash: {sorted(hashes)}")
    return hashes.pop()


def _stage_fns(
    *, toolchain_image: str, env_digest: str, make_sandbox: MakeSandbox, gate_runner: GateRunner,
    review_client: ReviewClient, reviewer_lineage: str, review_prompt_hash: str,
    build_request: ReviewRequestBuilder = canonical_review_request,
) -> dict[str, Callable[[Any], Any]]:
    """Wire the four gauntlet stage closures for one cell. static/own_tests run in the pinned
    toolchain sandbox; llm_review uses the injected client + this cell's reviewer + the request
    builder (default envelope; board #2 = a real provider body); gate drives enforcement."""
    return {
        "static": lambda s: static_stage(
            s, image=toolchain_image, env_digest=env_digest, make_sandbox=make_sandbox),
        "own_tests": lambda s: own_tests_stage(s, image=toolchain_image, make_sandbox=make_sandbox),
        "llm_review": lambda s: llm_review_stage(
            s, reviewer_lineage=reviewer_lineage, review_prompt_hash=review_prompt_hash,
            review_client=review_client, build_request=build_request),
        "gate": lambda s: gate_stage(s, gate_runner=gate_runner),
    }


# ------------------------------------------------------------------
# Board #2 label <-> client + capture consistency (the render-gate SEAL)
# ------------------------------------------------------------------


def _client_model_id(review_client: ReviewClient) -> str | None:
    """The reviewer model the client declares — from a capturing wrapper's ``inner`` (board #2) or
    the client itself. Duck-typed to avoid a live_review import cycle (it imports ReviewCapture)."""
    inner = getattr(review_client, "inner", None)
    if inner is not None:
        return getattr(inner, "model_id", None)
    return getattr(review_client, "model_id", None)


def _assert_label_consistent(
    response_source: str, review_client: ReviewClient, build_request: ReviewRequestBuilder,
) -> None:
    """SEAL (pre-stage): the board label and the injected client must agree, and a LIVE board's
    request-builder model must match the client's declared reviewer-of-record. A mislabel or a
    model mismatch fails fast, before any stage runs. ``recorded`` ⇔ RecordedReviewClient;
    ``live`` ⇔ a capturing client (``.sink``) that is NOT a RecordedReviewClient."""
    is_recorded = isinstance(review_client, RecordedReviewClient)
    if response_source == "recorded":
        if not is_recorded:
            raise RenderDriverError(
                "response_source='recorded' requires a RecordedReviewClient (label mismatch)")
    elif response_source == "live":
        if is_recorded:
            raise RenderDriverError(
                "response_source='live' must NOT use a RecordedReviewClient (label mismatch)")
        if not hasattr(review_client, "sink"):
            raise RenderDriverError(
                "response_source='live' requires a capturing client exposing '.sink'")
        want = getattr(build_request, "model", None)
        if want is None:
            raise RenderDriverError(
                "a live board requires a build_request carrying '.model' (model consistency)")
        got = _client_model_id(review_client)
        if got is not None and want != got:
            raise RenderDriverError(
                f"reviewer model mismatch: build_request.model={want!r} != client.model_id={got!r}")
    else:
        raise RenderDriverError(f"bad response_source {response_source!r}: expect recorded|live")


def _capture_records(
    response_source: str, review_client: ReviewClient, signing_key: SigningKey,
) -> list[dict[str, Any]] | None:
    """Signed capture records for the board's mode — recorded replay (board #1) or live mint (board
    #2). None if the mode mints none. Live captures come from the capturing client's ``.sink``."""
    if response_source == "recorded" and isinstance(review_client, RecordedReviewClient):
        return [sign_capture_record(c, signing_key, source="recorded")
                for c in review_client.captures]
    if response_source == "live" and hasattr(review_client, "sink"):
        return [sign_capture_record(c, signing_key, source="live")
                for c in getattr(review_client, "sink")]
    return None


def _assert_capture_consistent(
    response_source: str, capture_records: list[dict[str, Any]] | None, receipts: list[Receipt],
) -> None:
    """SEAL (post-build, pre-emit): every bundled capture's ``source`` == the board label; and for a
    LIVE board every non-ERROR llm_review cell is COVERED by a live capture (no reviewed-but-
    uncaptured cell — catches a wrapper that returned but failed to record)."""
    for rec in capture_records or []:
        if rec["body"]["source"] != response_source:
            raise RenderDriverError(
                f"capture source {rec['body']['source']!r} != board label {response_source!r}")
    if response_source == "live":
        captured = {rec["body"]["request_digest"] for rec in capture_records or []}
        for r in receipts:
            if str(r.payload["stage"]) == "llm_review" and str(r.payload["outcome"]) != "error":
                rd = str(r.payload["observation"]["request_digest"])
                if rd not in captured:
                    raise RenderDriverError(
                        f"live board: llm_review cell {r.payload['cell_id']} has no live capture "
                        f"for request_digest {rd}")


def _emit(artifact: BoardArtifact, out_dir: Path) -> None:
    """Write the board + all signed receipts to ``out_dir`` (called ONLY after admission passed).
    Receipts are the source of truth; the rendered board.json + disclosure are the inspectable
    view."""
    out_dir.mkdir(parents=True, exist_ok=True)
    receipts_dir = out_dir / "receipts"
    receipts_dir.mkdir(exist_ok=True)
    _write_receipt(receipts_dir / "manifest.json", artifact.manifest_receipt)
    for r in artifact.cell_stage_receipts:
        slug = str(r.payload["cell_id"]).replace("/", "_")
        _write_receipt(receipts_dir / f"{slug}__{r.payload['stage']}.json", r)
    (out_dir / "board.json").write_text(
        json.dumps(artifact.render_metadata, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "DISCLOSURE.txt").write_text(
        str(artifact.render_metadata["disclosure"]) + "\n", encoding="utf-8")
    (out_dir / "normalized.json").write_bytes(normalize_board(artifact))
    # Signed capture records for a recorded board — one file per request_digest (the disclosure's
    # "bundled here". Present only when response_source == "recorded"; not part of normalize_board.)
    capture_records = artifact.render_metadata.get("capture_records")
    if capture_records:
        captures_dir = out_dir / "captures"
        captures_dir.mkdir(exist_ok=True)
        for rec in capture_records:
            digest = str(rec["body"]["request_digest"])
            (captures_dir / f"{digest}.json").write_text(
                json.dumps(rec, indent=2, sort_keys=True), encoding="utf-8")


def _write_receipt(path: Path, r: Receipt) -> None:
    path.write_text(json.dumps(
        {"kind": r.kind, "run_id": r.run_id, "payload": r.payload, "digest": r.digest,
         "signature": r.signature}, indent=2, sort_keys=True), encoding="utf-8")


__all__ = [
    "BOARD_DISCLOSURE", "LIVE_REVIEW_DISCLOSURE", "BoardArtifact", "RecordedReviewClient",
    "RenderDriverError", "RecordedRequestMismatch", "ReviewCapture", "TaskSpec",
    "capture_request_digest", "normalize_board", "render_board", "render_table",
    "sign_capture_record",
]
