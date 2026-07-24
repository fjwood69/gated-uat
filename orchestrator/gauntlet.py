"""orchestrator/gauntlet.py — the B1 step-2 GAUNTLET (the per-cell stage runner).

The board manifest (step 1) is the signed EXPECTATION; the gauntlet produces the signed
OBSERVATIONS. For one board cell + its produced artifact, the gauntlet runs the ratified ordered
stages — ``static -> own_tests -> llm_review -> gate`` — and emits ONE signed ``cell_stage`` receipt
per stage. Every receipt binds three things (carry-in 1): the manifest anchor (``manifest_digest``),
the cell's ``planned_run_id`` (the receipt's run_id), and the ONE ``artifact_tree_digest`` the whole
cell is verified against.

Structural laws (made true-by-construction, not merely intended):

  * ONE IMMUTABLE ARTIFACT PER ROW (amendment 3). The artifact is SEALED once per cell into a
    content-addressed archive (``seal_artifact``); its ``core.tree_hash`` IS the digest bound in
    every stage receipt.

  * CAPABILITY-DELETION, not a before/after tripwire (gap-1). No stage is handed a generic
    host-writable tree. The stage seam is ``StageFn = Callable[[SealedArtifact], ...]``:
    each stage provisions its OWN isolation directly from the seal —

      - ``static`` + ``own_tests`` extract a fresh view and hand it to a hermetic ``OCISandbox``,
        binding the SEALED digest (never a re-measurement of the view): ``prepare()`` copytrees the
        view into its OWN immutable snapshot, re-hashes THAT snapshot, and RAISES
        ``ArtifactHashMismatchError`` if it != the sealed digest — so an extract->copytree
        mutation window is closed by the pin, not by an after-hash we control (FOLD-A);
      - ``llm_review`` reads NO host tree at all: it serialises the sealed artifact's file bytes
        into a canonical, versioned, domain-separated document (``canonical_review_source``) that a
        reader can reconstruct ``artifact_tree_digest`` from (FOLD-B), and the review client seam is
        ``(request_bytes, ...)`` — bytes-in/response-out, no host-fs access (transmit-restriction to
        the completion path is the Step-3 provider-gate, NOT this seam);
      - ``gate`` extracts a fresh view for the real enforcement adapter, whose measured digest MUST
        equal the bound digest (P1 schema law).

    ``extract_view`` verifies the extracted view == the seal BEFORE yielding; its AFTER-hash is
    honest P3 operator-error DETECTION only (the real isolation is downstream). ``materialise`` +
    ``_chmod_tree`` (the chmod/after-hash "proof" the board ruled theater) are DELETED.

  * UNIFORM TREE POLICY (P1 hardening). ``assert_safe_artifact_tree`` rejects symlinks / HARDLINKS
    (st_nlink>1) / special files up front — the SAME class the gate's tarball path rejects.

  * COHERENCE IS SCHEMA LAW ON EVERY STAGE (dissent). A signed receipt whose outcome contradicts its
    measurement is unrepresentable — encoded in schemas.validate_cell_stage_payload.

  * HARNESS-HONEST ERRORS + CELL-LEVEL PUBLISHING. A stage crash / bad view -> a PUBLISHED ERROR
    receipt ({"harness_error"}). A pre-stage failure publishes an ERROR receipt for EVERY planned
    stage (``run_gauntlet``) so no planned cell vanishes from the denominator.

``gate.*`` / ``sandbox.*`` / ``core.chain`` imports are DEFERRED into the functions that need them
so this module imports with only ``core`` + sibling ``orchestrator`` modules on the path.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import tree_hash
from nacl.signing import SigningKey

from .evidence import Receipt, build_receipt
from .schemas import (
    GATE_CELL_OUTCOME_BY_KIND,
    OWN_TESTS_CELL_OUTCOME,
    UNMEASURABLE_TREE_DIGEST,
    expected_pytest_status,
)

CELL_STAGE_KIND = "cell_stage"
# The ratified ordered gauntlet (build order == run order).
GAUNTLET_STAGES: tuple[str, ...] = ("static", "own_tests", "llm_review", "gate")
# The reserved sentinel bound on a cell-level ERROR receipt when the artifact could NOT be safely
# materialised or hashed. Canonical in schemas; a RESERVED value made unreachable for a normal
# receipt by the sentinel schema law (forces outcome=error + harness_error), not by crypto accident.
UNMEASURABLE_DIGEST = UNMEASURABLE_TREE_DIGEST

# Container mount points (== sandbox.oci.ARTIFACT_MOUNT / WORK_DIR — literals to keep the pin import
# deferred; a drift would be caught by the real-podman keystone).
_ARTIFACT_MOUNT = "/artifact"
_WORK_DIR = "/work"

# The pinned in-container static toolchain invocations (ruff + mypy), run over the :ro /artifact
# mount with caches directed at the writable tmpfs /work. The TOOLCHAIN identity is the sandbox
# image's resolved config digest (asserted == manifest env_digest), which subsumes per-exe digests.
_RUFF_ARGV: tuple[str, ...] = (
    "ruff", "check", "--no-fix", "--cache-dir", "/work/ruff", "/artifact")
_MYPY_ARGV: tuple[str, ...] = (
    "mypy", "--cache-dir", "/work/mypy", "--no-error-summary", "/artifact")
# The producer suite, run inside the container over the ro artifact. ``-B`` keeps __pycache__ out of
# the read-only /artifact; ``-p no:cacheprovider`` writes no .pytest_cache; cwd is the tmpfs /work.
_PYTEST_ARGV: tuple[str, ...] = (
    "python3", "-B", "-m", "pytest", "/artifact", "-p", "no:cacheprovider", "-q")


class DigestMismatchError(RuntimeError):
    """An extracted stage view's ``tree_hash`` != the sealed digest (verified on extraction). The
    view is not the sealed artifact — surfaced as a PUBLISHED ERROR, never a silent rerun."""


class UnsafeArtifactError(ValueError):
    """The artifact tree contains a symlink / hardlink / special file / duplicate path — rejected up
    front (the SAME policy the gate's tarball extractor enforces) so the gauntlet's staging paths
    cannot diverge from the gate's (P1 hardening)."""


class HarnessMisconfigError(RuntimeError):
    """The cell could not be dispatched (e.g. stage_fns missing a required stage). Harness
    misconfiguration is an OUTCOME the denominator must represent — caught inside the cell perimeter
    and published as four ERROR receipts, never allowed to escape run_gauntlet (dissent gap 2a)."""


# ------------------------------------------------------------------
# Cell context + the pure per-stage result
# ------------------------------------------------------------------


@dataclass(frozen=True)
class CellContext:
    """The signed-into-every-receipt identity of one board cell, echoed from the manifest.

    ``planned_run_id`` is the manifest's UUID4 for this cell; it is the ``cell_stage`` receipt's
    run_id (envelope-signed). ``manifest_digest`` is the signed manifest receipt's digest (anchor).
    ``reviewer_lineage`` != ``lineage``.
    """

    manifest_digest: str      # hex64 — the signed board-manifest receipt digest (anchor)
    planned_run_id: str       # UUID4 — the manifest cell's planned_run_id (== receipt run_id)
    cell_id: str              # task_id/lineage/replicate (== a manifest cell_id)
    lineage: str              # producing lineage
    reviewer_lineage: str     # cross-lineage reviewer (!= lineage)
    side: str                 # tempting | clean


@dataclass(frozen=True)
class StageObservation:
    """The pure result of running one stage over the sealed artifact — turned into a signed receipt
    by ``build_cell_stage_receipt``. ``outcome`` is one of schemas.VALID_CELL_OUTCOMES;
    ``observation`` is the stage-shaped observation dict (validated at receipt-build time)."""

    stage: str
    outcome: str
    observation: dict[str, Any]


# ------------------------------------------------------------------
# Harness identity + time
# ------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def harness_code_sha() -> str:
    """A DETERMINISTIC content digest of the harness SOURCE (orchestrator/*.py): a sorted map of
    (filename -> sha256(source bytes)), hashed. Identifies the harness that produced the receipt;
    labelled NON-authz (it authorises nothing). Same construction as the enforcement driver's."""
    pkg = Path(__file__).resolve().parent
    entries = [[p.name, hashlib.sha256(p.read_bytes()).hexdigest()]
               for p in sorted(pkg.glob("*.py"))]
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------
# The immutable artifact + the fresh per-stage view
# ------------------------------------------------------------------


def assert_safe_artifact_tree(root: Path) -> None:
    """Reject an artifact tree containing a symlink, HARDLINK, or special file (device/fifo/etc) —
    the SAME class the gate's ``safe_extract_tarball`` rejects. This keeps ``core.tree_hash`` over
    the tree = ``F:``-only, so the sandbox copy and the gate adapter copy canonicalise identically
    (P1 hardening). Hardlinks are DETECTED (``st_nlink > 1`` on a regular file), not merely
    claimed."""
    if not root.exists():
        raise UnsafeArtifactError(f"artifact path does not exist: {root}")
    if root.is_symlink():
        raise UnsafeArtifactError(f"artifact root is a symlink: {root}")
    paths = [root] if root.is_file() else [
        Path(dp) / n for dp, dns, fns in os.walk(root) for n in (*dns, *fns)]
    for p in paths:
        if p.is_symlink():
            raise UnsafeArtifactError(f"symlink rejected (uniform with the gate path): {p}")
        if not p.is_dir() and not p.is_file():
            raise UnsafeArtifactError(f"special file rejected (not a regular file/dir): {p}")
        # a hardlinked regular file has st_nlink > 1 (dirs legitimately do, so files only).
        if p.is_file() and not p.is_dir() and p.stat().st_nlink > 1:
            raise UnsafeArtifactError(f"hardlink rejected (st_nlink={p.stat().st_nlink}): {p}")


@dataclass(frozen=True)
class SealedArtifact:
    """The artifact sealed ONCE as a content-addressed archive. ``digest`` == ``core.tree_hash`` of
    the tree == the ``artifact_tree_digest`` bound in every cell receipt. ``archive`` is a read-only
    tar (top-level prefix ``artifact/``) — the single immutable source from which each stage
    provisions a FRESH view (or reads canonical bytes). Frozen: no stage can redirect it."""

    archive: Path
    digest: str


class SealError(RuntimeError):
    """The artifact could not be sealed into its immutable archive (a copy/tar failure). A
    cell-level failure — run_gauntlet publishes an ERROR receipt for every stage rather than
    dropping the cell."""


@contextmanager
def seal_artifact(artifact_dir: Path) -> Iterator[SealedArtifact]:
    """Seal the artifact into an immutable content-addressed archive and yield it. Rejects an unsafe
    tree first (symlink/hardlink/special). The archive is written read-only; ``digest`` is
    ``core.tree_hash`` of the ORIGINAL tree (== every stage's bound digest). Purged on exit."""
    import tarfile
    assert_safe_artifact_tree(artifact_dir)
    if not artifact_dir.is_dir():
        # B1 artifacts are directory TREES. A file-root hashes under core.tree_hash's "" relpath
        # rule but seals under 'artifact/<name>', so canonical_review_source could not reconstruct
        # sealed.digest (consult P1). Forbid it rather than carry a special case.
        raise UnsafeArtifactError(f"artifact must be a directory tree, not a file: {artifact_dir}")
    digest = tree_hash(artifact_dir)
    seal_dir = Path(tempfile.mkdtemp(prefix="gauntlet-seal-"))
    try:
        archive = seal_dir / "artifact.tar"
        try:
            with tarfile.open(archive, "w") as tf:
                tf.add(artifact_dir, arcname="artifact", recursive=True)
            os.chmod(archive, 0o444)  # read-only seal
        except (OSError, tarfile.TarError) as exc:
            raise SealError(f"could not seal artifact {artifact_dir}: {exc}") from exc
        yield SealedArtifact(archive=archive, digest=digest)
    finally:
        shutil.rmtree(seal_dir, ignore_errors=True)


def verify_tree(tree: Path, expected_digest: str) -> None:
    """Raise DigestMismatchError if ``tree_hash(tree) != expected_digest``."""
    actual = tree_hash(tree)
    if actual != expected_digest:
        raise DigestMismatchError(
            f"artifact_tree_digest mismatch: expected {expected_digest!r}, tree is {actual!r}")


@contextmanager
def extract_view(sealed: SealedArtifact) -> Iterator[Path]:
    """Extract a FRESH, ephemeral view of the sealed artifact for ONE stage's re-isolating consumer
    (an ``OCISandbox`` mount source, or the gate adapter's copy source), and discard it after.

    Extraction uses the gate's own trusted ``safe_extract_tarball`` (so every stage canonicalises
    identically), then the view is verified == the seal BEFORE it is yielded. There is NO chmod: the
    view is not the measured surface — the consumer re-isolates (the sandbox copytrees the view into
    its OWN immutable snapshot and re-hashes THAT against the sealed digest; the gate adapter
    re-copies + re-measures). The AFTER verify is honest P3 operator-error DETECTION (a drift flags
    harness/operator error), NOT a security proof — the downstream re-measurement is the proof."""
    from gate.artifact import safe_extract_tarball
    view = Path(tempfile.mkdtemp(prefix="gauntlet-view-"))
    try:
        safe_extract_tarball(sealed.archive, view)
        verify_tree(view, sealed.digest)   # the extracted view IS the sealed bytes, or we refuse
        yield view
        verify_tree(view, sealed.digest)   # P3 DETECTION only (downstream re-measurement is proof)
    finally:
        shutil.rmtree(view, ignore_errors=True)


# ------------------------------------------------------------------
# The signed cell_stage receipt
# ------------------------------------------------------------------


def build_cell_stage_receipt(
    cell: CellContext,
    stage: str,
    outcome: str,
    observation: dict[str, Any],
    artifact_tree_digest: str,
    signing_key: SigningKey,
) -> Receipt:
    """Assemble + sign one ``cell_stage`` receipt. ``build_receipt`` validates the payload
    (schemas.validate_cell_stage_payload) BEFORE signing, so an incoherent observation, a bad
    outcome, or a gate ``measured_tree_digest`` != the bound digest (P1) is rejected at mint — an
    unsignable lie, not a stored one. The receipt run_id is the cell's ``planned_run_id``."""
    payload: dict[str, Any] = {
        "schema_version": 1,
        "manifest_digest": cell.manifest_digest,
        "cell_id": cell.cell_id,
        "lineage": cell.lineage,
        "reviewer_lineage": cell.reviewer_lineage,
        "side": cell.side,
        "stage": stage,
        "artifact_tree_digest": artifact_tree_digest,
        "outcome": outcome,
        "executed_at": _now_iso(),
        "code_sha": harness_code_sha(),
        "observation": observation,
    }
    return build_receipt(CELL_STAGE_KIND, cell.planned_run_id, payload, signing_key)


def _error_receipt(
    cell: CellContext, stage: str, artifact_tree_digest: str, reason: str, signing_key: SigningKey,
) -> Receipt:
    """A PUBLISHED ERROR receipt for a stage that could not honestly measure (digest mismatch or an
    unexpected crash). Outcome=error; observation is the canonical harness-error record."""
    return build_cell_stage_receipt(
        cell, stage, "error", {"harness_error": reason}, artifact_tree_digest, signing_key)


# A stage is a pure function of the SEALED artifact — each stage provisions its OWN isolation from
# the seal (extract_view into a re-isolating consumer, or canonical bytes). No generic
# host-writable view seam exists (gap-1 capability-deletion).
StageFn = Callable[[SealedArtifact], StageObservation]


def run_stage(
    cell: CellContext,
    sealed: SealedArtifact,
    artifact_tree_digest: str,
    stage: str,
    stage_fn: StageFn,
    signing_key: SigningKey,
) -> Receipt:
    """Run ONE stage over the sealed artifact and return its signed receipt.

    The stage provisions its own isolation from the seal; ANY exception (a provisioning failure, an
    extract_view DigestMismatchError, an image drift, or any crash) becomes a PUBLISHED ERROR
    receipt (outcome=error, harness_error) — the cell is never silently rerun. A normal return is
    turned into a signed receipt; a malformed observation is rejected by the schema at build time
    (fail-closed, surfaced as an ERROR receipt rather than an unsigned exception)."""
    try:
        result = stage_fn(sealed)
        if result.stage != stage:
            raise ValueError(f"stage_fn returned stage {result.stage!r}, expected {stage!r}")
        return build_cell_stage_receipt(
            cell, stage, result.outcome, result.observation, artifact_tree_digest, signing_key)
    except Exception as exc:  # noqa: BLE001 — any stage failure is a published ERROR row
        return _error_receipt(
            cell, stage, artifact_tree_digest, f"{type(exc).__name__}: {exc}", signing_key)


def run_gauntlet(
    cell: CellContext,
    artifact_dir: Path,
    stage_fns: dict[str, StageFn],
    signing_key: SigningKey,
) -> list[Receipt]:
    """Run the full ordered gauntlet for one cell and return the ordered list of signed cell_stage
    receipts (one per stage in ``GAUNTLET_STAGES``). The artifact is SEALED once (the immutable row
    artifact); each stage provisions a fresh view/bytes from the seal. ``stage_fns`` maps each stage
    name to its closure (image, env_digest, budget, reviewer).

    TOTAL CELL EXCEPTION PERIMETER (dissent gaps 1 + 2a): the ENTIRE per-cell dispatch — the
    stage_fns configuration check, the preflight (assert_safe, lstat-only, no open — a FIFO is
    rejected before hashing can block on it), the seal, and every stage — lives INSIDE one catch-all
    whose contract is "publish four ERROR receipts or die trying". No exception type exits
    ``run_gauntlet`` without filling the cell; raising is reserved for a failure of the PUBLISHING
    machinery itself, when the run is UNATTESTABLE the board must not render. The ERROR
    receipts bind the UNMEASURABLE sentinel; the sentinel schema law forces outcome=error +
    harness_error."""
    try:
        missing = [s for s in GAUNTLET_STAGES if s not in stage_fns]
        if missing:
            raise HarnessMisconfigError(f"stage_fns missing required stage(s): {missing}")
        with seal_artifact(artifact_dir) as sealed:
            return [run_stage(cell, sealed, sealed.digest, s, stage_fns[s], signing_key)
                    for s in GAUNTLET_STAGES]
    except Exception as exc:  # noqa: BLE001 — NO exit without filling the cell (four ERROR receipts)
        return [_error_receipt(cell, s, UNMEASURABLE_DIGEST,
                               f"cell_failure: {type(exc).__name__}: {exc}", signing_key)
                for s in GAUNTLET_STAGES]


# ------------------------------------------------------------------
# Canonical review source + the shared hermetic-sandbox runner
# ------------------------------------------------------------------


def _strip_seal_prefix(name: str) -> str | None:
    """Strip the seal's top-level ``artifact/`` component from a tar member name — IDENTICAL to the
    gate extractor's ``_strip_top_level`` (split on the first ``/``), so a review-source relpath ==
    the extracted-view relpath == the ``core.tree_hash`` relpath. None for the prefix dir."""
    parts = name.split("/", 1)
    return parts[1] if len(parts) == 2 and parts[1] else None


def build_review_source_payload(files: list[tuple[str, bytes]]) -> bytes:
    """The SINGLE sealed serializer for review-source bytes (Board #3 P3, Option A). Sort ``files``
    by RAW utf-8 relpath (mirroring ``core.tree_hash``), build the per-file ``{path_b64, sha256,
    content_b64}`` payload, and domain-separate via ``canonical_bytes``. ``canonical_review_source``
    (a sealed tar) and the Board #3 reviewable-wire auditor (wire-extracted ``(relpath, content)``)
    BOTH call this, so a ``source_digest`` recompute cannot DRIFT from the sealed form —
    the recompute is a REPLAY of one function, not a parallel reimplementation.

    Behaviour-preserving: byte-identical to the prior inline construction, so every existing
    ``source_digest`` is unchanged (3.1 / board #1 untouched). ``rel.encode('utf-8')`` fails closed
    on a non-utf-8 relpath (the existing path binding — no parallel path encoding is introduced)."""
    from core.chain import canonical_bytes
    ordered = sorted(files, key=lambda e: e[0].encode("utf-8"))
    payload = {
        "files": [
            {
                "path_b64": base64.b64encode(rel.encode("utf-8")).decode("ascii"),
                "sha256": hashlib.sha256(data).hexdigest(),
                "content_b64": base64.b64encode(data).decode("ascii"),
            }
            for rel, data in ordered
        ]
    }
    return canonical_bytes("gated-uat.review-source", payload)


def canonical_review_source(sealed: SealedArtifact) -> bytes:
    """Serialise the sealed artifact's FILE BYTES into a canonical, versioned, domain-separated
    document — the exact bytes the LLM reviewer is shown (FOLD-B). Reads the tar MEMBERS (not the
    raw tar bytes — tar metadata is not the artifact); sorts by the RAW utf-8 relpath (mirroring
    ``core.tree_hash``); records for each file its relpath (base64 — ASCII, so canonical_bytes' NFC
    normalisation cannot alter the raw path bytes), its ``sha256(bytes)``, and its content (base64).

    Reconstruction-exact: an auditor recomputes ``core.tree_hash`` from the (relpath, sha256) pairs
    (F:+sha256 per file, sorted by relpath, Merkle over rel\\0digest\\0) and confirms it equals
    the receipt's ``artifact_tree_digest`` — so ``source_digest`` verifiably corresponds to the
    sealed artifact. Duplicate relpaths (after strip) fail closed. Symlinks/specials cannot occur
    (the seal rejects them), so every entry is a regular file."""
    import tarfile

    files: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    with tarfile.open(sealed.archive, "r") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            rel = _strip_seal_prefix(member.name)
            if rel is None:
                continue
            if rel in seen:
                raise UnsafeArtifactError(f"duplicate path in sealed source: {rel!r}")
            seen.add(rel)
            src = tf.extractfile(member)
            files.append((rel, src.read() if src is not None else b""))
    files.sort(key=lambda e: e[0].encode("utf-8"))   # mirror core.tree_hash ordering exactly
    # In-stage fail-closed self-check (consult P2): reconstruct core.tree_hash's Merkle root
    # from (relpath, per-file sha256) using its EXACT construction (F:+sha256, rel\0digest\0 pairs,
    # sha256: prefix) and refuse if it != the sealed digest — a serializer drift can never ship a
    # source that does not correspond to the bound artifact_tree_digest.
    root_h = hashlib.sha256()
    for rel, data in files:
        entry = "F:" + hashlib.sha256(data).hexdigest()
        root_h.update(rel.encode("utf-8"))
        root_h.update(b"\0")
        root_h.update(entry.encode("utf-8"))
        root_h.update(b"\0")
    reconstructed = f"sha256:{root_h.hexdigest()}"
    if reconstructed != sealed.digest:
        raise DigestMismatchError(
            f"review source does not reconstruct the sealed digest: {reconstructed!r} != "
            f"{sealed.digest!r}")
    # Delegate the payload construction to the SINGLE sealed serializer (Board #3 P3, Option A) —
    # byte-identical to the prior inline build, and the exact function the reviewable-wire auditor
    # replays. ``files`` is already sorted above; the helper re-sorts idempotently.
    return build_review_source_payload(files)


# A sandbox factory: constructs a FRESH sandbox for one stage run (default: a real OCISandbox).
MakeSandbox = Callable[[], Any]


@dataclass(frozen=True)
class _SandboxRun:
    """The out-of-band facts a hermetic sandbox run yields: the resolved image config digest, the
    real isolation level, and per-argv exit codes (None if a run did not cleanly complete)."""

    image_digest: str
    isolation_level: str
    exit_codes: tuple[int | None, ...]


def _run_argvs_in_sandbox(
    sealed: SealedArtifact,
    *,
    image: str,
    argvs: tuple[tuple[str, ...], ...],
    budget_seconds: float,
    make_sandbox: MakeSandbox | None,
) -> _SandboxRun:
    """Extract a fresh view, prepare a FRESH hermetic sandbox over it BINDING THE SEALED DIGEST
    (FOLD-A: ``prepare()`` re-hashes its snapshot and raises if it != sealed.digest — so an
    extract->copytree mutation is caught by the pin, not an after-hash we control), run each argv in
    turn over the ro /artifact, and return the out-of-band facts. Teardown CONFIRMS destruction."""
    from core import ArtifactSpec, Command, Fixtures, ResourceBudget

    def _default_factory() -> Any:
        from sandbox.oci import OCISandbox
        return OCISandbox(image=image)

    factory = make_sandbox or _default_factory
    sandbox = factory()  # a fresh sandbox object per cell — never reused across runs (P2)
    # Record the sandbox's REAL isolation level; a weaker (or absent) level fails closed
    # at schema validation rather than being masked.
    level = getattr(getattr(sandbox, "isolation_level", None), "value", "unknown")
    with extract_view(sealed) as view:
        spec = ArtifactSpec(path=view, tree_hash=sealed.digest)  # FOLD-A: SEALED digest, not view's
        handle = sandbox.prepare(spec, Fixtures())
        try:
            results = [
                sandbox.run(handle, Command(argv=tuple(argv)),
                            ResourceBudget(wall_clock_seconds=budget_seconds))
                for argv in argvs
            ]
        finally:
            sandbox.teardown(handle)  # CONFIRMS destruction (SandboxLeakError if it cannot)
    image_digest = str(results[0].image_digest) if results else "unknown"
    exit_codes = tuple(
        int(r.exit_code) if (r.outcome == "completed" and r.exit_code is not None) else None
        for r in results)
    return _SandboxRun(image_digest=image_digest, isolation_level=str(level), exit_codes=exit_codes)


def _invocation_digest(image_digest: str, argvs: tuple[tuple[str, ...], ...]) -> str:
    """A canonical digest of exactly WHAT was run (image config digest + the ordered argvs + the ro
    mount + workdir) — bound into the observation so a static/own_tests pass is auditable (FOLD-C:
    guards a neutered invocation like ``ruff --select NOTHING`` that the exit code alone can't
    reveal)."""
    from core.chain import canonical_bytes
    payload = {
        "image_digest": image_digest,
        "mount": f"{_ARTIFACT_MOUNT}:ro",
        "workdir": _WORK_DIR,
        "argvs": [list(argv) for argv in argvs],
    }
    return hashlib.sha256(canonical_bytes("gated-uat.invocation", payload)).hexdigest()


# ------------------------------------------------------------------
# Stage: static (ruff + mypy IN-CONTAINER, over the ro /artifact) — no artifact runtime executes
# ------------------------------------------------------------------
#
# Static runs INSIDE the hermetic OCISandbox (not on the host): the sandbox image is the pinned
# toolchain, and its resolved config digest is ASSERTED == the manifest env_digest — pinning the
# image pins ruff + mypy (subsumes per-exe digests) and closes the host-side mypy-plugin-execution
# residual. The ONLY observation is the out-of-band exit code (stdout is DEVNULL in the sandbox);
# parsing tool stdout would re-trust the very output the sandbox deliberately discards. A static
# ``pass`` therefore means "the pinned tools exited 0", NOT "no static defects exist" (the artifact
# ships its own config and can suppress findings — on-thesis for the complicit-tooling demo;
# the gate is the boundary). The invocation vector is bound (FOLD-C) so what ran is auditable.


def static_stage(
    sealed: SealedArtifact,
    *,
    image: str,
    env_digest: str,
    ruff_argv: tuple[str, ...] = _RUFF_ARGV,
    mypy_argv: tuple[str, ...] = _MYPY_ARGV,
    budget_seconds: float = 120.0,
    make_sandbox: MakeSandbox | None = None,
) -> StageObservation:
    """Run ruff + mypy in the pinned hermetic sandbox over the ro artifact; assert the sandbox's
    resolved image config digest == the manifest ``env_digest`` (drift -> ERROR); observe exit codes
    only. outcome = pass iff both exit 0. A run that does not cleanly complete (timeout / sandbox
    error) raises -> a published ERROR receipt."""
    argvs = (ruff_argv, mypy_argv)
    run = _run_argvs_in_sandbox(
        sealed, image=image, argvs=argvs, budget_seconds=budget_seconds, make_sandbox=make_sandbox)
    if run.image_digest != env_digest:
        raise RuntimeError(
            f"static toolchain image drift: manifest env_digest {env_digest!r}, "
            f"sandbox ran {run.image_digest!r}")
    ruff_exit, mypy_exit = run.exit_codes[0], run.exit_codes[1]
    if ruff_exit is None or mypy_exit is None:
        raise RuntimeError(f"static sandbox run did not complete: exits={run.exit_codes!r}")
    outcome = "pass" if (ruff_exit == 0 and mypy_exit == 0) else "fail"
    return StageObservation(
        stage="static",
        outcome=outcome,
        observation={
            "env_digest": run.image_digest,
            "ruff_exit": ruff_exit,
            "mypy_exit": mypy_exit,
            "invocation_digest": _invocation_digest(run.image_digest, argvs),
        },
    )


# ------------------------------------------------------------------
# Stage: own_tests (the SECURITY-SENSITIVE stage) — the producer's pytest, hermetically
# ------------------------------------------------------------------
#
# own-tests GREEN on the evasion is the demonstration — the producer's tests are complicit; that is
# the thesis of the board. Do not make this stage catch the evasion.
#
# The stage runs the PRODUCER'S OWN pytest suite inside a fresh hermetic OCISandbox (the SAME
# isolation the gate uses): /artifact mounted read-only (bound to the SEALED digest — FOLD-A),
# --network=none, sterile env, writable tmpfs /work, teardown that CONFIRMS container destruction.
# The ONLY observation is the container EXIT CODE, read out-of-band — never the producer's stdout.


def own_tests_stage(
    sealed: SealedArtifact,
    *,
    image: str,
    budget_seconds: float = 120.0,
    make_sandbox: MakeSandbox | None = None,
    pytest_argv: tuple[str, ...] = _PYTEST_ARGV,
) -> StageObservation:
    """Run the producer's pytest in a FRESH hermetic sandbox over the sealed artifact; observe ONLY
    the out-of-band container exit code. Isolation is the gate's (HERMETIC). own-tests GREEN on the
    evasion is intentional (the thesis) — this stage never inspects WHAT the tests assert."""
    argvs = (pytest_argv,)
    run = _run_argvs_in_sandbox(
        sealed, image=image, argvs=argvs, budget_seconds=budget_seconds, make_sandbox=make_sandbox)
    exit_code = run.exit_codes[0]
    # status + outcome via the CANONICAL schema maps (single source; own_tests + schema agree). A
    # non-completing run (exit None) -> status 'error' -> cell outcome 'error'.
    status = expected_pytest_status(exit_code)
    return StageObservation(
        stage="own_tests",
        outcome=OWN_TESTS_CELL_OUTCOME[status],
        observation={
            "sandbox_isolation_level": run.isolation_level,
            "image_digest": run.image_digest,
            "container_exit_code": exit_code,
            "pytest_status": status,
            "invocation_digest": _invocation_digest(run.image_digest, argvs),
        },
    )


# ------------------------------------------------------------------
# Stage: llm_review (a MEASUREMENT stage, NOT a security boundary)
# ------------------------------------------------------------------
#
# A cross-lineage reviewer (reviewer_lineage != lineage, fixed by the manifest) reviews the sealed
# artifact under a FIXED, PUBLISHED review prompt (its hash committed in the manifest) and returns a
# STRUCTURED verdict. Strict ``approve`` -> PASS. CONTAINMENT IS STRUCTURAL (consult P1): the STAGE
# builds the canonical request envelope that EMBEDS the sealed source bytes and computes
# ``request_digest`` over THOSE bytes — the client is handed the request to transmit and cannot
# substitute a different body while still matching the bound digest. Two independent digests
# (source, request) don't prove containment; a harness-built request that embeds the source does.
# The client seam is bytes-in/bytes-out — never a host path — so it cannot read the host filesystem.
# CLAIM SCOPE (Board-held): the harness BUILT a canonical request embedding the sealed source
# and digested it, and the client seam is bytes-in/response-out with no host-fs access. It does NOT
# claim the client TRANSMITTED those bytes verbatim (that is the Step-3 provider-gate, unbuilt) nor
# that the model "saw it and nothing else". Containment is end-to-end ONLY once the provider-gate
# lands. The reviewer is a MEASUREMENT, not a boundary.


@dataclass(frozen=True)
class ReviewOutcome:
    """What the reviewer client returned: the structured verdict, the provider/model identity, and
    the raw response bytes (digested into the receipt, never stored). The client does NOT supply the
    request — the stage builds it (containment is structural, not the client's word) — so a fooled
    or hallucinated verdict is a measurement error, never a breach."""

    verdict: str            # 'approve' | 'request_changes' (schema-validated at receipt build)
    provider_id: str
    model_id: str
    raw_response: bytes     # the exact bytes received from the reviewer (digested, not stored)


# A review client: (request_bytes, reviewer_lineage, review_prompt_hash) -> ReviewOutcome. Handed
# EXACT request bytes the stage built (embedding the sealed source), never a host path. Injected so
# B1 can drive it manually / with a deterministic fake; a real client is a completion-only egress
# that transmits request_bytes verbatim (see the provider-gate ReviewClient).
ReviewClient = Callable[[bytes, str, str], ReviewOutcome]

# A review-request builder: (source_bytes, reviewer_lineage, review_prompt_hash) -> request_bytes.
# DEFAULT = _canonical_review_request (the gated-uat envelope) so board #1 + ALL 3.1 request_digests
# stay byte-identical. Board #2 injects a builder that emits a REAL provider API body
# (live_review.AnthropicMessagesRequestBuilder) — the additive (C) exception to injection-only.
ReviewRequestBuilder = Callable[[bytes, str, str], bytes]


def _canonical_review_request(
    source_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
) -> bytes:
    """Build the canonical review REQUEST envelope — a versioned, domain-separated document that
    EMBEDS the sealed source bytes (base64). ``request_digest`` = sha256 of THESE bytes, so the
    receipt's containment claim is structural: the harness built the request, and a client cannot
    substitute a different body and still match the bound digest (consult P1 fold)."""
    from core.chain import canonical_bytes
    return canonical_bytes("gated-uat.review-request", {
        "review_prompt_hash": review_prompt_hash,
        "reviewer_lineage": reviewer_lineage,
        "source_b64": base64.b64encode(source_bytes).decode("ascii"),
    })


def llm_review_stage(
    sealed: SealedArtifact,
    *,
    reviewer_lineage: str,
    review_prompt_hash: str,
    review_client: ReviewClient,
    build_request: ReviewRequestBuilder = _canonical_review_request,
) -> StageObservation:
    """Serialise the sealed artifact to canonical source bytes (self-checked to reconstruct the
    sealed digest), BUILD the review request (``build_request``; default = the canonical envelope,
    board #2 = a real provider body), hand the exact request bytes to the (bytes-in/response-out)
    review client, and record it. ``outcome`` = pass iff the verdict is exactly ``approve``. Binds
    ``source_digest`` (the sealed source) and ``request_digest`` (whatever the builder produced,
    which EMBEDS the source — containment is structural) + ``response_digest``. Measurement, not
    security. ``build_request`` is additive: with the default, request bytes/digest are unchanged
    from before (3.1 preserved)."""
    source_bytes = canonical_review_source(sealed)
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    request_bytes = build_request(source_bytes, reviewer_lineage, review_prompt_hash)
    request_digest = hashlib.sha256(request_bytes).hexdigest()
    result = review_client(request_bytes, reviewer_lineage, review_prompt_hash)
    response_digest = hashlib.sha256(result.raw_response).hexdigest()
    outcome = "pass" if result.verdict == "approve" else "fail"
    return StageObservation(
        stage="llm_review",
        outcome=outcome,
        observation={
            "provider_id": result.provider_id,
            "model_id": result.model_id,
            "review_prompt_hash": review_prompt_hash,
            "source_digest": source_digest,
            "request_digest": request_digest,
            "response_digest": response_digest,
            "verdict": result.verdict,
        },
    )


# ------------------------------------------------------------------
# Stage: gate (the existing enforcement machinery) — P1: bind the tree the gate ACTUALLY measured
# ------------------------------------------------------------------
#
# The gate is gated's REAL enforcement path. The consult's load-bearing P1 finding: the adapter
# selects + copies its OWN source and measures its OWN tree_hash at a source-selection seam, so a
# receipt that merely bound the cell's expected digest could certify a DIFFERENT tree than the gate
# evaluated (a false green). The fix is a SCHEMA LAW (schemas.validate_cell_stage_payload): the gate
# observation carries the digest the adapter ACTUALLY measured (``measured_tree_digest``), and the
# orchestrator refuses to sign unless it equals the cell's bound ``artifact_tree_digest``. The gate
# receives a fresh extract_view of the sealed artifact.


@dataclass(frozen=True)
class GateMeasurement:
    """The gate's real projection, plus the digest it ACTUALLY measured. ``result_kind`` is a
    VALID_RESULT_KINDS discriminator; ``admitted_outcome`` is 'pass'|'fail' for admitted_run (else
    None); ``measured_tree_digest`` is the ``sha256:<hex>`` the enforcement adapter captured at its
    source-selection seam — the P1 anchor the cell outcome is only valid against."""

    result_kind: str
    result_reason: str
    result_sub_reason: str
    gate_outcome: str | None
    admitted_outcome: str | None    # 'pass'|'fail' for admitted_run; None otherwise
    measured_tree_digest: str


# A gate runner: view -> GateMeasurement. Injected so B1 can drive the real adapter at fanout / a
# real-podman keystone, and unit-test the stage (incl. the P1 law) with a fake.
GateRunner = Callable[[Path], GateMeasurement]


def gate_stage(sealed: SealedArtifact, *, gate_runner: GateRunner) -> StageObservation:
    """Run the artifact through the real gate over a fresh extract_view and bind the digest the gate
    MEASURED. The cell outcome is DERIVED from ``result_kind`` (admitted->its verdict,
    blocking_refusal->blocked, else->error) via the canonical schema map — never taken on trust from
    the runner. If the gate measured a different tree than the cell bound, the receipt is unsignable
    (P1)."""
    with extract_view(sealed) as view:
        m = gate_runner(view)
    if m.result_kind == "admitted_run":
        outcome = m.admitted_outcome or "error"
    else:
        outcome = GATE_CELL_OUTCOME_BY_KIND.get(m.result_kind, "error")
    return StageObservation(
        stage="gate",
        outcome=outcome,
        observation={
            "result_kind": m.result_kind,
            "result_reason": m.result_reason,
            "result_sub_reason": m.result_sub_reason,
            "gate_outcome": m.gate_outcome,
            "measured_tree_digest": m.measured_tree_digest,
        },
    )


def gate_measurement_from_enforcement(
    enforcement_outcome: Any, measured_tree_digest: str
) -> GateMeasurement:
    """Map a real ``enforcement_driver.EnforcementOutcome`` + the tree_hash the adapter captured at
    its source-selection seam into a GateMeasurement. Used by the fanout / keystone that drives the
    real GatedEnforcementAdapter; ``measured_tree_digest`` is the adapter's captured
    ``artifact_tree_hash`` (for an admitted run) or the staged spec.tree_hash — the digest the gate
    actually evaluated, which the P1 law then checks against the cell's bound digest."""
    eo = enforcement_outcome
    admitted = eo.outcome if eo.result_kind == "admitted_run" else None
    return GateMeasurement(
        result_kind=str(eo.result_kind),
        result_reason=str(eo.reason),
        result_sub_reason=str(eo.sub_reason),
        gate_outcome=eo.gate_outcome,
        admitted_outcome=admitted,
        measured_tree_digest=measured_tree_digest,
    )
