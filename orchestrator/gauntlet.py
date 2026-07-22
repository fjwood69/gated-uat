"""orchestrator/gauntlet.py — the B1 step-2 GAUNTLET (the per-cell stage runner).

The board manifest (step 1) is the signed EXPECTATION; the gauntlet produces the signed
OBSERVATIONS. For one board cell + its produced artifact, the gauntlet runs the ratified ordered
stages — ``static -> own_tests -> llm_review -> gate`` — and emits ONE signed ``cell_stage`` receipt
per stage. Every receipt binds three things (carry-in 1): the manifest anchor (``manifest_digest``),
the cell's ``planned_run_id`` (the receipt's run_id), and the ONE ``artifact_tree_digest`` the whole
cell is verified against.

Structural laws (made true-by-construction, not merely intended):

  * ONE IMMUTABLE ARTIFACT PER ROW (amendment 3), by CONSTRUCTION not patrol (dissent P1). The
    artifact is SEALED once per cell into a content-addressed archive (``seal_artifact``); its
    ``core.tree_hash`` IS the digest bound in every stage receipt. Each stage materialises a FRESH,
    ephemeral view from the seal (``materialise``, via the gate's own ``safe_extract_tarball``),
    verified == the seal on extraction, discarded after. No mutable tree is shared across stages, so
    a mutate->measure->restore attack has nothing persistent to restore into — capability-deletion,
    not a before/after tripwire. The bound digest is the SEAL's, never re-measured from a stage's
    (possibly-tampered) view.

  * UNIFORM TREE POLICY (P1 hardening). ``assert_safe_artifact_tree`` rejects symlinks / HARDLINKS
    (st_nlink>1, actually detected) / special files up front — the SAME class the gate's tarball
    path rejects — and every stage extracts through that same tarball path, so the staging paths
    canonicalise identically. Combined with the gate receipt binding the digest the adapter ACTUALLY
    measured (schema law), the source-selection false-green vector is unrepresentable.

  * COHERENCE IS SCHEMA LAW ON EVERY STAGE (dissent — swept across all four producers). A signed
    receipt whose outcome contradicts its measurement (own_tests exit!=status, static non-zero-exit
    'pass', reviewer request_changes 'pass', gate_outcome incoherent with result_kind per the real
    account()) is unrepresentable — encoded in schemas.validate_cell_stage_payload.

  * HARNESS-HONEST ERRORS + CELL-LEVEL PUBLISHING. A stage crash / bad view -> a PUBLISHED ERROR
    receipt ({"harness_error"}). A pre-stage failure (unsafe tree / seal failure) publishes an ERROR
    receipt for EVERY planned stage (``run_gauntlet``), so no planned cell vanishes from the
    denominator (amendment 2 under every failure geometry) — a publishing path, never an escape.

``gate.*`` / ``sandbox.*`` imports are DEFERRED into the functions that need them so this module
imports with only ``core`` + sibling ``orchestrator`` modules on the path.
"""

from __future__ import annotations

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
    expected_pytest_status,
)

CELL_STAGE_KIND = "cell_stage"
# The ratified ordered gauntlet (build order == run order).
GAUNTLET_STAGES: tuple[str, ...] = ("static", "own_tests", "llm_review", "gate")
# Reserved sentinel digest bound on a cell-level ERROR receipt when the artifact could NOT be safely
# materialised or hashed (unsafe tree / FIFO / missing / unreadable) — sha256 of all-zeros
# is cryptographically impossible, so it can never collide with a real tree_hash.
UNMEASURABLE_DIGEST = "sha256:" + "0" * 64


class DigestMismatchError(RuntimeError):
    """A materialised stage view's ``tree_hash`` != the sealed digest (verified on extraction).
    A mismatch means the view is not the sealed artifact — the stage's observation is void.
    Surfaced as a PUBLISHED ERROR receipt, never a silent rerun (amendment 3)."""


class UnsafeArtifactError(ValueError):
    """The artifact tree contains a symlink / hardlink / special file — rejected up front (the SAME
    policy the gate's tarball extractor enforces) so the gauntlet's staging paths cannot diverge
    from the gate's on link representation (P1 hardening)."""


# ------------------------------------------------------------------
# Cell context + the pure per-stage result
# ------------------------------------------------------------------


@dataclass(frozen=True)
class CellContext:
    """The signed-into-every-receipt identity of one board cell, echoed from the manifest.

    ``planned_run_id`` is the manifest's UUID4 for this cell; it is the ``cell_stage`` receipt's
    run_id (envelope-signed) — so "binds planned_run_id" (carry-in 1) is structural.
    ``manifest_digest`` is the signed manifest receipt's digest (the board anchor).
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
    """The pure result of running one stage over the immutable snapshot — turned into a signed
    receipt by ``build_cell_stage_receipt``. ``outcome`` is one of schemas.VALID_CELL_OUTCOMES;
    ``observation`` is the stage-shaped observation dict (validated at receipt-build time)."""

    stage: str
    outcome: str
    observation: dict[str, Any]


# A stage is a pure function of the immutable snapshot path. Callers close over any extra inputs
# (image digest, budget, review client) so the cell runner stays generic.
StageFn = Callable[[Path], StageObservation]


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
# The immutable artifact + the before/after digest guard
# ------------------------------------------------------------------


def assert_safe_artifact_tree(root: Path) -> None:
    """Reject an artifact tree containing a symlink, HARDLINK, or special file (device/fifo/etc) —
    the SAME class the gate's ``safe_extract_tarball`` rejects. Source trees rarely need links; a
    tree that does fails closed. This keeps ``core.tree_hash`` over the tree = ``F:``-only, so the
    own_tests sandbox copy and the gate adapter copy canonicalise identically (P1 hardening).

    Hardlinks are DETECTED, not merely claimed (dissent): a regular file with ``st_nlink > 1``
    shares
    an inode with another name — rejected, so a claimed rejection is one we actually perform."""
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
    materialises a FRESH, ephemeral view. No mutable tree is shared across stages, so a
    mutate->measure->restore attack has nothing persistent to restore into (dissent P1: immutability
    by construction, not by a before/after tripwire)."""

    archive: Path
    digest: str


class SealError(RuntimeError):
    """The artifact could not be sealed into its immutable archive (a copy/tar failure). A
    cell-level
    failure — run_gauntlet publishes an ERROR receipt for every stage rather than dropping the
    cell."""


@contextmanager
def seal_artifact(artifact_dir: Path) -> Iterator[SealedArtifact]:
    """Seal the artifact into an immutable content-addressed archive and yield it. Rejects an unsafe
    tree first (symlink/hardlink/special). The archive is written read-only; ``digest`` is
    ``core.tree_hash`` of the ORIGINAL tree (== every stage's bound digest). Purged on exit."""
    import tarfile
    assert_safe_artifact_tree(artifact_dir)
    digest = tree_hash(artifact_dir)
    seal_dir = Path(tempfile.mkdtemp(prefix="gauntlet-seal-"))
    try:
        archive = seal_dir / "artifact.tar"
        try:
            with tarfile.open(archive, "w") as tf:
                if artifact_dir.is_dir():
                    tf.add(artifact_dir, arcname="artifact", recursive=True)
                else:
                    tf.add(artifact_dir, arcname=f"artifact/{artifact_dir.name}")
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


def _chmod_tree(root: Path, *, writable: bool) -> None:
    """Recursively set every entry read-only (dirs 0o555, files 0o444) or restore write (dirs 0o755,
    files 0o644). Owner-chmod succeeds regardless of a parent dir's write bit; restore precedes the
    rmtree so a read-only view can be purged."""
    for p in (root, *root.rglob("*")):
        try:
            if writable:
                p.chmod(0o755 if p.is_dir() else 0o644)
            else:
                p.chmod(0o555 if p.is_dir() else 0o444)
        except OSError:
            pass


@contextmanager
def materialise(sealed: SealedArtifact) -> Iterator[Path]:
    """Materialise a FRESH, ephemeral, READ-ONLY view of the sealed artifact for ONE stage.

    Extraction uses the gate's own trusted ``safe_extract_tarball`` (so every stage canonicalises
    identically), then the view is verified == the seal (BEFORE), chmod'd unwritable at
    the filesystem level, yielded, and re-verified == the seal (AFTER) — the after-check is the
    cryptographic PROOF the read-only constraint held during the stage (dissent gap 2), not mere
    defence-in-depth. A stage that tries to write its view fails with an OS error; a stage that
    somehow mutated it fails the after-check -> a published ERROR receipt. (own_tests gets the
    STRONGER form — a ``:ro`` bind mount inside the OCISandbox.)"""
    from gate.artifact import safe_extract_tarball
    view = Path(tempfile.mkdtemp(prefix="gauntlet-view-"))
    try:
        safe_extract_tarball(sealed.archive, view)
        verify_tree(view, sealed.digest)   # BEFORE: the view IS the sealed bytes, or we refuse
        _chmod_tree(view, writable=False)  # genuinely read-only at the FS level
        yield view
        verify_tree(view, sealed.digest)   # AFTER: proof the read-only constraint held this stage
    finally:
        _chmod_tree(view, writable=True)   # restore write so the view can be purged
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


def run_stage(
    cell: CellContext,
    sealed: SealedArtifact,
    artifact_tree_digest: str,
    stage: str,
    stage_fn: StageFn,
    signing_key: SigningKey,
) -> Receipt:
    """Run ONE stage over a FRESH materialised view of the sealed artifact and return its signed
    receipt.

    A materialise DigestMismatchError, a bad extraction, or ANY unexpected exception from the stage
    becomes a PUBLISHED ERROR receipt (outcome=error, harness_error) — the cell is never silently
    rerun. A normal return is turned into a signed receipt from the stage's ``StageObservation``; if
    that observation is malformed the schema rejects it at build time (fail-closed, surfaced as an
    ERROR receipt rather than an unsigned exception)."""
    try:
        with materialise(sealed) as view:   # fresh, ephemeral, verified == the seal
            result = stage_fn(view)
        if result.stage != stage:
            raise ValueError(f"stage_fn returned stage {result.stage!r}, expected {stage!r}")
        return build_cell_stage_receipt(
            cell, stage, result.outcome, result.observation, artifact_tree_digest, signing_key)
    except DigestMismatchError as exc:
        return _error_receipt(cell, stage, artifact_tree_digest, f"materialise: {exc}", signing_key)
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
    artifact); each stage materialises a fresh view from the seal. ``stage_fns`` maps each stage
    name to its closure (image, budget, reviewer).

    CELL-LEVEL FAILURE PATH (dissent, amendment 2): the bound digest is computed BEFORE sealing so
    that an unsafe-tree or seal failure still publishes an ERROR receipt for EVERY planned stage —
    never a cell that vanishes from the denominator. The error path is a PUBLISHING path, not an
    escape hatch; the bijection planned-cells<->terminal-receipts holds under every failure
    geometry."""
    missing = [s for s in GAUNTLET_STAGES if s not in stage_fns]
    if missing:
        raise ValueError(f"stage_fns missing required stage(s): {missing}")
    # The preflight (assert_safe, lstat-only — no open) + the hash both live INSIDE the failure
    # perimeter, and safety is asserted BEFORE any hash: a FIFO / device is rejected by lstat before
    # ``_hash_file`` can block on it (the hang), a missing/unreadable path raises IO, and an
    # unsafe tree raises — ALL of which publish four ERROR receipts (bound to the UNMEASURABLE
    # sentinel, since the tree could not be safely hashed), so no cell vanishes from the denominator
    # by raising OR by hanging. ``seal_artifact`` asserts-then-hashes in that safe order.
    try:
        with seal_artifact(artifact_dir) as sealed:
            return [run_stage(cell, sealed, sealed.digest, s, stage_fns[s], signing_key)
                    for s in GAUNTLET_STAGES]
    except (UnsafeArtifactError, SealError, OSError) as exc:
        return [_error_receipt(cell, s, UNMEASURABLE_DIGEST,
                               f"cell_failure: {type(exc).__name__}: {exc}", signing_key)
                for s in GAUNTLET_STAGES]


# ------------------------------------------------------------------
# Stage: static (ruff + mypy, pinned, deterministic) — NO artifact runtime code executes
# ------------------------------------------------------------------


@dataclass(frozen=True)
class StaticTools:
    """The pinned static toolchain. ``ruff_argv``/``mypy_argv`` are argv prefixes (the resolved
    executables) so a test can inject fakes. TOOLCHAIN PIN (dissent): the executable's content sha
    is a CAPTURED coordinate, not merely "whatever PATH supplied" — it is recorded in every static
    observation AND, when ``expected_ruff_digest``/``expected_mypy_digest`` are set (a SEALED board
    run), ENFORCED (a drift fails the stage closed). Runs on the HOST: ruff never executes the
    target's runtime code and mypy is static analysis. RESIDUAL (documented, out of B1 scope): a
    malicious ``[tool.mypy]`` plugin / imported conftest could execute during mypy collection — the
    controlled B1 corpus contains none; a hardening path is to run static in the hermetic
    container."""

    ruff_argv: tuple[str, ...]
    mypy_argv: tuple[str, ...]
    python_version: str
    expected_ruff_digest: str | None = None   # sha256:<hex> of the ruff executable; enforced if set
    expected_mypy_digest: str | None = None   # sha256:<hex> of the mypy executable; enforced if set


def _run(argv: list[str], cwd: Path) -> tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stdout


def _exe_digest(argv0: str) -> str:
    """sha256:<hex> of the executable file at ``argv0`` (the pinned toolchain coordinate). 'unknown'
    only if the path is not a readable file (a fake argv), which a sealed run's enforcement
    rejects."""
    p = Path(argv0)
    if not p.is_file():
        return "unknown"
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def static_stage(view: Path, tools: StaticTools | None = None) -> StageObservation:
    """Run ruff + mypy (pinned) over the materialised view; observe (exits, findings_count,
    tool_versions incl the executable DIGESTS). Deterministic: caches are directed OUTSIDE the view.
    outcome = pass iff both tools exit 0. If the toolchain digests are pinned and the on-disk
    executable's digest differs, the stage fails closed (a captured coordinate, enforced)."""
    import subprocess
    t = tools or default_static_tools()
    ruff_digest = _exe_digest(t.ruff_argv[0])
    mypy_digest = _exe_digest(t.mypy_argv[0])
    if t.expected_ruff_digest is not None and ruff_digest != t.expected_ruff_digest:
        raise RuntimeError(
            f"ruff toolchain digest drift: pinned {t.expected_ruff_digest!r}, "
            f"on-disk {ruff_digest!r}")
    if t.expected_mypy_digest is not None and mypy_digest != t.expected_mypy_digest:
        raise RuntimeError(
            f"mypy toolchain digest drift: pinned {t.expected_mypy_digest!r}, "
            f"on-disk {mypy_digest!r}")
    with tempfile.TemporaryDirectory(prefix="gauntlet-static-") as scratch:
        ruff_cache = str(Path(scratch) / "ruff")
        mypy_cache = str(Path(scratch) / "mypy")
        # ruff: JSON output so findings are countable; cache OUTSIDE the view.
        ruff_argv = [*t.ruff_argv, "check", "--no-fix", "--output-format", "json",
                     "--cache-dir", ruff_cache, str(view)]
        try:
            ruff_rc, ruff_out = _run(ruff_argv, Path(scratch))
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"ruff invocation failed: {exc}") from exc
        try:
            findings = len(json.loads(ruff_out)) if ruff_out.strip() else 0
        except json.JSONDecodeError:
            findings = 0
        # mypy: cache OUTSIDE the view; run from scratch cwd so no .mypy_cache lands in it.
        mypy_argv = [*t.mypy_argv, "--cache-dir", mypy_cache, "--no-error-summary", str(view)]
        try:
            mypy_rc, _ = _run(mypy_argv, Path(scratch))
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"mypy invocation failed: {exc}") from exc
    outcome = "pass" if (ruff_rc == 0 and mypy_rc == 0) else "fail"
    return StageObservation(
        stage="static",
        outcome=outcome,
        observation={
            "tool_versions": {
                "ruff": _tool_version([*t.ruff_argv, "--version"]),
                "ruff_exe_digest": ruff_digest,
                "mypy": _tool_version([*t.mypy_argv, "--version"]),
                "mypy_exe_digest": mypy_digest,
                "python": t.python_version,
            },
            "ruff_exit": int(ruff_rc),
            "mypy_exit": int(mypy_rc),
            "findings_count": int(findings),
        },
    )


def _tool_version(argv: list[str]) -> str:
    import subprocess
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or proc.stderr.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def default_static_tools() -> StaticTools:
    """Pinned static toolchain from the ``ruff`` / ``mypy`` executables on PATH (they are installed
    as standalone binaries, not importable modules, so ``python -m ruff`` is not available)."""
    import sys
    return StaticTools(
        ruff_argv=(shutil.which("ruff") or "ruff",),
        mypy_argv=(shutil.which("mypy") or "mypy",),
        python_version=sys.version.split()[0],
    )


# ------------------------------------------------------------------
# Stage: own_tests (the SECURITY-SENSITIVE stage) — the producer's pytest, hermetically
# ------------------------------------------------------------------
#
# own-tests GREEN on the evasion is the demonstration — the producer's tests are complicit; that is
# the thesis of the board. Do not make this stage catch the evasion.
#
# The stage runs the PRODUCER'S OWN pytest suite inside a fresh hermetic OCISandbox — the SAME
# isolation the gate uses (IsolationLevel.HERMETIC): /artifact mounted read-only,
# ``--network=none``,
# a sterile env (no host env, no host mounts but the ro artifact), a writable tmpfs /work, and a
# teardown that CONFIRMS container destruction. The ONLY observation is the CONTAINER EXIT CODE,
# read
# out-of-band by the orchestrator — never the producer's stdout, which is untrusted. P2 hardening: a
# FRESH sandbox object is constructed per cell (never reused across runs), and the sandbox exposes
# no
# shared writable mount beyond the ro artifact + the per-run tmpfs, so the untrusted pytest cannot
# reach the orchestrator's signing key or a concurrent gate run's state. (The signing key living in
# the orchestrator process is a documented residual; an HSM / constant-time signing is out of B1
# scope.)

# The producer suite, run inside the container over the ro artifact. ``-B`` keeps __pycache__ out of
# the read-only /artifact; ``-p no:cacheprovider`` writes no .pytest_cache; cwd is the tmpfs /work.
_PYTEST_ARGV: tuple[str, ...] = (
    "python3", "-B", "-m", "pytest", "/artifact", "-p", "no:cacheprovider", "-q")

# A sandbox factory: constructs a FRESH sandbox for one own_tests run (default: a real OCISandbox).
SandboxFactory = Callable[[], Any]


def own_tests_stage(
    view: Path,
    *,
    image: str,
    budget_seconds: float = 120.0,
    make_sandbox: SandboxFactory | None = None,
    pytest_argv: tuple[str, ...] = _PYTEST_ARGV,
) -> StageObservation:
    """Run the producer's pytest in a FRESH hermetic sandbox over the materialised view; observe
    ONLY
    the out-of-band container exit code. Isolation is the gate's (HERMETIC). own-tests GREEN on the
    evasion is intentional (the thesis) — this stage never inspects WHAT the tests assert.
    ``make_sandbox`` is injectable for tests; the default constructs a fresh
    ``sandbox.oci.OCISandbox(image)`` (deferred import)."""
    from core import ArtifactSpec, Command, Fixtures, ResourceBudget

    def _default_factory() -> Any:
        from sandbox.oci import OCISandbox
        return OCISandbox(image=image)

    factory = make_sandbox or _default_factory
    spec = ArtifactSpec(path=view, tree_hash=tree_hash(view))
    sandbox = factory()  # P2: a fresh sandbox object per cell — never reused across runs
    # Record the sandbox's REAL isolation level; the schema requires 'hermetic' for own_tests, so a
    # weaker (or absent -> 'unknown') level fails closed rather than being masked as hermetic.
    level = getattr(getattr(sandbox, "isolation_level", None), "value", "unknown")
    handle = sandbox.prepare(spec, Fixtures())
    try:
        result = sandbox.run(
            handle, Command(argv=tuple(pytest_argv)),
            ResourceBudget(wall_clock_seconds=budget_seconds))
    finally:
        sandbox.teardown(handle)  # CONFIRMS destruction (SandboxLeakError if it cannot)

    if result.outcome == "completed" and result.exit_code is not None:
        exit_code: int | None = int(result.exit_code)
    else:
        # timeout / container-level error: no clean exit code -> pytest_status='error'
        exit_code = None
    # status + outcome via the CANONICAL schema maps (single source; own_tests + schema agree).
    status = expected_pytest_status(exit_code)
    return StageObservation(
        stage="own_tests",
        outcome=OWN_TESTS_CELL_OUTCOME[status],
        observation={
            "sandbox_isolation_level": str(level),
            "image_digest": str(result.image_digest),
            "container_exit_code": exit_code,
            "pytest_status": status,
        },
    )


# ------------------------------------------------------------------
# Stage: llm_review (a MEASUREMENT stage, NOT a security boundary)
# ------------------------------------------------------------------
#
# A cross-lineage reviewer (reviewer_lineage != lineage, fixed by the manifest) is shown the
# artifact
# under a FIXED, PUBLISHED review prompt (its hash committed in the manifest) and returns a
# STRUCTURED
# verdict. Strict ``approve`` -> PASS; anything else -> the reviewer requested changes (it "caught"
# something). The board records the provider/model id and the raw request/response DIGESTS so the
# measurement is auditable — but the reviewer is a MEASUREMENT, not a security boundary: a
# hallucinated
# or fooled verdict is a measurement error, not a breach (the gate is the boundary). For a
# well-constructed evasion the reviewer may well approve (green) — that, like own-tests being
# complicit, is part of what the gate-BLOCKED column then demonstrates.


@dataclass(frozen=True)
class ReviewOutcome:
    """What the reviewer client actually did: the structured verdict plus the EXACT request/response
    bytes it sent/received (digested into the receipt) and the provider/model identity. The stage
    trusts none of it as a security signal — it records a measurement."""

    verdict: str            # 'approve' | 'request_changes' (schema-validated at receipt build)
    provider_id: str
    model_id: str
    raw_request: bytes      # the exact bytes sent to the reviewer (digested, not stored)
    raw_response: bytes     # the exact bytes received from the reviewer (digested, not stored)


# A review client: (snapshot, reviewer_lineage, review_prompt_hash) -> ReviewOutcome. Injected so B1
# can drive it manually / with a deterministic fake; a real client calls the reviewer model.
ReviewClient = Callable[[Path, str, str], ReviewOutcome]


def llm_review_stage(
    view: Path,
    *,
    reviewer_lineage: str,
    review_prompt_hash: str,
    review_client: ReviewClient,
) -> StageObservation:
    """Run the cross-lineage LLM review over the materialised view and record the measurement.
    ``outcome`` = pass iff the verdict is exactly ``approve``. The request/response are digested
    (never stored); the provider/model id is recorded. Measurement, not security."""
    result = review_client(view, reviewer_lineage, review_prompt_hash)
    request_digest = hashlib.sha256(result.raw_request).hexdigest()
    response_digest = hashlib.sha256(result.raw_response).hexdigest()
    outcome = "pass" if result.verdict == "approve" else "fail"
    return StageObservation(
        stage="llm_review",
        outcome=outcome,
        observation={
            "provider_id": result.provider_id,
            "model_id": result.model_id,
            "review_prompt_hash": review_prompt_hash,
            "request_digest": request_digest,
            "response_digest": response_digest,
            "verdict": result.verdict,
        },
    )


# ------------------------------------------------------------------
# Stage: gate (the existing enforcement machinery) — P1: bind the tree the gate ACTUALLY measured
# ------------------------------------------------------------------
#
# The gate is gated's REAL enforcement path (the pre-existing GatedEnforcementAdapter drives the
# live
# job runner). The consult's load-bearing P1 finding: the adapter selects + copies its OWN source
# and
# measures its OWN tree_hash at a source-selection seam, so a receipt that merely bound the cell's
# expected digest could certify a DIFFERENT tree than the gate evaluated (a false green). The fix is
# structural and made a SCHEMA LAW (schemas.validate_cell_stage_payload): the gate observation
# carries
# the digest the adapter ACTUALLY measured (``measured_tree_digest``), and the orchestrator refuses
# to
# sign unless it equals the cell's bound ``artifact_tree_digest`` — the gate may certify ONLY the
# tree
# it measured. Combined with assert_safe_artifact_tree (uniform symlink rejection), the two staging
# paths cannot diverge and the source-selection false-green vector is closed.


@dataclass(frozen=True)
class GateMeasurement:
    """The gate's real projection, plus the digest it ACTUALLY measured. ``result_kind`` is a
    VALID_RESULT_KINDS discriminator; ``admitted_outcome`` is 'pass'|'fail' for an admitted_run
    (else
    None); ``measured_tree_digest`` is the ``sha256:<hex>`` the enforcement adapter captured at its
    source-selection seam — the P1 anchor the cell outcome is only valid against."""

    result_kind: str
    result_reason: str
    result_sub_reason: str
    gate_outcome: str | None
    admitted_outcome: str | None    # 'pass'|'fail' for admitted_run; None otherwise
    measured_tree_digest: str


# A gate runner: snapshot -> GateMeasurement. Injected so B1 can drive the real adapter at fanout /
# a real-podman keystone, and unit-test the stage (incl. the P1 law) with a fake.
GateRunner = Callable[[Path], GateMeasurement]

def gate_stage(view: Path, *, gate_runner: GateRunner) -> StageObservation:
    """Run the artifact through the real gate and bind the digest the gate MEASURED. The cell
    outcome
    is DERIVED from ``result_kind`` (admitted->its verdict, blocking_refusal->blocked, else->error)
    via the canonical schema map (schemas.GATE_CELL_OUTCOME_BY_KIND) — never taken on trust from the
    runner. If the gate measured a different tree than the cell bound, the receipt is unsignable
    (P1)."""
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
