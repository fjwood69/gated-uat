"""orchestrator/gauntlet.py — the B1 step-2 GAUNTLET (the per-cell stage runner).

The board manifest (step 1) is the signed EXPECTATION; the gauntlet produces the signed
OBSERVATIONS. For one board cell + its produced artifact, the gauntlet runs the ratified ordered
stages — ``static -> own_tests -> llm_review -> gate`` — and emits ONE signed ``cell_stage`` receipt
per stage. Every receipt binds three things (carry-in 1): the manifest anchor (``manifest_digest``),
the cell's ``planned_run_id`` (the receipt's run_id), and the ONE ``artifact_tree_digest`` the whole
cell is verified against.

Structural laws (made true-by-construction, not merely intended):

  * ONE IMMUTABLE ARTIFACT PER ROW (amendment 3). The artifact is snapshotted ONCE per cell into an
    immutable copy; its ``core.tree_hash`` is THE digest bound in every stage receipt. Each stage is
    wrapped in ``stage_guard`` which re-verifies the snapshot digest BEFORE and AFTER the stage; a
    mismatch either side is a DigestMismatchError -> a PUBLISHED ERROR receipt, never a silent
    rerun.

  * UNIFORM TREE POLICY (P1 hardening). ``assert_safe_artifact_tree`` rejects symlinks / hardlinks /
    special files up front — the SAME class the gate's real tarball path rejects — so the two
    staging paths (own_tests's sandbox copy and the gate adapter's own copy) cannot diverge on a
    symlink's ``L:``-vs-followed representation. Combined with the gate receipt binding the digest
    the adapter ACTUALLY measured (schema law in schemas.validate_cell_stage_payload), the
    source-selection false-green vector is closed.

  * HARNESS-HONEST ERRORS. A digest mismatch or an unexpected stage crash is recorded as an ERROR
    receipt whose observation is a canonical ``{"harness_error": <str>}`` — a stage never signs a
    measurement it did not make.

The GATE's after-check (P3) is DEFENCE-IN-DEPTH, not a boundary against untrusted code: a stage runs
over its own sandbox/adapter copy, never the shared immutable snapshot, so the after-hash changing
would signal a harness bug or a mount misconfiguration — it is NOT what stops a malicious producer
(the sandbox does that). It is kept because amendment 3 mandates it and it cheaply catches a stage
that wrote where it must not.

``gate.*`` / ``sandbox.*`` imports are DEFERRED into the stage functions so this module imports with
only ``core`` on the path (as ``manifest.py`` does).
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

CELL_STAGE_KIND = "cell_stage"
# The ratified ordered gauntlet (build order == run order).
GAUNTLET_STAGES: tuple[str, ...] = ("static", "own_tests", "llm_review", "gate")


class DigestMismatchError(RuntimeError):
    """The immutable snapshot's ``tree_hash`` != the bound digest, checked before/after a stage.
    A mismatch means the artifact under measurement is not the one the cell bound — the stage's
    observation is void. Surfaced as a PUBLISHED ERROR receipt, never a silent rerun (amdt 3)."""


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
    """Reject an artifact tree containing a symlink, hardlink, or special file (device/fifo/etc) —
    the SAME class the gate's ``safe_extract_tarball`` rejects. Source trees rarely need links; a
    tree that does fails closed. This keeps ``core.tree_hash`` over the tree = ``F:``-only, so the
    own_tests sandbox copy and the gate adapter copy canonicalise identically (P1 hardening)."""
    if not root.exists():
        raise UnsafeArtifactError(f"artifact path does not exist: {root}")
    if root.is_symlink():
        raise UnsafeArtifactError(f"artifact root is a symlink: {root}")
    if root.is_file():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for name in (*dirnames, *filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                raise UnsafeArtifactError(f"symlink rejected (uniform with the gate path): {p}")
            if not p.is_dir() and not p.is_file():
                raise UnsafeArtifactError(f"special file rejected (not a regular file/dir): {p}")


@contextmanager
def immutable_snapshot(artifact_dir: Path) -> Iterator[tuple[Path, str]]:
    """Snapshot the artifact ONCE into an immutable copy and yield ``(snapshot_path, digest)`` where
    ``digest = core.tree_hash(snapshot)``. Rejects an unsafe tree first. The snapshot is the single
    immutable artifact the whole cell (every stage) is verified against; it is purged on exit.

    A stage runs over this snapshot but must never WRITE to it (stages copy it into their own
    sandbox
    / adapter workspace); ``stage_guard`` re-hashes it before+after each stage to catch any
    violation.
    """
    assert_safe_artifact_tree(artifact_dir)
    snapshot = Path(tempfile.mkdtemp(prefix="gauntlet-cell-"))
    try:
        if artifact_dir.is_dir():
            shutil.copytree(artifact_dir, snapshot, dirs_exist_ok=True)
        else:
            shutil.copy2(artifact_dir, snapshot / artifact_dir.name)
        digest = tree_hash(snapshot)
        yield snapshot, digest
    finally:
        shutil.rmtree(snapshot, ignore_errors=True)


def verify_tree(snapshot: Path, expected_digest: str) -> None:
    """Raise DigestMismatchError if ``tree_hash(snapshot) != expected_digest``."""
    actual = tree_hash(snapshot)
    if actual != expected_digest:
        raise DigestMismatchError(
            f"artifact_tree_digest mismatch: expected {expected_digest!r}, snapshot is {actual!r}")


@contextmanager
def stage_guard(snapshot: Path, expected_digest: str) -> Iterator[Path]:
    """Verify the snapshot digest BEFORE and AFTER a stage (amendment 3). The BEFORE check confirms
    the stage measures the bound artifact; the AFTER check is DEFENCE-IN-DEPTH (P3) — a stage runs
    over its own sandbox/adapter copy, not this shared snapshot, so an after-mismatch signals a
    harness bug or mount misconfiguration, NOT a defeated malicious producer (the sandbox stops
    that). A mismatch either side raises DigestMismatchError -> the caller publishes an ERROR
    receipt.
    """
    verify_tree(snapshot, expected_digest)   # before
    yield snapshot
    verify_tree(snapshot, expected_digest)   # after


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
    snapshot: Path,
    artifact_tree_digest: str,
    stage: str,
    stage_fn: StageFn,
    signing_key: SigningKey,
) -> Receipt:
    """Run ONE stage under the before/after digest guard and return its signed receipt.

    A DigestMismatchError (before or after) or ANY unexpected exception from the stage becomes a
    PUBLISHED ERROR receipt (outcome=error, harness_error) — the cell is never silently rerun. A
    normal return is turned into a signed receipt from the stage's ``StageObservation``; if that
    observation is malformed the schema rejects it at build time (fail-closed, surfaced to the
    caller
    as an ERROR receipt rather than an unsigned exception)."""
    try:
        with stage_guard(snapshot, artifact_tree_digest) as snap:
            result = stage_fn(snap)
        if result.stage != stage:
            raise ValueError(f"stage_fn returned stage {result.stage!r}, expected {stage!r}")
        return build_cell_stage_receipt(
            cell, stage, result.outcome, result.observation, artifact_tree_digest, signing_key)
    except DigestMismatchError as exc:
        return _error_receipt(
            cell, stage, artifact_tree_digest, f"digest_guard: {exc}", signing_key)
    except Exception as exc:  # noqa: BLE001 — any stage failure is a published ERROR row, not a crash
        return _error_receipt(
            cell, stage, artifact_tree_digest, f"{type(exc).__name__}: {exc}", signing_key)


def run_gauntlet(
    cell: CellContext,
    artifact_dir: Path,
    stage_fns: dict[str, StageFn],
    signing_key: SigningKey,
) -> list[Receipt]:
    """Run the full ordered gauntlet for one cell and return the ordered list of signed cell_stage
    receipts (one per stage in ``GAUNTLET_STAGES``). Snapshots the artifact ONCE (the immutable row
    artifact); every stage is verified against that one digest before+after. ``stage_fns`` maps each
    stage name to its closure (which carries the stage's extra inputs — image, budget, reviewer)."""
    missing = [s for s in GAUNTLET_STAGES if s not in stage_fns]
    if missing:
        raise ValueError(f"stage_fns missing required stage(s): {missing}")
    receipts: list[Receipt] = []
    with immutable_snapshot(artifact_dir) as (snapshot, digest):
        for stage in GAUNTLET_STAGES:
            receipts.append(
                run_stage(cell, snapshot, digest, stage, stage_fns[stage], signing_key))
    return receipts


# ------------------------------------------------------------------
# Stage: static (ruff + mypy, pinned, deterministic) — NO artifact runtime code executes
# ------------------------------------------------------------------


@dataclass(frozen=True)
class StaticTools:
    """The pinned static toolchain. Commands are argv prefixes (``python -m ruff`` / ``-m mypy`` by
    default) so a test can inject fakes; versions are recorded in the observation. Runs on the HOST:
    ruff never executes the target's runtime code and mypy is static analysis. RESIDUAL (documented,
    out of B1 scope): a malicious ``[tool.mypy]`` plugin / imported conftest could execute during
    mypy collection — the controlled B1 corpus contains none; a hardening path is to run static in
    the same hermetic container as own_tests."""

    ruff_argv: tuple[str, ...]
    mypy_argv: tuple[str, ...]
    python_version: str


def _run(argv: list[str], cwd: Path) -> tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stdout


def static_stage(snapshot: Path, tools: StaticTools | None = None) -> StageObservation:
    """Run ruff + mypy (pinned) over the read-only snapshot; observe (exits, findings_count,
    tool_versions). Deterministic: caches are directed OUTSIDE the snapshot so the tools never write
    into the artifact (which would trip the after-hash). outcome = pass iff both tools exit 0."""
    import subprocess
    t = tools or default_static_tools()
    with tempfile.TemporaryDirectory(prefix="gauntlet-static-") as scratch:
        ruff_cache = str(Path(scratch) / "ruff")
        mypy_cache = str(Path(scratch) / "mypy")
        # ruff: JSON output so findings are countable; cache OUTSIDE the snapshot.
        ruff_argv = [*t.ruff_argv, "check", "--no-fix", "--output-format", "json",
                     "--cache-dir", ruff_cache, str(snapshot)]
        try:
            ruff_rc, ruff_out = _run(ruff_argv, Path(scratch))
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"ruff invocation failed: {exc}") from exc
        try:
            findings = len(json.loads(ruff_out)) if ruff_out.strip() else 0
        except json.JSONDecodeError:
            findings = 0
        # mypy: cache OUTSIDE the snapshot; run from scratch cwd so no .mypy_cache lands in it.
        mypy_argv = [*t.mypy_argv, "--cache-dir", mypy_cache, "--no-error-summary", str(snapshot)]
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
                "mypy": _tool_version([*t.mypy_argv, "--version"]),
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

# pytest exit codes: 0 all-passed, 1 tests-failed, 2 interrupted, 3 internal, 4 usage, 5 no-tests.
_PYTEST_STATUS_BY_EXIT: dict[int, str] = {0: "passed", 1: "failed", 5: "no_tests"}
_OWN_TESTS_OUTCOME: dict[str, str] = {
    "passed": "pass", "failed": "fail", "no_tests": "error", "error": "error"}
# The producer suite, run inside the container over the ro artifact. ``-B`` keeps __pycache__ out of
# the read-only /artifact; ``-p no:cacheprovider`` writes no .pytest_cache; cwd is the tmpfs /work.
_PYTEST_ARGV: tuple[str, ...] = (
    "python3", "-B", "-m", "pytest", "/artifact", "-p", "no:cacheprovider", "-q")

# A sandbox factory: constructs a FRESH sandbox for one own_tests run (default: a real OCISandbox).
SandboxFactory = Callable[[], Any]


def own_tests_stage(
    snapshot: Path,
    *,
    image: str,
    budget_seconds: float = 120.0,
    make_sandbox: SandboxFactory | None = None,
    pytest_argv: tuple[str, ...] = _PYTEST_ARGV,
) -> StageObservation:
    """Run the producer's pytest in a FRESH hermetic sandbox; observe ONLY the out-of-band container
    exit code. Isolation is the gate's (HERMETIC). own-tests GREEN on the evasion is intentional
    (the
    thesis) — this stage never inspects WHAT the tests assert. ``make_sandbox`` is injectable for
    tests; the default constructs a fresh ``sandbox.oci.OCISandbox(image)`` (deferred import)."""
    from core import ArtifactSpec, Command, Fixtures, ResourceBudget

    def _default_factory() -> Any:
        from sandbox.oci import OCISandbox
        return OCISandbox(image=image)

    factory = make_sandbox or _default_factory
    spec = ArtifactSpec(path=snapshot, tree_hash=tree_hash(snapshot))
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
        ec = int(result.exit_code)
        exit_code: int | None = ec
        status = _PYTEST_STATUS_BY_EXIT.get(ec, "error")
    else:
        # timeout / container-level error: no clean exit code -> pytest_status='error'
        exit_code = None
        status = "error"
    return StageObservation(
        stage="own_tests",
        outcome=_OWN_TESTS_OUTCOME[status],
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
    snapshot: Path,
    *,
    reviewer_lineage: str,
    review_prompt_hash: str,
    review_client: ReviewClient,
) -> StageObservation:
    """Run the cross-lineage LLM review over the artifact and record the measurement. ``outcome`` =
    pass iff the verdict is exactly ``approve``. The request/response are digested (never stored);
    the
    provider/model id is recorded. Measurement, not security."""
    result = review_client(snapshot, reviewer_lineage, review_prompt_hash)
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

# The cell outcome is DERIVED from the observed result_kind (never taken on trust from the runner),
# so an incoherent (outcome, result_kind) pair is unrepresentable at the stage, not just at the
# schema.
_GATE_OUTCOME_BY_KIND: dict[str, str] = {
    "blocking_refusal": "blocked",
    "non_run": "error",
    "infrastructure_failure": "error",
}


def gate_stage(snapshot: Path, *, gate_runner: GateRunner) -> StageObservation:
    """Run the artifact through the real gate and bind the digest the gate MEASURED. The cell
    outcome
    is derived from ``result_kind`` (admitted->its verdict, blocking_refusal->blocked, else->error).
    If the gate measured a different tree than the cell bound, the receipt is unsignable (P1)."""
    m = gate_runner(snapshot)
    if m.result_kind == "admitted_run":
        outcome = m.admitted_outcome or "error"
    else:
        outcome = _GATE_OUTCOME_BY_KIND.get(m.result_kind, "error")
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
