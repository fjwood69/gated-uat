"""tests/test_render_driver.py — Step 3.1 driver unit tests (fakes; no podman).

Proves the driver LOGIC + the board-ruling riders without real containers:
  * input hygiene — duplicate task_ids rejected before any stage (denominator-inflation seam);
  * RecordedReviewClient — replays only an exact request-digest match, else fail-closed;
  * fail-closed emit — a failed admission writes NOTHING to out_dir;
  * admissible != gate verdict — the render shows the real run-verdict, not a bare pass, per stage;
  * three-way gate distinction (render-honesty seal) — a caught evasion (admitted_run + FAIL
    run-verdict → "ADMIT/fail"), a governance refusal ("BLOCKED"), and an error ("ERROR") render
    DISTINCTLY; a caught evasion is never relabelled "BLOCKED";
  * structurally regenerable — two runs over identical inputs + the same recorded reviewer produce
    IDENTICAL normalize_board() bytes (the published normalization the claim rests on).

The real two-sided board is the real-podman keystone; here the fake gate uniformly returns the real
catch shape — admitted_run with a FAIL run-verdict → display "ADMIT/fail" (the detector caught the
behaviour; in a gated deployment the PR check fails, so the merge is blocked). This is NOT a
governance blocking_refusal ("BLOCKED"); admissibility is independent of the verdict either way.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.manifest import plan_cells
from orchestrator.render_driver import (
    RecordedRequestMismatch,
    RecordedReviewClient,
    RenderDriverError,
    ReviewCapture,
    TaskSpec,
    capture_request_digest,
    normalize_board,
    render_board,
)
from orchestrator.trust import generate_signer
from tests._fakes import FakeSandbox, gate_runner

_ENV_DIGEST = "sha256:" + "a" * 64
_RPH = "b" * 64
_LINEAGES = ["claude-x", "gpt-y"]
_TOOLCHAIN = {"python_version": "3.12.3", "ruff_version": "0.15.15", "mypy_version": "2.1.0",
              "env_digest": _ENV_DIGEST}
_PREREG = "2026-07-23T10:00:00Z"


def _artifact(dir_: Path, body: str) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / "main.py").write_text(body, encoding="utf-8")
    return dir_


def _tasks(tmp: Path) -> list[TaskSpec]:
    tempting = _artifact(tmp / "tempting", "x = 1\n")
    clean = _artifact(tmp / "clean", "y = 2\n")
    return [
        TaskSpec(task_id="retry-swallow", prompt="p1", prompt_hash="a" * 64, side="tempting",
                 counterpart_task_id="retry-clean", detector_id="retry",
                 invariant_corpus_version="v1", review_prompt_hash=_RPH, artifact_dir=tempting),
        TaskSpec(task_id="retry-clean", prompt="p2", prompt_hash="c" * 64, side="clean",
                 counterpart_task_id="retry-swallow", detector_id="retry",
                 invariant_corpus_version="v1", review_prompt_hash=_RPH, artifact_dir=clean),
    ]


def _captures(tasks: list[TaskSpec], verdict: str = "approve") -> tuple[ReviewCapture, ...]:
    """Pre-capture a recorded reviewer response for every distinct (artifact, reviewer) request the
    board will issue — the honest board-builder captures once, then replays."""
    by_task = {t.task_id: t for t in tasks}
    cells = plan_cells([(t.task_id, t.side) for t in tasks], _LINEAGES, 1)
    seen: dict[str, ReviewCapture] = {}
    for cell in cells:
        art = by_task[str(cell["task_id"])].artifact_dir
        rd = capture_request_digest(art, str(cell["reviewer_lineage"]), _RPH)
        resp = b'{"verdict":"' + verdict.encode() + b'"}'
        seen[rd] = ReviewCapture(request_digest=rd, response=resp, verdict=verdict,
                                 provider_id="anthropic", model_id="reviewer-1")
    return tuple(seen.values())


def _make_sandbox() -> FakeSandbox:
    # static + own_tests exit 0; image config id == the manifest env_digest pin.
    return FakeSandbox(exit_code=0, image_digest=_ENV_DIGEST)


def _render(tmp: Path, *, out_dir: Path | None = None, verdict: str = "approve"):  # noqa: ANN202
    tasks = _tasks(tmp)
    s = generate_signer()
    return render_board(
        tasks=tasks, lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
        corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
        make_sandbox=_make_sandbox, gate_runner=gate_runner("admitted_run", admitted="fail"),
        review_client=RecordedReviewClient(_captures(tasks, verdict)),
        signing_key=s.signing_key, verify_key=s.verify_key, out_dir=out_dir)


# ---- input hygiene ------------------------------------------------------------------------------

def test_duplicate_task_ids_rejected(tmp_path: Path) -> None:
    tasks = _tasks(tmp_path)
    dup = [tasks[0], tasks[0]]  # same task_id twice -> denominator inflation
    s = generate_signer()
    with pytest.raises(RenderDriverError):
        render_board(
            tasks=dup, lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
            corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
            make_sandbox=_make_sandbox, gate_runner=gate_runner("admitted_run", admitted="fail"),
            review_client=RecordedReviewClient(()), signing_key=s.signing_key,
            verify_key=s.verify_key)


# ---- RecordedReviewClient request binding -------------------------------------------------------

def test_recorded_client_replays_only_matching_request() -> None:
    import hashlib
    req = b"CANONICAL-REQUEST-ENVELOPE"
    rd = hashlib.sha256(req).hexdigest()
    cap = ReviewCapture(request_digest=rd, response=b'{"verdict":"approve"}', verdict="approve",
                        provider_id="anthropic", model_id="reviewer-1")
    client = RecordedReviewClient((cap,))
    out = client(req, "gpt-y", _RPH)  # exact request-digest match -> replays
    assert out.verdict == "approve" and out.raw_response == b'{"verdict":"approve"}'
    with pytest.raises(RecordedRequestMismatch):
        client(b"A-DIFFERENT-REQUEST", "gpt-y", _RPH)  # un-captured -> fail-closed


# ---- admissible board: emit + structural regenerability -----------------------------------------

def test_board_is_admissible_and_emits(tmp_path: Path) -> None:
    out = tmp_path / "out"
    artifact = _render(tmp_path, out_dir=out)
    assert artifact.manifest_payload["manifest_version"] == 1
    assert len(artifact.cell_stage_receipts) == 4 * 4  # 4 cells x 4 stages
    assert (out / "board.json").is_file()
    assert (out / "DISCLOSURE.txt").is_file()
    assert (out / "normalized.json").is_file()
    assert len(list((out / "receipts").glob("*.json"))) == 1 + 16  # manifest + 16 cell_stage


def test_recorded_board_bundles_signed_capture_records(tmp_path: Path) -> None:
    # gap-1: a recorded board writes one signed capture record per captured request under captures/,
    # each Ed25519-verifiable and response-digest-bound — so a reader can confirm the replayed bytes
    # were captured, not invented. (NOT a B1 receipt; excluded from normalize_board.)
    import base64
    import hashlib
    import json

    from nacl.signing import VerifyKey

    out = tmp_path / "out"
    tasks = _tasks(tmp_path)
    captures = _captures(tasks)
    _render(tmp_path, out_dir=out)
    files = sorted((out / "captures").glob("*.json"))
    assert len(files) == len(captures)  # one file per distinct captured request
    for f in files:
        rec = json.loads(f.read_text())
        assert rec["body"]["source"] == "recorded"
        assert f.stem == rec["body"]["request_digest"]  # filename IS the request digest
        # response_digest binds the recorded bytes
        raw = base64.b64decode(rec["body"]["response_b64"])
        assert hashlib.sha256(raw).hexdigest() == rec["body"]["response_digest"]
        # signature verifies against the embedded verify key over canonical body bytes
        payload = json.dumps(rec["body"], sort_keys=True, separators=(",", ":")).encode()
        VerifyKey(bytes.fromhex(rec["verify_key_hex"])).verify(
            payload, bytes.fromhex(rec["signature"]))
    # capture records do NOT perturb the structural claim
    assert b"capture_record" not in normalize_board(_render(tmp_path / "n"))


def test_render_table_shows_real_run_verdict_not_bare_pass(tmp_path: Path) -> None:
    # the real catch shape: the gate ADMITTED the run and the detector returned FAIL -> "ADMIT/fail"
    # (in a gated deployment the required check fails, so the merge is blocked). NOT "BLOCKED" —
    # that is a governance blocking_refusal, a mechanism this row never takes (board ruling).
    artifact = _render(tmp_path)
    rows = artifact.render_metadata["table"]["rows"]
    assert len(rows) == 4
    for row in rows:
        assert row["columns"]["gate"]["verdict"] == "ADMIT/fail"    # admitted_run + FAIL verdict
        assert row["columns"]["static"]["verdict"] == "pass"
        assert row["response_source"] == "recorded"                # UNSIGNED origin disclosed


def test_gate_outcomes_render_three_way_distinct() -> None:
    # RENDER-HONESTY SEAL CONDITION (board ruling): the gate column must keep three DISTINCT
    # families apart — a caught evasion (admitted_run + FAIL run-verdict), a governance refusal,
    # and an error are three different events and must render as three different labels. Collapsing
    # any pair (e.g. admitted_run/fail -> "BLOCKED") would borrow a label for a mechanism the row
    # never took — the category error gated itself exists to police.
    from orchestrator.render_driver import _cell_verdict

    def gv(outcome: str, kind: str) -> str:
        return _cell_verdict("gate", {"outcome": outcome, "observation": {"result_kind": kind}})

    caught = gv("fail", "admitted_run")
    admitted = gv("pass", "admitted_run")
    refusal = gv("error", "blocking_refusal")
    infra = gv("error", "infrastructure_failure")
    harness = _cell_verdict("gate", {"outcome": "error", "observation": {"harness_error": "x"}})
    assert caught == "ADMIT/fail"   # detector caught it -> FAIL run-verdict (merge blocked)
    assert admitted == "ADMIT"      # admitted_run + pass -> merge allowed
    assert refusal == "BLOCKED"     # governance currency/drift refusal — a DISTINCT event
    assert infra == "ERROR" and harness == "ERROR"
    assert len({caught, refusal, infra}) == 3  # the three "stopped/errored" families never collapse


def test_blocking_refusal_still_renders_as_blocked(tmp_path: Path) -> None:
    # the governance-refusal path (degraded / drift / generation-moved) is a REAL gate outcome for
    # OTHER scenarios; it must still render "BLOCKED", distinct from a caught evasion (ADMIT/fail).
    tasks = _tasks(tmp_path)
    s = generate_signer()
    artifact = render_board(
        tasks=tasks, lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
        corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
        make_sandbox=_make_sandbox, gate_runner=gate_runner("blocking_refusal"),
        review_client=RecordedReviewClient(_captures(tasks)), signing_key=s.signing_key,
        verify_key=s.verify_key)
    for row in artifact.render_metadata["table"]["rows"]:
        assert row["columns"]["gate"]["verdict"] == "BLOCKED"


def test_normalize_board_is_deterministic_across_runs(tmp_path: Path) -> None:
    # two independent runs over identical inputs + the same recorded reviewer -> IDENTICAL norm
    # bytes, though raw receipt bytes differ (fresh uuid4 run_ids + executed_at per run).
    a1 = _render(tmp_path / "run1")
    a2 = _render(tmp_path / "run2")
    # raw manifests differ (uuid4 board_id / run_ids)
    assert a1.manifest_receipt.digest != a2.manifest_receipt.digest
    # but the normalised (nonce/timestamp/crypto-stripped) bytes are identical
    assert normalize_board(a1) == normalize_board(a2)


# ---- fail-closed emit ---------------------------------------------------------------------------

def _boom(*_a: object, **_k: object) -> None:
    raise RuntimeError("forced admission failure")


def test_no_emit_when_admission_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # FAIL-CLOSED: if assert_board_admissible raises, NOTHING is written to out_dir. (The driver
    # wires env_digest consistently, so a pin mismatch cannot arise from valid inputs — we force the
    # admission failure at the gate itself to prove the emit is strictly after admission.)
    out = tmp_path / "out"
    tasks = _tasks(tmp_path)
    s = generate_signer()
    monkeypatch.setattr("orchestrator.render_driver.assert_board_admissible", _boom)
    with pytest.raises(RuntimeError):
        render_board(
            tasks=tasks, lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
            corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
            make_sandbox=_make_sandbox, gate_runner=gate_runner("admitted_run", admitted="fail"),
            review_client=RecordedReviewClient(_captures(tasks)), signing_key=s.signing_key,
            verify_key=s.verify_key, out_dir=out)
    assert not out.exists()  # FAIL-CLOSED: nothing written before admission passed
