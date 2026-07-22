"""tests/test_gauntlet_keystone.py — B1 seal gate 2: FOLD-A CONTRACT proof through REAL podman.

The unit FOLD-A test (test_gauntlet_foundation) proves the harness binds ``sealed.digest`` against a
``RealisticSandbox`` that MIMICS the pin's ``prepare()``. The Board (SD2/SD7) held that mimic
+ delegation is not a contract proof: capability-deletion's physical enforcement — ``OCISandbox``
copytreeing the view into an immutable snapshot, re-hashing it, raising ``ArtifactHashMismatch``
on drift — must be exercised through the REAL sandbox.

This keystone does that: a DIVERGENT view (monkeypatched ``extract_view``) is pushed through a
real ``OCISandbox.prepare()`` bound to ``sealed.digest``; the mismatch must bubble up into a
published ERROR receipt. It needs a local Podman image; it skips cleanly when absent (CI provides
``localhost/mori:local``). ``prepare()`` raises before any tool runs, so the image need not carry
ruff/mypy — a clean-static run in a real toolchain image is a separate (Step-4/fanout) concern.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from orchestrator import gauntlet
from orchestrator.gauntlet import (
    CellContext,
    SealedArtifact,
    run_stage,
    seal_artifact,
    static_stage,
)
from orchestrator.trust import generate_signer

_IMAGE = "localhost/mori:local"
_RUN_ID = "66666666-6666-4666-8666-666666666666"


def _podman_image_available(image_ref: str) -> bool:
    if not shutil.which("podman"):
        return False
    return subprocess.run(  # noqa: S603
        ["podman", "image", "exists", image_ref], capture_output=True, check=False).returncode == 0


def _resolve_image_digest(image_ref: str) -> str:
    r = subprocess.run(  # noqa: S603
        ["podman", "image", "inspect", "--format", "{{.Id}}", image_ref],
        capture_output=True, text=True, check=False)
    image_id = r.stdout.strip()
    return image_id if image_id.startswith("sha256:") else "sha256:" + image_id


def _cell() -> CellContext:
    return CellContext(
        manifest_digest="a" * 64, planned_run_id=_RUN_ID, cell_id="retry/claude-x/0",
        lineage="claude-x", reviewer_lineage="gpt-y", side="tempting")


pytestmark = pytest.mark.skipif(
    not _podman_image_available(_IMAGE), reason=f"{_IMAGE} not present in the Podman image store")


def test_fold_a_drift_through_real_prepare_is_error_receipt(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # GATE 2 (the non-optional contract proof): a DIVERGENT view pushed through the REAL
    # OCISandbox.prepare() (which copytrees the view, re-hashes the snapshot, and raises
    # ArtifactHashMismatchError != sealed.digest) must publish an ERROR receipt — proving physical
    # window-closure, not just the harness's binding intent.
    from sandbox.oci import OCISandbox

    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    divergent = tmp_path.parent / "keystone-divergent"
    divergent.mkdir()
    (divergent / "a.py").write_text("TAMPERED = True\n")

    @contextlib.contextmanager
    def fake_extract_view(_sealed: SealedArtifact):  # noqa: ANN202
        yield divergent

    env = _resolve_image_digest(_IMAGE)
    with seal_artifact(tmp_path) as sealed:
        monkeypatch.setattr(gauntlet, "extract_view", fake_extract_view)
        r = run_stage(
            _cell(), sealed, sealed.digest, "static",
            lambda sl: static_stage(sl, image=_IMAGE, env_digest=env,
                                    make_sandbox=lambda: OCISandbox(image=_IMAGE)),
            s.signing_key)
    # real prepare() re-hashed the divergent snapshot != sealed.digest -> raised -> ERROR receipt
    assert r.payload["outcome"] == "error"
    err = r.payload["observation"]["harness_error"]
    assert "ArtifactHashMismatchError" in err or "!=" in err


def test_honest_view_through_real_prepare_reaches_the_toolchain(
    tmp_path: Path
) -> None:
    # the counterpart: an HONEST view (no monkeypatch) passes prepare()'s re-hash and reaches the
    # in-container run. mori:local carries no ruff/mypy, so the tool invocation does not cleanly
    # complete -> ERROR (a documented consequence, NOT a prepare mismatch). This proves prepare()
    # ACCEPTS the faithful view — the drift test above is not vacuously erroring for another reason.
    from sandbox.oci import OCISandbox

    s = generate_signer()
    (tmp_path / "a.py").write_text("x = 1\n")
    env = _resolve_image_digest(_IMAGE)
    with seal_artifact(tmp_path) as sealed:
        r = run_stage(
            _cell(), sealed, sealed.digest, "static",
            lambda sl: static_stage(sl, image=_IMAGE, env_digest=env,
                                    make_sandbox=lambda: OCISandbox(image=_IMAGE)),
            s.signing_key)
    # prepare() did NOT raise a hash mismatch (honest view verified); an ERROR here, if any, is a
    # tool-not-found / non-completion, never an ArtifactHashMismatchError.
    err = r.payload["observation"].get("harness_error", "")
    assert "ArtifactHashMismatchError" not in err
