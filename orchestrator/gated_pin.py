"""orchestrator/gated_pin.py — pinned gated dependency contract.

Single source of truth for the pinned gated commit.  Both pytest (conftest.py)
and the CLI (_derive_gated_commit) import verify_gated_dependency() so the
same exact-pin + clean-tree invariant is enforced on every entry path.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Full 40-char SHA — 7-char prefixes are 28 bits and not authoritative.
_PINNED_COMMIT = "1d75d54a97986e18fae499c370f8615e6cf89e15"
# Short form used in display-only contexts (error messages, receipts).
_PINNED_COMMIT_SHORT = "1d75d54"

# The INDEPENDENTLY-ACCEPTED RetryCheck profile digest at the pin — the literal captured in the
# slice-2.0 provenance contract (goldens/pin_provenance.json → resolved_profile_digest), NOT a
# value self-computed at runtime. Production supplies an externally-accepted digest so the gate
# enforces the EXACT profile that was accepted; self-computing profile_of(...).digest() and feeding
# it back to the same registry proves only self-consistency (the 2.0 circularity bug in miniature).
# Injecting THIS literal into the seed + enforcement registries makes acceptance independent. A
# drift (the runtime resolved digest ≠ this) fails detector resolution closed; a change to this
# literal is a board decision, cross-checked against the golden by test_pin_contract.
ACCEPTED_RETRYCHECK_PROFILE_DIGEST = (
    "81bb684adfc63428b8280fe0d5596cc3a1c1c6446016d654f64ce7143d4d2fd5"
)


def verify_gated_dependency(gated_dir: Path) -> str:
    """Verify *gated_dir* is the pinned commit with a fully clean working tree.

    Returns the 7-char short form for use in receipts.  Raises RuntimeError if:
    - git rev-parse fails (not a git repo, git not found, etc.)
    - the full commit SHA does not match _PINNED_COMMIT
    - git status fails (repository inspection failure must not be treated as clean)
    - any non-ignored untracked or modified file is present — an untracked .py
      file in a directory on sys.path can shadow evidence-bearing imports

    This check is necessary but not sufficient for production artifact binding
    (§11): in a deployed artifact context verify the installed package hash
    rather than relying on sibling git metadata.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=gated_dir,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        # cwd doesn't exist, git not found, or similar OS-level failure.
        raise RuntimeError(f"Could not verify gated commit: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"Could not verify gated commit: {result.stderr.strip()}")
    actual = result.stdout.strip()
    if actual != _PINNED_COMMIT:
        raise RuntimeError(
            f"gated checkout is at {actual[:7]!r} ({actual}), "
            f"expected pinned commit {_PINNED_COMMIT_SHORT!r} ({_PINNED_COMMIT}) — "
            f"evidence-bearing code requires the exact commit"
        )
    # Check for any non-ignored modifications or untracked files.
    # --untracked-files=no is intentionally absent: an untracked .py module can
    # shadow evidence-bearing imports when gated_dir is on sys.path.
    # git status failure (nonzero) is a hard error — do not treat as clean.
    try:
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=gated_dir,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not inspect gated working tree: {exc}") from exc
    if dirty.returncode != 0:
        raise RuntimeError(
            f"Could not inspect gated working tree: {dirty.stderr.strip()}"
        )
    if dirty.stdout.strip():
        raise RuntimeError(
            f"gated checkout is not clean — "
            f"evidence-bearing code requires a fully clean tree:\n{dirty.stdout}"
        )
    return _PINNED_COMMIT_SHORT
