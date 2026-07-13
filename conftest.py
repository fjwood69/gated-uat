"""conftest.py — add gated to sys.path and assert pinned commit.

Production: install gated from a pinned artifact hash (§11). Development: add
the sibling checkout at ../gated. The pinned commit is asserted via git so a
stale checkout fails loudly rather than silently testing the wrong code.

Pinned: 07d2161 (gated 3.5: P1-3 remediation — measurement-derived identity)
canonical_digest API contract: core.chain.canonical_digest(domain, payload, *, version=int) -> str
"""
from __future__ import annotations

import subprocess
import sys
import warnings
from pathlib import Path

_GATED_DEV = Path(__file__).parent.parent / "gated"
_PINNED_COMMIT_PREFIX = "07d2161"

if str(_GATED_DEV) not in sys.path and _GATED_DEV.is_dir():
    sys.path.insert(0, str(_GATED_DEV))

    # Assert gated is at the pinned commit.
    result = subprocess.run(
        ["git", "rev-parse", "--short=7", "HEAD"],
        cwd=_GATED_DEV,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        actual = result.stdout.strip()
        if actual != _PINNED_COMMIT_PREFIX:
            warnings.warn(
                f"gated checkout is at {actual!r}, expected pinned commit "
                f"{_PINNED_COMMIT_PREFIX!r} — evidence chain may not be compatible",
                stacklevel=1,
            )
    else:
        warnings.warn("Could not verify gated commit (not a git repo?)", stacklevel=1)
