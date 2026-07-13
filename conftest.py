"""conftest.py — gated sys.path injection, commit pin, and test helpers.

Production: install gated from a pinned artifact hash (§11). Development: add
the sibling checkout at ../gated. The pinned commit is asserted via git so a
stale or dirty checkout fails loudly (error, not warning) rather than silently
testing the wrong code.

Pinned: 07d2161 (gated 3.5: P1-3 remediation — measurement-derived identity)
canonical_digest API contract: core.chain.canonical_digest(domain, payload, *, version=int) -> str
"""
from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

_GATED_DEV = Path(__file__).parent.parent / "gated"
_PINNED_COMMIT_PREFIX = "07d2161"

if _GATED_DEV.is_dir():
    if str(_GATED_DEV) not in sys.path:
        sys.path.insert(0, str(_GATED_DEV))

    # Assert gated is at the exact pinned commit — fail the session if not.
    result = subprocess.run(
        ["git", "rev-parse", "--short=7", "HEAD"],
        cwd=_GATED_DEV,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not verify gated commit: {result.stderr.strip()}"
        )
    actual = result.stdout.strip()
    if actual != _PINNED_COMMIT_PREFIX:
        raise RuntimeError(
            f"gated checkout is at {actual!r}, expected pinned commit "
            f"{_PINNED_COMMIT_PREFIX!r} — evidence-bearing tests require the exact commit"
        )

    # Assert no tracked modifications — untracked files are ignored because they
    # don't affect the evidence-bearing code paths.
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=_GATED_DEV,
        capture_output=True,
        text=True,
    )
    if dirty.returncode == 0 and dirty.stdout.strip():
        raise RuntimeError(
            f"gated checkout has uncommitted tracked changes — "
            f"evidence-bearing tests require a clean tree:\n{dirty.stdout}"
        )


# ------------------------------------------------------------------
# Test-only factory (§P1-3 schema-negative)
# ------------------------------------------------------------------


def build_receipt_unchecked(
    kind: str,
    run_id: str,
    payload: dict[str, Any],
    signing_key: SigningKey,
) -> "Receipt":  # type: ignore[name-defined]  # noqa: F821
    """Build a Receipt with a valid digest+signature, bypassing schema validation.

    Use ONLY in tests that need a cryptographically valid receipt over a
    schema-invalid payload — to prove that schema and signature checks are
    independent gates in verify_integrity().

    NOT for production use. The Receipt will verify at the digest/signature
    level and fail at schema validation inside verify_integrity().
    """
    from core.chain import canonical_digest

    from orchestrator.evidence import (
        CANONICAL_DIGEST_VERSION,
        DOMAIN_PREFIX,
        Receipt,
        canonical_envelope,
    )
    from orchestrator.trust import sign_receipt

    safe_payload: dict[str, Any] = copy.deepcopy(payload)
    domain = f"{DOMAIN_PREFIX}-{kind}"
    digest = canonical_digest(
        domain,
        canonical_envelope(kind, run_id, safe_payload),
        version=CANONICAL_DIGEST_VERSION,
    )
    sig = sign_receipt(kind, digest, signing_key)
    return Receipt(kind=kind, run_id=run_id, payload=safe_payload, digest=digest, signature=sig)
