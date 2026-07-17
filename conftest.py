"""conftest.py — gated sys.path injection, commit pin, and test helpers.

Production: install gated from a pinned artifact hash (§11). Development: add
the sibling checkout at ../gated. The pinned commit and clean-tree invariant are
enforced by orchestrator.gated_pin.verify_gated_dependency() — the same function
the CLI calls — so pytest and the installed CLI share exactly one enforcement path.

Pinned: 1d75d54 (gated 3.5 S3-completion: cross-store ABA closure + torn-read atomicity).
The authoritative pin lives in orchestrator.gated_pin._PINNED_COMMIT — this line is prose.
canonical_digest API contract: core.chain.canonical_digest(domain, payload, *, version=int) -> str
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

# Dedicated pin worktree — never reuse ../gated (the live step-3.5-jobs
# checkout).  One-time setup: run
#   git -C ../gated worktree add --detach ../gated-uat-pin \
#       1d75d54a97986e18fae499c370f8615e6cf89e15
# then leave it in place.
_GATED_DEV = Path(__file__).parent.parent / "gated-uat-pin"

if _GATED_DEV.is_dir():
    if str(_GATED_DEV) not in sys.path:
        sys.path.insert(0, str(_GATED_DEV))

    # Shared enforcement: exact-pin + clean-tree; raises RuntimeError on mismatch.
    # The adapter imports gate/engine modules from the worktree at runtime, so a
    # dirty or mismatched tree silently executes different bytes than 628e5a3.
    from orchestrator.gated_pin import verify_gated_dependency

    verify_gated_dependency(_GATED_DEV)


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
