"""orchestrator/evidence.py — the signed evidence CHAIN (§7).

Board-ratified chain: four independently-signed receipts + a final index.

    preregistration → execution → teardown → index

INTEGRITY vs ADMISSION are separate concerns:

  verify_integrity(chain, verify_key)
      Cryptographic + structural validity: signatures, digest matches, kind
      positions, run_id consistency, trust-anchor check, schema completeness.
      A chain with teardown.failure=True still passes integrity; it is a
      valid signed record of what happened.

  evaluate_admission(chain) -> bool
      Evidence admissibility: was the run complete and clean? Rejects chains
      where execution errored (infrastructure failure) or teardown failed.
      Separate from integrity — a failed-teardown chain may be cryptographically
      valid but must not be counted as a successful UAT run.

Trust anchor:
  verify_key (the externally-pinned VerifyKey) IS the trust root. After
  signature verification, verify_integrity checks that index.payload
  ["verify_key_hex"] encodes the same key. An attacker who self-signs a chain
  with a different key fails the signature check; even if signatures matched,
  their embedded key would not equal the pinned trusted anchor.

Canonicalizer coupling (§P1):
  All digest calls use canonical_digest(version=1) explicitly. The alg and
  version are recorded in execution receipts. A gated-internal version change
  must bump EVIDENCE_CHAIN_VERSION here and is visible in all signed evidence.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from core.chain import CANONICAL_DIGEST_VERSION, canonical_digest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

from .schemas import SchemaViolationError, validate_payload
from .trust import BadSignatureError, sign_receipt, verify_receipt_sig

EVIDENCE_CHAIN_VERSION = 1
_DOMAIN_PREFIX = "gated-uat-evidence"
_CANONICAL_ALG = "sha256"

# The expected receipt kinds in chain order (position is validated).
_CHAIN_ORDER = ("prereg", "execution", "teardown", "index")


# ------------------------------------------------------------------
# Errors — all fail-closed (§0.4, §9.9)
# ------------------------------------------------------------------


class ChainVerificationError(ValueError):
    """Verification failed — structural, cryptographic, or schema error."""


class MissingLinkError(ChainVerificationError):
    """A required receipt is absent from the chain."""


# ------------------------------------------------------------------
# Receipt dataclass
# ------------------------------------------------------------------


@dataclass(frozen=True)
class Receipt:
    kind: str             # prereg | execution | teardown | index
    run_id: str
    payload: dict[str, Any]   # deep-copied on construction; see build_receipt
    digest: str           # canonical_digest of the receipt envelope (v1)
    signature: str        # hex Ed25519 signature (trust.py sign_receipt)


# ------------------------------------------------------------------
# Building receipts
# ------------------------------------------------------------------


def _envelope(kind: str, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "run_id": run_id,
        "payload": payload,
        "chain_version": EVIDENCE_CHAIN_VERSION,
    }


def build_receipt(
    kind: str,
    run_id: str,
    payload: dict[str, Any],
    signing_key: SigningKey,
) -> Receipt:
    """Build and sign a single receipt.

    Validates the payload schema before signing — an incomplete payload is
    rejected here, not on verification. The payload is deep-copied so caller
    mutations after construction do not affect the signed evidence.
    """
    validate_payload(kind, payload)
    safe_payload: dict[str, Any] = copy.deepcopy(payload)
    domain = f"{_DOMAIN_PREFIX}-{kind}"
    digest = canonical_digest(
        domain, _envelope(kind, run_id, safe_payload), version=CANONICAL_DIGEST_VERSION
    )
    sig = sign_receipt(kind, digest, signing_key)
    return Receipt(kind=kind, run_id=run_id, payload=safe_payload, digest=digest, signature=sig)


def build_index(
    run_id: str,
    prereg: Receipt,
    execution: Receipt,
    teardown: Receipt,
    signing_key: SigningKey,
    verify_key_hex: str,
) -> Receipt:
    """Build and sign the index receipt, referencing the three prior receipts by digest."""
    from .schemas import SIGNER_ROLE
    payload: dict[str, Any] = {
        "schema_version": 1,
        "prereg": prereg.digest,
        "execution": execution.digest,
        "teardown": teardown.digest,
        "verify_key_hex": verify_key_hex,
        "signer_role": SIGNER_ROLE,
    }
    return build_receipt("index", run_id, payload, signing_key)


# ------------------------------------------------------------------
# Verification — fails closed (§0.4, §9.9)
# ------------------------------------------------------------------


def verify_integrity(
    prereg: Receipt | None,
    execution: Receipt | None,
    teardown: Receipt | None,
    index: Receipt | None,
    verify_key: VerifyKey,
) -> None:
    """Verify the complete four-link evidence chain — INTEGRITY only.

    Checks (all independently, all required):
    1. No link is missing (MissingLinkError).
    2. Each receipt is in the expected position (kind matches position).
    3. All receipts share the same run_id.
    4. Each receipt's stored digest matches the recomputed digest.
    5. Each receipt's signature is valid under *verify_key*.
    6. Schema completeness: each payload passes its kind-specific validator.
    7. Index cross-references match the actual prior receipt digests.
    8. Trust anchor: index.verify_key_hex encodes the same key as *verify_key*.

    Malformed hex inputs are wrapped in ChainVerificationError.
    Does NOT assess admission (outcome, teardown success) — see evaluate_admission.
    """
    # 1. Missing links.
    for name, receipt in zip(_CHAIN_ORDER, (prereg, execution, teardown, index)):
        if receipt is None:
            raise MissingLinkError(f"Missing required receipt: {name!r}")

    assert prereg is not None
    assert execution is not None
    assert teardown is not None
    assert index is not None

    # 2. Kind-in-position check.
    for expected_kind, receipt in zip(_CHAIN_ORDER, (prereg, execution, teardown, index)):
        if receipt.kind != expected_kind:
            raise ChainVerificationError(
                f"Receipt in position {expected_kind!r} has kind {receipt.kind!r}"
            )

    # 3. run_id consistency.
    run_ids = {r.run_id for r in (prereg, execution, teardown, index)}
    if len(run_ids) != 1:
        raise ChainVerificationError(
            f"Receipts have inconsistent run_ids: {run_ids!r}"
        )
    canonical_run_id = prereg.run_id

    # 4 + 5 + 6. Per-receipt: digest recompute, signature, schema.
    for receipt in (prereg, execution, teardown, index):
        _verify_one(receipt, verify_key)

    # 7. Index cross-references.
    for name, receipt in (("prereg", prereg), ("execution", execution), ("teardown", teardown)):
        expected = receipt.digest
        got = index.payload.get(name)
        if got != expected:
            raise ChainVerificationError(
                f"Index references {name!r} as {got!r} but receipt digest is {expected!r}"
            )

    # 8. Trust anchor: index.verify_key_hex must equal the externally-pinned key.
    trusted_hex = verify_key.encode(HexEncoder).decode()
    embedded_hex = index.payload.get("verify_key_hex", "")
    if embedded_hex != trusted_hex:
        raise ChainVerificationError(
            "index.verify_key_hex does not match the externally-trusted verify key — "
            "the chain was not signed by the trusted EvidenceSigner"
        )

    _ = canonical_run_id  # used implicitly via run_ids check above


def _verify_one(receipt: Receipt, verify_key: VerifyKey) -> None:
    """Verify a single receipt: digest recompute + signature + schema."""
    domain = f"{_DOMAIN_PREFIX}-{receipt.kind}"
    try:
        expected = canonical_digest(
            domain,
            _envelope(receipt.kind, receipt.run_id, receipt.payload),
            version=CANONICAL_DIGEST_VERSION,
        )
    except Exception as exc:
        raise ChainVerificationError(
            f"Receipt {receipt.kind!r}: error recomputing digest"
        ) from exc

    if receipt.digest != expected:
        raise ChainVerificationError(
            f"Receipt {receipt.kind!r} digest mismatch: "
            f"stored={receipt.digest!r} recomputed={expected!r}"
        )

    try:
        verify_receipt_sig(receipt.kind, receipt.digest, receipt.signature, verify_key)
    except BadSignatureError as exc:
        raise ChainVerificationError(
            f"Receipt {receipt.kind!r} signature invalid"
        ) from exc
    except (ValueError, Exception) as exc:
        raise ChainVerificationError(
            f"Receipt {receipt.kind!r}: malformed signature or digest hex"
        ) from exc

    try:
        validate_payload(receipt.kind, receipt.payload)
    except SchemaViolationError as exc:
        raise ChainVerificationError(
            f"Receipt {receipt.kind!r} schema violation: {exc}"
        ) from exc


# ------------------------------------------------------------------
# Admission — separate from integrity
# ------------------------------------------------------------------


def evaluate_admission(
    prereg: Receipt,
    execution: Receipt,
    teardown: Receipt,
) -> bool:
    """Assess whether a chain is admissible as successful UAT evidence.

    Returns True only when:
    - execution.outcome is "pass" or "fail" (a UAT verdict, not infra error)
    - teardown.failure is False (the run was cleanly torn down)

    A chain that fails admission may still be valid evidence of what happened
    (verify_integrity passes); it is not counted as a successful UAT run.
    Callers should log non-admissible chains rather than discarding them.
    """
    teardown_clean = not bool(teardown.payload.get("failure", True))
    execution_outcome = execution.payload.get("outcome", "error")
    return teardown_clean and execution_outcome in ("pass", "fail")


# ------------------------------------------------------------------
# Backward-compatible alias
# ------------------------------------------------------------------


def verify_chain(
    prereg: Receipt | None,
    execution: Receipt | None,
    teardown: Receipt | None,
    index: Receipt | None,
    verify_key: VerifyKey,
) -> None:
    """Alias for verify_integrity. Prefer verify_integrity in new code."""
    verify_integrity(prereg, execution, teardown, index, verify_key)


# ------------------------------------------------------------------
# Serialisation helpers
# ------------------------------------------------------------------


def receipt_to_dict(r: Receipt) -> dict[str, Any]:
    return {
        "kind": r.kind,
        "run_id": r.run_id,
        "payload": copy.deepcopy(r.payload),
        "digest": r.digest,
        "signature": r.signature,
    }


def receipt_from_dict(d: dict[str, Any]) -> Receipt:
    return Receipt(
        kind=d["kind"],
        run_id=d["run_id"],
        payload=copy.deepcopy(d["payload"]),
        digest=d["digest"],
        signature=d["signature"],
    )
