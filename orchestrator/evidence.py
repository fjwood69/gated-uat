"""orchestrator/evidence.py — the signed evidence CHAIN (§7).

Board-ratified chain: four independently-signed receipts + a final index.

    preregistration → execution → teardown → index

INTEGRITY vs ADMISSION are separate concerns:

  verify_integrity(chain, verify_key) -> VerifiedChain
      Cryptographic + structural validity: signatures, digest matches, kind
      positions, run_id consistency, trust-anchor check, schema completeness,
      semantic continuity (§P1-2), evidence continuity (§P0-closure). Returns
      a VerifiedChain on success. A chain with teardown.failure=True still
      passes integrity — it is a valid signed record of what happened.

  evaluate_admission(chain: VerifiedChain) -> bool
      Evidence admissibility: was the run clean enough to be counted?
      Accepts only a VerifiedChain to ensure integrity was verified first.
      A gated "fail" verdict IS admissible evidence. An "error" outcome or
      a failed teardown is NOT — those are infrastructure failures.

Trust anchor:
  verify_key (the externally-pinned VerifyKey) IS the trust root. After
  signature verification, verify_integrity checks that index.payload
  ["verify_key_hex"] encodes the same key. An attacker who self-signs a chain
  with a different key fails the signature check; even if signatures matched,
  their embedded key would not equal the pinned trusted anchor.

Canonicalizer version (§P1-1):
  CANONICAL_DIGEST_VERSION is pinned locally as the literal 1. It is NOT
  imported from core.chain — if gated bumps its constant, evidence-chain v1
  is unaffected. The version is recorded in execution receipts; a future
  evidence-chain version must define a new local literal.

VerifiedChain integrity seal (§P0-closure):
  _VERIFIED_SENTINEL is a module-private object. VerifiedChain.__post_init__
  raises TypeError unless the sentinel is passed — only verify_integrity()
  holds it. This proves, at the type level, that integrity was verified before
  evaluate_admission() is called.

Evidence continuity (§P0-closure):
  execution.payload["prereg_digest"] must equal prereg.digest.
  teardown.payload["execution_digest"] must equal execution.digest.
  Enforced both at BUILD TIME (via asymmetric builders) and at VERIFY TIME
  (cross-reference checks 7a/7b in verify_integrity). Defence in depth: a
  receipt constructed outside the normal builders still fails at verify.
"""
from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass
from typing import Any

from core.chain import canonical_digest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

from .isolation import validate_run_id
from .schemas import SIGNER_ROLE, SchemaViolationError, validate_payload
from .trust import BadSignatureError, sign_receipt, verify_receipt_sig

EVIDENCE_CHAIN_VERSION = 1

# Canonicalization protocol constants — public because they are the wire-format
# contract. Third-party verifiers and tests need the exact domain/envelope
# structure to reproduce digests. CANONICAL_DIGEST_VERSION is pinned locally
# (do NOT import from core.chain).
CANONICAL_DIGEST_VERSION = 1
DOMAIN_PREFIX = "gated-uat-evidence"

# The expected receipt kinds in chain order (position is validated).
_CHAIN_ORDER = ("prereg", "execution", "teardown", "index")

# Module-private sentinel: only verify_integrity() holds a reference.
# VerifiedChain.__post_init__ rejects construction without this sentinel,
# proving integrity was verified before evaluate_admission() is called.
_VERIFIED_SENTINEL = object()


# ------------------------------------------------------------------
# Errors — all fail-closed (§0.4, §9.9)
# ------------------------------------------------------------------


class ChainVerificationError(ValueError):
    """Verification failed — structural, cryptographic, or schema error."""


class MissingLinkError(ChainVerificationError):
    """A required receipt is absent from the chain."""


class SemanticContinuityError(ChainVerificationError):
    """Receipt payloads are internally inconsistent across the chain."""


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
# VerifiedChain — proof that verify_integrity passed (§P1-4, §P0-closure)
# ------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedChain:
    """Proof-of-integrity: verify_integrity() returns this on success.

    evaluate_admission() accepts only this type, ensuring callers cannot
    skip integrity verification before checking admissibility.

    Construction is sealed: __post_init__ raises TypeError unless the
    module-private _VERIFIED_SENTINEL is passed. Only verify_integrity()
    holds the sentinel, so external callers cannot forge a VerifiedChain.

    verify_key_hex stores the trusted verifying key as a stable, hashable,
    serialisable hex string rather than a nacl VerifyKey object (which is
    not guaranteed hashable, breaking frozen-dataclass __hash__).
    """

    prereg: Receipt
    execution: Receipt
    teardown: Receipt
    index: Receipt
    verify_key_hex: str  # hex Ed25519 key that verified this chain
    # InitVar: passed to __post_init__ but NOT stored as an attribute.
    _sentinel: dataclasses.InitVar[object | None] = None

    def __post_init__(self, _sentinel: object | None) -> None:
        if _sentinel is not _VERIFIED_SENTINEL:
            raise TypeError(
                "VerifiedChain must be constructed via verify_integrity(), not directly. "
                "External construction bypasses integrity verification."
            )

    @property
    def is_admitted(self) -> bool:
        """Convenience delegation to evaluate_admission(self)."""
        return evaluate_admission(self)


# ------------------------------------------------------------------
# Canonicalisation helpers (public protocol surface)
# ------------------------------------------------------------------


def canonical_envelope(
    kind: str, run_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Build the canonical envelope for digest/signature computation.

    This is the wire-format contract — public so third-party verifiers and
    tests can reproduce digests without depending on private internals.
    """
    return {
        "kind": kind,
        "run_id": run_id,
        "payload": payload,
        "chain_version": EVIDENCE_CHAIN_VERSION,
    }


# ------------------------------------------------------------------
# Building receipts
# ------------------------------------------------------------------


def build_receipt(
    kind: str,
    run_id: str,
    payload: dict[str, Any],
    signing_key: SigningKey,
) -> Receipt:
    """Build and sign a single receipt.

    Validates UUID4 format of run_id and payload schema before signing.
    An invalid run_id or incomplete payload is rejected here, not on
    verification. The payload is deep-copied so caller mutations after
    construction do not affect the signed evidence.
    """
    validate_run_id(run_id)
    validate_payload(kind, payload)
    safe_payload: dict[str, Any] = copy.deepcopy(payload)
    domain = f"{DOMAIN_PREFIX}-{kind}"
    digest = canonical_digest(
        domain,
        canonical_envelope(kind, run_id, safe_payload),
        version=CANONICAL_DIGEST_VERSION,
    )
    sig = sign_receipt(kind, digest, signing_key)
    return Receipt(kind=kind, run_id=run_id, payload=safe_payload, digest=digest, signature=sig)


def build_execution_receipt(
    prereg: Receipt,
    payload: dict[str, Any],
    signing_key: SigningKey,
) -> Receipt:
    """Build and sign an execution receipt bound to a specific preregistration.

    Injects ``prereg_digest`` from *prereg.digest* into the payload before
    signing. Any caller-supplied ``prereg_digest`` is overwritten so the
    binding is always derived from the actual receipt, not asserted by the
    caller.

    Uses *prereg.run_id* as the run_id — execution and prereg must share
    the same run.
    """
    safe_payload: dict[str, Any] = copy.deepcopy(payload)
    safe_payload["prereg_digest"] = prereg.digest
    return build_receipt("execution", prereg.run_id, safe_payload, signing_key)


def build_teardown_receipt(
    execution: Receipt,
    payload: dict[str, Any],
    signing_key: SigningKey,
) -> Receipt:
    """Build and sign a teardown receipt bound to a specific execution.

    Injects ``execution_digest`` from *execution.digest* into the payload
    before signing. Any caller-supplied ``execution_digest`` is overwritten
    so the binding is always derived from the actual receipt.

    Uses *execution.run_id* as the run_id — teardown and execution must
    share the same run.
    """
    safe_payload: dict[str, Any] = copy.deepcopy(payload)
    safe_payload["execution_digest"] = execution.digest
    return build_receipt("teardown", execution.run_id, safe_payload, signing_key)


def build_index(
    run_id: str,
    prereg: Receipt,
    execution: Receipt,
    teardown: Receipt,
    signing_key: SigningKey,
    verify_key_hex: str,
) -> Receipt:
    """Build and sign the index receipt, referencing the three prior receipts by digest."""
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
# Semantic continuity — §P1-2
# ------------------------------------------------------------------


def validate_semantic_continuity(
    prereg: Receipt,
    execution: Receipt,
    teardown: Receipt,
) -> None:
    """Verify semantic consistency across the three evidence receipts.

    Raises SemanticContinuityError if:
    - profile is not identical across all three receipts
    - execution.gated_commit != prereg.gated_commit

    Called from verify_integrity() after per-receipt checks complete.
    Also testable in isolation by passing Receipt objects directly.
    """
    prereg_profile = prereg.payload.get("profile")
    exec_profile = execution.payload.get("profile")
    td_profile = teardown.payload.get("profile")
    if prereg_profile != exec_profile or prereg_profile != td_profile:
        raise SemanticContinuityError(
            f"Profile mismatch across chain: "
            f"prereg={prereg_profile!r} execution={exec_profile!r} teardown={td_profile!r}"
        )
    prereg_commit = prereg.payload.get("gated_commit")
    exec_commit = execution.payload.get("gated_commit")
    if prereg_commit != exec_commit:
        raise SemanticContinuityError(
            f"gated_commit mismatch: prereg={prereg_commit!r} execution={exec_commit!r}"
        )


# ------------------------------------------------------------------
# Verification — fails closed (§0.4, §9.9)
# ------------------------------------------------------------------


def verify_integrity(
    prereg: Receipt | None,
    execution: Receipt | None,
    teardown: Receipt | None,
    index: Receipt | None,
    verify_key: VerifyKey,
) -> VerifiedChain:
    """Verify the complete four-link evidence chain — INTEGRITY only.

    Checks (all independently, all required):
    1. No link is missing (MissingLinkError).
    2. Each receipt is in the expected position (kind matches position).
    3. All receipts share the same run_id.
    4–6. Per-receipt: digest recompute, signature, schema.
    7a. Evidence continuity: execution.prereg_digest == prereg.digest.
    7b. Evidence continuity: teardown.execution_digest == execution.digest.
    7c. Index cross-references match the actual prior receipt digests.
    8. Trust anchor: index.verify_key_hex encodes the same key as *verify_key*.
    9. Semantic continuity: identical profile, consistent gated_commit.

    Returns a VerifiedChain on success. Raises on any failure (fail-closed).
    Does NOT assess admission — see evaluate_admission(VerifiedChain).
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

    # 4–6. Per-receipt: digest recompute, signature, schema.
    for receipt in (prereg, execution, teardown, index):
        _verify_one(receipt, verify_key)

    # 7a. Evidence continuity: execution must bind prereg.
    exec_prereg_digest = execution.payload.get("prereg_digest", "")
    if exec_prereg_digest != prereg.digest:
        raise ChainVerificationError(
            f"execution.prereg_digest {exec_prereg_digest!r} does not match "
            f"prereg.digest {prereg.digest!r}"
        )

    # 7b. Evidence continuity: teardown must bind execution.
    td_exec_digest = teardown.payload.get("execution_digest", "")
    if td_exec_digest != execution.digest:
        raise ChainVerificationError(
            f"teardown.execution_digest {td_exec_digest!r} does not match "
            f"execution.digest {execution.digest!r}"
        )

    # 7c. Index cross-references.
    for name, receipt in (
        ("prereg", prereg),
        ("execution", execution),
        ("teardown", teardown),
    ):
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

    # 9. Semantic continuity.
    validate_semantic_continuity(prereg, execution, teardown)

    return VerifiedChain(
        prereg=prereg,
        execution=execution,
        teardown=teardown,
        index=index,
        verify_key_hex=trusted_hex,
        _sentinel=_VERIFIED_SENTINEL,
    )


def _verify_one(receipt: Receipt, verify_key: VerifyKey) -> None:
    """Verify a single receipt: digest recompute + signature + schema."""
    domain = f"{DOMAIN_PREFIX}-{receipt.kind}"
    try:
        expected = canonical_digest(
            domain,
            canonical_envelope(receipt.kind, receipt.run_id, receipt.payload),
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
# Admission — separate from integrity, requires VerifiedChain (§P1-4)
# ------------------------------------------------------------------


def evaluate_admission(chain: VerifiedChain) -> bool:
    """Assess whether a VerifiedChain constitutes admissible UAT evidence.

    Accepts only a VerifiedChain — integrity must be verified before
    admission is checked. Callers cannot bypass verify_integrity().

    Returns True when:
    - execution.outcome is "pass" or "fail" (a UAT verdict, not infra error)
    - teardown.failure is False (the run was cleanly torn down)

    A gated "fail" verdict IS admissible — it is evidence that the gate
    correctly blocked a non-compliant promotion. An "error" outcome or a
    failed teardown is NOT admissible (infrastructure failure, not a verdict).

    Non-admissible chains should be logged rather than discarded; they are
    still cryptographically valid records of what happened.
    """
    teardown_clean = not bool(chain.teardown.payload.get("failure", True))
    execution_outcome = chain.execution.payload.get("outcome", "error")
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
) -> VerifiedChain:
    """Alias for verify_integrity. Prefer verify_integrity in new code."""
    return verify_integrity(prereg, execution, teardown, index, verify_key)


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
