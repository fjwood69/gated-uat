"""orchestrator/trust.py — signing-key management for the evidence chain.

Roles:
  EvidenceSigner — holds the Ed25519 signing key; signs each receipt.
  Verifier       — holds only the verify (public) key; never touches the
                   signing key. Verification requires no private material.

The trust anchor is the verify_key_hex pinned OUTSIDE the evidence chain.
The index embeds this hex for audit reference; verify_chain checks that it
matches the externally-supplied trusted key. An attacker who generates their
own keypair fails signature verification; even if they somehow passed that,
their embedded key would not match the pinned trusted anchor.

Key persistence:
  Signing key is written atomically with O_CREAT|O_EXCL at mode 0600,
  then fsync'd. Load-time checks refuse non-0600 or non-file paths.
  The verify key is derived on load (never stored separately).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError as _NaClBadSignatureError
from nacl.signing import SigningKey, VerifyKey

# Re-export so callers need not import nacl directly.
BadSignatureError = _NaClBadSignatureError

RECEIPT_KINDS: frozenset[str] = frozenset({"prereg", "execution", "teardown", "index"})


@dataclass(frozen=True)
class EvidenceSigner:
    """Holds the private signing key and derived public key hex.

    The signing key must never leave the trusted signing environment.
    Share only *verify_key_hex* with Verifiers and embed it in the index.
    """

    signing_key: SigningKey
    verify_key: VerifyKey
    verify_key_hex: str


def generate_signer() -> EvidenceSigner:
    """Generate a new Ed25519 EvidenceSigner. Persist the signing key immediately."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    return EvidenceSigner(
        signing_key=sk,
        verify_key=vk,
        verify_key_hex=vk.encode(HexEncoder).decode(),
    )


def load_signer(path: Path) -> EvidenceSigner:
    """Load an EvidenceSigner from a persisted signing-key file.

    Raises PermissionError if the file mode is not exactly 0600.
    Raises FileNotFoundError if the path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Signing key not found: {path}")
    if not path.is_file():
        raise PermissionError(f"Signing key path is not a regular file: {path}")
    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        raise PermissionError(
            f"Signing key {path} has mode {oct(mode)}, expected 0o600 — refusing to load"
        )
    data = json.loads(path.read_text())
    sk = SigningKey(bytes.fromhex(data["signing_key_hex"]))
    vk = sk.verify_key
    return EvidenceSigner(
        signing_key=sk,
        verify_key=vk,
        verify_key_hex=vk.encode(HexEncoder).decode(),
    )


def save_signing_key(signing_key: SigningKey, path: Path, *, overwrite: bool = False) -> None:
    """Persist the signing key atomically at mode 0600.

    Uses O_CREAT|O_EXCL for new files (atomic exclusive creation — no window
    under the process umask). Uses O_TRUNC + rename for overwrite (atomic
    replace via rename). fsync'd before the rename/close.

    Raises FileExistsError if the path exists and *overwrite* is False.
    """
    content = json.dumps(
        {"signing_key_hex": signing_key.encode(HexEncoder).decode()},
        separators=(",", ":"),
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)

    if overwrite:
        tmp = path.with_suffix(".key.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        tmp.rename(path)
    else:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)


def load_verify_key(hex_str: str) -> VerifyKey:
    """Reconstruct a VerifyKey from a hex string (the public trust anchor)."""
    return VerifyKey(bytes.fromhex(hex_str))


def sign_receipt(kind: str, digest_hex: str, signing_key: SigningKey) -> str:
    """Sign a receipt digest.

    Message: ``b"gated-uat-<kind>-signature:v1\\x00" + bytes.fromhex(digest_hex)``
    Returns the signature as lowercase hex.
    """
    if kind not in RECEIPT_KINDS:
        raise ValueError(f"Unknown receipt kind: {kind!r}")
    message = f"gated-uat-{kind}-signature:v1\x00".encode() + bytes.fromhex(digest_hex)
    signed = signing_key.sign(message)
    return bytes(signed.signature).hex()


def verify_receipt_sig(
    kind: str, digest_hex: str, signature_hex: str, verify_key: VerifyKey
) -> None:
    """Verify a receipt signature.

    Raises :exc:`BadSignatureError` on failure.
    Raises :exc:`ValueError` for malformed hex inputs.
    """
    if kind not in RECEIPT_KINDS:
        raise ValueError(f"Unknown receipt kind: {kind!r}")
    message = f"gated-uat-{kind}-signature:v1\x00".encode() + bytes.fromhex(digest_hex)
    verify_key.verify(message, bytes.fromhex(signature_hex))
