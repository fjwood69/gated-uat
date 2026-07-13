"""tests/test_cli.py — CLI argument parsing and trust-root enforcement.

Coverage:
- Argparse: --key-file and --trusted-verify-key-hex are required; omitting either
  raises SystemExit(2).
- Trust-root mismatch: signing key's derived verify key != --trusted-verify-key-hex
  → exit code 2 before any run is started.
- Trust-root match: signing key's derived verify key == --trusted-verify-key-hex
  → check passes; execution continues (fails later for corpus/gated reasons, not key
  mismatch — proving the trust gate is not a false barrier).
- CLI exit semantics: the trust-root check fires before any registry allocation or
  corpus load, so a mismatch is a configuration error (exit 2), not a run failure.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import MagicMock, patch

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from cli import _build_parser, _cmd_run
from profiles.p1_regression import CorpusConfigError


def _make_key_file() -> tuple[SigningKey, str, str]:
    """Generate a new SigningKey, write it to a temp file, return (key, path, vk_hex)."""
    key = SigningKey.generate()
    vk_hex: str = key.verify_key.encode(HexEncoder).decode()
    fd, path = tempfile.mkstemp(suffix=".key")
    os.write(fd, bytes(key))
    os.close(fd)
    return key, path, vk_hex


_VALID_DIGEST = "sha256:" + "a" * 64


def _args(
    *,
    key_file: str,
    trusted_verify_key_hex: str,
    image_ref: str = "localhost/mori:local",
    image_digest: str = _VALID_DIGEST,
    corpus_path: str = "/tmp/corpus",
    runs_dir: str = "/tmp/runs",
    trials: int = 1,
    profile: str = "p1",
) -> Namespace:
    return Namespace(
        profile=profile,
        image_ref=image_ref,
        image_digest=image_digest,
        trials=trials,
        key_file=key_file,
        trusted_verify_key_hex=trusted_verify_key_hex,
        corpus_path=corpus_path,
        runs_dir=runs_dir,
    )


class TestArgparse(unittest.TestCase):
    """Parser rejects invocations missing required arguments."""

    def _parse(self, argv: list[str]) -> Namespace:
        return _build_parser().parse_args(argv)

    def test_run_requires_key_file(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            self._parse([
                "run", "p1",
                "--image-ref", "localhost/mori:local",
                "--image-digest", "a" * 64,
                "--trusted-verify-key-hex", "b" * 64,
            ])
        self.assertEqual(cm.exception.code, 2)

    def test_run_requires_trusted_verify_key_hex(self) -> None:
        _, path, _ = _make_key_file()
        try:
            with self.assertRaises(SystemExit) as cm:
                self._parse([
                    "run", "p1",
                    "--image-ref", "localhost/mori:local",
                    "--image-digest", "a" * 64,
                    "--key-file", path,
                ])
            self.assertEqual(cm.exception.code, 2)
        finally:
            os.unlink(path)

    def test_run_requires_image_ref(self) -> None:
        _, path, vk = _make_key_file()
        try:
            with self.assertRaises(SystemExit) as cm:
                self._parse([
                    "run", "p1",
                    "--image-digest", "a" * 64,
                    "--key-file", path,
                    "--trusted-verify-key-hex", vk,
                ])
            self.assertEqual(cm.exception.code, 2)
        finally:
            os.unlink(path)

    def test_run_with_all_required_args_parses(self) -> None:
        _, path, vk = _make_key_file()
        try:
            ns = self._parse([
                "run", "p1",
                "--image-ref", "localhost/mori:local",
                "--image-digest", "a" * 64,
                "--key-file", path,
                "--trusted-verify-key-hex", vk,
            ])
            self.assertEqual(ns.profile, "p1")
            self.assertEqual(ns.trusted_verify_key_hex, vk)
        finally:
            os.unlink(path)


class TestTrustRootCheck(unittest.TestCase):
    """_cmd_run rejects invocations where the signing key does not match the pinned verify key."""

    def test_missing_key_file_exits_2(self) -> None:
        _, path, vk = _make_key_file()
        os.unlink(path)  # remove so file doesn't exist
        with patch("orchestrator.runtime.validate_image_digest"):
            result = _cmd_run(_args(key_file=path, trusted_verify_key_hex=vk))
        self.assertEqual(result, 2)

    def test_verify_key_mismatch_exits_2(self) -> None:
        """Signing key's derived verify key does not match the pinned trusted key → exit 2."""
        _, path, _ = _make_key_file()
        wrong_vk = "f" * 64  # any hex that is not the real verify key
        try:
            with patch("orchestrator.runtime.validate_image_digest"):
                result = _cmd_run(_args(key_file=path, trusted_verify_key_hex=wrong_vk))
            self.assertEqual(result, 2)
        finally:
            os.unlink(path)

    def test_verify_key_match_passes_trust_check(self) -> None:
        """Signing key's derived verify key matches → trust check passes.

        The run then fails for a different reason (corpus config error).  The point is
        that exit code 2 (trust mismatch) is NOT returned, proving the trust gate is
        not a false barrier when the key is correct.
        """
        _, path, correct_vk = _make_key_file()
        try:
            with (
                patch("orchestrator.runtime.validate_image_digest"),
                patch("cli._derive_gated_commit", return_value="628e5a3"),
                patch("orchestrator.isolation.Registry"),
                patch("profiles.p1_regression.run", side_effect=CorpusConfigError("no corpus")),
            ):
                result = _cmd_run(_args(key_file=path, trusted_verify_key_hex=correct_vk))
            # Must NOT be 2 (trust mismatch); corpus config error yields exit 1.
            self.assertNotEqual(result, 2, "exit 2 means trust-root check fired, not corpus error")
            self.assertEqual(result, 1)
        finally:
            os.unlink(path)

    def test_verify_key_mismatch_does_not_touch_registry(self) -> None:
        """A trust mismatch aborts before any run is allocated in the registry."""
        _, path, _ = _make_key_file()
        wrong_vk = "e" * 64
        try:
            mock_registry = MagicMock()
            with (
                patch("orchestrator.runtime.validate_image_digest"),
                patch("cli._derive_gated_commit", return_value="628e5a3"),
                patch("orchestrator.isolation.Registry", return_value=mock_registry),
            ):
                _cmd_run(_args(key_file=path, trusted_verify_key_hex=wrong_vk))
            mock_registry.allocate.assert_not_called()
        finally:
            os.unlink(path)

    def test_gated_pin_mismatch_exits_1(self) -> None:
        """verify_gated_dependency() raising RuntimeError → exit 1 with diagnostic."""
        _, path, correct_vk = _make_key_file()
        try:
            with (
                patch("orchestrator.runtime.validate_image_digest"),
                patch(
                    "cli._derive_gated_commit",
                    side_effect=RuntimeError("gated checkout is at 'e3a1f4a', expected '628e5a3'"),
                ),
            ):
                result = _cmd_run(_args(key_file=path, trusted_verify_key_hex=correct_vk))
            self.assertEqual(result, 1, "pin mismatch must produce exit 1, not 2 or 0")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
