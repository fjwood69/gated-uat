"""tests/test_runtime.py — RuntimePack stub (§P0-closure, Phase 0)."""
from __future__ import annotations

import unittest

from orchestrator.runtime import (
    RuntimePack,
    RuntimePackError,
    compute_runtime_pack_digest,
    validate_runtime_pack,
)


def _pack(**kwargs: str) -> RuntimePack:  # type: ignore[type-arg]
    defaults = {
        "runtime_id": "python-3.11-test",
        "version": "0.0.1-dev",
        "toolchain_image_digest": "",
        "accepted_source_forms": ("sdist",),
        "isolated_build_plan": "",
        "frozen_run_command": "pytest tests/",
        "dependency_policy": "",
        "observer_capabilities": ("stdout", "exit_code"),
        "resource_budget": "",
    }
    return RuntimePack(**{**defaults, **kwargs})  # type: ignore[arg-type]


class TestRuntimePack(unittest.TestCase):
    def test_valid_pack_passes(self) -> None:
        validate_runtime_pack(_pack())  # must not raise

    def test_missing_runtime_id_raises(self) -> None:
        with self.assertRaises(RuntimePackError):
            validate_runtime_pack(_pack(runtime_id=""))

    def test_missing_version_raises(self) -> None:
        with self.assertRaises(RuntimePackError):
            validate_runtime_pack(_pack(version=""))

    def test_missing_frozen_run_command_raises(self) -> None:
        with self.assertRaises(RuntimePackError):
            validate_runtime_pack(_pack(frozen_run_command=""))

    def test_digest_is_hex64(self) -> None:
        d = compute_runtime_pack_digest(_pack())
        self.assertEqual(len(d), 64)
        self.assertRegex(d, r"^[0-9a-f]{64}$")

    def test_digest_stable(self) -> None:
        pack = _pack()
        self.assertEqual(compute_runtime_pack_digest(pack), compute_runtime_pack_digest(pack))

    def test_digest_differs_on_field_change(self) -> None:
        d1 = compute_runtime_pack_digest(_pack(version="1.0.0"))
        d2 = compute_runtime_pack_digest(_pack(version="2.0.0"))
        self.assertNotEqual(d1, d2)

    def test_frozen_pack(self) -> None:
        pack = _pack()
        with self.assertRaises(Exception):
            pack.version = "mutated"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
