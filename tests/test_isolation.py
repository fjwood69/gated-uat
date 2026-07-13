"""tests/test_isolation.py — §9.7 double-allocation + state machine + UUID4 validation.

Phase 0 acceptance: two processes on the same filesystem racing to allocate
the same run_id serialize — one wins, one raises AllocationError.
"""
from __future__ import annotations

import multiprocessing
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path

from orchestrator.isolation import (
    AllocationError,
    Registry,
    RunState,
    RunStateError,
    run_id_slug,
    validate_run_id,
)


def _try_allocate(
    registry_path: str, run_id: str, result_queue: "multiprocessing.Queue[str]"
) -> None:
    try:
        reg = Registry(Path(registry_path))
        reg.allocate(run_id=run_id)
        result_queue.put("success")
    except AllocationError:
        result_queue.put("rejected")


class TestRunIdValidation(unittest.TestCase):
    def test_valid_uuid4_accepted(self) -> None:
        rid = str(uuid.uuid4())
        validate_run_id(rid)  # must not raise

    def test_arbitrary_text_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_run_id("my-custom-run-name")

    def test_uuid3_rejected(self) -> None:
        rid = str(uuid.uuid3(uuid.NAMESPACE_DNS, "example.com"))
        with self.assertRaises(ValueError):
            validate_run_id(rid)

    def test_empty_string_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_run_id("")

    def test_slug_format(self) -> None:
        rid = str(uuid.uuid4())
        slug = run_id_slug(rid)
        self.assertTrue(slug.startswith("r"))
        self.assertEqual(len(slug), 33)  # 'r' + 32 hex chars
        self.assertNotIn("-", slug)


class TestRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._path = Path(self._tmpdir) / "registry.db"

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _reg(self) -> Registry:
        return Registry(self._path)

    # ------------------------------------------------------------------
    # Basic allocation
    # ------------------------------------------------------------------

    def test_allocate_generates_uuid4(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        self.assertEqual(len(rid), 36)
        self.assertEqual(rid.count("-"), 4)
        validate_run_id(rid)  # confirms UUID4 format

    def test_allocate_custom_uuid4(self) -> None:
        reg = self._reg()
        rid = str(uuid.uuid4())
        result = reg.allocate(run_id=rid)
        self.assertEqual(result, rid)

    def test_allocate_arbitrary_text_rejected(self) -> None:
        reg = self._reg()
        with self.assertRaises(ValueError):
            reg.allocate(run_id="not-a-uuid")

    def test_distinct_allocations_unique(self) -> None:
        reg = self._reg()
        r1 = reg.allocate()
        r2 = reg.allocate()
        self.assertNotEqual(r1, r2)

    # ------------------------------------------------------------------
    # Double-allocation prevention — §9.7
    # ------------------------------------------------------------------

    def test_same_run_id_rejected(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        with self.assertRaises(AllocationError):
            reg.allocate(run_id=rid)

    def test_concurrent_processes_serialized(self) -> None:
        """§9.7: two processes racing on the same run_id — one wins, one is rejected."""
        ctx = multiprocessing.get_context("spawn")
        results: multiprocessing.Queue[str] = ctx.Queue()
        run_id = str(uuid.uuid4())

        p1 = ctx.Process(target=_try_allocate, args=(str(self._path), run_id, results))
        p2 = ctx.Process(target=_try_allocate, args=(str(self._path), run_id, results))
        p1.start()
        p2.start()
        p1.join(timeout=10)
        p2.join(timeout=10)

        self.assertEqual(p1.exitcode, 0, "p1 process did not exit cleanly")
        self.assertEqual(p2.exitcode, 0, "p2 process did not exit cleanly")

        outcomes = sorted([results.get(timeout=5), results.get(timeout=5)])
        self.assertEqual(outcomes, ["rejected", "success"])

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def test_is_active_after_allocation(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        self.assertTrue(reg.is_active(rid))

    def test_is_not_active_after_release(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        reg.release(rid)
        self.assertFalse(reg.is_active(rid))

    def test_release_reaped_state(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        reg.release(rid, state=RunState.REAPED)
        self.assertFalse(reg.is_active(rid))

    def test_release_failed_state(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        reg.release(rid, state=RunState.FAILED)
        self.assertFalse(reg.is_active(rid))

    def test_release_unknown_run_id_raises(self) -> None:
        reg = self._reg()
        with self.assertRaises(RunStateError):
            reg.release(str(uuid.uuid4()))

    def test_release_already_terminal_raises(self) -> None:
        reg = self._reg()
        rid = reg.allocate()
        reg.release(rid)
        with self.assertRaises(RunStateError):
            reg.release(rid)

    def test_release_active_state_rejected(self) -> None:
        """release() must refuse non-terminal target states."""
        reg = self._reg()
        rid = reg.allocate()
        with self.assertRaises(ValueError):
            reg.release(rid, state=RunState.ACTIVE)  # type: ignore[arg-type]

    def test_unknown_run_id_not_active(self) -> None:
        reg = self._reg()
        self.assertFalse(reg.is_active("00000000-0000-4000-8000-000000000000"))


if __name__ == "__main__":
    unittest.main()
