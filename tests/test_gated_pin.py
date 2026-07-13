"""tests/test_gated_pin.py — unit tests for verify_gated_dependency().

Exercises the three rejection paths in isolation without relying on conftest.py
or a real gated checkout.  Each case uses a temp git repo seeded to the
required state so the subprocess calls return controlled output.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from orchestrator.gated_pin import _PINNED_COMMIT, _PINNED_COMMIT_SHORT, verify_gated_dependency


def _init_repo(path: Path, commit_sha: str | None = None) -> None:
    """Initialise a bare-minimum git repo with one commit at *commit_sha*.

    If *commit_sha* is None the repo has no commits (verify should fail at
    rev-parse).  Otherwise a single empty commit is created; the actual SHA
    will differ from *commit_sha* but we patch git output via monkeypatching
    where needed — here we just need a well-formed repo.
    """
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "test"],
        check=True,
    )
    if commit_sha is not None:
        (path / "placeholder").write_text("x")
        subprocess.run(["git", "-C", str(path), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(path), "commit", "-q", "-m", "init"],
            check=True,
        )


class TestVerifyGatedDependency(unittest.TestCase):
    """verify_gated_dependency() raises RuntimeError for every deviation."""

    def test_not_a_directory_path_nonexistent(self) -> None:
        """A non-existent path propagates from git rev-parse failure."""
        with TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no-such-dir"
            with self.assertRaises(RuntimeError) as cm:
                verify_gated_dependency(missing)
        self.assertIn("Could not verify gated commit", str(cm.exception))

    def test_wrong_commit_raises(self) -> None:
        """A repo at a different commit is rejected with the SHA mismatch message."""
        with TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            _init_repo(repo, commit_sha="placeholder")
            with self.assertRaises(RuntimeError) as cm:
                verify_gated_dependency(repo)
        msg = str(cm.exception)
        self.assertIn(_PINNED_COMMIT_SHORT, msg)
        self.assertIn(_PINNED_COMMIT, msg)

    def test_dirty_tree_raises(self) -> None:
        """A repo at the right commit but with uncommitted changes is rejected.

        We cannot construct a real commit at _PINNED_COMMIT in a temp repo, so
        this test monkeypatches subprocess.run to return controlled output for
        the two git calls, simulating: (1) rev-parse returns the pinned SHA;
        (2) status --porcelain returns a dirty line.
        """
        import unittest.mock as mock

        call_count = 0

        def fake_run(
            cmd: list[str], *, cwd: Path | None = None, **kwargs: object
        ) -> mock.MagicMock:
            nonlocal call_count
            call_count += 1
            result = mock.MagicMock()
            result.returncode = 0
            if "rev-parse" in cmd:
                result.stdout = _PINNED_COMMIT + "\n"
                result.stderr = ""
            else:
                # git status --porcelain
                result.stdout = " M gate/backends.py\n"
                result.stderr = ""
            return result

        with mock.patch("orchestrator.gated_pin.subprocess.run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as cm:
                verify_gated_dependency(Path("/fake/gated"))

        self.assertIn("clean", str(cm.exception))
        self.assertEqual(call_count, 2, "both git calls must have been made")

    def test_git_status_failure_raises(self) -> None:
        """A nonzero git status exit code is a hard error, not treated as clean."""
        import unittest.mock as mock

        call_count = 0

        def fake_run(
            cmd: list[str], *, cwd: Path | None = None, **kwargs: object
        ) -> mock.MagicMock:
            nonlocal call_count
            call_count += 1
            result = mock.MagicMock()
            if "rev-parse" in cmd:
                result.returncode = 0
                result.stdout = _PINNED_COMMIT + "\n"
                result.stderr = ""
            else:
                # git status exits nonzero — e.g. repository corruption
                result.returncode = 128
                result.stdout = ""
                result.stderr = "fatal: not a git repository"
            return result

        with mock.patch("orchestrator.gated_pin.subprocess.run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as cm:
                verify_gated_dependency(Path("/fake/gated"))

        self.assertIn("working tree", str(cm.exception))

    def test_clean_pinned_repo_returns_short_form(self) -> None:
        """A clean repo at the pinned commit returns the 7-char short form.

        Uses the real gated-uat-pin worktree if present; otherwise skips.
        """
        pin_dir = Path(__file__).parent.parent.parent / "gated-uat-pin"
        if not pin_dir.is_dir():
            self.skipTest("gated-uat-pin worktree not present")
        result = verify_gated_dependency(pin_dir)
        self.assertEqual(result, _PINNED_COMMIT_SHORT)


if __name__ == "__main__":
    unittest.main()
