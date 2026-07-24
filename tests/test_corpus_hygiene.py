"""tests/test_corpus_hygiene.py — fixtures are sealed AS-IS from disk; keep the trees CLEAN.

``gauntlet.canonical_review_source`` seals the fixture tree from disk. Untracked cruft
(``.mypy_cache`` / ``__pycache__`` / ``.pytest_cache`` / a stray ``.pyc`` / editor junk) would
BLOAT the sealed source — a live review over a cruft-inflated tree ERRORs on the builder's
max-source guard, and any such file perturbs ``source_digest`` / ``request_digest``. This
fail-closed guard (born of the Board #2 live-run dry-run near-miss, where local ``.mypy_cache``
inflated a 12 KB fixture to 3.8 MB) keeps a dirty tree from ever reaching a mint again — the teeth
live in CI, not a run-time checklist line.
"""

from __future__ import annotations

from pathlib import Path

_CORPUS = Path(__file__).resolve().parent.parent / "corpora" / "fixtures"
_ALLOWED_FILES = frozenset({"main.py", "test_retry.py"})   # the only files a fixture may hold
_BANNED_DIRS = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git"})


def test_fixture_trees_are_clean() -> None:
    assert _CORPUS.is_dir(), f"corpus dir missing: {_CORPUS}"
    fixtures = [d for d in sorted(_CORPUS.iterdir()) if d.is_dir()]
    assert fixtures, "no fixture directories found"
    for fx in fixtures:
        for entry in sorted(fx.rglob("*")):
            rel = entry.relative_to(fx)
            if entry.is_dir():
                assert entry.name not in _BANNED_DIRS, f"cache/cruft dir in {fx.name}: {rel}"
                continue
            assert entry.suffix != ".pyc", f"stray .pyc in {fx.name}: {rel}"
            assert not entry.name.startswith("."), f"hidden / editor junk in {fx.name}: {rel}"
            assert entry.name in _ALLOWED_FILES, (
                f"unexpected file in {fx.name}: {rel} (allowed: {sorted(_ALLOWED_FILES)})")
        assert (fx / "main.py").is_file(), f"{fx.name} is missing main.py"
