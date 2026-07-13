"""tests/test_corpus.py — corpus loading and vacuity guard tests.

Exercises _load_corpus() from profiles/p1_regression.py:
- Happy path: loads real corpus from corpora/
- Empty manifest: CorpusConfigError before any run is allocated
- Missing manifest.json: CorpusConfigError
- Missing fixture file: CorpusConfigError
- Payload digest mismatch: CorpusConfigError
- Vacuity guard: no KNOWN_GOOD or no KNOWN_BAD raises CorpusConfigError
- Unknown label: CorpusConfigError
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from core.calibration import FixtureLabel

from profiles.p1_regression import CorpusConfigError, _load_corpus

_REAL_CORPUS = Path(__file__).parent.parent / "corpora"


def _write_corpus(tmp: Path, fixtures: list[dict[str, Any]], *, include_files: bool = True) -> None:
    """Write a minimal corpus directory structure under *tmp*."""
    manifest = {
        "schema_version": 1,
        "gated_source_repo": "fjwood69/gated",
        "gated_pinned_commit": "96bebac",
        "detector_id": "RetryCheck",
        "detector_entrypoint": ["python3", "/artifact/main.py"],
        "fixtures": fixtures,
    }
    fixtures_dir = tmp / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    clean_fixtures = []
    for entry in fixtures:
        payload = entry.pop("_payload", b"# placeholder")
        entry.setdefault("payload_digest", "sha256:" + hashlib.sha256(payload).hexdigest())
        if include_files:
            fdir = fixtures_dir / entry["fixture_id"]
            fdir.mkdir(exist_ok=True)
            (fdir / "main.py").write_bytes(payload)
        clean_fixtures.append({k: v for k, v in entry.items()})
    manifest["fixtures"] = clean_fixtures
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    (tmp / "manifest.json").write_bytes(manifest_bytes)


class TestCorpusLoading(unittest.TestCase):
    def test_real_corpus_loads_successfully(self) -> None:
        """The committed corpus at corpora/ loads without error."""
        corpus = _load_corpus(_REAL_CORPUS)
        # 1 KNOWN_GOOD (retry-good-v1) + 2 KNOWN_BAD
        known_good = [f for f in corpus.fixtures if f.label is FixtureLabel.KNOWN_GOOD]
        known_bad = [f for f in corpus.fixtures if f.label is FixtureLabel.KNOWN_BAD]
        self.assertEqual(len(known_good), 1)
        self.assertEqual(len(known_bad), 2)
        self.assertTrue(corpus.manifest_digest)

    def test_real_corpus_is_adequate(self) -> None:
        """Corpus must have both KNOWN_GOOD and KNOWN_BAD (vacuity guard passes)."""
        corpus = _load_corpus(_REAL_CORPUS)
        cal_set = corpus.to_calibration_set()
        self.assertGreater(len(cal_set.known_good), 0)
        self.assertGreater(len(cal_set.known_bad), 0)

    def test_manifest_digest_is_sha256(self) -> None:
        """manifest_digest is a non-empty hex string."""
        corpus = _load_corpus(_REAL_CORPUS)
        self.assertEqual(len(corpus.manifest_digest), 64)
        int(corpus.manifest_digest, 16)  # must be valid hex

    def test_fixture_payload_digest_matches_manifest(self) -> None:
        """The payload bytes of each fixture match the digest in manifest.json."""
        manifest = json.loads((_REAL_CORPUS / "manifest.json").read_bytes())
        corpus = _load_corpus(_REAL_CORPUS)
        digest_by_id = {e["fixture_id"]: e["payload_digest"] for e in manifest["fixtures"]}
        for fixture in corpus.fixtures:
            expected_hex = digest_by_id[fixture.fixture_id].removeprefix("sha256:")
            actual_hex = hashlib.sha256(fixture.payload).hexdigest()
            self.assertEqual(actual_hex, expected_hex, msg=f"fixture {fixture.fixture_id!r}")


class TestCorpusConfigErrors(unittest.TestCase):
    def test_missing_manifest_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))

    def test_empty_fixtures_list_raises(self) -> None:
        """Empty fixtures list refuses before touching the registry."""
        with tempfile.TemporaryDirectory() as tmp:
            _write_corpus(Path(tmp), [])
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))

    def test_missing_fixture_file_raises(self) -> None:
        """Manifest references a fixture whose file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = [{"fixture_id": "no-such-fixture", "label": "KNOWN_GOOD"}]
            _write_corpus(Path(tmp), fixtures, include_files=False)
            # manually write manifest with a digest but no file
            manifest_file = Path(tmp) / "manifest.json"
            manifest = json.loads(manifest_file.read_bytes())
            manifest["fixtures"][0]["payload_digest"] = "sha256:" + "a" * 64
            manifest_file.write_bytes(json.dumps(manifest).encode())
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))

    def test_payload_digest_mismatch_raises(self) -> None:
        """Fixture file exists but SHA-256 doesn't match manifest."""
        with tempfile.TemporaryDirectory() as tmp:
            good = {"fixture_id": "f1", "label": "KNOWN_GOOD", "_payload": b"# real"}
            bad_entry = {"fixture_id": "f2", "label": "KNOWN_BAD", "_payload": b"# bad"}
            _write_corpus(Path(tmp), [good, bad_entry])
            # Corrupt the manifest digest for f2.
            manifest_file = Path(tmp) / "manifest.json"
            manifest = json.loads(manifest_file.read_bytes())
            for e in manifest["fixtures"]:
                if e["fixture_id"] == "f2":
                    e["payload_digest"] = "sha256:" + "0" * 64
            manifest_file.write_bytes(json.dumps(manifest).encode())
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))

    def test_vacuity_no_known_good_raises(self) -> None:
        """A corpus with only KNOWN_BAD fixtures is refused by the vacuity guard."""
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = [
                {"fixture_id": "b1", "label": "KNOWN_BAD", "_payload": b"# bad1"},
                {"fixture_id": "b2", "label": "KNOWN_BAD", "_payload": b"# bad2"},
            ]
            _write_corpus(Path(tmp), fixtures)
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))

    def test_vacuity_no_known_bad_raises(self) -> None:
        """A corpus with only KNOWN_GOOD fixtures is refused by the vacuity guard."""
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = [
                {"fixture_id": "g1", "label": "KNOWN_GOOD", "_payload": b"# good1"},
            ]
            _write_corpus(Path(tmp), fixtures)
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))

    def test_unknown_label_raises(self) -> None:
        """An entry with an unrecognised label is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = [
                {"fixture_id": "g1", "label": "KNOWN_GOOD", "_payload": b"# good"},
                {"fixture_id": "x1", "label": "MAYBE_BAD", "_payload": b"# unknown"},
            ]
            _write_corpus(Path(tmp), fixtures)
            with self.assertRaises(CorpusConfigError):
                _load_corpus(Path(tmp))


if __name__ == "__main__":
    unittest.main()
