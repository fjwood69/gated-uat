"""tests/test_attestation_projector.py — seals for the in-toto behavioural-verification projector.

The headline property of the projector shape is that a STRANGER can re-derive the Statement from
the published record alone. That claim is only worth publishing if it is MEASURED, so the keystone
here is a stranger-simulation: copy ONLY the published sealed-run directory into an isolated
location (no repo working tree, no PolicyStore, no local state), run the projector there, and
byte-compare the ``attested`` and ``derived`` blocks against the Statement produced from the repo.
``declared`` is excluded from the comparison BY CONSTRUCTION — it is the operator-asserted tier.

Also sealed: derived.* always carries source_fields + recipe (a derived field without a recipe is
the built-not-bound pattern reappearing inside the fix for it), declared.* is always flagged
un-evidenced, the subject binds the gate's OWN captured artifact hash, and statement_id
disambiguates cells that share a subject digest.
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

import pytest
from nacl.signing import SigningKey, VerifyKey

from attestation.projector import (
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    _pae,
    build_statements,
    canonical_json,
    dsse_envelope,
    project,
    read_sealed_run,
)

REPO = Path(__file__).resolve().parent.parent
BOARD3 = REPO / "sealed-runs" / "19e2136b-7fe1-41c6-b4a1-f3da008e3b81"
BOARD2 = REPO / "sealed-runs" / "67e2c03c-ae24-4db1-ac6a-30481ca5dbd5"
SEED = "11" * 32


def _statements(run_dir: Path) -> list[dict]:
    return build_statements(run_dir, read_sealed_run(run_dir))


# ==== KEYSTONE: stranger-simulation — the split is MEASURED, not declared ========================

@pytest.mark.parametrize("run_dir", [BOARD3, BOARD2], ids=["board3", "board2"])
def test_stranger_can_rederive_attested_and_derived(run_dir: Path, tmp_path: Path) -> None:
    """A stranger with ONLY the published sealed-run directory reproduces attested + derived
    byte-for-byte. declared is excluded by construction (it is not evidenced by the record)."""
    ours = _statements(run_dir)
    # isolate: copy ONLY the published run dir — no repo, no stores, no working tree
    isolated = tmp_path / "stranger" / run_dir.name
    shutil.copytree(run_dir, isolated)
    theirs = build_statements(isolated, read_sealed_run(isolated))

    assert len(ours) == len(theirs) and ours, "same cell count"
    for a, b in zip(ours, theirs, strict=True):
        assert a["subject"] == b["subject"], "subject must be re-derivable"
        assert a["predicate"]["statement_id"] == b["predicate"]["statement_id"]
        for block in ("attested", "derived"):
            assert canonical_json(a["predicate"][block]) == canonical_json(b["predicate"][block]), \
                f"{block} is NOT stranger-reproducible — the headline property fails"


def test_declared_is_excluded_from_the_reproducibility_claim() -> None:
    """declared.* is the operator-asserted tier: every field is flagged un-evidenced and defaults
    to null, so the artifact states what it cannot evidence instead of implying it."""
    for st in _statements(BOARD3):
        declared = st["predicate"]["declared"]
        assert declared, "declared block must exist (naming the residual, not hiding it)"
        for name, field in declared.items():
            assert field["evidenced_by_record"] is False, f"{name} must be flagged un-evidenced"
            assert field["value"] is None, f"{name} must default to null (not invented)"
            assert field["note"], f"{name} must say WHY it is not evidenced"
        for expected in ("calibration_state", "detector_digest", "execution_identity", "sandbox"):
            assert expected in declared


# ==== derived.* MUST carry source_fields + recipe (schema-required, not conventional) ============

@pytest.mark.parametrize("run_dir", [BOARD3, BOARD2], ids=["board3", "board2"])
def test_every_derived_field_has_source_fields_and_recipe(run_dir: Path) -> None:
    for st in _statements(run_dir):
        derived = st["predicate"]["derived"]
        assert derived, "derived block must not be empty"
        for name, field in derived.items():
            assert set(field) == {"value", "source_fields", "recipe"}, f"{name} shape"
            assert field["source_fields"], f"{name} must name its sources"
            assert field["recipe"].strip(), f"{name} must state its recipe"


def test_merge_effect_is_derived_never_attested() -> None:
    """Board ruling 2: merge_effect next to attested.outcome would be the built-not-bound
    overclaim — it must live in derived.* only."""
    for st in _statements(BOARD3):
        assert "merge_effect" not in st["predicate"]["attested"]
        assert "merge_effect" in st["predicate"]["derived"]


def test_merge_effect_recipe_matches_engine_semantics() -> None:
    """ADMIT/fail is a caught evasion (merge blocked); ADMIT is allowed. The projector must not
    re-label: it derives the consequence from the engine's own vocabulary."""
    by_cell = {st["predicate"]["attested"]["cell"]["cell_id"]: st for st in _statements(BOARD3)}
    for cell_id, st in by_cell.items():
        a, d = st["predicate"]["attested"], st["predicate"]["derived"]["merge_effect"]["value"]
        if a["result_kind"] == "admitted_run" and a["outcome"] == "fail":
            assert d == "blocked", f"{cell_id}: caught evasion must block the merge"
        elif a["result_kind"] == "admitted_run" and a["outcome"] == "pass":
            assert d == "allowed", f"{cell_id}: clean admitted run is allowed"
    # the tempting side is the demonstration: it must be blocked
    assert all(by_cell[c]["predicate"]["derived"]["merge_effect"]["value"] == "blocked"
               for c in by_cell if c.startswith("retry-swallow/"))


# ==== board_status: a cell-level Statement cannot imply a clean board ============================

def test_board_status_reflects_the_review_column() -> None:
    """Board ruling 5: emitting over a partially-errored board is honest ONLY if every Statement
    carries the board-level state. #2 refused entirely; #3 truncated on the clean cells."""
    for st in _statements(BOARD2):
        assert st["predicate"]["derived"]["board_status"]["value"] == "review_column_refused"
    for st in _statements(BOARD3):
        assert st["predicate"]["derived"]["board_status"]["value"] == "partial_error"


@pytest.mark.parametrize("run_dir", [BOARD3, BOARD2], ids=["board3", "board2"])
def test_board_status_is_derived_only_never_attested(run_dir: Path) -> None:
    """Dissent P1: board_status is a PROJECTOR COMPUTATION over the board's llm_review outcomes,
    so it must not occupy a measured-shaped slot — the same law merge_effect was moved for.

    Note WHY this needs its own seal: the stranger-simulation CANNOT catch this class. The review
    receipts are public, so a stranger recomputes the identical string and the keystone passes on a
    misclassified field. Reproducibility and correct CLASSIFICATION are two different properties.
    """
    for st in _statements(run_dir):
        assert "board_status" not in st["predicate"]["attested"]
        assert "board_status" in st["predicate"]["derived"]


@pytest.mark.parametrize("run_dir", [BOARD3, BOARD2], ids=["board3", "board2"])
def test_no_projector_computation_hides_in_attested(run_dir: Path) -> None:
    """The class law, not just its instances: no key that exists in derived.* may ALSO appear in
    attested.*. (The structural closure — populating attested.* only through a reader that records
    each field's source artifact + JSON pointer — is a named follow-up increment.)"""
    for st in _statements(run_dir):
        overlap = set(st["predicate"]["derived"]) & set(st["predicate"]["attested"])
        assert not overlap, f"projector computation(s) dual-homed in attested: {sorted(overlap)}"


def test_scope_disclaims_board_level_and_review_column() -> None:
    st = _statements(BOARD2)[0]
    scope = st["predicate"]["scope"]
    joined = " ".join(scope["does_not_attest"]).lower()
    assert "unauthenticated" in joined and "review" in joined
    assert "board-level" in joined
    assert "derived.board_status" in joined, "scope must point at the DERIVED board_status"
    assert scope["trust_root"] == "local-key"          # machine-readable enum, Rego-routable


# ==== subject binding + statement identity ======================================================

@pytest.mark.parametrize("run_dir", [BOARD3, BOARD2], ids=["board3", "board2"])
def test_subject_binds_the_gates_own_captured_artifact_hash(run_dir: Path) -> None:
    """The subject digest is the artifact hash enforce() ITSELF captured (payload top-level), not a
    re-derived view — that is what makes the binding meaningful rather than tautological."""
    receipts = {}
    for f in (run_dir / "board" / "receipts").glob("*gate.json"):
        p = json.loads(f.read_text())["payload"]
        receipts[str(p["cell_id"])] = str(p["artifact_tree_digest"])
    for st in _statements(run_dir):
        cell_id = st["predicate"]["attested"]["cell"]["cell_id"]
        subj = st["subject"][0]
        assert subj["name"] == cell_id, "subject.name carries cell_id (collision disambiguation)"
        assert subj["digest"]["sha256"] == receipts[cell_id].split(":", 1)[1]
        assert ":" not in subj["digest"]["sha256"], "in-toto digest is bare hex"


def test_statement_id_disambiguates_shared_subject_digests() -> None:
    """Two cells of one task share an artifact digest — statement_id + subject.name are what stop a
    verifier keyed on the digest alone from collapsing them."""
    sts = _statements(BOARD3)
    ids = [st["predicate"]["statement_id"] for st in sts]
    assert len(set(ids)) == len(ids), "statement_ids unique"
    by_digest: dict[str, list[str]] = {}
    for st in sts:
        by_digest.setdefault(st["subject"][0]["digest"]["sha256"], []).append(
            st["predicate"]["statement_id"])
    shared = [v for v in by_digest.values() if len(v) > 1]
    assert shared, "the collision case must actually exist in this corpus"
    for group in shared:
        assert len(set(group)) == len(group), "shared subject -> still-distinct statement_ids"


def test_statement_envelope_shape() -> None:
    for st in _statements(BOARD3):
        assert st["_type"] == STATEMENT_TYPE
        assert st["predicateType"] == PREDICATE_TYPE
        assert set(st) == {"_type", "subject", "predicateType", "predicate"}
        assert set(st["predicate"]) == {
            "statement_id", "attested", "declared", "derived", "scope", "stability_note"}
        assert "v0.1" in st["predicate"]["stability_note"]


# ==== DSSE ======================================================================================

def test_dsse_signature_verifies_over_pae() -> None:
    sk = SigningKey(bytes.fromhex(SEED))
    st = _statements(BOARD3)[0]
    env = dsse_envelope(st, sk, sk.verify_key.encode().hex())
    payload = base64.b64decode(env["payload"])
    assert json.loads(payload) == st                       # payload IS the Statement
    VerifyKey(bytes.fromhex(env["signatures"][0]["keyid"])).verify(
        _pae(env["payloadType"], payload), base64.b64decode(env["signatures"][0]["sig"]))
    assert env["payloadType"] == "application/vnd.in-toto+json"


def test_dsse_rejects_a_tampered_payload() -> None:
    from nacl.exceptions import BadSignatureError
    sk = SigningKey(bytes.fromhex(SEED))
    st = _statements(BOARD3)[0]
    env = dsse_envelope(st, sk, sk.verify_key.encode().hex())
    tampered = dict(st)
    tampered["predicate"] = {**st["predicate"], "statement_id": "forged/cell"}
    with pytest.raises(BadSignatureError):
        VerifyKey(bytes.fromhex(env["signatures"][0]["keyid"])).verify(
            _pae(env["payloadType"], canonical_json(tampered)),
            base64.b64decode(env["signatures"][0]["sig"]))


# ==== emit ======================================================================================

def test_project_emits_statements_dsse_and_pubkey(tmp_path: Path) -> None:
    out = tmp_path / "att"
    sts = project(BOARD3, out, SEED)
    assert len(sts) == 4
    assert len(list(out.glob("*.statement.json"))) == 4
    assert len(list(out.glob("*.dsse.json"))) == 4
    assert (out / "attestation-key.pub").is_file()
    blob = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    for marker in (b"sk-ant-", b"x-api-key", b"BEGIN "):
        assert marker not in blob, "no secret material in emitted attestations"


def test_projector_is_deterministic(tmp_path: Path) -> None:
    a = project(BOARD3, tmp_path / "a", SEED)
    b = project(BOARD3, tmp_path / "b", SEED)
    assert canonical_json(a) == canonical_json(b)


# ==== full JSON-Schema validation (bonus when jsonschema is installed) ==========================

@pytest.mark.parametrize("run_dir", [BOARD3, BOARD2], ids=["board3", "board2"])
def test_predicate_validates_against_published_schema(run_dir: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((REPO / "attestation" / "predicate-schema.json").read_text())
    for st in _statements(run_dir):
        jsonschema.validate(instance=st["predicate"], schema=schema)
