"""attestation/projector.py — project a PUBLISHED sealed-run record into in-toto Statements.

A PROJECTOR, not an emit path: it reads a published sealed-run directory and emits one signed
in-toto Statement (+ DSSE envelope) per gated cell. It touches NOTHING sealed — no render_board,
no receipt schema, no provider-gate, no ALLOWED_PATHS — and it runs strictly downstream of a
board that has already been published.

THE PROPERTY THIS SHAPE BUYS (and the reason for the field grouping): because the sealed record
is public, a stranger can re-run this projector over it and byte-compare their ``attested`` and
``derived`` blocks against the published Statement. That claim is only true for fields actually
present in the public record — so the predicate encodes provenance CLASS IN THE FIELD PATH:

  * ``attested.*`` — read from the published SIGNED artifacts (receipts / manifest). A stranger
    reproduces these exactly. This is the measured tier.
  * ``derived.*``  — computed HERE by the projector. Every derived field carries ``source_fields``
    + ``recipe`` (schema-REQUIRED, not conventional): a derived field without a recipe is the
    built-not-bound pattern reappearing inside the fix for it. A stranger reproduces these too
    (same inputs, stated recipe) — they are re-derivable but NOT measured by the gate.
  * ``declared.*`` — operator-asserted, NOT evidenced by the published record (calibration state,
    detector digest, execution identity, sandbox posture). A stranger CANNOT reproduce these; by
    default they are emitted as ``null`` with a per-field note, so the artifact states what it
    cannot evidence rather than quietly implying it.

Run:  python attestation/projector.py <sealed-run-dir> --out <dir> [--key <hex seed>]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

PREDICATE_TYPE = "https://gated.dev/attestations/behavioural-verification/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Fields the sealed record does NOT evidence (board ruling: declared, never attested). Emitted as
# null + note unless an operator supplies --declarations; excluded from the stranger comparison.
_DECLARED_FIELDS = {
    "calibration_state": "policy ENABLED state lives in the gate's PolicyStore — out-of-band",
    "detector_digest": "not published in the sealed record",
    "execution_identity": "the canonicalised 4-tuple is not published",
    "sandbox": "gate runtime / network posture / gate image pin are not published "
               "(manifest toolchain.env_digest is the static/own_tests image, NOT proven to be "
               "the gate's sandbox image)",
}

STABILITY_NOTE = (
    "v0.1 — field names may change before v1. RESIDUALS: (1) declared.* is operator-asserted and "
    "NOT stranger-reproducible (calibration_state, detector_digest, execution_identity, sandbox "
    "posture — none published). (2) corpus is a VERSION STRING, not a digest: a corpus that "
    "changes without the string changing yields a stale-but-signed attestation; closing it needs "
    "a corpus digest in the manifest (future mint). (3) manifest toolchain.env_digest is the "
    "static/own_tests image and is NOT proven to be the gate's sandbox image — the gate's "
    "execution environment is not evidenced by the published record. (4) trust_root is "
    "'local-key': no hardware root, no TEE, no third-party notarisation (reference-tier). "
    "(5) pre-mint commitment ordering for the published boards is OPERATIONAL, not "
    "artifact-provable, and is PERMANENTLY so — a timestamp applied now proves existence-by-now, "
    "which is after those runs; TSA helps FUTURE mints only. (6) derived.merge_effect is computed "
    "by this projector and was NEVER emitted by the gate."
)

SCOPE = {
    "attests": "the behaviour measured by the gate for this cell's artifact, under the conditions "
               "evidenced in attested.*",
    "does_not_attest": [
        "provenance of the bytes (a provenance predicate's job — they compose on the same subject)",
        "general correctness of the artifact",
        "anything about the review column: llm_review verdicts are UNAUTHENTICATED model output",
        "any board-level claim — this Statement is scoped to ONE cell (see attested.board_status)",
    ],
    "trust_root": "local-key",
}


# ------------------------------------------------------------------
# Reading the published record (the ONLY input)
# ------------------------------------------------------------------


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _bare_hex(digest: str) -> str:
    """in-toto ``digest.sha256`` is bare hex; the sealed record writes ``sha256:<hex>``."""
    return digest.split(":", 1)[1] if ":" in digest else digest


def read_sealed_run(run_dir: Path) -> dict[str, Any]:
    """Read a PUBLISHED sealed-run directory. No repo working tree, no PolicyStore, no local
    state — exactly what a stranger who cloned the public repo can see."""
    board = run_dir / "board"
    receipts = board / "receipts"
    manifest = _load(receipts / "manifest.json")
    gate, review = [], []
    for f in sorted(receipts.glob("*.json")):
        if f.name == "manifest.json":
            continue
        r = _load(f)
        stage = str(r["payload"]["stage"])
        if stage == "gate":
            gate.append(r)
        elif stage == "llm_review":
            review.append(r)
    cpath = run_dir / "commitment.json"
    commitment = _load(cpath) if cpath.is_file() else None
    return {"manifest": manifest, "gate": gate, "review": review, "commitment": commitment}


# ------------------------------------------------------------------
# Derived values — each MUST carry source_fields + recipe (schema-required)
# ------------------------------------------------------------------


def _derive_merge_effect(result_kind: str, outcome: str) -> dict[str, Any]:
    """The promotion consequence. NEVER emitted by the gate — computed here, so it lives in
    derived.* with its recipe (board ruling 2: a sibling of attested.outcome would be the
    built-not-bound overclaim)."""
    if result_kind == "admitted_run":
        value = "allowed" if outcome == "pass" else "blocked"
    elif result_kind == "blocking_refusal":
        value = "blocked"
    else:
        value = "indeterminate"
    return {
        "value": value,
        "source_fields": ["attested.outcome", "attested.result_kind"],
        "recipe": ("admitted_run + pass -> allowed; admitted_run + fail -> blocked (the detector "
                   "judged it and the required check fails); blocking_refusal -> blocked; "
                   "non_run / infrastructure_failure -> indeterminate"),
    }


def _derive_board_status(review_receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Board-level review-column state, so a reader of ONE cell cannot mistake a partially-errored
    board for a clean one (board ruling 5)."""
    outcomes = [str(r["payload"]["outcome"]) for r in review_receipts]
    if outcomes and all(o == "error" for o in outcomes):
        value = "review_column_refused"
    elif any(o == "error" for o in outcomes):
        value = "partial_error"
    else:
        value = "review_column_complete"
    return {
        "value": value,
        "source_fields": ["llm_review receipt outcomes (all cells of this board)"],
        "recipe": ("all llm_review outcomes == error -> review_column_refused; any == error -> "
                   "partial_error; otherwise review_column_complete"),
    }


# ------------------------------------------------------------------
# Building one Statement per gated cell
# ------------------------------------------------------------------


def build_statements(
    run_dir: Path, sealed: dict[str, Any], declarations: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """One in-toto Statement per GATE cell. ``subject.name`` carries the cell_id (board ruling 3:
    the digest alone is a semantic collision — two cells of one task share an artifact digest but
    may carry different verdicts), and ``statement_id`` is ``<board_id>/<cell_id>``."""
    manifest = sealed["manifest"]
    mp = manifest["payload"]
    board_id = str(manifest["run_id"])
    detector_by_task = {str(t["task_id"]): str(t.get("detector_id", "")) for t in mp["tasks"]}
    corpus_by_task = {str(t["task_id"]): str(t.get("invariant_corpus_version", ""))
                      for t in mp["tasks"]}
    board_status = _derive_board_status(sealed["review"])

    statements: list[dict[str, Any]] = []
    for r in sealed["gate"]:
        p = r["payload"]
        obs = p["observation"]
        cell_id = str(p["cell_id"])
        task_id = cell_id.split("/", 1)[0]
        # PRECISION (board): artifact_tree_digest from the receipt payload TOP-LEVEL (the subject);
        # measured_tree_digest from the observation.
        subject_digest = _bare_hex(str(p["artifact_tree_digest"]))

        attested = {
            "outcome": str(p["outcome"]),
            "result_kind": str(obs.get("result_kind", "")),
            "gate_outcome": str(obs.get("gate_outcome", "")),
            "measurement": {
                "result_reason": str(obs.get("result_reason", "")),
                "result_sub_reason": str(obs.get("result_sub_reason", "")),
                "measured_tree_digest": str(obs.get("measured_tree_digest", "")),
            },
            "cell": {
                "cell_id": cell_id, "task_id": str(p["side"]) and task_id,
                "side": str(p["side"]), "lineage": str(p["lineage"]),
                "reviewer_lineage": str(p["reviewer_lineage"]),
            },
            "detector_id": detector_by_task.get(task_id, ""),
            "corpus_version": corpus_by_task.get(task_id, ""),
            "code_sha": str(p["code_sha"]),
            "gated_commit": str(mp["gated_commit"]),
            "preregistered_at": str(mp["preregistered_at"]),
            "denominator": mp["denominator"],
            "board_status": board_status["value"],
            "linkage": {
                "board_id": board_id,
                "manifest_digest": str(p["manifest_digest"]),
                "receipt_run_id": str(r["run_id"]),
                "receipt_digest": str(r["digest"]),
                "commitment_digest": (
                    hashlib.sha256(
                        json.dumps(sealed["commitment"]["body"], sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")).hexdigest()
                    if sealed["commitment"] else ""),
                "sealed_run_path": f"sealed-runs/{run_dir.name}",
            },
        }
        declared = {
            k: {"value": (declarations or {}).get(k), "evidenced_by_record": False, "note": note}
            for k, note in _DECLARED_FIELDS.items()
        }
        derived = {
            "merge_effect": _derive_merge_effect(attested["result_kind"], attested["outcome"]),
            "board_status": board_status,
        }
        statements.append({
            "_type": STATEMENT_TYPE,
            "subject": [{"name": cell_id, "digest": {"sha256": subject_digest}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "statement_id": f"{board_id}/{cell_id}",
                "attested": attested,
                "declared": declared,
                "derived": derived,
                "scope": SCOPE,
                "stability_note": STABILITY_NOTE,
            },
        })
    statements.sort(key=lambda s: s["predicate"]["statement_id"])
    return statements


# ------------------------------------------------------------------
# DSSE
# ------------------------------------------------------------------


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (v1)."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" " + \
        str(len(payload)).encode() + b" " + payload


def dsse_envelope(
    statement: dict[str, Any], signing_key: SigningKey, key_id: str,
) -> dict[str, Any]:
    payload = canonical_json(statement)
    sig = signing_key.sign(_pae(DSSE_PAYLOAD_TYPE, payload)).signature
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def canonical_json(obj: Any) -> bytes:
    """The byte form everything is signed/compared over — stable across runs and machines."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------


def project(run_dir: Path, out_dir: Path, seed_hex: str | None = None,
            declarations: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    sealed = read_sealed_run(run_dir)
    statements = build_statements(run_dir, sealed, declarations)
    sk = SigningKey(bytes.fromhex(seed_hex)) if seed_hex else SigningKey.generate()
    key_id = sk.verify_key.encode().hex()
    out_dir.mkdir(parents=True, exist_ok=True)
    for st in statements:
        slug = st["predicate"]["statement_id"].split("/", 1)[1].replace("/", "_")
        (out_dir / f"{slug}.statement.json").write_bytes(canonical_json(st))
        (out_dir / f"{slug}.dsse.json").write_text(
            json.dumps(dsse_envelope(st, sk, key_id), indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "attestation-key.pub").write_text(
        json.dumps({"alg": "ed25519", "keyid": key_id, "public_key_hex": key_id}, indent=2),
        encoding="utf-8")
    return statements


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dir", type=Path, help="a PUBLISHED sealed-run directory")
    ap.add_argument("--out", type=Path, required=True, help="output directory for Statements")
    ap.add_argument("--key", type=str, default=None, help="ed25519 signing seed (hex)")
    ap.add_argument("--declarations", type=Path, default=None,
                    help="optional JSON of operator-asserted declared.* values")
    a = ap.parse_args()
    decl = _load(a.declarations) if a.declarations else None
    sts = project(a.run_dir, a.out, a.key, decl)
    print(f"projected {len(sts)} Statement(s) from {a.run_dir.name} -> {a.out}")
    for s in sts:
        pr = s["predicate"]
        print(f"  {pr['statement_id']}: attested.outcome={pr['attested']['outcome']} "
              f"result_kind={pr['attested']['result_kind']} "
              f"derived.merge_effect={pr['derived']['merge_effect']['value']}")


if __name__ == "__main__":
    main()
