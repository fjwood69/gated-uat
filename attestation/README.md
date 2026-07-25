# Behavioural-verification attestations (in-toto), v0.1

A **projector**: it reads a *published* sealed-run directory and emits one signed
[in-toto Statement](https://github.com/in-toto/attestation) (+ DSSE envelope) per gated cell. It
touches nothing sealed — no `render_board`, no receipt schema, no provider-gate, no ALLOWED_PATHS
— and runs strictly downstream of a board that has already been published.

```bash
python attestation/projector.py sealed-runs/<board_id> --out sealed-runs/<board_id>/attestations
```

> **`sealed-runs/<board_id>/attestations/` is POST-HOC PROJECTOR OUTPUT — it is NOT part of the
> mint seal.** Anything sitting in a sealed-run directory reads as "sealed" by default, so state it
> plainly: these files were produced *after* publication by re-reading the record, signed by a
> projector key, and nothing in them was signed at mint time. The mint-sealed evidence is
> `commitment.json`, `board/receipts/`, and `board/captures/`.

## What this attests (and the one that matters)

One artifact digest can carry several attestations answering different questions:

| attestation | answers |
|---|---|
| provenance (SLSA et al.) | where the bytes came from |
| AI-session attestation | what the agent did (models, tools, attribution) |
| **behavioural-verification (this)** | **whether what it produced behaves — measured by executing it** |

Nothing in the landscape executes the artifact and measures behaviour, which is why this composes
rather than competes. Three attestations, three questions, one subject.

## The field grouping is the point

The reason for a projector (rather than emitting during the mint) is that **a stranger can re-run
it over the public record and check their Statement matches the published one**. That claim is only
true for fields the record actually contains — so the predicate encodes provenance **class in the
field path**:

| block | meaning | stranger-reproducible? |
|---|---|---|
| `attested.*` | read from published **signed** artifacts (receipts / manifest) | **yes — byte-for-byte** |
| `derived.*` | computed by the projector; every field carries `source_fields` + `recipe` | **yes** (same inputs + stated recipe) — but **never measured by the gate** |
| `declared.*` | operator-asserted, **not evidenced** by the record | **no** — flagged `evidenced_by_record: false`, defaults to `null` |

`source_fields` + `recipe` are **schema-required** on every `derived.*` field: a derived value
without a recipe is exactly the "built-not-bound" pattern reappearing inside the fix for it.

The split is **measured, not asserted** — `tests/test_attestation_projector.py` runs a
**stranger simulation**: it copies *only* the published run directory into an isolated location
(no repo tree, no PolicyStore, no local state), re-projects, and byte-compares `attested` +
`derived`. `declared` is excluded by construction.

**What that test does and does not prove (named honestly):**

- ✅ **Data-plane isolation** — the projector needs *nothing* beyond the published run directory:
  no PolicyStore, no repo working tree, no local state.
- ❌ **Not process-plane isolation** — it re-imports the *same* `attestation.projector` module
  in-process. It is not an independent re-implementation, which is a genuinely different (and
  later) property.
- ❌ **Not classification** — reproducibility says nothing about whether a field is in the *right*
  block. A stranger recomputes a projector-computed value identically, so this test passes on a
  misclassified field. Class is enforced separately (`derived.*` keys may not appear in
  `attested.*`; see the seals). The structural closure — populating `attested.*` only via a reader
  that records each field's source artifact and JSON pointer, with the schema requiring that
  provenance — is a **named follow-up increment**.

### Placeholder policy: `attested.*` and `declared.*` are deliberately opposite

- **`attested.*` — never emit a placeholder.** Anything unverifiable does not belong in the block
  at all; a `null` there would be a slot pretending to be evidence.
- **`declared.*` — always emit**, with `value: null`, `evidenced_by_record: false`, and a note.
  The block exists to *name* what is not evidenced; omitting defeats it and leaves a reader unable
  to tell "inapplicable" from "unavailable".

## Verify walkthrough

1. **Recompute the subject.** Take the cell's gate receipt
   (`board/receipts/<cell>__gate.json`) and read `payload.artifact_tree_digest` — the hash the gate
   **itself** captured during `enforce()` (not a re-derived view; that is what makes the binding
   meaningful). Strip the `sha256:` prefix → must equal `subject[0].digest.sha256`.
2. **Verify the DSSE signature.** `payload` is base64 of the canonical Statement JSON. Verify over
   the DSSE PAE with the ed25519 key in `attestations/attestation-key.pub`:
   `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`.
3. **Read the predicate.** `attested.outcome` + `attested.result_kind` are the gate's own
   vocabulary; `attested.measurement.result_reason` is what was actually measured (e.g.
   `egress==1 — attempted once, gave up`). `derived.merge_effect` is the *consequence*, computed
   here — check its `recipe`.
4. **Follow the linkage** back into the public record: `linkage.receipt_digest`,
   `linkage.manifest_digest`, `linkage.board_id`, `linkage.commitment_digest`,
   `linkage.sealed_run_path`.
5. **Re-derive it yourself.** Clone the repo, run the projector over the same directory, and
   compare `attested` + `derived`. They must match byte-for-byte.

### Note for in-toto-native consumers

`subject[0].name` carries the **cell_id**, which makes it **run-scoped** rather than purely
artifact-semantic. This is deliberate: two cells of the same task share an identical artifact
digest but may carry different verdicts, so a verifier keyed on the digest alone would collapse
them. Key on **`(subject digest, cell_id, reviewer_lineage)`**, or use `predicate.statement_id`
(`<board_id>/<cell_id>`), which is unique per Statement.

## Composition with a policy engine (documentation, not integration)

The Statement is attachable as a custom evidence material (evidence-identifier key + a `data`
object), which makes it addressable by policies that route on the identifier. Sketch:

```rego
# deny unless a behavioural-verification attestation exists for this subject,
# the gate allowed promotion, and the detector was calibrated.
deny[msg] {
  not behavioural_ok
  msg := "no passing behavioural-verification attestation for this artifact"
}
behavioural_ok {
  att := input.attestations[_]
  att.predicateType == "https://gated.dev/attestations/behavioural-verification/v0.1"
  att.subject[_].digest.sha256 == input.artifact.sha256
  # keying on the digest ALONE is the collision case — two cells of one task share an artifact
  # digest with possibly different verdicts. Pin the cell too:
  att.subject[_].name == input.cell_id                 # or: att.predicate.statement_id == ...
  att.predicate.attested.cell.reviewer_lineage == input.reviewer_lineage
  att.predicate.derived.merge_effect.value == "allowed"
  att.predicate.declared.calibration_state.value == "ENABLED"   # NOTE: declared, not attested
}
```

That last line is the honest part: `calibration_state` is **declared**, so a policy relying on it
is trusting the operator, not the record. The field path says so.

## Residuals (v0.1 — stability note)

1. **`declared.*` is operator-asserted, not stranger-reproducible**: `calibration_state`
   (PolicyStore, out-of-band), `detector_digest`, `execution_identity`, `sandbox` posture — none
   are published.
2. **Corpus is a version string (`v1`), not a digest** — a corpus that changes without the string
   changing yields a stale-but-signed attestation. Closing it needs a corpus digest in the manifest
   (future mint).
3. **`toolchain.env_digest` is the static/own_tests image** and is *not* proven to be the gate's
   sandbox image — the gate's execution environment is not evidenced by the published record.
4. **`trust_root: "local-key"`** — no hardware root, no TEE, no third-party notarisation
   (reference-tier).
5. **Pre-mint commitment ordering for the published boards is operational, not artifact-provable,
   and is permanently so.** A timestamp applied now proves existence-*by-now*, which is *after*
   those runs — an RFC 3161 countersignature helps **future** mints only.
6. **`derived.merge_effect` is computed by this projector** and was never emitted by the gate.
7. **A Statement does not carry `execution_identity`, so its environment scoping is *derivable*,
   not *readable*.** The identity was not sourceable from the published record (residual 1), so a
   consumer wanting to know which engine environment a Statement describes must follow the linkage
   to the sealed run and read `gated_commit` from its `commitment.json`. That linkage is sound —
   `subject` and `sealed_run_path` bind the Statement to exactly one published run — but it is a
   second hop, and a consumer who reads only the predicate will not see an environment at all.
   Scoping that must be reconstructed is weaker than scoping that is stated, and an identity
   change on the engine side is invisible from the predicate alone.
8. **Field names may change before v1.**

## Board #2 (the true negative) is attested too

Board #2's review column refused entirely; its **gate** cells still produced real verdicts, so
Statements are emitted — each carrying `derived.board_status: review_column_refused` (a projector
computation, with its recipe — *not* a measured field) and a `scope.does_not_attest` entry for any
board-level claim. Emitting the honest failure is the test of the projector, not an exception to
it.
