# Warrant — how the counts in `MEASURED.json` were obtained

**This document exists to be falsified.** A warrant that says "trust us" launders trust; one that says
"re-run this, here is exactly what I ran and on what" can be checked and, if wrong, shown to be wrong.
Everything needed to attempt that is below.

---

## The claim

Each artifact in this corpus was executed inside the `gated` observed sandbox — a sealed network with
no route off it — and the **boundary egress attempts** were counted **from outside the sandbox**, by a
proxy the artifact can neither read nor write.

**Measured 5 rows × 3 rounds = 15 sealed runs.** Every row produced an identical count in every round,
and every count equalled its independently-derived by-construction value.

| Member | Measured egress | Stable across 3 rounds |
|---|---|---|
| `retry-swallow-v2` | 1 | yes |
| `retry-swallow-v2-mutated-behavioural` | 3 | yes |
| `retry-swallow-v2-mutated-cosmetic` | 1 | yes |
| `two-unconditional-egresses-v1` | 2 | yes |
| `retry-good-v2` | 3 | yes |

Residue after the run: **0** leftover sandbox resources.

## The falsifier block — what the claim is conditional on

| | |
|---|---|
| **Producer** | `fjwood69`, on `uk-smr-nuc15pro` |
| **Engine** | `gated` commit **`2806d07`** — the real `ObservedOCISandbox`, never a reimplementation |
| **Sandbox image** | **`sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4`** (`docker.io/library/python:3.11-alpine`) |
| **Runtime** | podman 4.9.3, rootless |
| **Kernel** | 6.17.0-35-generic, 14 cpus |
| **Witness condition** | the sealed-network witness returns a **persistent 503** for the duration of a run |
| **Corpus** | `gated-uat`, this tree at the tagged commit |

⚠ **The image digest is part of the claim, not decoration.** The counts are conditional on what the
artifact executes inside. Recording the digest now is what stops it being reconstructed — i.e.
guessed — later.

⚠ **The host is NOT a clean room.** It was running twelve unrelated production containers during the
measurement. That is stated because a number presented without its conditions invites the reader to
assume conditions that never held.

## Reproducing it

```bash
# 1. verify this corpus
sha256sum -c SHA256SUMS

# 2. check the counts against a derivation that needs no runtime
python3 -c "from expectations import BY_CONSTRUCTION; print(BY_CONSTRUCTION)"

# 3. re-measure, using the engine at the commit named above
#    (harness: dotfiles docs/gated-planning/state/e2e-determinism-v1.py)
```

**Expect the same counts. If you do not get them, the disagreement is the finding** — and it is worth
more than the agreement. Report it; do not assume your host is wrong.

## What this warrant does NOT establish

- **Not that the counts are CORRECT in principle** — only that this engine, on this image, produced
  them repeatably, and that a by-construction reading of the fixtures agrees. Two agreeing derivations
  are still two derivations.
- **Not that the gate judges intent.** It counts attempts. `two-unconditional-egresses-v1` has no
  retry logic at all and is admitted; that is the instrument's limit, shipped deliberately rather than
  curated away.
- **Not a per-PR cost figure.** These are five rows plus a witness; a real gate run is one artifact.
- **Not a wall-clock claim.** Staging is excluded, timings are host-dependent, and no number here
  should be quoted as "what the gate costs".

## Provenance of this measurement

| | |
|---|---|
| determinism harness | `e2e-determinism-v1.py` (preserved in the producer's private records) |
| sealed-operation contract | `gated` **`ab9b449`** |
| pre-tag gate | `pretag_gate.py`, in this corpus — proven to refuse on four independent axes before it was ever allowed to pass |
