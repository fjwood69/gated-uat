# The gated demo corpus

Five artifacts, their **measured** boundary-egress counts, and the warrant for those numbers.

---

## ⚠ WHAT THIS CORPUS IS, AND WHAT IT IS NOT

**It is a FROZEN MEASUREMENT.** A consumer that checks its own run against `MEASURED.json` is a
**DRIFT DETECTOR** — it tells you the gate still behaves as it did when these numbers were frozen. It
is **not an independent correctness oracle.** If a frozen number were wrong, a consumer would check
`wrong == wrong` and print green forever.

That is stated here, in the demo's docs, and on the receipt, because an unlabelled drift detector
gets read as a correctness proof — and the whole point of this project is not letting an instrument
be credited with a property it does not have.

**What limits the damage:** every count in `MEASURED.json` is also derived **by construction** in
`expectations.py` — by *reading* the fixture and counting the calls a persistent-failure run must
make, with no runtime involved. The pre-tag gate asserts the two agree. A wrong number now has to be
wrong in both, and the second derivation is checkable by a reader with no container runtime at all.

## The five members, and the admission rule

**ADMISSION RULE: the corpus ships an artifact if and only if it is WARRANTED — that is, it has a
measured count in `MEASURED.json`, a by-construction derivation in `expectations.py`, and a row in
the determinism warrant. Nothing ships on the strength of being interesting.**

| Member | Measured | Why it is here |
|---|---|---|
| `retry-swallow-v2` | 1 | producer-side checks pass; the gate blocks it |
| `retry-swallow-v2-mutated-behavioural` | 3 | the published post-mutation bytes — one line, count moves |
| `retry-swallow-v2-mutated-cosmetic` | 1 | one line, count **unchanged** — the byte-change control |
| `two-unconditional-egresses-v1` | 2 | no retry logic at all, and the gate **admits** it |
| `retry-good-v2` | 3 | what a genuine retry looks like at the boundary |

### The v1 fixtures: present, NOT shipped, NOT warranted

`retry-good-v1`, `retry-swallow-v1` and `retry-no-retry-v1` remain in this repository and are **not**
members of the corpus. They have no measured counts, no by-construction derivations and no warrant,
so under the admission rule above they do not ship.

They are **left in place deliberately rather than deleted.** Removing them from the tree would not
unpublish them — git history keeps them, and a tag publishes the line they sit on. Deleting them
would create the impression they were withdrawn for cause when they were simply superseded by the v2
forms. **Present-and-explained beats absent-and-unexplained.**

Do not pin them. They are earlier drafts, and nothing measures them.

## ⚠ THE MUTATED VARIANTS ARE GENERATED — NEVER HAND-EDIT THEM

`retry-swallow-v2-mutated-behavioural` and `-cosmetic` must be **byte-identical** to what the demo's
live one-line mutation produces from `retry-swallow-v2`. That equality is the only thing making the
receipt's post-mutation digest checkable against a published digest.

**This warning cannot live inside those files.** It was tried: an explanatory docstring header was
added to both, and the header itself broke the byte-equality it was warning about. Documentation
added to an artifact whose defining property is byte-equality destroys the property.

So the warning lives in three places that cannot break it — here, in the generator, and in the
**failure message of the pre-tag gate**, which refuses if the equality is ever broken. An enforced
invariant with a good failure message is the only warning that survives.

## Verifying this corpus offline

**Use exactly this command.** `git hash-object` computes something different (it prefixes a blob
header) and will report a mismatch on a perfectly correct artifact:

```bash
sha256sum -c SHA256SUMS
```

`SHA256SUMS` is coreutils format, paths relative to this directory.

## Files

| | |
|---|---|
| `fixtures/` | the artifacts |
| `MEASURED.json` | measured egress counts. **Counts only** — no verdicts |
| `expectations.py` | by-construction derivations, maintained **by hand**, never regenerated from a run |
| `WARRANT.md` | how the counts were measured, by whom, on what, and how to reproduce |
| `SHA256SUMS` | per-member digests |
| `pretag_gate.py` | the checks that must pass before any of this is tagged |

## Why `MEASURED.json` records counts and never verdicts

A verdict is `f(count, expectation)`, and the expectation is **demo policy for these fixtures** — not
a truth about retries. Freezing `ADMIT`/`BLOCK` into a digest-pinned artifact would ossify one demo's
threshold into corpus truth that every later consumer conforms to. Counts are the measurement;
verdicts are the consumer's to compute.
