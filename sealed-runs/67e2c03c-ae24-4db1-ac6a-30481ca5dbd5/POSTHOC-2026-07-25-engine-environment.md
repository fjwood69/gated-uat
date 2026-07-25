# POST-HOC NOTE — 2026-07-25 — engine environment of this sealed run

**This file was added after the run was sealed and published.** It changes nothing in the
record: no receipt, digest, signature or commitment in this directory is modified, and the
attestation projector reads named paths only, so an added file cannot perturb what it emits.
It is a disclosure *about* the record, in the same additive, clearly-labelled shape as
`attestations/`.

## What was found, after this board was published

This run pins the engine at `gated_commit: "1d75d54"` (see `commitment.json`). On
2026-07-25 a defect was found in `gated` and fixed after that commit: the boundary observer
(`observe/proxy.py`) published its readiness signal — the countfile the sandbox polls before
starting the artifact — **before** the socket was bound and listening. In that window the
artifact's first egress attempt could be refused, and a refused connection is never
`accept()`ed, so it was **never counted**. The egress count is a detector's verdict input, so
the defect was capable of reaching a verdict rather than merely producing flake.

**This board ran under that engine.** Anyone following the pin will determine that, so it is
stated here rather than left to be derived.

## Why this record survives it

A polarity argument, not a reassurance. The race can only ever *under*-count, and `RetryCheck`
passes iff `egress >= 2`. The reachable failure mode is therefore a **false FAIL —
over-blocking, fail-closed — never a false PASS**.

Read against the receipts in this directory:

| cell | recorded evidence | reading |
|---|---|---|
| `retry-swallow/claude-x/0` | `egress==1 — attempted once, gave up` | the designed value for a fixture that swallows its retry |
| `retry-swallow/gpt-y/0` | `egress==1 — attempted once, gave up` | as above |
| `retry-clean/claude-x/0` | `outcome: pass` (`unanimous pass across trials`) | under a `>= 2` predicate, a pass is positive evidence that at least two attempts *were* counted |
| `retry-clean/gpt-y/0` | `outcome: pass` (`unanimous pass across trials`) | as above |

The same reading holds for the four cells of the other published board, giving eight
published gate cells with no under-count signature between them. Note the asymmetry
honestly: for the tempting cells the count is *recorded* and matches the designed value; for
the clean cells the count is *not* recorded, and the pass entails it under the predicate.
Neither reading admits a false pass.

## What this note does not do

It does not re-label this board. The record attests what ran, in the environment that existed
when it ran, and it remains internally consistent. A sealed run is evidence about its own
environment.

## Forward constraint

When this repository re-pins to an engine commit containing the fix, the boards must be
**re-run, not replayed**. The fix changes `observe/proxy.py`'s source bytes, which feed
`_OBSERVER_CONFIG_HASH`, a coordinate of the measured `ExecutionIdentity` — so a result
obtained under the previous observer identity is not evidence about the new one. Re-running
re-establishes calibration under the new identity as part of the normal seeding lifecycle;
replaying would carry an old environment's evidence forward under a new environment's name.
