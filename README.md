# gated-uat

Signed UAT evidence harness for the [`gated`](https://github.com/fjwood69/gated) promotion gate.

`gated` is the behavioural enforcement layer that governs agent code promotion.
`gated-uat` is the external test harness that produces tamper-evident, cryptographically
signed evidence that `gated` is calibrated correctly against known fixtures before
any promotion decision is made.

**Status:** Live-enforcement evidence (schema v3, provenance-typed) built. The **B1
Demonstration Board apparatus** is MERGED (`c7f3c02`): the signed manifest + four-stage
gauntlet + render/admission gate. **Step 3.1** adds the **render driver** (`render_board`) —
the first production caller of `assert_board_admissible`, so the **caller-law is satisfied** —
and the **first two-sided real row**, proven by a real-podman keystone: a tempting evasion
passes static, own_tests and llm_review, then the gate runs it and the detector FAILs it
(**ADMIT/fail** → the required check fails, merge blocked); its clean counterpart ends in
**ADMIT**. Capture-record provenance is unsigned-in-B1 / optional. See **Caller-law** in the
Demonstration Board section below.

---

## What it does

A single UAT run produces a **four-receipt signed chain**:

```
preregistration → execution → teardown → index
```

Each receipt is independently signed with an Ed25519 key.  Each digest cross-references
the prior receipt.  The `index` receipt binds all three and embeds the verifier's public
key.  The chain is verified by `verify_integrity()` and the result (`VerifiedChain`)
is the only type accepted by `evaluate_admission()`.

The current profile (`p1`) runs `gated`'s `RetryCheck` detector against three fixtures
(1 KNOWN_GOOD, 2 KNOWN_BAD) using `ObservedOCISandbox` — a hermetically sealed OCI
container with a sidecar egress observer.  A `PASS` verdict requires the detector to
correctly classify every fixture; a `FAIL` is valid signed evidence of a regression.

---

## Demonstration Board (B1) — the signed gate-demonstration *apparatus*

Beyond the calibration chain, `gated-uat` can produce a **demonstration board**: a
preregistered, two-sided matrix of artifact rows × gauntlet stages — disclosure, not a
ranking. The apparatus is merged; **Step 3.1** adds the render driver and the **first
two-sided row** through real components (a real-podman keystone). What exists today:

- **Signed manifest (the prereg):** `build_manifest` commits the *complete ordered
  denominator* (every planned cell), the toolchain pin (`env_digest`), reviewer
  independence, and no-silent-reruns — signed Ed25519 **before** any agent/API call
  (`manifest.py`).
- **The gauntlet (per cell):** `static → own_tests → llm_review → gate`, each a signed
  `cell_stage` observation bound to the manifest anchor and one immutable artifact digest.
  On the **tempting** side, the intended demonstration is **green-green-green-ADMIT/fail**:
  the producer's own tests pass on an evasion (the thesis); the gate **admits** the run under
  a healthy ENABLED policy and the detector returns a **FAIL** run-verdict (`admitted_run` /
  `run_verdict` / outcome `fail`) — so a required PR check fails and the merge is blocked. That
  is **not** a governance `blocking_refusal` (rendered `BLOCKED`), which is reserved for
  currency/drift refusals. The clean counterpart is green across all stages, ending in **ADMIT**.
  `static` + `own_tests` run in a hermetic OCI sandbox (exit-code-only); the `gate` stage runs
  `gated`'s **real** enforcement path.
- **Capability-deletion, not policy:** the review client is transmit-only with a
  completion-path egress allowlist (`provider_gate.py`); each sandbox stage binds the
  *sealed* artifact digest through the pin's real `OCISandbox.prepare()` (drift →
  `ArtifactHashMismatch` → ERROR), proven through **real Podman** (`test_gauntlet_keystone.py`).
- **Render/admission gate (`assert_board_admissible`):** a board is admissible **only**
  when the signed manifest verifies (*render-requires-pin*), every `cell_stage` receipt
  verifies and anchors to it, the terminal receipts are an **exact bijection** with the
  planned cells (no cherry-pick / duplicate / unplanned), and every measured `static`
  receipt's `env_digest` **==** the signed manifest toolchain pin (an operator cannot
  silently swap the analyser).

**Caller-law (satisfied, Step 3.1).** `assert_board_admissible` now has its first production
caller: `render_board` calls it BEFORE any emit (fail-closed — nothing is written until
admission passes), and a real-podman keystone drives a populated two-sided board through it.
Any OTHER render / UI / export path **must** likewise call it before emitting board output.
Capture-record provenance is signed by the local render key only — optional, not part of
admissibility, origin not gate-verified (see the board disclosure).

---

## Repository layout

```
gated-uat/
├── cli.py                        # Entry point: `gated-uat run p1 ...`
├── conftest.py                   # pytest sys.path injection + commit-pin enforcement
├── pyproject.toml                # Build + dev deps (hatchling, pynacl, mypy, ruff, pytest)
│
├── orchestrator/
│   ├── evidence.py               # Receipt, VerifiedChain, verify_integrity, evaluate_admission
│   ├── schemas.py                # Versioned payload schemas (v1/v2/v3 + manifest + cell_stage)
│   ├── trust.py                  # EvidenceSigner, sign/verify_receipt_sig
│   ├── isolation.py              # Registry (SQLite run ledger), RunState
│   ├── runtime.py                # RuntimePack: image + Python version fingerprint
│   ├── calibration_driver.py     # GatedCalibrationAdapter (single gated import seam)
│   ├── enforcement_driver.py     # Live-enforcement evidence (schema v3, provenance matrix)
│   ├── expectations.py           # Authored expectation ontology (the signed predictions)
│   ├── manifest.py               # B1 board manifest + render/admission gate (assert_board_admissible)
│   ├── gauntlet.py               # B1 four-stage gauntlet + sealed-artifact machinery
│   ├── provider_gate.py          # B1 transmit-only review client (completion-path egress allowlist)
│   └── gated_pin.py              # Pinned commit + verify_gated_dependency()
│
├── profiles/
│   └── p1_regression.py          # P1 profile: corpus load → calibration → signed chain
│
├── corpora/
│   ├── manifest.json             # Fixture registry (fixture_id, label, payload_digest)
│   └── fixtures/
│       ├── retry-good-v1/        # KNOWN_GOOD: genuine retry loop
│       ├── retry-swallow-v1/     # KNOWN_BAD: exception-swallowing (looks like retry, isn't)
│       └── retry-no-retry-v1/    # KNOWN_BAD: single attempt, no retry
│
├── tests/                        # 22 files; podman-gated tests self-skip when the image is absent
│   ├── test_evidence.py          # Chain integrity, fail-closed, trust anchor, admission
│   ├── test_schema_v3.py         # Schema v1/v2/v3 validators, provenance matrix, dispatch
│   ├── test_isolation.py         # Registry allocate/release, state machine
│   ├── test_runtime.py           # RuntimePack digest stability
│   ├── test_corpus.py            # Corpus loading, vacuity guard, digest validation
│   ├── test_calibration_driver.py # Domain types, observer artifact canonicalisation
│   ├── test_cli.py               # CLI argument parsing, exit codes
│   ├── test_gated_pin.py         # verify_gated_dependency() — all rejection paths
│   ├── test_pin_contract.py      # gated pin image / dependency contract
│   ├── test_adapter_integration.py # Vertical slice: adapter → gated imports → outcome
│   ├── test_enforcement_{evidence,negatives,seed}.py  # Live-enforcement (v3) scenarios
│   ├── test_expectation_closure.py # Authored-expectation ontology closure
│   ├── test_manifest.py          # B1 signed board manifest + denominator render gate
│   ├── test_gauntlet_{foundation,own_tests,gate_review,coherence}.py  # B1 gauntlet stages
│   ├── test_gauntlet_keystone.py # B1 real-podman FOLD-A contract proof (SD2/SD7)
│   ├── test_provider_gate.py     # B1 transmit-only review client / egress allowlist (SD1)
│   └── test_board_render.py      # B1 render/admission gate (assert_board_admissible)
│
└── RUNS/                         # Run registry (SQLite) + artifact output; gitignored
```

---

## Dependencies

### Python packages

```bash
pip install -e ".[dev]"   # pynacl + mypy + ruff + pytest
```

### `gated` (external pinned dependency)

`gated` is not on PyPI.  The harness resolves it from a dedicated worktree:

```
../gated-uat-pin    ← a sibling of this repo, pinned at 1d75d54a97986e18fae499c370f8615e6cf89e15
```

One-time setup (after cloning this repo), with `$GATED` = your local `gated` clone:

```bash
git -C "$GATED" worktree add --detach \
    ../gated-uat-pin \
    1d75d54a97986e18fae499c370f8615e6cf89e15
```

`conftest.py` adds `gated-uat-pin` to `sys.path` and calls `verify_gated_dependency()`
on every pytest run.  The CLI calls the same check before signing any evidence.
A dirty or mismatched checkout is a hard rejection — not a warning.

### OCI image

The P1 profile requires a local Podman image `localhost/mori:local`.  Resolve its
image-config digest with `{{.Id}}` (not `{{.Digest}}`):

```bash
podman image inspect --format '{{.Id}}' localhost/mori:local
```

The `{{.Digest}}` field is the manifest hash; the OCI backend uses the image-config
hash (`{{.Id}}`).  Supplying the wrong hash causes `ImageDigestMismatchError`.

---

## Running tests

```bash
cd gated-uat

# Full suite (requires gated-uat-pin worktree):
pytest

# Type check:
mypy --strict .

# Lint:
ruff check .

# Podman-gated integration tests only (requires localhost/mori:local):
pytest tests/test_adapter_integration.py -k TestGatedAdapterGenuinePodman
```

Tests that require Podman images are guarded with `pytest.mark.skipif(...)` and skip
cleanly when the image is absent. The real-podman keystones (incl. the B1 FOLD-A contract
proof) **run** on the self-hosted NUC `integration-podman` CI job (push-to-`main`), which
**hard-fails if `localhost/mori:local` is absent** — so a keystone can never silently skip
on the merge gate.

---

## CLI usage

```bash
# Generate a signing key (32 raw bytes):
python3 -c "from nacl.signing import SigningKey; open('uat.key','wb').write(SigningKey.generate()._signing_key)"

# Extract the verify key (64 hex chars — pin this independently, not from the same key file):
python3 -c "
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
print(SigningKey(open('uat.key','rb').read()).verify_key.encode(HexEncoder).decode())
"

# Run the P1 profile:
IMAGE_DIGEST=$(podman image inspect --format '{{.Id}}' localhost/mori:local)
python3 -m cli run p1 \
    --image-ref localhost/mori:local \
    --image-digest "sha256:${IMAGE_DIGEST#sha256:}" \
    --key-file uat.key \
    --trusted-verify-key-hex <hex from above> \
    --trials 5

# Exit 0 = admitted PASS; exit 1 = rejected / FAIL / ERROR; exit 2 = usage error.
```

---

## Schema

Receipt kinds and schema versions in use:

| Version / kind | When | Notable |
|---|---|---|
| v1 (Phase 0) | archived | `runtime_pack_digest` optional |
| v2 (Phase 1) | calibration | `runtime_pack_digest` + `observer_log_*` required; provenance fields required for PASS/FAIL |
| **v3 (Phase 2)** | live enforcement | provenance-typed **(scenario × observed_kind) matrix**; the prereg is the *signed prediction*; admissibility is prereg-relative (confirm/refute) |
| `manifest` (B1) | board prereg | anchored **complete-denominator** board manifest (toolchain `env_digest` pin, reviewer independence, no silent reruns) |
| `cell_stage` (B1) | board observation | one signed observation per gauntlet stage; toolchain-pinned `static`; P1 measured-tree law |

`SCHEMA_VERSION_MIN_ADMIT = 2` — v1 receipts are cryptographically verifiable but
not admissible as UAT evidence.

---

## Evidence model

```
verify_integrity(chain, verify_key) → VerifiedChain
    Cryptographic + structural: signatures, digest cross-refs, run_id consistency,
    trust-anchor (index.verify_key_hex == pinned key), schema completeness,
    semantic continuity (profile + gated_commit consistent across receipts).

evaluate_admission(chain: VerifiedChain) → bool
    Admissibility: requires VerifiedChain (integrity first); schema_version >= 2;
    teardown.failure == False; outcome in {"pass", "fail"} (not "error").
    A gated "fail" IS admissible — it is valid signed evidence of a regression.
```

The `VerifiedChain` sentinel constructor is private — only `verify_integrity()` holds
the sentinel object.  `evaluate_admission()` cannot be called on an unverified chain.

### The engine environment the published boards ran in

Both sealed runs pin the engine at `gated_commit: "1d75d54"` (recorded in each
`commitment.json`). That commit predates a defect later found and fixed in `gated`: the
boundary observer published its readiness signal *before* its socket was listening, so an
artifact's first egress attempt could be refused — and a refused connection is never
accepted, so it was never counted. The egress count is a detector's verdict input, so this
was capable of reaching a verdict. **Every board published here ran under that engine**, and
a reader who follows the pin will work that out; it is stated here rather than left to be
derived.

The published records survive it, and the reason is a polarity argument rather than a
reassurance. The race can only *under*-count, and `RetryCheck` passes iff `egress >= 2`, so
the reachable failure is a **false FAIL — over-blocking — never a false PASS**. Read against
the receipts in this repository: the four `retry-swallow` cells each record
`egress==1 — attempted once, gave up`, which is the designed value for a fixture that
swallows its retry; the four `retry-clean` cells each record a pass, and under a `>= 2`
predicate a pass is positive evidence that at least two attempts *were* counted. No cell
shows the under-count signature, and no verdict published here could have been a false pass.

This is a **post-hoc disclosure about a historical record, not a re-labelling of it**. The
boards attest what ran in the environment that existed at the time, and they remain
internally consistent. The forward constraint is the other half: when this repository
re-pins to an engine commit containing the fix, the boards must be **re-run, not replayed** —
the fix changes the measured observer identity, and a result obtained under the old identity
is not evidence about the new one. Each sealed-run directory carries a dated post-hoc note
saying the same thing beside the record itself.

---

## Phases

| Phase | Status | Scope |
|-------|--------|-------|
| 0 | Complete | Four-receipt chain, schema, trust, registry, RuntimePack |
| 1 | Complete `b7d769f` | Programmatic calibration, schema v2, ObservedOCISandbox, commit-pin |
| 2 | Live-enforcement evidence **built** `7950aaa` | schema v3 provenance matrix; the 2.1–2.2b enforcement / recalibration scenarios (`gated` S3-completion pinned at `1d75d54`) |
| B1 | **Merged** `c7f3c02` | Demonstration Board **apparatus**: manifest + gauntlet + render/admission gate (gap-1 capability-deletion, provider-gate SD1, real-podman FOLD-A SD2/SD7, Gate 3 render pin) |
| 3.1 | **Built** | Render driver (`render_board`) — caller-law satisfied — + first two-sided real row (real-podman keystone: `ADMIT/fail` / `ADMIT`); signed capture records (local key, optional) |

**Open / named follow-ons (stated plainly, not done):** more **populated** rows — Step 3.1
lands the FIRST two-sided row (render driver + real-podman keystone); additional agent /
detector rows follow; **P2 cell-identity reconciliation**. §11 artifact binding: the board
binds one immutable artifact digest per cell, but formal §11 closure is **not** claimed here.

---

## Licence

Apache-2.0
