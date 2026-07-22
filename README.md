# gated-uat

Signed UAT evidence harness for the [`gated`](https://github.com/fjwood69/gated) promotion gate.

`gated` is the behavioural enforcement layer that governs agent code promotion.
`gated-uat` is the external test harness that produces tamper-evident, cryptographically
signed evidence that `gated` is calibrated correctly against known fixtures before
any promotion decision is made.

**Status:** Live-enforcement evidence (schema v3, provenance-typed) built. The **B1
Demonstration Board apparatus** is MERGED (`c7f3c02`): the signed manifest + four-stage
gauntlet + render/admission gate that *can produce* a signed gate demonstration. Scope it
precisely — the board **machinery/spine** is merged, **not a demonstration that exists**:
there are **no real rows yet** (the first populated row is the next increment). The
render/admission gate (`assert_board_admissible`) is a proven **component** with **no
production caller yet** — see **Caller-law** in the Demonstration Board section below.

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
ranking. **The apparatus is built and merged; it is not yet populated** — no real agent
artifacts have been run through it (that is the next increment). What exists today:

- **Signed manifest (the prereg):** `build_manifest` commits the *complete ordered
  denominator* (every planned cell), the toolchain pin (`env_digest`), reviewer
  independence, and no-silent-reruns — signed Ed25519 **before** any agent/API call
  (`manifest.py`).
- **The gauntlet (per cell):** `static → own_tests → llm_review → gate`, each a signed
  `cell_stage` observation bound to the manifest anchor and one immutable artifact digest.
  On the **tempting side**, the *intended* demonstration is **green-green-green-BLOCKED**:
  the producer's own tests pass on an evasion (that is the thesis) and the gate BLOCKS it;
  the clean-counterpart side is green across all stages. `static` + `own_tests` run in a
  hermetic OCI sandbox (exit-code-only); the `gate` stage runs `gated`'s **real**
  enforcement path.
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

**Caller-law (honest scope).** `assert_board_admissible` is a proven gate **component** —
it has **no production caller yet**. Any future render / UI / export path **must** call it
before emitting board output. Nothing here claims the render pipeline enforces the pin
end-to-end, nor that a populated demonstration exists — both are named follow-ons.

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
/home/nucadmin/gated-uat-pin    ← pinned at 1d75d54a97986e18fae499c370f8615e6cf89e15
```

One-time setup (after cloning this repo):

```bash
git -C /home/nucadmin/gated worktree add --detach \
    /home/nucadmin/gated-uat-pin \
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
cd /home/nucadmin/gated-uat

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

---

## Phases

| Phase | Status | Scope |
|-------|--------|-------|
| 0 | Complete | Four-receipt chain, schema, trust, registry, RuntimePack |
| 1 | Complete `b7d769f` | Programmatic calibration, schema v2, ObservedOCISandbox, commit-pin |
| 2 | Live-enforcement evidence **built** `7950aaa` | schema v3 provenance matrix; the 2.1–2.2b enforcement / recalibration scenarios (`gated` S3-completion pinned at `1d75d54`) |
| B1 | **Merged** `c7f3c02` | Demonstration Board **apparatus**: manifest + gauntlet + render/admission gate (gap-1 capability-deletion, provider-gate SD1, real-podman FOLD-A SD2/SD7, Gate 3 render pin) |

**Open / named follow-ons (stated plainly, not done):** a **populated** board — real agent
artifact rows, the first is the next increment; a **render driver** that calls
`assert_board_admissible` (the caller-law); **P2 cell-identity reconciliation**. §11 artifact
binding: the board binds one immutable artifact digest per cell, but formal §11 closure is
**not** claimed here.

---

## Licence

Apache-2.0
