# gated-uat

Signed UAT evidence harness for the [`gated`](https://github.com/fjwood69/gated) promotion gate.

`gated` is the behavioural enforcement layer that governs agent code promotion.
`gated-uat` is the external test harness that produces tamper-evident, cryptographically
signed evidence that `gated` is calibrated correctly against known fixtures before
any promotion decision is made.

**Status:** Phase 1 complete (schema v2, ObservedOCISandbox, commit-pin enforcement,
signed four-receipt chain). Phase 2 (live `AuthorizedRunPlan` enforcement wiring) pending.

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

## Repository layout

```
gated-uat/
├── cli.py                        # Entry point: `gated-uat run p1 ...`
├── conftest.py                   # pytest sys.path injection + commit-pin enforcement
├── pyproject.toml                # Build + dev deps (hatchling, pynacl, mypy, ruff, pytest)
│
├── orchestrator/
│   ├── evidence.py               # Receipt, VerifiedChain, verify_integrity, evaluate_admission
│   ├── schemas.py                # Versioned payload schemas (v1 / v2)
│   ├── trust.py                  # EvidenceSigner, sign/verify_receipt_sig
│   ├── isolation.py              # Registry (SQLite run ledger), RunState
│   ├── runtime.py                # RuntimePack: image + Python version fingerprint
│   ├── calibration_driver.py     # GatedCalibrationAdapter (single gated import seam)
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
├── tests/
│   ├── test_evidence.py          # Chain integrity, fail-closed, trust anchor, admission
│   ├── test_schemas.py           # Schema v1/v2 validators, version dispatch
│   ├── test_isolation.py         # Registry allocate/release, state machine
│   ├── test_runtime.py           # RuntimePack digest stability
│   ├── test_corpus.py            # Corpus loading, vacuity guard, digest validation
│   ├── test_calibration_driver.py # Domain types, observer artifact canonicalisation
│   ├── test_cli.py               # CLI argument parsing, exit codes
│   ├── test_gated_pin.py         # verify_gated_dependency() — all three rejection paths
│   └── test_adapter_integration.py # Vertical slice: adapter → gated imports → outcome
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
../gated-uat-pin    ← pinned at 628e5a3d8274a74bb74cecaf7667fdf989398ebd
```

One-time setup (after cloning this repo):

```bash
git -C ../gated worktree add --detach \
    ../gated-uat-pin \
    628e5a3d8274a74bb74cecaf7667fdf989398ebd
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

Tests that require Podman images are guarded with `@unittest.skipUnless(...)` and
skip cleanly when the image is absent.

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

Two schema versions are in use:

| Version | When | Notable fields |
|---------|------|---------------|
| v1 (Phase 0) | archived | `runtime_pack_digest` optional |
| **v2 (Phase 1)** | current | `runtime_pack_digest` required; `observer_log_digest` + `observer_log_truncated` required; provenance fields (`resolved_profile_digest`, `trust_policy_digest`, `guard_policy_digest`, `execution_identity_digest`, `policies_consistent`) required for PASS/FAIL |

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
| 1 | **Complete** `b7d769f` | Programmatic calibration, schema v2, ObservedOCISandbox, commit-pin |
| 2 | Pending | Live `AuthorizedRunPlan` enforcement wiring; §11 artifact binding |

Phase 2 is blocked on `gated` S3-completion (AuthorizedRunPlan, step-3.5-jobs branch).

---

## Licence

Apache-2.0
