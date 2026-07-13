# gated-uat — Phase-0 Closure Complete / Phase 1 Start

**Written**: 2026-07-13  
**Repo state**: `main` at `9632afe` — NOT pushed (Fred's call)  
**Tests**: 66/66, mypy --strict, ruff — all green

---

## What was built this session

Phase-0 closure: all five board-ratified items from the post-P1-remediation design consult.

### 1. Schema strictness (`orchestrator/schemas.py`)

- **Bool exclusion**: `_require()` rejects `True`/`False` for `int` fields (`isinstance(v, bool)` check after `isinstance(v, int)`).
- **Timestamp regex**: `_ISO_RE` now requires timezone (`Z` or `±HH:MM`) and has `$` anchor — rejects trailing garbage and timezone-free strings.
- **Exact key sets**: `_PREREG_KEYS / _EXECUTION_KEYS / _TEARDOWN_KEYS / _INDEX_KEYS` + `_check_unknown_keys()` helper — any unrecognised key raises `SchemaViolationError`.
- **Evidence continuity fields**: `prereg_digest` (hex64) required in execution payloads; `execution_digest` (hex64) required in teardown payloads — schema v1 is now forward-chained.
- **`runtime_pack_digest`**: whitelisted in `_EXECUTION_KEYS` and `_TEARDOWN_KEYS`; optional in Phase 0, validated as hex64 when present.

### 2. VerifiedChain sentinel (`orchestrator/evidence.py`)

- `_VERIFIED_SENTINEL = object()` — module-private, held only by `verify_integrity()`.
- `VerifiedChain` gains `_sentinel: dataclasses.InitVar[object | None] = None` + `__post_init__` that raises `TypeError` if sentinel ≠ `_VERIFIED_SENTINEL`.
- External `VerifiedChain(prereg=..., ..., verify_key_hex="...")` construction now raises `TypeError`.
- `verify_integrity()` passes `_sentinel=_VERIFIED_SENTINEL` — the only valid construction path.

### 3. Asymmetric builders + evidence continuity (`orchestrator/evidence.py`)

- `build_execution_receipt(prereg: Receipt, payload, signing_key) -> Receipt` — injects `prereg_digest = prereg.digest`, uses `prereg.run_id`.
- `build_teardown_receipt(execution: Receipt, payload, signing_key) -> Receipt` — injects `execution_digest = execution.digest`, uses `execution.run_id`.
- Both overwrite any caller-supplied digest field (builder always wins).
- `build_receipt()` now calls `validate_run_id(run_id)` before schema check — UUID4 enforced at build time.
- `verify_integrity()` adds:
  - **Check 7a**: `execution.payload["prereg_digest"] == prereg.digest`
  - **Check 7b**: `teardown.payload["execution_digest"] == execution.digest`
  - These run after per-receipt schema validation (4–6) so schema errors are caught first.

### 4. `release()` race fix (`orchestrator/isolation.py`)

- `BEGIN` → `BEGIN IMMEDIATE` in `release()`.
- Prevents TOCTOU: two processes reading "active" simultaneously could both update before the prior commit was visible in a deferred transaction.
- `allocate()` already used `BEGIN EXCLUSIVE` — unchanged.

### 5. RuntimePack stub (`orchestrator/runtime.py` — new file)

```python
@dataclass(frozen=True)
class RuntimePack:
    runtime_id: str
    version: str
    toolchain_image_digest: str
    accepted_source_forms: tuple[str, ...]
    isolated_build_plan: str
    frozen_run_command: str
    dependency_policy: str
    observer_capabilities: tuple[str, ...]
    resource_budget: str

def validate_runtime_pack(pack: RuntimePack) -> None: ...   # non-empty: runtime_id, version, frozen_run_command
def compute_runtime_pack_digest(pack: RuntimePack) -> str:  # SHA-256 of sorted-keys JSON
```

### 6. Conftest pin

Bumped from `07d2161` → `96bebac` (gated 3.5 S2: packaging + mandatory-guard foundation).  
`core.chain.canonical_digest` API unchanged — wire-neutral commit.

---

## Test inventory (66 total)

`tests/test_evidence.py` — 56 tests  
`tests/test_isolation.py` — 18 tests  
`tests/test_runtime.py` — 8 tests (new this session)  

New in this session:
- `TestPhase0Closure` class (11 tests): sentinel forge → `TypeError`; asymmetric builder injection; continuity mismatch failures; `prereg_digest`/`execution_digest` required at build; bool-as-int; timestamp no-TZ; timestamp trailing garbage; unknown key.
- All `_full_chain()` / semantic continuity / run_id mismatch tests updated to use asymmetric builders.
- `test_invalid_outcome_rejected_at_build` and `test_teardown_failure_without_error_field_rejected` updated to supply the now-required continuity fields before testing the specific violation.

---

## Phase 0 acceptance status

| Criterion | Status |
|---|---|
| Schema v1 frozen (exact key sets, bool exclusion, TZ timestamps) | ✅ |
| `VerifiedChain` construction sealed via sentinel | ✅ |
| Evidence continuity: execution binds prereg, teardown binds execution | ✅ |
| `verify_integrity()` cross-refs 7a+7b after per-receipt schema pass | ✅ |
| `release()` uses `BEGIN IMMEDIATE` | ✅ |
| `RuntimePack` stub + `compute_runtime_pack_digest()` | ✅ |
| UUID4 validated at `build_receipt()` | ✅ |
| 66/66, mypy --strict, ruff | ✅ |
| Packaging (build backend, CLI entry point, proper gated install) | ❌ NOT YET |

**Packaging is the only remaining Phase-0 item.** The spec calls for:
- `pyproject.toml` build backend (`hatchling` or `flit-core`)
- Package discovery (`packages = ["orchestrator"]`)
- CLI entry point for `cli.py` (stub exists?)
- Resolve `sys.path.insert` hack in conftest → proper `gated` artifact install in Phase 1

This is a low-risk cosmetic item and can be done at the start of Phase 1 or as a Phase 0 tail commit. It does not gate Phase 1 design work.

---

## Phase 1 — what comes next

Phase 1 = Python runtime pack + actual P1 UAT harness. The design is fully consulted and ratified (consult IDs `consult-17e96be68c17` and `consult-3ed36a75faa4` in mori canon).

### Phase 1 build order

**Step 1 — Python `RuntimePack` implementation**
- Replace stub fields with typed `PythonRuntimePack` subclass (or separate class)
- Podman image digest (sha256:hex), lockfile hash, isolated build in ephemeral rootless container
- `observer_capabilities = ("stdout", "stderr", "exit_code", "timing")`
- `toolchain_image_digest` validated as `sha256:<hex64>`

**Step 2 — P1 regression profile**
- `profiles/p1_regression.py`: Python-specific test runner
- Uses `RuntimePack` to build + run in Podman container
- Produces execution receipt via `build_execution_receipt(prereg, ...)`
- Observer captures stdout/stderr/exit_code → teardown receipt

**Step 3 — `Registry` integration**
- `allocate()` at run start → `release(state=COMPLETED/FAILED)` at end
- Ensure run_id flows through all receipt builders

**Step 4 — P2 acceptance profile** (after P1 green)
- Extended corpus, longer-running scenarios

**Key gotchas for Phase 1**:
- `runtime_pack_digest` transitions from optional → required in schema; bump `SCHEMA_VERSION` or add as required without version bump (board decision needed — ask at Phase 1 start)
- `BackendGuard` now mandatory in gated 3.5 S2 (`96bebac`) — `backend_guard` required param on `calibrate` and the three gate entry points; Phase 1 must provide one
- `conftest.py` pinned at `96bebac` — if gated moves forward again, update the pin (core.chain API stable, so usually safe)

---

## Key file map

```
gated-uat/
  conftest.py                    # sys.path + commit pin (96bebac) + build_receipt_unchecked()
  orchestrator/
    __init__.py
    evidence.py                  # VerifiedChain, build_*_receipt, verify_integrity, evaluate_admission
    isolation.py                 # Registry, validate_run_id, run_id_slug
    runtime.py                   # RuntimePack stub + compute_runtime_pack_digest (NEW)
    schemas.py                   # validate_*_payload, key sets, _check_unknown_keys
    trust.py                     # EvidenceSigner, generate_signer, sign/verify_receipt_sig
  tests/
    test_evidence.py             # 56 tests — full chain + Phase-0 closure negatives
    test_isolation.py            # 18 tests — allocation, concurrency, state machine
    test_runtime.py              # 8 tests — RuntimePack stub (NEW)
  pyproject.toml                 # gated-uat 0.0.1, pynacl>=1.5, mypy/ruff/pytest dev deps
  RESUME-phase0-closure.md       # this file
```

---

## Session context / decisions made

- **Advisor consult Q1 verdict**: Option C (sealed constructor via sentinel) — correct balance between convention and re-verify
- **Advisor consult Q2 verdict**: Asymmetric builders inject at build time + verify_integrity cross-checks at verify time (defence in depth)
- **Advisor consult Q3 verdict**: `orchestrator/runtime.py` separate file; `runtime_pack_digest` optional in schema v1, required from Phase 1+
- `release()` `BEGIN IMMEDIATE` (not `UPDATE ... WHERE state='active'`) — keeps distinct error messages for "not found" vs "already terminal"
- Conftest gated pin updated to `96bebac` without checking out old commit — `core.chain` API verified unchanged
