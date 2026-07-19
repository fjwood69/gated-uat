# gated-uat — Claude Code context

Operational context for CC sessions on `uk-smr-nuc15pro`.
See `README.md` for architecture and usage docs.

## Hard lane rule (read this first)

`/home/nucadmin/gated` is Fab's live step-3.5-jobs checkout for the `gated` repo.
**Never** `mv`, `rm`, `git checkout`, `git reset`, or `worktree-manipulate` it.
This caused a multi-hour incident in the session that built Phase 1 (July 2026).

All work in this repo stays inside `/home/nucadmin/gated-uat`.

For the pinned gated dependency: use `/home/nucadmin/gated-uat-pin` (dedicated worktree).
Never repoint at `/home/nucadmin/gated` — even read-only references should go to the pin worktree.

## Host

| Property | Value |
|----------|-------|
| Machine | `uk-smr-nuc15pro`, user `nucadmin` |
| Repo path | `/home/nucadmin/gated-uat` |
| Git remote | `https://github.com/fjwood69/gated-uat` (private) |
| Push auth | `GITHUB_TOKEN=$(~/bin/get-secret.sh GITHUB_TOKEN)` |
| Branch | `main` |

```bash
GITHUB_TOKEN=$(~/bin/get-secret.sh GITHUB_TOKEN)
git push https://fjwood69:${GITHUB_TOKEN}@github.com/fjwood69/gated-uat.git
```

## Pinned gated dependency

The harness depends on `gated` at commit `1d75d54a97986e18fae499c370f8615e6cf89e15`
(gated 3.5 S3 ckpt3: trust + guard policy provenance through CalibrationResult).

One-time worktree setup (already done — do not repeat):

```bash
git -C /home/nucadmin/gated worktree add --detach \
    /home/nucadmin/gated-uat-pin \
    1d75d54a97986e18fae499c370f8615e6cf89e15
```

`conftest.py` adds `gated-uat-pin` to `sys.path` on every pytest run and calls
`orchestrator.gated_pin.verify_gated_dependency()` — the same check the CLI runs.
A dirty tree or mismatched commit is a **hard rejection**.

If the worktree is missing (e.g. after a machine wipe), recreate it with the command
above.  The `gated` source repo at `/home/nucadmin/gated` must be on step-3.5-jobs
(Fab's branch) — not checked out to 1d75d54 itself.

## Phase status

| Phase | Status | HEAD |
|-------|--------|------|
| 0 | Complete | `9632afe` |
| 1 | **Complete** | `b7d769f` |
| 2 | Pending | — |

**Phase 2 blockers:**
- `AuthorizedRunPlan` integration — pending `gated` S3-completion on step-3.5-jobs (`3831770`, HELD)
- §11 artifact binding — `verify_gated_dependency()` currently uses git metadata; production should verify installed package hash

## Key design invariants (do not violate)

**Adapter seam** — `GatedCalibrationAdapter` in `orchestrator/calibration_driver.py` is the
**only** permitted import from gated's `gate/`, `engine/`, or `sandbox/` layers.
Profiles must not import from those namespaces directly.

**VerifiedChain sentinel** — `evaluate_admission()` only accepts `VerifiedChain`.
`VerifiedChain.__post_init__` raises `TypeError` unless the module-private sentinel is
passed — only `verify_integrity()` holds it. This is structural, not a convention.

**Integrity ≠ admission** — `verify_integrity()` checks cryptographic + structural
validity (a FAIL outcome passes integrity).  `evaluate_admission()` additionally
requires `schema_version >= 2`, `teardown.failure == False`, and outcome in
`{"pass", "fail"}` (not `"error"`).  These are separate concerns by design.

**Observer backend** — `ObservedOCISandbox` is required for `RetryCheck` to produce
PASS/FAIL verdicts (it counts egress through the sidecar proxy).  Plain `OCISandbox`
(`backend_kind="oci"`) causes all `RetryCheck` verdicts to be ERROR.  The P1 profile
uses `backend_kind="observed"` — do not change this.

**Full-SHA pin** — `_PINNED_COMMIT` in `orchestrator/gated_pin.py` must be the full
40-char SHA.  7-char prefixes are 28 bits and not authoritative.

## Image digest gotcha

When resolving a Podman image digest for `--image-digest`, use `{{.Id}}` (image-config
hash), **not** `{{.Digest}}` (manifest hash).  The OCI backend measures `.Id` at
runtime; supplying `.Digest` causes `ImageDigestMismatchError`.

```bash
# Correct:
podman image inspect --format '{{.Id}}' localhost/mori:local

# Wrong (manifest hash — will not match):
podman image inspect --format '{{.Digest}}' localhost/mori:local
```

If `.Id` is missing the `sha256:` prefix, prepend it manually.

## gated API surface (what the adapter bridges)

All of this lives at `/home/nucadmin/gated-uat-pin` (pinned commit `1d75d54`).
The gitnexus index for `gated` (path `/home/nucadmin/gated`, branch `step-3.5-jobs`)
is the authoritative call-graph reference for these symbols.

| Symbol | File (in gated) | Notes |
|--------|----------------|-------|
| `guarded_backend(kind, image_ref)` | `gate/backends.py:146` | Composition root; returns `(sandbox_factory, guard_policy)`. No upstream callers in gated itself — external entry point. |
| `calibrate(backend_guard=..., ...)` | `engine/calibration.py:251` | Called once per `CalibrationRequest`; returns `CalibrationResult` |
| `CalibrationResult` | `engine/calibration.py:136` | Carries `guard_policy_digest` (line 168), `trust_policy_digest`, `execution_identity_digest`, `policies_consistent` |
| `BackendGuardPolicy` (Protocol) | `gate/backends.py:101` | `policy_id: str`; mandatory on all `calibrate()` calls |
| `_TrustedBackendGuardPolicy` | `gate/backends.py:118` | Concrete guard returned by `guarded_backend()` |
| `ObservationTrustPolicy.policy_digest` | `gate/trust_policy.py:46` | Feeds `trust_policy_digest` in `CalibrationResult` |
| `calibrated_subject_identity` | `gate/attestation.py:92` | Produces `execution_identity_digest` |
| `trust_policy_digest` / `guard_policy_digest` | `gate/attestation.py:131-132` | Both sourced from `CalibrationResult` fields |

`resolve_trust_policy()` is called unmocked in integration tests — it is the key S3
import path validated by `TestGatedAdapterUnmocked` in `tests/test_adapter_integration.py`.

## Running tests

```bash
cd /home/nucadmin/gated-uat

# Full suite:
pytest

# With coverage:
pytest --tb=short

# Type check:
mypy --strict .

# Lint:
ruff check .

# Podman-only (requires localhost/mori:local):
pytest tests/test_adapter_integration.py -k TestGatedAdapterGenuinePodman
pytest tests/test_adapter_integration.py -k TestP1RegressionRun
```

127 tests pass at `b7d769f`.  Tests that require Podman images skip cleanly when absent.

## Schema versions

| Version | Status | Admitted |
|---------|--------|---------|
| v1 | Archived (Phase 0 receipts) | No (`SCHEMA_VERSION_MIN_ADMIT = 2`) |
| v2 | Current | Yes |

v2 execution receipt requires: `runtime_pack_digest`, `observer_log_digest`,
`observer_log_truncated`, and (for PASS/FAIL) `resolved_profile_digest`,
`trust_policy_digest`, `guard_policy_digest`, `execution_identity_digest`,
`policies_consistent`.

Bump `SCHEMA_VERSION` in `orchestrator/schemas.py` for any new breaking field.
Keep old validators so archived receipts remain cryptographically verifiable.

## git discipline

- Commit-pin enforcement means `gated-uat-pin` must stay at `1d75d54d...` — if you
  need to test against a newer gated commit, that is a Phase 2 decision, not a local
  workaround.  Update `_PINNED_COMMIT` in `gated_pin.py`, then move the pin worktree.
- Before any git op, check `git -C /home/nucadmin/gated-uat status` first.
- Never `git reset` (any form) — see feedback memory `feedback_never_git_reset.md`.
- Run `detect_changes()` in gitnexus before committing to verify blast radius.

## gitnexus

`gated-uat` is **not yet indexed** in gitnexus (as of July 2026).  Use the `gated`
index (path `/home/nucadmin/gated`, branch `step-3.5-jobs`) to understand gated's
API surface before touching the adapter.

```
query({search_query: "...", repo: "gated"})
context({name: "guarded_backend", repo: "gated"})
```

The `ai-stack` index is stale for `mori-verse` work (branch `mori-verse-3.3-tier-gatekeeper`,
2 commits behind as of July 2026).  Re-index with:
```bash
node .gitnexus/run.cjs analyze
```

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **gated-uat** (997 symbols, 2067 relationships, 44 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/gated-uat/context` | Codebase overview, check index freshness |
| `gitnexus://repo/gated-uat/clusters` | All functional areas |
| `gitnexus://repo/gated-uat/processes` | All execution flows |
| `gitnexus://repo/gated-uat/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
