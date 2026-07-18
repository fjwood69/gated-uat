# Design — slice 2.1 prereg/evidence rebuild + ABA rebuild (one unit)

Status: DRAFT for /consult → board. Supersedes the prereg/evidence timing + the ABA negative in
the HELD 2.1b/2.1c. 2.1a's enable-path core + the three landed corrections (271fe96) stand.

## Why (the two ratified-core failures the dissent caught)

1. **Preregistration is a postdiction.** `enforce()` runs `job_runner(event)` *before* `_build_chain()`
   mints the prereg. A prediction written after the observation is not a prediction — prereg-relative
   admissibility (the amendment's reason to exist) does not exist, and `evaluate_admission` checks only
   `outcome ∈ {pass,fail}` + teardown-clean, with nothing to compare against.
2. **The evidence contract signs what the scenario never produced** (`plan_policy_id=seed.policy_id`
   for non-runs; forbids refusals from carrying observed heads; binds a post-read `policy_generation`
   as an admission-bracket head; omits the promised seed-trace + fault-injection signables).

The fix is one contract: **fields typed by provenance class — configured / captured / measured-observed /
fault-injection / seed-trace — and a receipt may sign only what its scenario actually produced in each
class**, with admissibility = signed pre-run expectation vs signed post-run observation.

## A. Preregistration (minted + SIGNED before `job_runner(event)`)

Only pre-run-knowable signables:

| field | provenance | notes |
|---|---|---|
| `schema_version` = 3 | fixed | |
| `profile`, `gated_commit`, `corpus_version`, `preregistered_at` | configured | as today |
| `scenario` | configured | stable id: `compliant_admit`, `non_enabled`, `mis_route`, `aba_generation_moved`, `subject_drift_second_image`, `sha_tamper` |
| `configured_policy_id` | configured | the policy the run TARGETS (always present) |
| `code_sha` | configured | identity of the harness that made the prediction (see Q1) |
| `run_context_pre` | configured | `event_digest` + `image_ref`/`toolchain_image_digest` + `detector_id` — all chosen pre-run |
| `expected` | **prediction** | `{kind, reason, sub_reason}` — the committed claim (see below) |

`expected` = the JobResult class + discriminating token the scenario predicts, all deterministic
pre-run:
- admitted_run → `{kind: admitted_run, reason: <expected outcome: pass|fail>, sub_reason: ""}`
  (we predict the *outcome*, not the engine's internal verdict-reason token — that keeps the claim
  pre-run-committable for a known-good/known-bad candidate; see Q2).
- blocking_refusal → `{kind: blocking_refusal, reason: <RunAdmissionRefusal token>, sub_reason: <...>}`.
- non_run → `{kind: non_run, reason: <Disposition token>, sub_reason: ""}`.
- infrastructure_failure → `{kind: infrastructure_failure, reason: <InfraFailureReason token>, sub_reason: ""}`.
- mis_route is not a JobResult (it RAISES GateDecisionError) → `expected.kind = raises`,
  `reason = GateDecisionError` (admissibility for a raise-scenario = the raise happened; see Q3).

## B. Execution receipt (post-run) — provenance-typed OBSERVED fields

```
CONFIGURED   echoed from prereg: configured_policy_id, profile, gated_commit, detector_id,
             run_context_pre, scenario.
CAPTURED     plan_policy_id — ONLY when a plan was actually captured (RUN_ENFORCING dispatched a
             plan: admitted_run or a post-run refusal). ABSENT for non_run / infra-before-run /
             mis_route. Never fabricated from seed.policy_id.
OBSERVED     the closed discriminator the run produced: {result_kind, result_reason,
             result_sub_reason, gate_outcome}; plus scenario-specific observed fields, present ONLY
             for the scenarios that measured them:
               admitted_run: bound_oracle_head, observed_policy_head_post_admission (RENAMED — no
                 bracket claim; see C), artifact_tree_hash, image_digest, the 4 coords, outcome.
               subject_drift refusal: the MEASURED (drifted) coords + the drift image_digest — the
                 evidence of WHY it refused.
               aba refusal: the observed set-head trajectory + the two policy generations
                 (bound vs moved) — the evidence the generation bracket fired.
             (Fred: add scenario-specific observed fields rather than declaring all non-admitted
             measurements nonexistent.)
FAULT_INJECTION  signed disclosure {locus, mechanism, interleaving_point}, present ONLY for
             fault-injecting scenarios (aba, sha_tamper). The evidence DISCLOSES the injection.
SEED_TRACE   signed SeedProvenance (configured + measured/store-derived fields) — how the policy
             reached ENABLED. Bound into every enforcement chain.
```

## C. Admissibility = signed expectation vs signed observation

`evaluate_admission(chain)` for a v3 enforcement chain:
1. teardown clean (as today); AND
2. `execution.observed.{kind,reason,sub_reason} == prereg.expected.{kind,reason,sub_reason}`.

MATCH → admissible (the scenario CONFIRMED its prediction — including a predicted refusal/block).
MISMATCH → **not admissible = FAIL** (e.g. expected `blocking_refusal(policy_generation_moved)` but
got `admitted_run` ⇒ the ABA closure FAILED; or a scenario predicted a block but got SKIP_NEUTRAL ⇒
the silent-fall-open the amendment forbids). Integrity still passes (a valid signed record of a
refuted prediction); admission is what flags it.

`policy_generation` → **`observed_policy_head_post_admission`**, explicitly post-read, NO
admission-bracket claim (AdmittedRunResult does not expose the bracket generation). Filed gated
follow-up: expose the bracket generation from the result-bound admission proof; then the stronger
"admission-bracket head" binding arrives via design→board on the gated side.

## D. ABA rebuild (store-layer scheduler — genuine ABA, below-seam)

Replace the governance-view subclass (the rejected fork) with a **store-layer scheduler** that
sequences REAL public writes and leaves the production `_ProductionAdmissionGovernanceView`
UNTOUCHED:

1. real fixture **append** on the calibration store: set-head `H → H1`;
2. real **policy transition** (ENABLED → …): moves the policy generation;
3. real fixture **deprecate/re-add**: set-head `H1 → H` (the ABA return to an identical-looking head).

Interleaved so that at admission's set-head read the head is back to `H` (the set-head check is
DEFEATED — passes), and ONLY the generation bracket catches the move → `POLICY_GENERATION_MOVED`.
The interleaving point (between the attestation snapshot and the post-oracle generation re-read) is
driven by a store-layer wrapper's method boundary, not by overriding a governance read. Disclosed as
signed `fault_injection{locus: calibration-store scheduler, mechanism: append→transition→deprecate
(H→H1→H), interleaving_point: post-attestation / pre-generation-reread}`.

This tests true cross-store ABA (identical head at bind and check, real movement between), not a
generation race.

## Open questions for /consult + board

- **Q1 code_sha**: what identity binds the harness that made the prediction? gated-uat git HEAD is
  wrong (tests run on dirty trees; the receipt is runtime-generated, not committed). Options: a digest
  of the `orchestrator` package bytes; or drop it and rely on `gated_commit` + the signer key as the
  harness-identity anchor. Recommendation: package-bytes digest, or omit with rationale.
- **Q2 admitted expected-reason granularity**: predict `outcome` (pass|fail) vs the engine's internal
  verdict-reason token. Predicting the token over-commits to an implementation detail; predicting the
  outcome is the honest falsifiable claim. Recommendation: outcome.
- **Q3 raise-scenario admissibility**: `mis_route` RAISES (no JobResult, no chain). Does it get a
  signed "expected-raise / observed-raise" record, or stay a plain `assertRaises` with no evidence
  chain? A raise produces no receipt to sign. Recommendation: `mis_route` stays a plain assertion
  (no chain); the signed-evidence contract covers only scenarios that produce a JobResult.
- **Q4 scheduler realizability**: does gated's calibration store expose a deprecate/re-add that
  returns set-head to an EARLIER value (true H→H1→H), and a timing seam to interleave it at the
  bracket? If not, the genuine-ABA test may need a gated-side hook (a follow-up), and 2.1c's ABA
  negative is deferred with that dependency logged — better than shipping a generation-race mislabelled
  as ABA.

---

## REDESIGN of [2]/[3] — the (scenario, observed_kind) MATRIX (re-validation withdrawal)

**Defect the first cut shipped:** `_SCENARIO_KIND` keyed the required execution fields to the
scenario's *predicted* kind, so the schema became a CONFIRMATION FILTER — an ABA run that
*unexpectedly admits* could not be serialised at all, and the one observation the prereg discipline
exists to capture ("predicted block, it admitted") died at schema validation before
`evaluate_admission` saw it. The instrument could only record agreement. Fix:

**M1 — matrix.** Separate the two axes:
- SCENARIO (what the HARNESS did) determines CONFIGURED + FAULT-INJECTION fields:
  `seed_trace` (all scenarios), `fault_injection` (aba: base+5 heads; sha_tamper: base triple),
  `drift_image_digest` (subject_drift).
- OBSERVED `result_kind` (what the SUT PRODUCED) determines OBSERVED-RESULT fields:
  `admitted_run` → the 8 measured coordinates; `blocking_refusal`/`non_run`/`infrastructure_failure`
  → none. `plan_policy_id` = explicit null iff `non_run`; `gate_outcome` = explicit null iff
  `infrastructure_failure`.
- Exact key set = COMMON ∪ configured(scenario) ∪ observed(result_kind). EVERY closed kind is
  representable under EVERY scenario. The schema NO LONGER checks scenario↔kind coherence — that was
  the defect. `evaluate_admission` is the SOLE place expectation meets observation.

**M2 — prereg bound to the authored fixture (P1b).** `validate_prereg_payload` asserts the expected
triple `== expected_for(ScenarioId(scenario))` EXACTLY (unit [1]'s authored authority was never
consumed; authority unconsumed is authority absent). Add prereg-tamper negatives. Also add
`rc_image_digest` (sha256:, resolved pre-run) so image identity is continuable.

**M3 — continuity binds run context (P1c, fork-4 rebindability).** `validate_semantic_continuity` v3:
`execution.event_digest == prereg.rc_event_digest`; `plan_policy_id == configured_policy_id` when
present; `seed_trace.policy_id == configured_policy_id`; `seed_trace.detector_id ==
prereg.rc_detector_id`; and the run image (`image_digest` for admitted / `drift_image_digest` for
subject_drift) `== prereg.rc_image_digest`.

**M4 — ABA evidence non-degenerate (P2).** The 5 heads are hex64 (not merely non-empty), and the
schema asserts the ABA shape: `head_bound == head_returned`, `head_moved != head_bound`,
`policy_head_pre != policy_head_post`. Tests narrow `assertRaises(Exception)` → `SemanticContinuityError`.

**Acceptance floor — the signed-refutation round-trip.** For each of {aba-admits, degraded-admits,
degraded-neutrals, tamper-admits}: a chain minted (predicts X) + observed (Y≠X) must
`verify_integrity` PASS (an honest record) and `evaluate_admission` FAIL (a recorded refutation). The
harness must prove it can write down its own falsification before [4] proceeds.

### Open questions for /consult (redesign)
- **QM-1:** Are there `(scenario, observed_kind)` cells that are PHYSICALLY impossible (the harness
  could never produce them) — and if so should the schema reject them, or stay permissive and let
  admissibility fail? (Permissive keeps the schema a pure recorder; rejecting re-introduces a
  confirmation-filter risk. Lean permissive — but is any cell a genuine integrity violation, e.g. a
  `non_run` carrying a captured plan?)
- **QM-2:** The degraded-neutrals refutation: a DEGRADED policy that silently neutrals yields observed
  `(non_run, "skip_neutral", "")` vs expected `(non_run, "block_action_required", "")` → admission
  fails. Is comparing the disposition token the right granularity to catch silent-fall-open, or is a
  coarser kind-only compare a hole?
- **QM-3:** Image continuity for subject_drift binds `drift_image_digest == rc_image_digest` — i.e.
  the prereg's `rc_image_digest` is the RUN (drift) image, while the SEED ran on a different image.
  Is preregistering the run image (not the seed image) the honest choice, and does anything need to
  bind the seed image too?
