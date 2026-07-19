# DESIGN — gated-uat slice 2.2b: live-**authorization** rebind refusals

Pinned gated: `1d75d54`. Predecessor: 2.2a `be8d042` (admission-*currency* refusals + injection taxonomy).

## 1. Scope — the remaining `admit_run_result` refusal chain

gated's `admit_run_result` runs an ordered, fail-closed live-currency chain (verified vs source,
`gate/run_admission.py:445–523`). Coverage after 2.1 + 2.2a:

| # | Refusal | sub_reason | Covered by |
|---|---------|-----------|-----------|
| 1 | LIVE_ATTESTATION_UNAVAILABLE | store_unreachable / attestation_absent | 2.2a (attestation_absent) |
| 2 | ORACLE_UNAVAILABLE | store_unreachable / **unresolved** | 2.2a (store_unreachable) |
| 3 | **AUTHORIZED_SET_MOVED** | — | **2.2b ← Scenario A** |
| 4 | SET_HEAD_STALE | — | 2.2a |
| 5 | **AUTHORIZED_SUBJECT_MOVED** | — | **2.2b ← Scenario B** |
| 6 | POLICY_GENERATION_MOVED | store_unreachable | 2.1 (ABA) |

Structural (`_validate_structural`, run pre-live at both mint and admit): ICV_UNSUPPORTED,
UNAUTHORIZED_SUBJECT (mint-incoherent), INCOMPLETE_COORDINATES, SUBJECT_DRIFT (2.1).

2.2b closes the two **live-authorization rebind** refusals (#3, #5) with REAL governance, and
**triages the genuinely non-inducible remainders** under the 2.2a taxonomy rather than fabricating them.

## 2. The attestation is one ENABLED row (grounding)

`current_attestation(policy_id)` → `(set_id, oracle_head, subject, generation)` is the newest
`tier_transition_chain` ENABLED row (`policy_store.py:1325`), created by `ratify_enable` from a
`calibration_pass`. Its coordinates:
- `set_id`, `oracle_head` (= `pinned_set_version`) — **set-membership derived, image-independent**
  (`set_head` = "digest of the CURRENT membership of set_id … an append to set X moves set_head(X)
  and NOTHING else", `calibration_store.py:327/354`).
- `subject` (= `detector_identity`) — **run/image derived** (`eid = report.execution_identity.digest()`,
  `run_admission.py:83–91`).
- `generation` (= `record_hash`) — monotonic per transition.

This split is what makes the two scenarios separable and non-preempting.

## 3. Scenario A — AUTHORIZED_SET_MOVED (Class A / STORE_MUTATION)

**Mechanism (real):** seed ENABLED on set1; mint the plan (`plan.authorized_set = set1`); between mint
and admit's attestation read, a scheduler performs a REAL `ratify_enable` onto a pass from a **second
calibrated set** (set2, a distinct fixture corpus), appending an ENABLED row with `set_id = set2`.
admit reads live attestation `set_id = set2 != plan.authorized_set (set1)` → **AUTHORIZED_SET_MOVED**.

**Ordering / non-preemption:** check #3, fires before oracle/set_head/subject/generation. Requires
only that the attestation is present (ENABLED) with a different set — which the re-enable guarantees.
`live_head`, subject, generation are never reached. ✔

**Fixtures:** a second calibration set (set2) with its own known-good/known-bad, calibrated + a pass,
ratifiable onto the same policy. (Fixture-heavy: a full second calibration lifecycle.)

**Negative control (unarmed):** same wrapped store, no re-enable armed → live set stays set1 → admits.

## 4. Scenario B — AUTHORIZED_SUBJECT_MOVED (Class A / STORE_MUTATION)

**Mechanism (real):** seed ENABLED on set1 calibrated on `_IMAGE_REF` (subject = subj1); mint the plan
(`plan.target_subject = subj1`); between mint and admit, a scheduler performs a REAL `ratify_enable`
onto a **same-set (set1) / second-image (`_IMAGE_REF_2`) calibration pass** — same fixtures ⇒ same
`set_id` + `pinned_set_version`, but a different image ⇒ different `detector_identity` (subj2). admit
reads: set matches (set1), head matches (unchanged membership), but `plan.target_subject (subj1) !=
live_subject (subj2)` → **AUTHORIZED_SUBJECT_MOVED**.

**Ordering / non-preemption (the delicate part):**
- #1 attestation present ✔ (re-enabled, ENABLED)
- #3 set match: same fixture set ⇒ `live_set_id == set1` ✔ (NOT AUTHORIZED_SET_MOVED)
- #4 head match: same membership ⇒ `bound_head == live_head` ✔ (NOT SET_HEAD_STALE)
- #5 subject differs ⇒ fires. #6 generation is checked AFTER → subject wins. ✔

**Distinct from 2.1 SUBJECT_DRIFT:** drift = the *measured* subject (second image at run) != dispatched
target, caught in `_validate_structural` (a runner-bypass). Here the run is compliant (measured ==
dispatched == subj1); it is the *live-authorized* subject that governance moved to subj2. Different
check, different code path, different scenario id.

**Fixtures:** the same set1 corpus re-calibrated on `_IMAGE_REF_2` → a second pass with subj2.

**Negative control (unarmed):** no re-enable → live subject stays subj1 → admits.

## 5. Triage — non-inducible-by-real-governance (NOT fabricated scenarios)

Per the UAT fidelity boundary (an evidence harness tests only what the real public path can PRODUCE;
construction-refused conditions → SUT unit tests) and the 2.2a `assert_inducible` discipline:

- **ORACLE_UNAVAILABLE `unresolved`** (None-return): `oracle_head_for` = `set_head`, which is
  **str-or-raise, never None** (2.2a ruling). A None is a value the real component's type cannot
  produce → FABRICATION-class → NOT a ScenarioId. Documented; the raise-path (`store_unreachable`) is
  the 2.2a-covered real fault.
- **UNAUTHORIZED_SUBJECT** (mint-incoherent): the real gatekeeper mints target == authorized from ONE
  snapshot by construction (`gatekeeper.py:205`). Only a hand-built plan violates it → FABRICATION.
- **ICV_UNSUPPORTED**: requires a plan minted under a different identity contract version — not
  producible in a single-build harness → FABRICATION / documented.
- **INCOMPLETE_COORDINATES** (coords are `str|None`): OPEN PROBE (carryover). Whether a *real* sandbox
  report can present an absent measured coordinate is unverified. **Proposal:** investigate as a probe;
  if a real degraded run can produce it → a Class-A/B scenario; if not → documented FABRICATION. Do
  NOT fabricate a report with a nulled coordinate to force it.

**Codification:** extend the taxonomy so these four have an explicit, tested classification (either a
`NON_INDUCIBLE` rationale table or their exclusion asserted by a completeness test), so "we didn't
cover it" is a *proven* non-inducibility, not a silent gap.

## 6. Test plan (standing doctrine: slow tier = mechanism, fast tier = contract)

- **Fast tier** (`test_schema_v3.py`): add SET_MOVED + SUBJECT_MOVED to `_EXPECTED_KIND` /
  `_BASE_TRIPLE_FAULT` as needed; prereg canon + matched-admits + (both are sub_reason="" so no
  currency converse) the (scenario, observed_kind) matrix cells; taxonomy completeness test covers the
  two new ids + the NON_INDUCIBLE triage.
- **Podman tier** (`test_enforcement_evidence.py`): one armed scenario test each (real re-enable
  scheduler → genuine refusal → signed admissible refutation chain) + one **full unarmed negative
  control** each (same wrapped store, no re-enable → admitted_run/pass; `require_completed_disclosure`
  raises).
- New schedulers in `tests/_currency_schedulers.py` (or a sibling `_authz_schedulers.py`): the
  DISARMED→ARMED→FIRING→COMPLETED state machine, arming post-stage, firing the real `ratify_enable`
  rebind at the live attestation read; disclosure is the induction record (COMPLETED-gated).

## 7. Open questions for /consult (deep, security)

1. **Scenario B reachability:** is a same-set/second-image `ratify_enable` actually admissible by
   gated's lifecycle (does re-enabling require leaving ENABLED first; does a second pass on the same
   set/version coexist), and does it truly leave `set_head` byte-identical? (Claimed from source; want
   an adversarial check.)
2. **Ordering traps:** any path where the re-enable's intermediate state (e.g. a transient
   non-ENABLED between DEGRADED and re-ENABLED) is observed by admit and yields LIVE_ATTESTATION_
   UNAVAILABLE instead — masking the intended refusal? The scheduler must fire so the FINAL committed
   state is the rebind.
3. **Triage soundness:** are ORACLE-unresolved / UNAUTHORIZED_SUBJECT / ICV genuinely non-inducible via
   the real public path (so SUT-unit/documented is correct, not a coverage dodge)?
4. **INCOMPLETE_COORDINATES:** inducible by a real degraded run, or FABRICATION?
5. **Scope:** is 2.2b = {A, B, triage-codification}, with INCOMPLETE_COORDINATES probe as a separate
   follow-up — or should the probe land in 2.2b?

## 8. Consult fold (deep security review, dissent-refined) — RATIFY-READY

Consulted deep/security; every load-bearing lifecycle fact then verified against `1d75d54`.

**Mechanism refined (both A + B) — fully real, NO read-interception.** `ratify_enable` enforces
`state == CALIBRATING` (`gatekeeper.py:461`), so a rebind is a REAL `ENABLED → (transition) CALIBRATING
→ run_calibration → ratify_enable → ENABLED` sequence performed **inside `artifact_source`** (which runs
AFTER plan-mint, the proven 2.1/2.2a interleave), committed IN FULL before admit's attestation read. The
transient CALIBRATING is therefore never observed by admit (kills consult trap §2.2 structurally); the
armed read is a PLAIN real read of the already-moved ENABLED row (more honest than the 2.2a read-wrapper
— no wrapper on the admit read path at all). The scheduler's COMPLETED-gated disclosure is the rebind
induction record; a half-done rebind leaves FAILED and `enforce` aborts evidence. Single-shot, post-commit.

**Scenario A (AUTHORIZED_SET_MOVED):** rebind onto a DISTINCT second set (set2 corpus). live_set_id=set2
≠ plan.authorized_set=set1 → fires (check #3, earliest). Negative control: stage-but-don't-rebind → admits.

**Scenario B (AUTHORIZED_SUBJECT_MOVED):** rebind onto a SAME-set (set1) / SECOND-IMAGE (`_IMAGE_REF_2`)
pass. Verified: `pass_binding` keys on `calibration_result_ref` (distinct per run) so the img2 pass
coexists and ratify selects it; same fixtures ⇒ identical `set_id` + `set_head` (sorted-membership digest,
image-independent); img2 ⇒ different `detector_identity`(subj2). So set match + head match, only subject
moves → fires (check #5), not preempted. Negative control: stage-but-don't-rebind → admits.

**Triage — verified non-inducible via the real public path (documented + completeness-tested, NOT
fabricated):**
- ORACLE_UNAVAILABLE `unresolved` (None-return): `oracle_head_for` = `set_head`, **str-or-raise, never
  None** — even a fully-deprecated set returns an (empty-membership) digest. The None branch is
  unreachable by the real store. FABRICATION-class.
- UNAUTHORIZED_SUBJECT: the real gatekeeper mints `target_subject == authorized_subject` from ONE
  snapshot (`gatekeeper.py:205`) — a real mint cannot violate it. FABRICATION-class.
- ICV_UNSUPPORTED: `ratify_enable` binds `identity_contract_version = IDENTITY_CONTRACT_VERSION` (the
  build constant); the plan's ICV comes from the same build. A single-pinned-build harness cannot mint a
  foreign ICV (this is the gated BUILD's contract version, NOT an image attribute). FABRICATION-class.
- **INCOMPLETE_COORDINATES — RECLASSIFIED to triage (the consult's one real finding):** a real degraded
  podman run yields non-zero exit / no report / malformed output / runner health error — never a
  *structurally-valid-but-coordinate-incomplete* report. Hitting the exact refusal needs an injected
  partial report = fabrication. **Removed from the probe scope**; the carryover "INCOMPLETE_COORDINATES
  probe" is hereby resolved as non-inducible-via-real-path.

**FINAL 2.2b scope:** `{ Scenario A, Scenario B, triage-codification of the 4 non-inducible refusals }`.
No fabricated scenarios. Both evidence tiers per standing doctrine (fast = contract, slow = mechanism).

**Taxonomy codification:** add a `NON_INDUCIBLE` rationale (a small table mapping each of the 4 refusals
to its FABRICATION reason) + a completeness test asserting EVERY gated `RunAdmissionRefusal` member is
either a covered ScenarioId or an explicitly-classified non-inducible — so an uncovered refusal is a
PROVEN non-inducibility, never a silent gap. This is the 2.2b analogue of `assert_inducible`.

## 9. REVISION — NOT RATIFIED (board P1), corrected mechanism = OPTION 3 (public recalibration loop)

**Why §3/§4/§8's mechanism is DEAD (board's cut, confirmed vs source):** they claimed an
`ENABLED → CALIBRATING` re-enable. The ACTUAL legal table (`policy_state.py:96-109`) FORBIDS both
`ENABLED→CALIBRATING` and `DEGRADED→CALIBRATING`, and `transition()` refuses a CALIBRATING target
outright (`policy_store.py:329`; `enter_calibrating` is the sole path, itself gated by the same table).
The `gatekeeper.py:461` cite ("enforces state==CALIBRATING") was the DOCSTRING pointed-at, not the line
read — the line calls `pass_binding()`. Lesson banked: a file:line is evidence only when the line + the
enforcing table are READ.

**OPTION 3 — the refusals ARE publicly inducible via the LEGAL operator recalibration loop** (verified
vs `1d75d54`, lines read). The set/subject lock the board relied on is ONLY the RestoreController
reattest keep-alive (`restore_controller.py:239-249`). The deliberate recalibration loop is a different,
fully-legal path: `ENABLED → ADVISORY → PENDING_CALIBRATION → CALIBRATING → ENABLED`. On it:
- `run_calibration` (`gatekeeper.py:298,308,335`) takes `set_id` as a FREE caller input, seals THAT set,
  runs a REAL measurement, persists a pass bound to the MEASURED subject;
- `enter_calibrating` guards = non-empty-routing + ICV + legal-edge + no-active-**recalibration**-intent
  (the admission plan is NOT a refresh_intent, so it does not block) — NO prior-set/subject pin;
- `ratify_enable` pulls `(subject, set_id)` FROM the pass; `transition(ENABLED)` binds the pass's OWN
  coordinates via `_pass_exists_unlocked`; `satisfy_intent_with_pass` binds by
  `(generation, revision, head, set_id, ICV)` — NONE compares to the prior authorized set/subject.

So both refusals are **pure public Class-A STORE_MUTATION** — NO disclosed non-public injection (the
board's Option 2 is unnecessary), NO coverage hole (Option 1 unnecessary).

- **Scenario A (AUTHORIZED_SET_MOVED):** recalibrate onto a DISTINCT second set (set2 corpus) →
  live_set_id=set2 ≠ plan.authorized_set=set1 → fires check #3 (before #4 SET_HEAD_STALE).
- **Scenario B (AUTHORIZED_SUBJECT_MOVED):** recalibrate the SAME set on `_IMAGE_REF_2`. The four subject
  coordinates are profile/trust/guard digests (policy-derived, image-INDEPENDENT) + `eid`
  (`execution_identity.digest()`, image-DEPENDENT). Second image ⇒ eid moves ⇒ subject moves; profile/
  trust/guard unchanged ⇒ `run_calibration` witness-check (`gatekeeper.py:393`) PASSES; same fixtures ⇒
  identical set_id + set_head. So set match + head match, only subject moved → fires check #5 (not
  preempted by #3/#4). Pass coexists (calibration_result_ref includes the subject → distinct ref).

**Induction seam:** the scheduler runs the WHOLE loop inside `artifact_source` (AFTER plan-mint, the
proven interleave), committed IN FULL before admit's single read. The transient ADVISORY/CALIBRATING
states are never observed (the harness drives it synchronously; admit reads the final ENABLED-on-new
row). COMPLETED-gated disclosure = the recalibration induction record. Negative control: stage-but-do-
NOT-run-the-loop → admit reads the original ENABLED binding → admitted_run/pass.

**Surviving structural claims RE-VERIFIED under the corrected lifecycle** (Fred flagged they were earned
against a dead sequence): set_head image-independence (`_compute_set_head` sorted-membership digest) ✓;
subject-moves-with-image (eid vs policy-derived profile/trust/guard) ✓; pass coexistence by ref ✓.

**Triage unchanged** (still non-inducible; INCOMPLETE_COORDINATES reclassified per the prior consult).

**Consult status (honest):** the re-consult was SOURCE-BLIND — deep returned empty (Bifrost routing
flake), quick reasoned without the repo and only hypothesised a pin that source-read DISPROVES. Option 3
therefore rests on MY primary-source verification (lines cited above, read), not an independent review.
If the consult routing is fixed, a source-having re-consult is cheap insurance before build.

**REVISED 2.2b scope:** `{ Scenario A (public loop), Scenario B (public loop), triage-codification }`.
Cost vs the dead design: each armed scenario runs an EXTRA real podman calibration (the loop's
measurement) — slower, but maximally honest (fully public governance, no injection class needed).
