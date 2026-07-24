# Board #3 (DRAFT v3 — aligned to Fred's (Y) pin) — reviewable-wire redesign

Status: **DRAFT for Fred's final nod before build.** Supersedes v2 (which carried the heavy
reconstruction stack Fred's pin explicitly rejects). Frame + rulings are Fred's board package;
this doc records the aligned build shape + three specifics needing his nod.

## Frame (Fred)
Board #2 sealed a TRUE NEGATIVE: ratified (C) builder sent `block2 = base64(canonical_review_source)`
— auditor-optimised, unreviewable; claude-sonnet-5 refused 5/5. Board #3 makes the wire
**reviewable** while preserving both binding properties. New committed shape → new fingerprint,
new commitment, new `board_id`, new n=1 seal. Board #2's builder untouched under its board_id.

## Ruling: (Y) — decoded file text, thin envelope-recompute
`source_digest = sha256(canonical_review_source(sealed))` is over the **full sealed tree**
(sorted `{files:[{path_b64,sha256,content_b64}]}`), computed in `llm_review_stage` BEFORE the
builder (unchanged). Fixtures are **multi-file** (`main.py` + `test_retry.py`) — verified.

**(X) rejected:** envelope-as-text closes double-encode refusal but the model still reviews
base64 `content_b64`; does not close "wire is reviewable". Rehearsal-proves-engagement ≠ reviewable.

## Wire (`AnthropicReviewableRequestBuilder`)
Exactly one `user` message; NO `system`, no assistant/tool blocks. Content blocks, in order:
- **block 0 — prompt**: byte-exact canonical `REVIEW_PROMPT`, nothing else.
- **block 1 — path list**: a small JSON array of the file relpaths in **canonical relpath order**
  (the `canonical_review_source` sort). JSON string-escaping is the injective inverse — no in-band
  delimiter. This is the "paths bound on the wire" the pin requires; `sha256` is NOT carried
  (auditor recomputes it — nothing decorative to lie about).
- **blocks 2 … N+1 — one text block per file**: RAW decoded UTF-8 file content, same canonical
  order as block 1. A zero-byte file is an explicit `""` block.

Whole Messages body serialised canonically (`sort_keys`, `separators=(",",":")`,
`ensure_ascii=True`) so `request_digest = sha256(body)` is reproducible. (Per the standing P2.7
note: `ensure_ascii=True` escapes non-ASCII in the body — the source-bytes digest and the body
digest remain two distinct, documented objects.)

## Builder fail-closed (before returning)
- **strict UTF-8**: `base64.b64decode(content_b64).decode("utf-8", errors="strict")` per file —
  raise on non-UTF-8 (a non-UTF-8 file cannot be shown as text; fail-closed, not lossy).
- **self-parse (thin)**: the builder runs its OWN auditor recompute over the wire it just built
  and asserts `sha256(rebuilt envelope) == source_digest` before returning — a framing bug can
  never pass the builder yet break the auditor.
- **NO NFC assertion** — dropped per the pin (see Residuals).

## Auditor recompute (the blessed path — a replay of the sealed function, NOT a new layer)
From the captured `request_b64`:
1. `body = json.loads(b64decode(request_b64))`.
2. **block 0**: `sha256(prompt_text.encode()) == review_prompt_hash`.
3. read block 1 path list; extract each file block's `content_bytes = text.encode("utf-8")`;
   pair `(relpath[i], content_bytes[i])` (count-aligned).
4. **rebuild via the EXISTING sealed algorithm**: sort pairs by raw-utf-8 relpath and build the
   `canonical_review_source` payload `{files:[{path_b64:b64(rel), sha256:sha256(content).hex(),
   content_b64:b64(content)}]}`, then `canonical_bytes("gated-uat.review-source", payload)`;
   assert `sha256 == source_digest`. This is a recompute of the fixed sealed
   `canonical_review_source`/`canonical_bytes` function — **no new Merkle, no NFC theatre, no
   block-set reconstruction layer.** The single `source_digest` equality subsumes per-file
   integrity + file-set completeness (a missing/extra/tampered file → mismatch).

## Rehearsal gate (Fred — the three-strikes law)
Before the sealed mint: ONE unsealed, **disclosed-as-rehearsal** transmission of the exact
committed wire shape to the real endpoint with a throwaway, prompt-irrelevant fixture — proving
the counterpart engages the shape (non-refusal) before we spend the seal. Disclosed in the run
record; **not part of n**. `test-fake-must-match-real-engine` now extends: no fake may stand in
for the counterpart's *content acceptance*, only for its transport.

## Seal suite deltas
- block2-is-strict-UTF-8; builder-v2 minimal-shape (exactly prompt + pathlist + N file blocks);
  envelope-recompute == source_digest; rehearsal-occurred-and-disclosed; all Board #2 seals
  (i)–(xiii) re-run under the new shape. `parse_anthropic_verdict` unchanged (refusal→ERROR proven).

## New commitment (pre-mint, published before the first live call)
`board_id`, n=1, `model=claude-sonnet-5`, `base_url`, **fingerprint-v2** (serializer id bumped,
new `review_prompt_hash`), `max_tokens=512`, max-source cap. Publish-whatever-happened. n=1, no
expansion. New n=1 mint = NEW seal (not a redo of `67e2c03c`).

## Residuals (named, not blocking)
- **Provider re-normalisation**: the provider may rewrite text before the model; disclosure attests
  the request/response **binding** (what we sent), NOT "the bytes the model saw". Reviewer stays a
  MEASUREMENT; gate column is the demonstration backbone. (This is why NFC-proof is theatre — dropped.)
- **Extra-block**: the bare recompute ignores any content block beyond the N files, so a builder
  *could* add a block the model sees but the recompute doesn't cover. `request_b64` is published, so
  a human sees it — but see specific #2 below for a one-line guard.

## Explicitly out (Fred)
ALLOWED_PATHS, receipt schema, provider-gate, prompt-content changes beyond block-shape, multi-model, k/n.

---

## Three specifics needing Fred's nod before build
1. **Path binding shape** — block 1 = a JSON array of readable relpaths (injective via JSON
   escaping), index-aligned to the file blocks. Alternative: `path_b64` list (opaque but
   trivially injective). Recommend readable relpaths (helps the reviewer; ASCII-safe fixtures).
2. **Extra-block guard** — include a one-line shape assertion (`content` is EXACTLY
   `[prompt, pathlist, *N files]`, no `system`) as a thin builder+auditor guard closing the
   extra-block residual? It is NOT the heavy block-set layer — just a count/shape check. Recommend
   YES (cheap, closes a real hole); your call to leave it as a named residual instead.
3. **Self-parse** — keep the builder self-parse (thin)? Recommend YES (same spirit as the
   rehearsal gate; catches builder framing bugs pre-mint).
