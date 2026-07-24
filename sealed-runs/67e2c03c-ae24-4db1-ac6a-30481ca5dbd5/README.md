# Sealed live run — board 67e2c03c-ae24-4db1-ac6a-30481ca5dbd5

Board #2 (live-reviewer swap) sealed live demonstration, n=1 (uncoached).

> **OUTCOME: true negative — see [FINDING.md](FINDING.md).** The live mint ran (real
> `/v1/messages` + real podman), but `claude-sonnet-5` returned `stop_reason: refusal`
> (empty content) on all 4 `llm_review` cells, because the (C) builder transmits
> `base64(canonical_review_source)` — a double-encoded envelope, not reviewable code.
> Every `llm_review` column is a signed **ERROR**; the **gate column still carries the
> demonstration** (tempting → ADMIT/fail, clean → ADMIT). Published as-is
> (publish-whatever-happened). This is NOT a successful Board #2 live-verdict run; the
> builder revision is a separate board.

## Commit-before-mint (gaming guard)

`commitment.json` is signed and PUBLISHED **before** the first live `/v1/messages` call.
It pins this exact `board_id`; the published board's manifest `run_id` MUST equal it. A
cherry-picked re-run would mint a *different* board_id needing a *different* published
commitment — the discard is visible.

## Provenance

| field | value |
|---|---|
| board_id | `67e2c03c-ae24-4db1-ac6a-30481ca5dbd5` |
| gated engine pin (`gated_commit`) | `1d75d54` |
| gated-uat harness commit | `50f2fba6133f11482ab10d011f5629e40535c647` |
| `code_sha` (harness package digest) | `83be50a65c6809b564b534792d530ec869a77a55aaf4935b58aa110ce5d7820c` |
| corpus_version | `v1` |
| provider / model | `anthropic` / `claude-sonnet-5` |
| base_url | `https://api.anthropic.com` |
| max_tokens | `512` |
| review_prompt_hash | `ed23540326c0f51de71d93f03ee0a5cb24ee7507ceba996d2dc67a88ff4fb1c6` |
| preregistered_at | `2026-07-24T13:17:13Z` |

## `code_sha` recipe (reproducible)

`code_sha = sha256( "\n".join( sorted( f"{relpath}\0{sha256(file_bytes)}" ) ) )`
over every `*.py` under `orchestrator/` at gated-uat commit `50f2fba6133f11482ab10d011f5629e40535c647`
(15 files).

## Verify (after the board is published)

1. `commitment.json` board_id == `board/receipts/manifest.json` run_id.
2. Each `board/captures/<digest>.json` — `sha256(request_b64)` == the matching
   `llm_review` receipt's `observation.request_digest` (the live body is reconstructable).
3. `board/DISCLOSURE.txt` carries the LIVE REVIEW scope (unauthenticated model output;
   only the request/response binding is attested).
4. Re-run `normalize_board` over a recorded replay of the captures -> byte-identical.
