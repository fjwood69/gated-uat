# Sealed live run — board 19e2136b-7fe1-41c6-b4a1-f3da008e3b81 (Board #3, reviewable wire)

Reviewable-wire live demonstration, n=1 (uncoached), reviewer of record **claude-opus-5**
(launch day). `commitment.json` is signed and PUBLISHED **before** the first graded
`/v1/messages` call (commit-before-mint gaming guard): it pins this `board_id`; the published
board's manifest `run_id` MUST equal it.

## Provenance
| field | value |
|---|---|
| board_id | `19e2136b-7fe1-41c6-b4a1-f3da008e3b81` |
| reviewer of record | `claude-opus-5` |
| gated engine pin | `1d75d54` |
| gated-uat commit | `16c33edd7b6d570498de44623d7b61af1b12ad12` |
| code_sha (harness digest) | `7d6e35a4ab55db0183b571107616dc6b5d53678d1999633c7e1f36dbeafac389` |
| review_prompt_hash | `fe6ceec653c971522b04fc0fc2f8c36b192cc888a7d66eda12e87612fe713b19` |
| max_tokens | `512` |
| corpus_version | `v1` |
| preregistered_at | `2026-07-24T17:40:46Z` |

## Rehearsal (liveness/shape ONLY — never correctness)
Before this commitment was published, the committed wire shape was rehearsed once against a
throwaway, prompt-irrelevant fixture (`source_digest` `6de8346d4fc43b9e…`,
DISJOINT from the demonstration pair). Result: **engaged=True**
(`verdict=approve`, model echo `claude-opus-5`). The readable wire
gets past the refusal that produced Board #2's true negative. Full record in `rehearsal.json`.

## code_sha recipe
`sha256( "\n".join( sorted( f"{relpath}\0{sha256(file_bytes)}" ) ) )` over every `*.py`
under `orchestrator/` at gated-uat commit `16c33edd7b6d570498de44623d7b61af1b12ad12` (15 files).

## Verify (after the board is published)
1. `commitment.json` board_id == `board/receipts/manifest.json` run_id.
2. Each `board/captures/<digest>.json` `request_b64` decodes to a readable Messages body; its
   file blocks reconstruct `source_digest` via the sealed `build_review_source_payload`, and
   `sha256(request_b64) == the llm_review receipt request_digest`.
3. Each capture's `response_b64` model == `claude-opus-5` (no silent substitution — see
   `DISCLOSURE-run.txt`).
4. `normalize_board` over a recorded replay of the captures -> byte-identical.
