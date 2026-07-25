# Commit provenance — board 67e2c03c-ae24-4db1-ac6a-30481ca5dbd5 #2 (true negative)

**The `gated-uat commit` recorded in `README.md` no longer exists.** After this board was
sealed, the repository's git history was rewritten twice (to remove internal host paths and an
ops file carrying a token-in-URL push recipe) before the repo was made public. Rewriting changes
every commit SHA, so the originally-recorded harness commit is unreachable.

Nothing in the sealed evidence changed — the rewrite touched only documentation/comment strings
and removed non-`orchestrator/` ops files. The commitment, receipts, captures and signatures are
byte-identical to the moment of minting.

## How to verify `code_sha` today

`code_sha` = `sha256( "\n".join( sorted( f"{relpath}\0{sha256(file_bytes)}" ) ) )` over every
`*.py` under `orchestrator/`.

| | |
|---|---|
| committed `code_sha` | `83be50a65c6809b564b534792d530ec869a77a55aaf4935b58aa110ce5d7820c` |
| originally recorded commit (DEAD) | `50f2fba6133f11482ab10d011f5629e40535c647` |
| **live commit where `code_sha` reproduces** | **`417d2529d184`** |

```bash
git checkout 417d2529d184
# recompute the digest over orchestrator/*.py -> must equal the committed code_sha above
```

Disclosed rather than quietly corrected: the rewrite was ours, it cost this link, and the
replacement is stated so any reader can still re-derive the binding independently.
