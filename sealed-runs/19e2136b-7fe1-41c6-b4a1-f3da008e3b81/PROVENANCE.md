# Commit provenance — board 19e2136b-7fe1-41c6-b4a1-f3da008e3b81 #3 (reviewable wire)

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
| committed `code_sha` | `7d6e35a4ab55db0183b57110…` |
| originally recorded commit (DEAD) | `16c33edd7b6d…(as recorded)` |
| **live commit where `code_sha` reproduces** | **`2fc56ec91493`** |

```bash
git checkout 2fc56ec91493
# recompute the digest over orchestrator/*.py -> must equal the committed code_sha above
```

Disclosed rather than quietly corrected: the rewrite was ours, it cost this link, and the
replacement is stated so any reader can still re-derive the binding independently.
