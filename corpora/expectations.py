"""BY-CONSTRUCTION expectations — derived by READING the fixtures, never by running them.

⚠ THIS FILE EXISTS TO BREAK A CIRCULARITY, and the circularity is worth stating plainly. The release
freezes measured egress counts produced by the gate. If a frozen count were wrong, every later run
would check `wrong == wrong`, print green forever, and the demo would be a drift detector wearing a
correctness oracle's clothes.

What breaks it is a SECOND, INDEPENDENT DERIVATION of the same numbers. These are obtained by reading
the source and counting the calls a persistent-failure run must make — a human-derivable claim that
can be checked without executing anything. The pre-tag gate asserts the two agree.

That converts "the gate said so" into "the gate AGREED WITH a claim derived another way". It does not
make the demo a correctness oracle — two agreeing derivations are still two derivations — but a wrong
number now has to be wrong in BOTH, and the second one is checkable by a reader with no container
runtime at all.

⚠ IT MUST NEVER IMPORT `gated`, and it must never import the fixtures. Importing the engine would
re-enter the loop this file exists to break; importing the fixtures would let their code, rather than
a reading of it, decide the answer.

⚠ AND IT MUST BE MAINTAINED BY HAND. If a future edit "regenerates" these from a run, the file becomes
a copy of the thing it checks and the check becomes a tautology — silently, with every test green.
"""

# The witness returns a persistent failure (HTTP 503) for the duration of a demo run. Every count
# below is derived under THAT condition, stated because the numbers are meaningless without it: a
# witness that succeeded on the first call would change three of the five.
WITNESS = "persistent 503"

# fixture -> (expected egress count, the derivation, in enough detail to be checked by reading)
BY_CONSTRUCTION: dict[str, tuple[int, str]] = {
    "retry-swallow-v2": (
        1,
        "fetch_with_retry loops up to attempts=3, but _safe_get catches the OSError raised on 503 and "
        "returns b'unavailable' — a TRUTHY sentinel. The loop's `if result: return result` therefore "
        "returns after the FIRST call. One call reaches the boundary.",
    ),
    "retry-swallow-v2-mutated-behavioural": (
        3,
        "identical to retry-swallow-v2 except the except-clause returns b'' — FALSY. `if result` is "
        "never true, so the loop runs to its bound of 3 and returns the falsy value. Three calls "
        "reach the boundary. This is the ONLY line that differs, and it is why the count moves.",
    ),
    "retry-swallow-v2-mutated-cosmetic": (
        1,
        "identical to retry-swallow-v2 except one line gains a trailing COMMENT. Comments do not "
        "execute. The truthy sentinel still short-circuits the loop after one call. Count unchanged "
        "at 1 — which is the whole point of the row: changed bytes, unchanged behaviour.",
    ),
    "two-unconditional-egresses-v1": (
        2,
        "fetch_twice calls _attempt() twice, unconditionally. _attempt swallows OSError, so a refused "
        "connection does NOT prevent the second call. Exactly two calls reach the boundary, and "
        "notably this holds whether the witness answers or refuses — the only witness-independent "
        "row in the set.",
    ),
    "retry-good-v2": (
        3,
        "fetch_with_retry loops up to attempts=3; _get RAISES on 503 and the loop catches and "
        "continues rather than returning. With a persistent failure all three attempts are made. "
        "Three calls reach the boundary.",
    ),
}

# The corpus members, as an EXACT SET. Exact-set equality is a DISTINCT AXIS from content equality: a
# corpus can have every member's bytes correct and still be wrong by having one too few or one too
# many. Content checks are blind to that, in the same way a control that checks an argv node is blind
# to the arguments passed into it.
EXPECTED_MEMBERS = frozenset(BY_CONSTRUCTION)
