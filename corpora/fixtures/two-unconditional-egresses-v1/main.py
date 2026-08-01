"""two-unconditional-egresses-v1 — TWO unconditional egresses and NO retry logic whatsoever.

THE ROW THAT ADMITS THE INSTRUMENT'S LIMIT. The gate counts boundary egress attempts; it does not
judge intent. This artifact contains no retry: it simply makes two calls, one after the other, and
the second is not conditioned on the first in any way. The gate ADMITS it.

That is not a flaw being hidden — it is the symmetric half of the thesis. ``retry-swallow-v2`` shows
producer-side checks passing an artifact the gate blocks; this one shows the gate admitting an
artifact no reviewer would call resilient. A demo that showed only the first half would be curating
its table so the instrument looks more semantic than it is, which is the exact failure the gate exists
to expose in others.

⚠ BOTH ATTEMPTS ARE UNCONDITIONAL EVEN WHEN THE WITNESS REFUSES. The ``except OSError: pass`` is
load-bearing, not laziness: if a refused connection propagated, the second attempt would never run and
the measured count would become environment-dependent — 2 when the witness answers, 1 when it does
not. A row whose number moves with the weather is not a control. What the boundary counts is the
ATTEMPT, not its outcome, so swallowing the outcome is exactly right here and nowhere else.

⚠ AND THAT MAKES THIS THE ONLY WITNESS-INDEPENDENT ROW, which is a second job it does incidentally:
its count is 2 whether the witness answers, refuses or is misconfigured, so a reading other than 2 is
evidence about the COUNTER rather than about the artifact. Every other row's number depends on the
witness failing persistently, so on those a wrong number is ambiguous between artifact, witness and
counter. Treat this as a partial counter self-check ONLY — it is not the negative control, which is
still owed separately and is a different claim: a ZERO-EGRESS artifact must measure exactly 0. A
counter never shown to read zero on a silent artifact is an uncalibrated display, and this one only
ever shows it reading two.
"""
import socket


def _attempt() -> None:
    """One boundary egress. Its outcome is deliberately discarded — see the module docstring."""
    try:
        conn = socket.create_connection(("health-proxy", 8080), timeout=3)
        conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
        conn.recv(64)
        conn.close()
    except OSError:
        pass


def fetch_twice() -> None:
    """Two calls. NOT a retry — the second does not depend on the first having failed."""
    _attempt()
    _attempt()


if __name__ == "__main__":
    fetch_twice()
