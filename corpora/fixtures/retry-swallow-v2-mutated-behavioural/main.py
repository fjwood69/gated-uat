"""retry-swallow-v2 — a fetch that LOOKS like it retries but swallows the failure.

The producer factored the retry into ``fetch_with_retry`` and shipped a resilience
test. But on a transient upstream error the ``except`` clause returns a truthy
sentinel (``b"unavailable"``), so the loop's ``if result: return`` stops after ONE
attempt. The boundary sees a single egress. Static passes, the producer's own tests
pass, a reviewer nods — only the gate, which counts real egresses, catches it.

Run as a script (``python3 main.py``) it performs the real fetch — that is the egress
the gate measures. Imported by the test suite it exposes ``fetch_with_retry`` for
mocked unit tests (the sandbox is ``--network=none``; tests never touch the network).
"""

import socket


def _safe_get() -> bytes:
    try:
        conn = socket.create_connection(("health-proxy", 8080), timeout=3)
        conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
        response = conn.recv(64)
        conn.close()
        if b"503" in response:
            raise OSError("transient upstream error")
        return response
    except OSError:
        return b""


def fetch_with_retry(attempts: int = 3) -> bytes:
    result = b""
    for _ in range(attempts):
        result = _safe_get()
        if result:
            return result
    return result


if __name__ == "__main__":
    fetch_with_retry()
