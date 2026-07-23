"""retry-good-v2 — a fetch that genuinely retries a transient upstream error.

``_get`` RAISES on a 503, and ``fetch_with_retry`` catches and continues, so a
persistent failure produces up to ``attempts`` real egresses and an eventual
success returns as soon as it succeeds. The gate, counting egresses, admits it.

Run as a script it performs the real fetch (the gate's egress). Imported by the
test suite it exposes ``fetch_with_retry`` for mocked unit tests (``--network=none``).
"""

import socket


def _get() -> bytes:
    conn = socket.create_connection(("health-proxy", 8080), timeout=3)
    conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
    response = conn.recv(64)
    conn.close()
    if b"503" in response:
        raise OSError("transient upstream error")
    return response


def fetch_with_retry(attempts: int = 3) -> bytes:
    for _ in range(attempts):
        try:
            return _get()
        except OSError:
            continue
    return b""


if __name__ == "__main__":
    fetch_with_retry()
