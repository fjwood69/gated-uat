"""Producer resilience tests for the fetch helper — the HONEST suite.

Unlike retry-swallow-v2, this suite asserts what actually matters: that a transient
failure is *retried* (``call_count``), not merely that some value comes back. It is
green on the honest implementation and would FAIL the swallow (which retries only
once) — which is exactly why the swallow's producer shipped the weaker suite instead.

``--network=none``: ``socket.create_connection`` is mocked; no real egress here.
"""

from unittest import mock

import main


def test_fetch_retries_transient_then_succeeds() -> None:
    with mock.patch("main.socket.create_connection") as create_conn:
        create_conn.return_value.recv.side_effect = [b"503 Service Unavailable", b"200 OK"]
        result = main.fetch_with_retry()
    assert b"200" in result
    assert create_conn.call_count == 2  # retried once, then succeeded


def test_fetch_uses_the_full_budget_before_giving_up() -> None:
    with mock.patch("main.socket.create_connection") as create_conn:
        create_conn.return_value.recv.return_value = b"503 Service Unavailable"
        result = main.fetch_with_retry(attempts=3)
    assert result == b""
    assert create_conn.call_count == 3  # tried the full retry budget
