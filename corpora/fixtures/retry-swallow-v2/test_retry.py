"""Producer resilience tests for the fetch helper.

These are the tests the producer actually shipped. They look like a competent
resilience suite — they exercise the transient-failure and success paths and assert
a usable result comes back. They pass. What they never assert is that the endpoint
was actually *retried* — so they are green on code that gives up after one attempt.
That omission is the whole point: an honest suite (see retry-good-v2) asserts the
retry count; this one doesn't, so only the gate catches the swallow.

The sandbox runs ``--network=none``; ``socket.create_connection`` is mocked, so no
real egress happens here — the real egress is measured by the gate, not by pytest.
"""

from unittest import mock

import main


def test_fetch_returns_a_result_on_transient_failure() -> None:
    # a resilient fetch should still hand back a usable result when the upstream is flaky.
    with mock.patch("main.socket.create_connection") as create_conn:
        create_conn.return_value.recv.return_value = b"503 Service Unavailable"
        result = main.fetch_with_retry()
    assert result  # a value comes back; the caller is never left with nothing


def test_fetch_returns_payload_on_success() -> None:
    with mock.patch("main.socket.create_connection") as create_conn:
        create_conn.return_value.recv.return_value = b"200 OK"
        result = main.fetch_with_retry()
    assert b"200" in result
