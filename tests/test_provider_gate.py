"""tests/test_provider_gate.py — B1 seal gate 1: the provider-gate ReviewClient (closes SD1).

Proves the egress boundary is CAPABILITY-DELETION, not policy:
  * the completion path (/v1/messages) is reachable; a control-plane path (/v1/environments, ...) is
    REFUSED at the send boundary (the transport is never even called);
  * the allowlist is EXACTLY {COMPLETION_PATH} — a schema/config law: widening it (a future
    "add tool-use") breaks this test rather than silently growing the surface;
  * the client TRANSMITS the harness-built request bytes VERBATIM (never re-forges the body);
  * end-to-end through llm_review_stage: the bytes that cross the client == the stage-built envelope
    embedding the sealed source, and request_digest binds them (containment now holds THROUGH a real
    transmit-only client, up to the wire this client owns).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from orchestrator.gauntlet import (
    _canonical_review_request,
    canonical_review_source,
    llm_review_stage,
    seal_artifact,
)
from orchestrator.provider_gate import (
    COMPLETION_PATH,
    CONTROL_PLANE_PATHS,
    CompletionOnlyEgress,
    EgressRefused,
    ReviewProviderClient,
)

_BASE = "https://api.anthropic.com"
_PROMPT_HASH = "b" * 64


class RecordingTransport:
    """Records every (url, body) it is asked to send; returns a canned response. Lets tests assert
    WHAT crossed the wire (verbatim bytes) and that a refused path never reaches the transport."""

    def __init__(self, response: bytes = b'{"verdict":"approve"}') -> None:
        self.calls: list[tuple[str, bytes]] = []
        self._response = response

    def __call__(self, url: str, body: bytes) -> bytes:
        self.calls.append((url, body))
        return self._response


def _parse_verdict(response: bytes) -> str:
    return str(json.loads(response)["verdict"])


def _client(transport: RecordingTransport) -> ReviewProviderClient:
    return ReviewProviderClient(
        egress=CompletionOnlyEgress(transport=transport, base_url=_BASE),
        provider_id="anthropic", model_id="reviewer-1", parse_verdict=_parse_verdict)


def _seal(tmp_path: Path):  # noqa: ANN202
    (tmp_path / "a.py").write_text("x = 1\n")
    return seal_artifact(tmp_path)


# ---- egress allowlist: completion reachable, control-plane refused ----

def test_completion_path_is_reachable() -> None:
    t = RecordingTransport()
    egress = CompletionOnlyEgress(transport=t, base_url=_BASE)
    out = egress.post(COMPLETION_PATH, b"hello")
    assert out == b'{"verdict":"approve"}'
    assert t.calls == [(_BASE + COMPLETION_PATH, b"hello")]


def test_control_plane_paths_are_refused_before_the_transport() -> None:
    t = RecordingTransport()
    egress = CompletionOnlyEgress(transport=t, base_url=_BASE)
    for path in CONTROL_PLANE_PATHS:
        with pytest.raises(EgressRefused):
            egress.post(path, b"x")
    # capability-deletion: the refused paths NEVER reached the transport
    assert t.calls == []


def test_allowlist_is_exactly_the_completion_path_schema_law() -> None:
    # a future "add tool-use / environment provisioning" would widen this set -> this test fails,
    # rather than the surface silently growing (schema/config law).
    egress = CompletionOnlyEgress(transport=RecordingTransport(), base_url=_BASE)
    assert egress.allowed_paths == frozenset({COMPLETION_PATH})
    assert COMPLETION_PATH not in CONTROL_PLANE_PATHS


def test_client_surface_has_no_control_plane_method() -> None:
    # the client holds ONLY a completion-only egress; it exposes no environment/agent/tool/session
    # method or field — there is no code path to a control-plane call.
    fields = {f.name for f in dataclasses.fields(ReviewProviderClient)}
    assert fields == {"egress", "provider_id", "model_id", "parse_verdict"}
    surface = {n for n in dir(ReviewProviderClient) if not n.startswith("_")}
    for banned in ("environment", "agent", "tool", "session", "provision", "launch"):
        assert not any(banned in n.lower() for n in surface)


# ---- transmit-only: the client transmits request bytes VERBATIM ----

def test_client_transmits_request_bytes_verbatim() -> None:
    t = RecordingTransport()
    client = _client(t)
    request_bytes = b"CANONICAL-REQUEST-ENVELOPE-BYTES"
    outcome = client(request_bytes, "gpt-y", _PROMPT_HASH)
    # exactly one call, to the completion path, with the EXACT bytes (no re-encode / re-forge)
    assert t.calls == [(_BASE + COMPLETION_PATH, request_bytes)]
    assert outcome.verdict == "approve"
    assert outcome.provider_id == "anthropic" and outcome.model_id == "reviewer-1"
    assert outcome.raw_response == b'{"verdict":"approve"}'


def test_request_changes_verdict_flows_through() -> None:
    t = RecordingTransport(response=b'{"verdict":"request_changes"}')
    outcome = _client(t)(b"req", "gpt-y", _PROMPT_HASH)
    assert outcome.verdict == "request_changes"


# ---- end-to-end: containment holds THROUGH the real client, up to the wire it owns ----

def test_llm_review_through_provider_gate_transmits_the_sealed_source(tmp_path: Path) -> None:
    t = RecordingTransport()
    with _seal(tmp_path) as sealed:
        expected_request = _canonical_review_request(
            canonical_review_source(sealed), "gpt-y", _PROMPT_HASH)
        obs = llm_review_stage(sealed, reviewer_lineage="gpt-y", review_prompt_hash=_PROMPT_HASH,
                               review_client=_client(t))
    # the bytes that crossed the client == the stage-built envelope embedding the sealed source
    assert t.calls == [(_BASE + COMPLETION_PATH, expected_request)]
    # and the receipt binds THOSE bytes (containment through the transmit-only client)
    assert obs.observation["request_digest"] == hashlib.sha256(expected_request).hexdigest()
    assert obs.outcome == "pass"


def test_llm_review_through_provider_gate_cannot_reach_control_plane() -> None:
    # the review egress a stage is handed has NO reachable control-plane path — the property the
    # llm_review stage relies on for the exfil-surface argument.
    egress = CompletionOnlyEgress(transport=RecordingTransport(), base_url=_BASE)
    with pytest.raises(EgressRefused):
        egress.post("/v1/environments", b"exfil")
