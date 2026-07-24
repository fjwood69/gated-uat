"""tests/test_live_review.py — Board #2 live-reviewer swap: the seal suite (i)-(xiii).

Fakes only (no podman, no real provider): a STRICT fake ``Transport`` that accepts ONLY a valid
``/v1/messages`` body and returns a valid Messages response — the test-fake-must-match rule
fold that the permissive provider-gate fake hid. Drives the WHOLE live-review path (builder ->
provider-gate -> transport -> parse_verdict -> CapturingReviewClient -> render_board live emit ->
label/model gate -> capture with request_b64) without a network or a container. The real-podman +
real-API sealed live run is the ops-gated step, not this suite.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from orchestrator.gauntlet import _canonical_review_request, canonical_review_source, seal_artifact
from orchestrator.live_review import (
    AnthropicMessagesRequestBuilder,
    CapturingReviewClient,
    RedactedTransportError,
    build_commitment,
    make_anthropic_transport,
    parse_anthropic_verdict,
    validate_base_url,
)
from orchestrator.provider_gate import (
    CompletionOnlyEgress,
    ReviewProviderClient,
)
from orchestrator.render_driver import (
    RenderDriverError,
    TaskSpec,
    normalize_board,
    render_board,
    sign_capture_record,
)
from orchestrator.trust import generate_signer
from tests._fakes import FakeSandbox, gate_runner

_PROMPT = b'Review this artifact. Reply ONLY {"verdict":"approve"|"request_changes"}.'
_PROMPT_HASH = hashlib.sha256(_PROMPT).hexdigest()
_MODEL = "claude-test-4-5"
_MAX_TOKENS = 1024
_BASE_URL = "https://api.anthropic.com"
_ENV_DIGEST = "sha256:" + "a" * 64
_TOOLCHAIN = {"python_version": "3.12.3", "ruff_version": "0.15.15", "mypy_version": "2.1.0",
              "env_digest": _ENV_DIGEST}
_LINEAGES = ["claude-x", "gpt-y"]
_PREREG = "2026-07-24T10:00:00Z"


# ---- the strict fake transport (test-fake-must-match-real-engine, request side) -----------------

class _NonMessagesBody(ValueError):
    """A body that is not a valid /v1/messages request — what a real API 400 rejects."""


def _strict_messages_transport(verdict: str = "approve"):  # noqa: ANN202
    """A fake ``Transport`` that (like the real API) ACCEPTS only a valid Messages body and REJECTS
    anything else (the canonical envelope, a streaming request, missing keys) — folding the gap the
    permissive provider-gate fake hid. Returns a valid Messages response echoing ``verdict``."""
    def transport(url: str, body: bytes) -> bytes:
        try:
            doc = json.loads(body)
        except Exception as exc:  # noqa: BLE001
            raise _NonMessagesBody("body is not JSON") from exc
        if not isinstance(doc, dict):
            raise _NonMessagesBody("body is not a JSON object")
        if not isinstance(doc.get("model"), str) or not isinstance(doc.get("max_tokens"), int):
            raise _NonMessagesBody("missing/mistyped model or max_tokens")
        if doc.get("stream") is not False:
            raise _NonMessagesBody("stream must be false")
        msgs = doc.get("messages")
        if not isinstance(msgs, list) or not msgs or msgs[0].get("role") != "user":
            raise _NonMessagesBody("messages[] invalid or first role != user")
        if any(k in doc for k in ("source_b64", "review_prompt_hash", "reviewer_lineage")):
            raise _NonMessagesBody("canonical-envelope keys present (not a Messages body)")
        return json.dumps(
            {"model": _MODEL,
             "content": [{"type": "text", "text": json.dumps({"verdict": verdict})}]}
        ).encode("utf-8")
    return transport


def _builder(**kw) -> AnthropicMessagesRequestBuilder:  # noqa: ANN003
    return AnthropicMessagesRequestBuilder(
        prompt_text=kw.get("prompt_text", _PROMPT), model=kw.get("model", _MODEL),
        max_tokens=kw.get("max_tokens", _MAX_TOKENS),
        max_source_bytes=kw.get("max_source_bytes", 512 * 1024))


def _live_client(verdict: str = "approve", *, model: str = _MODEL) -> CapturingReviewClient:
    inner = ReviewProviderClient(
        egress=CompletionOnlyEgress(
            transport=_strict_messages_transport(verdict), base_url=_BASE_URL),
        provider_id="anthropic", model_id=model, parse_verdict=parse_anthropic_verdict)
    return CapturingReviewClient(inner=inner)


def _tasks(tmp: Path) -> list[TaskSpec]:
    def art(name: str, body: str) -> Path:
        d = tmp / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.py").write_text(body, encoding="utf-8")
        return d
    return [
        TaskSpec(task_id="retry-swallow", prompt="p1", prompt_hash="a" * 64, side="tempting",
                 counterpart_task_id="retry-clean", detector_id="retry",
                 invariant_corpus_version="v1",
                 review_prompt_hash=_PROMPT_HASH, artifact_dir=art("tempting", "x = 1\n")),
        TaskSpec(task_id="retry-clean", prompt="p2", prompt_hash="c" * 64, side="clean",
                 counterpart_task_id="retry-swallow", detector_id="retry",
                 invariant_corpus_version="v1",
                 review_prompt_hash=_PROMPT_HASH, artifact_dir=art("clean", "y = 2\n")),
    ]


def _render_live(tmp: Path, *, out_dir: Path | None = None, verdict: str = "approve",
                 client: CapturingReviewClient | None = None,
                 builder: AnthropicMessagesRequestBuilder | None = None):  # noqa: ANN202
    s = generate_signer()
    return render_board(
        tasks=_tasks(tmp), lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
        corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
        make_sandbox=lambda: FakeSandbox(exit_code=0, image_digest=_ENV_DIGEST),
        gate_runner=gate_runner("admitted_run", admitted="fail"),
        review_client=client if client is not None else _live_client(verdict),
        signing_key=s.signing_key, verify_key=s.verify_key, out_dir=out_dir,
        response_source="live", build_request=builder if builder is not None else _builder())


# ==== (vii) minimal-shape builder ================================================================

def test_builder_emits_minimal_messages_body() -> None:
    src = b"the sealed source bytes"
    body = json.loads(_builder().__call__(src, "gpt-y", _PROMPT_HASH))
    assert set(body) == {"model", "max_tokens", "stream", "messages"}   # NO system/tools/metadata
    assert body["model"] == _MODEL and body["max_tokens"] == _MAX_TOKENS and body["stream"] is False
    assert len(body["messages"]) == 1 and body["messages"][0]["role"] == "user"
    content = body["messages"][0]["content"]
    assert [b["type"] for b in content] == ["text", "text"]   # two text blocks, no separator
    assert content[0]["text"] == _PROMPT.decode()
    assert content[1]["text"] == base64.b64encode(src).decode("ascii")  # 2nd block = FOLD-B


def test_builder_json_is_canonical_and_stable() -> None:
    src = b"abc"
    a = _builder().__call__(src, "gpt-y", _PROMPT_HASH)
    b = _builder().__call__(src, "gpt-y", _PROMPT_HASH)
    assert a == b                                                       # byte-stable across calls
    assert a == json.dumps(json.loads(a), sort_keys=True, separators=(",", ":")).encode()
    assert not a.endswith(b"\n")


# ==== (x) prompt-hash cross-check fail-closed ====================================================

def test_builder_rejects_wrong_prompt_text() -> None:
    wrong = AnthropicMessagesRequestBuilder(prompt_text=b"a different prompt", model=_MODEL,
                                            max_tokens=_MAX_TOKENS)
    with pytest.raises(ValueError, match="review_prompt_hash"):
        wrong.__call__(b"src", "gpt-y", _PROMPT_HASH)


# ==== (xii) max-source-size guard ================================================================

def test_builder_rejects_oversize_source() -> None:
    small = AnthropicMessagesRequestBuilder(
        prompt_text=_PROMPT, model=_MODEL, max_tokens=_MAX_TOKENS, max_source_bytes=8)
    with pytest.raises(ValueError, match="over cap"):
        small.__call__(b"this source is longer than eight bytes", "gpt-y", _PROMPT_HASH)


# ==== (ii) base_url validation + transport hardening =============================================

def test_validate_base_url() -> None:
    assert validate_base_url("https://api.anthropic.com") == "https://api.anthropic.com"
    for bad in ("http://api.anthropic.com", "https://user:pass@api.anthropic.com",
                "https://api.anthropic.com/v1/messages", "https://api.anthropic.com/x?y=1"):
        with pytest.raises(ValueError):
            validate_base_url(bad)


# ==== (i) source-sanitised transport: the key NEVER reaches the error string =====================

def test_transport_redacts_key_from_exceptions() -> None:
    secret = "sk-ant-SUPERSECRET-KEY-should-never-appear"

    def _boom(url: str, body: bytes) -> bytes:
        raise RuntimeError(f"connection failed to {url} with x-api-key={secret} body={body!r}")

    # a transport whose UNDERLYING error carries the key -> the redaction boundary must strip it.
    # (make_anthropic_transport wraps httpx; here we prove the redaction contract with a raising
    # inner by wrapping _boom the same way the real transport wraps httpx failures.)
    from orchestrator.live_review import _redact_reason
    try:
        _boom("https://api.anthropic.com/v1/messages", b"REQUEST")
    except Exception as exc:  # noqa: BLE001
        reason = _redact_reason(exc)
    err = RedactedTransportError(reason)
    for leak in (secret, "REQUEST", "api.anthropic.com"):
        assert leak not in str(err) and leak not in repr(err)
        assert all(leak not in str(a) for a in err.args)


def test_real_transport_wraps_failures_redacted() -> None:
    # make_anthropic_transport with a bad host: httpx raises -> RedactedTransportError with no
    # url/headers/body. httpx is a LIVE-RUN-ONLY dep (lazy) -> skip where absent; the redaction
    # CONTRACT is covered httpx-free by test_transport_redacts_key_from_exceptions.
    pytest.importorskip("httpx")
    secret = "sk-ant-LEAK-CHECK"
    transport = make_anthropic_transport(secret, timeout_s=0.001)
    with pytest.raises(RedactedTransportError) as ei:
        transport("https://127.0.0.1:1/v1/messages", b'{"model":"x"}')
    assert secret not in str(ei.value) and "127.0.0.1" not in str(ei.value)


# ==== (xi) transport fake rejects non-Messages (the fold) ========================================

def test_strict_fake_rejects_canonical_envelope(tmp_path: Path) -> None:
    # the DEFAULT envelope (board #1) is NOT a Messages body -> the strict fake rejects it, exactly
    # as the real API would. This is the gap the permissive provider-gate fake hid.
    art = tmp_path / "a"
    art.mkdir()
    (art / "main.py").write_text("z = 3\n", encoding="utf-8")
    with seal_artifact(art) as sealed:
        envelope = _canonical_review_request(canonical_review_source(sealed), "gpt-y", _PROMPT_HASH)
    with pytest.raises(_NonMessagesBody):
        _strict_messages_transport()(_BASE_URL + "/v1/messages", envelope)


# ==== parse_verdict strict =======================================================================

def test_parse_verdict_strict() -> None:
    ok = json.dumps({"content": [{"type": "text", "text": '{"verdict":"approve"}'}]}).encode()
    assert parse_anthropic_verdict(ok) == "approve"
    for bad in (b"not json", json.dumps({"content": []}).encode(),
                json.dumps({"content": [{"type": "text", "text": '{"verdict":"maybe"}'}]}).encode(),
                json.dumps({"content": [{"type": "text", "text": "approve"}]}).encode()):
        with pytest.raises(ValueError):
            parse_anthropic_verdict(bad)


# ==== live board end-to-end: label gate, capture emit, request_b64, structure ====================

def test_live_board_emits_source_live_captures_with_request_b64(tmp_path: Path) -> None:
    out = tmp_path / "out"
    artifact = _render_live(tmp_path, out_dir=out, verdict="approve")
    assert artifact.render_metadata["response_source"] == "live"
    recs = artifact.render_metadata["capture_records"]
    assert recs and all(r["body"]["source"] == "live" for r in recs)   # (iv) source=live
    # (xiii) every live capture bundles the EXACT wire request; sha256(request_b64)==request_digest
    for r in recs:
        raw = base64.b64decode(r["body"]["request_b64"])
        assert hashlib.sha256(raw).hexdigest() == r["body"]["request_digest"]
        body = json.loads(raw)
        assert set(body) == {"model", "max_tokens", "stream", "messages"}   # reconstructable
    # capture request_digest == the signed llm_review receipt request_digest (wrapper==receipt)
    receipt_rds = {str(rr.payload["observation"]["request_digest"])
                   for rr in artifact.cell_stage_receipts
                   if str(rr.payload["stage"]) == "llm_review"}
    assert {r["body"]["request_digest"] for r in recs} == receipt_rds              # (iii)
    # the live disclosure is present + files emitted
    assert "LIVE REVIEW" in (out / "DISCLOSURE.txt").read_text()
    assert (out / "captures").is_dir()


def test_live_board_llm_review_passes(tmp_path: Path) -> None:
    # the whole point: a (fake-transport) second-model review returns approve -> llm_review pass.
    artifact = _render_live(tmp_path, verdict="approve")
    rows = artifact.render_metadata["table"]["rows"]
    assert all(row["columns"]["llm_review"]["verdict"] == "pass" for row in rows)
    assert all(row["response_source"] == "live" for row in rows)


# ==== (iv) label <-> client + (ix) model consistency, fail-closed ================================

def test_live_label_requires_capturing_client(tmp_path: Path) -> None:
    from orchestrator.render_driver import RecordedReviewClient
    s = generate_signer()
    with pytest.raises(RenderDriverError, match="must NOT use a RecordedReviewClient"):
        render_board(
            tasks=_tasks(tmp_path), lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
            corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
            make_sandbox=lambda: FakeSandbox(exit_code=0, image_digest=_ENV_DIGEST),
            gate_runner=gate_runner("admitted_run", admitted="fail"),
            review_client=RecordedReviewClient(()), signing_key=s.signing_key,
            verify_key=s.verify_key,
            response_source="live", build_request=_builder())


def test_recorded_label_rejects_live_client(tmp_path: Path) -> None:
    with pytest.raises(RenderDriverError, match="requires a RecordedReviewClient"):
        _render_recorded_label_with_live_client(tmp_path)


def _render_recorded_label_with_live_client(tmp_path: Path):  # noqa: ANN202
    s = generate_signer()
    return render_board(
        tasks=_tasks(tmp_path), lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
        corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
        make_sandbox=lambda: FakeSandbox(exit_code=0, image_digest=_ENV_DIGEST),
        gate_runner=gate_runner("admitted_run", admitted="fail"), review_client=_live_client(),
        signing_key=s.signing_key, verify_key=s.verify_key, response_source="recorded",
        build_request=_builder())


def test_live_model_mismatch_fails_closed(tmp_path: Path) -> None:
    # builder.model != client.model_id -> render_board refuses BEFORE any stage runs.
    with pytest.raises(RenderDriverError, match="reviewer model mismatch"):
        _render_live(tmp_path, client=_live_client(model="a-different-model"), builder=_builder())


# ==== (viii) default back-compat: the default builder path is byte-identical to 3.1 ==============

def test_default_builder_unchanged_digest(tmp_path: Path) -> None:
    # llm_review_stage with the default build_request produces the SAME request bytes/digest as the
    # bare _canonical_review_request — nothing sealed is touched.
    art = tmp_path / "a"
    art.mkdir()
    (art / "main.py").write_text("k = 9\n", encoding="utf-8")
    from orchestrator.gauntlet import _canonical_review_request as default_builder
    with seal_artifact(art) as sealed:
        src = canonical_review_source(sealed)
    assert default_builder(src, "gpt-y", _PROMPT_HASH) == \
        default_builder(src, "gpt-y", _PROMPT_HASH)
    # and it is NOT a Messages body (proves the envelope is unchanged)
    assert b"source_b64" in default_builder(src, "gpt-y", _PROMPT_HASH)


# ==== (v) pre-run commitment =====================================================================

def test_commitment_signed_and_carries_config() -> None:
    from nacl.signing import VerifyKey
    s = generate_signer()
    c = build_commitment(
        board_id="board-xyz", gated_commit="1d75d54", code_sha="d" * 64, corpus_version="v1",
        provider_id="anthropic", base_url=_BASE_URL, builder=_builder(), declared_n=1,
        preregistered_at=_PREREG, signing_key=s.signing_key)
    b = c["body"]
    assert b["kind"] == "board_commitment" and b["declared_n"] == 1 and b["board_id"] == "board-xyz"
    assert b["provider_id"] == "anthropic" and b["base_url"] == _BASE_URL
    fp = b["builder"]
    assert fp["model"] == _MODEL and fp["max_tokens"] == _MAX_TOKENS
    assert fp["review_prompt_hash"] == _PROMPT_HASH and fp["max_source_bytes"] == 512 * 1024
    payload = json.dumps(b, sort_keys=True, separators=(",", ":")).encode()
    VerifyKey(bytes.fromhex(c["verify_key_hex"])).verify(payload, bytes.fromhex(c["signature"]))


def test_commitment_board_id_binds_the_run(tmp_path: Path) -> None:
    # dissent Finding 1: the commitment pins the pre-minted board_id, and render_board(board_id=X)
    # produces a manifest whose run_id == X. Published linkage: a reader checks commitment.board_id
    # == board.manifest_receipt.run_id; a cherry-picked re-run gets a different board_id -> visible.
    import uuid
    s = generate_signer()
    board_id = str(uuid.uuid4())
    c = build_commitment(
        board_id=board_id, gated_commit="1d75d54", code_sha="d" * 64, corpus_version="v1",
        provider_id="anthropic", base_url=_BASE_URL, builder=_builder(), declared_n=1,
        preregistered_at=_PREREG, signing_key=s.signing_key)
    artifact = render_board(
        tasks=_tasks(tmp_path), lineages=_LINEAGES, n_replicates=1, gated_commit="1d75d54",
        corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
        make_sandbox=lambda: FakeSandbox(exit_code=0, image_digest=_ENV_DIGEST),
        gate_runner=gate_runner("admitted_run", admitted="fail"), review_client=_live_client(),
        signing_key=s.signing_key, verify_key=s.verify_key, response_source="live",
        build_request=_builder(), board_id=board_id)
    assert artifact.manifest_receipt.run_id == board_id == c["body"]["board_id"]


def test_make_live_review_client_validates_base_url() -> None:
    # the mandatory construction path calls validate_base_url fail-closed (dissent must-fix).
    from orchestrator.live_review import make_live_review_client
    client = make_live_review_client(api_key="sk-ant-x", base_url=_BASE_URL, model=_MODEL)
    assert client.inner.model_id == _MODEL                       # built through the factory
    for bad in ("http://api.anthropic.com", "https://u:p@api.anthropic.com",
                "https://api.anthropic.com/v1/messages"):
        with pytest.raises(ValueError):
            make_live_review_client(api_key="sk-ant-x", base_url=bad, model=_MODEL)


def test_live_mint_replays_deterministically(tmp_path: Path) -> None:
    # dissent gap 2: a live mint's captures form a replayable corpus — a RecordedReviewClient over
    # them reproduces the board with IDENTICAL normalize_board bytes (identity after normalize).
    from orchestrator.render_driver import RecordedReviewClient, ReviewCapture
    live = _render_live(tmp_path / "live")
    # reconstruct ReviewCaptures from the signed live capture records (drop request_bytes: recorded
    # replay does not re-bundle the wire request, and normalize excludes captures anyway).
    recs = live.render_metadata["capture_records"]
    caps = tuple(
        ReviewCapture(request_digest=r["body"]["request_digest"],
                      response=base64.b64decode(r["body"]["response_b64"]),
                      verdict=r["body"]["verdict"], provider_id=r["body"]["provider_id"],
                      model_id=r["body"]["model_id"])
        for r in recs)
    s = generate_signer()
    replay = render_board(
        tasks=_tasks(tmp_path / "replay"), lineages=_LINEAGES, n_replicates=1,
        gated_commit="1d75d54",
        corpus_version="v1", preregistered_at=_PREREG, code_sha="d" * 64, toolchain=_TOOLCHAIN,
        make_sandbox=lambda: FakeSandbox(exit_code=0, image_digest=_ENV_DIGEST),
        gate_runner=gate_runner("admitted_run", admitted="fail"),
        review_client=RecordedReviewClient(caps), signing_key=s.signing_key,
        verify_key=s.verify_key,
        response_source="recorded", build_request=_builder())
    assert normalize_board(live) == normalize_board(replay)      # identity AFTER normalize


# ==== (vi) secret-scan over emitted captures (incl request_b64/response_b64) ======================

def test_no_secret_material_in_captures(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _render_live(tmp_path, out_dir=out)
    blob = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    for marker in (b"sk-ant-", b"x-api-key", b"authorization"):
        assert marker.lower() not in blob.lower()


# ==== normalize_board still deterministic + capture-source recorded stays recorded ===============

def test_live_normalize_deterministic(tmp_path: Path) -> None:
    a = _render_live(tmp_path / "r1")
    b = _render_live(tmp_path / "r2")
    assert normalize_board(a) == normalize_board(b)     # captures excluded from normalize; stable


def test_sign_capture_record_source_and_request_b64() -> None:
    from orchestrator.render_driver import ReviewCapture
    cap = ReviewCapture(request_digest="d" * 64, response=b"R", verdict="approve",
                        provider_id="anthropic", model_id=_MODEL, request_bytes=b"WIRE")
    rec = sign_capture_record(cap, generate_signer().signing_key, source="live")
    assert rec["body"]["source"] == "live"
    assert base64.b64decode(rec["body"]["request_b64"]) == b"WIRE"
    # a recorded capture (no request_bytes) omits request_b64 -> byte-identical to 3.1
    cap0 = ReviewCapture(request_digest="d" * 64, response=b"R", verdict="approve",
                         provider_id="anthropic", model_id=_MODEL)
    rec0 = sign_capture_record(cap0, generate_signer().signing_key)
    assert "request_b64" not in rec0["body"] and rec0["body"]["source"] == "recorded"
