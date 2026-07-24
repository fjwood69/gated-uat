"""orchestrator/live_review.py — Board #2 live-reviewer plumbing (additive; provider-gate intact).

Everything the LIVE review swap needs that the recorded path did not, gathered here so the sealed
components stay sealed:

  * ``make_anthropic_transport`` — a hardened host-side httpx ``Transport`` for the egress.
    Header-only key; no redirects / no proxy / no env-trust; EVERY failure becomes a
    ``RedactedTransportError`` whose str/repr/args carry ONLY a class-level reason — so the api key
    (or url / headers / body) can never reach a signed ``harness_error`` observation (consult P1).
  * ``AnthropicMessagesRequestBuilder`` — the ratified (C) delta: emits a REAL ``/v1/messages`` body
    (content blocks) so the provider-gate transmits a valid, reviewable request VERBATIM. The
    default review request (``gauntlet._canonical_review_request``) is a gated-uat envelope, NOT an
    API body — swapping to live forced this additive builder (§1 stop finding). 3.1 digests are
    untouched because the default builder stays the bare envelope function.
  * ``parse_anthropic_verdict`` — a STRICT ``VerdictParser`` (approve | request_changes only).
  * ``CapturingReviewClient`` — wraps the live client and mints a replayable capture corpus
    (source='live'), recording the EXACT request bytes so ``request_digest`` == the receipt's by
    construction and the wire body is reconstructable from the capture (out-of-band structure
    attestation — no receipt-schema change).

The provider-gate (transmit-only egress) and the cell_stage receipt schema are UNCHANGED.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .gauntlet import ReviewClient, ReviewOutcome
from .provider_gate import CompletionOnlyEgress, ReviewProviderClient, Transport
from .render_driver import ReviewCapture

# The Anthropic Messages API version header the transport pins (a header, never in the body).
ANTHROPIC_VERSION = "2023-06-01"
# Sealed-source cap: base64 inflates ~+33%; a huge artifact would blow the context/body limit and
# yield a runtime rejection instead of a verdict (consult P3.11). Fail-closed above this.
_MAX_SOURCE_BYTES_DEFAULT = 512 * 1024


# ------------------------------------------------------------------
# Hardened transport (host-side; the ONLY new egress code)
# ------------------------------------------------------------------


class RedactedTransportError(RuntimeError):
    """A provider-transport failure with ALL sensitive material redacted. The originating exception
    (which may carry the api key, url, request/response bodies) is NEVER chained (``from None``) nor
    stringified — only a stable class-level reason survives, so this is SAFE to bake into a signed
    ``harness_error`` observation (consult P1: the key can never leak into a published receipt)."""


def validate_base_url(base_url: str) -> str:
    """Fail-closed validation (consult P1): HTTPS, no userinfo (no ``https://user:pass@…``), no path
    (the completion path is appended by the egress), no query/fragment. Returns it unchanged."""
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise ValueError("base_url must be https")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValueError("base_url must not contain userinfo")
    if parts.path.rstrip("/"):
        raise ValueError("base_url must have no path (the completion path is appended)")
    if parts.query or parts.fragment:
        raise ValueError("base_url must have no query or fragment")
    return base_url


def _redact_reason(exc: Exception) -> str:
    """A stable, NON-sensitive reason for a transport failure — class name + (if present) an HTTP
    status code. NEVER includes ``str(exc)`` / ``exc.args`` (which may carry the request, url, or
    key). This is the only string that survives the redaction boundary."""
    name = type(exc).__name__
    status = getattr(getattr(exc, "response", None), "status_code", None)
    tail = f" (status {status})" if status is not None else ""
    return f"provider transport failed: {name}{tail}"


def make_anthropic_transport(api_key: str, *, timeout_s: float = 60.0) -> Transport:
    """A hardened host-side ``Transport`` (url, body) -> response_bytes for the live review egress.
    ``x-api-key`` goes in a HEADER only (never url/query/body). ``httpx`` is imported LAZILY so the
    module + the fake-transport tests need no live dependency. Redaction is belt-and-braces with the
    post-hoc out_dir credential scan — but source sanitisation is the load-bearing guard: the raw
    exception (which may carry the key) is dropped at this boundary and NEVER reaches the caller."""
    key = api_key.strip()  # get-secret.sh may append a trailing newline

    def transport(url: str, body: bytes) -> bytes:
        import httpx  # lazy: only the sealed live run needs it; tests inject a fake transport

        headers = {
            "x-api-key": key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        try:
            with httpx.Client(follow_redirects=False, trust_env=False, proxy=None,
                              timeout=timeout_s) as client:
                resp = client.post(url, content=body, headers=headers)
                resp.raise_for_status()
                return bytes(resp.content)
        except Exception as exc:  # noqa: BLE001 — redact EVERYTHING; never leak url/headers/body/key
            raise RedactedTransportError(_redact_reason(exc)) from None

    return transport


# ------------------------------------------------------------------
# (C) The Board #2 request builder — a REAL /v1/messages body
# ------------------------------------------------------------------


@dataclass(frozen=True)
class AnthropicMessagesRequestBuilder:
    """The ratified (C) Board #2 ``ReviewRequestBuilder``: emits a REAL ``/v1/messages`` body so the
    transmit-only provider-gate sends a valid, reviewable request VERBATIM.

    Shape (MINIMAL — no system / tools / metadata / extra messages; enforced by test): one ``user``
    message with TWO content blocks — (1) the published prompt TEXT, (2) the sealed review source as
    base64. The 2nd block is ``base64(source_bytes)`` == the exact bytes gauntlet seals (FOLD-B),
    so an auditor can recompute ``source_digest`` / tree correspondence from ``request_b64`` (stored
    in the live capture) with NO receipt-schema change.

    Two distinct byte-objects, two distinct checks (P2.7): the receipt's ``review_prompt_hash``
    is ``sha256`` of the RAW UTF-8 ``prompt_text``; the wire body carries ``prompt_text.decode()``
    re-serialised with ``ensure_ascii=True`` (so non-ASCII appears as ``\\uXXXX`` escapes in
    ``request_bytes``). Do NOT "verify the prompt" by grepping the body — check the hash.
    ``request_digest = sha256(request_bytes)`` binds the WHOLE body; the JSON is frozen-canonical so
    it is byte-stable across runs (wrapper digest == receipt digest; replay after normalize)."""

    prompt_text: bytes          # raw published prompt; sha256(prompt_text) == review_prompt_hash
    model: str
    max_tokens: int
    max_source_bytes: int = _MAX_SOURCE_BYTES_DEFAULT

    def __call__(
        self, source_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
    ) -> bytes:
        if hashlib.sha256(self.prompt_text).hexdigest() != review_prompt_hash:
            raise ValueError(
                "prompt_text does not match review_prompt_hash (prereg binding)")
        if len(source_bytes) > self.max_source_bytes:
            raise ValueError(
                f"sealed source {len(source_bytes)}B over cap {self.max_source_bytes}B")
        prompt_str = self.prompt_text.decode("utf-8", errors="strict")  # raise, never mojibake
        source_b64 = base64.b64encode(source_bytes).decode("ascii")
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "stream": False,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": prompt_str},
                {"type": "text", "text": source_b64},
            ]}],
        }
        return json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def fingerprint(self) -> dict[str, Any]:
        """The builder identity bound into the light board commitment (consult P3.13) — so the
        published body shape is attested out-of-band. NEVER includes prompt_text (only its hash)."""
        return {
            "builder": "AnthropicMessagesRequestBuilder",
            "model": self.model,
            "max_tokens": self.max_tokens,
            "review_prompt_hash": hashlib.sha256(self.prompt_text).hexdigest(),
            "max_source_bytes": self.max_source_bytes,
            "serializer": "json:sort_keys,sep=(,:),ensure_ascii,utf-8,no-trailing-newline",
        }


# ------------------------------------------------------------------
# Strict verdict parser
# ------------------------------------------------------------------


def parse_anthropic_verdict(response: bytes) -> str:
    """STRICT ``VerdictParser``: parse the Anthropic Messages response, take the model's first text
    block, and read a structured verdict of EXACTLY 'approve' | 'request_changes'. Rejects
    streamed/truncated/malformed bodies (consult P3.10). The published review prompt instructs the
    model to reply with ``{"verdict": "approve" | "request_changes"}`` as its text."""
    try:
        doc = json.loads(response)
    except Exception:  # noqa: BLE001
        raise ValueError("review response is not valid JSON (streamed or truncated?)") from None
    if not isinstance(doc, dict):
        raise ValueError("review response is not a JSON object")
    if doc.get("stop_reason") == "max_tokens":
        raise ValueError("review response truncated (stop_reason=max_tokens) — raise max_tokens")
    content = doc.get("content")
    if not isinstance(content, list) or not content:
        raise ValueError("review response has no content blocks")
    text: str | None = None
    for block in content:
        if (isinstance(block, dict) and block.get("type") == "text"
                and isinstance(block.get("text"), str)):
            text = block["text"]
            break
    if text is None:
        raise ValueError("review response has no text block")
    try:
        verdict_doc = json.loads(text.strip())
        verdict = verdict_doc.get("verdict") if isinstance(verdict_doc, dict) else None
    except Exception:  # noqa: BLE001
        verdict = None
    if verdict not in ("approve", "request_changes"):
        raise ValueError(f"review verdict not in approve|request_changes: {verdict!r}")
    return str(verdict)


# ------------------------------------------------------------------
# Capturing client — mints the replayable live corpus
# ------------------------------------------------------------------


@dataclass(frozen=True)
class CapturingReviewClient:
    """Wraps a LIVE ``ReviewClient`` (ReviewProviderClient) and, on each successful call, records
    the EXACT (request_bytes, response) as a ``ReviewCapture`` into ``sink`` (source='live' when
    emitted). ``request_digest = sha256(request_bytes)`` == the receipt's ``request_digest``
    by construction, and ``request_bytes`` is stored so the wire body is reconstructable from the
    capture. Records EXACTLY ONCE per call and NEVER retries (consult §5): a raising inner client
    appends nothing and the cell terminates as a signed ERROR upstream — no double-mint, no phantom
    capture."""

    inner: ReviewClient
    sink: list[ReviewCapture] = field(default_factory=list)

    def __call__(
        self, request_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
    ) -> ReviewOutcome:
        outcome = self.inner(request_bytes, reviewer_lineage, review_prompt_hash)
        self.sink.append(ReviewCapture(
            request_digest=hashlib.sha256(request_bytes).hexdigest(),
            response=outcome.raw_response, verdict=outcome.verdict,
            provider_id=outcome.provider_id, model_id=outcome.model_id,
            request_bytes=request_bytes))
        return outcome


# ------------------------------------------------------------------
# The mandatory construction path (the ONLY place base_url is validated)
# ------------------------------------------------------------------


def make_live_review_client(
    *, api_key: str, base_url: str, model: str, provider_id: str = "anthropic",
    timeout_s: float = 60.0,
) -> CapturingReviewClient:
    """THE construction path for a live board #2 client — the ONLY place ``base_url`` is validated
    (dissent must-fix: ``validate_base_url`` was tested but never called on the path). Builds the
    hardened redacting transport + completion-only egress + provider client + capturing wrapper,
    fail-closed on a bad base_url. The sealed live run MUST build its client here — a hand-rolled
    egress with an unvalidated base_url or a non-redacting transport is OUT of seal."""
    validate_base_url(base_url)
    egress = CompletionOnlyEgress(
        transport=make_anthropic_transport(api_key, timeout_s=timeout_s), base_url=base_url)
    inner = ReviewProviderClient(
        egress=egress, provider_id=provider_id, model_id=model,
        parse_verdict=parse_anthropic_verdict)
    return CapturingReviewClient(inner=inner)


# ------------------------------------------------------------------
# The light pre-run board commitment (gaming guard)
# ------------------------------------------------------------------


def build_commitment(
    *, board_id: str, gated_commit: str, code_sha: str, corpus_version: str, provider_id: str,
    base_url: str, builder: AnthropicMessagesRequestBuilder, declared_n: int, preregistered_at: str,
    signing_key: Any,
) -> dict[str, Any]:
    """The LIGHT pre-run board commitment — PUBLISHED before the first live call. It pins the
    pre-minted ``board_id`` (dissent Finding 1: config alone is shared by every re-run, so the
    commitment MUST name the exact board it commits to) plus the live INTENT (provider/model + url
    via the builder fingerprint, declared-n, code/corpus), before any outcome is seen. Signed with
    the render key. THE LINKAGE THAT IS THE SEAL: a reader verifies commitment ``board_id`` ==
    published board's manifest ``board_id`` (== manifest_receipt.run_id); each run mints a FRESH
    board_id needing a FRESH published commitment, so a cherry-picked re-run leaves a published
    commitment with no matching board (or a board with no commitment) — the discard is VISIBLE.
    ``builder.fingerprint()`` carries the model, max_tokens, max_source_bytes + prompt hash."""
    body = {
        "kind": "board_commitment",
        "board_id": board_id,
        "declared_n": declared_n,
        "gated_commit": gated_commit,
        "code_sha": code_sha,
        "corpus_version": corpus_version,
        "provider_id": provider_id,
        "base_url": base_url,
        "preregistered_at": preregistered_at,
        "builder": builder.fingerprint(),
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signing_key.sign(payload).signature.hex()
    return {"body": body, "signature": signature,
            "verify_key_hex": signing_key.verify_key.encode().hex()}


__all__ = [
    "ANTHROPIC_VERSION", "AnthropicMessagesRequestBuilder", "CapturingReviewClient",
    "RedactedTransportError", "build_commitment", "make_anthropic_transport",
    "make_live_review_client", "parse_anthropic_verdict", "validate_base_url",
]
