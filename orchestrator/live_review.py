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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .gauntlet import ReviewClient, ReviewOutcome, build_review_source_payload
from .provider_gate import CompletionOnlyEgress, ReviewProviderClient, Transport
from .render_driver import BoardArtifact, ReviewCapture

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
# (Y) Board #3 — the REVIEWABLE wire: decoded file text, thin envelope-recompute
# ------------------------------------------------------------------

_REVIEW_SOURCE_DOMAIN = "gated-uat.review-source"
# The strict top-level whitelist for a reviewable /v1/messages body (consult P2): a body may carry
# EXACTLY these keys — so no system / tools / tool_choice / stop_sequences / temperature / a 2nd
# message / an assistant prefill can smuggle model-visible content the source_digest recompute would
# ignore. Enforced on OUR OWN emitted bytes, in BOTH the builder self-parse and the auditor.
_REVIEWABLE_TOP_KEYS = frozenset({"model", "max_tokens", "stream", "messages"})


class ReviewableWireError(ValueError):
    """The reviewable wire (or the canonical source it is built from) is malformed — a shape, count,
    whitelist, encoding, or reconstruction failure. Fail-closed: the builder raises before returning
    a wire, and the auditor raises before admitting a reconstruction."""


def _files_from_canonical_source(source_bytes: bytes) -> list[tuple[str, bytes]]:
    """Invert ``canonical_review_source``: read its versioned, domain-separated envelope and return
    the ordered ``(relpath, content_bytes)`` pairs. ``path_b64`` -> relpath is ``utf-8`` strict
    (fail-closed on a non-utf-8 path — no parallel encoding); each per-file ``sha256`` is verified
    against its ``content_b64`` (the envelope we were handed is internally consistent)."""
    try:
        doc = json.loads(source_bytes)
    except Exception:  # noqa: BLE001
        raise ReviewableWireError("canonical review source is not valid JSON") from None
    if not isinstance(doc, dict) or doc.get("domain") != _REVIEW_SOURCE_DOMAIN:
        raise ReviewableWireError("canonical review source has the wrong domain")
    if doc.get("version") != 1:  # dissent P3 nit: a future serializer v2 must fail loudly
        raise ReviewableWireError(f"unexpected review-source version {doc.get('version')!r}")
    payload = doc.get("payload")
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise ReviewableWireError("canonical review source payload is malformed")
    out: list[tuple[str, bytes]] = []
    for entry in payload["files"]:
        if not isinstance(entry, dict):
            raise ReviewableWireError("canonical review source file entry is not an object")
        try:
            relpath = base64.b64decode(entry["path_b64"], validate=True).decode(
                "utf-8", errors="strict")
            content = base64.b64decode(entry["content_b64"], validate=True)
        except Exception:  # noqa: BLE001
            raise ReviewableWireError("canonical review source file is not decodable") from None
        if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
            raise ReviewableWireError("canonical review source per-file sha256 mismatch")
        out.append((relpath, content))
    return out


def _strict_text_blocks(content: Any) -> list[str]:
    """Whitelist the user-message ``content`` (consult P2): a list of >= 3 blocks, each EXACTLY
    ``{"type":"text","text":<str>}`` with NO extra keys. Returns the ordered block texts."""
    if not isinstance(content, list) or len(content) < 3:
        raise ReviewableWireError("content must be [prompt, pathlist, >=1 file] text blocks")
    texts: list[str] = []
    for blk in content:
        if (not isinstance(blk, dict) or set(blk) != {"type", "text"}
                or blk.get("type") != "text" or not isinstance(blk.get("text"), str)):
            raise ReviewableWireError("every content block must be exactly {type:text, text:str}")
        texts.append(blk["text"])
    return texts


@dataclass(frozen=True)
class ReviewableWire:
    """A parsed, whitelist-checked reviewable wire: the prompt bytes shown to the model, the ordered
    relpaths (block 1), the ordered ``(relpath, content_bytes)`` file blocks, and the recomputed
    ``source_digest`` (via the SEALED serializer). Produced by ``parse_reviewable_wire`` — used by
    the builder self-parse, the seal tests, and any external auditor."""

    prompt_text: bytes
    model: str
    max_tokens: int
    relpaths: tuple[str, ...]
    files: tuple[tuple[str, bytes], ...]
    source_digest: str


def parse_reviewable_wire(request_bytes: bytes) -> ReviewableWire:
    """Parse + STRICT-whitelist a Board #3 reviewable wire and recompute its ``source_digest`` by
    REPLAYING the sealed ``build_review_source_payload`` (P3 Option A — no reimplementation).

    Whitelist (consult P2, fail-closed): top-level keys are EXACTLY
    ``{model, max_tokens, stream, messages}``; ``stream`` is ``False``; ``messages`` is EXACTLY one
    ``{role, content}`` with ``role=='user'``; ``content`` is text blocks only, each EXACTLY
    ``{type:text, text:str}``. No ``system`` / tools / stop_sequences / 2nd message / assistant
    prefill / unknown key can carry model-visible content the recompute would miss. Then block 0 =
    the prompt; block 1 = a JSON array of N relpaths; blocks 2..N+1 = the decoded file text,
    count-aligned. The CALLER binds ``sha256(prompt_text)==review_prompt_hash`` and
    ``source_digest==receipt.source_digest`` (see ``assert_reviewable_wire``)."""
    try:
        body = json.loads(request_bytes)
    except Exception:  # noqa: BLE001
        raise ReviewableWireError("wire is not valid JSON") from None
    if not isinstance(body, dict) or set(body) != set(_REVIEWABLE_TOP_KEYS):
        raise ReviewableWireError(
            f"wire top-level keys must be exactly {sorted(_REVIEWABLE_TOP_KEYS)}")
    if body.get("stream") is not False:
        raise ReviewableWireError("wire stream must be false")
    model = body["model"]
    max_tokens = body["max_tokens"]
    if (not isinstance(model, str) or isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)):
        raise ReviewableWireError("wire model/max_tokens mistyped")
    messages = body["messages"]
    if not isinstance(messages, list) or len(messages) != 1:
        raise ReviewableWireError("wire must carry exactly one message")
    msg = messages[0]
    if not isinstance(msg, dict) or set(msg) != {"role", "content"} or msg.get("role") != "user":
        raise ReviewableWireError("the one message must be exactly {role:'user', content:[...]}")
    texts = _strict_text_blocks(msg["content"])
    try:
        relpaths = json.loads(texts[1])
    except Exception:  # noqa: BLE001
        raise ReviewableWireError("path-list block is not valid JSON") from None
    if not isinstance(relpaths, list) or not all(isinstance(p, str) for p in relpaths):
        raise ReviewableWireError("path-list must be a JSON array of strings")
    if len(set(relpaths)) != len(relpaths):
        raise ReviewableWireError("duplicate relpath in path-list")  # consult P6
    file_texts = texts[2:]
    if len(file_texts) != len(relpaths):
        raise ReviewableWireError(
            f"file-block count {len(file_texts)} != path count {len(relpaths)}")
    files = tuple((relpaths[i], file_texts[i].encode("utf-8")) for i in range(len(relpaths)))
    source_bytes = build_review_source_payload(list(files))
    return ReviewableWire(
        prompt_text=texts[0].encode("utf-8"), model=model, max_tokens=max_tokens,
        relpaths=tuple(relpaths), files=files,
        source_digest=hashlib.sha256(source_bytes).hexdigest())


def assert_reviewable_wire(
    request_bytes: bytes, *, review_prompt_hash: str, source_digest: str,
    model: str, max_tokens: int,
) -> ReviewableWire:
    """Full external-auditor check: parse + whitelist, then bind the transmitted prompt to the
    committed ``review_prompt_hash``, the recomputed source to the receipt's ``source_digest``, AND
    the ``model`` / ``max_tokens`` to the pre-mint commitment fingerprint (consult P5 — a deviant
    model/max_tokens must not pass merely because shape + source_digest do). Fail-closed on any
    mismatch."""
    wire = parse_reviewable_wire(request_bytes)
    if hashlib.sha256(wire.prompt_text).hexdigest() != review_prompt_hash:
        raise ReviewableWireError("wire prompt does not match committed review_prompt_hash")
    if wire.source_digest != source_digest:
        raise ReviewableWireError("wire source reconstruction != receipt source_digest")
    if wire.model != model or wire.max_tokens != max_tokens:
        raise ReviewableWireError("wire model/max_tokens != committed fingerprint")
    return wire


@dataclass(frozen=True)
class AnthropicReviewableRequestBuilder:
    """Board #3 (Y) ``ReviewRequestBuilder`` — the REVIEWABLE wire. Emits a minimal ``/v1/messages``
    body whose one ``user`` message is EXACTLY: block 0 = the byte-exact published ``prompt_text``;
    block 1 = a JSON array of the file relpaths in canonical order; blocks 2..N+1 = the DECODED
    UTF-8 file text, one block per file. The model reads literal source; the auditor recomputes
    ``source_digest`` by REPLAYING the sealed ``build_review_source_payload`` over the extracted
    ``(relpath, content)`` — no base64 blob, no Merkle, no NFC. ``request_digest = sha256(wire)``
    binds the WHOLE body; the strict top-level + block whitelist (consult P2) means no hidden
    model-visible channel escapes the recompute.

    Fail-closed: a non-utf-8 file (or relpath) raises (it cannot be shown as text); the builder then
    SELF-PARSES the wire it built (consult P3) and asserts the recompute == the sealed
    ``source_digest`` + the whitelist, before returning — a framing bug can never pass the builder
    yet break the auditor.

    NOT injection-safe (consult P1): a sealed file whose text instructs the reviewer can steer the
    verdict. The receipt attests the request/response BINDING, not verdict correctness; the GATE
    column (the independent detector) is the enforcement signal, and the rehearsal gate is a
    LIVENESS/shape check, never a correctness check."""

    prompt_text: bytes
    model: str
    max_tokens: int
    max_source_bytes: int = _MAX_SOURCE_BYTES_DEFAULT

    def __call__(
        self, source_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
    ) -> bytes:
        if hashlib.sha256(self.prompt_text).hexdigest() != review_prompt_hash:
            raise ReviewableWireError(
                "prompt_text does not match review_prompt_hash (prereg binding)")
        if len(source_bytes) > self.max_source_bytes:
            raise ReviewableWireError(
                f"sealed source {len(source_bytes)}B over cap {self.max_source_bytes}B")
        files = _files_from_canonical_source(source_bytes)
        prompt_str = self.prompt_text.decode("utf-8", errors="strict")
        relpaths = [rel for rel, _ in files]
        # strict utf-8 decode per file — fail-closed on non-utf-8 content (cannot be shown as text)
        file_texts = [content.decode("utf-8", errors="strict") for _, content in files]
        content_blocks: list[dict[str, str]] = [{"type": "text", "text": prompt_str}]
        content_blocks.append({"type": "text", "text": json.dumps(
            relpaths, separators=(",", ":"), ensure_ascii=True)})
        content_blocks.extend({"type": "text", "text": t} for t in file_texts)
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "stream": False,
            "messages": [{"role": "user", "content": content_blocks}],
        }
        wire = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        # SELF-PARSE (consult P3): the wire we built must whitelist-parse AND recompute the SAME
        # source_digest as the sealed serializer over these bytes — else fail closed before return.
        parsed = parse_reviewable_wire(wire)
        if parsed.source_digest != hashlib.sha256(source_bytes).hexdigest():
            raise ReviewableWireError("builder self-parse: source_digest mismatch")
        if parsed.prompt_text != self.prompt_text:
            raise ReviewableWireError("builder self-parse: prompt mismatch")
        if parsed.model != self.model or parsed.max_tokens != self.max_tokens:  # consult P5
            raise ReviewableWireError("builder self-parse: model/max_tokens mismatch")
        return wire

    def fingerprint(self) -> dict[str, Any]:
        """The builder identity bound into the pre-run commitment. NEVER includes prompt_text (only
        its hash). The serializer id names the reviewable (Y) shape so a reader can distinguish it
        from the (C) base64 builder."""
        return {
            "builder": "AnthropicReviewableRequestBuilder",
            "model": self.model,
            "max_tokens": self.max_tokens,
            "review_prompt_hash": hashlib.sha256(self.prompt_text).hexdigest(),
            "max_source_bytes": self.max_source_bytes,
            "serializer": "json:sort_keys,sep=(,:),ensure_ascii,utf-8,reviewable-v1",
        }


# ------------------------------------------------------------------
# Rehearsal gate (LIVENESS/shape ONLY — never correctness; consult P1)
# ------------------------------------------------------------------


@dataclass(frozen=True)
class RehearsalRecord:
    """The disclosed pre-mint rehearsal outcome (the three-strikes law): ONE unsealed transmission
    of the committed wire SHAPE — same prompt, a throwaway prompt-irrelevant fixture — to the real
    endpoint, proving the counterpart ENGAGES the shape (returns a parseable verdict) before the
    seal is spent. LIVENESS/shape ONLY, never a correctness check (consult P1: the verdict is
    unauthenticated + injection-vulnerable; the gate column is enforcement). ``disclosed`` is always
    True (written into the run record); ``engaged`` is False on a refusal / transport failure — the
    mint MUST NOT proceed on ``engaged=False``. NOT part of n."""

    disclosed: bool
    engaged: bool
    provider_id: str
    model_id: str
    note: str


def rehearse_reviewable_shape(
    *, review_client: ReviewClient, builder: AnthropicReviewableRequestBuilder,
    throwaway_source_bytes: bytes, reviewer_lineage: str = "rehearsal",
) -> RehearsalRecord:
    """Transmit the committed wire SHAPE once, over a throwaway prompt-irrelevant fixture, to prove
    the counterpart engages it (consult P1: LIVENESS only). Uses the builder's own prompt hash so
    the shape is identical to the sealed run. ``engaged`` = the client returned a parseable verdict;
    a
    refusal / transport failure is a caught, DISCLOSED non-engagement. Test-fake-must-match-real-
    engine extension: in a test only the TRANSPORT may be faked, never the counterpart's content
    acceptance."""
    review_prompt_hash = hashlib.sha256(builder.prompt_text).hexdigest()
    request_bytes = builder(throwaway_source_bytes, reviewer_lineage, review_prompt_hash)
    try:
        outcome = review_client(request_bytes, reviewer_lineage, review_prompt_hash)
    except Exception as exc:  # noqa: BLE001 — a refusal / transport error is disclosed non-engagement
        return RehearsalRecord(disclosed=True, engaged=False, provider_id="", model_id="",
                               note=f"non-engagement: {type(exc).__name__}")
    return RehearsalRecord(disclosed=True, engaged=True, provider_id=outcome.provider_id,
                           model_id=outcome.model_id, note=f"verdict={outcome.verdict}")


# ------------------------------------------------------------------
# The HARD pre-mint gate (dissent P2-1: a declared control nothing consumes is not a control)
# ------------------------------------------------------------------


class RehearsalGateError(RuntimeError):
    """The pre-mint rehearsal gate refused: no disclosed+engaged rehearsal, or the rehearsal fixture
    was not disjoint from the demonstration pair. A live reviewable mint MUST NOT proceed."""


def assert_rehearsal_admits(rehearsal: RehearsalRecord | None) -> None:
    """The HARD pre-mint gate (dissent P2-1): a live reviewable mint may proceed ONLY behind a
    DISCLOSED rehearsal that ENGAGED. Absent or non-engaged -> raise — never a skippable library
    call. RUN-RECORD LAW (D2): the rehearsal is transmitted BEFORE the commitment is published; its
    fixture is DISJOINT from the demonstration pair; iterating the shape against the throwaway is
    legitimate, iterating against the demonstration pair is FORBIDDEN."""
    if rehearsal is None:
        raise RehearsalGateError("mint requires a disclosed rehearsal; none provided")
    if not rehearsal.disclosed:
        raise RehearsalGateError("rehearsal must be disclosed in the run record")
    if not rehearsal.engaged:
        raise RehearsalGateError(
            f"rehearsal non-engagement ({rehearsal.note}) — mint MUST NOT proceed")


def mint_reviewable_board(
    *, rehearsal: RehearsalRecord, throwaway_source_digest: str,
    demonstration_source_digests: frozenset[str], out_dir: Path,
    render: Callable[[], BoardArtifact],
) -> BoardArtifact:
    """THE reviewable-mint entrypoint (dissent P2-1) — the ONLY sanctioned path to a live reviewable
    board, so skipping the rehearsal is UNREPRESENTABLE (there is no mint without this call, and no
    call without an engaged record). ``rehearsal`` is a REQUIRED argument. Gates on
    ``assert_rehearsal_admits``, enforces the D2 disjointness (the rehearsal fixture's
    ``source_digest`` must NOT be one of the demonstration pair's — so the shape was never tuned
    against the graded artifacts), runs ``render`` (the pre-bound live ``render_board``), and writes
    the disclosed rehearsal record into ``out_dir`` alongside the commitment."""
    assert_rehearsal_admits(rehearsal)
    if throwaway_source_digest in demonstration_source_digests:
        raise RehearsalGateError(
            "rehearsal fixture must be DISJOINT from the demonstration pair (D2)")
    artifact = render()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "rehearsal.json").write_text(json.dumps({
        "kind": "rehearsal_record",
        "disclosed": rehearsal.disclosed,
        "engaged": rehearsal.engaged,
        "provider_id": rehearsal.provider_id,
        "model_id": rehearsal.model_id,
        "note": rehearsal.note,
        "throwaway_source_digest": throwaway_source_digest,
    }, indent=2, sort_keys=True), encoding="utf-8")
    return artifact


# ------------------------------------------------------------------
# The light pre-run board commitment (gaming guard)
# ------------------------------------------------------------------


class _FingerprintingBuilder(Protocol):
    """A review-request builder that also fingerprints itself for the commitment — structurally
    satisfied by BOTH the (C) ``AnthropicMessagesRequestBuilder`` and the (Y)
    ``AnthropicReviewableRequestBuilder`` (so build_commitment accepts either)."""

    model: str
    max_tokens: int

    def fingerprint(self) -> dict[str, Any]: ...

    def __call__(
        self, source_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
    ) -> bytes: ...


def build_commitment(
    *, board_id: str, gated_commit: str, code_sha: str, corpus_version: str, provider_id: str,
    base_url: str, builder: _FingerprintingBuilder, declared_n: int, preregistered_at: str,
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
    "ANTHROPIC_VERSION", "AnthropicMessagesRequestBuilder", "AnthropicReviewableRequestBuilder",
    "CapturingReviewClient", "RedactedTransportError", "RehearsalGateError", "RehearsalRecord",
    "ReviewableWire", "ReviewableWireError", "assert_rehearsal_admits", "assert_reviewable_wire",
    "build_commitment", "make_anthropic_transport", "make_live_review_client",
    "mint_reviewable_board", "parse_anthropic_verdict", "parse_reviewable_wire",
    "rehearse_reviewable_shape", "validate_base_url",
]
