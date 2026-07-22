"""orchestrator/provider_gate.py — the provider-gate ReviewClient (B1 seal gate 1, closes SD1).

The llm_review stage is the ONE component of the measurement environment with legitimate outbound
model-API access, so it is the exfiltration surface. This module is the concrete ``ReviewClient``
that closes it, as a CAPABILITY-DELETION (not a policy):

  * TRANSMIT-ONLY. The harness BUILDS the request envelope (``gauntlet._canonical_review_request``)
    and hands the client the exact ``request_bytes``; the client transmits them VERBATIM and returns
    the reviewer's response. It never constructs or forges a request body — there is no code path
    that does.

  * EGRESS ALLOWLIST SCOPED TO THE COMPLETION PATH. ``CompletionOnlyEgress.post`` will POST to the
    completion path (``/v1/messages``) and NOTHING else: any other path raises ``EgressRefused`` at
    the send boundary. The client is STRUCTURALLY incapable of reaching a control-plane path
    (``/v1/environments`` etc.) — not "configured not to". The allowlist is a frozenset the client
    cannot widen at call time.

  * SCHEMA/CONFIG LAW (no drift). ``ALLOWED_PATHS`` == ``{COMPLETION_PATH}`` exactly. A future
    "add tool-use / environment-provisioning to improve reviews" change widens that set (or adds a
    surface) and FAILS ``test_provider_gate`` — the surface does not silently grow.

The concrete network transport is INJECTED (real httpx at fanout / a fake in tests), so
the egress LAW is tested without a live network. The response->verdict parser is injected too — the
gate's job is the egress boundary + verbatim transmission, not the provider's wire format.

This closes SD1 at the B1 level: a real transmit-only client now backs the ``(request_bytes, ...)``
seam. (End-to-end containment past the wire is bounded by what THIS client transmits — which is,
by construction, exactly the harness-built request.)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .gauntlet import ReviewOutcome

# The ONLY egress path the review client may reach — the model completion endpoint (Anthropic
# Messages API). Everything else (agent launch, environment provisioning, sessions, tool-use) is a
# control-plane path and is unreachable by construction.
COMPLETION_PATH = "/v1/messages"

# Control-plane paths named ONLY for documentation + the guard test's coverage — the allowlist is
# positive (only COMPLETION_PATH), so this list is illustrative, not the enforcement mechanism.
CONTROL_PLANE_PATHS: tuple[str, ...] = (
    "/v1/environments", "/v1/organizations", "/v1/agents", "/v1/sessions", "/v1/files",
    "/v1/messages/batches", "/v1/models",
)

# A transport: (absolute_url, body_bytes) -> response_bytes. Injected; the gate imports no HTTP
# client itself (keeps the security law testable without a network).
Transport = Callable[[str, bytes], bytes]

# A response parser: response_bytes -> verdict string ('approve' | 'request_changes'). Injected; an
# invalid verdict is rejected downstream at cell_stage receipt build (schema VALID_REVIEW_VERDICTS).
VerdictParser = Callable[[bytes], str]


class EgressRefused(RuntimeError):
    """A non-completion (control-plane) path was attempted through the review egress. The client is
    capability-limited to the completion path; this is the hard refusal at the send boundary."""


@dataclass(frozen=True)
class CompletionOnlyEgress:
    """A transmit-only egress restricted to the completion path. capability-deletion: ``post`` sends
    to ``COMPLETION_PATH`` and refuses ANY other path — the allowlist is a frozenset fixed at
    construction, not a mutable flag. The base URL + transport are injected."""

    transport: Transport
    base_url: str
    allowed_paths: frozenset[str] = field(default_factory=lambda: frozenset({COMPLETION_PATH}))

    def post(self, path: str, body: bytes) -> bytes:
        """POST ``body`` to ``base_url + path`` — ONLY if ``path`` is in the allowlist. Any other
        path (a control-plane path) raises ``EgressRefused`` before the transport is ever called."""
        if path not in self.allowed_paths:
            raise EgressRefused(
                f"control-plane path refused (egress allowlist = {sorted(self.allowed_paths)}): "
                f"{path!r}")
        return self.transport(self.base_url.rstrip("/") + path, body)


@dataclass(frozen=True)
class ReviewProviderClient:
    """The concrete ``gauntlet.ReviewClient``: ``(request_bytes, reviewer_lineage, prompt_hash) ->
    ReviewOutcome``. It transmits the harness-built ``request_bytes`` VERBATIM to the completion
    (never re-encoding or re-forging), parses the reviewer's structured verdict from the response,
    and records the raw response bytes (digested by the stage, never stored). It has NO method that
    reaches a control-plane path — the only egress it holds is the completion-only one."""

    egress: CompletionOnlyEgress
    provider_id: str
    model_id: str
    parse_verdict: VerdictParser

    def __call__(
        self, request_bytes: bytes, reviewer_lineage: str, review_prompt_hash: str
    ) -> ReviewOutcome:
        # Transmit the EXACT harness-built request to the completion path — no re-forging, no other
        # path reachable. reviewer_lineage / review_prompt_hash are already bound in request_bytes
        # by the harness; they are not a second channel the client can diverge from.
        response = self.egress.post(COMPLETION_PATH, request_bytes)
        verdict = self.parse_verdict(response)
        return ReviewOutcome(
            verdict=verdict, provider_id=self.provider_id, model_id=self.model_id,
            raw_response=response)
