"""tests/test_evidence.py — §9.9 fail-closed tests, trust anchor, topology.

Every "fails closed" test follows the discipline: remove the guard → the test
raises → the result is not admitted.

Coverage:
  - Full chain round-trip with schema-valid payloads.
  - §9.9: all four missing-link cases.
  - §9.9: tampered payload, wrong key, digest forgery, index wrong reference.
  - Trust anchor (P0-1): self-signed chain with a different key is rejected.
  - Chain topology (P0-3): kind in wrong position, run_id mismatch, index
    verify_key_hex != trusted key.
  - Schema completeness (P0-2): incomplete payloads are rejected at build and
    at verify — schema validation fires independently of signature verification.
  - Semantic continuity (P1-2): profile mismatch and gated_commit mismatch
    across receipts are rejected; helper is testable in isolation.
  - Admission vs integrity (P1-4): evaluate_admission accepts only VerifiedChain;
    teardown.failure=True verifies but is not admitted; error outcome is not
    admitted; a gated "fail" IS admissible evidence.
  - §0.4: failed teardown still emits a signed, integrity-passing receipt.
  - Phase-0 closure: VerifiedChain sentinel seal; asymmetric builder continuity
    checks; schema strictness (bool exclusion, timestamp timezone, unknown keys).
"""

from __future__ import annotations

import copy
import unittest
import uuid
from datetime import datetime, timezone

from conftest import build_receipt_unchecked
from orchestrator.evidence import (
    ChainVerificationError,
    MissingLinkError,
    Receipt,
    SemanticContinuityError,
    VerifiedChain,
    build_execution_receipt,
    build_index,
    build_receipt,
    build_teardown_receipt,
    evaluate_admission,
    receipt_from_dict,
    receipt_to_dict,
    validate_semantic_continuity,
    verify_integrity,
)
from orchestrator.schemas import SchemaViolationError
from orchestrator.trust import EvidenceSigner, generate_signer

# ------------------------------------------------------------------
# Helpers — schema-valid base payloads (no injected digest fields)
# ------------------------------------------------------------------

_NOW = datetime.now(timezone.utc).isoformat()


def _prereg(profile: str = "p1") -> dict:  # type: ignore[type-arg]
    return {
        "schema_version": 2,
        "profile": profile,
        "gated_commit": "07d2161",
        "corpus_version": "output-b-v1",
        "preregistered_at": _NOW,
    }


def _execution(outcome: str = "pass", profile: str = "p1") -> dict:  # type: ignore[type-arg]
    """Base execution payload (schema v2) — does NOT include prereg_digest.

    Pass to build_execution_receipt() which injects prereg_digest from the
    actual prereg receipt. To call build_receipt("execution", ...) directly
    (e.g. in schema tests), add prereg_digest to the returned dict first.

    For PASS/FAIL outcomes all four provenance fields are included (required by schema).
    For ERROR they are omitted (optional by schema).
    """
    payload: dict = {  # type: ignore[type-arg]
        "schema_version": 2,
        "profile": profile,
        "gated_commit": "07d2161",
        "outcome": outcome,
        "executed_at": _NOW,
        "canonical_digest_alg": "sha256",
        "canonical_digest_version": 1,
        "runtime_pack_digest": "a" * 64,
        "observer_log_digest": "b" * 64,
        "observer_log_truncated": False,
    }
    if outcome in ("pass", "fail"):
        payload["resolved_profile_digest"] = "c" * 64
        payload["trust_policy_digest"] = "d" * 64
        payload["guard_policy_digest"] = "e" * 64
        payload["execution_identity_digest"] = "f" * 64
        payload["policies_consistent"] = True
    return payload


def _teardown(failure: bool = False, profile: str = "p1") -> dict:  # type: ignore[type-arg]
    """Base teardown payload (schema v2) — does NOT include execution_digest.

    Pass to build_teardown_receipt() which injects execution_digest from the
    actual execution receipt. To call build_receipt("teardown", ...) directly
    (e.g. in schema tests), add execution_digest to the returned dict first.
    """
    d: dict = {  # type: ignore[type-arg]
        "schema_version": 2,
        "profile": profile,
        "failure": failure,
        "torn_down_at": _NOW,
        "runtime_pack_digest": "a" * 64,
    }
    if failure:
        d["error"] = "fork deletion timed out"
    return d


# v1 helpers — used only in TestSchemaVersion to construct homogeneous v1 chains
def _v1_prereg(profile: str = "p1") -> dict:  # type: ignore[type-arg]
    return {
        "schema_version": 1,
        "profile": profile,
        "gated_commit": "07d2161",
        "corpus_version": "output-b-v1",
        "preregistered_at": _NOW,
    }


def _v1_execution(outcome: str = "pass", profile: str = "p1") -> dict:  # type: ignore[type-arg]
    return {
        "schema_version": 1,
        "profile": profile,
        "gated_commit": "07d2161",
        "outcome": outcome,
        "executed_at": _NOW,
        "canonical_digest_alg": "sha256",
        "canonical_digest_version": 1,
    }


def _v1_teardown(failure: bool = False, profile: str = "p1") -> dict:  # type: ignore[type-arg]
    d: dict = {  # type: ignore[type-arg]
        "schema_version": 1,
        "profile": profile,
        "failure": failure,
        "torn_down_at": _NOW,
    }
    if failure:
        d["error"] = "fork deletion timed out"
    return d


class TestEvidenceRoundTrip(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = generate_signer()
        self.run_id = str(uuid.uuid4())

    def _full_chain(
        self,
        outcome: str = "pass",
        failure: bool = False,
        signer: EvidenceSigner | None = None,
        profile: str = "p1",
    ) -> tuple[Receipt, Receipt, Receipt, Receipt]:
        s = signer or self.signer
        prereg = build_receipt("prereg", self.run_id, _prereg(profile), s.signing_key)
        execution = build_execution_receipt(prereg, _execution(outcome, profile), s.signing_key)
        teardown = build_teardown_receipt(execution, _teardown(failure, profile), s.signing_key)
        index = build_index(
            self.run_id, prereg, execution, teardown, s.signing_key, s.verify_key_hex
        )
        return prereg, execution, teardown, index

    def _verify(
        self,
        prereg: Receipt | None,
        execution: Receipt | None,
        teardown: Receipt | None,
        index: Receipt | None,
        signer: EvidenceSigner | None = None,
    ) -> VerifiedChain:
        s = signer or self.signer
        return verify_integrity(prereg, execution, teardown, index, s.verify_key)

    def test_complete_chain_verifies(self) -> None:
        chain = self._verify(*self._full_chain())
        self.assertIsInstance(chain, VerifiedChain)
        self.assertEqual(chain.verify_key_hex, self.signer.verify_key_hex)

    def test_serialise_round_trip(self) -> None:
        prereg, *_ = self._full_chain()
        restored = receipt_from_dict(receipt_to_dict(prereg))
        self.assertEqual(prereg, restored)

    def test_payload_deep_copied_at_build(self) -> None:
        """Mutating the original payload dict after build_receipt does not affect the receipt."""
        payload = _prereg()
        receipt = build_receipt("prereg", self.run_id, payload, self.signer.signing_key)
        payload["gated_commit"] = "mutated"
        self.assertEqual(receipt.payload["gated_commit"], "07d2161")

    # ------------------------------------------------------------------
    # §9.9 — missing link fails closed
    # ------------------------------------------------------------------

    def test_missing_prereg_fails_closed(self) -> None:
        _, execution, teardown, index = self._full_chain()
        with self.assertRaises(MissingLinkError):
            self._verify(None, execution, teardown, index)

    def test_missing_execution_fails_closed(self) -> None:
        prereg, _, teardown, index = self._full_chain()
        with self.assertRaises(MissingLinkError):
            self._verify(prereg, None, teardown, index)

    def test_missing_teardown_fails_closed(self) -> None:
        prereg, execution, _, index = self._full_chain()
        with self.assertRaises(MissingLinkError):
            self._verify(prereg, execution, None, index)

    def test_missing_index_fails_closed(self) -> None:
        prereg, execution, teardown, _ = self._full_chain()
        with self.assertRaises(MissingLinkError):
            self._verify(prereg, execution, teardown, None)

    # ------------------------------------------------------------------
    # §9.9 — malformed chain fails closed
    # ------------------------------------------------------------------

    def test_tampered_payload_fails_closed(self) -> None:
        prereg, execution, teardown, index = self._full_chain()
        tampered_payload = copy.deepcopy(execution.payload)
        tampered_payload["outcome"] = "pass" if execution.payload["outcome"] == "fail" else "fail"
        tampered_payload["gated_commit"] = "deadbeef"
        tampered = Receipt(
            kind=execution.kind,
            run_id=execution.run_id,
            payload=tampered_payload,
            digest=execution.digest,
            signature=execution.signature,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, tampered, teardown, index)

    def test_wrong_verify_key_fails_closed(self) -> None:
        chain = self._full_chain()
        wrong_signer = generate_signer()
        with self.assertRaises(ChainVerificationError):
            self._verify(*chain, signer=wrong_signer)

    def test_digest_forgery_fails_closed(self) -> None:
        prereg, execution, teardown, index = self._full_chain()
        forged = Receipt(
            kind=execution.kind,
            run_id=execution.run_id,
            payload=execution.payload,
            digest="a" * 64,
            signature=execution.signature,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, forged, teardown, index)

    def test_index_wrong_reference_fails_closed(self) -> None:
        prereg, execution, teardown, _ = self._full_chain()
        other_execution = build_execution_receipt(
            prereg, _execution("fail"), self.signer.signing_key
        )
        wrong_index = build_index(
            self.run_id,
            prereg,
            other_execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, execution, teardown, wrong_index)

    # ------------------------------------------------------------------
    # P0-1 — trust anchor: self-signed chain is rejected
    # ------------------------------------------------------------------

    def test_self_signed_chain_rejected(self) -> None:
        """Attacker generates own keypair and self-signs — rejected by trusted anchor check."""
        attacker = generate_signer()
        chain = self._full_chain(signer=attacker)
        with self.assertRaises(ChainVerificationError):
            self._verify(*chain)

    def test_index_embedded_key_mismatch_fails(self) -> None:
        """Index verify_key_hex was built with a different key than the trusted verifier."""
        attacker = generate_signer()
        prereg, execution, teardown, _ = self._full_chain()
        bad_index = build_index(
            self.run_id,
            prereg,
            execution,
            teardown,
            self.signer.signing_key,
            attacker.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, execution, teardown, bad_index)

    # ------------------------------------------------------------------
    # P0-3 — chain topology validation
    # ------------------------------------------------------------------

    def test_kind_in_wrong_position_fails(self) -> None:
        """Passing an execution receipt where prereg is expected fails."""
        prereg, execution, teardown, index = self._full_chain()
        with self.assertRaises(ChainVerificationError):
            self._verify(execution, prereg, teardown, index)

    def test_cross_run_mixing_fails(self) -> None:
        """Receipts from different runs cannot be mixed into a valid chain."""
        run2 = str(uuid.uuid4())
        prereg2 = build_receipt("prereg", run2, _prereg(), self.signer.signing_key)
        _, execution, teardown, index = self._full_chain()
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg2, execution, teardown, index)

    def test_index_run_id_mismatch_fails(self) -> None:
        """Index built for a different run_id than the receipts is rejected."""
        prereg, execution, teardown, _ = self._full_chain()
        other_run_id = str(uuid.uuid4())
        other_prereg = build_receipt("prereg", other_run_id, _prereg(), self.signer.signing_key)
        other_exec = build_execution_receipt(other_prereg, _execution(), self.signer.signing_key)
        other_td = build_teardown_receipt(other_exec, _teardown(), self.signer.signing_key)
        other_index = build_index(
            other_run_id,
            other_prereg,
            other_exec,
            other_td,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, execution, teardown, other_index)

    # ------------------------------------------------------------------
    # P0-2 — schema completeness
    # ------------------------------------------------------------------

    def test_missing_schema_field_rejected_at_build(self) -> None:
        """build_receipt rejects payloads missing required fields."""
        bad_payload = {"config": "p0-test"}
        with self.assertRaises(SchemaViolationError):
            build_receipt("prereg", self.run_id, bad_payload, self.signer.signing_key)

    def test_invalid_outcome_rejected_at_build(self) -> None:
        payload = _execution()
        payload["outcome"] = "not-a-valid-outcome"
        payload["prereg_digest"] = "a" * 64  # required; testing outcome validation here
        with self.assertRaises(SchemaViolationError):
            build_receipt("execution", self.run_id, payload, self.signer.signing_key)

    def test_teardown_failure_without_error_field_rejected(self) -> None:
        payload = _teardown(failure=True)
        payload["execution_digest"] = "a" * 64  # required; testing error-field validation
        del payload["error"]
        with self.assertRaises(SchemaViolationError):
            build_receipt("teardown", self.run_id, payload, self.signer.signing_key)

    def test_schema_violation_at_verify_is_independent_of_signature(self) -> None:
        """Schema validation at verify time fires independently of signature verification.

        build_receipt_unchecked produces a Receipt with a valid digest and valid
        signature over a schema-invalid payload, bypassing build_receipt()'s
        schema gate. verify_integrity() then rejects it at schema validation —
        not at digest or signature check — proving the two gates are independent.
        """
        # schema_version=2 is present so the homogeneous-chain check (4) passes;
        # the unknown key triggers schema violation in the per-receipt loop (5–6).
        bad_payload: dict = {"schema_version": 2, "not_a_valid_field": "garbage"}  # type: ignore[type-arg]
        invalid_prereg = build_receipt_unchecked(
            "prereg", self.run_id, bad_payload, self.signer.signing_key
        )
        # Build remaining valid receipts — execution.prereg_digest references the
        # VALID prereg from _full_chain(), not invalid_prereg. The schema check on
        # invalid_prereg fires in the per-receipt loop before any cross-ref check.
        _, execution, teardown, _ = self._full_chain()
        bad_index = build_index(
            self.run_id,
            invalid_prereg,
            execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError) as cm:
            self._verify(invalid_prereg, execution, teardown, bad_index)
        self.assertIn("schema violation", str(cm.exception).lower())

    # ------------------------------------------------------------------
    # P1-2 — semantic continuity
    # ------------------------------------------------------------------

    def test_profile_mismatch_raises_semantic_continuity_error(self) -> None:
        """Different profiles across prereg/execution/teardown fail the chain."""
        prereg = build_receipt("prereg", self.run_id, _prereg("p1"), self.signer.signing_key)
        execution = build_execution_receipt(
            prereg, _execution("pass", "p2"), self.signer.signing_key
        )
        teardown = build_teardown_receipt(
            execution, _teardown(profile="p1"), self.signer.signing_key
        )
        index = build_index(
            self.run_id,
            prereg,
            execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(SemanticContinuityError):
            self._verify(prereg, execution, teardown, index)

    def test_gated_commit_mismatch_raises_semantic_continuity_error(self) -> None:
        """Execution gated_commit != prereg gated_commit fails the chain."""
        exec_payload = _execution()
        exec_payload["gated_commit"] = "deadbeef"
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, exec_payload, self.signer.signing_key)
        teardown = build_teardown_receipt(execution, _teardown(), self.signer.signing_key)
        index = build_index(
            self.run_id,
            prereg,
            execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(SemanticContinuityError):
            self._verify(prereg, execution, teardown, index)

    def test_validate_semantic_continuity_testable_in_isolation(self) -> None:
        """validate_semantic_continuity can be targeted by tests independently."""
        prereg = build_receipt("prereg", self.run_id, _prereg("p1"), self.signer.signing_key)
        execution = build_execution_receipt(
            prereg, _execution("pass", "p1"), self.signer.signing_key
        )
        td_p2 = build_teardown_receipt(execution, _teardown(profile="p2"), self.signer.signing_key)
        with self.assertRaises(SemanticContinuityError):
            validate_semantic_continuity(prereg, execution, td_p2)

    def test_consistent_profile_and_commit_passes(self) -> None:
        """Identical profiles and matching commits verify cleanly."""
        chain = self._verify(*self._full_chain())
        self.assertIsInstance(chain, VerifiedChain)

    # ------------------------------------------------------------------
    # P1-4 — admission vs integrity, VerifiedChain gate
    # ------------------------------------------------------------------

    def test_teardown_failure_verifies_but_not_admitted(self) -> None:
        """§0.4: failed teardown is signed evidence of what happened; not admissible."""
        prereg, execution, teardown, index = self._full_chain(failure=True)
        chain = self._verify(prereg, execution, teardown, index)
        self.assertIsInstance(chain, VerifiedChain)
        self.assertFalse(evaluate_admission(chain))
        self.assertFalse(chain.is_admitted)
        self.assertTrue(teardown.payload["failure"])

    def test_error_outcome_verifies_but_not_admitted(self) -> None:
        """Infrastructure error (outcome='error') is signed but not admissible evidence."""
        prereg, execution, teardown, index = self._full_chain(outcome="error")
        chain = self._verify(prereg, execution, teardown, index)
        self.assertFalse(evaluate_admission(chain))
        self.assertFalse(chain.is_admitted)

    def test_clean_pass_is_admitted(self) -> None:
        prereg, execution, teardown, index = self._full_chain(outcome="pass")
        chain = self._verify(prereg, execution, teardown, index)
        self.assertTrue(evaluate_admission(chain))
        self.assertTrue(chain.is_admitted)

    def test_clean_fail_is_admitted(self) -> None:
        """A gated 'fail' verdict IS admissible evidence."""
        prereg, execution, teardown, index = self._full_chain(outcome="fail")
        chain = self._verify(prereg, execution, teardown, index)
        self.assertTrue(evaluate_admission(chain))
        self.assertTrue(chain.is_admitted)


# ------------------------------------------------------------------
# Phase-0 closure tests
# ------------------------------------------------------------------


class TestPhase0Closure(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = generate_signer()
        self.run_id = str(uuid.uuid4())

    def _chain(self) -> tuple[Receipt, Receipt, Receipt, Receipt]:
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, _execution(), self.signer.signing_key)
        teardown = build_teardown_receipt(execution, _teardown(), self.signer.signing_key)
        index = build_index(
            self.run_id,
            prereg,
            execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        return prereg, execution, teardown, index

    def _verify(
        self, prereg: Receipt, execution: Receipt, teardown: Receipt, index: Receipt
    ) -> VerifiedChain:
        return verify_integrity(prereg, execution, teardown, index, self.signer.verify_key)

    # ------------------------------------------------------------------
    # VerifiedChain sentinel seal
    # ------------------------------------------------------------------

    def test_direct_construction_raises_type_error(self) -> None:
        """VerifiedChain cannot be constructed directly — verify_integrity() is the only path."""
        chain = self._verify(*self._chain())
        with self.assertRaises(TypeError):
            VerifiedChain(
                prereg=chain.prereg,
                execution=chain.execution,
                teardown=chain.teardown,
                index=chain.index,
                verify_key_hex=chain.verify_key_hex,
            )

    # ------------------------------------------------------------------
    # Evidence continuity — asymmetric builder cross-references
    # ------------------------------------------------------------------

    def test_execution_prereg_digest_injected_by_builder(self) -> None:
        """build_execution_receipt injects prereg_digest from the actual prereg."""
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, _execution(), self.signer.signing_key)
        self.assertEqual(execution.payload["prereg_digest"], prereg.digest)

    def test_teardown_execution_digest_injected_by_builder(self) -> None:
        """build_teardown_receipt injects execution_digest from the actual execution."""
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, _execution(), self.signer.signing_key)
        teardown = build_teardown_receipt(execution, _teardown(), self.signer.signing_key)
        self.assertEqual(teardown.payload["execution_digest"], execution.digest)

    def test_execution_prereg_digest_mismatch_fails(self) -> None:
        """execution.prereg_digest must match the actual prereg digest at verify time."""
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        # Build execution with a valid-format but WRONG prereg_digest.
        wrong_exec_payload = {**_execution(), "prereg_digest": "b" * 64}
        wrong_exec = build_receipt(
            "execution", self.run_id, wrong_exec_payload, self.signer.signing_key
        )
        teardown = build_teardown_receipt(wrong_exec, _teardown(), self.signer.signing_key)
        index = build_index(
            self.run_id,
            prereg,
            wrong_exec,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, wrong_exec, teardown, index)

    def test_teardown_execution_digest_mismatch_fails(self) -> None:
        """teardown.execution_digest must match the actual execution digest at verify time."""
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, _execution(), self.signer.signing_key)
        # Build teardown with a valid-format but WRONG execution_digest.
        wrong_td_payload = {**_teardown(), "execution_digest": "c" * 64}
        wrong_td = build_receipt("teardown", self.run_id, wrong_td_payload, self.signer.signing_key)
        index = build_index(
            self.run_id,
            prereg,
            execution,
            wrong_td,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError):
            self._verify(prereg, execution, wrong_td, index)

    def test_execution_requires_prereg_digest_at_build(self) -> None:
        """build_receipt('execution', ...) rejects payloads missing prereg_digest."""
        payload = _execution()  # no prereg_digest
        with self.assertRaises(SchemaViolationError):
            build_receipt("execution", self.run_id, payload, self.signer.signing_key)

    def test_teardown_requires_execution_digest_at_build(self) -> None:
        """build_receipt('teardown', ...) rejects payloads missing execution_digest."""
        payload = _teardown()  # no execution_digest
        with self.assertRaises(SchemaViolationError):
            build_receipt("teardown", self.run_id, payload, self.signer.signing_key)

    # ------------------------------------------------------------------
    # Schema strictness: bool exclusion, timestamp timezone, unknown keys
    # ------------------------------------------------------------------

    def test_bool_rejected_as_int_field(self) -> None:
        """schema_version=True (bool) is rejected even though bool is a subclass of int."""
        payload = {**_prereg(), "schema_version": True}
        with self.assertRaises(SchemaViolationError) as cm:
            build_receipt("prereg", self.run_id, payload, self.signer.signing_key)
        self.assertIn("bool", str(cm.exception).lower())

    def test_timestamp_without_timezone_rejected(self) -> None:
        """ISO timestamp without timezone offset is rejected."""
        payload = {**_prereg(), "preregistered_at": "2026-07-13T10:00:00"}
        with self.assertRaises(SchemaViolationError):
            build_receipt("prereg", self.run_id, payload, self.signer.signing_key)

    def test_timestamp_with_trailing_garbage_rejected(self) -> None:
        """ISO timestamp with trailing text after the timezone is rejected."""
        payload = {**_prereg(), "preregistered_at": "2026-07-13T10:00:00Zextra"}
        with self.assertRaises(SchemaViolationError):
            build_receipt("prereg", self.run_id, payload, self.signer.signing_key)

    def test_unknown_key_in_payload_rejected(self) -> None:
        """A key not in the allowed set raises SchemaViolationError."""
        payload = {**_prereg(), "unexpected_field": "this-should-fail"}
        with self.assertRaises(SchemaViolationError) as cm:
            build_receipt("prereg", self.run_id, payload, self.signer.signing_key)
        self.assertIn("unknown keys", str(cm.exception).lower())


# ------------------------------------------------------------------
# Schema version gate
# ------------------------------------------------------------------


class TestSchemaVersion(unittest.TestCase):
    """Homogeneous-chain check, admission boundary, and mixed-version rejection."""

    def setUp(self) -> None:
        self.signer = generate_signer()
        self.run_id = str(uuid.uuid4())

    def _v1_chain(self, outcome: str = "pass") -> tuple[Receipt, Receipt, Receipt, Receipt]:
        prereg = build_receipt("prereg", self.run_id, _v1_prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, _v1_execution(outcome), self.signer.signing_key)
        teardown = build_teardown_receipt(execution, _v1_teardown(), self.signer.signing_key)
        index = build_index(
            self.run_id,
            prereg,
            execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        return prereg, execution, teardown, index

    def test_v1_chain_verify_integrity_passes(self) -> None:
        """A homogeneous v1 chain passes verify_integrity — verifiable but not admitted."""
        chain = verify_integrity(*self._v1_chain(), self.signer.verify_key)
        self.assertIsInstance(chain, VerifiedChain)
        self.assertEqual(chain.prereg.payload["schema_version"], 1)

    def test_v1_chain_evaluate_admission_returns_false(self) -> None:
        """v1 chains do not meet the schema_version >= 2 admission requirement."""
        chain = verify_integrity(*self._v1_chain(), self.signer.verify_key)
        self.assertFalse(evaluate_admission(chain))
        self.assertFalse(chain.is_admitted)

    def test_mixed_version_chain_fails(self) -> None:
        """A chain where prereg/index are v1 but execution/teardown are v2 is rejected.

        build_index propagates schema_version from prereg, so index is v1.
        versions = {1, 2} → homogeneous check 4 raises ChainVerificationError.
        """
        v1_prereg = build_receipt("prereg", self.run_id, _v1_prereg(), self.signer.signing_key)
        # _execution() and _teardown() are the module-level v2 helpers (updated above).
        v2_execution = build_execution_receipt(v1_prereg, _execution(), self.signer.signing_key)
        v2_teardown = build_teardown_receipt(v2_execution, _teardown(), self.signer.signing_key)
        mixed_index = build_index(
            self.run_id,
            v1_prereg,
            v2_execution,
            v2_teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        with self.assertRaises(ChainVerificationError):
            verify_integrity(
                v1_prereg, v2_execution, v2_teardown, mixed_index, self.signer.verify_key
            )

    def test_v2_chain_admits(self) -> None:
        """A homogeneous v2 chain with clean teardown and pass outcome is admitted."""
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, _execution("pass"), self.signer.signing_key)
        teardown = build_teardown_receipt(execution, _teardown(), self.signer.signing_key)
        index = build_index(
            self.run_id,
            prereg,
            execution,
            teardown,
            self.signer.signing_key,
            self.signer.verify_key_hex,
        )
        chain = verify_integrity(prereg, execution, teardown, index, self.signer.verify_key)
        self.assertEqual(chain.execution.payload["schema_version"], 2)
        self.assertTrue(evaluate_admission(chain))
        self.assertTrue(chain.is_admitted)


# ------------------------------------------------------------------
# P1-3 — execution provenance required for PASS/FAIL
# ------------------------------------------------------------------


class TestExecutionProvenanceRequirements(unittest.TestCase):
    """Schema: provenance fields are REQUIRED for PASS/FAIL, optional for ERROR.

    Board P1.3: any PASS or FAIL receipt without all four provenance digests
    and policies_consistent must be rejected at build time.  This is the gate
    that prevents evidence gap (a 'pass' with no measured identity).
    """

    def setUp(self) -> None:
        self.signer = generate_signer()
        self.run_id = str(uuid.uuid4())

    def _full_chain_for_provenance_test(
        self, exec_payload: dict  # type: ignore[type-arg]
    ) -> tuple[Receipt, ...]:
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, exec_payload, self.signer.signing_key)
        teardown = build_teardown_receipt(execution, _teardown(), self.signer.signing_key)
        index = build_index(
            self.run_id, prereg, execution, teardown,
            self.signer.signing_key, self.signer.verify_key_hex,
        )
        return prereg, execution, teardown, index

    def test_pass_without_resolved_profile_digest_rejected(self) -> None:
        """PASS receipt missing resolved_profile_digest is rejected at build."""
        payload = _execution("pass")
        del payload["resolved_profile_digest"]
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        with self.assertRaises(SchemaViolationError):
            build_execution_receipt(prereg, payload, self.signer.signing_key)

    def test_pass_without_trust_policy_digest_rejected(self) -> None:
        """PASS receipt missing trust_policy_digest is rejected at build."""
        payload = _execution("pass")
        del payload["trust_policy_digest"]
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        with self.assertRaises(SchemaViolationError):
            build_execution_receipt(prereg, payload, self.signer.signing_key)

    def test_pass_without_guard_policy_digest_rejected(self) -> None:
        """PASS receipt missing guard_policy_digest is rejected at build."""
        payload = _execution("pass")
        del payload["guard_policy_digest"]
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        with self.assertRaises(SchemaViolationError):
            build_execution_receipt(prereg, payload, self.signer.signing_key)

    def test_pass_without_execution_identity_digest_rejected(self) -> None:
        """PASS receipt missing execution_identity_digest is rejected at build."""
        payload = _execution("pass")
        del payload["execution_identity_digest"]
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        with self.assertRaises(SchemaViolationError):
            build_execution_receipt(prereg, payload, self.signer.signing_key)

    def test_pass_with_policies_consistent_false_rejected(self) -> None:
        """PASS receipt with policies_consistent=False is rejected — mixed-policy run."""
        payload = _execution("pass")
        payload["policies_consistent"] = False
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        with self.assertRaises(SchemaViolationError):
            build_execution_receipt(prereg, payload, self.signer.signing_key)

    def test_fail_without_provenance_rejected(self) -> None:
        """FAIL receipt missing provenance is also rejected — same requirements as PASS."""
        payload = _execution("fail")
        del payload["execution_identity_digest"]
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        with self.assertRaises(SchemaViolationError):
            build_execution_receipt(prereg, payload, self.signer.signing_key)

    def test_error_without_provenance_accepted(self) -> None:
        """ERROR receipt without provenance fields is accepted — they are optional for ERROR."""
        payload = _execution("error")
        # _execution("error") already omits provenance fields — just verify it builds cleanly.
        prereg = build_receipt("prereg", self.run_id, _prereg(), self.signer.signing_key)
        execution = build_execution_receipt(prereg, payload, self.signer.signing_key)
        self.assertEqual(execution.payload["outcome"], "error")
        self.assertNotIn("execution_identity_digest", execution.payload)

    def test_pass_with_all_provenance_fields_accepted(self) -> None:
        """PASS receipt with all provenance fields present builds and verifies cleanly."""
        prereg, execution, teardown, index = self._full_chain_for_provenance_test(
            _execution("pass")
        )
        chain = verify_integrity(prereg, execution, teardown, index, self.signer.verify_key)
        self.assertTrue(chain.is_admitted)
        self.assertIn("execution_identity_digest", chain.execution.payload)


if __name__ == "__main__":
    unittest.main()
