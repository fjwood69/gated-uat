"""tests/_gate_account.py — derive gate_outcome from the REAL gate.job_result.account().

Not a test module (underscore prefix): a shared helper so the gauntlet's gate FAKE and the coherence
parity test both read the SINGLE source of truth — account() — instead of re-encoding the
result_kind -> gate_outcome mapping (which would be the unbound-reader defect in a test costume).
The dissent catch: a BlockingRefusal is account()=run_verdict (a real admission verdict was
produced), NOT block_gate.
"""

from __future__ import annotations


def real_gate_outcome(kind: str) -> str | None:
    """Return account().gate_outcome.value for a minimal REAL JobResult of ``kind`` (or None).
    ``kind`` ∈ {admitted_run, blocking_refusal, non_run_block, non_run_neutral,
    infrastructure_failure}. admitted_run is heavy to construct, so it uses the real GateOutcome
    enum
    (== the run_verdict account() emits for an admitted run — the identical value the parity test
    verifies for blocking_refusal)."""
    from gate.job_result import (
        BlockingRefusal,
        GateOutcome,
        InfraFailureReason,
        InfrastructureFailure,
        NonRunDecision,
        account,
    )
    from gate.policy_state import Disposition
    from gate.run_admission import RunAdmissionRefusal

    if kind == "admitted_run":
        return GateOutcome.RUN_VERDICT.value
    if kind == "blocking_refusal":
        go = account(BlockingRefusal(RunAdmissionRefusal.ICV_UNSUPPORTED, "x")).gate_outcome
    elif kind == "non_run_block":
        go = account(NonRunDecision(Disposition.BLOCK_ACTION_REQUIRED, "x")).gate_outcome
    elif kind == "non_run_neutral":
        go = account(NonRunDecision(Disposition.SKIP_NEUTRAL, "x")).gate_outcome
    elif kind == "infrastructure_failure":
        infra = InfrastructureFailure(InfraFailureReason.WORKER_FAULT, detail="x")
        go = account(infra).gate_outcome
    else:
        raise ValueError(f"unknown kind: {kind!r}")
    return go.value if go is not None else None
