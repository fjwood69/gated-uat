"""gated-uat CLI — Phase 1."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from profiles import p1_regression

# Maps profile name → module with a run() entry point.
PROFILES = {
    "p1": p1_regression,
}


def _derive_gated_commit() -> str | None:
    """Verify and return the 7-char pinned gated commit from the gated-uat-pin worktree.

    Delegates to orchestrator.gated_pin.verify_gated_dependency() — the same
    enforcement used by pytest — so the CLI cannot sign evidence against a
    dirty or mismatched checkout.  Returns None if the pin worktree is absent
    (setup not performed); propagates RuntimeError if present but the pin or
    clean-tree check fails.
    """
    from orchestrator.gated_pin import verify_gated_dependency

    # Dedicated pin worktree — never the live 'gated' checkout (a detached pin only).
    gated_dir = Path(__file__).parent.parent / "gated-uat-pin"
    if not gated_dir.is_dir():
        return None
    return verify_gated_dependency(gated_dir)


def _cmd_run(args: argparse.Namespace) -> int:
    profile_name = args.profile
    if profile_name not in PROFILES:
        print(
            f"gated-uat: unknown profile {profile_name!r}. Available: {sorted(PROFILES)!r}",
            file=sys.stderr,
        )
        return 2

    from nacl.signing import SigningKey

    from orchestrator.isolation import Registry
    from orchestrator.runtime import validate_image_digest

    try:
        validate_image_digest(args.image_digest)
    except Exception as exc:
        print(f"gated-uat: --image-digest: {exc}", file=sys.stderr)
        return 2

    # P1.5: argparse requires --key-file; check the file actually exists on disk.
    key_path = Path(args.key_file)
    if not key_path.exists():
        print(f"gated-uat: key file not found: {key_path}", file=sys.stderr)
        return 2
    signing_key = SigningKey(key_path.read_bytes())

    # P1.5: verify the signing key's derived verify key matches the externally-pinned
    # trust root supplied by the operator.  Without this check, signer and verifier are
    # the same process — a tautological self-signed ring.  The trusted verify key must
    # be managed independently of (and before) the signing key is generated.
    from nacl.encoding import HexEncoder

    actual_vk_hex = signing_key.verify_key.encode(HexEncoder).decode()
    if actual_vk_hex != args.trusted_verify_key_hex:
        print(
            f"gated-uat: signing key's verify key ({actual_vk_hex[:16]}...) "
            f"does not match --trusted-verify-key-hex ({args.trusted_verify_key_hex[:16]}...)",
            file=sys.stderr,
        )
        return 2

    # F8: derive gated commit from the gated-uat-pin worktree; do not trust CLI input.
    # verify_gated_dependency() enforces the exact pin and clean-tree invariant;
    # a mismatch raises RuntimeError (not a configuration error — a hard rejection).
    try:
        gated_commit = _derive_gated_commit()
    except RuntimeError as exc:
        print(f"gated-uat: gated dependency check failed: {exc}", file=sys.stderr)
        return 1
    if gated_commit is None:
        print(
            "gated-uat: cannot derive gated commit — ensure gated-uat-pin worktree is set up",
            file=sys.stderr,
        )
        return 1

    verify_key = signing_key.verify_key
    corpus_path = Path(args.corpus_path)
    runs_path = Path(args.runs_dir)
    registry = Registry(runs_path / "registry.db")

    config = p1_regression.RunConfig(
        image_ref=args.image_ref,
        toolchain_image_digest=args.image_digest,
        gated_commit=gated_commit,
        corpus_path=corpus_path,
        signing_key=signing_key,
        verify_key=verify_key,
        registry=registry,
        artifact_dir=runs_path,
        trials=args.trials,
    )

    module = PROFILES[profile_name]
    try:
        chain = module.run(config)
    except p1_regression.CorpusConfigError as exc:
        print(f"gated-uat: corpus configuration error: {exc}", file=sys.stderr)
        return 1
    except p1_regression.ImageDigestMismatchError as exc:
        print(f"gated-uat: image digest mismatch: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"gated-uat: run failed: {exc}", file=sys.stderr)
        return 1

    outcome_str = chain.execution.payload.get("outcome", "unknown")
    admitted = chain.is_admitted
    run_id = chain.prereg.run_id
    print(f"run_id:  {run_id}")
    print(f"outcome: {outcome_str}")
    print(f"admitted: {admitted}")
    # P2: exit 0 only when both conditions hold — chain was admitted AND calibration passed.
    # is_admitted alone is insufficient (a verified "fail" is admitted as valid evidence).
    return 0 if (admitted and outcome_str == "pass") else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gated-uat",
        description="Signed UAT evidence harness for the gated promotion gate.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Execute a UAT profile and produce a signed chain.")
    run_p.add_argument(
        "profile",
        choices=sorted(PROFILES),
        help="UAT profile to execute.",
    )
    run_p.add_argument(
        "--image-ref",
        required=True,
        help="OCI image reference (e.g. localhost/mori:local).",
    )
    run_p.add_argument(
        "--image-digest",
        required=True,
        help="Pinned OCI image digest (sha256:<64 hex chars>).",
    )
    run_p.add_argument(
        "--trials",
        type=int,
        default=5,
        help="Number of calibration trials per fixture (default: %(default)s).",
    )
    run_p.add_argument(
        "--key-file",
        required=True,
        help="Path to a 32-byte Ed25519 signing key (required).",
    )
    run_p.add_argument(
        "--trusted-verify-key-hex",
        required=True,
        help=(
            "Externally-pinned Ed25519 verify key (64 lowercase hex chars). "
            "The signing key's derived verify key must match this value. "
            "Managed independently of the signing key to break the signer==verifier tautology."
        ),
    )
    run_p.add_argument(
        "--corpus-path",
        default=str(Path(__file__).parent / "corpora"),
        help="Path to the corpus directory (default: %(default)s).",
    )
    run_p.add_argument(
        "--runs-dir",
        default=str(Path(__file__).parent / "RUNS"),
        help="Path to the run registry directory (default: %(default)s).",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "run":
        return _cmd_run(args)
    return 2  # unreachable: argparse enforces valid subcommands


if __name__ == "__main__":
    sys.exit(main())
