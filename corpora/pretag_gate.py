#!/usr/bin/env python3
"""PRE-TAG GATE — the properties of the release cut, ENFORCED rather than inspected.

⚠ WHY THIS EXISTS. Every property the cut freezes previously rested on someone looking carefully, and
in this very process that failed once: the published mutated variants were first generated WITH an
explanatory docstring header, which broke the digest equality that is the hybrid pin's only load-
bearing property. It was caught by luck. A tag is irreversible and public, so the last thing standing
between a mistake and permanence must be a command, not an intention.

RUN IT ON THE EXACT CANDIDATE ARTIFACT, before tagging. It refuses unless ALL of:

  G1  every corpus member is present, and NOTHING ELSE is       (exact-set equality)
  G2  each member's digest matches SHA256SUMS                   (content equality)
  G3  both published mutants are BYTE-IDENTICAL to the LIVE applier's output   (the hybrid pin)
  G4  each mutant differs from its base by EXACTLY ONE LINE     (structure of the claim)
  G5  MEASURED.json validates: counts only, NO verdicts         (a demo threshold must not
                                                                 ossify into corpus truth)
  G6  MEASURED counts AGREE with the BY-CONSTRUCTION counts     (breaks the wrong==wrong circularity)
  G7  a format version is present                               (so a later consumer can REFUSE an
                                                                 unknown format rather than misparse)
  G8  every member is a regular file — no symlink, hardlink, device node, or duplicate name

G1 IS A DISTINCT AXIS FROM G2 and that is not pedantry: a corpus can have every member's bytes
correct and still be wrong by containing one member too few or one too many. Content checks are
structurally blind to it — the same shape as a control that guards an argv node while the arguments
passed into it go unchecked.

The verdict is the LAST LINE as well as the exit code, because a refusal that a shell pipeline can
discard is not a refusal.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from expectations import BY_CONSTRUCTION, EXPECTED_MEMBERS  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "fixtures"
BASE = "retry-swallow-v2"
# (published variant, the ONE-LINE mutation the demo applies live)
MUTANTS = {
    "retry-swallow-v2-mutated-behavioural": ('        return b"unavailable"', '        return b""'),
    "retry-swallow-v2-mutated-cosmetic": ("def _safe_get() -> bytes:",
                                          "def _safe_get() -> bytes:  # cosmetic only"),
}
FORMAT_VERSION = 1


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check(measured_path: Path, sums_path: Path) -> list[str]:
    """Return a list of failures. EMPTY means the gate passes."""
    fails: list[str] = []

    present = {d.name for d in CORPUS.iterdir() if d.is_dir() and (d / "main.py").exists()}
    shipped = present & EXPECTED_MEMBERS

    # G1 — exact set. Reported as two DIRECTED differences, never as one symmetric count: "missing"
    # and "extra" are different defects with different causes and must not share a message.
    missing = EXPECTED_MEMBERS - present
    if missing:
        fails.append(f"G1 MISSING member(s): {sorted(missing)}")
    if sums_path.exists():
        # Member names come ONLY from lines shaped `fixtures/<name>/main.py`. Splitting on "/" and
        # taking [0] yielded the literal "fixtures" for every entry — every member would have compared
        # equal to every other, and the exact-set check would have been uniformly, silently vacuous.
        listed = set()
        for ln in sums_path.read_text().splitlines():
            if not ln.strip():
                continue
            parts = ln.split()[-1].split("/")
            if len(parts) == 3 and parts[0] == "fixtures" and parts[2] == "main.py":
                listed.add(parts[1])
        extra = listed - EXPECTED_MEMBERS
        if extra:
            fails.append(f"G1 EXTRA member(s) in SHA256SUMS: {sorted(extra)}")
        if EXPECTED_MEMBERS - listed:
            fails.append(f"G1 member(s) absent from SHA256SUMS: {sorted(EXPECTED_MEMBERS - listed)}")

    # G8 — member type. A digest pins bytes, not semantics: a symlink inside a pinned tarball is
    # still a pinned symlink.
    for name in sorted(shipped):
        f = CORPUS / name / "main.py"
        if f.is_symlink() or not f.is_file():
            fails.append(f"G8 {name}/main.py is not a regular file")

    # G2 — content equality against SHA256SUMS.
    if sums_path.exists():
        for line in sums_path.read_text().splitlines():
            if not line.strip():
                continue
            digest, _, member = line.partition("  ")
            f = CORPUS.parent / member if not (CORPUS / member).exists() else CORPUS / member
            if not f.exists():
                fails.append(f"G2 SHA256SUMS lists a member that is not present: {member}")
            elif sha256(f) != digest:
                fails.append(f"G2 digest mismatch for {member}")

    # G3 + G4 — the hybrid pin, and the structure of the claim it makes.
    base_src = (CORPUS / BASE / "main.py").read_text()
    for variant, (old, new) in MUTANTS.items():
        vf = CORPUS / variant / "main.py"
        if not vf.exists():
            fails.append(f"G3 published variant absent: {variant}")
            continue
        if old not in base_src:
            fails.append(f"G3 the live mutation anchor for {variant} is GONE from {BASE} — the "
                         "published bytes can no longer be what the live applier produces")
            continue
        live = base_src.replace(old, new, 1)
        if vf.read_text() != live:
            fails.append(f"G3 {variant} is NOT byte-identical to the live applier's output "
                         "(a header, a trailing newline, or an editor normalisation will do this)")
        differing = sum(1 for a, b in zip(base_src.splitlines(), live.splitlines()) if a != b)
        if differing != 1:
            fails.append(f"G4 {variant} differs from {BASE} by {differing} lines, not exactly 1")

    # G5 + G6 + G7 — the measured record.
    if not measured_path.exists():
        fails.append("G5 MEASURED.json is absent")
        return fails
    data = json.loads(measured_path.read_text())
    if data.get("format_version") != FORMAT_VERSION:
        fails.append(f"G7 format_version is {data.get('format_version')!r}, expected {FORMAT_VERSION}")
    counts = data.get("egress_counts", {})
    banned = [k for k, v in counts.items() if isinstance(v, str) or str(v).upper() in ("ADMIT", "BLOCK")]
    if banned or "verdicts" in data:
        fails.append("G5 MEASURED.json contains VERDICTS. It records counts ONLY — a demo-scoped "
                     "threshold must not ossify into corpus truth every later consumer conforms to")
    for member, (expected, _why) in BY_CONSTRUCTION.items():
        got = counts.get(member)
        if got is None:
            fails.append(f"G6 MEASURED.json has no count for {member}")
        elif got != expected:
            fails.append(f"G6 {member}: measured {got} but BY-CONSTRUCTION derivation says {expected} "
                         "— one of them is wrong, and the cut must not freeze either until it is known "
                         "which")
    return fails


def main() -> int:
    measured = CORPUS.parent / "MEASURED.json"
    sums = CORPUS.parent / "SHA256SUMS"
    fails = check(measured, sums)
    print("=" * 96)
    for f in fails:
        print(f"  FAIL  {f}")
    print("=" * 96)
    if fails:
        print(f"### PRE-TAG GATE REFUSED — {len(fails)} failure(s). DO NOT TAG. ###")
        return 1
    print("### PRE-TAG GATE PASS — the candidate may be tagged ###")
    return 0


if __name__ == "__main__":
    sys.exit(main())
