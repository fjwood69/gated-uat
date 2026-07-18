"""tests/test_expectation_closure.py — the falsifiability guard for the expectation module.

``orchestrator/expectations.py`` holds each scenario's committed prediction. If that module could
import gated — directly OR transitively via a local helper — the prediction could be computed from
the gate, and the harness would be a mirror, not a falsifier.

The guard is an EXACT IMPORT WHITELIST, not a gated-root denylist (dissent: a root-only ban blocks
``import gate`` but sails ``from orchestrator.helper import x`` where helper imports gated — it
proves the corner while claiming the transitive property). The whitelist closes transitivity BY
CONSTRUCTION: the module may import EXACTLY ``{__future__, dataclasses, enum}``, none of which can
reach gated, so the guard needn't know gated's roots at all. Asserted as literal set-equality over
the module's AST imports (not sys.modules, which sees only what executed; not substring matching).
A fourth import — however innocent — trips the guard and is a deliberate, reviewed whitelist
amendment, never a silent widening.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from orchestrator.expectations import EXPECTATIONS, ScenarioId, expected_for

_MODULE = Path(__file__).resolve().parent.parent / "orchestrator" / "expectations.py"
# The EXACT set of import roots the expectation module is permitted — the stdlib primitives it needs
# and nothing else. Equality, not subset: widening this is a reviewed decision.
_IMPORT_WHITELIST = frozenset({"__future__", "dataclasses", "enum"})
_CLOSED_KINDS = frozenset(
    {"admitted_run", "blocking_refusal", "non_run", "infrastructure_failure"}
)


def _import_roots(source: str) -> set[str]:
    """The set of import roots in *source*. A relative import (``from . import x`` / ``from .helper
    import x``) is a LOCAL import — the transitive-laundering channel — recorded as ``<local>`` so
    it can never equal the stdlib whitelist. Shared by the real-module check and the teeth check."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            root = node.module.split(".")[0] if node.module and node.level == 0 else "<local>"
            roots.add(root)
    return roots


class ExpectationClosureTests(unittest.TestCase):
    def test_expectation_module_imports_exactly_the_whitelist(self) -> None:
        roots = _import_roots(_MODULE.read_text())
        self.assertEqual(
            roots, set(_IMPORT_WHITELIST),
            f"orchestrator/expectations.py imports {sorted(roots)}, not exactly "
            f"{sorted(_IMPORT_WHITELIST)} — the expectation module must stay import-austere so no "
            "path (direct or transitive) can reach the gate; widening the whitelist is a reviewed "
            "amendment.")

    def test_the_guard_has_teeth(self) -> None:
        # the guard is a claim too: prove its extraction REJECTS the laundering channels a root-only
        # denylist would miss — a direct gated import, and (the real gap) a LOCAL helper that could
        # itself import gated. Each must produce a root set != the whitelist.
        for source, why in (
            ("import gate", "direct gated import"),
            ("from orchestrator.helper import x", "absolute local helper (transitive)"),
            ("from .helper import x", "relative local helper (transitive)"),
            ("from . import helper", "relative package import"),
            ("import typing", "an innocent but un-whitelisted stdlib import"),
        ):
            with self.subTest(why=why):
                self.assertNotEqual(
                    _import_roots(source), set(_IMPORT_WHITELIST),
                    f"the whitelist guard failed to reject: {why}")

    def test_every_scenario_has_an_authored_expectation(self) -> None:
        # a closed ontology: every ScenarioId must have a literal expectation (no default/compose).
        for scenario in ScenarioId:
            with self.subTest(scenario=scenario):
                exp = expected_for(scenario)
                self.assertIn(exp.kind, _CLOSED_KINDS)
                self.assertTrue(exp.reason, "the expected reason token must be non-empty")

    def test_expectations_cover_exactly_the_scenario_ids(self) -> None:
        self.assertEqual(set(EXPECTATIONS), set(ScenarioId))


if __name__ == "__main__":
    unittest.main()
