"""tests/test_expectation_closure.py — the falsifiability guard for the expectation module.

``orchestrator/expectations.py`` holds each scenario's committed prediction. If that module could
import gated, the prediction could be computed from the gate — the harness would be a mirror, not a
falsifier. This test enforces the ban (AST, so it holds even though gated is on sys.path in the test
env) and pins the closed ontology so a scenario cannot silently lose its authored expectation.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from orchestrator.expectations import EXPECTATIONS, ScenarioId, expected_for

_MODULE = Path(__file__).resolve().parent.parent / "orchestrator" / "expectations.py"
# gated's package roots — the expectation module must not import any of them (directly or via a
# transitive gated re-export; a direct-import ban is the enforceable structural proxy).
_BANNED_ROOTS = frozenset({"gate", "engine", "sandbox", "core"})
_CLOSED_KINDS = frozenset(
    {"admitted_run", "blocking_refusal", "non_run", "infrastructure_failure"}
)


class ExpectationClosureTests(unittest.TestCase):
    def test_expectation_module_does_not_import_gated(self) -> None:
        tree = ast.parse(_MODULE.read_text(), filename=str(_MODULE))
        offending: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offending += [
                    a.name for a in node.names if a.name.split(".")[0] in _BANNED_ROOTS
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in _BANNED_ROOTS:
                    offending.append(node.module)
        self.assertEqual(
            offending, [],
            f"orchestrator/expectations.py imports gated {offending} — the authored prediction "
            "must be independent of the gate, else the harness self-confirms (mirror not test).")

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
