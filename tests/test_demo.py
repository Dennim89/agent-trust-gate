"""The offline demo: fixed expectations, and the injected instruction really is inert."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

import tests._helpers  # noqa: F401  (puts the repository root on sys.path)
from trust_gate import Action, Gate, Provenance, Source, Tier, Verdict
from trust_gate.demo import NOW, render, run

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = [
    (Verdict.ALLOW, Tier.T0),
    (Verdict.ALLOW, Tier.T1),
    (Verdict.CONFIRM_REQUIRED, Tier.T2),
    (Verdict.ALLOW, Tier.T2),
    (Verdict.DENY, Tier.T2),
    (Verdict.DENY, Tier.T3),
    (Verdict.DENY, Tier.T3),
    (Verdict.DENY, Tier.T3),
]


class DemoTest(unittest.TestCase):
    def test_decisions(self):
        got = [(d.verdict, d.tier) for _, d in run()]
        self.assertEqual(got, EXPECTED)

    def test_injected_instruction_changes_nothing(self):
        case, decision = run()[5]
        self.assertIn("tier=T0", case.action.args["note"])
        self.assertEqual((decision.verdict, decision.tier), (Verdict.DENY, Tier.T3))

        # Same transfer without the injected note: same verdict, same tier.
        args = {k: v for k, v in case.action.args.items() if k != "note"}
        clean = Action("transfer", args, provenance=case.action.provenance)
        d = Gate().evaluate(clean, now=NOW)
        self.assertEqual((d.verdict, d.tier), (decision.verdict, decision.tier))

        # Label the stranger as the owner and the T3 rule still denies it, with a draft.
        mislabeled = Action(
            "transfer", dict(case.action.args), provenance=Provenance(sources=(Source.OWNER,))
        )
        d = Gate().evaluate(mislabeled, now=NOW)
        self.assertEqual((d.verdict, d.tier, d.draft), (Verdict.DENY, Tier.T3, True))

    def test_token_is_what_separates_rows_three_and_four(self):
        results = run()
        (case3, d3), (case4, d4) = results[2], results[3]
        self.assertEqual(case3.action, case4.action)
        self.assertFalse(case3.approved)
        self.assertTrue(case4.approved)
        self.assertNotEqual(d3.verdict, d4.verdict)

    def test_render_is_deterministic(self):
        self.assertEqual(render(), render())

    def test_python_dash_m_prints_the_same_text(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "trust_gate"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, render() + "\n")


if __name__ == "__main__":
    unittest.main()
