"""README.md is part of the contract: its sample output and its snippet must be what the code does."""

from __future__ import annotations

import contextlib
import io
import re
import unittest
from pathlib import Path

import tests._helpers  # noqa: F401  (puts the repository root on sys.path)
from trust_gate import config
from trust_gate.demo import render

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def block(name: str) -> str:
    """The fenced code block between <!-- NAME:start --> and <!-- NAME:end -->."""
    pattern = rf"<!-- {re.escape(name)}:start -->\s*```[a-z]*\n(.*?)\n```\s*<!-- {re.escape(name)}:end -->"
    match = re.search(pattern, README, re.S)
    if match is None:
        raise AssertionError(f"README.md has no marked block {name!r}")
    return match.group(1)


class ReadmeTest(unittest.TestCase):
    def test_sample_output_is_what_the_demo_prints(self):
        lines = block("sample-output").splitlines()
        self.assertEqual(lines[0], "$ python -m trust_gate")
        self.assertEqual("\n".join(lines[1:]), render())

    def test_usage_snippet_runs_and_prints_the_documented_output(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(compile(block("usage-code"), "README.md", "exec"), {"__name__": "__readme__"})
        self.assertEqual(out.getvalue().rstrip("\n"), block("usage-output"))

    def test_quickstart_has_at_most_five_commands(self):
        match = re.search(r"## Quickstart.*?```bash\n(.*?)\n```", README, re.S)
        self.assertIsNotNone(match)
        commands = [ln for ln in match.group(1).splitlines() if ln.strip() and not ln.startswith("#")]
        self.assertLessEqual(len(commands), 5)

    def test_every_environment_variable_is_documented(self):
        for name in (config.ENV_DB, config.ENV_SPEND_THRESHOLD, config.ENV_UNDO_WINDOW):
            self.assertIn(f"`{name}`", README)

    def test_relative_links_and_named_files_exist(self):
        links = [t for t in re.findall(r"\]\(([^)]+)\)", README) if not t.startswith("http")]
        named = re.findall(r"`((?:tests|docs|trust_gate)/[\w./-]+\.(?:py|md))`", README)
        self.assertTrue(links and named)
        headings = {
            re.sub(r"[^\w\- ]", "", h.lower()).strip().replace(" ", "-")
            for h in re.findall(r"^#+ (.+)$", README, re.M)
        }
        for target in links + named:
            with self.subTest(target=target):
                if target.startswith("#"):
                    self.assertIn(target[1:], headings)
                else:
                    self.assertTrue((ROOT / target).is_file())

    def test_required_line_and_license_are_present(self):
        self.assertIn("Built with AI coding agents (Claude, Codex).", README)
        self.assertIn("MIT", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("Copyright (c) 2026 Denys", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_readme_does_not_claim_the_gate_covers_every_call(self):
        lowered = README.lower()
        for phrase in ("every tool call", "all tool calls", "every call is"):
            self.assertNotIn(phrase, lowered)
        self.assertIn("does not intercept", lowered)


if __name__ == "__main__":
    unittest.main()
