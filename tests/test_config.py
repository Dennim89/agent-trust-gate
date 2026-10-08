"""Settings: environment parsing, validation, and opening a gate on one SQLite file."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests._helpers import Clock, act
from trust_gate import Settings, Tier, Verdict
from trust_gate import config

ROOT = Path(__file__).resolve().parents[1]


class SettingsEnvTest(unittest.TestCase):
    def test_defaults(self):
        s = Settings()
        self.assertEqual((s.db_path, s.spend_threshold, s.undo_window_seconds),
                         (":memory:", 0.0, 30))

    def test_empty_environment_keeps_defaults(self):
        self.assertEqual(Settings.from_env({}), Settings())

    def test_reads_all_values(self):
        s = Settings.from_env({
            config.ENV_DB: "gate.db",
            config.ENV_SPEND_THRESHOLD: "12.5",
            config.ENV_UNDO_WINDOW: "45",
        })
        self.assertEqual((s.db_path, s.spend_threshold, s.undo_window_seconds),
                         ("gate.db", 12.5, 45))

    def test_non_string_values_in_a_custom_mapping_are_parsed(self):
        s = Settings.from_env({config.ENV_SPEND_THRESHOLD: 3, config.ENV_UNDO_WINDOW: 8})
        self.assertEqual((s.spend_threshold, s.undo_window_seconds), (3.0, 8))

    def test_blank_values_keep_defaults(self):
        s = Settings.from_env({
            config.ENV_DB: "   ",
            config.ENV_SPEND_THRESHOLD: "",
            config.ENV_UNDO_WINDOW: " ",
        })
        self.assertEqual(s, Settings())

    def test_bad_values_raise_instead_of_loosening(self):
        bad = [
            (config.ENV_SPEND_THRESHOLD, "abc"),
            (config.ENV_SPEND_THRESHOLD, "nan"),
            (config.ENV_SPEND_THRESHOLD, "inf"),
            (config.ENV_SPEND_THRESHOLD, "-1"),
            (config.ENV_UNDO_WINDOW, "soon"),
            (config.ENV_UNDO_WINDOW, "1.5"),
            (config.ENV_UNDO_WINDOW, "-5"),
        ]
        for name, value in bad:
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValueError):
                    Settings.from_env({name: value})

    def test_unparseable_values_name_the_variable(self):
        with self.assertRaisesRegex(ValueError, config.ENV_SPEND_THRESHOLD):
            Settings.from_env({config.ENV_SPEND_THRESHOLD: "abc"})
        with self.assertRaisesRegex(ValueError, config.ENV_UNDO_WINDOW):
            Settings.from_env({config.ENV_UNDO_WINDOW: "soon"})

    def test_direct_construction_is_validated_too(self):
        for kwargs in (
            {"db_path": ""},
            {"spend_threshold": float("nan")},
            {"spend_threshold": -0.5},
            {"spend_threshold": True},
            {"undo_window_seconds": -1},
            {"undo_window_seconds": 2.5},
            {"undo_window_seconds": False},
        ):
            with self.subTest(**{k: repr(v) for k, v in kwargs.items()}):
                with self.assertRaises(ValueError):
                    Settings(**kwargs)

    def test_default_source_is_the_process_environment(self):
        with mock.patch.dict(os.environ, {config.ENV_UNDO_WINDOW: "9"}):
            self.assertEqual(Settings.from_env().undo_window_seconds, 9)

    def test_env_example_lists_only_variables_the_code_reads(self):
        known = {config.ENV_DB, config.ENV_SPEND_THRESHOLD, config.ENV_UNDO_WINDOW}
        values = {}
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name, _, value = line.partition("=")
                values[name] = value
        self.assertEqual(set(values), known)
        # The example must itself be a valid configuration.
        Settings.from_env(values)


class SettingsOpenTest(unittest.TestCase):
    def test_gate_and_ledger_share_one_file_and_keep_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "gate.db")
            settings = Settings(db_path=path, spend_threshold=10, undo_window_seconds=7)

            gate, ledger = settings.open()
            try:
                d = gate.evaluate(act("send_message", args={"text": "hi"},
                                      idempotency_key="call-1"), now=Clock())
                self.assertEqual((d.verdict, d.tier, d.undo_window_seconds),
                                 (Verdict.ALLOW, Tier.T1, 7))
                ledger.record_success("send_message", Tier.T1, now=1.0)
                self.assertEqual(gate.action_log.count(), 1)

                # The spend threshold reaches the classifier.
                small = gate.evaluate(act("spend", args={"amount": 5}), now=Clock())
                big = gate.evaluate(act("spend", args={"amount": 50}), now=Clock())
                self.assertEqual((small.verdict, small.tier),
                                 (Verdict.CONFIRM_REQUIRED, Tier.T2))
                self.assertEqual((big.verdict, big.tier), (Verdict.DENY, Tier.T3))
            finally:
                ledger.close()
                gate.action_log.close()

            self.assertTrue(os.path.exists(path))

            gate, ledger = settings.open()
            try:
                self.assertEqual(gate.action_log.count(), 1)
                self.assertEqual(ledger.get("send_message").successes, 1)
            finally:
                ledger.close()
                gate.action_log.close()

    def test_in_memory_default_keeps_nothing_between_opens(self):
        gate, ledger = Settings().open()
        try:
            gate.evaluate(act("read_file", args={"path": "a.txt"}), now=Clock())
            self.assertEqual(gate.action_log.count(), 1)
        finally:
            ledger.close()
            gate.action_log.close()
        gate, ledger = Settings().open()
        try:
            self.assertEqual(gate.action_log.count(), 0)
        finally:
            ledger.close()
            gate.action_log.close()


if __name__ == "__main__":
    unittest.main()
