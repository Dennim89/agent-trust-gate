"""G2 TOTAL + DETERMINISTIC: classify() is total & deterministic; garbage => T3."""

from __future__ import annotations

import unittest

from tests._helpers import act
from trust_gate import Tier, classify


class G2TotalDeterministic(unittest.TestCase):
    def test_g2_known_tiers(self):
        cases = [
            (act("read_file", args={"path": "/etc/hosts"}), Tier.T0),
            (act("http_get", args={"url": "http://x"}), Tier.T0),
            (act("send_message", args={"to": "u", "text": "hi"}), Tier.T1),
            (act("schedule_cron", args={"expr": "* * * * *"}), Tier.T1),
            (act("ssh_exec", args={"cmd": "uptime"}, target="user@host"), Tier.T2),
            (act("mcp_write", args={"k": "v"}), Tier.T2),
            (act("trade", args={"amount": 1}), Tier.T3),
            (act("unknown_tool_xyz", args={}), Tier.T3),
        ]
        for a, expected in cases:
            self.assertEqual(classify(a), expected, f"{a.tool} -> {expected}")

    def test_g2_totality_on_garbage(self):
        garbage = [None, 123, "a string", object(), [], {}, 3.14, b"bytes", True]
        for g in garbage:
            tier = classify(g)  # must not raise
            self.assertIsInstance(tier, Tier)
            self.assertEqual(tier, Tier.T3, f"garbage {g!r} must be T3")

    def test_g2_remote_target_is_t2(self):
        # 203.0.113.7 is in the RFC 5737 documentation range (TEST-NET-3).
        self.assertEqual(classify(act("write_file", target="203.0.113.7")), Tier.T2)
        self.assertEqual(classify(act("write_file", target="u@h")), Tier.T2)

    def test_g2_determinism_1000_runs(self):
        samples = [
            act("read_file", args={"path": "/x"}),
            act("send_message", args={"text": "hello"}),
            act("ssh_exec", args={"cmd": "ls"}, target="u@h"),
            act("trade", args={"amount": 1}),
            act("weird_tool", args={"k": [1, 2, {"n": "v"}]}),
        ]
        baseline = [classify(s) for s in samples]
        for _ in range(1000):
            self.assertEqual([classify(s) for s in samples], baseline)

    def test_g2_arg_order_independent(self):
        a1 = act("mcp_write", args={"a": 1, "b": 2, "c": 3})
        a2 = act("mcp_write", args={"c": 3, "b": 2, "a": 1})
        self.assertEqual(classify(a1), classify(a2))


if __name__ == "__main__":
    unittest.main()
