"""G6 FAIL-CLOSED: injected errors resolve to DENY; bad tokens never ALLOW."""

from __future__ import annotations

import unittest

from tests._helpers import Clock, act, owner
from trust_gate import Gate, Verdict
import trust_gate.gate as gate_module


class _ExplodingLedger:
    """A ledger whose effective_tier always raises."""

    def effective_tier(self, *a, **k):
        raise RuntimeError("boom")


class G6FailClosed(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()

    def test_g6_classifier_exception_denies(self):
        gate = Gate()
        original = gate_module.classify

        def boom(*a, **k):
            raise RuntimeError("classifier exploded")

        gate_module.classify = boom
        try:
            d = gate.evaluate(act("read_file"), ledger=None, now=self.clock)
        finally:
            gate_module.classify = original
        self.assertEqual(d.verdict, Verdict.DENY)

    def test_g6_ledger_exception_denies(self):
        gate = Gate()
        # A benign T1 action, but the ledger blows up during adjustment.
        a = act("send_message", args={"text": "hi"})
        d = gate.evaluate(a, ledger=_ExplodingLedger(), now=self.clock)
        self.assertEqual(d.verdict, Verdict.DENY)

    def test_g6_token_check_exception_never_allows(self):
        gate = Gate()
        # Force the token verifier to raise; a T2 must not become ALLOW.
        orig = gate.tokens.verify_and_consume

        def boom(*a, **k):
            raise RuntimeError("token check exploded")

        gate.tokens.verify_and_consume = boom
        try:
            a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
            d = gate.evaluate(a, confirm_token="whatever", ledger=None, now=self.clock)
        finally:
            gate.tokens.verify_and_consume = orig
        self.assertNotEqual(d.verdict, Verdict.ALLOW)
        self.assertEqual(d.verdict, Verdict.DENY)

    def test_g6_malformed_token_never_allows(self):
        gate = Gate()
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        for bad in ["", "garbage", "no-dot-here", "aa.bb", "....", 12345, None, b"x"]:
            d = gate.evaluate(a, confirm_token=bad, ledger=None, now=self.clock)
            self.assertNotEqual(d.verdict, Verdict.ALLOW, f"token {bad!r}")

    def test_g6_expired_token_never_allows(self):
        gate = Gate()
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        token = gate.issue_confirm_token(a, now=self.clock, ttl_seconds=100)
        self.clock.advance(101)  # expire it
        d = gate.evaluate(a, confirm_token=token, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.CONFIRM_REQUIRED)

    def test_g6_mismatched_token_never_allows(self):
        gate = Gate()
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        other = act("mcp_write", args={"k": "v"}, provenance=owner())
        token_for_other = gate.issue_confirm_token(other, now=self.clock)
        d = gate.evaluate(a, confirm_token=token_for_other, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.CONFIRM_REQUIRED)

    def test_g6_valid_token_is_single_use(self):
        gate = Gate()
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        token = gate.issue_confirm_token(a, now=self.clock, ttl_seconds=300)
        d1 = gate.evaluate(a, confirm_token=token, ledger=None, now=self.clock)
        self.assertEqual(d1.verdict, Verdict.ALLOW)
        # Replay must fail.
        d2 = gate.evaluate(a, confirm_token=token, ledger=None, now=self.clock)
        self.assertEqual(d2.verdict, Verdict.CONFIRM_REQUIRED)

    def test_g6_forged_token_rejected(self):
        # A token minted with a different secret must not validate.
        real = Gate()
        attacker = Gate()  # different random secret
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        forged = attacker.issue_confirm_token(a, now=self.clock, ttl_seconds=300)
        d = real.evaluate(a, confirm_token=forged, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.CONFIRM_REQUIRED)

    def test_g6_happy_path_t2_confirm_allows(self):
        # Sanity: the confirm flow *does* work when everything is valid.
        gate = Gate()
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        d0 = gate.evaluate(a, ledger=None, now=self.clock)
        self.assertEqual(d0.verdict, Verdict.CONFIRM_REQUIRED)
        token = gate.issue_confirm_token(a, now=self.clock, ttl_seconds=300)
        d1 = gate.evaluate(a, confirm_token=token, ledger=None, now=self.clock)
        self.assertEqual(d1.verdict, Verdict.ALLOW)


if __name__ == "__main__":
    unittest.main()
