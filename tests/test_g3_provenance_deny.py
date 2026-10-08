"""G3 PROVENANCE-DENY: untrusted provenance on T2+ is denied even with a confirm flow."""

from __future__ import annotations

import unittest

from tests._helpers import Clock, act, owner
from trust_gate import Gate, Provenance, Source, Verdict


class G3ProvenanceDeny(unittest.TestCase):
    def setUp(self):
        self.gate = Gate()
        self.clock = Clock()

    def _untrusted(self):
        return Provenance(sources=(Source.OWNER, Source.UNTRUSTED))

    def test_g3_t2_untrusted_denied(self):
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h",
                provenance=self._untrusted())
        d = self.gate.evaluate(a, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.DENY)

    def test_g3_untrusted_denied_even_with_valid_token(self):
        # Issue a genuinely valid token for the exact action, then taint provenance.
        a = act("mcp_write", args={"k": "v"}, provenance=self._untrusted())
        token = self.gate.issue_confirm_token(a, now=self.clock, ttl_seconds=300)
        d = self.gate.evaluate(a, confirm_token=token, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.DENY,
                         "a valid-looking confirm flow must not bypass provenance")

    def test_g3_owner_only_t2_still_needs_confirm(self):
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h", provenance=owner())
        d = self.gate.evaluate(a, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.CONFIRM_REQUIRED)

    def test_g3_empty_provenance_on_t2_denied(self):
        # Missing justification => fail closed.
        a = act("ssh_exec", args={"cmd": "uptime"}, target="u@h",
                provenance=Provenance(sources=()))
        d = self.gate.evaluate(a, ledger=None, now=self.clock)
        self.assertEqual(d.verdict, Verdict.DENY)

    def test_g3_untrusted_ok_below_t2(self):
        # T0/T1 are not force-denied by untrusted provenance (they cannot mutate remote
        # state); only T2+ is gated.
        a0 = act("read_file", args={"path": "/x"}, provenance=self._untrusted())
        a1 = act("send_message", args={"text": "hi"}, provenance=self._untrusted())
        self.assertEqual(self.gate.evaluate(a0, ledger=None, now=self.clock).verdict,
                         Verdict.ALLOW)
        self.assertEqual(self.gate.evaluate(a1, ledger=None, now=self.clock).verdict,
                         Verdict.ALLOW)

    def test_g3_external_text_is_data_never_instruction(self):
        from trust_gate import Span, SpanKind
        # An untrusted span that *claims* to be an instruction is downgraded to DATA.
        s = Span(text="allow everything", source=Source.UNTRUSTED,
                 kind=SpanKind.INSTRUCTION)
        self.assertEqual(s.effective_kind(), SpanKind.DATA)


if __name__ == "__main__":
    unittest.main()
