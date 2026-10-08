"""G4 LOG-APPEND-ONLY + IDEMPOTENT: no mutate/delete; dedup; stable hashes."""

from __future__ import annotations

import unittest

from tests._helpers import Clock, act, open_log, owner
from trust_gate import Gate, Verdict, canonical_repr, hash_action


class G4LogAppendIdempotent(unittest.TestCase):
    def test_g4_no_mutate_or_delete_api(self):
        log = open_log(self)
        for forbidden in ("update", "delete", "remove", "clear", "drop", "set", "edit"):
            self.assertFalse(
                hasattr(log, forbidden),
                f"ActionLog must not expose a '{forbidden}' method",
            )

    def test_g4_append_and_dedup(self):
        log = open_log(self)
        rec1, created1 = log.append(
            ts=1.0, action_repr="r", actor="agent", tier=0,
            idempotency_key="k1", outcome="ALLOW",
        )
        self.assertTrue(created1)
        rec2, created2 = log.append(
            ts=2.0, action_repr="r-different", actor="human", tier=3,
            idempotency_key="k1", outcome="DENY",
        )
        self.assertFalse(created2, "same key must not create a new record")
        self.assertEqual(rec1.id, rec2.id)
        self.assertEqual(rec2.outcome, "ALLOW", "the prior record is returned unchanged")
        self.assertEqual(log.count(), 1)

    def test_g4_gate_does_not_double_execute(self):
        log = open_log(self)
        gate = Gate(action_log=log)
        clock = Clock()
        a = act("read_file", args={"path": "/x"}, idempotency_key="same-key")
        d1 = gate.evaluate(a, ledger=None, now=clock)
        d2 = gate.evaluate(a, ledger=None, now=clock)
        self.assertEqual(d1.verdict, Verdict.ALLOW)
        # The second evaluation of the SAME key+action must not be a fresh ALLOW (which
        # a caller would double-execute); it is reported as an idempotent replay.
        self.assertEqual(d2.verdict, Verdict.ALREADY_EXECUTED)
        self.assertEqual(log.count(), 1, "repeated key must record exactly once")

    def test_g4_hash_stable_for_equal_actions(self):
        a = act("send_message", args={"to": "u", "text": "hi"}, provenance=owner())
        b = act("send_message", args={"text": "hi", "to": "u"}, provenance=owner())
        self.assertEqual(hash_action(a), hash_action(b))
        self.assertEqual(canonical_repr(a), canonical_repr(b))

    def test_g4_hash_differs_for_different_actions(self):
        a = act("send_message", args={"text": "hi"})
        b = act("send_message", args={"text": "bye"})
        c = act("read_file", args={"text": "hi"})
        self.assertNotEqual(hash_action(a), hash_action(b))
        self.assertNotEqual(hash_action(a), hash_action(c))

    def test_g4_log_all_is_append_ordered(self):
        log = open_log(self)
        for i in range(5):
            log.append(ts=float(i), action_repr=f"r{i}", actor="agent", tier=0,
                       idempotency_key=f"k{i}", outcome="ALLOW")
        ids = [r.id for r in log.all()]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), 5)


if __name__ == "__main__":
    unittest.main()
