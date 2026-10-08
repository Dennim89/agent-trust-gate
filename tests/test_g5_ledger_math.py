"""G5 LEDGER-MATH: promotion/demotion arithmetic via the injected clock."""

from __future__ import annotations

import unittest

from tests._helpers import DAY, Clock, open_ledger
from trust_gate import Tier
from trust_gate.ledger import FREEZE_SECONDS, PROMO_N


class G5LedgerMath(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.ledger = open_ledger(self, self.clock)

    def test_g5_20_confirms_promote_exactly_one_tier(self):
        cls, base = "ssh_exec", Tier.T2
        for _ in range(PROMO_N):
            self.ledger.record_success(cls, base, now=self.clock())
        row = self.ledger.get(cls)
        self.assertEqual(row.tier, int(Tier.T1), "20 clean confirms => up one tier")
        self.assertEqual(row.successes, 0, "streak consumed on promotion")

    def test_g5_19_confirms_do_not_promote(self):
        cls, base = "ssh_exec", Tier.T2
        for _ in range(PROMO_N - 1):
            self.ledger.record_success(cls, base, now=self.clock())
        row = self.ledger.get(cls)
        self.assertEqual(row.tier, int(Tier.T2), "19 confirms must NOT promote")
        self.assertEqual(row.successes, 19)

    def test_g5_promotion_is_only_one_tier(self):
        # 40 confirms should promote at most... one tier per completed streak of 20.
        cls, base = "ssh_exec", Tier.T2
        for _ in range(40):
            self.ledger.record_success(cls, base, now=self.clock())
        # After 20 -> T1 (streak reset). Next 20 -> T0. So exactly two steps over 40.
        self.assertEqual(self.ledger.get(cls).tier, int(Tier.T0))

    def test_g5_window_expiry_resets_streak(self):
        cls, base = "ssh_exec", Tier.T2
        for _ in range(19):
            self.ledger.record_success(cls, base, now=self.clock())
        # Jump beyond the 30-day window before the 20th confirm.
        self.clock.advance(31 * DAY)
        self.ledger.record_success(cls, base, now=self.clock())
        row = self.ledger.get(cls)
        self.assertEqual(row.tier, int(Tier.T2), "stale streak must not promote")
        self.assertEqual(row.successes, 1, "streak restarted inside a fresh window")

    def test_g5_single_incident_demotes_two_tiers(self):
        cls, base = "send_message", Tier.T1
        self.ledger.record_incident(cls, base, now=self.clock())
        row = self.ledger.get(cls)
        self.assertEqual(row.tier, int(Tier.T3), "T1 + 2 => T3")
        self.assertEqual(row.successes, 0, "streak reset on incident")
        self.assertEqual(
            row.promotion_frozen_until, self.clock() + FREEZE_SECONDS,
        )

    def test_g5_single_override_demotes_two_tiers(self):
        cls, base = "ssh_exec", Tier.T2
        self.ledger.record_override(cls, base, now=self.clock())
        row = self.ledger.get(cls)
        self.assertEqual(row.tier, int(Tier.T3), "T2 + 2 => T3 (capped)")

    def test_g5_demotion_freezes_promotion_14_days(self):
        cls, base = "ssh_exec", Tier.T2
        # Demote T2 -> T3 wait: T2 is not T3-origin so it can re-promote after freeze.
        # Use a class that started at T2 but base allows promotion. Demote then confirm.
        self.ledger.record_override(cls, base, now=self.clock())
        # During the 14-day freeze, 20 confirms must NOT promote.
        for _ in range(PROMO_N):
            self.clock.advance(1)
            self.ledger.record_success(cls, base, now=self.clock())
        self.assertTrue(self.ledger.is_frozen(cls, now=self.clock()))
        # tier stays at the demoted T3 while frozen.
        self.assertEqual(self.ledger.get(cls).tier, int(Tier.T3))

    def test_g5_promotion_resumes_after_freeze(self):
        cls, base = "ssh_exec", Tier.T2
        self.ledger.record_override(cls, base, now=self.clock())  # -> T3, frozen 14d
        self.clock.advance(FREEZE_SECONDS + 1)  # past the freeze
        for _ in range(PROMO_N):
            self.clock.advance(1)
            self.ledger.record_success(cls, base, now=self.clock())
        # base_tier is T2 (not T3-origin) so it may promote out of the demoted T3.
        self.assertEqual(self.ledger.get(cls).tier, int(Tier.T2), "T3 -> T2 after freeze")

    def test_g5_t3_class_never_auto_promotes(self):
        cls, base = "trade", Tier.T3
        for _ in range(100):
            self.clock.advance(1)
            self.ledger.record_success(cls, base, now=self.clock())
        self.assertEqual(
            self.ledger.get(cls).tier, int(Tier.T3),
            "a T3-origin class never auto-promotes out of T3",
        )

    def test_g5_demotion_floors_at_t3(self):
        cls, base = "trade", Tier.T3
        self.ledger.record_incident(cls, base, now=self.clock())
        self.assertEqual(self.ledger.get(cls).tier, int(Tier.T3), "cannot exceed T3")


if __name__ == "__main__":
    unittest.main()
