"""The trust ledger -- earned autonomy, per action class.

A class's *effective* tier can drift over time based on lived experience:

  Promotion (earn autonomy, tier number DECREASES by 1):
      20 consecutive clean, owner-confirmed successes, all within a 30-day window,
      AND zero overrides during that streak, AND the class is not frozen,
      AND the class did not originate as T3 (T3 never auto-promotes out of T3).

  Demotion (lose autonomy, tier number INCREASES by 2, capped at T3):
      A SINGLE incident OR a SINGLE override immediately drops the class two tiers,
      freezes promotion for 14 days, and resets the success streak.

All time arithmetic uses an injected ``clock`` callable (default ``time.time``) so tests
are fully deterministic; the enforcement logic never reads the wall clock directly.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .tiers import Tier


PROMO_N = 20                     # consecutive clean confirms required to promote
PROMO_WINDOW_SECONDS = 30 * 86400  # the streak must fit inside 30 days
FREEZE_SECONDS = 14 * 86400      # promotion freeze after an incident/override
DEMOTION_STEP = 2                # tiers dropped per incident/override


@dataclass(frozen=True)
class LedgerRow:
    action_class: str
    base_tier: int
    tier: int
    successes: int               # current streak length
    streak_start_ts: Optional[float]
    overrides: int               # cumulative override/incident count
    last_incident_ts: Optional[float]
    promotion_frozen_until: Optional[float]
    updated_at: float


class TrustLedger:
    """SQLite-backed per-class trust state with promotion/demotion rules."""

    def __init__(
        self,
        db_path: str = ":memory:",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_ledger (
                action_class            TEXT PRIMARY KEY,
                base_tier               INTEGER NOT NULL,
                tier                    INTEGER NOT NULL,
                successes               INTEGER NOT NULL DEFAULT 0,
                streak_start_ts         REAL,
                overrides               INTEGER NOT NULL DEFAULT 0,
                last_incident_ts        REAL,
                promotion_frozen_until  REAL,
                updated_at              REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    # -- helpers ------------------------------------------------------------------

    def _now(self, now: Optional[float]) -> float:
        return float(now) if now is not None else float(self._clock())

    def _row(self, action_class: str) -> Optional[LedgerRow]:
        r = self._conn.execute(
            "SELECT * FROM trust_ledger WHERE action_class = ?", (action_class,)
        ).fetchone()
        if r is None:
            return None
        return LedgerRow(
            action_class=r["action_class"],
            base_tier=r["base_tier"],
            tier=r["tier"],
            successes=r["successes"],
            streak_start_ts=r["streak_start_ts"],
            overrides=r["overrides"],
            last_incident_ts=r["last_incident_ts"],
            promotion_frozen_until=r["promotion_frozen_until"],
            updated_at=r["updated_at"],
        )

    def _ensure(self, action_class: str, base_tier: Tier, now: float) -> LedgerRow:
        row = self._row(action_class)
        if row is not None:
            return row
        self._conn.execute(
            """
            INSERT INTO trust_ledger
                (action_class, base_tier, tier, successes, streak_start_ts,
                 overrides, last_incident_ts, promotion_frozen_until, updated_at)
            VALUES (?, ?, ?, 0, NULL, 0, NULL, NULL, ?)
            """,
            (action_class, int(base_tier), int(base_tier), now),
        )
        self._conn.commit()
        row = self._row(action_class)
        assert row is not None
        return row

    def _write(self, row: LedgerRow) -> None:
        self._conn.execute(
            """
            UPDATE trust_ledger SET
                base_tier = ?, tier = ?, successes = ?, streak_start_ts = ?,
                overrides = ?, last_incident_ts = ?, promotion_frozen_until = ?,
                updated_at = ?
            WHERE action_class = ?
            """,
            (
                row.base_tier, row.tier, row.successes, row.streak_start_ts,
                row.overrides, row.last_incident_ts, row.promotion_frozen_until,
                row.updated_at, row.action_class,
            ),
        )
        self._conn.commit()

    # -- public read --------------------------------------------------------------

    def get(self, action_class: str) -> Optional[LedgerRow]:
        return self._row(action_class)

    def effective_tier(
        self,
        action_class: str,
        base_tier: Tier,
        now: Optional[float] = None,
    ) -> Tier:
        """The tier the gate should enforce for this class.

        If the class has a ledger row, its earned/penalized ``tier`` is used; otherwise
        the freshly classified ``base_tier`` applies. (The gate additionally overrides
        this with T3 whenever a fresh classification is dangerous -- earned trust can
        never relax a genuinely dangerous action.)

        Cross-shape guard: trust is earned against a *specific* base risk (the
        ``base_tier`` recorded on the row). Because the ledger is keyed only on the tool
        name, the SAME tool can appear later in a higher-risk shape (e.g. a local T1
        ``send_message`` promoted to T0, then reused against a remote target where the
        fresh classification is T2). Spending the low-risk relaxation on that higher-risk
        shape is a privilege escalation. So whenever the current ``base_tier`` is riskier
        (numerically higher) than the base the row's trust was accumulated on, we clamp:
        the enforced tier can never be *less restrictive* than the fresh ``base_tier``.
        A penalty (row.tier more restrictive) is always honored.
        """
        row = self._row(action_class)
        if row is None:
            return base_tier
        stored = Tier(row.tier)
        if row.base_tier < int(base_tier):
            # Earned relaxation does not transfer to a higher-risk shape.
            return Tier(max(int(stored), int(base_tier)))
        return stored

    def is_frozen(self, action_class: str, now: Optional[float] = None) -> bool:
        row = self._row(action_class)
        if row is None or row.promotion_frozen_until is None:
            return False
        return self._now(now) < row.promotion_frozen_until

    # -- mutations ----------------------------------------------------------------

    def record_success(
        self,
        action_class: str,
        base_tier: Tier,
        now: Optional[float] = None,
    ) -> LedgerRow:
        """Record one clean, owner-confirmed success and promote if earned."""
        t = self._now(now)
        row = self._ensure(action_class, base_tier, t)

        streak = row.successes
        streak_start = row.streak_start_ts

        # Start or restart the 30-day window as needed.
        if streak == 0 or streak_start is None:
            streak_start = t
        elif (t - streak_start) > PROMO_WINDOW_SECONDS:
            # The window elapsed; this success begins a fresh streak.
            streak = 0
            streak_start = t

        streak += 1

        tier = row.tier
        frozen = (
            row.promotion_frozen_until is not None
            and t < row.promotion_frozen_until
        )
        window_ok = (t - streak_start) <= PROMO_WINDOW_SECONDS
        can_promote = (
            streak >= PROMO_N
            and window_ok
            and not frozen
            and row.base_tier != int(Tier.T3)   # T3 classes never auto-promote out
            and tier > int(Tier.T0)             # cannot go above maximum trust
        )

        if can_promote:
            tier = tier - 1
            # Consume the streak; the next promotion must be re-earned.
            streak = 0
            streak_start = None

        updated = LedgerRow(
            action_class=row.action_class,
            base_tier=row.base_tier,
            tier=tier,
            successes=streak,
            streak_start_ts=streak_start,
            overrides=row.overrides,
            last_incident_ts=row.last_incident_ts,
            promotion_frozen_until=row.promotion_frozen_until,
            updated_at=t,
        )
        self._write(updated)
        return updated

    def record_incident(
        self,
        action_class: str,
        base_tier: Tier,
        now: Optional[float] = None,
    ) -> LedgerRow:
        """Record an incident OR an override: demote 2 tiers, freeze, reset streak."""
        t = self._now(now)
        row = self._ensure(action_class, base_tier, t)

        new_tier = min(int(Tier.T3), row.tier + DEMOTION_STEP)

        updated = LedgerRow(
            action_class=row.action_class,
            base_tier=row.base_tier,
            tier=new_tier,
            successes=0,                         # reset the streak
            streak_start_ts=None,
            overrides=row.overrides + 1,
            last_incident_ts=t,
            promotion_frozen_until=t + FREEZE_SECONDS,
            updated_at=t,
        )
        self._write(updated)
        return updated

    # An override is treated identically to an incident for demotion purposes.
    record_override = record_incident

    def close(self) -> None:
        self._conn.close()
