"""Shared test helpers: sys.path bootstrap + a deterministic clock."""

from __future__ import annotations

import os
import sys

# Make the package importable regardless of how discover was invoked.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from trust_gate import Action, ActionLog, Provenance, Source, TrustLedger  # noqa: E402


class Clock:
    """A settable, deterministic clock. Call the instance to read 'now'."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = float(start)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> "Clock":
        self.t += float(seconds)
        return self

    def set(self, seconds: float) -> "Clock":
        self.t = float(seconds)
        return self


DAY = 86400.0


def owner(*sources):
    """Build a Provenance justified by the OWNER (default) or given sources."""
    if not sources:
        sources = (Source.OWNER,)
    return Provenance(sources=tuple(sources))


def act(tool, *, args=None, target=None, provenance=None, actor="agent",
        idempotency_key=None):
    """Concise Action factory for tests."""
    return Action(
        tool=tool,
        args=args or {},
        target=target,
        provenance=provenance if provenance is not None else owner(),
        actor=actor,
        idempotency_key=idempotency_key,
    )


def open_log(case, db_path=":memory:"):
    """An ActionLog that the test case closes when it finishes."""
    log = ActionLog(db_path)
    case.addCleanup(log.close)
    return log


def open_ledger(case, clock, db_path=":memory:"):
    """A TrustLedger that the test case closes when it finishes."""
    ledger = TrustLedger(db_path, clock=clock)
    case.addCleanup(ledger.close)
    return ledger
