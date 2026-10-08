"""Optional settings read from environment variables.

The library needs none of this: every value is also a constructor argument. ``Settings`` is for
a service that wants to configure the gate from a ``.env`` file or the process environment.

A bad value raises ``ValueError`` at start-up. It never falls back to something more permissive.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Mapping, Optional, Tuple

from .action_log import ActionLog
from .gate import DEFAULT_UNDO_WINDOW_SECONDS, Gate
from .ledger import TrustLedger
from .tiers import DEFAULT_SPEND_THRESHOLD

ENV_DB = "TRUST_GATE_DB"
ENV_SPEND_THRESHOLD = "TRUST_GATE_SPEND_THRESHOLD"
ENV_UNDO_WINDOW = "TRUST_GATE_UNDO_WINDOW_SECONDS"


@dataclass(frozen=True)
class Settings:
    """Gate settings.

    ``db_path``: SQLite file for the action log and the trust ledger. The default,
    ``":memory:"``, keeps nothing after the process exits.
    ``spend_threshold``: a spend above this amount (or of unknown amount) is T3.
    ``undo_window_seconds``: the undo window reported with an allowed T1 action.
    """

    db_path: str = ":memory:"
    spend_threshold: float = DEFAULT_SPEND_THRESHOLD
    undo_window_seconds: int = DEFAULT_UNDO_WINDOW_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.db_path, str) or not self.db_path.strip():
            raise ValueError("db_path must be a non-empty string")
        if isinstance(self.spend_threshold, bool) or not isinstance(
            self.spend_threshold, (int, float)
        ):
            raise ValueError("spend_threshold must be a number")
        if not math.isfinite(self.spend_threshold) or self.spend_threshold < 0:
            raise ValueError("spend_threshold must be a finite number >= 0")
        if (
            isinstance(self.undo_window_seconds, bool)
            or not isinstance(self.undo_window_seconds, int)
            or self.undo_window_seconds < 0
        ):
            raise ValueError("undo_window_seconds must be an integer >= 0")

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "Settings":
        """Read the settings from ``environ`` (default: ``os.environ``).

        A variable that is unset or empty keeps its default.
        """
        env = os.environ if environ is None else environ
        kwargs = {}

        db_path = _value(env, ENV_DB)
        if db_path is not None:
            kwargs["db_path"] = db_path

        threshold = _value(env, ENV_SPEND_THRESHOLD)
        if threshold is not None:
            try:
                kwargs["spend_threshold"] = float(threshold)
            except ValueError:
                raise ValueError(f"{ENV_SPEND_THRESHOLD} must be a number") from None

        undo = _value(env, ENV_UNDO_WINDOW)
        if undo is not None:
            try:
                kwargs["undo_window_seconds"] = int(undo)
            except ValueError:
                raise ValueError(f"{ENV_UNDO_WINDOW} must be an integer") from None

        return cls(**kwargs)

    def open(self) -> Tuple[Gate, TrustLedger]:
        """Open the database and return ``(gate, ledger)``.

        The gate writes allowed actions to the action log. Close both when you are done:
        ``ledger.close()`` and ``gate.action_log.close()``.
        """
        log = ActionLog(self.db_path)
        try:
            ledger = TrustLedger(self.db_path)
        except Exception:
            log.close()
            raise
        gate = Gate(
            action_log=log,
            spend_threshold=self.spend_threshold,
            undo_window_seconds=self.undo_window_seconds,
        )
        return gate, ledger


def _value(env: Mapping[str, str], name: str) -> Optional[str]:
    raw = env.get(name)
    if raw is None:
        return None
    raw = str(raw).strip()
    return raw or None
