"""Append-only, immutable action log + canonical action hashing.

Guarantees (G4):
  * The public API exposes NO update or delete path. Once appended, a record is frozen.
  * A repeated ``idempotency_key`` never double-records and never double-executes: the
    prior record is returned unchanged.
  * ``hash_action`` is stable for equal actions and differs for different actions.

The log stores, per entry: a monotonic id, timestamp, a canonical repr of the action,
before/after state hashes (opaque to this library -- supplied by the executor), the
actor (human|agent), the enforced tier, the idempotency key, and the outcome.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional


# --------------------------------------------------------------------------------------
# Canonicalization + hashing
# --------------------------------------------------------------------------------------

def _canonicalize(value: Any) -> Any:
    """Recursively convert a value into a deterministic, JSON-safe structure.

    Dict keys are sorted at serialization time; enums become their ``.value``; anything
    exotic falls back to ``str``. This makes equal actions hash identically regardless of
    dict insertion order.
    """
    from enum import Enum

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _canonicalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def canonical_repr(action: Any) -> str:
    """Deterministic canonical string for an action.

    Only the load-bearing fields participate (tool, args, target, provenance sources,
    actor). Insertion order is irrelevant because keys are sorted.
    """
    # Import here to avoid a circular import at module load time.
    from .tiers import Action

    if isinstance(action, Action):
        payload = {
            "tool": str(action.tool),
            "args": _canonicalize(action.args),
            "target": action.target,
            "provenance": sorted(s.value for s in action.provenance.sources),
            "actor": action.actor,
        }
    else:
        # Unknown shape -> canonicalize whatever it is (fail-closed determinism).
        payload = {"raw": _canonicalize(action)}

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hash_action(action: Any) -> str:
    """SHA-256 hex digest over the canonical representation of an action."""
    return hashlib.sha256(canonical_repr(action).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------
# The append-only log
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class LogRecord:
    """An immutable log entry."""

    id: int
    ts: float
    action_repr: str
    before_state_hash: Optional[str]
    after_state_hash: Optional[str]
    actor: str
    tier: int
    idempotency_key: str
    outcome: str


class ActionLog:
    """Append-only SQLite-backed action log.

    There is deliberately no ``update``/``delete``/``clear`` method on this class. The
    UNIQUE constraint on ``idempotency_key`` enforces exactly-once semantics at the DB
    level in addition to the in-code guard.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        # check_same_thread=False keeps things simple for tests; this library is not a
        # concurrency primitive.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_log (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                ts                 REAL    NOT NULL,
                action_repr        TEXT    NOT NULL,
                before_state_hash  TEXT,
                after_state_hash   TEXT,
                actor              TEXT    NOT NULL,
                tier               INTEGER NOT NULL,
                idempotency_key    TEXT    NOT NULL UNIQUE,
                outcome            TEXT    NOT NULL
            )
            """
        )
        self._conn.commit()

    # -- read ---------------------------------------------------------------------

    def get_by_idempotency_key(self, key: str) -> Optional[LogRecord]:
        row = self._conn.execute(
            "SELECT * FROM action_log WHERE idempotency_key = ?", (key,)
        ).fetchone()
        return self._row_to_record(row) if row else None

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM action_log").fetchone()[0])

    def all(self) -> list[LogRecord]:
        rows = self._conn.execute("SELECT * FROM action_log ORDER BY id").fetchall()
        return [self._row_to_record(r) for r in rows]

    # -- append (the ONLY mutation, and it is monotonic) --------------------------

    def append(
        self,
        *,
        ts: float,
        action_repr: str,
        actor: str,
        tier: int,
        idempotency_key: str,
        outcome: str,
        before_state_hash: Optional[str] = None,
        after_state_hash: Optional[str] = None,
    ) -> tuple[LogRecord, bool]:
        """Append a record, or return the existing one for a duplicate key.

        Returns ``(record, created)`` where ``created`` is False when the
        ``idempotency_key`` was already present (dedup -> no double execution).
        """
        existing = self.get_by_idempotency_key(idempotency_key)
        if existing is not None:
            return existing, False

        try:
            cur = self._conn.execute(
                """
                INSERT INTO action_log
                    (ts, action_repr, before_state_hash, after_state_hash,
                     actor, tier, idempotency_key, outcome)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts, action_repr, before_state_hash, after_state_hash,
                    actor, int(tier), idempotency_key, outcome,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            # Lost a race on the UNIQUE key -> return the winner. Still exactly-once.
            existing = self.get_by_idempotency_key(idempotency_key)
            if existing is not None:
                return existing, False
            raise

        record = self.get_by_idempotency_key(idempotency_key)
        assert record is not None  # just inserted
        return record, True

    # -- helpers ------------------------------------------------------------------

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> LogRecord:
        return LogRecord(
            id=row["id"],
            ts=row["ts"],
            action_repr=row["action_repr"],
            before_state_hash=row["before_state_hash"],
            after_state_hash=row["after_state_hash"],
            actor=row["actor"],
            tier=row["tier"],
            idempotency_key=row["idempotency_key"],
            outcome=row["outcome"],
        )

    def close(self) -> None:
        self._conn.close()
