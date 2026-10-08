"""The interceptor: the deterministic boundary between decision and execution.

``Gate.evaluate`` is a PURE function of (action, ledger state, confirm tokens, clock). It
never consults any attacker-controllable free-text field. Its verdict:

    T0                 -> ALLOW               (read-only; logged after)
    T1                 -> ALLOW               (reversible; an undo window is recorded)
    T2                 -> CONFIRM_REQUIRED, unless a valid, single-use, non-forgeable
                          confirm token bound to THIS exact action is presented -> ALLOW
    T3                 -> DENY                (never autonomous; a DRAFT marker is offered
                          for out-of-band human approve+deploy)
    UNTRUSTED prov.    -> DENY on any T2+ action, overriding everything else
    any exception      -> DENY                (fail closed)

Confirm tokens are HMAC-signed over a hash of the exact action plus an expiry and a
single-use nonce. A forged, expired, mismatched, or replayed token can never yield ALLOW.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Set

from .action_log import ActionLog, canonical_repr, hash_action
from .ledger import TrustLedger
from .tiers import Action, Tier, action_class_key, classify


# --------------------------------------------------------------------------------------
# Decision types
# --------------------------------------------------------------------------------------

class Verdict(Enum):
    ALLOW = "ALLOW"
    CONFIRM_REQUIRED = "CONFIRM_REQUIRED"
    DENY = "DENY"
    # A key whose exact action already executed. Distinct from ALLOW so a caller
    # trusting the verdict cannot be tricked into a second (double) execution.
    ALREADY_EXECUTED = "ALREADY_EXECUTED"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    tier: Tier
    reason: str
    action_class: str
    # Extra, non-authoritative metadata for the caller/UI.
    undo_window_seconds: Optional[int] = None
    draft: bool = False
    action_hash: Optional[str] = None


# Default: T1 undo window (seconds) recorded alongside an auto-allowed reversible action.
DEFAULT_UNDO_WINDOW_SECONDS = 30


# --------------------------------------------------------------------------------------
# Confirm tokens
# --------------------------------------------------------------------------------------

@dataclass
class ConfirmTokenService:
    """Issues and verifies single-use, action-bound, expiring confirm tokens.

    Security properties:
      * Non-forgeable: an HMAC over (action_hash, exp, nonce) with a server secret.
        Without the secret an attacker cannot mint a token.
      * Action-bound: the token embeds the hash of the exact action; presenting it for a
        different action fails.
      * Expiring: ``exp`` is checked against the injected clock.
      * Single-use: a consumed nonce is remembered and rejected on replay.
    """

    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _consumed: Set[str] = field(default_factory=set)

    def _sign(self, body: bytes) -> str:
        return hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    def issue(self, action: Any, *, expires_at: float) -> str:
        """Mint a token for ``action`` that is valid until ``expires_at``."""
        payload = {
            "ah": hash_action(action),
            "exp": float(expires_at),
            "nonce": secrets.token_hex(16),
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = self._sign(body)
        return body.hex() + "." + sig

    def verify_and_consume(self, action: Any, token: Any, *, now: float) -> bool:
        """Return True and consume the nonce iff the token is valid for this action.

        Fail-closed: any malformed structure, bad signature, wrong action, expiry, or
        replay returns False. Never raises.
        """
        try:
            if not isinstance(token, str) or "." not in token:
                return False
            body_hex, sig = token.rsplit(".", 1)
            body = bytes.fromhex(body_hex)

            # Constant-time signature check first (reject forgeries).
            expected = self._sign(body)
            if not hmac.compare_digest(expected, sig):
                return False

            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                return False

            # Action binding.
            if payload.get("ah") != hash_action(action):
                return False

            # Expiry.
            exp = payload.get("exp")
            if not isinstance(exp, (int, float)) or now >= float(exp):
                return False

            # Single-use.
            nonce = payload.get("nonce")
            if not isinstance(nonce, str) or nonce in self._consumed:
                return False

            self._consumed.add(nonce)
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------------------

class Gate:
    """The interceptor. One instance guards a stream of proposed actions."""

    def __init__(
        self,
        *,
        action_log: Optional[ActionLog] = None,
        tokens: Optional[ConfirmTokenService] = None,
        spend_threshold: float = 0.0,
        undo_window_seconds: int = DEFAULT_UNDO_WINDOW_SECONDS,
    ) -> None:
        self.action_log = action_log
        self.tokens = tokens or ConfirmTokenService()
        self.spend_threshold = spend_threshold
        self.undo_window_seconds = undo_window_seconds

    # -- token issuance convenience ----------------------------------------------

    def issue_confirm_token(
        self, action: Any, *, now: Callable[[], float] | float, ttl_seconds: float = 300
    ) -> str:
        t = now() if callable(now) else float(now)
        return self.tokens.issue(action, expires_at=t + ttl_seconds)

    # -- the verdict --------------------------------------------------------------

    def evaluate(
        self,
        action: Any,
        *,
        confirm_token: Any = None,
        ledger: Optional[TrustLedger] = None,
        now: Callable[[], float] | float = time.time,
    ) -> Decision:
        """Return a ``Decision``. Total and fail-closed: any error yields DENY."""
        # The entire body is wrapped so that ANY unexpected failure denies.
        try:
            t = now() if callable(now) else float(now)

            cls = action_class_key(action)

            # (0) Idempotency / replay + collision guard. If an action_log is attached
            #     and this action's idempotency key already recorded an executed
            #     (ALLOWED) action, we must NOT return a fresh ALLOW for it -- that would
            #     let a caller double-execute -- and a DIFFERENT action must NOT be able
            #     to ride a colliding key (which would execute without an audit trace).
            if self.action_log is not None:
                idem = self._idempotency_guard(action, cls)
                if idem is not None:
                    return idem

            # (A) Fresh, danger-aware classification. This is the honest tier and can
            #     never be relaxed below T3 for a genuinely dangerous action.
            base = classify(action, spend_threshold=self.spend_threshold)

            # (B) Provenance hard gate on the HONEST tier. Untrusted (or unjustified)
            #     content on any T2+ action is denied before anything else can relax it.
            if base >= Tier.T2 and not self._provenance_ok(action):
                return self._deny(
                    base, cls, action,
                    "untrusted or unjustified provenance on a T2+ action",
                )

            # (C) Ledger adjustment. Earned trust may relax a NON-dangerous tier; a
            #     penalty may further restrict it. A fresh T3 is never adjusted.
            enforce = base
            if base != Tier.T3 and ledger is not None:
                try:
                    enforce = ledger.effective_tier(cls, base, now=t)
                except Exception:
                    # A broken ledger must not open the gate.
                    return self._deny(base, cls, action, "ledger error (fail closed)")

            # (D) Re-apply the provenance gate against the ENFORCED tier too, so a
            #     penalty that pushed a T1 up to T3 still denies, and a relaxation can
            #     never dodge the untrusted check.
            if enforce >= Tier.T2 and not self._provenance_ok(action):
                return self._deny(
                    enforce, cls, action,
                    "untrusted or unjustified provenance on a T2+ action",
                )

            # (E) Dispatch on the enforced tier.
            if enforce <= Tier.T0:
                return self._allow(enforce, cls, action, t, "read-only")

            if enforce == Tier.T1:
                return self._allow(
                    enforce, cls, action, t, "reversible side effect",
                    undo_window=self.undo_window_seconds,
                )

            if enforce == Tier.T2:
                ok = False
                if confirm_token is not None:
                    ok = self.tokens.verify_and_consume(action, confirm_token, now=t)
                if ok:
                    return self._allow(
                        enforce, cls, action, t, "external mutation (confirmed)",
                    )
                return Decision(
                    verdict=Verdict.CONFIRM_REQUIRED,
                    tier=enforce,
                    reason="external mutation requires a valid single-use confirm token",
                    action_class=cls,
                    action_hash=self._safe_hash(action),
                )

            # enforce == Tier.T3 (or anything unexpectedly higher)
            return self._deny(
                enforce, cls, action,
                "dangerous or unknown action -- draft only, human approves out of band",
                draft=True,
            )
        except Exception:
            # Absolutely nothing escapes without a DENY.
            return Decision(
                verdict=Verdict.DENY,
                tier=Tier.T3,
                reason="fail-closed: unexpected error during evaluation",
                action_class="unknown",
            )

    # -- internals ----------------------------------------------------------------

    def _log_key(self, action: Any) -> Optional[str]:
        """The idempotency key this action logs under (explicit key, else action hash).

        Must mirror ``_log`` exactly so the guard and the append agree on the key.
        """
        if isinstance(action, Action) and action.idempotency_key:
            return action.idempotency_key
        return self._safe_hash(action)

    def _idempotency_guard(self, action: Any, cls: str) -> Optional[Decision]:
        """Return a Decision if this key was already used to execute an action.

        * Same key + IDENTICAL action  -> ALREADY_EXECUTED (idempotent replay; do not
          re-run). This is deliberately NOT a fresh ALLOW.
        * Same key + DIFFERENT action  -> DENY (idempotency-key collision; fail closed,
          so a forged key cannot smuggle an un-logged side effect through).
        * No prior record              -> None (proceed with normal evaluation).

        Fail-closed: any error denies rather than silently allowing.
        """
        try:
            key = self._log_key(action)
            if key is None:
                return None
            existing = self.action_log.get_by_idempotency_key(key)
            if existing is None:
                return None
            if existing.action_repr == canonical_repr(action):
                return Decision(
                    verdict=Verdict.ALREADY_EXECUTED,
                    tier=Tier(existing.tier),
                    reason="idempotent replay: this exact action already executed",
                    action_class=cls,
                    action_hash=self._safe_hash(action),
                )
            return Decision(
                verdict=Verdict.DENY,
                tier=Tier.T3,
                reason="idempotency-key collision: key already bound to a different action",
                action_class=cls,
                action_hash=self._safe_hash(action),
            )
        except Exception:
            return Decision(
                verdict=Verdict.DENY,
                tier=Tier.T3,
                reason="fail-closed: idempotency guard error",
                action_class=cls,
            )

    @staticmethod
    def _provenance_ok(action: Any) -> bool:
        """True only if provenance is present and entirely owner-trusted."""
        try:
            prov = getattr(action, "provenance", None)
            if prov is None:
                return False
            if prov.has_untrusted():
                return False
            return prov.owner_justified()
        except Exception:
            return False

    @staticmethod
    def _safe_hash(action: Any) -> Optional[str]:
        try:
            return hash_action(action)
        except Exception:
            return None

    def _log(self, action: Any, tier: Tier, t: float, outcome: str) -> None:
        if self.action_log is None:
            return
        try:
            key = self._log_key(action)
            if key is None:
                key = hash_action(action)
            actor = getattr(action, "actor", "agent")
            self.action_log.append(
                ts=t,
                action_repr=canonical_repr(action),
                actor=actor,
                tier=int(tier),
                idempotency_key=key,
                outcome=outcome,
            )
        except Exception:
            # Logging must never turn an ALLOW into a crash; the verdict already stands.
            pass

    def _allow(
        self,
        tier: Tier,
        cls: str,
        action: Any,
        t: float,
        reason: str,
        *,
        undo_window: Optional[int] = None,
    ) -> Decision:
        self._log(action, tier, t, Verdict.ALLOW.value)
        return Decision(
            verdict=Verdict.ALLOW,
            tier=tier,
            reason=reason,
            action_class=cls,
            undo_window_seconds=undo_window,
            action_hash=self._safe_hash(action),
        )

    def _deny(
        self,
        tier: Tier,
        cls: str,
        action: Any,
        reason: str,
        *,
        draft: bool = False,
    ) -> Decision:
        return Decision(
            verdict=Verdict.DENY,
            tier=tier,
            reason=reason,
            action_class=cls,
            draft=draft,
            action_hash=self._safe_hash(action),
        )
