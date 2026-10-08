"""Tiers + the deterministic classification rules.

A *tier* answers one question: "how much autonomy is this action allowed?"

    T0  read-only .................... auto-allow
    T1  reversible side effect ....... auto-allow, undo window recorded
    T2  external mutation ............ requires a single-use confirm token
    T3  irreversible / dangerous ..... never autonomous; DENY (draft-only)

Higher tier number == more restrictive.

``classify()`` is the deterministic, *total* function at the heart of the gate. It is a
pure function of an action's STRUCTURED fields (tool, args, target, amount) and never of
any attacker-controllable free text such as a ``note``/``system``/``reason`` field.
Every possible input yields a Tier; anything unknown, ambiguous, malformed, or dangerous
collapses to T3 (fail-closed to the most restrictive tier).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Optional

from .provenance import Provenance, coerce_provenance


class Tier(IntEnum):
    """Autonomy tier. Larger == more restrictive."""

    T0 = 0  # read-only
    T1 = 1  # reversible side effect
    T2 = 2  # external mutation
    T3 = 3  # irreversible / dangerous / unknown


# Default spend threshold in the caller's own units (e.g. USD). Any spend whose amount is
# unknown or strictly greater than this is T3. Default 0.0 => essentially every real spend
# is T3 unless the integrator deliberately raises the bar.
DEFAULT_SPEND_THRESHOLD: float = 0.0


@dataclass
class Action:
    """A *proposed* tool call, before it is allowed to execute.

    Only ``tool``, ``args``, ``target`` and the parsed spend amount participate in
    classification. ``provenance`` gates T2+ actions. All other keys the caller might
    stuff into ``args`` (``note``, ``system``, ``reason``, an injected instruction ...)
    are inert with respect to the verdict.
    """

    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    target: Optional[str] = None
    provenance: Provenance = field(default_factory=Provenance)
    actor: str = "agent"  # "human" | "agent"
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        # Coerce provenance so tests / callers may pass a list of Source or Span.
        self.provenance = coerce_provenance(self.provenance)


@dataclass(frozen=True)
class ActionClass:
    """The stable *class* an action belongs to, plus its freshly computed base tier.

    The ledger tracks trust per ``name``; the gate enforces ``base_tier`` (possibly
    adjusted by the ledger, but never relaxed below a freshly detected T3).
    """

    name: str
    base_tier: Tier


# --------------------------------------------------------------------------------------
# Tool vocabularies. Membership is exact (normalized) tool name.
# --------------------------------------------------------------------------------------

T0_TOOLS = frozenset({
    "read_file", "read", "list_dir", "ls", "cat", "stat", "get_status", "status",
    "whoami", "search", "query", "db_read", "http_get", "fetch", "get", "list",
    "view", "describe", "head", "tail", "grep", "glob", "ping",
})

T1_TOOLS = frozenset({
    "send_message", "send_telegram", "send_email", "notify", "reply", "message",
    "schedule_cron", "cron_create", "create_reminder", "reminder", "post_draft",
    "enqueue", "add_calendar_event",
})

T2_TOOLS = frozenset({
    "ssh_exec", "remote_exec", "run_remote", "exec_remote", "mcp_write", "mcp_set",
    "mcp_state_change", "remote_write", "remote_file_write", "scp_put", "sftp_put",
    "db_write", "http_post", "http_put", "api_write", "deploy", "restart_service",
})

# Spend-like tools: tier depends on the parsed amount vs. threshold.
SPEND_TOOLS = frozenset({"spend", "transfer", "withdraw", "payout", "payment", "pay"})

# Always-T3 tools (irreversible value movement / secrets / production redeploys).
T3_TOOLS = frozenset({
    "trade", "buy", "sell", "swap", "place_order", "wallet_send", "sign_transaction",
    "sign_tx", "sign", "export_private_key", "reveal_seed", "prod_redeploy",
    "redeploy_prod", "deploy_prod", "production_deploy",
})

# Substrings that, if present anywhere in the structured content, force T3.
T3_KEYWORDS = (
    "private_key", "privatekey", "private key", "seed_phrase", "seed phrase",
    "mnemonic", "secret_key", "secretkey", "wallet", "keypair",
)

# Dangerous command fragments. Case-insensitive. Any hit => T3.
# NOTE: `rm` with recursive+force flags is handled by ``_is_destructive_rm`` below,
# which is order/whitespace/long-flag robust and does not rely on a single regex.
_DANGER_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bmkfs\b",
        r"\bdd\b[^\n]*\bof=",
        r"\bdrop\s+(table|database|schema|index)\b",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}",           # classic fork bomb
        r">\s*/dev/sd[a-z]",
        r"\bformat\s+[a-z]:",
        r"\btruncate\s+table\b",
        r"\bshutdown\b|\breboot\b",
    )
]


def _amount(args: Dict[str, Any]) -> Optional[float]:
    """Extract a numeric spend amount from args, or None if not determinable.

    A non-finite result (NaN, +inf, -inf) is treated as *unknown* (``None``) so it
    fails closed: NaN/inf are not knowable amounts and must not slip past the
    ``amt > threshold`` comparison (for which NaN/-inf are silently False) into T2.
    """
    for key in ("amount", "value", "sol", "usd", "lamports", "qty", "quantity"):
        if key in args:
            try:
                v = float(args[key])
            except (TypeError, ValueError):
                return None  # present but unparseable -> unknown -> fail closed
            if not math.isfinite(v):
                return None  # NaN / +-inf -> unknown -> fail closed
            return v
    return None


# Recursive-force `rm` detection, robust to flag order, spacing, and long options.
_RM_WORD_RE = re.compile(r"(?<![\w./-])rm(?![\w./-])", re.IGNORECASE)
_CMD_SEP_RE = re.compile(r"[;&|\n]")


def _is_destructive_rm(text: str) -> bool:
    """True if ``text`` contains an ``rm`` invocation with BOTH recursive and force.

    Catches the equivalent forms that evaded an earlier single regex: ``rm -rf``,
    ``rm -fr``, ``rm -r -f``, ``rm -f -r``, arbitrary spacing, and the long options
    ``--recursive`` / ``--force`` (and ``--no-preserve-root``, which is destructive on
    its own). Flags may appear in any order/position.
    """
    lowered = text.lower()
    for m in _RM_WORD_RE.finditer(lowered):
        # Only scan option tokens up to the next shell command separator.
        segment = _CMD_SEP_RE.split(lowered[m.end():], 1)[0]
        recursive = force = False
        for tok in segment.split():
            if not tok.startswith("-"):
                continue
            if tok.startswith("--"):
                name = tok[2:].strip("\"'`,)")
                if name == "recursive":
                    recursive = True
                elif name == "force":
                    force = True
                elif name == "no-preserve-root":
                    recursive = force = True
            else:
                letters = tok[1:]
                if "r" in letters:
                    recursive = True
                if "f" in letters:
                    force = True
            if recursive and force:
                return True
    return False


def _structured_text(action: Action) -> str:
    """A lowercased blob of ONLY the structured, semantically-load-bearing fields.

    We serialize tool, target and args. Yes, args may contain attacker text -- but the
    only effect scanning it can have is to *raise* the tier to T3 (fail-closed). It can
    never lower a tier, so an injection string is at worst a self-denial-of-service.
    """
    try:
        args_repr = json.dumps(action.args, sort_keys=True, default=str)
    except Exception:
        args_repr = str(getattr(action, "args", ""))
    return " ".join([
        str(getattr(action, "tool", "")),
        str(getattr(action, "target", "") or ""),
        args_repr,
    ]).lower()


def _is_dangerous(text: str) -> bool:
    if _is_destructive_rm(text):
        return True
    return any(p.search(text) for p in _DANGER_PATTERNS)


def _remote_target(action: Action) -> bool:
    """Heuristic: does this action mutate something *remote*?"""
    target = str(getattr(action, "target", "") or "").lower()
    if not target:
        return False
    return (
        "@" in target                # user@host
        or "://" in target           # scheme://host
        or bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", target))  # bare IP
        or target.startswith("remote:")
    )


def classify(
    action: Any,
    *,
    spend_threshold: float = DEFAULT_SPEND_THRESHOLD,
) -> Tier:
    """Total, deterministic classifier. Returns a Tier for ANY input.

    Order of checks (most restrictive wins):
      1. Danger fragments anywhere in structured content -> T3.
      2. Always-T3 tools / secret & wallet keywords -> T3.
      3. Spend-like tools: amount unknown or > threshold -> T3, else T2.
      4. Known external-mutation tools (or a remote target) -> T2.
      5. Known reversible tools -> T1.
      6. Known read-only tools -> T0.
      7. Anything else (unknown tool, garbage, None) -> T3 (fail closed).
    """
    try:
        if not isinstance(action, Action):
            # We only classify real Actions. Anything else is unknown => T3.
            return Tier.T3

        tool = str(action.tool).strip().lower()
        text = _structured_text(action)

        # (1) dangerous fragments
        if _is_dangerous(text):
            return Tier.T3

        # (2) always-T3 tools and secret/wallet keywords
        if tool in T3_TOOLS:
            return Tier.T3
        if any(k in text for k in T3_KEYWORDS):
            return Tier.T3

        # (3) spend-like tools
        if tool in SPEND_TOOLS:
            amt = _amount(action.args if isinstance(action.args, dict) else {})
            if amt is None or amt > spend_threshold:
                return Tier.T3
            return Tier.T2

        # (4) external mutation
        if tool in T2_TOOLS or _remote_target(action):
            return Tier.T2

        # (5) reversible side effects
        if tool in T1_TOOLS:
            return Tier.T1

        # (6) read only
        if tool in T0_TOOLS:
            return Tier.T0

        # (7) unknown / unmatched -> most restrictive
        return Tier.T3
    except Exception:
        # Any error at all -> deny-by-default tier.
        return Tier.T3


def action_class_key(action: Any) -> str:
    """Stable ledger key for an action's class.

    We key on the normalized tool name (or ``"unknown"``). This is what the trust ledger
    tracks streaks/incidents against.
    """
    try:
        if not isinstance(action, Action):
            return "unknown"
        tool = str(action.tool).strip().lower()
        return tool or "unknown"
    except Exception:
        return "unknown"


def classify_action(
    action: Any,
    *,
    spend_threshold: float = DEFAULT_SPEND_THRESHOLD,
) -> ActionClass:
    """Return both the ledger class key and the freshly computed base tier."""
    return ActionClass(
        name=action_class_key(action),
        base_tier=classify(action, spend_threshold=spend_threshold),
    )
