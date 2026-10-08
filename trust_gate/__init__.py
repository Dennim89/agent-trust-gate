"""Trust Gate: deterministic, fail-closed permission tiers for AI-agent tool calls.

The gate sits between "the agent proposed a tool call" and "the tool runs". It is pure logic
plus local SQLite, standard library only, and it makes no network calls. It decides. It does
not execute tools, and it does not hook into any agent framework: it only sees the calls you
pass to it.

Public API surface::

    from trust_gate import (
        Gate, Decision, Verdict, ConfirmTokenService,
        Tier, Action, ActionClass, classify, classify_action, action_class_key,
        Provenance, Source, Span, SpanKind,
        TrustLedger,
        ActionLog, hash_action, canonical_repr,
        build_action, evaluate_call, issue_call_token, normalize_tool_name,
        Settings,
    )
"""

from __future__ import annotations

from .action_log import ActionLog, LogRecord, canonical_repr, hash_action
from .adapter import (
    DEFAULT_ALIASES,
    build_action,
    evaluate_call,
    issue_call_token,
    normalize_tool_name,
)
from .config import Settings
from .gate import ConfirmTokenService, Decision, Gate, Verdict
from .ledger import LedgerRow, TrustLedger
from .provenance import Provenance, Source, Span, SpanKind
from .tiers import (
    Action,
    ActionClass,
    Tier,
    action_class_key,
    classify,
    classify_action,
)

__all__ = [
    # gate
    "Gate", "Decision", "Verdict", "ConfirmTokenService",
    # adapter
    "build_action", "evaluate_call", "issue_call_token", "normalize_tool_name",
    "DEFAULT_ALIASES",
    # config
    "Settings",
    # tiers
    "Tier", "Action", "ActionClass", "classify", "classify_action", "action_class_key",
    # provenance
    "Provenance", "Source", "Span", "SpanKind",
    # ledger
    "TrustLedger", "LedgerRow",
    # log
    "ActionLog", "LogRecord", "hash_action", "canonical_repr",
]

__version__ = "0.1.0"
