"""Turn a tool call from your own agent into an ``Action`` and ask the gate about it.

This module executes nothing. It normalizes the tool name, copies the arguments, builds an
``Action`` and calls ``Gate.evaluate``. The caller runs the tool, and only on ``ALLOW``.

Tool names outside the gate's vocabulary classify as T3. Use ``aliases`` to map the names your
agent uses onto the vocabulary (for example ``{"bash": "ssh_exec"}``). The default aliases below
map only to T2 and T3 names, so nothing is relaxed unless you ask for it.
"""

from __future__ import annotations

import time
from copy import deepcopy
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional

from .gate import Decision, Gate
from .ledger import TrustLedger
from .provenance import Provenance
from .tiers import Action

# External mutations: owner provenance and a confirm token are required (T2).
_MUTATION_ALIASES = {
    "api_post": "http_post",
    "db_update": "db_write",
    "file_write": "mcp_write",
    "local_write": "mcp_write",
    "remote_restart": "restart_service",
    "service_restart": "restart_service",
    "write_file": "mcp_write",
}

# Irreversible value movement: always T3.
_DANGEROUS_ALIASES = {
    "execute_order": "place_order",
    "order_execute": "place_order",
    "wallet_sign": "sign_tx",
}

DEFAULT_ALIASES: Mapping[str, str] = MappingProxyType(
    {**_MUTATION_ALIASES, **_DANGEROUS_ALIASES}
)


def _norm(name: object) -> str:
    return str(name or "").strip().lower().replace("-", "_").replace(" ", "_")


def _merge_aliases(aliases: Optional[Mapping[str, str]]) -> Dict[str, str]:
    merged = dict(DEFAULT_ALIASES)
    for key, value in (aliases or {}).items():
        merged[_norm(key)] = _norm(value)
    return merged


def normalize_tool_name(name: object, aliases: Optional[Mapping[str, str]] = None) -> str:
    """Return the gate's tool name for the name your agent uses.

    The name is lower-cased, and ``-`` and spaces become ``_``. Your ``aliases`` override the
    defaults. A name with no alias comes back normalized but otherwise unchanged, so an unknown
    tool still classifies as T3.
    """
    raw = _norm(name)
    return _merge_aliases(aliases).get(raw, raw)


def _safe_args(args: object) -> Dict[str, Any]:
    if args is None:
        return {}
    if isinstance(args, dict):
        try:
            return deepcopy(args)
        except Exception:
            return dict(args)
    return {"value": args}


def build_action(
    tool: object,
    *,
    args: object = None,
    target: object = None,
    provenance: object = None,
    actor: str = "agent",
    idempotency_key: Optional[str] = None,
    aliases: Optional[Mapping[str, str]] = None,
) -> Action:
    """Build an ``Action`` from a proposed tool call.

    With no ``provenance`` the action is unjustified, which the gate denies at T2 and above.
    """
    return Action(
        tool=normalize_tool_name(tool, aliases),
        args=_safe_args(args),
        target=None if target is None else str(target),
        provenance=provenance if provenance is not None else Provenance(),
        actor=str(actor or "agent"),
        idempotency_key=idempotency_key,
    )


def evaluate_call(
    tool: object,
    *,
    args: object = None,
    target: object = None,
    provenance: object = None,
    actor: str = "agent",
    idempotency_key: Optional[str] = None,
    confirm_token: object = None,
    gate: Optional[Gate] = None,
    ledger: Optional[TrustLedger] = None,
    now: Callable[[], float] | float = time.time,
    aliases: Optional[Mapping[str, str]] = None,
) -> Decision:
    """Evaluate a proposed tool call without executing it.

    Pass your own ``gate``: a confirm token only verifies on the ``Gate`` that issued it. With no
    ``gate`` a throw-away one is used, which can never confirm a T2 action.
    """
    action = build_action(
        tool,
        args=args,
        target=target,
        provenance=provenance,
        actor=actor,
        idempotency_key=idempotency_key,
        aliases=aliases,
    )
    return (gate or Gate()).evaluate(
        action, confirm_token=confirm_token, ledger=ledger, now=now
    )


def issue_call_token(
    gate: Gate,
    tool: object,
    *,
    args: object = None,
    target: object = None,
    provenance: object = None,
    actor: str = "agent",
    idempotency_key: Optional[str] = None,
    now: Callable[[], float] | float = time.time,
    ttl_seconds: float = 300,
    aliases: Optional[Mapping[str, str]] = None,
) -> str:
    """Issue a confirm token bound to the exact normalized action.

    Call this only after the owner approved this action, through a channel the agent's context
    cannot write to. The token is single use and expires after ``ttl_seconds``.
    """
    action = build_action(
        tool,
        args=args,
        target=target,
        provenance=provenance,
        actor=actor,
        idempotency_key=idempotency_key,
        aliases=aliases,
    )
    return gate.issue_confirm_token(action, now=now, ttl_seconds=ttl_seconds)
