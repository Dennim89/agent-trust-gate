# Design notes

How the gate reaches a verdict, what it assumes, and what it leaves to you. Everything here
describes the code in `trust_gate/`. The tests named below check most of it.

## Scope

Trust Gate is a decision function. Given a proposed action it returns a `Decision`. It does not
run tools, hook into an agent framework or sandbox anything, and it makes no network calls. The
code that runs the tool has to do what the decision says. If a tool can run without passing
through your call to the gate, the gate does not cover it.

## Threat model

**Adversary.** Any content in the agent's context that the owner did not write: a web page, a
stranger's chat message, the output of a third-party command or tool. The adversary controls the
text of that content. The text may contain prompt injections: "ignore previous instructions",
fake `system:`, `reason:` or `tier=T0` fields, SQL or shell payloads, zero-width or
right-to-left characters.

**Trust boundary.** The owner is the only trusted principal. Text from anyone else is data, never
an instruction: `Span.effective_kind()` downgrades every non-owner span to `DATA`. An action
carries the set of sources behind it (`Provenance`).

**What the gate promises against this adversary.** Each item is checked by the named tests.

1. **No free text lowers a tier.** Classification reads the tool name, the target and the
   arguments (for spend tools, the amount). A scan of all of it for dangerous fragments and secret
   keywords can only raise a tier to T3. Fields such as `note`, `system` or `reason` have no other
   meaning to the classifier. (`test_g1_t3_unbypassable.py`)
2. **T3 cannot be relaxed.** A dangerous action is classified again on every call. A valid
   confirm token, a provenance label or earned ledger trust does not lower it.
   (`test_g1_t3_unbypassable.py`, `test_redteam.py`)
3. **Untrusted provenance blocks T2 and above.** An action at T2 or higher is denied if any
   source behind it is untrusted, or if it has no recorded source. A valid token does not help.
   (`test_g3_provenance_deny.py`)
4. **Approvals cannot be forged, reused or repurposed.** A T2 action needs a token signed with
   HMAC-SHA256 under a secret the attacker does not have. The token is bound to the hash of the
   exact action, expires, and works once. (`test_g6_fail_closed.py`, `test_redteam.py`)
5. **The log is append-only by API.** `ActionLog` has no update or delete method, and a repeated
   idempotency key is recorded once. This is not tamper evidence: see "Action log" below.
   (`test_g4_log_append_idempotent.py`)
6. **Errors deny.** An exception in the classifier, the ledger, the clock or the idempotency
   guard gives DENY. A malformed, expired or mismatched token never gives ALLOW.
   (`test_g6_fail_closed.py`)

**Not covered.**

- Running the tools. The gate does not execute anything, and it does not compute the before and
  after state hashes that `ActionLog` can store. The executor supplies those.
- The host, the process and the SQLite file at rest.
- Wrong provenance. The gate believes the `Provenance` it is given.
- Where data goes. T0 and T1 actions are allowed even when untrusted text led to them.

## How a verdict is computed

### `classify(action)` in `tiers.py`

The first rule that matches wins. The result is always a `Tier`. Anything that is not an
`Action`, and any exception, gives T3.

1. A dangerous fragment anywhere in the tool name, target or arguments gives T3: `rm` with
   recursive and force flags (any order, long flags too), `mkfs`, `dd ... of=`,
   `DROP TABLE|DATABASE|SCHEMA|INDEX`, `TRUNCATE TABLE`, a fork bomb, a redirect to `/dev/sdX`,
   `format X:`, `shutdown`, `reboot`.
2. A tool in the always-T3 list (`trade`, `buy`, `sell`, `swap`, `place_order`, `wallet_send`,
   `sign_transaction`, `sign_tx`, `sign`, `export_private_key`, `reveal_seed`, and the production
   redeploy names), or a secret or wallet keyword anywhere in the same text (`private_key`,
   `seed phrase`, `mnemonic`, `secret_key`, `wallet`, `keypair`), gives T3.
3. A spend tool (`spend`, `transfer`, `withdraw`, `payout`, `payment`, `pay`) gives T3 when the
   amount is unknown or above the threshold, otherwise T2. The amount is the first of `amount`,
   `value`, `sol`, `usd`, `lamports`, `qty`, `quantity` found in the arguments. A value that is
   not a finite number is unknown. The default threshold is 0.
4. A tool in the T2 list, or a target that looks remote (contains `@` or `://`, holds an IPv4
   address, or starts with `remote:`), gives T2.
5. A tool in the T1 list gives T1.
6. A tool in the T0 list gives T0.
7. Anything else gives T3.

The vocabulary lives in `tiers.py` (`T0_TOOLS`, `T1_TOOLS`, `T2_TOOLS`, `SPEND_TOOLS`,
`T3_TOOLS`). Map your own tool names onto it with the `aliases` argument of the adapter.

### `Gate.evaluate(action, ...)` in `gate.py`

1. If an `ActionLog` is attached, check the idempotency key (the action's own
   `idempotency_key`, else its hash). The same key with the same action gives `ALREADY_EXECUTED`.
   The same key with a different action gives DENY.
2. Classify the action. This is the base tier.
3. If the base tier is T2 or higher and the provenance is not entirely owner-trusted, DENY.
4. If a ledger is given and the base tier is below T3, ask it for the effective tier. A ledger
   error gives DENY.
5. If the effective tier is T2 or higher and the provenance is not entirely owner-trusted, DENY.
6. T0 gives ALLOW. T1 gives ALLOW with an undo window in the decision. T2 gives ALLOW if a valid
   token is presented and CONFIRM_REQUIRED otherwise. T3 gives DENY with `draft=True`.

Only an ALLOW is written to the action log. `Decision.draft` is True only for a T3 denial that
reached step 6. A denial that came from provenance (step 3 or 5) has `draft=False`.

## Provenance

`Source` is `OWNER` or `UNTRUSTED`. A `Span` is a piece of text with a source and a claimed kind
(`DATA` or `INSTRUCTION`). For a non-owner span the claimed kind is ignored.

`Provenance.from_spans(spans)` collects the source of every span that went into the action, so a
single untrusted span taints it. `owner_justified()` is true only when there is at least one source
and all of them are the owner. An empty provenance is not owner-justified, which is why an action
with no recorded source is denied at T2 and above.

A provenance given as a list is coerced. An item that is neither a `Source` nor a `Span` counts
as untrusted.

## Confirm tokens

`ConfirmTokenService.issue(action, expires_at=...)` returns `hex(body) + "." + HMAC-SHA256`. The
body holds the hash of the action, the expiry and a random nonce. Verification checks, in this
order: the signature (constant time), the action hash, the expiry (`now >= exp` is expired), and
that the nonce has not been used. Any failure, including an exception, returns False.

The secret is random per `ConfirmTokenService` unless you pass one. Used nonces are kept in
memory, so single use holds within one service object. See the README for what that means across
processes.

Issue a token only after the owner approved this exact action through a channel the agent's
context cannot write to. The gate cannot check that.

## Earned autonomy (the ledger)

`TrustLedger` keeps one row per action class, keyed by the normalized tool name. All time
arithmetic uses the clock you inject.

- **Promotion**, one tier down: 20 consecutive clean, owner-confirmed successes inside 30 days,
  no override in that streak, promotion not frozen, and the class did not start as T3. The streak
  is used up by the promotion.
- **Demotion**, two tiers up and capped at T3: one incident or one override. It also freezes
  promotion for 14 days and resets the streak.
- A class that started as T3 never promotes.
- A fresh T3 classification ignores the ledger.
- Trust earned on a lower base tier does not carry over to a riskier shape of the same tool.
  Example: 20 clean local `send_message` calls promote it to T0, but the same tool aimed at a
  remote target classifies as T2 and stays T2. A demotion always applies.

You report outcomes yourself: `record_success`, `record_incident`, `record_override`.

## Action log

`ActionLog` is a SQLite table: id, timestamp, canonical action text, optional before and after
state hashes, actor, enforced tier, a unique idempotency key and the outcome. `append` returns
`(record, created)`; a repeated key returns the first record unchanged.

The class has no update or delete method. Anyone who can write the database file can still change
it, so treat the log as an audit aid, not as evidence that resists tampering.

## Integration contract

1. **Adapt.** Build an `Action` for each proposed call, or let `evaluate_call` do it. Tag
   provenance honestly: the owner's own message is `Source.OWNER`; web pages, other people's
   messages and output from third-party tools are `Source.UNTRUSTED`.
2. **Evaluate.** `gate.evaluate(action, confirm_token=..., ledger=..., now=...)`.
3. **Obey.** Run the tool only on `ALLOW`, and honor `decision.undo_window_seconds` for T1.
   On `CONFIRM_REQUIRED`, show the owner the exact action. If they approve, issue a token and
   evaluate again. On `DENY`, do not run it. If `decision.draft` is set, you may show a draft for
   approval outside the agent. On `ALREADY_EXECUTED`, do not run it again.
4. **Report.** If you use the ledger, report the outcome so autonomy is earned or taken away.

The decision depends only on structured inputs, the ledger state, the tokens and the clock. It
never depends on the text an attacker controls.
