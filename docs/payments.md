# Paying for storage: `storage.near` escrow

Phase 2 of DESIGN.md §6. Payers keep a stablecoin balance in the
`storage.near` escrow. Approved settlers (the billing service, or gateway
operators billing their own usage) charge it for metered usage, and the money
goes to the serving gateway's earnings.

Source: `contracts/storage/src/escrow.rs`. Tests: `contracts/storage/src/tests.rs`
(unit) and `contracts/storage/tests/sandbox.rs` (local sandbox, with a mock
NEP-141 token and a mock NEP-245 intents contract).

## Units and assets

- **Amounts are in micro-USD** (1e-6 USD). This covers `settle` amounts,
  spend caps and the minimum first deposit. Every allow-listed asset counts
  as $1 per whole token. An asset with `decimals = d` (d >= 6) holds
  `usd_micro * 10^(d-6)` token units. USDC has 6 decimals, so 1 micro-USD is
  1 USDC unit.
- **Asset ids** say where the tokens are held:
  - `nep141:<token>`: the token is held directly by storage.near, for example
    `nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`
    (native USDC on mainnet);
  - `nep245:<mt contract>:<token id>`: storage.near's own balance *inside* a
    NEAR Intents contract, for example
    `nep245:intents.near:nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`.
- The default allow-list is exactly those two (mainnet USDC, held directly or
  held in intents). The owner changes it with
  `set_asset({id, decimals, accept_deposits})`. Decimals cannot change after
  an asset is added. `accept_deposits: false` stops new deposits, but existing
  balances can still be spent and withdrawn.
- `settle` draws from a payer's assets **in allow-list order**. Payouts go
  back the way the asset came in: `ft_transfer` for `nep141:` assets, and
  `mt_transfer` into the receiver's intents account for `nep245:` assets.

## Funding

Every deposit carries a `msg` that is either empty or JSON:

```json
{"payer": "alice.near", "spend_cap_per_day": "5000000"}
```

- `payer` is the account to credit. It defaults to the sender.
- `spend_cap_per_day` is the daily cap in micro-USD. It applies only when the
  payer is the sender. You cannot set someone else's cap.
- The first deposit for a new payer must be at least `min_new_payer_deposit`
  (default $0.10). Token deposits cannot attach NEAR, so this minimum bounds
  the storage that deposits can make the contract pay for.
- A bad `msg`, a token not on the allow-list, or a below-minimum first
  deposit makes the receiver panic. The token contract then refunds the sender
  in full (`ft_resolve_transfer` / `mt_resolve_transfer`).

Below, `USDC=17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`.

### 1. Directly from a USDC balance (NEP-141)

```sh
near call $USDC ft_transfer_call \
  '{"receiver_id":"storage.near","amount":"5000000","msg":"{\"spend_cap_per_day\":\"1000000\"}"}' \
  --accountId alice.near --depositYocto 1 --gas 100000000000000
```

This credits $5 to alice and caps spending at $1/day. One-time deployment
step: storage.near must be registered with the token
(`near call $USDC storage_deposit '{"account_id":"storage.near"}' --deposit 0.00125`).

### 2. From a NEAR Intents balance with `mt_transfer_call` (NEP-245)

USDC (or anything swapped into USDC) that alice holds in `intents.near` can
move straight into the escrow. The tokens never leave intents. They become
storage.near's intents balance.

```sh
near call intents.near mt_transfer_call \
  "{\"receiver_id\":\"storage.near\",\"token_id\":\"nep141:$USDC\",\"amount\":\"5000000\",\"msg\":\"{\\\"spend_cap_per_day\\\":\\\"1000000\\\"}\"}" \
  --accountId alice.near --depositYocto 1 --gas 100000000000000
```

intents.near debits alice, credits storage.near, and then calls
`storage.near.mt_on_transfer(sender_id: "alice.near", previous_owner_ids:
["alice.near"], token_ids: ["nep141:$USDC"], amounts: ["5000000"], msg)`.
The escrow credits asset `nep245:intents.near:nep141:$USDC` and returns
`["0"]` (nothing unused). If the call panics, intents.near's
`mt_resolve_transfer` refunds the whole amount.

### 3. Gasless: a signed `transfer` intent

Alice can sign an intent (NEP-413 or any other signing standard intents
supports) and let a relayer submit it through `intents.near.execute_intents`.
She needs no NEAR for gas:

```json
{
  "signer_id": "alice.near",
  "deadline": "2026-12-01T00:00:00Z",
  "intents": [{
    "intent": "transfer",
    "receiver_id": "storage.near",
    "tokens": {"nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1": "5000000"},
    "msg": "{\"spend_cap_per_day\":\"1000000\"}"
  }]
}
```

When `msg` is present, the `Transfer` intent calls `mt_on_transfer` on the
receiver and resolves refunds exactly as `mt_transfer_call` does. The
notification gets 30 TGas by default and at least 5 TGas; `min_gas` overrides
it. The same intent payload can follow a `token_diff` swap, so the payer can
fund storage from any asset intents supports.

### 4. Out of intents with `ft_withdraw` + `msg`

```sh
near call intents.near ft_withdraw \
  "{\"token\":\"$USDC\",\"receiver_id\":\"storage.near\",\"amount\":\"5000000\",\"msg\":\"{\\\"payer\\\":\\\"alice.near\\\"}\"}" \
  --accountId alice.near --depositYocto 1 --gas 100000000000000
```

With `msg` set, intents calls `$USDC.ft_transfer_call(storage.near, …, msg)`.
In that call **`sender_id` is `intents.near`, not alice**, so `msg.payer` is
required. The escrow rejects (and the token refunds) any deposit relayed by a
contract that appears in a `nep245:` asset id when it has no `payer`.
Otherwise the money would be credited to intents.near itself. This route
ends up as a direct `nep141:` balance, so the cap cannot be set here; call
`set_spend_cap` instead.

## Spend caps

```sh
near call storage.near set_spend_cap '{"per_day":"1000000"}' --accountId alice.near --deposit 0.01
```

- `per_day: null` blocks all charges. **A payer with no cap cannot be charged
  at all.** A payer must opt in by setting a cap here or in a deposit `msg`.
- The window is the UTC day: `block_timestamp / 86400 s`.

## Settlement: integration notes for the billing lane

Only owner-approved settlers can call `settle`:

- `add_settler(account_id, any_gateway: true)` is for a billing operator
  (cloud-api metering job) that credits any registered gateway.
- `add_settler(account_id, any_gateway: false)` is for a gateway operator
  billing its own usage. Each entry's `gateway` must equal the settler.

```sh
near call storage.near settle '{"entries":[
  {"payer":"alice.near","amount":"1250","gateway":"gw1.operator.near","period_id":"2026-11-19T10/gw1"},
  {"payer":"app.near","amount":"98000","gateway":"gw1.operator.near","period_id":"2026-11-19T10/gw1"}
]}' --accountId billing.near --deposit 0.1 --gas 300000000000000
```

Rust: `nstorage_near::StorageContract::settle(&signer, &[SettleEntry{..}])`.

- **Each entry is applied whole or not at all.** It never charges part of
  an entry, and one bad entry does not fail the batch. The call returns one
  `{payer, period_id, status, charged}` per entry. `status` is one of:
  `Settled`, `AlreadySettled`, `InvalidEntry` (zero amount or bad
  `period_id`), `GatewayNotAllowed`, `UnknownGateway` (not in the registry,
  where registered and deregistering gateways both count), `NoSpendCap`,
  `CapExceeded`, `InsufficientBalance`.
- **Idempotency key** is `(settler, payer, period_id)`. `gateway` and
  `amount` are not part of it. So:
  - put the gateway in `period_id` when one settler bills several gateways
    for the same payer and period, for example `"2026-11-19T10/gw1"`;
  - retrying a timed-out transaction is safe, because entries already
    settled come back as `AlreadySettled` and are not charged again;
  - if an entry fails with `CapExceeded` or `InsufficientBalance`, nothing is
    recorded. The settler can retry the same `period_id` later (for example
    the next UTC day, when the cap resets) or split the amount across new
    `period_id`s.
  - `is_settled(settler, payer, period_id)` checks a key.
- Limits: at most 100 entries per call, `period_id` 1..=64 printable ASCII.
  Attach about 0.001 NEAR per entry for storage (idempotency keys and new
  earnings rows). The excess is refunded.
- Recommended cadence: settle at least once per `withdraw_delay_sec` (default
  3 days). A payer's withdrawal can only run that long after the request,
  and **funds stay spendable until it runs**. Usage served before the
  request can still be settled during the notice period.
- Phase-1 billing (cloud credits) can use the same metering output. Settling
  onchain only replaces the "debit credits" step.

## Withdrawals

Payers give notice before they withdraw:

```sh
near call storage.near request_withdraw_balance '{"asset":"nep141:'$USDC'","amount":"5000000"}' --accountId alice.near --deposit 0.01
# … after withdraw_delay_sec …
near call storage.near withdraw_balance '{}' --accountId alice.near --depositYocto 1 --gas 100000000000000
```

- `withdraw_balance` pays out min(requested, current balance). Settlements
  made during the notice period reduce what is left.
- A new request replaces the pending one and restarts the timer.
  `cancel_withdraw_balance` drops it.
- For `nep245:` assets the payout is `intents.near.mt_transfer`, back into
  the payer's intents account.

Gateways withdraw their earnings with
`withdraw_earnings` (attach 1 yocto). There is one payout per asset. For
NEP-141 payouts the gateway must be registered with the token
(`storage_deposit`). If any transfer fails, a callback credits the amount
back (`on_payout`).

## Research notes: NEAR Intents / NEP-245 deposit flow

Checked against `near/intents` at commit `dbad9c8` (2026-11-13; the
`Transfer`/`NotifyOnTransfer` code is identical in tag `defuse/v0.4.5`):

- **Receiver interface**: `crates/near/nep245/src/receiver.rs`,
  `mt_on_transfer(sender_id, previous_owner_ids, token_ids, amounts, msg) -> PromiseOrValue<Vec<U128>>`.
  The return value is the per-token *unused* amount to refund. This matches
  NEP-245 (https://github.com/near/NEPs/blob/master/neps/nep-0245.md).
- **mt_transfer_call**: `contracts/defuse/src/contract/tokens/nep245/core.rs`.
  It requires 1 yocto and no approvals. It moves the internal balance first,
  then `notify_on_transfer` calls the receiver with `previous_owner_ids =
  [sender; n]`, then runs `mt_resolve_transfer`
  (`.../nep245/resolver.rs`). That function treats a failed or malformed
  result as "refund everything", caps each refund at the amount and at the
  receiver's current balance, and emits an `mt_transfer` event with the
  refund memo.
- **Token ids** inside intents are `nep141:<contract>`, `nep171:<contract>:<id>`
  or `nep245:<contract>:<id>`. USDC is `nep141:$USDC`.
- **Transfer intent with notification**:
  `contracts/defuse/core/src/intents/tokens.rs`, `Transfer { receiver_id,
  tokens, memo, #[serde(flatten)] notification: Option<NotifyOnTransfer {
  msg, min_gas }> }`. In the intent JSON, `msg` and `min_gas` sit next to
  `tokens`. `MT_ON_TRANSFER_GAS_DEFAULT` is 30 TGas and
  `MT_ON_TRANSFER_GAS_MIN` is 5 TGas
  (`contracts/defuse/core/src/tokens.rs`). Refunds are resolved by the same
  `notify_and_resolve_transfer` (`contracts/defuse/src/contract/intents/state.rs`).
- **ft_withdraw with msg**: `contracts/defuse/src/contract/tokens/nep141/withdraw.rs`.
  `msg: Some(..)` turns the outgoing `ft_transfer` into `ft_transfer_call`
  with the intents contract as the sender. Hence the `payer` requirement
  above.
- Deposits *into* intents with a notify action (`DepositAction::Notify`) are
  commented out upstream. They are not usable today.

Not verified: real `intents.near` and USDC on mainnet or testnet. Per
instructions, nothing was deployed and no funds were spent. The sandbox uses
a mock MT contract that copies the defuse semantics above (balance move →
`mt_on_transfer` → `mt_resolve_transfer` refunds).
