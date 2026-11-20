# Paying for storage: `drive.near` escrow

Phase 2 of DESIGN.md §6. Payers keep a stablecoin balance in the
`drive.near` escrow. Approved settlers (the billing service, or gateway
operators billing their own usage) charge it for metered usage, and the money
goes to the serving gateway's earnings.

Source: `contracts/drive/src/escrow.rs`. Tests: `contracts/drive/src/tests.rs`
(unit) and `contracts/drive/tests/sandbox.rs` (local sandbox, with a mock
NEP-141 token and a mock NEP-245 intents contract).

## Units and assets

- **Amounts are in micro-USD** (1e-6 USD). This covers `settle` amounts,
  spend caps and the minimum first deposit. Every allow-listed asset counts
  as $1 per whole token. An asset with `decimals = d` (d >= 6) holds
  `usd_micro * 10^(d-6)` token units. USDC has 6 decimals, so 1 micro-USD is
  1 USDC unit.
- **Asset ids** say where the tokens are held:
  - `nep141:<token>`: the token is held directly by drive.near, for example
    `nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`
    (native USDC on mainnet);
  - `nep245:<mt contract>:<token id>`: drive.near's own balance *inside* a
    NEAR Intents contract, for example
    `nep245:intents.near:nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`.
- The default allow-list is exactly those two (mainnet USDC, held directly or
  held in intents). The owner changes it with
  `set_asset({id, decimals, accept_deposits})`. Decimals cannot change after
  an asset is added. `accept_deposits: false` stops new deposits, but existing
  balances can still be spent and withdrawn. **The owner's asset allow-list
  and the $1-per-whole-token valuation are trust assumptions**: a depegged or
  malicious allow-listed token is still valued at $1 by the contract.
- `settle` draws from a payer's assets **in allow-list order**. Payouts go
  back the way the asset came in: `ft_transfer` for `nep141:` assets, and
  `mt_transfer` into the receiver's intents account for `nep245:` assets.

## Funding

Before a new payer can receive a deposit, it must create its escrow entry and pay for its storage:

```sh
near call drive.near register_payer '{}' --accountId alice.near --deposit 0.01
```

`register_payer` charges the actual storage cost and refunds the excess. This is what prevents an
attacker from creating arbitrarily many contract-paid `PayerAccount` entries using refundable token
deposits: token deposits alone no longer create state. An empty entry can be removed with
`close_payer`, which refunds its storage.

Every deposit carries a `msg` that is either empty or JSON:

```json
{"payer": "alice.near", "spend_cap_per_day": "5000000"}
```

- `payer` is the account to credit. It defaults to the sender. The payer must already be registered.
- `spend_cap_per_day` is the daily cap in micro-USD. It applies only when the
  payer is the sender. You cannot set someone else's cap.
- The first deposit for a newly registered payer must be at least
  `min_new_payer_deposit` (default $0.10). This is now an anti-dust minimum, not
  the storage payment; storage is paid by `register_payer`.
- A bad `msg`, a token not on the allow-list, an unregistered payer, or a
  below-minimum first deposit makes the receiver panic. The token contract then
  refunds the sender in full (`ft_resolve_transfer` / `mt_resolve_transfer`).

Below, `USDC=17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1`.

### 1. Directly from a USDC balance (NEP-141)

```sh
near call $USDC ft_transfer_call \
  '{"receiver_id":"drive.near","amount":"5000000","msg":"{\"spend_cap_per_day\":\"1000000\"}"}' \
  --accountId alice.near --depositYocto 1 --gas 100000000000000
```

This credits $5 to alice and caps spending at $1/day. Alice must have called
`register_payer` first. One-time deployment step: drive.near must be registered
with the token (`near call $USDC storage_deposit '{"account_id":"drive.near"}' --deposit 0.00125`).

### 2. From a NEAR Intents balance with `mt_transfer_call` (NEP-245)

USDC (or anything swapped into USDC) that alice holds in `intents.near` can
move straight into the escrow. The tokens never leave intents. They become
drive.near's intents balance.

```sh
near call intents.near mt_transfer_call \
  "{\"receiver_id\":\"drive.near\",\"token_id\":\"nep141:$USDC\",\"amount\":\"5000000\",\"msg\":\"{\\\"spend_cap_per_day\\\":\\\"1000000\\\"}\"}" \
  --accountId alice.near --depositYocto 1 --gas 100000000000000
```

intents.near debits alice, credits drive.near, and then calls
`drive.near.mt_on_transfer(sender_id: "alice.near", previous_owner_ids:
["alice.near"], token_ids: ["nep141:$USDC"], amounts: ["5000000"], msg)`.
The escrow credits asset `nep245:intents.near:nep141:$USDC` and returns
`["0"]` (nothing unused). If the call panics, intents.near's
`mt_resolve_transfer` refunds the whole amount. The payer must already be
registered (`register_payer`).

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
    "receiver_id": "drive.near",
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
  "{\"token\":\"$USDC\",\"receiver_id\":\"drive.near\",\"amount\":\"5000000\",\"msg\":\"{\\\"payer\\\":\\\"alice.near\\\"}\"}" \
  --accountId alice.near --depositYocto 1 --gas 100000000000000
```

With `msg` set, intents calls `$USDC.ft_transfer_call(drive.near, …, msg)`.
In that call **`sender_id` is `intents.near`, not alice**, so `msg.payer` is
required. The escrow rejects (and the token refunds) any deposit relayed by a
contract that appears in a `nep245:` asset id when it has no `payer`.
Otherwise the money would be credited to intents.near itself. This route
ends up as a direct `nep141:` balance, so the cap cannot be set here; call
`set_spend_cap` instead.

## Spend caps

```sh
near call drive.near set_spend_cap '{"per_day":"1000000"}' --accountId alice.near --deposit 0.01
```

- `per_day: null` blocks all charges. **A payer with no cap cannot be charged
  at all.** A payer must opt in by setting a cap here or in a deposit `msg`.
- **Raising the cap applies at once; lowering it (including to `null`) applies
  only after `withdraw_delay_sec`** (the same notice period as withdrawals).
  Until then `settle` uses the old cap. `get_payer` shows the cap in force
  (`spend_cap_per_day`) and the scheduled one (`pending_spend_cap: {per_day,
  effective_at_ns}`). A raise, or setting the current cap again, cancels a
  pending decrease; a new decrease replaces it and restarts the timer. The
  same rules apply to `spend_cap_per_day` in a deposit `msg`. Without the
  delay a payer could use storage, zero the cap, and withdraw after the notice
  period, leaving the gateway unpaid.
- `set_spend_cap` also creates the caller's `PayerAccount` if needed (it is
  payable and charges/refunds storage), so it can be used instead of a separate
  `register_payer`.
- The window is the UTC day: `block_timestamp / 86400 s`.

## Settlement: integration notes for the billing lane

Only owner-approved settlers can call `settle`:

- `add_settler(account_id, any_gateway: true)` is for a billing operator
  (cloud-api metering job) that credits any registered gateway. This is the
  fully trusted billing lane and does **not** require per-payer authorization.
- `add_settler(account_id, any_gateway: false)` is for a gateway operator
  billing its own usage. Each entry's `gateway` must equal the settler, and
  the payer must authorize that settler with
  `set_settler_authorization(settler, true)`. This prevents an approved
  self-settler from charging payers that never chose it. Revoke with
  `set_settler_authorization(settler, false)`: like a cap decrease, **the
  revocation takes effect after `withdraw_delay_sec`**, so the gateway can
  still bill usage it already served. `get_settler_authorizations(payer)`
  returns `[{settler, expires_at_ns}]`, with `expires_at_ns` set while a
  revocation is pending. Authorizing again cancels it; revoking again does
  not move the deadline. Revoking needs no deposit. Example:

  ```sh
  near call drive.near set_settler_authorization \
    '{"settler":"gw1.operator.near","allowed":true}' \
    --accountId alice.near --deposit 0.01
  ```

```sh
near call drive.near settle '{"entries":[
  {"payer":"alice.near","amount":"1250","gateway":"gw1.operator.near","period":"493978"},
  {"payer":"app.near","amount":"98000","gateway":"gw1.operator.near","period":"493978"}
]}' --accountId billing.near --deposit 0.1 --gas 300000000000000
```

Rust: `near_drive_chain::StorageContract::settle(&signer, &[SettleEntry{..}])`.

- **Each entry is applied whole or not at all.** It never charges part of
  an entry, and one bad entry does not fail the batch. The call returns one
  `{payer, gateway, period, status, charged}` per entry. `status` is one of:
  `Settled`, `AlreadySettled`, `InvalidEntry` (zero amount),
  `GatewayNotAllowed`, `UnknownGateway` (not in the registry, where
  registered and deregistering gateways both count), `SettlerNotAuthorized`
  (a self-settler the payer did not authorize), `PeriodTooOld` (see below),
  `NoSpendCap`, `CapExceeded`, `InsufficientBalance`.
- **`period` is a number** (`U64`, a decimal string in JSON), e.g. the
  gateway meter's hourly window index (`period_start_ms / window_ms`). One
  entry per (payer, gateway, period): sum all services of a window into it.
- **Idempotency key** is `(payer, gateway, period)`. The settler and
  `amount` are not part of it. So:
  - retrying a timed-out transaction is safe, because entries already
    settled come back as `AlreadySettled` and are not charged again;
  - rotating the billing account (a new settler) does not reset idempotency,
    and the billing lane and a gateway's self-settle lane cannot both charge
    the same period of the same gateway;
  - if an entry fails with `CapExceeded` or `InsufficientBalance`, nothing is
    recorded. The settler can retry the same `period` later (for example
    the next UTC day, when the cap resets), within the window below.
  - `is_settled(payer, gateway, period)` checks a period;
    `get_settle_window(payer, gateway)` returns the raw window.
- **Bounded idempotency state: a sliding window.** For each (payer, gateway)
  the contract keeps only the newest settled `period` (`latest`) and a
  128-bit bitmap of which of the 128 periods `latest-127 ..= latest` are
  settled (`SETTLE_WINDOW = 128`; 24 bytes of value per pair, never growing
  with time). A period above `latest` moves the window forward; a period
  inside it is accepted once, in any order; a period more than 127 behind
  `latest` is refused as `PeriodTooOld`, because the contract can no longer
  tell whether it was settled. With hourly periods that leaves 5 days to
  retry a failed period, more than the default 3-day notice period, after
  which the payer's funds may be gone anyway. Why not the alternatives: the
  old per-period set grew forever; a plain "strictly increasing period"
  counter is as small but makes one failed period (`CapExceeded` today)
  unsettleable as soon as a later one succeeds, which breaks the "retry
  tomorrow" flow; and keying by settler instead of gateway resets
  idempotency whenever the billing account is rotated.
- Limits: at most 100 entries per call. Attach about 0.001 NEAR per entry
  for storage (a new idempotency window per new (payer, gateway) pair, new
  earnings rows); once a pair's window exists, settling more periods for it
  needs no storage. The excess is refunded.
- Recommended cadence: settle at least once per `withdraw_delay_sec` (default
  3 days). A payer's withdrawal can only run that long after the request,
  and **funds stay spendable until it runs**. Cap decreases and settler
  revocations wait out the same notice period, so usage served before any of
  these requests can still be settled during it.
- Phase-1 billing (cloud credits) can use the same metering output. Settling
  onchain only replaces the "debit credits" step.

## Sponsorship: who may be named as payer

A namespace's rules can name a `payer` for a prefix (DESIGN.md §4.2), e.g.
`app.near` paying for `users/{account}/`. Naming someone else as payer would
bill them without consent, so **a payer other than the namespace owner only
counts if it opted in** for that namespace:

```sh
near call drive.near set_sponsorship '{"namespace":"app.near","allowed":true}' --accountId alice.near --deposit 0.01
near view drive.near is_sponsor '{"payer":"alice.near","namespace":"app.near"}'   # true
```

- Keyed by (payer, namespace); storage is charged to the payer and refunded
  when it sets `allowed: false`. A namespace is always its own sponsor.
- For an `{account}` payer the bound account (e.g. `bob.near` for
  `users/bob.near/...`) must sponsor the namespace too.
- When the payer has not opted in, usage under that rule is billed to the
  **namespace owner**. Gateways apply this when they resolve the payer for a
  request (`near-drive-gateway` `policies.rs`: concrete payers when the rules
  are loaded, `{account}` payers per request; answers cached 60 s). Gateway
  config `policies` overrides are trusted as written.
- **The contract does not check sponsorship in `settle`.** A settle entry
  carries (payer, gateway, period, amount), not the namespace or path the
  usage came from, so the contract cannot tell which namespace's rule made
  this payer liable. Consent is enforced off-chain by the gateway / billing
  service when usage is attributed; onchain the payer's protection is the
  spend cap and, for self-settlers, `set_settler_authorization`.

## Withdrawals

Payers give notice before they withdraw:

```sh
near call drive.near request_withdraw_balance '{"asset":"nep141:'$USDC'","amount":"5000000"}' --accountId alice.near --deposit 0.01
# … after withdraw_delay_sec …
near call drive.near withdraw_balance '{}' --accountId alice.near --depositYocto 1 --gas 100000000000000
```

- `withdraw_balance` pays out min(requested, current balance). Settlements
  made during the notice period reduce what is left.
- The storage deposit for the withdrawal request is refunded when the request
  executes or is cancelled.
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
