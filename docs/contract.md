# The `drive.near` contract

Holds what has to be shared and public: access rules per account, published sharing keys, the gateway registry,
credential epochs, anchors, and stablecoin / NEAR Intents escrow for payments ([payments.md](payments.md)).
Source: `contracts/drive`.

Methods (JSON args; `U128` = decimal string):

| area | methods |
|---|---|
| rules | `set_rules(rules)` (payable; the caller's own namespace; ≤ 32 rules, one `{account}` per prefix), `get_rules(namespace)` |
| keys | `set_enc_key(key)` / `remove_enc_key()` (payable), `get_enc_key(account_id)` |
| revocation | `bump_cred_epoch() -> u64` (payable), `get_cred_epoch(account_id) -> u64` |
| anchors | `anchor(namespace, root, seq)` (owner or active gateway; seq strictly increasing), `get_anchor(namespace)` |
| registry | `register_gateway(info)` (stake ≥ `gateway_min_stake` + storage), `update_gateway(info)`, `deregister_gateway()`, `withdraw_gateway_stake()` (after a delay), `get_gateway(operator)`, `list_gateways(from_index, limit)`, `gateways_count()` |
| escrow | `ft_on_transfer`, `mt_on_transfer`, `set_spend_cap(per_day)`, `settle(entries)`, `request_withdraw_balance(asset, amount)`, `cancel_withdraw_balance()`, `withdraw_balance()`, `withdraw_earnings()`, `get_payer`, `get_earnings`, `is_settled`, `get_assets`, `get_settlers` |
| owner | `new(owner_id, assets?, config?)`, `set_config(patch)`, `set_asset(asset)`, `add_settler(account_id, any_gateway)`, `remove_settler`, `set_owner`, `get_config`, `get_owner` |

`info = {url, regions, backends, price_hint, attestation?}`.

The CLI wraps the user-facing calls: `near drive grant` / `rules` (`set_rules` / `get_rules`), `publish-key`
(`set_enc_key`), `gateways` (`list_gateways`).

Building and testing the contract: [development.md](development.md#contract).
