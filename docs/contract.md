# The `drive.near` contract

Holds what has to be shared and public: access rules per account, published sharing keys, the gateway registry,
credential epochs, anchors, and stablecoin / NEAR Intents escrow for payments ([payments.md](payments.md)).
Source: `contracts/drive`.

Methods (JSON args; `U128` = decimal string):

| area | methods |
|---|---|
| rules | `set_rules(rules)` (payable; the caller's own namespace; ≤ 32 rules, one `{account}` per prefix), `get_rules(namespace)` |
| keys | `set_enc_key(key)` / `remove_enc_key()` (payable), `get_enc_key(account_id)`; `set_sign_key(key)` (payable; `ed25519:<base58>`), `get_sign_keys(account_id) -> [{key, since_ms}]` |
| revocation | `bump_cred_epoch() -> u64` (payable), `get_cred_epoch(account_id) -> u64` |
| anchors | `anchor(namespace, root, seq)` (owner or the owner-authorized active gateway; seq strictly increasing), `clear_anchor(namespace)` (owner), `set_anchor_authority(gateway?)` / `get_anchor_authority(namespace)`, `get_anchor(namespace)` |
| registry | `register_gateway(info)` (stake ≥ `gateway_min_stake` + storage), `update_gateway(info)`, `deregister_gateway()`, `force_deregister_gateway(operator)` (owner), `withdraw_gateway_stake()` (after the snapshotted delay), `get_gateway(operator)`, `list_gateways(from_index, limit)`, `gateways_count()` |
| escrow | `ft_on_transfer`, `mt_on_transfer`, `register_payer()` (payable; required before deposits), `close_payer()` (payable; empty entry), `set_spend_cap(per_day)` (decreases delayed), `set_settler_authorization(settler, allowed)` (revocation delayed) / `is_settler_authorized`, `set_sponsorship(namespace, allowed)` (payable) / `is_sponsor(payer, namespace)`, `settle(entries)`, `request_withdraw_balance(asset, amount)`, `cancel_withdraw_balance()`, `withdraw_balance()`, `withdraw_earnings()`, `get_payer`, `get_earnings`, `is_settled(payer, gateway, period)`, `get_settle_window(payer, gateway)`, `get_assets`, `get_settlers`, `get_settler_authorizations` |
| owner | `new(owner_id, assets?, config?)`, `migrate()` (private), `get_state_version`, `set_config(patch)`, `set_asset(asset)`, `add_settler(account_id, any_gateway)`, `remove_settler`, `propose_owner(owner_id)`, `accept_owner()`, `get_pending_owner`, `get_config`, `get_owner` |

`info = {url, regions, backends, price_hint, attestation?}`.

`anchor` is authorized per namespace: the owner can always call it, or the owner may set
`set_anchor_authority(gateway)` for one active registered gateway. `clear_anchor` lets the owner recover from a
gateway that submits a poisoned root or an unreachable `seq` (including `u64::MAX`). Freed anchor storage is
refunded to the account that paid for the current anchor (`Anchor.payer`), not to whoever replaces it.

`register_payer` is required before `ft_on_transfer` / `mt_on_transfer` credits a new payer. It pays for the
`PayerAccount` storage in NEAR; the old refundable token-deposit minimum remains only as an initial-deposit
minimum. `close_payer` removes an empty entry and refunds its storage.

For `settle`, `add_settler(account, any_gateway: true)` is the trusted billing lane and needs no payer
signature. `any_gateway: false` self-settlers must also be authorized by the payer with
`set_settler_authorization`; otherwise the result status is `SettlerNotAuthorized`. Lowering a spend cap and
revoking a settler take effect after `withdraw_delay_sec`; a rule's `payer` other than the namespace owner only
counts if it called `set_sponsorship(namespace, true)`. Details: [payments.md](payments.md).

`set_sign_key` publishes the key that signs the caller's pointer records (derived from the root key, DESIGN.md §4).
Each account keeps a history, oldest first: a new key is appended with `since_ms` = block time in ms (the same key
as the latest entry is a no-op), and only the newest 16 entries are kept. Readers accept a record only if its
`writer_pk` was the writer's key in force at the record's `ts_ms`. JSON: `[{"key": "ed25519:...", "since_ms":
"1763600000000"}]`.

## Upgrades and state migration

The contract state is versioned: its first field is `version` (`STATE_VERSION`, currently 1; view
`get_state_version`). Every code upgrade runs `migrate`, a `#[private] #[init(ignore_state)]` method that reads the
stored version and returns the state in the new layout. For version 1 it only checks the version (identity).

Procedure:

1. If the change alters the borsh layout of `Contract` or of any stored value (`PayerAccount`, `Gateway`, ...), bump
   `STATE_VERSION`, keep the old layout as a `ContractV<n>` struct (and old value types where needed), and add a match
   arm in `migrate` that decodes the old state and converts it. Collections stored under their own keys
   (`LookupMap` etc.) are converted lazily on read or in bounded batches by a separate owner method; `migrate` itself
   must fit in one transaction's gas. Pure code changes need no version bump.
2. Add a unit test that writes the old state and calls `migrate`, and run the sandbox suite.
3. Build reproducibly (below) and deploy and migrate **in one transaction** from the contract account, so no call
   ever sees new code with old state:

   ```sh
   near contract deploy drive.near use-file near_drive_contract.wasm \
     with-init-call migrate json-args '{}' prepaid-gas '300 Tgas' attached-deposit '0 NEAR' \
     network-config mainnet sign-with-keychain send
   ```

   `migrate` panics on an unknown version, which rolls the whole transaction back (the old code stays).
4. Check `get_state_version` and run `contracts/verify.sh drive.near`.

The CLI wraps the user-facing calls: `near drive grant` / `rules` (`set_rules` / `get_rules`), `publish-key`
(`set_enc_key` and `set_sign_key`), `gateways` (`list_gateways`).

## Reproducible build and verification

The contract builds reproducibly: anyone can rebuild it from source and get byte-for-byte the same wasm, and so check
that a deployed `drive.near` runs exactly the published source.

- `contracts/drive/Cargo.toml` pins the build environment (`[package.metadata.near.reproducible_build]`): the
  `sourcescan/cargo-near` Docker image **by digest**, and the build command inside it (`cargo near build
  non-reproducible-wasm --locked`, so the dependency versions come from `contracts/Cargo.lock`).
- `cargo near build reproducible-wasm` only runs on a clean commit that is pushed to the public repository, and
  embeds [NEP-330](https://github.com/near/NEPs/blob/master/neps/nep-0330.md) build info in the wasm: image, command,
  `contract_path` and `source_code_snapshot` (`git+https://github.com/ilblackdragon/near-drive?rev=<commit>`). A deployed
  contract returns it from the `contract_source_metadata` view.

**Build** (needs git, Docker and [cargo-near](https://github.com/near/cargo-near)):

```sh
contracts/build-reproducible.sh [commit-or-tag] [out-dir]     # default: main -> contracts/res/
```

It clones the public repository at that revision into a temporary directory (so local, uncommitted changes can't
leak in), builds in the pinned image, and prints the wasm's SHA-256 and its NEAR code hash (base58). Each release
attaches `near_drive_contract.wasm` built this way, with its code hash in the release notes
(`.github/workflows/contract.yml`, also run whenever `contracts/` changes on `main`).

**Verify a deployment:**

```sh
contracts/verify.sh drive.near            # or: verify.sh <account> testnet | <rpc-url>
```

It reads the account's `contract_source_metadata` and on-chain code hash, rebuilds the recorded commit, and
compares: `OK: ... runs exactly the code built from ... @ <commit>`, or `MISMATCH`. A contract deployed from an
ordinary (non-reproducible) build has no build info and is reported as not verifiable. The same metadata also lets
[SourceScan](https://nearblocks.io/verifier) verify the contract and show its source on NEAR explorers.

The code hash changes with every commit, even if the contract source didn't change, because the wasm embeds the
commit it was built from; compare builds of the same commit.

**Deploying:** always deploy the wasm from `build-reproducible.sh` (or the release asset), never a local
`cargo near build non-reproducible-wasm` output, so the deployment stays verifiable.

Checked so far:
- Three independent builds of the same commit (two fresh clones, and a pinned checkout) gave the identical wasm
  (sha256 `1fbf13c5…6c52`, code hash `38vdScEnDv777Hoeir9BnfBZi1Ph6qoeJXEHpGbLHXqB` for commit `d338bb4`).
- GitHub's runner (`contract.yml`) rebuilt the same commit to the same code hash, so it reproduces across machines.
- The contract's sandbox test suites pass with the reproducible wasm.
- `verify.sh` against a local sandbox chain reports OK for the reproducible deployment and rejects an ordinary build.

Building and testing the contract during development: [development.md](development.md#contract).
