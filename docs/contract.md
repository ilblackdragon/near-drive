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
| anchors | `anchor(namespace, root, seq)` (owner or the owner-authorized active gateway; seq strictly increasing), `clear_anchor(namespace)` (owner), `set_anchor_authority(gateway?)` / `get_anchor_authority(namespace)`, `get_anchor(namespace)` |
| registry | `register_gateway(info)` (stake ≥ `gateway_min_stake` + storage), `update_gateway(info)`, `deregister_gateway()`, `force_deregister_gateway(operator)` (owner), `withdraw_gateway_stake()` (after the snapshotted delay), `get_gateway(operator)`, `list_gateways(from_index, limit)`, `gateways_count()` |
| escrow | `ft_on_transfer`, `mt_on_transfer`, `register_payer()` (payable; required before deposits), `close_payer()` (payable; empty entry), `set_spend_cap(per_day)`, `set_settler_authorization(settler, allowed)` / `is_settler_authorized`, `settle(entries)`, `request_withdraw_balance(asset, amount)`, `cancel_withdraw_balance()`, `withdraw_balance()`, `withdraw_earnings()`, `get_payer`, `get_earnings`, `is_settled`, `get_assets`, `get_settlers`, `get_settler_authorizations` |
| owner | `new(owner_id, assets?, config?)`, `set_config(patch)`, `set_asset(asset)`, `add_settler(account_id, any_gateway)`, `remove_settler`, `propose_owner(owner_id)`, `accept_owner()`, `get_pending_owner`, `get_config`, `get_owner` |

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
`set_settler_authorization`; otherwise the result status is `SettlerNotAuthorized`.

The CLI wraps the user-facing calls: `near drive grant` / `rules` (`set_rules` / `get_rules`), `publish-key`
(`set_enc_key`), `gateways` (`list_gateways`).

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
