//! `drive.near`: the onchain half of NEAR Drive (DESIGN.md §4.2, §5.1, §6, §7).
//!
//! - namespace policy (`set_rules` / `get_rules`), same JSON shape as
//!   `near_drive_core::policy::Rule`;
//! - X25519 encryption keys for sharing (`set_enc_key` / `get_enc_key`);
//! - ed25519 record-signing keys with history (`set_sign_key` / `get_sign_keys`);
//! - gateway registry with a NEAR stake (`register_gateway` …);
//! - per-account credential epochs for hosted-S3 revocation;
//! - rollback-detection anchors (`anchor` / `get_anchor`);
//! - stablecoin escrow funded by NEP-141 `ft_transfer_call` or NEP-245
//!   `mt_transfer_call` (NEAR Intents), spent by approved settlers;
//! - payer opt-in for namespaces that name it in a rule (`set_sponsorship`).
//!
//! State is versioned (`STATE_VERSION`, the first field of the state) and
//! upgraded with `migrate` after deploying new code (docs/contract.md).
//!
//! Storage staking: every method that grows state charges the caller for the
//! bytes it added (attach NEAR; the excess is refunded) and refunds bytes it
//! frees. The exceptions are deposits, which cannot carry NEAR: a payer must
//! first call `register_payer` (payable) to create its `PayerAccount`, and
//! adding balance rows is bounded by `MAX_ASSETS`. Payout callbacks also grow
//! state without a new deposit; they restore what was removed.
use near_sdk::{
    env,
    json_types::{U128, U64},
    near, require,
    store::{IterableMap, LookupMap, LookupSet},
    AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise,
};

pub mod escrow;
pub mod gateway;
pub mod validate;

#[cfg(test)]
mod tests;

pub use escrow::{
    AssetConfig, PayerAccount, PendingSpendCap, SettleEntry, SettleResult, SettleStatus,
    SettleWindow, SettlerAuth, SettlerAuthView,
};
pub use gateway::{Gateway, GatewayInfo, GatewayView};

/// Native USDC on NEAR mainnet (6 decimals).
pub const MAINNET_USDC: &str = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
pub const MAINNET_INTENTS: &str = "intents.near";

pub(crate) const SEC: u64 = 1_000_000_000;

/// Layout version of [`Contract`]. Bump it whenever the borsh layout of the
/// state changes, and teach `migrate` to read the previous layout.
pub const STATE_VERSION: u32 = 1;

/// One published record-signing key and when it was published (block time,
/// ms). `get_sign_keys` returns the history oldest first.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct SignKeyEntry {
    pub key: String,
    pub since_ms: U64,
}

/// One namespace policy rule. JSON-identical to `near_drive_core::policy::Rule`.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub prefix: String,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub payer: Option<String>,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Anchor {
    pub root: String,
    pub seq: u64,
    /// Account that submitted it (namespace owner or an authorized gateway).
    pub by: AccountId,
    /// Account that paid for the bytes currently occupied by this anchor.
    /// Refunds for shrinking/clearing go here, not to whoever happens to
    /// replace the anchor.
    pub payer: AccountId,
    pub block_height: U64,
    pub timestamp_ns: U64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Minimum NEAR stake to register a gateway (yoctoNEAR).
    pub gateway_min_stake: U128,
    /// Delay between `deregister_gateway` and `withdraw_gateway_stake`.
    pub gateway_unstake_delay_sec: u64,
    /// Notice a payer gives before withdrawing escrow balance.
    pub withdraw_delay_sec: u64,
    /// Minimum first deposit (micro-USD) that creates a payer entry. Token
    /// deposits cannot attach NEAR, so this bounds unpaid storage growth.
    pub min_new_payer_deposit: U128,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway_min_stake: U128(NearToken::from_near(5).as_yoctonear()),
            gateway_unstake_delay_sec: 7 * 24 * 3600,
            withdraw_delay_sec: 3 * 24 * 3600,
            min_new_payer_deposit: U128(100_000), // $0.10
        }
    }
}

/// Partial update for `set_config`.
#[near(serializers = [json])]
#[derive(Clone, Debug, Default)]
pub struct ConfigPatch {
    pub gateway_min_stake: Option<U128>,
    pub gateway_unstake_delay_sec: Option<u64>,
    pub withdraw_delay_sec: Option<u64>,
    pub min_new_payer_deposit: Option<U128>,
}

#[near]
#[derive(BorshStorageKey)]
enum Key {
    Rules,
    EncKeys,
    Gateways,
    CredEpochs,
    Anchors,
    AnchorAuthorities,
    Payers,
    Earnings,
    Settled,
    Settlers,
    SettlerAuths,
    SignKeys,
    Sponsorships,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    /// Always [`STATE_VERSION`] for the code that wrote it. Kept first so
    /// `migrate` can read it before knowing the rest of the layout.
    pub(crate) version: u32,
    pub(crate) owner: AccountId,
    pub(crate) pending_owner: Option<AccountId>,
    pub(crate) config: Config,
    pub(crate) rules: LookupMap<AccountId, Vec<Rule>>,
    pub(crate) enc_keys: LookupMap<AccountId, String>,
    /// account -> signing-key history, oldest first, at most `MAX_SIGN_KEYS`.
    pub(crate) sign_keys: LookupMap<AccountId, Vec<SignKeyEntry>>,
    pub(crate) gateways: IterableMap<AccountId, Gateway>,
    pub(crate) cred_epochs: LookupMap<AccountId, u64>,
    pub(crate) anchors: LookupMap<AccountId, Anchor>,
    /// namespace -> active gateway allowed to anchor on its behalf.
    pub(crate) anchor_authorities: LookupMap<AccountId, AccountId>,
    /// Allow-listed escrow assets, in spending order.
    pub(crate) assets: Vec<AssetConfig>,
    pub(crate) payers: LookupMap<AccountId, PayerAccount>,
    /// gateway operator -> [(asset, amount)]
    pub(crate) earnings: LookupMap<AccountId, Vec<(String, u128)>>,
    /// (payer, gateway) -> anti-replay window over settled periods.
    pub(crate) settled: LookupMap<(AccountId, AccountId), SettleWindow>,
    /// settler -> may credit any gateway (true) or only itself (false).
    pub(crate) settlers: IterableMap<AccountId, bool>,
    /// payer -> settlers the payer allows to charge it (self-settlers only).
    pub(crate) settler_auths: LookupMap<AccountId, Vec<SettlerAuth>>,
    /// (payer, namespace): the payer agrees to pay for rules of `namespace`
    /// that name it as `payer`.
    pub(crate) sponsorships: LookupSet<(AccountId, AccountId)>,
}

#[near]
impl Contract {
    /// `assets` defaults to mainnet USDC, held directly (NEP-141) or as an
    /// `intents.near` balance (NEP-245 token `nep141:<usdc>`).
    #[init]
    pub fn new(
        owner_id: AccountId,
        assets: Option<Vec<AssetConfig>>,
        config: Option<Config>,
    ) -> Self {
        let assets = assets.unwrap_or_else(|| {
            vec![
                AssetConfig {
                    id: format!("nep141:{MAINNET_USDC}"),
                    decimals: 6,
                    accept_deposits: true,
                },
                AssetConfig {
                    id: format!("nep245:{MAINNET_INTENTS}:nep141:{MAINNET_USDC}"),
                    decimals: 6,
                    accept_deposits: true,
                },
            ]
        });
        for a in &assets {
            a.validate().unwrap_or_else(|e| env::panic_str(&e));
        }
        Self {
            version: STATE_VERSION,
            owner: owner_id,
            pending_owner: None,
            config: config.unwrap_or_default(),
            rules: LookupMap::new(Key::Rules),
            enc_keys: LookupMap::new(Key::EncKeys),
            sign_keys: LookupMap::new(Key::SignKeys),
            gateways: IterableMap::new(Key::Gateways),
            cred_epochs: LookupMap::new(Key::CredEpochs),
            anchors: LookupMap::new(Key::Anchors),
            anchor_authorities: LookupMap::new(Key::AnchorAuthorities),
            assets,
            payers: LookupMap::new(Key::Payers),
            earnings: LookupMap::new(Key::Earnings),
            settled: LookupMap::new(Key::Settled),
            settlers: IterableMap::new(Key::Settlers),
            settler_auths: LookupMap::new(Key::SettlerAuths),
            sponsorships: LookupSet::new(Key::Sponsorships),
        }
    }

    /// Upgrade the stored state to this code's layout. Call it (as the
    /// contract account) in the same transaction as the code deployment.
    /// Version 1 is the current layout, so this only checks the version.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let raw = env::storage_read(b"STATE").unwrap_or_else(|| env::panic_str("no state"));
        let version = raw
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or_else(|| env::panic_str("state too short"));
        match version {
            STATE_VERSION => near_sdk::borsh::from_slice::<Self>(&raw)
                .unwrap_or_else(|_| env::panic_str("cannot decode state")),
            v => env::panic_str(&format!(
                "cannot migrate state version {v} (this code is version {STATE_VERSION})"
            )),
        }
    }

    pub fn get_state_version(&self) -> u32 {
        self.version
    }

    // ---------------------------------------------------------------- policy

    /// Replace the caller's namespace policy. Empty `rules` deletes it.
    /// Attach NEAR for storage growth; the excess is refunded.
    #[payable]
    pub fn set_rules(&mut self, rules: Vec<Rule>) {
        validate::validate_rules(&rules).unwrap_or_else(|e| env::panic_str(&e));
        let ns = env::predecessor_account_id();
        let start = env::storage_usage();
        if rules.is_empty() {
            self.rules.remove(&ns);
        } else {
            self.rules.insert(ns.clone(), rules);
        }
        self.rules.flush();
        self.charge_storage(&ns, start);
        env::log_str(&format!("EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"set_rules\",\"data\":[{{\"namespace\":\"{ns}\"}}]}}"));
    }

    pub fn get_rules(&self, namespace: AccountId) -> Vec<Rule> {
        self.rules.get(&namespace).cloned().unwrap_or_default()
    }

    // ------------------------------------------------------- encryption keys

    /// Publish the caller's `x25519:<base58>` key for receiving shared objects.
    #[payable]
    pub fn set_enc_key(&mut self, key: String) {
        validate::validate_enc_key(&key).unwrap_or_else(|e| env::panic_str(&e));
        let acct = env::predecessor_account_id();
        let start = env::storage_usage();
        self.enc_keys.insert(acct.clone(), key);
        self.enc_keys.flush();
        self.charge_storage(&acct, start);
    }

    /// Remove the caller's published key (refunds its storage).
    #[payable]
    pub fn remove_enc_key(&mut self) {
        let acct = env::predecessor_account_id();
        let start = env::storage_usage();
        self.enc_keys.remove(&acct);
        self.enc_keys.flush();
        self.charge_storage(&acct, start);
    }

    pub fn get_enc_key(&self, account_id: AccountId) -> Option<String> {
        self.enc_keys.get(&account_id).cloned()
    }

    // ---------------------------------------------------------- signing keys

    /// Publish the caller's `ed25519:<base58>` record-signing key. Appended to
    /// the caller's history unless it equals the latest entry; the history
    /// keeps the newest `MAX_SIGN_KEYS` entries. Attach NEAR for storage.
    #[payable]
    pub fn set_sign_key(&mut self, key: String) {
        validate::validate_sign_key(&key).unwrap_or_else(|e| env::panic_str(&e));
        let acct = env::predecessor_account_id();
        let start = env::storage_usage();
        let mut hist = self.sign_keys.get(&acct).cloned().unwrap_or_default();
        if hist.last().map(|e| &e.key) != Some(&key) {
            if hist.len() >= validate::MAX_SIGN_KEYS {
                hist.drain(..=hist.len() - validate::MAX_SIGN_KEYS);
            }
            hist.push(SignKeyEntry {
                key: key.clone(),
                since_ms: U64(env::block_timestamp_ms()),
            });
            self.sign_keys.insert(acct.clone(), hist);
            self.sign_keys.flush();
            env::log_str(&format!("EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"set_sign_key\",\"data\":[{{\"account_id\":\"{acct}\",\"key\":\"{key}\"}}]}}"));
        }
        self.charge_storage(&acct, start);
    }

    /// The account's signing-key history, oldest first (empty if none).
    pub fn get_sign_keys(&self, account_id: AccountId) -> Vec<SignKeyEntry> {
        self.sign_keys.get(&account_id).cloned().unwrap_or_default()
    }

    // ----------------------------------------------------------- sponsorship

    /// Agree (`allowed = true`) or stop agreeing to pay for `namespace`'s
    /// rules that name the caller as `payer`. Without it such a rule bills
    /// the namespace owner instead (enforced by gateways and the billing
    /// service; see docs/payments.md). Attach NEAR for storage.
    #[payable]
    pub fn set_sponsorship(&mut self, namespace: AccountId, allowed: bool) {
        let payer = env::predecessor_account_id();
        let start = env::storage_usage();
        let key = (payer.clone(), namespace.clone());
        if allowed {
            self.sponsorships.insert(key);
        } else {
            self.sponsorships.remove(&key);
        }
        self.charge_storage(&payer, start);
        env::log_str(&format!("EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"set_sponsorship\",\"data\":[{{\"payer\":\"{payer}\",\"namespace\":\"{namespace}\",\"allowed\":{allowed}}}]}}"));
    }

    /// Whether `payer` agreed to pay for `namespace`. A namespace always pays
    /// for itself.
    pub fn is_sponsor(&self, payer: AccountId, namespace: AccountId) -> bool {
        payer == namespace || self.sponsorships.contains(&(payer, namespace))
    }

    // ---------------------------------------------------- credential epochs

    /// Invalidate every hosted-S3 credential the caller was issued so far.
    #[payable]
    pub fn bump_cred_epoch(&mut self) -> u64 {
        let acct = env::predecessor_account_id();
        let start = env::storage_usage();
        let next = self.cred_epochs.get(&acct).copied().unwrap_or(0) + 1;
        self.cred_epochs.insert(acct.clone(), next);
        self.cred_epochs.flush();
        self.charge_storage(&acct, start);
        next
    }

    pub fn get_cred_epoch(&self, account_id: AccountId) -> u64 {
        self.cred_epochs.get(&account_id).copied().unwrap_or(0)
    }

    // --------------------------------------------------------------- anchors

    /// Authorize a registered gateway to submit anchors for the caller's own
    /// namespace. `None` revokes it. The gateway must still be active when
    /// `anchor` is called. The owner can always anchor.
    #[payable]
    pub fn set_anchor_authority(&mut self, gateway: Option<AccountId>) {
        let ns = env::predecessor_account_id();
        let start = env::storage_usage();
        match gateway {
            Some(gateway) => {
                self.anchor_authorities.insert(ns.clone(), gateway);
            }
            None => {
                self.anchor_authorities.remove(&ns);
            }
        }
        self.anchor_authorities.flush();
        self.charge_storage(&ns, start);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"set_anchor_authority\",\"data\":[{{\"namespace\":\"{ns}\"}}]}}"
        ));
    }

    pub fn get_anchor_authority(&self, namespace: AccountId) -> Option<AccountId> {
        self.anchor_authorities.get(&namespace).cloned()
    }

    /// Record a Merkle root of the namespace's pointer records. Callable by
    /// the namespace owner or a gateway the owner authorized for that
    /// namespace. `seq` must strictly increase; the owner can reset it with
    /// `clear_anchor` after a poisoned/unreachable sequence.
    #[payable]
    pub fn anchor(&mut self, namespace: AccountId, root: String, seq: u64) {
        validate::validate_root(&root).unwrap_or_else(|e| env::panic_str(&e));
        let caller = env::predecessor_account_id();
        let authorized = caller == namespace
            || (self.anchor_authorities.get(&namespace) == Some(&caller)
                && self.is_active_gateway(&caller));
        require!(
            authorized,
            "only the namespace owner or an authorized active gateway can anchor"
        );
        let prev = self.anchors.get(&namespace);
        if let Some(prev) = &prev {
            require!(
                seq > prev.seq,
                format!("seq must be greater than {}", prev.seq)
            );
        }
        let prev_payer = prev.as_ref().map(|a| a.payer.clone());
        let start = env::storage_usage();
        self.anchors.insert(
            namespace,
            Anchor {
                root,
                seq,
                by: caller.clone(),
                payer: caller.clone(),
                block_height: U64(env::block_height()),
                timestamp_ns: U64(env::block_timestamp()),
            },
        );
        self.anchors.flush();
        self.settle_anchor_storage(&caller, prev_payer.as_ref(), start);
    }

    /// Delete the caller's anchor and refund its storage. This is the owner's
    /// escape hatch if an authorized gateway ever submits a poisoned root or
    /// an unreachable `seq`.
    #[payable]
    pub fn clear_anchor(&mut self, namespace: AccountId) {
        let caller = env::predecessor_account_id();
        require!(
            caller == namespace,
            "only the namespace owner can clear the anchor"
        );
        let prev = self
            .anchors
            .get(&namespace)
            .cloned()
            .unwrap_or_else(|| env::panic_str("no anchor"));
        let start = env::storage_usage();
        self.anchors.remove(&namespace);
        self.anchors.flush();
        self.settle_anchor_storage(&caller, Some(&prev.payer), start);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"clear_anchor\",\"data\":[{{\"namespace\":\"{namespace}\"}}]}}"
        ));
    }

    pub fn get_anchor(&self, namespace: AccountId) -> Option<Anchor> {
        self.anchors.get(&namespace).cloned()
    }

    // ----------------------------------------------------------------- owner

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_pending_owner(&self) -> Option<AccountId> {
        self.pending_owner.clone()
    }

    pub fn get_config(&self) -> Config {
        self.config.clone()
    }

    /// Start a two-step ownership transfer. The new owner must call
    /// `accept_owner`, which prevents a typo from permanently losing the
    /// contract.
    pub fn propose_owner(&mut self, owner_id: AccountId) {
        self.assert_owner();
        require!(owner_id != self.owner, "already the owner");
        self.pending_owner = Some(owner_id);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"propose_owner\",\"data\":[{{\"owner\":\"{}\"}}]}}",
            self.owner
        ));
    }

    pub fn accept_owner(&mut self) {
        let pending = self
            .pending_owner
            .clone()
            .unwrap_or_else(|| env::panic_str("no pending owner"));
        require!(
            env::predecessor_account_id() == pending,
            "only the pending owner can accept"
        );
        self.owner = pending;
        self.pending_owner = None;
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"set_owner\",\"data\":[{{\"owner\":\"{}\"}}]}}",
            self.owner
        ));
    }

    pub fn set_config(&mut self, patch: ConfigPatch) {
        self.assert_owner();
        let c = &mut self.config;
        if let Some(v) = patch.gateway_min_stake {
            c.gateway_min_stake = v;
        }
        if let Some(v) = patch.gateway_unstake_delay_sec {
            c.gateway_unstake_delay_sec = v;
        }
        if let Some(v) = patch.withdraw_delay_sec {
            c.withdraw_delay_sec = v;
        }
        if let Some(v) = patch.min_new_payer_deposit {
            c.min_new_payer_deposit = v;
        }
    }
}

impl Contract {
    pub(crate) fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    /// Settle storage staking for a state change that started at `start`
    /// bytes: charge growth to the attached deposit, refund the rest (plus the
    /// cost of any bytes freed) to `account`.
    pub(crate) fn charge_storage(&self, account: &AccountId, start: u64) {
        let attached = env::attached_deposit().as_yoctonear();
        let byte_cost = env::storage_byte_cost().as_yoctonear();
        let end = env::storage_usage();
        let refund = if end > start {
            let need = byte_cost * u128::from(end - start);
            require!(
                attached >= need,
                format!(
                    "attach at least {need} yoctoNEAR to cover {} bytes of storage",
                    end - start
                )
            );
            attached - need
        } else {
            attached.saturating_add(byte_cost * u128::from(start - end))
        };
        self.refund(account, refund);
    }

    pub(crate) fn refund(&self, account: &AccountId, amount: u128) {
        if amount > 0 {
            Promise::new(account.clone())
                .transfer(NearToken::from_yoctonear(amount))
                .detach();
        }
    }

    /// Anchor storage can be paid by a different account than the one that
    /// replaces or clears it. Charge growth to the caller, refund excess
    /// attached deposit to the caller, and refund freed bytes to the previous
    /// storage payer.
    pub(crate) fn settle_anchor_storage(
        &self,
        caller: &AccountId,
        prev_payer: Option<&AccountId>,
        start: u64,
    ) {
        let attached = env::attached_deposit().as_yoctonear();
        let byte_cost = env::storage_byte_cost().as_yoctonear();
        let end = env::storage_usage();
        if end > start {
            let need = byte_cost * u128::from(end - start);
            require!(
                attached >= need,
                format!(
                    "attach at least {need} yoctoNEAR to cover {} bytes of storage",
                    end - start
                )
            );
            self.refund(caller, attached - need);
            return;
        }
        let freed = byte_cost * u128::from(start - end);
        let payer = prev_payer.unwrap_or(caller);
        if payer == caller {
            self.refund(caller, attached.saturating_add(freed));
        } else {
            self.refund(caller, attached);
            self.refund(payer, freed);
        }
    }
}
