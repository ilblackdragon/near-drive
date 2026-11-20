//! Stablecoin escrow (DESIGN.md §6 phase 2).
//!
//! Units: settlement amounts, spend caps and the minimum deposit are in
//! micro-USD (1e-6 USD). An allow-listed asset with `decimals` d (>= 6) holds
//! `amount_usd_micro * 10^(d-6)` token units, i.e. every stablecoin is valued
//! at $1.
//!
//! Funding:
//! - the payer first calls `register_payer` (payable; pays the PayerAccount
//!   storage), then
//! - NEP-141: `<token>.ft_transfer_call(drive.near, amount, msg)` lands in
//!   `ft_on_transfer`; asset id `nep141:<token>`;
//! - NEP-245 (NEAR Intents): `intents.near.mt_transfer_call(drive.near,
//!   "nep141:<token>", amount, msg)` or a signed `transfer` intent with a
//!   `msg` lands in `mt_on_transfer`; asset id `nep245:intents.near:nep141:<token>`.
//!   The tokens stay inside intents.near, as drive.near's intents balance.
//!
//! `msg` is empty (credit the sender) or JSON
//! `{"payer":"alice.near","spend_cap_per_day":"5000000"}`; the cap is only
//! applied when the payer is the sender. The payer must already have
//! registered, so token deposits cannot grow contract-paid state.
//!
//! Spending: approved settlers call `settle`. Each entry is applied whole or
//! not at all, at most once per (settler, payer, period_id), within the
//! payer's daily cap and balance. `any_gateway = true` is the owner-approved
//! billing lane; `any_gateway = false` self-settlers must also be authorized
//! by the payer. Payers withdraw with a notice period, so usage served before
//! the request can still be settled.
use crate::{validate, Contract, ContractExt, SEC};
use near_sdk::{
    assert_one_yocto, env,
    json_types::{U128, U64},
    near, require,
    serde_json::{self, json},
    AccountId, Gas, NearToken, Promise, PromiseOrValue,
};

pub const MAX_ASSETS: usize = 8;
pub const MAX_SETTLE_ENTRIES: usize = 100;
pub const MAX_AUTHORIZED_SETTLERS: usize = 32;
const DAY_NS: u64 = 24 * 3600 * SEC;
const PAYOUT_GAS: Gas = Gas::from_tgas(20);
const ON_PAYOUT_GAS: Gas = Gas::from_tgas(10);

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct AssetConfig {
    /// `nep141:<token>` or `nep245:<mt contract>:<token id>`.
    pub id: String,
    /// Token decimals, >= 6 (USDC/USDT on NEAR: 6).
    pub decimals: u8,
    /// False stops new deposits; balances stay spendable and withdrawable.
    pub accept_deposits: bool,
}

pub(crate) enum AssetKind {
    Ft(AccountId),
    Mt(AccountId, String),
}

impl AssetConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !(6..=24).contains(&self.decimals) {
            return Err("decimals must be 6..=24".into());
        }
        self.kind().map(|_| ())
    }

    pub(crate) fn kind(&self) -> Result<AssetKind, String> {
        let bad = || format!("invalid asset id {:?}", self.id);
        if let Some(t) = self.id.strip_prefix("nep141:") {
            return Ok(AssetKind::Ft(t.parse().map_err(|_| bad())?));
        }
        if let Some(rest) = self.id.strip_prefix("nep245:") {
            let (c, tok) = rest.split_once(':').ok_or_else(bad)?;
            if tok.is_empty() || tok.len() > validate::MAX_TOKEN_ID_LEN {
                return Err(bad());
            }
            return Ok(AssetKind::Mt(
                c.parse().map_err(|_| bad())?,
                tok.to_string(),
            ));
        }
        Err(bad())
    }

    /// Token units per micro-USD.
    pub(crate) fn scale(&self) -> u128 {
        10u128.pow(u32::from(self.decimals) - 6)
    }
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct WithdrawRequest {
    pub asset: String,
    pub amount: U128,
    pub ready_at_ns: U64,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Default)]
pub struct PayerAccount {
    pub balances: Vec<(String, u128)>,
    /// micro-USD per UTC day; None = settlers cannot charge.
    pub spend_cap_per_day: Option<u128>,
    pub day: u64,
    pub spent_today: u128,
    pub withdrawal: Option<WithdrawRequest>,
    /// Whether at least one deposit has been accepted. Used to apply
    /// `min_new_payer_deposit` exactly once, independent of later withdrawals.
    pub funded: bool,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct AssetBalance {
    pub asset: String,
    pub amount: U128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PayerView {
    pub balances: Vec<AssetBalance>,
    /// Spendable value in micro-USD.
    pub available: U128,
    pub spend_cap_per_day: Option<U128>,
    pub spent_today: U128,
    pub pending_withdrawal: Option<WithdrawRequest>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, Default)]
pub struct DepositMsg {
    pub payer: Option<AccountId>,
    pub spend_cap_per_day: Option<U128>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct SettleEntry {
    pub payer: AccountId,
    /// micro-USD.
    pub amount: U128,
    pub gateway: AccountId,
    /// Settler-chosen billing period id, e.g. `"2026-11-19/gw1"`.
    pub period_id: String,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub enum SettleStatus {
    Settled,
    AlreadySettled,
    InvalidEntry,
    GatewayNotAllowed,
    UnknownGateway,
    SettlerNotAuthorized,
    NoSpendCap,
    CapExceeded,
    InsufficientBalance,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct SettleResult {
    pub payer: AccountId,
    pub period_id: String,
    pub status: SettleStatus,
    pub charged: U128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub enum PayoutKind {
    Earnings,
    Balance,
}

fn emit(event: &str, data: serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        json!({"standard": "near-drive", "version": "1.0.0", "event": event, "data": [data]})
    ));
}

fn add_to(v: &mut Vec<(String, u128)>, asset: &str, amount: u128) {
    match v.iter_mut().find(|(a, _)| a == asset) {
        Some((_, b)) => {
            *b = b
                .checked_add(amount)
                .unwrap_or_else(|| env::panic_str("balance overflow"))
        }
        None => v.push((asset.to_string(), amount)),
    }
}

fn sub_from(v: &mut Vec<(String, u128)>, asset: &str, amount: u128) {
    let i = v
        .iter()
        .position(|(a, _)| a == asset)
        .unwrap_or_else(|| env::panic_str("no balance"));
    v[i].1 = v[i]
        .1
        .checked_sub(amount)
        .unwrap_or_else(|| env::panic_str("insufficient balance"));
    if v[i].1 == 0 {
        v.remove(i);
    }
}

fn settle_key(settler: &AccountId, payer: &AccountId, period_id: &str) -> [u8; 32] {
    env::sha256_array(format!("{settler}\0{payer}\0{period_id}").as_bytes())
}

#[near]
impl Contract {
    // -------------------------------------------------------------- deposits

    /// NEP-141 receiver. Returns the unused amount (always 0 when accepted).
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let asset = format!("nep141:{}", env::predecessor_account_id());
        self.credit(&sender_id, &msg, &[(asset, amount.0)]);
        PromiseOrValue::Value(U128(0))
    }

    /// NEP-245 receiver (NEAR Intents). Returns per-token unused amounts.
    pub fn mt_on_transfer(
        &mut self,
        sender_id: AccountId,
        previous_owner_ids: Vec<AccountId>,
        token_ids: Vec<String>,
        amounts: Vec<U128>,
        msg: String,
    ) -> PromiseOrValue<Vec<U128>> {
        require!(
            !token_ids.is_empty()
                && token_ids.len() == amounts.len()
                && previous_owner_ids.len() == token_ids.len(),
            "invalid args"
        );
        require!(
            previous_owner_ids.iter().all(|owner| owner == &sender_id),
            "previous owners must equal sender"
        );
        let mt = env::predecessor_account_id();
        let deposits: Vec<(String, u128)> = token_ids
            .iter()
            .zip(&amounts)
            .map(|(t, a)| (format!("nep245:{mt}:{t}"), a.0))
            .collect();
        self.credit(&sender_id, &msg, &deposits);
        PromiseOrValue::Value(vec![U128(0); amounts.len()])
    }

    /// Create the caller's escrow entry and pay for its storage. Deposits to
    /// an account that has not registered are rejected by `ft_on_transfer` /
    /// `mt_on_transfer`; this is what prevents refundable token deposits from
    /// growing contract-paid state without bound.
    #[payable]
    pub fn register_payer(&mut self) {
        let payer = env::predecessor_account_id();
        require!(
            self.payers.get(&payer).is_none(),
            "payer already registered"
        );
        let start = env::storage_usage();
        self.payers.insert(payer.clone(), PayerAccount::default());
        self.payers.flush();
        self.charge_storage(&payer, start);
        emit("register_payer", json!({"payer": payer}));
    }

    /// Close an empty escrow entry and refund its storage deposit. Balances
    /// and any pending withdrawal must be cleared first.
    #[payable]
    pub fn close_payer(&mut self) {
        let payer = env::predecessor_account_id();
        let acct = self
            .payers
            .get(&payer)
            .cloned()
            .unwrap_or_else(|| env::panic_str("no escrow balance"));
        require!(acct.balances.is_empty(), "withdraw the balance first");
        require!(acct.withdrawal.is_none(), "cancel the withdrawal first");
        let start = env::storage_usage();
        self.payers.remove(&payer);
        self.settler_auths.remove(&payer);
        self.payers.flush();
        self.settler_auths.flush();
        self.charge_storage(&payer, start);
        emit("close_payer", json!({"payer": payer}));
    }

    /// Set the caller's daily spend cap in micro-USD (None = no charges).
    /// Also creates the caller's escrow entry if needed.
    #[payable]
    pub fn set_spend_cap(&mut self, per_day: Option<U128>) {
        let payer = env::predecessor_account_id();
        let start = env::storage_usage();
        let mut acct = self.payers.get(&payer).cloned().unwrap_or_default();
        acct.spend_cap_per_day = per_day.map(|v| v.0);
        self.payers.insert(payer.clone(), acct);
        self.payers.flush();
        self.charge_storage(&payer, start);
    }

    /// Authorize (`allowed = true`) or revoke a self-settler that may charge
    /// the caller. Only `any_gateway = false` settlers need this; the
    /// owner-approved billing operator (`any_gateway = true`) remains a fully
    /// trusted lane.
    #[payable]
    pub fn set_settler_authorization(&mut self, settler: AccountId, allowed: bool) {
        let payer = env::predecessor_account_id();
        require!(
            self.payers.get(&payer).is_some(),
            "register payer before authorizing a settler"
        );
        let start = env::storage_usage();
        let mut list = self.settler_auths.get(&payer).cloned().unwrap_or_default();
        if allowed {
            if !list.contains(&settler) {
                require!(
                    list.len() < MAX_AUTHORIZED_SETTLERS,
                    format!("at most {MAX_AUTHORIZED_SETTLERS} authorized settlers")
                );
                list.push(settler.clone());
            }
        } else {
            list.retain(|s| s != &settler);
        }
        if list.is_empty() {
            self.settler_auths.remove(&payer);
        } else {
            self.settler_auths.insert(payer.clone(), list);
        }
        self.settler_auths.flush();
        self.charge_storage(&payer, start);
        emit(
            "set_settler_authorization",
            json!({"payer": payer, "settler": settler, "allowed": allowed}),
        );
    }

    pub fn is_settler_authorized(&self, payer: AccountId, settler: AccountId) -> bool {
        self.authorized_settler(&payer, &settler)
    }

    pub fn get_settler_authorizations(&self, payer: AccountId) -> Vec<AccountId> {
        self.settler_auths.get(&payer).cloned().unwrap_or_default()
    }

    // ------------------------------------------------------------ settlement

    /// Charge payers for usage and credit gateways. Only approved settlers.
    /// Attach NEAR for the storage of new idempotency/earnings entries
    /// (about 0.001 NEAR per entry); the excess is refunded.
    #[payable]
    pub fn settle(&mut self, entries: Vec<SettleEntry>) -> Vec<SettleResult> {
        let settler = env::predecessor_account_id();
        let any_gateway = *self
            .settlers
            .get(&settler)
            .unwrap_or_else(|| env::panic_str("not an approved settler"));
        require!(
            entries.len() <= MAX_SETTLE_ENTRIES,
            format!("at most {MAX_SETTLE_ENTRIES} entries")
        );
        let today = env::block_timestamp() / DAY_NS;
        let byte_cost = env::storage_byte_cost().as_yoctonear();
        let mut settler_growth: u64 = 0;
        let results = entries
            .into_iter()
            .map(|e| {
                let before = env::storage_usage();
                let status = self.settle_one(&settler, any_gateway, today, &e);
                // LookupMap writes are cached; flush before measuring so the
                // payer's freed rows and the settler's new rows are visible.
                self.payers.flush();
                self.earnings.flush();
                let after = env::storage_usage();
                if after > before {
                    settler_growth = settler_growth.saturating_add(after - before);
                } else if before > after {
                    // Only payer balance rows shrink here (settle never
                    // removes earnings), so the refund belongs to the payer.
                    self.refund(&e.payer, byte_cost * u128::from(before - after));
                }
                let charged = if status == SettleStatus::Settled {
                    e.amount
                } else {
                    U128(0)
                };
                SettleResult {
                    payer: e.payer,
                    period_id: e.period_id,
                    status,
                    charged,
                }
            })
            .collect();
        let need = byte_cost * u128::from(settler_growth);
        let attached = env::attached_deposit().as_yoctonear();
        require!(
            attached >= need,
            format!("attach at least {need} yoctoNEAR to cover {settler_growth} bytes of settlement storage")
        );
        self.refund(&settler, attached - need);
        results
    }

    // ----------------------------------------------------------- withdrawals

    /// Give notice to withdraw `amount` of `asset` after `withdraw_delay_sec`.
    /// Replaces any pending request (and restarts its timer). Until executed,
    /// the funds stay spendable by settlers.
    #[payable]
    pub fn request_withdraw_balance(&mut self, asset: String, amount: U128) -> WithdrawRequest {
        require!(amount.0 > 0, "amount must be positive");
        require!(self.asset(&asset).is_some(), "unknown asset");
        let payer = env::predecessor_account_id();
        let start = env::storage_usage();
        let acct = self
            .payers
            .get_mut(&payer)
            .unwrap_or_else(|| env::panic_str("no escrow balance"));
        let req = WithdrawRequest {
            asset,
            amount,
            ready_at_ns: U64(env::block_timestamp()
                .saturating_add(self.config.withdraw_delay_sec.saturating_mul(SEC))),
        };
        acct.withdrawal = Some(req.clone());
        self.payers.flush();
        self.charge_storage(&payer, start);
        req
    }

    #[payable]
    pub fn cancel_withdraw_balance(&mut self) {
        let payer = env::predecessor_account_id();
        let start = env::storage_usage();
        if let Some(acct) = self.payers.get_mut(&payer) {
            acct.withdrawal = None;
        }
        self.payers.flush();
        self.charge_storage(&payer, start);
    }

    /// Execute a matured withdrawal request: pays out min(requested, balance)
    /// back to the payer (NEP-141 `ft_transfer`, or NEP-245 `mt_transfer`
    /// into the payer's intents account). Attach 1 yoctoNEAR.
    #[payable]
    pub fn withdraw_balance(&mut self) -> Promise {
        assert_one_yocto();
        let payer = env::predecessor_account_id();
        let start = env::storage_usage();
        let req = {
            let acct = self
                .payers
                .get_mut(&payer)
                .unwrap_or_else(|| env::panic_str("no escrow balance"));
            acct.withdrawal
                .take()
                .unwrap_or_else(|| env::panic_str("no withdrawal requested"))
        };
        self.payers.flush();
        let after_take = env::storage_usage();
        require!(
            env::block_timestamp() >= req.ready_at_ns.0,
            format!("withdrawal ready at {} ns", req.ready_at_ns.0)
        );
        let acct = self
            .payers
            .get_mut(&payer)
            .unwrap_or_else(|| env::panic_str("no escrow balance"));
        let have = acct
            .balances
            .iter()
            .find(|(a, _)| *a == req.asset)
            .map(|(_, b)| *b)
            .unwrap_or(0);
        let amount = req.amount.0.min(have);
        require!(amount > 0, "nothing to withdraw");
        sub_from(&mut acct.balances, &req.asset, amount);
        self.payers.flush();
        // Refund the request bytes paid by the payer. The balance row was
        // created by a token deposit (no attached NEAR), so its freed storage
        // stays with the contract to cover that subsidy.
        let request_bytes = start.saturating_sub(after_take);
        if request_bytes > 0 {
            self.refund(
                &payer,
                env::storage_byte_cost().as_yoctonear() * u128::from(request_bytes),
            );
        }
        emit(
            "withdraw_balance",
            json!({"payer": payer, "asset": req.asset, "amount": U128(amount)}),
        );
        self.payout(&req.asset, &payer, amount, PayoutKind::Balance)
    }

    /// Pay out all of the caller's gateway earnings. Attach 1 yoctoNEAR.
    /// NEP-141 payouts need the caller registered with the token
    /// (`storage_deposit`); a failed transfer is credited back.
    #[payable]
    pub fn withdraw_earnings(&mut self) {
        assert_one_yocto();
        let op = env::predecessor_account_id();
        let earned: Vec<_> = self
            .earnings
            .remove(&op)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, a)| *a > 0)
            .collect();
        require!(!earned.is_empty(), "no earnings");
        // One independent payout per asset (joint promises cannot be returned).
        for (asset, amount) in earned {
            emit(
                "withdraw_earnings",
                json!({"gateway": op, "asset": asset, "amount": U128(amount)}),
            );
            self.payout(&asset, &op, amount, PayoutKind::Earnings)
                .detach();
        }
    }

    /// Restores the amount if the token transfer failed.
    #[private]
    pub fn on_payout(
        &mut self,
        account: AccountId,
        asset: String,
        amount: U128,
        kind: PayoutKind,
    ) -> bool {
        // Accept any successful token result. 1024 bytes covers standard
        // implementer payloads (the previous 64-byte cap misread longer
        // successful results as failures).
        if env::promise_result_checked(0, 1024).is_ok() {
            return true;
        }
        match kind {
            PayoutKind::Balance => {
                let mut acct = self.payers.get(&account).cloned().unwrap_or_default();
                acct.funded = true;
                add_to(&mut acct.balances, &asset, amount.0);
                self.payers.insert(account.clone(), acct);
            }
            PayoutKind::Earnings => {
                let mut e = self.earnings.get(&account).cloned().unwrap_or_default();
                add_to(&mut e, &asset, amount.0);
                self.earnings.insert(account.clone(), e);
            }
        }
        emit(
            "payout_failed",
            json!({"account": account, "asset": asset, "amount": amount}),
        );
        false
    }

    // ----------------------------------------------------------------- views

    pub fn get_payer(&self, account_id: AccountId) -> Option<PayerView> {
        let a = self.payers.get(&account_id)?;
        let today = env::block_timestamp() / DAY_NS;
        Some(PayerView {
            balances: a
                .balances
                .iter()
                .map(|(asset, b)| AssetBalance {
                    asset: asset.clone(),
                    amount: U128(*b),
                })
                .collect(),
            available: U128(self.available(a)),
            spend_cap_per_day: a.spend_cap_per_day.map(U128),
            spent_today: U128(if a.day == today { a.spent_today } else { 0 }),
            pending_withdrawal: a.withdrawal.clone(),
        })
    }

    pub fn get_earnings(&self, account_id: AccountId) -> Vec<AssetBalance> {
        self.earnings
            .get(&account_id)
            .map(|v| {
                v.iter()
                    .map(|(asset, b)| AssetBalance {
                        asset: asset.clone(),
                        amount: U128(*b),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn is_settled(&self, settler: AccountId, payer: AccountId, period_id: String) -> bool {
        self.settled
            .contains(&settle_key(&settler, &payer, &period_id))
    }

    pub fn get_assets(&self) -> Vec<AssetConfig> {
        self.assets.clone()
    }

    /// `[(settler, may_credit_any_gateway)]`
    pub fn get_settlers(&self) -> Vec<(AccountId, bool)> {
        self.settlers.iter().map(|(a, b)| (a.clone(), *b)).collect()
    }

    // ----------------------------------------------------------------- owner

    /// Add an asset or change `accept_deposits`. Decimals are immutable.
    pub fn set_asset(&mut self, asset: AssetConfig) {
        self.assert_owner();
        asset.validate().unwrap_or_else(|e| env::panic_str(&e));
        match self.assets.iter_mut().find(|a| a.id == asset.id) {
            Some(a) => {
                require!(a.decimals == asset.decimals, "decimals cannot change");
                a.accept_deposits = asset.accept_deposits;
            }
            None => {
                require!(
                    self.assets.len() < MAX_ASSETS,
                    format!("at most {MAX_ASSETS} assets")
                );
                self.assets.push(asset);
            }
        }
    }

    /// `any_gateway = false` limits the settler to crediting itself (a gateway
    /// operator billing its own usage); `true` is for billing operators.
    pub fn add_settler(&mut self, account_id: AccountId, any_gateway: bool) {
        self.assert_owner();
        self.settlers.insert(account_id, any_gateway);
    }

    pub fn remove_settler(&mut self, account_id: AccountId) {
        self.assert_owner();
        self.settlers.remove(&account_id);
    }
}

impl Contract {
    pub(crate) fn asset(&self, id: &str) -> Option<&AssetConfig> {
        self.assets.iter().find(|a| a.id == id)
    }

    /// Spendable micro-USD across all assets.
    fn available(&self, a: &PayerAccount) -> u128 {
        a.balances
            .iter()
            .filter_map(|(id, b)| self.asset(id).map(|c| b / c.scale()))
            .fold(0u128, |acc, v| acc.saturating_add(v))
    }

    fn authorized_settler(&self, payer: &AccountId, settler: &AccountId) -> bool {
        self.settler_auths
            .get(payer)
            .is_some_and(|v| v.contains(settler))
    }

    /// Accounts that hold tokens on behalf of others (NEP-245 contracts such
    /// as intents.near): deposits sent *from* them must name the payer.
    fn is_custodian(&self, account: &AccountId) -> bool {
        self.assets
            .iter()
            .any(|a| matches!(a.kind(), Ok(AssetKind::Mt(c, _)) if &c == account))
    }

    fn credit(&mut self, sender: &AccountId, msg: &str, deposits: &[(String, u128)]) {
        let m: DepositMsg = if msg.trim().is_empty() {
            DepositMsg::default()
        } else {
            serde_json::from_str(msg)
                .unwrap_or_else(|e| env::panic_str(&format!("invalid msg: {e}")))
        };
        if m.payer.is_none() && self.is_custodian(sender) {
            env::panic_str("deposits relayed by an intents contract must set msg.payer");
        }
        let payer = m.payer.unwrap_or_else(|| sender.clone());
        let mut usd: u128 = 0;
        for (asset, amount) in deposits {
            let cfg = self
                .asset(asset)
                .unwrap_or_else(|| env::panic_str(&format!("asset {asset} is not accepted")));
            require!(
                cfg.accept_deposits,
                format!("asset {asset} is not accepting deposits")
            );
            require!(*amount > 0, "amount must be positive");
            usd = usd.saturating_add(amount / cfg.scale());
        }
        let mut acct =
            self.payers.get(&payer).cloned().unwrap_or_else(|| {
                env::panic_str("payer not registered; call register_payer first")
            });
        if !acct.funded {
            require!(
                usd >= self.config.min_new_payer_deposit.0,
                format!(
                    "first deposit must be at least {} micro-USD",
                    self.config.min_new_payer_deposit.0
                )
            );
            acct.funded = true;
        }
        for (asset, amount) in deposits {
            add_to(&mut acct.balances, asset, *amount);
        }
        if let Some(cap) = m.spend_cap_per_day {
            if &payer == sender {
                acct.spend_cap_per_day = Some(cap.0);
            }
        }
        self.payers.insert(payer.clone(), acct);
        for (asset, amount) in deposits {
            emit(
                "deposit",
                json!({"payer": payer, "sender": sender, "asset": asset, "amount": U128(*amount)}),
            );
        }
    }

    fn settle_one(
        &mut self,
        settler: &AccountId,
        any_gateway: bool,
        today: u64,
        e: &SettleEntry,
    ) -> SettleStatus {
        if e.amount.0 == 0 || validate::validate_period_id(&e.period_id).is_err() {
            return SettleStatus::InvalidEntry;
        }
        if !any_gateway && &e.gateway != settler {
            return SettleStatus::GatewayNotAllowed;
        }
        if !self.is_gateway(&e.gateway) {
            return SettleStatus::UnknownGateway;
        }
        if !any_gateway && !self.authorized_settler(&e.payer, settler) {
            return SettleStatus::SettlerNotAuthorized;
        }
        let key = settle_key(settler, &e.payer, &e.period_id);
        if self.settled.contains(&key) {
            return SettleStatus::AlreadySettled;
        }
        let Some(acct) = self.payers.get(&e.payer).cloned() else {
            return SettleStatus::InsufficientBalance;
        };
        let Some(cap) = acct.spend_cap_per_day else {
            return SettleStatus::NoSpendCap;
        };
        let spent = if acct.day == today {
            acct.spent_today
        } else {
            0
        };
        if spent.saturating_add(e.amount.0) > cap {
            return SettleStatus::CapExceeded;
        }
        if self.available(&acct) < e.amount.0 {
            return SettleStatus::InsufficientBalance;
        }
        // Draw from assets in allow-list order.
        let mut acct = acct;
        let mut earned = self.earnings.get(&e.gateway).cloned().unwrap_or_default();
        let mut left = e.amount.0;
        for cfg in &self.assets {
            if left == 0 {
                break;
            }
            let Some(bal) = acct
                .balances
                .iter()
                .find(|(a, _)| *a == cfg.id)
                .map(|(_, b)| *b)
            else {
                continue;
            };
            let take_usd = left.min(bal / cfg.scale());
            if take_usd == 0 {
                continue;
            }
            let units = take_usd * cfg.scale();
            sub_from(&mut acct.balances, &cfg.id, units);
            add_to(&mut earned, &cfg.id, units);
            left -= take_usd;
        }
        require!(left == 0, "internal: balance accounting");
        acct.day = today;
        acct.spent_today = spent.saturating_add(e.amount.0);
        self.payers.insert(e.payer.clone(), acct);
        self.earnings.insert(e.gateway.clone(), earned);
        self.settled.insert(key);
        emit(
            "settle",
            json!({"settler": settler, "payer": e.payer, "gateway": e.gateway, "period_id": e.period_id, "amount": e.amount}),
        );
        SettleStatus::Settled
    }

    fn payout(&self, asset: &str, to: &AccountId, amount: u128, kind: PayoutKind) -> Promise {
        let cfg = self
            .asset(asset)
            .unwrap_or_else(|| env::panic_str("unknown asset"));
        let memo = "NEAR Drive payout";
        let one = NearToken::from_yoctonear(1);
        let p = match cfg.kind().unwrap_or_else(|e| env::panic_str(&e)) {
            AssetKind::Ft(token) => Promise::new(token).function_call(
                "ft_transfer",
                json!({"receiver_id": to, "amount": U128(amount), "memo": memo}).to_string().into_bytes(),
                one,
                PAYOUT_GAS,
            ),
            AssetKind::Mt(mt, token_id) => Promise::new(mt).function_call(
                "mt_transfer",
                json!({"receiver_id": to, "token_id": token_id, "amount": U128(amount), "approval": null, "memo": memo})
                    .to_string()
                    .into_bytes(),
                one,
                PAYOUT_GAS,
            ),
        };
        p.then(
            Self::ext(env::current_account_id())
                .with_static_gas(ON_PAYOUT_GAS)
                .on_payout(to.clone(), asset.to_string(), U128(amount), kind),
        )
    }
}
