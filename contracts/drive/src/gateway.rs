//! Gateway registry: anyone can list a gateway by staking NEAR, like a
//! public RPC. SDKs read `list_gateways`, probe `/healthz` and pick one.
use crate::{validate, Contract, ContractExt, SEC};
use near_sdk::{
    assert_one_yocto, env,
    json_types::{U128, U64},
    near, require, AccountId, Gas, NearToken, Promise,
};

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct GatewayInfo {
    pub url: String,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub backends: Vec<String>,
    /// Free-form price description, e.g. `"storage=0.02usd/gib-mo;egress=0.01usd/gib"`.
    #[serde(default)]
    pub price_hint: String,
    /// TEE attestation (e.g. base64 TDX quote) for hosted S3 endpoints.
    #[serde(default)]
    pub attestation: Option<String>,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Gateway {
    pub info: GatewayInfo,
    /// NEAR stake (yocto), returned by `withdraw_gateway_stake`.
    pub stake: u128,
    pub registered_at: u64,
    /// 0 while active; block timestamp once deregistered (including by the
    /// owner with `force_deregister_gateway`).
    pub deregistered_at: u64,
    /// Withdrawal unlocks at this timestamp. Snapshotted at deregistration so
    /// a later config change cannot extend a gateway's lockup.
    pub unlock_at_ns: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct GatewayView {
    pub operator: AccountId,
    pub url: String,
    pub regions: Vec<String>,
    pub backends: Vec<String>,
    pub price_hint: String,
    pub attestation: Option<String>,
    pub stake: U128,
    pub registered_at_ns: U64,
    /// False once deregistered (the stake is then waiting out the delay).
    pub active: bool,
    pub stake_unlock_at_ns: Option<U64>,
}

pub const MAX_LIST_LIMIT: u32 = 100;
const ON_WITHDRAW_GAS: Gas = Gas::from_tgas(10);

#[near]
impl Contract {
    /// Register the caller as a gateway operator. Attach at least
    /// `gateway_min_stake` plus the storage cost of the entry; everything
    /// above the storage cost becomes the stake.
    #[payable]
    pub fn register_gateway(&mut self, info: GatewayInfo) {
        validate::validate_gateway(&info).unwrap_or_else(|e| env::panic_str(&e));
        let op = env::predecessor_account_id();
        require!(
            self.gateways.get(&op).is_none(),
            "already registered (deregister and withdraw the stake first)"
        );
        let start = env::storage_usage();
        self.gateways.insert(
            op.clone(),
            Gateway {
                info,
                stake: 0,
                registered_at: env::block_timestamp(),
                deregistered_at: 0,
                unlock_at_ns: 0,
            },
        );
        self.gateways.flush();
        let storage = env::storage_byte_cost().as_yoctonear()
            * u128::from(env::storage_usage().saturating_sub(start));
        let attached = env::attached_deposit().as_yoctonear();
        let min = self.config.gateway_min_stake.0;
        let need = storage
            .checked_add(min)
            .unwrap_or_else(|| env::panic_str("gateway stake overflow"));
        require!(
            attached >= need,
            format!("attach at least {need} yoctoNEAR (stake {min} + storage {storage})")
        );
        self.gateways.get_mut(&op).unwrap().stake = attached - storage;
        env::log_str(&format!("EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"register_gateway\",\"data\":[{{\"operator\":\"{op}\"}}]}}"));
    }

    /// Replace the caller's gateway info. Attach NEAR if it grows.
    #[payable]
    pub fn update_gateway(&mut self, info: GatewayInfo) {
        validate::validate_gateway(&info).unwrap_or_else(|e| env::panic_str(&e));
        let op = env::predecessor_account_id();
        let start = env::storage_usage();
        let g = self
            .gateways
            .get_mut(&op)
            .unwrap_or_else(|| env::panic_str("not a registered gateway"));
        require!(g.deregistered_at == 0, "gateway is deregistered");
        g.info = info;
        self.gateways.flush();
        self.charge_storage(&op, start);
        env::log_str(&format!("EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"update_gateway\",\"data\":[{{\"operator\":\"{op}\"}}]}}"));
    }

    /// Stop being listed as active. The stake unlocks after the delay in
    /// effect at this moment; later owner config changes do not extend it.
    /// Earnings stay withdrawable.
    #[payable]
    pub fn deregister_gateway(&mut self) {
        assert_one_yocto();
        let op = env::predecessor_account_id();
        self.mark_deregistered(&op);
        env::log_str(&format!("EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"deregister_gateway\",\"data\":[{{\"operator\":\"{op}\"}}]}}"));
    }

    /// Owner escape hatch: stop a gateway from anchoring/settling as active
    /// without waiting for it to deregister. The stake is still withdrawable
    /// by the operator after the snapshotted delay.
    pub fn force_deregister_gateway(&mut self, operator: AccountId) {
        self.assert_owner();
        self.mark_deregistered(&operator);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"force_deregister_gateway\",\"data\":[{{\"operator\":\"{operator}\"}}]}}"
        ));
    }

    /// After the unstake delay, remove the entry and return stake + storage.
    /// On transfer failure the callback restores the entry so the operator can
    /// retry instead of losing its stake.
    #[payable]
    pub fn withdraw_gateway_stake(&mut self) -> Promise {
        assert_one_yocto();
        let op = env::predecessor_account_id();
        let g = self
            .gateways
            .get(&op)
            .cloned()
            .unwrap_or_else(|| env::panic_str("not a registered gateway"));
        require!(g.deregistered_at != 0, "deregister first");
        require!(
            env::block_timestamp() >= g.unlock_at_ns,
            format!("stake unlocks at {} ns", g.unlock_at_ns)
        );
        let start = env::storage_usage();
        self.gateways.remove(&op);
        self.gateways.flush();
        let freed = env::storage_byte_cost().as_yoctonear()
            * u128::from(start.saturating_sub(env::storage_usage()));
        let amount = g
            .stake
            .checked_add(freed)
            .and_then(|v| v.checked_add(1))
            .unwrap_or_else(|| env::panic_str("stake payout overflow"));
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"withdraw_gateway_stake\",\"data\":[{{\"operator\":\"{op}\"}}]}}"
        ));
        Promise::new(op.clone())
            .transfer(NearToken::from_yoctonear(amount))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(ON_WITHDRAW_GAS)
                    .on_withdraw_gateway_stake(
                        op,
                        g.info,
                        U128(g.stake),
                        U64(g.registered_at),
                        U64(g.deregistered_at),
                        U64(g.unlock_at_ns),
                    ),
            )
    }

    /// Restores the removed gateway entry if the stake transfer failed.
    #[private]
    pub fn on_withdraw_gateway_stake(
        &mut self,
        operator: AccountId,
        info: GatewayInfo,
        stake: U128,
        registered_at: U64,
        deregistered_at: U64,
        unlock_at_ns: U64,
    ) -> bool {
        if env::promise_result_checked(0, 1024).is_ok() {
            return true;
        }
        if let Some(mut current) = self.gateways.get(&operator).cloned() {
            // The operator re-registered while the transfer was in flight;
            // keep the new entry and add the old stake back to it.
            current.stake = current
                .stake
                .checked_add(stake.0)
                .unwrap_or_else(|| env::panic_str("gateway stake overflow"));
            self.gateways.insert(operator.clone(), current);
        } else {
            self.gateways.insert(
                operator.clone(),
                Gateway {
                    info,
                    stake: stake.0,
                    registered_at: registered_at.0,
                    deregistered_at: deregistered_at.0,
                    unlock_at_ns: unlock_at_ns.0,
                },
            );
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-drive\",\"version\":\"1.0.0\",\"event\":\"gateway_stake_restored\",\"data\":[{{\"operator\":\"{operator}\"}}]}}"
        ));
        false
    }

    pub fn get_gateway(&self, operator: AccountId) -> Option<GatewayView> {
        self.gateways
            .get(&operator)
            .map(|g| self.view_gateway(&operator, g))
    }

    pub fn list_gateways(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<GatewayView> {
        let limit = limit.unwrap_or(MAX_LIST_LIMIT).min(MAX_LIST_LIMIT) as usize;
        self.gateways
            .iter()
            .skip(from_index.unwrap_or(0) as usize)
            .take(limit)
            .map(|(op, g)| self.view_gateway(op, g))
            .collect()
    }

    pub fn gateways_count(&self) -> u32 {
        self.gateways.len()
    }
}

impl Contract {
    fn view_gateway(&self, op: &AccountId, g: &Gateway) -> GatewayView {
        GatewayView {
            operator: op.clone(),
            url: g.info.url.clone(),
            regions: g.info.regions.clone(),
            backends: g.info.backends.clone(),
            price_hint: g.info.price_hint.clone(),
            attestation: g.info.attestation.clone(),
            stake: U128(g.stake),
            registered_at_ns: U64(g.registered_at),
            active: g.deregistered_at == 0,
            stake_unlock_at_ns: (g.deregistered_at != 0).then_some(U64(g.unlock_at_ns)),
        }
    }

    fn mark_deregistered(&mut self, op: &AccountId) {
        let delay = self.config.gateway_unstake_delay_sec.saturating_mul(SEC);
        let g = self
            .gateways
            .get_mut(op)
            .unwrap_or_else(|| env::panic_str("not a registered gateway"));
        require!(g.deregistered_at == 0, "already deregistered");
        let at = env::block_timestamp().max(1);
        g.deregistered_at = at;
        g.unlock_at_ns = at.saturating_add(delay);
    }

    /// Known to the registry (active or waiting out the unstake delay).
    pub(crate) fn is_gateway(&self, op: &AccountId) -> bool {
        self.gateways.get(op).is_some()
    }

    pub(crate) fn is_active_gateway(&self, op: &AccountId) -> bool {
        self.gateways
            .get(op)
            .is_some_and(|g| g.deregistered_at == 0)
    }
}
