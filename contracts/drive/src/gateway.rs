//! Gateway registry: anyone can list a gateway by staking NEAR, like a
//! public RPC. SDKs read `list_gateways`, probe `/healthz` and pick one.
use crate::{validate, Contract, ContractExt, SEC};
use near_sdk::{
    assert_one_yocto, env,
    json_types::{U128, U64},
    near, require, AccountId, NearToken, Promise,
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
    pub deregistered_at: Option<u64>,
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

#[near]
impl Contract {
    /// Register the caller as a gateway operator. Attach at least
    /// `gateway_min_stake` plus the storage cost of the entry; everything
    /// above the storage cost becomes the stake.
    #[payable]
    pub fn register_gateway(&mut self, info: GatewayInfo) {
        validate::validate_gateway(&info).unwrap_or_else(|e| env::panic_str(&e));
        let op = env::predecessor_account_id();
        require!(self.gateways.get(&op).is_none(), "already registered (deregister and withdraw the stake first)");
        let start = env::storage_usage();
        self.gateways.insert(op.clone(), Gateway { info, stake: 0, registered_at: env::block_timestamp(), deregistered_at: None });
        self.gateways.flush();
        let storage = env::storage_byte_cost().as_yoctonear() * u128::from(env::storage_usage().saturating_sub(start));
        let attached = env::attached_deposit().as_yoctonear();
        let min = self.config.gateway_min_stake.0;
        require!(
            attached >= storage + min,
            format!("attach at least {} yoctoNEAR (stake {min} + storage {storage})", storage + min)
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
        let g = self.gateways.get_mut(&op).unwrap_or_else(|| env::panic_str("not a registered gateway"));
        require!(g.deregistered_at.is_none(), "gateway is deregistered");
        g.info = info;
        self.gateways.flush();
        self.charge_storage(&op, start);
    }

    /// Stop being listed as active. The stake unlocks after
    /// `gateway_unstake_delay_sec`; earnings stay withdrawable.
    #[payable]
    pub fn deregister_gateway(&mut self) {
        assert_one_yocto();
        let op = env::predecessor_account_id();
        let g = self.gateways.get_mut(&op).unwrap_or_else(|| env::panic_str("not a registered gateway"));
        require!(g.deregistered_at.is_none(), "already deregistered");
        g.deregistered_at = Some(env::block_timestamp());
    }

    /// After the unstake delay, remove the entry and return stake + storage.
    #[payable]
    pub fn withdraw_gateway_stake(&mut self) -> Promise {
        assert_one_yocto();
        let op = env::predecessor_account_id();
        let g = self.gateways.get(&op).cloned().unwrap_or_else(|| env::panic_str("not a registered gateway"));
        let at = g.deregistered_at.unwrap_or_else(|| env::panic_str("deregister first"));
        let unlock = at.saturating_add(self.config.gateway_unstake_delay_sec.saturating_mul(SEC));
        require!(env::block_timestamp() >= unlock, format!("stake unlocks at {unlock} ns"));
        let start = env::storage_usage();
        self.gateways.remove(&op);
        self.gateways.flush();
        let freed = env::storage_byte_cost().as_yoctonear() * u128::from(start.saturating_sub(env::storage_usage()));
        Promise::new(op).transfer(NearToken::from_yoctonear(g.stake + freed + 1))
    }

    pub fn get_gateway(&self, operator: AccountId) -> Option<GatewayView> {
        self.gateways.get(&operator).map(|g| self.view_gateway(&operator, g))
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
        let delay = self.config.gateway_unstake_delay_sec.saturating_mul(SEC);
        GatewayView {
            operator: op.clone(),
            url: g.info.url.clone(),
            regions: g.info.regions.clone(),
            backends: g.info.backends.clone(),
            price_hint: g.info.price_hint.clone(),
            attestation: g.info.attestation.clone(),
            stake: U128(g.stake),
            registered_at_ns: U64(g.registered_at),
            active: g.deregistered_at.is_none(),
            stake_unlock_at_ns: g.deregistered_at.map(|t| U64(t.saturating_add(delay))),
        }
    }

    /// Known to the registry (active or waiting out the unstake delay).
    pub(crate) fn is_gateway(&self, op: &AccountId) -> bool {
        self.gateways.get(op).is_some()
    }
}
