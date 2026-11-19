//! Minimal NEP-245 multi-token contract standing in for `intents.near` in
//! sandbox tests. Mirrors the defuse semantics that matter to storage.near:
//! `mt_transfer_call` moves the balance, calls the receiver's
//! `mt_on_transfer(sender_id, previous_owner_ids, token_ids, amounts, msg)`
//! and refunds the returned unused amounts in `mt_resolve_transfer`.
use near_sdk::{
    assert_one_yocto, env, json_types::U128, near, require, serde_json::json, store::LookupMap, AccountId, Gas,
    NearToken, PanicOnDefault, Promise,
};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Mt {
    balances: LookupMap<(AccountId, String), u128>,
}

#[near]
impl Mt {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    pub fn mint(&mut self, account_id: AccountId, token_id: String, amount: U128) {
        let k = (account_id, token_id);
        let b = self.balances.get(&k).copied().unwrap_or(0);
        self.balances.insert(k, b + amount.0);
    }

    pub fn mt_balance_of(&self, account_id: AccountId, token_id: String) -> U128 {
        U128(self.balances.get(&(account_id, token_id)).copied().unwrap_or(0))
    }

    fn move_tokens(&mut self, from: &AccountId, to: &AccountId, token_id: &str, amount: u128) {
        require!(amount > 0 && from != to, "invalid transfer");
        let fk = (from.clone(), token_id.to_string());
        let fb = self.balances.get(&fk).copied().unwrap_or(0);
        require!(fb >= amount, "insufficient balance");
        self.balances.insert(fk, fb - amount);
        let tk = (to.clone(), token_id.to_string());
        let tb = self.balances.get(&tk).copied().unwrap_or(0);
        self.balances.insert(tk, tb + amount);
    }

    #[payable]
    pub fn mt_transfer(
        &mut self,
        receiver_id: AccountId,
        token_id: String,
        amount: U128,
        approval: Option<(AccountId, u64)>,
        memo: Option<String>,
    ) {
        assert_one_yocto();
        require!(approval.is_none(), "approvals are not supported");
        let _ = memo;
        self.move_tokens(&env::predecessor_account_id(), &receiver_id, &token_id, amount.0);
    }

    #[payable]
    pub fn mt_transfer_call(
        &mut self,
        receiver_id: AccountId,
        token_id: String,
        amount: U128,
        approval: Option<(AccountId, u64)>,
        memo: Option<String>,
        msg: String,
    ) -> Promise {
        assert_one_yocto();
        require!(approval.is_none(), "approvals are not supported");
        let _ = memo;
        let sender = env::predecessor_account_id();
        self.move_tokens(&sender, &receiver_id, &token_id, amount.0);
        Promise::new(receiver_id.clone())
            .function_call(
                "mt_on_transfer",
                json!({
                    "sender_id": sender,
                    "previous_owner_ids": [sender],
                    "token_ids": [token_id],
                    "amounts": [amount],
                    "msg": msg,
                })
                .to_string()
                .into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(40),
            )
            .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(15)).mt_resolve_transfer(
                vec![sender],
                receiver_id,
                vec![token_id],
                vec![amount],
            ))
    }

    #[private]
    pub fn mt_resolve_transfer(
        &mut self,
        previous_owner_ids: Vec<AccountId>,
        receiver_id: AccountId,
        token_ids: Vec<String>,
        amounts: Vec<U128>,
    ) -> Vec<U128> {
        let refunds: Vec<U128> = env::promise_result_checked(0, 4096)
            .ok()
            .and_then(|v| near_sdk::serde_json::from_slice::<Vec<U128>>(&v).ok())
            .filter(|r| r.len() == amounts.len())
            .unwrap_or_else(|| amounts.clone());
        let mut used = Vec::new();
        for (((owner, token), amount), refund) in previous_owner_ids.iter().zip(&token_ids).zip(&amounts).zip(&refunds) {
            let rk = (receiver_id.clone(), token.clone());
            let rb = self.balances.get(&rk).copied().unwrap_or(0);
            let r = refund.0.min(amount.0).min(rb);
            if r > 0 {
                self.balances.insert(rk, rb - r);
                let ok = (owner.clone(), token.clone());
                let ob = self.balances.get(&ok).copied().unwrap_or(0);
                self.balances.insert(ok, ob + r);
            }
            used.push(U128(amount.0 - r));
        }
        used
    }
}
