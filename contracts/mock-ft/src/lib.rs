//! Minimal NEP-141 token for sandbox tests: `mint`, `storage_deposit`
//! (registration required to receive), `ft_transfer`, `ft_transfer_call` with
//! refunds via `ft_resolve_transfer`.
use near_sdk::{
    assert_one_yocto, env, json_types::U128, near, require, serde_json::json, store::LookupMap, AccountId, Gas,
    NearToken, PanicOnDefault, Promise,
};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Token {
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl Token {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        let b = self.balances.get(&account_id).copied().unwrap_or(0);
        self.balances.insert(account_id, b + amount.0);
    }

    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>, registration_only: Option<bool>) {
        let _ = registration_only;
        let a = account_id.unwrap_or_else(env::predecessor_account_id);
        if self.balances.get(&a).is_none() {
            self.balances.insert(a, 0);
        }
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    fn move_tokens(&mut self, from: &AccountId, to: &AccountId, amount: u128) {
        require!(amount > 0, "zero amount");
        let fb = self.balances.get(from).copied().unwrap_or_else(|| env::panic_str("sender not registered"));
        require!(fb >= amount, "insufficient balance");
        let tb = self.balances.get(to).copied().unwrap_or_else(|| env::panic_str("receiver not registered"));
        self.balances.insert(from.clone(), fb - amount);
        self.balances.insert(to.clone(), tb + amount);
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let _ = memo;
        self.move_tokens(&env::predecessor_account_id(), &receiver_id, amount.0);
    }

    #[payable]
    pub fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>, msg: String) -> Promise {
        assert_one_yocto();
        let _ = memo;
        let sender = env::predecessor_account_id();
        self.move_tokens(&sender, &receiver_id, amount.0);
        Promise::new(receiver_id.clone())
            .function_call(
                "ft_on_transfer",
                json!({"sender_id": sender, "amount": amount, "msg": msg}).to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(40),
            )
            .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(10)).ft_resolve_transfer(
                sender,
                receiver_id,
                amount,
            ))
    }

    #[private]
    pub fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128 {
        let unused = match env::promise_result_checked(0, 128) {
            Ok(v) => near_sdk::serde_json::from_slice::<U128>(&v).map(|u| u.0.min(amount.0)).unwrap_or(amount.0),
            Err(_) => amount.0,
        };
        if unused > 0 {
            let rb = self.balances.get(&receiver_id).copied().unwrap_or(0);
            let refund = unused.min(rb);
            self.balances.insert(receiver_id, rb - refund);
            let sb = self.balances.get(&sender_id).copied().unwrap_or(0);
            self.balances.insert(sender_id, sb + refund);
        }
        U128(amount.0 - unused)
    }
}

