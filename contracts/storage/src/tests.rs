use crate::escrow::{PayoutKind, SettleStatus};
use crate::*;
use near_sdk::{
    json_types::U128,
    mock::MockAction,
    test_utils::{get_created_receipts, get_logs, VMContextBuilder},
    testing_env, PromiseOrValue, PromiseResult, RuntimeFeesConfig,
};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const DAY: u64 = 24 * 3600 * SEC;
const USDC: &str = "usdc.near";
const DAI: &str = "dai.near";
const INTENTS: &str = "intents.near";

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn ctx_at(pred: &str, deposit: u128, ts: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(acc("storage.near"))
        .predecessor_account_id(acc(pred))
        .signer_account_id(acc(pred))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .block_timestamp(ts)
        .build());
}

fn ctx(pred: &str, deposit: u128) {
    ctx_at(pred, deposit, 1_000 * DAY);
}

fn assets() -> Vec<AssetConfig> {
    vec![
        AssetConfig { id: format!("nep141:{USDC}"), decimals: 6, accept_deposits: true },
        AssetConfig { id: format!("nep245:{INTENTS}:nep141:{USDC}"), decimals: 6, accept_deposits: true },
        AssetConfig { id: format!("nep141:{DAI}"), decimals: 18, accept_deposits: true },
    ]
}

fn setup() -> Contract {
    ctx("owner.near", 0);
    Contract::new(acc("owner.near"), Some(assets()), None)
}

fn rule(prefix: &str, read: &[&str], write: &[&str], payer: Option<&str>) -> Rule {
    Rule {
        prefix: prefix.into(),
        read: read.iter().map(|s| s.to_string()).collect(),
        write: write.iter().map(|s| s.to_string()).collect(),
        payer: payer.map(Into::into),
    }
}

fn transfers() -> Vec<(String, u128)> {
    get_created_receipts()
        .into_iter()
        .flat_map(|r| {
            let to = r.receiver_id.to_string();
            r.actions.into_iter().filter_map(move |a| match a {
                MockAction::Transfer { deposit, .. } => Some((to.clone(), deposit.as_yoctonear())),
                _ => None,
            })
        })
        .collect()
}

fn calls() -> Vec<(String, String, String)> {
    get_created_receipts()
        .into_iter()
        .flat_map(|r| {
            let to = r.receiver_id.to_string();
            r.actions.into_iter().filter_map(move |a| match a {
                MockAction::FunctionCallWeight { method_name, args, .. } => Some((
                    to.clone(),
                    String::from_utf8(method_name).unwrap(),
                    String::from_utf8(args).unwrap(),
                )),
                _ => None,
            })
        })
        .collect()
}

fn gw_info(url: &str) -> GatewayInfo {
    GatewayInfo {
        url: url.into(),
        regions: vec!["eu-west".into()],
        backends: vec!["fs".into(), "r2".into()],
        price_hint: "storage=0.02usd/gib-mo".into(),
        attestation: None,
    }
}

fn register(c: &mut Contract, op: &str) {
    ctx(op, 6 * NEAR);
    c.register_gateway(gw_info(&format!("https://{op}")));
}

fn deposit_ft(c: &mut Contract, token: &str, sender: &str, amount: u128, msg: &str) {
    ctx(token, 0);
    match c.ft_on_transfer(acc(sender), U128(amount), msg.into()) {
        PromiseOrValue::Value(v) => assert_eq!(v.0, 0),
        _ => panic!("expected value"),
    }
}

// ------------------------------------------------------------------ rules

#[test]
fn rules_roundtrip_and_shape() {
    let mut c = setup();
    let rules = vec![
        rule("users/{account}/", &["{account}"], &["{account}", "app.near"], Some("app.near")),
        rule("public/", &["*"], &[], None),
    ];
    ctx("app.near", NEAR);
    c.set_rules(rules.clone());
    assert_eq!(c.get_rules(acc("app.near")), rules);
    assert!(c.get_rules(acc("other.near")).is_empty());
    // Excess deposit refunded to the caller.
    let t = transfers();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].0, "app.near");
    assert!(t[0].1 < NEAR && t[0].1 > NEAR / 2);
    // JSON shape matches nstorage_core::policy::Rule (payer null / missing ok).
    let json = near_sdk::serde_json::to_string(&c.get_rules(acc("app.near"))).unwrap();
    assert_eq!(
        json,
        r#"[{"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},{"prefix":"public/","read":["*"],"write":[],"payer":null}]"#
    );
    let parsed: Vec<Rule> = near_sdk::serde_json::from_str(r#"[{"prefix":"x/"}]"#).unwrap();
    assert_eq!(parsed, vec![rule("x/", &[], &[], None)]);
}

#[test]
#[should_panic(expected = "attach at least")]
fn rules_need_storage_deposit() {
    let mut c = setup();
    ctx("app.near", 0);
    c.set_rules(vec![rule("public/", &["*"], &[], None)]);
}

#[test]
#[should_panic(expected = "rule 0: {account} used but the prefix has no {account}")]
fn rules_validated() {
    let mut c = setup();
    ctx("app.near", NEAR);
    c.set_rules(vec![rule("public/", &["{account}"], &[], None)]);
}

#[test]
fn rules_clear_refunds_storage() {
    let mut c = setup();
    ctx("app.near", NEAR);
    c.set_rules(vec![rule("public/", &["*"], &[], None)]);
    let paid = NEAR - transfers()[0].1;
    ctx("app.near", 0);
    c.set_rules(vec![]);
    assert!(c.get_rules(acc("app.near")).is_empty());
    let t = transfers();
    assert_eq!(t, vec![("app.near".to_string(), paid)]);
}

// ------------------------------------------------------- keys and epochs

#[test]
fn enc_keys() {
    let mut c = setup();
    let k = format!("x25519:{}", bs58::encode([3u8; 32]).into_string());
    ctx("alice.near", NEAR / 10);
    c.set_enc_key(k.clone());
    assert_eq!(c.get_enc_key(acc("alice.near")), Some(k));
    assert_eq!(c.get_enc_key(acc("bob.near")), None);
    ctx("alice.near", 0);
    c.remove_enc_key();
    assert_eq!(c.get_enc_key(acc("alice.near")), None);
}

#[test]
#[should_panic(expected = "x25519 key must be base58 of 32 bytes")]
fn enc_key_validated() {
    let mut c = setup();
    ctx("alice.near", NEAR);
    c.set_enc_key("x25519:abc".into());
}

#[test]
fn cred_epoch() {
    let mut c = setup();
    assert_eq!(c.get_cred_epoch(acc("alice.near")), 0);
    ctx("alice.near", NEAR / 10);
    assert_eq!(c.bump_cred_epoch(), 1);
    ctx("alice.near", 0); // no growth on later bumps
    assert_eq!(c.bump_cred_epoch(), 2);
    assert_eq!(c.get_cred_epoch(acc("alice.near")), 2);
}

// ---------------------------------------------------------------- anchors

#[test]
fn anchors() {
    let mut c = setup();
    ctx("alice.near", NEAR / 10);
    c.anchor(acc("alice.near"), "root1".into(), 1);
    register(&mut c, "gw.near");
    ctx("gw.near", NEAR / 10);
    c.anchor(acc("alice.near"), "root2".into(), 5);
    let a = c.get_anchor(acc("alice.near")).unwrap();
    assert_eq!((a.root.as_str(), a.seq, a.by.as_str()), ("root2", 5, "gw.near"));
    assert!(c.get_anchor(acc("bob.near")).is_none());
}

#[test]
#[should_panic(expected = "seq must be greater than 5")]
fn anchor_seq_monotonic() {
    let mut c = setup();
    ctx("alice.near", NEAR / 10);
    c.anchor(acc("alice.near"), "r".into(), 5);
    ctx("alice.near", NEAR / 10);
    c.anchor(acc("alice.near"), "r".into(), 5);
}

#[test]
#[should_panic(expected = "only the namespace owner or a registered gateway can anchor")]
fn anchor_by_stranger() {
    let mut c = setup();
    ctx("eve.near", NEAR / 10);
    c.anchor(acc("alice.near"), "r".into(), 1);
}

#[test]
#[should_panic(expected = "only the namespace owner or a registered gateway can anchor")]
fn anchor_by_deregistered_gateway() {
    let mut c = setup();
    register(&mut c, "gw.near");
    ctx("gw.near", 1);
    c.deregister_gateway();
    ctx("gw.near", NEAR / 10);
    c.anchor(acc("alice.near"), "r".into(), 1);
}

// --------------------------------------------------------------- gateways

#[test]
fn gateway_lifecycle() {
    let mut c = setup();
    register(&mut c, "gw1.near");
    register(&mut c, "gw2.near");
    register(&mut c, "gw3.near");
    let all = c.list_gateways(None, None);
    assert_eq!(all.len(), 3);
    assert!(all.iter().all(|g| g.active && g.stake.0 > 5 * NEAR && g.stake.0 < 6 * NEAR));
    assert_eq!(c.list_gateways(Some(1), Some(1))[0].operator.as_str(), "gw2.near");
    assert_eq!(c.gateways_count(), 3);

    ctx("gw1.near", NEAR);
    let mut info = gw_info("https://new.example");
    info.attestation = Some("quote".into());
    c.update_gateway(info.clone());
    assert_eq!(c.get_gateway(acc("gw1.near")).unwrap().url, "https://new.example");

    let stake = c.get_gateway(acc("gw1.near")).unwrap().stake.0;
    ctx("gw1.near", 1);
    c.deregister_gateway();
    let v = c.get_gateway(acc("gw1.near")).unwrap();
    assert!(!v.active);
    assert_eq!(v.stake_unlock_at_ns.unwrap().0, 1_000 * DAY + 7 * DAY);

    ctx_at("gw1.near", 1, 1_000 * DAY + 7 * DAY);
    let _ = c.withdraw_gateway_stake();
    assert!(c.get_gateway(acc("gw1.near")).is_none());
    let t = transfers();
    assert_eq!(t.len(), 1);
    assert!(t[0].1 > stake, "stake plus freed storage returned");
}

#[test]
#[should_panic(expected = "stake unlocks at")]
fn gateway_stake_locked() {
    let mut c = setup();
    register(&mut c, "gw.near");
    ctx("gw.near", 1);
    c.deregister_gateway();
    ctx_at("gw.near", 1, 1_000 * DAY + 7 * DAY - 1);
    let _ = c.withdraw_gateway_stake();
}

#[test]
#[should_panic(expected = "attach at least")]
fn gateway_min_stake() {
    let mut c = setup();
    ctx("gw.near", 5 * NEAR); // stake would be 5 NEAR minus storage
    c.register_gateway(gw_info("https://gw"));
}

#[test]
#[should_panic(expected = "already registered")]
fn gateway_double_register() {
    let mut c = setup();
    register(&mut c, "gw.near");
    register(&mut c, "gw.near");
}

#[test]
#[should_panic(expected = "url must be http(s)://")]
fn gateway_validated() {
    let mut c = setup();
    ctx("gw.near", 6 * NEAR);
    c.register_gateway(gw_info("ftp://gw"));
}

// ----------------------------------------------------------------- escrow

#[test]
fn ft_deposits() {
    let mut c = setup();
    deposit_ft(&mut c, USDC, "alice.near", 1_000_000, "");
    deposit_ft(&mut c, USDC, "alice.near", 500_000, r#"{"payer":"bob.near"}"#);
    let a = c.get_payer(acc("alice.near")).unwrap();
    assert_eq!(a.available.0, 1_000_000);
    assert_eq!(a.balances[0].asset, format!("nep141:{USDC}"));
    assert_eq!(c.get_payer(acc("bob.near")).unwrap().available.0, 500_000);
    assert!(get_logs()[0].starts_with("EVENT_JSON:{"));
    // 18-decimals asset is valued per micro-USD.
    deposit_ft(&mut c, DAI, "alice.near", 2 * 10u128.pow(18), "");
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 3_000_000);
}

#[test]
fn deposit_sets_own_cap_only() {
    let mut c = setup();
    deposit_ft(&mut c, USDC, "alice.near", 1_000_000, r#"{"spend_cap_per_day":"250000"}"#);
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().spend_cap_per_day, Some(U128(250_000)));
    deposit_ft(&mut c, USDC, "alice.near", 1_000_000, r#"{"payer":"bob.near","spend_cap_per_day":"9"}"#);
    assert_eq!(c.get_payer(acc("bob.near")).unwrap().spend_cap_per_day, None);
}

#[test]
#[should_panic(expected = "is not accepted")]
fn ft_unknown_token() {
    let mut c = setup();
    deposit_ft(&mut c, "scam.near", "alice.near", 1_000_000, "");
}

#[test]
#[should_panic(expected = "invalid msg")]
fn ft_bad_msg() {
    let mut c = setup();
    deposit_ft(&mut c, USDC, "alice.near", 1_000_000, "{nope");
}

#[test]
#[should_panic(expected = "first deposit must be at least 100000")]
fn ft_min_first_deposit() {
    let mut c = setup();
    deposit_ft(&mut c, USDC, "alice.near", 99_999, "");
}

#[test]
#[should_panic(expected = "must set msg.payer")]
fn ft_from_intents_requires_payer() {
    // intents.near `ft_withdraw(token, storage.near, amount, msg)` arrives as
    // ft_on_transfer with sender_id = intents.near.
    let mut c = setup();
    deposit_ft(&mut c, USDC, INTENTS, 1_000_000, "");
}

#[test]
fn ft_from_intents_with_payer() {
    let mut c = setup();
    deposit_ft(&mut c, USDC, INTENTS, 1_000_000, r#"{"payer":"alice.near"}"#);
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 1_000_000);
}

#[test]
#[should_panic(expected = "is not accepting deposits")]
fn asset_paused() {
    let mut c = setup();
    ctx("owner.near", 0);
    c.set_asset(AssetConfig { id: format!("nep141:{USDC}"), decimals: 6, accept_deposits: false });
    deposit_ft(&mut c, USDC, "alice.near", 1_000_000, "");
}

#[test]
fn mt_deposits() {
    let mut c = setup();
    ctx(INTENTS, 0);
    let r = c.mt_on_transfer(
        acc("alice.near"),
        vec![acc("alice.near")],
        vec![format!("nep141:{USDC}")],
        vec![U128(2_000_000)],
        String::new(),
    );
    match r {
        PromiseOrValue::Value(v) => assert_eq!(v, vec![U128(0)]),
        _ => panic!(),
    }
    let p = c.get_payer(acc("alice.near")).unwrap();
    assert_eq!(p.balances[0].asset, format!("nep245:{INTENTS}:nep141:{USDC}"));
    assert_eq!(p.available.0, 2_000_000);
}

#[test]
#[should_panic(expected = "is not accepted")]
fn mt_wrong_contract() {
    let mut c = setup();
    ctx("fake-intents.near", 0);
    let _ = c.mt_on_transfer(acc("alice.near"), vec![acc("alice.near")], vec![format!("nep141:{USDC}")], vec![U128(1_000_000)], String::new());
}

#[test]
#[should_panic(expected = "is not accepted")]
fn mt_wrong_token() {
    let mut c = setup();
    ctx(INTENTS, 0);
    let _ = c.mt_on_transfer(acc("alice.near"), vec![acc("alice.near")], vec!["nep141:scam.near".into()], vec![U128(1_000_000)], String::new());
}

#[test]
#[should_panic(expected = "invalid args")]
fn mt_bad_lengths() {
    let mut c = setup();
    ctx(INTENTS, 0);
    let _ = c.mt_on_transfer(acc("alice.near"), vec![], vec![format!("nep141:{USDC}")], vec![U128(1_000_000)], String::new());
}

fn funded() -> Contract {
    let mut c = setup();
    register(&mut c, "gw.near");
    register(&mut c, "gw2.near");
    ctx("owner.near", 0);
    c.add_settler(acc("billing.near"), true);
    c.add_settler(acc("gw.near"), false);
    deposit_ft(&mut c, USDC, "alice.near", 1_000_000, r#"{"spend_cap_per_day":"600000"}"#);
    c
}

fn entry(payer: &str, amount: u128, gw: &str, period: &str) -> SettleEntry {
    SettleEntry { payer: acc(payer), amount: U128(amount), gateway: acc(gw), period_id: period.into() }
}

fn settle_as(c: &mut Contract, settler: &str, ts: u64, entries: Vec<SettleEntry>) -> Vec<SettleStatus> {
    ctx_at(settler, NEAR, ts);
    c.settle(entries).into_iter().map(|r| r.status).collect()
}

#[test]
fn settle_rules() {
    let mut c = funded();
    deposit_ft(&mut c, USDC, "nocap.near", 1_000_000, "");
    let t = 1_000 * DAY;
    let s = settle_as(
        &mut c,
        "billing.near",
        t,
        vec![
            entry("alice.near", 400_000, "gw.near", "p1"),
            entry("alice.near", 400_000, "gw.near", "p1"),   // duplicate period
            entry("alice.near", 300_000, "gw.near", "p2"),   // 700k > 600k cap
            entry("nocap.near", 1, "gw.near", "p1"),          // no cap set
            entry("alice.near", 1, "nobody.near", "p3"),      // not a gateway
            entry("alice.near", 0, "gw.near", "p4"),          // zero
            entry("ghost.near", 1, "gw.near", "p5"),          // no balance
        ],
    );
    use SettleStatus::*;
    assert_eq!(s, vec![Settled, AlreadySettled, CapExceeded, NoSpendCap, UnknownGateway, InvalidEntry, InsufficientBalance]);
    assert!(c.is_settled(acc("billing.near"), acc("alice.near"), "p1".into()));
    assert!(!c.is_settled(acc("gw.near"), acc("alice.near"), "p1".into()));
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 600_000);
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().spent_today.0, 400_000);
    assert_eq!(c.get_earnings(acc("gw.near"))[0].amount.0, 400_000);

    // Next day the cap resets; with a higher cap, balance is the limit.
    ctx_at("alice.near", NEAR, t + DAY);
    c.set_spend_cap(Some(U128(5_000_000)));
    let s = settle_as(&mut c, "billing.near", t + DAY, vec![entry("alice.near", 600_001, "gw2.near", "p2")]);
    assert_eq!(s, vec![InsufficientBalance]);
    let s = settle_as(&mut c, "billing.near", t + DAY, vec![entry("alice.near", 600_000, "gw2.near", "p2")]);
    assert_eq!(s, vec![Settled]);
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 0);
}

#[test]
fn settle_self_only_settler() {
    let mut c = funded();
    let s = settle_as(
        &mut c,
        "gw.near",
        1_000 * DAY,
        vec![entry("alice.near", 1, "gw2.near", "a"), entry("alice.near", 1, "gw.near", "a")],
    );
    assert_eq!(s, vec![SettleStatus::GatewayNotAllowed, SettleStatus::Settled]);
}

#[test]
#[should_panic(expected = "not an approved settler")]
fn settle_unapproved() {
    let mut c = funded();
    settle_as(&mut c, "eve.near", 1_000 * DAY, vec![entry("alice.near", 1, "gw.near", "a")]);
}

#[test]
fn settle_draws_assets_in_order() {
    let mut c = funded();
    // alice: 1.0 USDC direct, + 0.5 intents-USDC, + 2 DAI (18 dec)
    ctx(INTENTS, 0);
    let _ = c.mt_on_transfer(acc("alice.near"), vec![acc("alice.near")], vec![format!("nep141:{USDC}")], vec![U128(500_000)], String::new());
    deposit_ft(&mut c, DAI, "alice.near", 2 * 10u128.pow(18) + 7, "");
    ctx("alice.near", NEAR);
    c.set_spend_cap(Some(U128(10_000_000)));
    let s = settle_as(&mut c, "billing.near", 1_000 * DAY, vec![entry("alice.near", 2_000_000, "gw.near", "x")]);
    assert_eq!(s, vec![SettleStatus::Settled]);
    let p = c.get_payer(acc("alice.near")).unwrap();
    // USDC and intents-USDC drained first, then 0.5 DAI: 1.5 DAI (+ 7 wei dust) left.
    assert_eq!(p.balances.len(), 1);
    assert_eq!(p.balances[0].amount.0, 15 * 10u128.pow(17) + 7);
    assert_eq!(p.available.0, 1_500_000);
    let e = c.get_earnings(acc("gw.near"));
    assert_eq!(e.len(), 3);
    assert_eq!(e[2].amount.0, 5 * 10u128.pow(17));
}

#[test]
fn withdraw_balance_with_notice() {
    let mut c = funded();
    let usdc = format!("nep141:{USDC}");
    ctx("alice.near", NEAR / 10);
    let req = c.request_withdraw_balance(usdc.clone(), U128(900_000));
    assert_eq!(req.ready_at_ns.0, 1_000 * DAY + 3 * DAY);
    // Usage served before the request can still be settled during notice.
    let s = settle_as(&mut c, "billing.near", 1_000 * DAY + DAY, vec![entry("alice.near", 300_000, "gw.near", "d1")]);
    assert_eq!(s, vec![SettleStatus::Settled]);
    ctx_at("alice.near", 1, 1_000 * DAY + 3 * DAY);
    let _ = c.withdraw_balance();
    let cs = calls();
    assert_eq!(cs[0].0, USDC);
    assert_eq!(cs[0].1, "ft_transfer");
    assert!(cs[0].2.contains(r#""amount":"700000""#), "{}", cs[0].2);
    assert!(cs[0].2.contains(r#""receiver_id":"alice.near""#));
    assert_eq!(cs[1].1, "on_payout");
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 0);
}

#[test]
#[should_panic(expected = "withdrawal ready at")]
fn withdraw_balance_too_early() {
    let mut c = funded();
    ctx("alice.near", NEAR / 10);
    c.request_withdraw_balance(format!("nep141:{USDC}"), U128(1));
    ctx_at("alice.near", 1, 1_000 * DAY + 3 * DAY - 1);
    let _ = c.withdraw_balance();
}

#[test]
fn intents_payout_uses_mt_transfer_and_restores_on_failure() {
    let mut c = funded();
    let asset = format!("nep245:{INTENTS}:nep141:{USDC}");
    ctx(INTENTS, 0);
    let _ = c.mt_on_transfer(acc("alice.near"), vec![acc("alice.near")], vec![format!("nep141:{USDC}")], vec![U128(500_000)], String::new());
    ctx("alice.near", NEAR / 10);
    c.request_withdraw_balance(asset.clone(), U128(500_000));
    ctx_at("alice.near", 1, 1_000 * DAY + 3 * DAY);
    let _ = c.withdraw_balance();
    let cs = calls();
    assert_eq!((cs[0].0.as_str(), cs[0].1.as_str()), (INTENTS, "mt_transfer"));
    assert!(cs[0].2.contains(&format!(r#""token_id":"nep141:{USDC}""#)));
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 1_000_000);

    // Transfer failed: callback restores the balance.
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(acc("storage.near"))
            .predecessor_account_id(acc("storage.near"))
            .build(),
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Failed],
    );
    assert!(!c.on_payout(acc("alice.near"), asset, U128(500_000), PayoutKind::Balance));
    assert_eq!(c.get_payer(acc("alice.near")).unwrap().available.0, 1_500_000);
}

#[test]
fn withdraw_earnings_pays_each_asset() {
    let mut c = funded();
    ctx(INTENTS, 0);
    let _ = c.mt_on_transfer(acc("alice.near"), vec![acc("alice.near")], vec![format!("nep141:{USDC}")], vec![U128(500_000)], String::new());
    ctx("alice.near", NEAR);
    c.set_spend_cap(None);
    c.set_spend_cap(Some(U128(5_000_000)));
    settle_as(&mut c, "billing.near", 1_000 * DAY, vec![entry("alice.near", 1_200_000, "gw.near", "e")]);
    ctx("gw.near", 1);
    c.withdraw_earnings();
    let cs: Vec<_> = calls().into_iter().map(|(to, m, _)| (to, m)).collect();
    assert!(cs.contains(&(USDC.to_string(), "ft_transfer".to_string())));
    assert!(cs.contains(&(INTENTS.to_string(), "mt_transfer".to_string())));
    assert!(c.get_earnings(acc("gw.near")).is_empty());

    testing_env!(
        VMContextBuilder::new().current_account_id(acc("storage.near")).predecessor_account_id(acc("storage.near")).build(),
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Failed],
    );
    c.on_payout(acc("gw.near"), format!("nep141:{USDC}"), U128(1_000_000), PayoutKind::Earnings);
    assert_eq!(c.get_earnings(acc("gw.near"))[0].amount.0, 1_000_000);
}

#[test]
#[should_panic(expected = "no earnings")]
fn withdraw_no_earnings() {
    let mut c = funded();
    ctx("gw.near", 1);
    c.withdraw_earnings();
}

// ------------------------------------------------------------------ owner

#[test]
#[should_panic(expected = "owner only")]
fn owner_only() {
    let mut c = setup();
    ctx("eve.near", 0);
    c.add_settler(acc("eve.near"), true);
}

#[test]
#[should_panic(expected = "decimals cannot change")]
fn asset_decimals_immutable() {
    let mut c = setup();
    ctx("owner.near", 0);
    c.set_asset(AssetConfig { id: format!("nep141:{USDC}"), decimals: 18, accept_deposits: true });
}

#[test]
fn owner_config() {
    let mut c = setup();
    ctx("owner.near", 0);
    c.set_config(ConfigPatch { withdraw_delay_sec: Some(60), ..Default::default() });
    assert_eq!(c.get_config().withdraw_delay_sec, 60);
    c.add_settler(acc("billing.near"), true);
    assert_eq!(c.get_settlers(), vec![(acc("billing.near"), true)]);
    c.remove_settler(acc("billing.near"));
    assert!(c.get_settlers().is_empty());
    c.set_owner(acc("new.near"));
    assert_eq!(c.get_owner(), acc("new.near"));
}

#[test]
fn default_assets_are_mainnet_usdc() {
    ctx("owner.near", 0);
    let c = Contract::new(acc("owner.near"), None, None);
    let ids: Vec<_> = c.get_assets().into_iter().map(|a| a.id).collect();
    assert_eq!(ids, vec![format!("nep141:{MAINNET_USDC}"), format!("nep245:intents.near:nep141:{MAINNET_USDC}")]);
}
