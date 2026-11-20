//! End-to-end tests on a local NEAR sandbox node (near-workspaces).
//!
//! Needs the wasm files built first:
//!   cargo near build non-reproducible-wasm --manifest-path contracts/drive/Cargo.toml
//!   cargo near build non-reproducible-wasm --no-abi --manifest-path contracts/mock-ft/Cargo.toml
//!   cargo near build non-reproducible-wasm --no-abi --manifest-path contracts/mock-mt/Cargo.toml
//! (`contracts/build.sh` does all three.)
//!
//! Besides the contract flows, this drives `near-drive-chain` (our hand-rolled
//! borsh transaction builder + RPC client) against the real node.
use anyhow::Result;
use near_drive_chain::{GatewayInfo, SettleEntry, Signer, StorageContract};
use near_drive_core::policy::Rule;
use near_workspaces::{network::Sandbox, types::NearToken, Account, Contract, Worker};
use serde_json::{json, Value};

const TGAS: u64 = 1_000_000_000_000;

fn wasm(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/../target/near/{name}/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|_| panic!("{p} missing: run contracts/build.sh first"))
}

async fn sub(root: &Account, name: &str, near: u128) -> Result<Account> {
    Ok(root
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(near))
        .transact()
        .await?
        .into_result()?)
}

fn signer(a: &Account) -> Signer {
    let sk = near_drive_core::keys::parse_secret_key(&a.secret_key().to_string()).unwrap();
    Signer::new(a.id().as_str(), sk)
}

async fn call(
    a: &Account,
    c: &str,
    m: &str,
    args: Value,
    deposit: u128,
) -> Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(a.call(&c.parse()?, m)
        .args_json(args)
        .deposit(NearToken::from_yoctonear(deposit))
        .gas(near_workspaces::types::Gas::from_gas(300 * TGAS))
        .transact()
        .await?)
}

async fn view(w: &Worker<Sandbox>, c: &str, m: &str, args: Value) -> Result<Value> {
    Ok(w.view(&c.parse()?, m).args_json(args).await?.json()?)
}

async fn ft_balance(w: &Worker<Sandbox>, token: &Contract, a: &str) -> Result<u128> {
    Ok(view(
        w,
        token.id().as_str(),
        "ft_balance_of",
        json!({"account_id": a}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?)
}

async fn mt_balance(w: &Worker<Sandbox>, mt: &Contract, a: &str, token: &str) -> Result<u128> {
    Ok(view(
        w,
        mt.id().as_str(),
        "mt_balance_of",
        json!({"account_id": a, "token_id": token}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?)
}

async fn available(w: &Worker<Sandbox>, storage: &str, payer: &str) -> Result<u128> {
    let v = view(w, storage, "get_payer", json!({"account_id": payer})).await?;
    Ok(v.get("available")
        .and_then(Value::as_str)
        .map(|s| s.parse().unwrap())
        .unwrap_or(0))
}

#[tokio::test]
async fn sandbox_end_to_end() -> Result<()> {
    let w = near_workspaces::sandbox().await?;
    let root = w.root_account()?;
    let usdc = sub(&root, "usdc", 20)
        .await?
        .deploy(&wasm("mock_ft"))
        .await?
        .into_result()?;
    let intents = sub(&root, "intents", 20)
        .await?
        .deploy(&wasm("mock_mt"))
        .await?
        .into_result()?;
    let storage = sub(&root, "storage", 30)
        .await?
        .deploy(&wasm("near_drive_contract"))
        .await?
        .into_result()?;
    let (owner, alice, bob, carol, gw, billing) = (
        sub(&root, "owner", 10).await?,
        sub(&root, "alice", 10).await?,
        sub(&root, "bob", 10).await?,
        sub(&root, "carol", 10).await?,
        sub(&root, "gw", 20).await?,
        sub(&root, "billing", 10).await?,
    );
    let sid = storage.id().as_str();
    let usdc_id = usdc.id().to_string();
    let intents_id = intents.id().to_string();
    let ft_asset = format!("nep141:{usdc_id}");
    let mt_token = format!("nep141:{usdc_id}"); // token id inside intents
    let mt_asset = format!("nep245:{intents_id}:{mt_token}");

    usdc.call("new").transact().await?.into_result()?;
    intents.call("new").transact().await?.into_result()?;
    storage
        .call("new")
        .args_json(json!({
            "owner_id": owner.id(),
            "assets": [
                {"id": ft_asset, "decimals": 6, "accept_deposits": true},
                {"id": mt_asset, "decimals": 6, "accept_deposits": true},
            ],
            "config": {
                "gateway_min_stake": NearToken::from_near(1).as_yoctonear().to_string(),
                "gateway_unstake_delay_sec": 1,
                "withdraw_delay_sec": 1,
                "min_new_payer_deposit": "100000",
            },
        }))
        .transact()
        .await?
        .into_result()?;

    // ---------------------------------------------------- policy via near-drive-chain
    let sc = StorageContract::new(w.rpc_addr(), sid);
    let storage_deposit = NearToken::from_millinear(10).as_yoctonear();
    for a in [&alice, &bob, &carol] {
        call(a, sid, "register_payer", json!({}), storage_deposit)
            .await?
            .into_result()?;
    }
    let rules: Vec<Rule> = serde_json::from_str(
        r#"[{"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},
            {"prefix":"public/","read":["*"],"write":[]}]"#,
    )?;
    let out = sc.set_rules(&signer(&alice), &rules).await?;
    assert!(
        out.logs.iter().any(|l| l.contains("set_rules")),
        "{:?}",
        out.logs
    );
    assert_eq!(sc.get_rules(alice.id().as_str()).await?, rules);
    assert!(sc.get_rules(bob.id().as_str()).await?.is_empty());
    // grant = read-modify-write by prefix
    let r = Rule {
        prefix: "public/".into(),
        read: vec!["*".into()],
        write: vec![bob.id().to_string()],
        payer: None,
    };
    let updated = sc.grant(&signer(&alice), r.clone()).await?;
    assert_eq!(updated.len(), 2);
    assert_eq!(sc.get_rules(alice.id().as_str()).await?[1], r);
    // invalid rules are rejected by the contract
    let bad = vec![Rule {
        prefix: "x/{account}/{account}/".into(),
        read: vec![],
        write: vec![],
        payer: None,
    }];
    let e = sc
        .set_rules(&signer(&alice), &bad)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("at most one {account}"), "{e}");
    // storage is refunded: alice paid only for what she stores
    let bal = alice.view_account().await?.balance;
    assert!(
        bal > NearToken::from_millinear(9_900),
        "alice balance {bal}"
    );

    let key = near_drive_core::crypto::RootKey::generate().x25519_public();
    sc.set_enc_key(&signer(&carol), &key).await?;
    assert_eq!(sc.get_enc_key(carol.id().as_str()).await?, Some(key));
    assert_eq!(sc.get_enc_key(bob.id().as_str()).await?, None);

    assert_eq!(sc.bump_cred_epoch(&signer(&bob)).await?, 1);
    assert_eq!(sc.bump_cred_epoch(&signer(&bob)).await?, 2);
    assert_eq!(sc.get_cred_epoch(bob.id().as_str()).await?, 2);

    // --------------------------------------------------------------- gateways
    let info = GatewayInfo {
        url: "https://gw.example".into(),
        regions: vec!["eu".into()],
        backends: vec!["fs".into()],
        ..Default::default()
    };
    sc.register_gateway(&signer(&gw), &info, NearToken::from_near(2).as_yoctonear())
        .await?;
    let gws = sc.all_gateways().await?;
    assert_eq!(gws.len(), 1);
    assert_eq!(
        (gws[0].operator.as_str(), gws[0].url.as_str(), gws[0].active),
        (gw.id().as_str(), "https://gw.example", true)
    );
    assert!(gws[0].stake >= NearToken::from_near(2).as_yoctonear());

    // anchors: owner and an authorized gateway, monotonic
    call(
        &alice,
        sid,
        "set_anchor_authority",
        json!({"gateway": gw.id()}),
        storage_deposit,
    )
    .await?
    .into_result()?;
    sc.anchor(&signer(&alice), alice.id().as_str(), "root-1", 1)
        .await?;
    sc.anchor(&signer(&gw), alice.id().as_str(), "root-2", 2)
        .await?;
    assert_eq!(
        sc.get_anchor(alice.id().as_str()).await?.unwrap().root,
        "root-2"
    );
    assert!(sc
        .anchor(&signer(&gw), alice.id().as_str(), "root-x", 2)
        .await
        .is_err());
    assert!(sc
        .anchor(&signer(&bob), alice.id().as_str(), "root-x", 3)
        .await
        .is_err());

    // ------------------------------------------------- NEP-141 ft_transfer_call
    for a in [&alice, &carol] {
        call(
            &owner,
            &usdc_id,
            "mint",
            json!({"account_id": a.id(), "amount": "5000000"}),
            0,
        )
        .await?
        .into_result()?;
    }
    call(
        &owner,
        &usdc_id,
        "mint",
        json!({"account_id": intents.id(), "amount": "5000000"}),
        0,
    )
    .await?
    .into_result()?;
    call(
        &owner,
        &usdc_id,
        "storage_deposit",
        json!({"account_id": sid}),
        0,
    )
    .await?
    .into_result()?;

    let r = call(&alice, &usdc_id, "ft_transfer_call",
        json!({"receiver_id": sid, "amount": "2000000", "msg": r#"{"spend_cap_per_day":"1500000"}"#}), 1).await?;
    assert!(r.is_success(), "{r:?}");
    assert_eq!(available(&w, sid, alice.id().as_str()).await?, 2_000_000);
    assert_eq!(ft_balance(&w, &usdc, alice.id().as_str()).await?, 3_000_000);
    assert_eq!(ft_balance(&w, &usdc, sid).await?, 2_000_000);

    // malformed msg: ft_on_transfer panics, token contract refunds
    let _ = call(
        &alice,
        &usdc_id,
        "ft_transfer_call",
        json!({"receiver_id": sid, "amount": "1000000", "msg": "{oops"}),
        1,
    )
    .await?;
    assert_eq!(ft_balance(&w, &usdc, alice.id().as_str()).await?, 3_000_000);

    // relayed by the intents contract (`ft_withdraw` with msg): payer required
    let _ = call(
        intents.as_account(),
        &usdc_id,
        "ft_transfer_call",
        json!({"receiver_id": sid, "amount": "1000000", "msg": ""}),
        1,
    )
    .await?;
    assert_eq!(
        ft_balance(&w, &usdc, intents.id().as_str()).await?,
        5_000_000,
        "refunded"
    );
    let msg = json!({"payer": carol.id()}).to_string();
    call(
        intents.as_account(),
        &usdc_id,
        "ft_transfer_call",
        json!({"receiver_id": sid, "amount": "1000000", "msg": msg}),
        1,
    )
    .await?
    .into_result()?;
    assert_eq!(available(&w, sid, carol.id().as_str()).await?, 1_000_000);

    // ------------------------------------------------ NEP-245 mt_transfer_call
    call(
        &owner,
        &intents_id,
        "mint",
        json!({"account_id": bob.id(), "token_id": mt_token, "amount": "3000000"}),
        0,
    )
    .await?
    .into_result()?;
    call(
        &owner,
        &intents_id,
        "mint",
        json!({"account_id": bob.id(), "token_id": "nep141:scam.near", "amount": "3000000"}),
        0,
    )
    .await?
    .into_result()?;
    let r = call(&bob, &intents_id, "mt_transfer_call", json!({
        "receiver_id": sid, "token_id": mt_token, "amount": "2000000", "msg": r#"{"spend_cap_per_day":"1000000"}"#,
    }), 1).await?;
    assert!(r.is_success(), "{r:?}");
    assert_eq!(
        r.json::<Vec<String>>()?,
        vec!["2000000"],
        "mt_transfer_call returns used amounts"
    );
    assert_eq!(available(&w, sid, bob.id().as_str()).await?, 2_000_000);
    assert_eq!(mt_balance(&w, &intents, sid, &mt_token).await?, 2_000_000);
    // not allow-listed token: refunded
    let _ = call(
        &bob,
        &intents_id,
        "mt_transfer_call",
        json!({"receiver_id": sid, "token_id": "nep141:scam.near", "amount": "1000000", "msg": ""}),
        1,
    )
    .await?;
    assert_eq!(
        mt_balance(&w, &intents, bob.id().as_str(), "nep141:scam.near").await?,
        3_000_000
    );

    // ------------------------------------------------------------------ settle
    call(
        &owner,
        sid,
        "add_settler",
        json!({"account_id": billing.id(), "any_gateway": true}),
        0,
    )
    .await?
    .into_result()?;
    let entries = vec![
        SettleEntry {
            payer: alice.id().to_string(),
            amount: 1_200_000,
            gateway: gw.id().to_string(),
            period_id: "2026-11-19".into(),
        },
        SettleEntry {
            payer: bob.id().to_string(),
            amount: 900_000,
            gateway: gw.id().to_string(),
            period_id: "2026-11-19".into(),
        },
        SettleEntry {
            payer: carol.id().to_string(),
            amount: 1,
            gateway: gw.id().to_string(),
            period_id: "2026-11-19".into(),
        },
        SettleEntry {
            payer: alice.id().to_string(),
            amount: 400_000,
            gateway: gw.id().to_string(),
            period_id: "2026-11-19b".into(),
        },
    ];
    let res = sc.settle(&signer(&billing), &entries).await?;
    let st: Vec<&str> = res.iter().map(|r| r.status.as_str()).collect();
    assert_eq!(st, ["Settled", "Settled", "NoSpendCap", "CapExceeded"]);
    let again = sc.settle(&signer(&billing), &entries[..1]).await?;
    assert_eq!(again[0].status, "AlreadySettled");
    assert!(
        sc.settle(&signer(&alice), &entries[..1]).await.is_err(),
        "not a settler"
    );
    assert_eq!(available(&w, sid, alice.id().as_str()).await?, 800_000);
    let earnings = view(&w, sid, "get_earnings", json!({"account_id": gw.id()})).await?;
    assert_eq!(
        earnings,
        json!([{"asset": ft_asset, "amount": "1200000"}, {"asset": mt_asset, "amount": "900000"}])
    );

    // ------------------------------------------------------- withdraw_earnings
    // gw is not registered with the token: ft_transfer fails, earnings restored
    let _ = call(&gw, sid, "withdraw_earnings", json!({}), 1).await?;
    let earnings = view(&w, sid, "get_earnings", json!({"account_id": gw.id()})).await?;
    assert_eq!(
        earnings,
        json!([{"asset": ft_asset, "amount": "1200000"}]),
        "intents leg paid, ft leg restored"
    );
    assert_eq!(
        mt_balance(&w, &intents, gw.id().as_str(), &mt_token).await?,
        900_000
    );
    call(&gw, &usdc_id, "storage_deposit", json!({}), 0)
        .await?
        .into_result()?;
    call(&gw, sid, "withdraw_earnings", json!({}), 1)
        .await?
        .into_result()?;
    assert_eq!(ft_balance(&w, &usdc, gw.id().as_str()).await?, 1_200_000);
    assert_eq!(
        view(&w, sid, "get_earnings", json!({"account_id": gw.id()})).await?,
        json!([])
    );

    // ------------------------------------------------- withdraw_balance (notice)
    call(
        &alice,
        sid,
        "request_withdraw_balance",
        json!({"asset": ft_asset, "amount": "10000000"}),
        NearToken::from_millinear(10).as_yoctonear(),
    )
    .await?
    .into_result()?;
    let early = call(&alice, sid, "withdraw_balance", json!({}), 1).await?;
    // The 1 s delay may or may not have passed by now; force it to have.
    if early.is_failure() {
        w.fast_forward(5).await?;
        call(&alice, sid, "withdraw_balance", json!({}), 1)
            .await?
            .into_result()?;
    }
    assert_eq!(ft_balance(&w, &usdc, alice.id().as_str()).await?, 3_800_000);
    assert_eq!(available(&w, sid, alice.id().as_str()).await?, 0);

    // ---------------------------------------------------- gateway deregistration
    call(&gw, sid, "deregister_gateway", json!({}), 1)
        .await?
        .into_result()?;
    assert!(!sc.all_gateways().await?[0].active);
    w.fast_forward(5).await?;
    let before = gw.view_account().await?.balance;
    call(&gw, sid, "withdraw_gateway_stake", json!({}), 1)
        .await?
        .into_result()?;
    let after = gw.view_account().await?.balance;
    // Leave room for the call's gas; the important invariant is that the
    // ~2 NEAR stake is returned, not that the exact stake value is kept.
    assert!(
        after.as_yoctonear()
            > before.as_yoctonear() + NearToken::from_millinear(1_500).as_yoctonear()
    );
    assert!(sc.all_gateways().await?.is_empty());
    Ok(())
}
