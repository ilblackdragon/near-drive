//! Full stack on a sandbox node: a real nstorage gateway resolving access
//! keys (`view_access_key`) and namespace rules (`get_rules`) from the chain,
//! clients sharing to accounts via keys published in storage.near, and
//! gateway discovery from the onchain registry. Build wasm first
//! (`contracts/build.sh`).
use anyhow::Result;
use near_workspaces::{types::NearToken, Account};
use nstorage_client::{
    nstorage_core::{crypto::RootKey, policy::Rule, NearUri},
    Client, PutOptions,
};
use nstorage_gateway::{router, AppState, Config};
use nstorage_near::{GatewayInfo, Signer, StorageContract};
use serde_json::json;

fn wasm(name: &str) -> Vec<u8> {
    let p = format!("{}/../target/near/{name}/{name}.wasm", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|_| panic!("{p} missing: run contracts/build.sh first"))
}

fn sk(a: &Account) -> ed25519_dalek::SigningKey {
    nstorage_client::nstorage_core::keys::parse_secret_key(&a.secret_key().to_string()).unwrap()
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test]
async fn gateway_reads_policy_and_keys_from_chain() -> Result<()> {
    let w = near_workspaces::sandbox().await?;
    let root = w.root_account()?;
    let mk = |name: &'static str| {
        let root = root.clone();
        async move { anyhow::Ok(root.create_subaccount(name).initial_balance(NearToken::from_near(20)).transact().await?.into_result()?) }
    };
    let storage = mk("storage").await?.deploy(&wasm("nstorage_contract")).await?.into_result()?;
    let (app, bob, carol, op) = (mk("app").await?, mk("bob").await?, mk("carol").await?, mk("op").await?);
    storage.call("new").args_json(json!({"owner_id": root.id()})).transact().await?.into_result()?;
    w.fast_forward(5).await?; // make the new access keys final for view_access_key
    let (rpc, sid) = (w.rpc_addr(), storage.id().to_string());

    // A real gateway with no dev keys and no config policies: chain only.
    let dir = tempfile::tempdir()?;
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: dir.path().to_path_buf(),
        rpc_url: Some(rpc.clone()),
        storage_contract: sid.clone(),
        ..Default::default()
    };
    let state = AppState::new(cfg).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gw_url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    let client = |a: &Account, root: Option<RootKey>| {
        Client::new(&gw_url, a.id().as_str(), sk(a), root).with_chain(&rpc, &sid)
    };
    let app_c = client(&app, None);
    let bob_c = client(&bob, Some(RootKey::generate()));
    let carol_c = client(&carol, Some(RootKey::generate()));
    let (a, b, c) = (app.id().as_str(), bob.id().as_str(), carol.id().as_str());

    // App-writes-for-user: app's policy lets each user read their prefix and
    // the app write it; bob publishes his key, app encrypts to it.
    app_c
        .grant(Rule { prefix: "users/{account}/".into(), read: vec!["{account}".into()], write: vec!["{account}".into(), a.into()], payer: Some(a.into()) })
        .await?;
    assert_eq!(app_c.rules(a).await?.len(), 1);
    let bob_key = bob_c.publish_enc_key().await?;
    assert_eq!(app_c.resolve_enc_key(b).await?, bob_key);
    assert!(app_c.resolve_enc_key(c).await.is_err(), "carol has not published yet");

    let inbox = u(&format!("near://{a}/users/{b}/inbox/1"));
    let opts = PutOptions { share_with: vec![app_c.resolve_enc_key(b).await?], ..Default::default() };
    app_c.put(&inbox, b"for bob only", &opts).await?;
    assert_eq!(bob_c.get(&inbox).await?.1, b"for bob only");
    let e = carol_c.get(&inbox).await.unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");
    let e = carol_c.put(&u(&format!("near://{a}/users/{b}/x")), b"x", &PutOptions { public: true, ..Default::default() }).await.unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");

    // Sharing by account name: bob grants carol read on doc/, carol
    // publishes her key, bob re-wraps the object key to it.
    bob_c.grant(Rule { prefix: "doc/".into(), read: vec![c.into()], write: vec![], payer: None }).await?;
    let doc = u(&format!("near://{b}/doc/notes.txt"));
    bob_c.put(&doc, b"shared notes", &PutOptions::default()).await?;
    assert!(carol_c.get(&doc).await.is_err(), "not shared yet: no wrapped key for carol");
    carol_c.publish_enc_key().await?;
    bob_c.share_with_account(&doc, c).await?;
    assert_eq!(carol_c.get(&doc).await?.1, b"shared notes");

    // Discovery: register this gateway plus a dead one; discover picks the live one.
    let sc = StorageContract::new(&rpc, &sid);
    let stake = 5 * nstorage_near::ONE_NEAR;
    sc.register_gateway(&Signer::new(op.id().as_str(), sk(&op)), &GatewayInfo { url: gw_url.clone(), ..Default::default() }, stake).await?;
    sc.register_gateway(&Signer::new(c, sk(&carol)), &GatewayInfo { url: "http://127.0.0.1:9".into(), ..Default::default() }, stake).await?;
    let found = Client::discover(&rpc, &sid, b, sk(&bob), None).await?;
    assert_eq!(nstorage_client::discover_gateway(&rpc, &sid).await?, gw_url);
    assert!(found.list(&u(&format!("near://{b}/doc/"))).await?.iter().any(|e| e.path == "doc/notes.txt"));
    Ok(())
}
