//! Read-only checks against the live MPC contracts (view calls only, no
//! transactions). Run with `cargo test -p nstorage-ckd -- --ignored`.
use nstorage_ckd::{near::Rpc, CkdNetwork};

async fn check(network: &str) {
    let net = CkdNetwork::for_network(network).unwrap();
    let rpc = Rpc::new(&net.rpc_url);
    let state = rpc
        .view_call(&net.contract, "state", &serde_json::json!({}))
        .await
        .unwrap();
    let domains = state
        .pointer("/Running/domains/domains")
        .and_then(|d| d.as_array())
        .expect("Running state");
    let d = domains
        .iter()
        .find(|d| d["id"] == net.domain_id)
        .expect("default domain exists");
    assert_eq!(
        d["purpose"], "CKD",
        "{network}: domain {} must be a CKD domain",
        net.domain_id
    );
    // Must be a valid compressed G2 point in the prime-order subgroup.
    rpc.mpc_public_key(&net.contract, net.domain_id)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "network"]
async fn testnet_ckd_domain_and_public_key() {
    check("testnet").await
}

#[tokio::test]
#[ignore = "network"]
async fn mainnet_ckd_domain_and_public_key() {
    check("mainnet").await
}
