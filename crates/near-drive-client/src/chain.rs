//! `drive.near` integration: gateway discovery, encryption-key lookup for
//! sharing by account name, and policy grants.
use crate::Client;
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;
use near_drive_core::{crypto::RootKey, policy::Rule, record::PointerRecord, NearUri};
use near_drive_chain::{GatewayView, NoContract, Signer, StorageContract};
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Pick the active registered gateway with the lowest `GET /healthz` latency.
pub async fn discover_gateway(rpc_url: &str, contract: &str) -> Result<String> {
    let gws = StorageContract::new(rpc_url, contract).all_gateways().await?;
    pick_gateway(&gws).await
}

pub(crate) async fn pick_gateway(gws: &[GatewayView]) -> Result<String> {
    let http = reqwest::Client::builder().timeout(PROBE_TIMEOUT).build()?;
    let probes = gws.iter().filter(|g| g.active).map(|g| {
        let http = http.clone();
        let url = g.url.trim_end_matches('/').to_string();
        async move {
            let t = Instant::now();
            let ok = http.get(format!("{url}/healthz")).send().await.is_ok_and(|r| r.status().is_success());
            ok.then(|| (t.elapsed(), url))
        }
    });
    futures_util::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .min()
        .map(|(_, url)| url)
        .ok_or_else(|| anyhow!("no healthy gateway among {} registered", gws.len()))
}

/// How a root key relates to the keys an account published in `drive.near`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishedKeys {
    /// The published X25519 key and the latest record-signing key both come
    /// from this root key.
    Match,
    /// Some keys are not published yet (the ones that are match). Readers
    /// reject records until the signing key is published (`publish-key`).
    Missing { enc: bool, sign: bool },
    /// A published key comes from a different root key.
    Mismatch {
        published_enc: Option<String>,
        published_sign: Option<String>,
        enc: String,
        sign: String,
    },
    /// No contract at that RPC (dev setups): nothing to compare with.
    NoContract,
}

/// Compares `root` with what `account` published: `get_enc_key` and the
/// latest `get_sign_keys` entry (one view-call pair).
pub async fn check_published_keys(contract: &StorageContract, account: &str, root: &RootKey) -> Result<PublishedKeys> {
    let (enc_r, sign_r) = futures_util::future::join(contract.get_enc_key(account), contract.get_sign_keys(account)).await;
    let no_contract = |e: Option<&anyhow::Error>| e.is_some_and(|e| e.downcast_ref::<NoContract>().is_some());
    if no_contract(enc_r.as_ref().err()) || no_contract(sign_r.as_ref().err()) {
        return Ok(PublishedKeys::NoContract);
    }
    let published_enc = enc_r?;
    let published_sign = sign_r?.pop().map(|e| e.key);
    let (enc, sign) = (root.x25519_public(), root.sign_public_key());
    let enc_bad = published_enc.as_ref().is_some_and(|p| *p != enc);
    let sign_bad = published_sign.as_ref().is_some_and(|p| *p != sign);
    Ok(if enc_bad || sign_bad {
        PublishedKeys::Mismatch { published_enc, published_sign, enc, sign }
    } else if published_enc.is_none() || published_sign.is_none() {
        PublishedKeys::Missing { enc: published_enc.is_none(), sign: published_sign.is_none() }
    } else {
        PublishedKeys::Match
    })
}

impl Client {
    /// [`check_published_keys`] for this client's account and root key.
    pub async fn check_published_keys(&self) -> Result<PublishedKeys> {
        let root = self.root.as_ref().ok_or_else(|| anyhow!("no root key loaded"))?;
        check_published_keys(self.chain()?, self.account(), root).await
    }

    /// Use `contract` on `rpc_url` for account-key lookups and grants, and
    /// (unless [`Client::with_writer_check`] chose otherwise) to check the
    /// writer of every record read ([`crate::WriterCheck::Chain`]).
    pub fn with_chain(mut self, rpc_url: &str, contract: &str) -> Self {
        let c = StorageContract::new(rpc_url, contract);
        if self.writers.check.is_none() {
            self.writers.set(crate::WriterCheck::Chain(c.clone()));
        }
        self.chain = Some(c);
        self
    }

    /// A client on the fastest healthy gateway from the registry.
    pub async fn discover(rpc_url: &str, contract: &str, account: &str, sk: SigningKey, root: Option<RootKey>) -> Result<Self> {
        let gw = discover_gateway(rpc_url, contract).await?;
        Ok(Self::new(gw, account, sk, root).with_chain(rpc_url, contract))
    }

    pub fn chain(&self) -> Result<&StorageContract> {
        self.chain.as_ref().ok_or_else(|| anyhow!("no storage contract configured (Client::with_chain)"))
    }

    fn signer(&self) -> Signer {
        Signer::new(self.account(), self.sk.clone())
    }

    /// The `x25519:` key `account` published in `drive.near`.
    pub async fn resolve_enc_key(&self, account: &str) -> Result<String> {
        match self.chain()?.get_enc_key(account).await? {
            Some(k) => Ok(k),
            None => bail!("{account} has not published an encryption key (near drive publish-key)"),
        }
    }

    /// `share` to an account name, resolving its published key onchain.
    /// The account also needs read access through namespace policy.
    pub async fn share_with_account(&self, uri: &NearUri, account: &str) -> Result<PointerRecord> {
        let key = self.resolve_enc_key(account).await?;
        self.share(uri, &key).await
    }

    /// Publish this account's X25519 public key (needs the root key and a
    /// full-access key, since storage staking attaches a deposit).
    pub async fn publish_enc_key(&self) -> Result<String> {
        let key = self.x25519_public().ok_or_else(|| anyhow!("publishing a key requires the root key"))?;
        self.chain()?.set_enc_key(&self.signer(), &key).await?;
        Ok(key)
    }

    /// Publish this account's record-signing key (readers check records
    /// against it). Needs the root key and a full-access key.
    pub async fn publish_sign_key(&self) -> Result<String> {
        let key = self.sign_public_key().ok_or_else(|| anyhow!("publishing a key requires the root key"))?;
        self.chain()?.set_sign_key(&self.signer(), &key).await?;
        Ok(key)
    }

    /// Add or replace (by prefix) a rule in this account's namespace policy.
    pub async fn grant(&self, rule: Rule) -> Result<Vec<Rule>> {
        self.chain()?.grant(&self.signer(), rule).await
    }

    pub async fn rules(&self, namespace: &str) -> Result<Vec<Rule>> {
        self.chain()?.get_rules(namespace).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw(url: &str, active: bool) -> GatewayView {
        GatewayView {
            operator: "gw.near".into(),
            url: url.into(),
            regions: vec![],
            backends: vec![],
            price_hint: String::new(),
            attestation: None,
            stake: 0,
            active,
        }
    }

    /// Mock NEAR RPC answering `get_enc_key` / `get_sign_keys` views.
    async fn mock_rpc(enc: Option<String>, sign: Vec<&str>, contract_exists: bool) -> String {
        use axum::{routing::post, Json, Router};
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use serde_json::{json, Value};
        let sign: Vec<Value> = sign.iter().enumerate().map(|(i, k)| json!({"key": k, "since_ms": i.to_string()})).collect();
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<Value>| {
                let (enc, sign) = (enc.clone(), sign.clone());
                async move {
                    let p = &req["params"];
                    assert_eq!(p["request_type"], "call_function");
                    let args: Value = serde_json::from_slice(&B64.decode(p["args_base64"].as_str().unwrap()).unwrap()).unwrap();
                    assert_eq!(args["account_id"], "alice.near");
                    if !contract_exists {
                        return Json(json!({"jsonrpc":"2.0","id":req["id"],"error":{"name":"HANDLER_ERROR","cause":{"name":"NO_CONTRACT_CODE"}}}));
                    }
                    let v = match p["method_name"].as_str().unwrap() {
                        "get_enc_key" => json!(enc),
                        "get_sign_keys" => json!(sign),
                        m => panic!("unexpected view {m}"),
                    };
                    Json(json!({"jsonrpc":"2.0","id":req["id"],"result":{"result": serde_json::to_vec(&v).unwrap(), "logs": []}}))
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    #[tokio::test]
    async fn published_key_consistency() {
        let root = RootKey::from_bytes([1; 32]);
        let other = RootKey::from_bytes([2; 32]);
        let check = |url: String| {
            let root = RootKey::from_bytes(*root.as_bytes());
            async move { check_published_keys(&StorageContract::new(url, "drive.near"), "alice.near", &root).await.unwrap() }
        };
        let (enc, sign) = (root.x25519_public(), root.sign_public_key());
        // Match: the latest signing key counts, older ones are history.
        let url = mock_rpc(Some(enc.clone()), vec![&other.sign_public_key(), &sign], true).await;
        assert_eq!(check(url).await, PublishedKeys::Match);
        // Nothing published / only the encryption key.
        assert_eq!(check(mock_rpc(None, vec![], true).await).await, PublishedKeys::Missing { enc: true, sign: true });
        assert_eq!(check(mock_rpc(Some(enc.clone()), vec![], true).await).await, PublishedKeys::Missing { enc: false, sign: true });
        // Mismatch: keys of another root key, or rotated away from this one.
        let url = mock_rpc(Some(other.x25519_public()), vec![&other.sign_public_key()], true).await;
        assert!(matches!(check(url).await, PublishedKeys::Mismatch { .. }));
        let url = mock_rpc(Some(enc.clone()), vec![&sign, &other.sign_public_key()], true).await;
        match check(url).await {
            PublishedKeys::Mismatch { published_sign, sign: ours, .. } => {
                assert_eq!(published_sign, Some(other.sign_public_key()));
                assert_eq!(ours, sign);
            }
            r => panic!("{r:?}"),
        }
        let url = mock_rpc(None, vec![&other.sign_public_key()], true).await;
        assert!(matches!(check(url).await, PublishedKeys::Mismatch { published_enc: None, .. }));
        // No contract (dev setups).
        assert_eq!(check(mock_rpc(None, vec![], false).await).await, PublishedKeys::NoContract);
    }

    #[tokio::test]
    async fn picks_healthy_gateway() {
        let app = axum_lite().await;
        let dead = "http://127.0.0.1:1".to_string();
        let got = pick_gateway(&[gw(&dead, true), gw(&app, true), gw(&app, false)]).await.unwrap();
        assert_eq!(got, app);
        assert!(pick_gateway(&[gw(&dead, true), gw(&app, false)]).await.is_err());
    }

    /// Minimal HTTP server answering `GET /healthz` with 200.
    async fn axum_lite() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
                });
            }
        });
        url
    }
}
