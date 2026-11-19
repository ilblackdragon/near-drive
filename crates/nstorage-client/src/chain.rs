//! `storage.near` integration: gateway discovery, encryption-key lookup for
//! sharing by account name, and policy grants.
use crate::Client;
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;
use nstorage_core::{crypto::RootKey, policy::Rule, record::PointerRecord, NearUri};
use nstorage_near::{GatewayView, Signer, StorageContract};
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

impl Client {
    /// Use `contract` on `rpc_url` for account-key lookups and grants.
    pub fn with_chain(mut self, rpc_url: &str, contract: &str) -> Self {
        self.chain = Some(StorageContract::new(rpc_url, contract));
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

    /// The `x25519:` key `account` published in `storage.near`.
    pub async fn resolve_enc_key(&self, account: &str) -> Result<String> {
        match self.chain()?.get_enc_key(account).await? {
            Some(k) => Ok(k),
            None => bail!("{account} has not published an encryption key (nst publish-key)"),
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
