//! `GET /v1/o/{ns}/{path}?mode=locate`: record + manifest + per-chunk
//! direct-fetch URLs, so large reads can bypass the gateway.
//!
//! Response:
//! ```json
//! {"record": {...}, "manifest": {...},
//!  "chunks": [{"cid": "b3:..", "len": 4194320, "url": "https://..." | null, "expires_ms": 1763.. | null}]}
//! ```
//! Objects up to `small_cache.inline_max_bytes` come with each chunk's bytes
//! inlined as `"data": "<base64>"` (and no URL), so a small read is one request.
//! `url: null` (and no `data`) means "fetch through the gateway":
//! `GET /v1/o/{ns}/{path}?chunk={cid}` (signed; supports `Range`).
//! Clients must verify every fetched chunk against its cid.
use crate::{
    store::{DirectUrl, IndexEntry},
    AppState,
};
use futures_util::{StreamExt, TryStreamExt};
use near_drive_core::{manifest::Manifest, record::PointerRecord};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LocatedChunk {
    pub cid: String,
    pub len: u64,
    pub url: Option<String>,
    pub expires_ms: Option<u64>,
    /// Chunk bytes (base64) for small objects; saves the client a round trip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Located {
    pub record: PointerRecord,
    pub manifest: Manifest,
    /// Exact stored manifest bytes, base64.
    pub manifest_raw: String,
    pub chunks: Vec<LocatedChunk>,
    /// Storage class of the object (absent for objects stored before classes were recorded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

const LOCATE_CONCURRENCY: usize = 32;

pub async fn locate(st: &AppState, entry: IndexEntry, manifest: Manifest, manifest_raw: String) -> anyhow::Result<Located> {
    let class = entry.class.as_deref();
    let refs: Vec<(String, u64)> = manifest.chunks.iter().map(|c| (c.cid.clone(), c.len)).collect();
    // Small object: inline its chunks instead of handing out URLs.
    let inline = st.blobs.inline_max() > 0 && manifest.stored_size() <= st.blobs.inline_max();
    let chunks = futures_util::stream::iter(refs)
        .map(move |(cid, len): (String, u64)| async move {
            if inline {
                if let Some(b) = st.blobs.get(class, &cid).await? {
                    let data = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b));
                    return anyhow::Ok(LocatedChunk { cid, len, url: None, expires_ms: None, data });
                }
            }
            let d = match st.blobs.direct_url(class, &cid).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("direct url for {cid}: {e:#}");
                    None
                }
            };
            let (url, expires_ms) = match d {
                Some(DirectUrl { url, expires_ms }) => (Some(url), expires_ms),
                None => (None, None),
            };
            anyhow::Ok(LocatedChunk { cid, len, url, expires_ms, data: None })
        })
        .buffered(LOCATE_CONCURRENCY)
        .try_collect()
        .await?;
    Ok(Located { class: entry.class.clone(), record: entry.record, manifest, manifest_raw, chunks })
}
