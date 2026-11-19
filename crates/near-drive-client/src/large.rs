//! Large objects: streaming upload/download with bounded memory, parallel
//! chunk transfers, direct (gateway-bypassing) chunk fetches via
//! `?mode=locate`, and byte-range reads.
//!
//! Memory use is about `(parallelism + 2) * chunk_size` regardless of object
//! size. The on-the-wire format is identical to [`Client::put`] / [`Client::get`].
use super::*;
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use near_drive_core::crypto::stream::{chunk_count, chunk_plain_len, ChunkOpener, ChunkSealer};
use std::{ops::Range, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const ATTEMPTS: u32 = 3;
/// Don't use a direct URL that expires sooner than this.
const URL_MIN_REMAINING_MS: u64 = 30_000;

/// One chunk as returned by `?mode=locate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocatedChunk {
    pub cid: String,
    pub len: u64,
    /// Direct-fetch URL (presigned S3, bridge/CDN). None = fetch via gateway.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

/// `GET ...?mode=locate` response. Gateways without locate support answer
/// with a plain head (no `chunks`), which degrades to gateway fetches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Located {
    pub record: PointerRecord,
    pub manifest: Manifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_raw: Option<String>,
    /// Storage class of the object, when the gateway recorded one.
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub chunks: Vec<LocatedChunk>,
}

impl Located {
    pub fn head(&self) -> ObjectHead {
        ObjectHead { record: self.record.clone(), manifest: self.manifest.clone(), manifest_raw: self.manifest_raw.clone(), class: self.class.clone() }
    }

    fn direct_url(&self, idx: usize) -> Option<&str> {
        let c = self.chunks.get(idx)?;
        if c.expires_ms.is_some_and(|e| e < now_ms() + URL_MIN_REMAINING_MS) {
            return None;
        }
        c.url.as_deref()
    }
}

#[derive(Clone)]
enum Sealer {
    Plain,
    Enc(Arc<ChunkSealer>),
}

#[derive(Clone)]
enum Opener {
    Plain,
    Enc(Arc<ChunkOpener>),
}

/// Read until `buf` holds `n` bytes or EOF.
async fn read_full<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        let k = r.read(&mut buf[filled..]).await?;
        if k == 0 {
            break;
        }
        filled += k;
    }
    buf.truncate(filled);
    Ok(buf)
}

fn retryable(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::REQUEST_TIMEOUT
}

async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_millis(250 * 4u64.pow(attempt))).await;
}

impl Client {
    /// Upload one already-encoded chunk (retries transient failures).
    pub(crate) async fn upload_chunk(&self, namespace: &str, cid: String, bytes: Bytes, class: Option<&str>) -> Result<ChunkRef> {
        let len = bytes.len() as u64;
        let path = format!("/v1/chunk/{namespace}/{cid}");
        let mut attempt = 0;
        loop {
            let r = self.send_with(Method::PUT, &path, "", bytes.clone(), class).await;
            match r {
                Ok(resp) if resp.status().is_success() => return Ok(ChunkRef { cid, len }),
                Ok(resp) if !retryable(resp.status()) || attempt + 1 >= ATTEMPTS => {
                    Self::check(resp).await?;
                    unreachable!("check fails on non-success");
                }
                Err(e) if attempt + 1 >= ATTEMPTS => return Err(e),
                _ => {}
            }
            backoff(attempt).await;
            attempt += 1;
        }
    }

    /// Fetch a chunk via the gateway (signed, retried), verifying its cid.
    /// `idx` goes into the (signed) query so that concurrent fetches of a
    /// repeated chunk never produce identical signatures (gateway replay cache).
    async fn fetch_via_gateway(&self, uri: &NearUri, cid: &str, idx: usize) -> Result<Bytes> {
        let q = format!("chunk={cid}&i={idx}");
        let mut attempt = 0;
        loop {
            let res = async {
                let resp = self.send(Method::GET, &Self::obj_path(uri), &q, Bytes::new()).await?;
                let status = resp.status();
                if !status.is_success() {
                    let retry = retryable(status);
                    let text = resp.text().await.unwrap_or_default();
                    return Ok::<_, anyhow::Error>(Err((retry, anyhow!("gateway returned {status}: {text}"))));
                }
                Ok(Ok(resp.bytes().await?))
            }
            .await;
            match res {
                Ok(Ok(b)) => {
                    ensure!(near_drive_core::cid(&b) == cid, "chunk {cid} content does not match its id");
                    return Ok(b);
                }
                Ok(Err((false, e))) => return Err(e),
                Ok(Err((true, e))) | Err(e) if attempt + 1 >= ATTEMPTS => return Err(e),
                _ => {}
            }
            backoff(attempt).await;
            attempt += 1;
        }
    }

    /// Fetch chunk `idx` of a located object: direct URL first, gateway fallback.
    async fn fetch_chunk(&self, uri: &NearUri, loc: &Located, idx: usize) -> Result<Bytes> {
        let cid = &loc.manifest.chunks[idx].cid;
        if let Some(url) = loc.direct_url(idx) {
            match self.http.get(url).send().await {
                Ok(resp) if resp.status() == StatusCode::OK => match resp.bytes().await {
                    Ok(b) if near_drive_core::cid(&b) == *cid => return Ok(b),
                    Ok(_) => eprintln_debug(&format!("direct fetch of {cid} returned wrong content; using gateway")),
                    Err(e) => eprintln_debug(&format!("direct fetch of {cid}: {e}; using gateway")),
                },
                Ok(resp) => eprintln_debug(&format!("direct fetch of {cid}: HTTP {}; using gateway", resp.status())),
                Err(e) => eprintln_debug(&format!("direct fetch of {cid}: {e}; using gateway")),
            }
        }
        self.fetch_via_gateway(uri, cid, idx).await
    }

    /// Record + manifest + per-chunk direct URLs. None if the object does not exist.
    pub async fn locate(&self, uri: &NearUri) -> Result<Option<Located>> {
        let resp = self.send(Method::GET, &Self::obj_path(uri), "mode=locate", Bytes::new()).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let loc: Located = Self::check(resp).await?.json().await?;
        verify_head(uri, &loc.head())?;
        let m = &loc.manifest;
        ensure!(
            loc.chunks.is_empty() || (loc.chunks.len() == m.chunks.len() && loc.chunks.iter().zip(&m.chunks).all(|(a, b)| a.cid == b.cid)),
            "gateway locate chunks do not match the manifest"
        );
        ensure!(m.chunks.len() as u64 == chunk_count(m.size, m.chunk_size), "manifest chunk count does not match size / chunk_size");
        Ok(Some(loc))
    }

    /// Upload a file with bounded memory and `self.parallelism` concurrent chunk uploads.
    pub async fn put_file(&self, path: impl AsRef<Path>, uri: &NearUri, opts: &PutOptions) -> Result<PointerRecord> {
        let path = path.as_ref();
        let f = tokio::fs::File::open(path).await.with_context(|| format!("opening {}", path.display()))?;
        self.put_reader(f, uri, opts).await
    }

    /// Upload everything `reader` yields (size need not be known up front).
    pub async fn put_reader<R: AsyncRead + Unpin + Send>(&self, mut reader: R, uri: &NearUri, opts: &PutOptions) -> Result<PointerRecord> {
        NearUri::object(&uri.namespace, &uri.path)?;
        let sealer = if opts.public {
            Sealer::Plain
        } else {
            let mut rs = Vec::new();
            if let Some(root) = &self.root {
                rs.push(crypto::Recipient::Owner(root));
            }
            for k in &opts.share_with {
                rs.push(crypto::Recipient::X25519(crypto::parse_x25519(k)?));
            }
            ensure!(!rs.is_empty(), "no root key loaded and no share_with recipients; run `near drive keygen` or use --public");
            Sealer::Enc(Arc::new(ChunkSealer::new(&rs)?))
        };
        let cs = self.chunk_size;
        ensure!(cs > 0 && cs as u64 <= near_drive_core::manifest::MAX_CHUNK_BYTES, "bad chunk_size");
        let class = opts.class.as_deref();
        let ns = uri.namespace.as_str();
        // Repeated content (public data) yields repeated cids: upload each once.
        let seen = std::sync::Mutex::new(std::collections::HashSet::<String>::new());
        let seen = &seen;

        // (index, is_last, plaintext); one chunk of read-ahead to know `is_last`.
        let first = read_full(&mut reader, cs).await?;
        let pieces = stream::try_unfold((reader, Some(first), 0u64), move |(mut r, cur, idx)| async move {
            let Some(cur) = cur else { return Ok::<_, anyhow::Error>(None) };
            let next = if cur.len() < cs { Vec::new() } else { read_full(&mut r, cs).await? };
            let last = next.is_empty();
            Ok(Some(((idx, last, cur), (r, (!last).then_some(next), idx + 1))))
        });
        let refs: Vec<(ChunkRef, u64)> = pieces
            .map_ok(|(idx, last, pt)| {
                let sealer = sealer.clone();
                async move {
                    let plen = pt.len() as u64;
                    let (cid, ct) = tokio::task::spawn_blocking(move || -> Result<(String, Vec<u8>)> {
                        let ct = match sealer {
                            Sealer::Plain => pt,
                            Sealer::Enc(s) => s.seal(idx, last, &pt)?,
                        };
                        Ok((near_drive_core::cid(&ct), ct))
                    })
                    .await??;
                    if !seen.lock().unwrap().insert(cid.clone()) {
                        return Ok((ChunkRef { len: ct.len() as u64, cid }, plen));
                    }
                    Ok((self.upload_chunk(ns, cid, ct.into(), class).await?, plen))
                }
            })
            .try_buffered(self.parallelism.max(1))
            .try_collect()
            .await?;

        let size = refs.iter().map(|(_, l)| l).sum();
        let manifest = Manifest {
            version: 1,
            size,
            chunk_size: cs as u64,
            chunks: refs.into_iter().map(|(r, _)| r).collect(),
            enc: match &sealer {
                Sealer::Plain => None,
                Sealer::Enc(s) => Some(s.enc_info().clone()),
            },
            content_type: opts.content_type.clone(),
        };
        self.commit_manifest(uri, &manifest, class).await
    }

    fn opener(&self, m: &Manifest) -> Result<Opener> {
        Ok(match &m.enc {
            None => Opener::Plain,
            Some(enc) => {
                let root = self.root.as_ref().ok_or_else(|| anyhow!("object is encrypted and no root key is loaded"))?;
                Opener::Enc(Arc::new(ChunkOpener::new(root, enc)?))
            }
        })
    }

    /// Fetch + verify + decrypt chunk `idx` (decryption off the async runtime).
    async fn plain_chunk(&self, uri: &NearUri, loc: &Located, opener: &Opener, idx: usize) -> Result<Vec<u8>> {
        let ct = self.fetch_chunk(uri, loc, idx).await?;
        let m = &loc.manifest;
        let n = m.chunks.len();
        let expect = chunk_plain_len(m.size, m.chunk_size, idx as u64);
        let opener = opener.clone();
        let pt = tokio::task::spawn_blocking(move || match opener {
            Opener::Plain => Ok(ct.to_vec()),
            Opener::Enc(o) => o.open(idx as u64, idx + 1 == n, &ct),
        })
        .await??;
        ensure!(pt.len() as u64 == expect, "chunk {idx} has {} plaintext bytes, expected {expect}", pt.len());
        Ok(pt)
    }

    async fn locate_or_404(&self, uri: &NearUri) -> Result<Located> {
        self.locate(uri).await?.ok_or_else(|| anyhow!("{uri} not found"))
    }

    /// Download to `path` with parallel chunk fetches (direct URLs preferred).
    /// Writes `{path}.drive-part` and renames it into place when complete.
    pub async fn get_to_file(&self, uri: &NearUri, path: impl AsRef<Path>) -> Result<ObjectHead> {
        use std::os::unix::fs::FileExt;
        let path = path.as_ref().to_path_buf();
        let loc = self.locate_or_404(uri).await?;
        let opener = self.opener(&loc.manifest)?;
        let mut part = path.clone().into_os_string();
        part.push(".drive-part");
        let part = std::path::PathBuf::from(part);
        let file = std::fs::File::create(&part).with_context(|| format!("creating {}", part.display()))?;
        file.set_len(loc.manifest.size)?;
        let file = Arc::new(file);
        let cs = loc.manifest.chunk_size;
        let res: Result<()> = stream::iter(0..loc.manifest.chunks.len())
            .map(|i| {
                let (file, loc, opener) = (file.clone(), &loc, &opener);
                async move {
                    let pt = self.plain_chunk(uri, loc, opener, i).await?;
                    tokio::task::spawn_blocking(move || file.write_all_at(&pt, i as u64 * cs)).await??;
                    Ok(())
                }
            })
            .buffer_unordered(self.parallelism.max(1))
            .try_collect()
            .await;
        if let Err(e) = res {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        file.sync_all()?;
        std::fs::rename(&part, &path)?;
        Ok(loc.head())
    }

    /// Stream the object, in order, into `w` with bounded memory.
    pub async fn get_to_writer<W: AsyncWrite + Unpin>(&self, uri: &NearUri, w: W) -> Result<ObjectHead> {
        let loc = self.locate_or_404(uri).await?;
        self.write_range(uri, &loc, 0..loc.manifest.size, w).await?;
        Ok(loc.head())
    }

    /// Plaintext bytes `[range.start, min(range.end, size))`. Fetches and
    /// decrypts only the chunks overlapping the range.
    pub async fn get_range(&self, uri: &NearUri, range: Range<u64>) -> Result<Vec<u8>> {
        let loc = self.locate_or_404(uri).await?;
        let mut out = Vec::new();
        self.write_range(uri, &loc, range, &mut out).await?;
        Ok(out)
    }

    /// Stream plaintext bytes `[range.start, min(range.end, size))` of an
    /// already-located object into `w`, in order, with bounded memory. Lets
    /// callers that need the head first (e.g. to send response headers) read
    /// exactly the version they located.
    pub async fn write_range<W: AsyncWrite + Unpin>(&self, uri: &NearUri, loc: &Located, range: Range<u64>, mut w: W) -> Result<()> {
        let m = &loc.manifest;
        let (start, end) = (range.start.min(m.size), range.end.min(m.size));
        if start >= end {
            w.flush().await?;
            return Ok(());
        }
        let opener = self.opener(m)?;
        let cs = m.chunk_size;
        let (first, last) = ((start / cs) as usize, ((end - 1) / cs) as usize);
        let mut s = stream::iter(first..=last).map(|i| self.plain_chunk(uri, loc, &opener, i)).buffered(self.parallelism.max(1));
        let mut idx = first as u64;
        while let Some(pt) = s.try_next().await? {
            let base = idx * cs;
            let a = start.saturating_sub(base) as usize;
            let b = (end - base).min(pt.len() as u64) as usize;
            w.write_all(&pt[a..b]).await?;
            idx += 1;
        }
        w.flush().await?;
        Ok(())
    }
}

fn eprintln_debug(msg: &str) {
    if std::env::var_os("NEAR_DRIVE_DEBUG").is_some() {
        eprintln!("near-drive: {msg}");
    }
}
