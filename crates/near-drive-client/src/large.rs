//! Large objects: streaming upload/download with bounded memory, parallel
//! chunk transfers, direct (gateway-bypassing) chunk fetches via
//! `?mode=locate`, and byte-range reads.
//!
//! Memory use is about `(parallelism + 2) * chunk_size` regardless of object
//! size. The on-the-wire format is identical to [`Client::put`] / [`Client::get`].
use super::*;
use crate::resume;
use crate::net::{ok_or_attempt, transport, with_retries, Attempt};
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use near_drive_core::crypto::stream::{chunk_count, chunk_plain_len, ChunkOpener, ChunkSealer};
use std::{ops::Range, path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    /// The chunk itself (base64), inlined by the gateway for small objects so
    /// a small read takes one round trip. Verified against `cid` like any fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
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

/// An upload backed by a journal (see `resume.rs`).
struct JournalRun<'a> {
    journal: &'a resume::Journal,
    /// Chunks the gateway already stored in an earlier run.
    done: &'a std::collections::HashMap<u64, ChunkRef>,
    sealer: Sealer,
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

/// Which version a `.drive-part` file belongs to.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PartMeta {
    uri: String,
    manifest_cid: String,
    size: u64,
}

/// For each chunk: are the bytes at its offset in `f` exactly that chunk?
/// (Re-encrypt / hash them and compare with the manifest's cid.)
fn chunks_on_disk(f: &std::fs::File, m: &Manifest, opener: &Opener) -> Result<Vec<bool>> {
    let n = m.chunks.len();
    let mut buf = vec![0u8; m.chunk_size as usize];
    (0..n)
        .map(|i| {
            let len = chunk_plain_len(m.size, m.chunk_size, i as u64) as usize;
            let b = &mut buf[..len];
            near_drive_core::fsx::read_exact_at(f, b, i as u64 * m.chunk_size)?;
            let cid = match opener {
                Opener::Plain => near_drive_core::cid(b),
                Opener::Enc(o) => near_drive_core::cid(&o.reseal(i as u64, i + 1 == n, b)?),
            };
            Ok(cid == m.chunks[i].cid)
        })
        .collect()
}

impl Client {
    /// Upload one already-encoded chunk (retries transient failures).
    pub(crate) async fn upload_chunk(&self, namespace: &str, cid: String, bytes: Bytes, class: Option<&str>) -> Result<ChunkRef> {
        let len = bytes.len() as u64;
        let path = format!("/v1/chunk/{namespace}/{cid}");
        let what = format!("upload chunk {cid}");
        with_retries(&self.net, &what, |_| {
            let bytes = bytes.clone();
            let path = &path;
            async move { ok_or_attempt(self.send_with(Method::PUT, path, "", bytes, class, 0).await).await }
        })
        .await?;
        Ok(ChunkRef { cid, len })
    }

    /// Fetch a chunk via the gateway (signed, retried), verifying its cid.
    /// `idx` goes into the (signed) query so that concurrent fetches of a
    /// repeated chunk never produce identical signatures (gateway replay cache).
    pub(crate) async fn fetch_via_gateway(&self, uri: &NearUri, cid: &str, idx: usize, len: u64) -> Result<Bytes> {
        let q = format!("chunk={cid}&i={idx}");
        let path = Self::obj_path(uri);
        let what = format!("fetch chunk {idx}");
        with_retries(&self.net, &what, |_| {
            let (q, path) = (&q, &path);
            async move {
                let resp = match ok_or_attempt(self.send_with(Method::GET, path, q, Bytes::new(), None, len).await).await {
                    Attempt::Done(r) => r,
                    Attempt::Retry(e, w) => return Attempt::Retry(e, w),
                    Attempt::Fatal(e) => return Attempt::Fatal(e),
                };
                match resp.bytes().await {
                    Ok(b) if near_drive_core::cid(&b) == cid => Attempt::Done(b),
                    // corrupted or truncated in transit: fetch again
                    Ok(_) => Attempt::Retry(anyhow!("chunk {cid} content does not match its id"), None),
                    Err(e) => transport(e.into()),
                }
            }
        })
        .await
    }

    /// Fetch chunk `idx` of a located object: inlined bytes, else the direct
    /// URL, else (or on any direct-fetch problem) the gateway.
    async fn fetch_chunk(&self, uri: &NearUri, loc: &Located, idx: usize) -> Result<Bytes> {
        let c = &loc.manifest.chunks[idx];
        let cid = &c.cid;
        if let Some(data) = loc.chunks.get(idx).and_then(|l| l.data.as_deref()) {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(data) {
                Ok(b) if near_drive_core::cid(&b) == *cid => return Ok(b.into()),
                _ => debug(&format!("inlined chunk {cid} is invalid; fetching it")),
            }
        }
        if let Some(url) = loc.direct_url(idx) {
            let r = self.http.get(url).timeout(self.net.timeout_for(c.len)).send().await;
            match r {
                Ok(resp) if resp.status() == StatusCode::OK => match resp.bytes().await {
                    Ok(b) if near_drive_core::cid(&b) == *cid => return Ok(b),
                    Ok(_) => debug(&format!("direct fetch of {cid} returned wrong content; using gateway")),
                    Err(e) => debug(&format!("direct fetch of {cid}: {e}; using gateway")),
                },
                Ok(resp) => debug(&format!("direct fetch of {cid}: HTTP {}; using gateway", resp.status())),
                Err(e) => debug(&format!("direct fetch of {cid}: {e}; using gateway")),
            }
        }
        self.fetch_via_gateway(uri, cid, idx, c.len).await
    }

    /// Record + manifest + per-chunk direct URLs. None if the object does not exist.
    pub async fn locate(&self, uri: &NearUri) -> Result<Option<Located>> {
        let Some(loc): Option<Located> = self.get_json("locate", &Self::obj_path(uri), "mode=locate").await? else { return Ok(None) };
        self.verify_read(uri, &loc.head()).await?;
        let m = &loc.manifest;
        ensure!(
            loc.chunks.is_empty() || (loc.chunks.len() == m.chunks.len() && loc.chunks.iter().zip(&m.chunks).all(|(a, b)| a.cid == b.cid)),
            "gateway locate chunks do not match the manifest"
        );
        ensure!(m.chunks.len() as u64 == chunk_count(m.size, m.chunk_size), "manifest chunk count does not match size / chunk_size");
        Ok(Some(loc))
    }

    /// Upload a file with bounded memory and `self.parallelism` concurrent
    /// chunk uploads. With `opts.resume_dir`, an interrupted upload of the same
    /// file to the same URI resumes where it stopped (see `resume.rs`).
    pub async fn put_file(&self, path: impl AsRef<Path>, uri: &NearUri, opts: &PutOptions) -> Result<PointerRecord> {
        let path = path.as_ref();
        let f = tokio::fs::File::open(path).await.with_context(|| format!("opening {}", path.display()))?;
        let Some(dir) = &opts.resume_dir else { return self.put_stream(f, uri, opts, None).await };
        // Resuming an encrypted upload needs the owner's key to recover the object key.
        if !opts.public && (self.root.is_none() || opts.skip_owner_key) {
            return self.put_stream(f, uri, opts, None).await;
        }
        let key = resume::key_for(&self.account, &uri.to_string(), path, self.chunk_size as u64, opts)?;
        let jpath = resume::journal_path(dir, &key);
        let resumed = match resume::load(&jpath, &key) {
            Some(r) => {
                let (src, cs) = (key.src.clone(), key.chunk_size);
                let r = tokio::task::spawn_blocking(move || resume::file_unchanged(&src, cs, &r).map(|ok| ok.then_some(r))).await??;
                if r.is_none() {
                    debug("file changed since the interrupted upload; starting over");
                }
                r
            }
            None => None,
        };
        let (sealer, journal, done) = match resumed {
            Some(r) => {
                let sealer = match &r.enc {
                    None => Sealer::Plain,
                    Some(enc) => Sealer::Enc(Arc::new(ChunkSealer::reopen(self.root.as_ref().expect("checked"), enc)?)),
                };
                if !r.done.is_empty() {
                    debug(&format!("resuming upload of {uri}: {} chunks already stored", r.done.len()));
                }
                (sealer, resume::Journal::append(&jpath)?, r.done)
            }
            None => {
                let sealer = self.new_sealer(opts)?;
                let enc = match &sealer {
                    Sealer::Plain => None,
                    Sealer::Enc(s) => Some(s.enc_info().clone()),
                };
                (sealer, resume::Journal::create(&jpath, &key, enc)?, Default::default())
            }
        };
        let jr = JournalRun { journal: &journal, done: &done, sealer };
        let rec = self
            .put_stream(f, uri, opts, Some(jr))
            .await
            .with_context(|| format!("upload of {uri} interrupted; run it again to resume"))?;
        journal.finish();
        Ok(rec)
    }

    /// Upload everything `reader` yields (size need not be known up front).
    pub async fn put_reader<R: AsyncRead + Unpin + Send>(&self, reader: R, uri: &NearUri, opts: &PutOptions) -> Result<PointerRecord> {
        self.put_stream(reader, uri, opts, None).await
    }

    fn new_sealer(&self, opts: &PutOptions) -> Result<Sealer> {
        Ok(if opts.public {
            Sealer::Plain
        } else {
            Sealer::Enc(Arc::new(ChunkSealer::new(&self.recipients(opts)?)?))
        })
    }

    async fn put_stream<R: AsyncRead + Unpin + Send>(&self, mut reader: R, uri: &NearUri, opts: &PutOptions, jr: Option<JournalRun<'_>>) -> Result<PointerRecord> {
        NearUri::object(&uri.namespace, &uri.path)?;
        self.record_key()?;
        let (sealer, journal, done) = match jr {
            Some(j) => (j.sealer, Some(j.journal), Some(j.done)),
            None => (self.new_sealer(opts)?, None, None),
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
                    if let Some(r) = done.and_then(|d| d.get(&idx)) {
                        seen.lock().unwrap().insert(r.cid.clone());
                        return Ok((r.clone(), plen));
                    }
                    if let Some(j) = journal {
                        let ph = resume::plain_hash(&pt);
                        // small write + fdatasync; fine inline next to a chunk upload
                        j.dispatched(idx, &ph)?;
                    }
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
                    let r = self.upload_chunk(ns, cid, ct.into(), class).await?;
                    if let Some(j) = journal {
                        j.done(idx, &r)?;
                    }
                    Ok((r, plen))
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
        self.commit_manifest(uri, &manifest, class, opts.expect_seq).await
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
    ///
    /// Resumable: if a download fails, the part file and
    /// `{path}.drive-part.json` stay. The next call for the same version of the
    /// object checks every chunk already on disk (by re-deriving its cid from
    /// the bytes) and fetches only the missing or damaged ones.
    pub async fn get_to_file(&self, uri: &NearUri, path: impl AsRef<Path>) -> Result<ObjectHead> {
            let path = path.as_ref().to_path_buf();
        let loc = self.locate_or_404(uri).await?;
        let opener = self.opener(&loc.manifest)?;
        let suffixed = |s: &str| {
            let mut p = path.clone().into_os_string();
            p.push(s);
            std::path::PathBuf::from(p)
        };
        let (part, meta_path) = (suffixed(".drive-part"), suffixed(".drive-part.json"));
        let meta = PartMeta { uri: uri.to_string(), manifest_cid: loc.record.manifest_cid.clone(), size: loc.manifest.size };
        let resumable = part.exists() && std::fs::read(&meta_path).ok().and_then(|b| serde_json::from_slice::<PartMeta>(&b).ok()).is_some_and(|m| m == meta);
        let file = if resumable {
            std::fs::OpenOptions::new().read(true).write(true).open(&part)?
        } else {
            let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&part).with_context(|| format!("creating {}", part.display()))?;
            std::fs::write(&meta_path, serde_json::to_vec(&meta)?)?;
            f
        };
        file.set_len(loc.manifest.size)?;
        let file = Arc::new(file);
        let n = loc.manifest.chunks.len();
        let have: Vec<bool> = if resumable {
            let (f, m, o) = (file.clone(), loc.manifest.clone(), opener.clone());
            tokio::task::spawn_blocking(move || chunks_on_disk(&f, &m, &o)).await??
        } else {
            vec![false; n]
        };
        if resumable {
            debug(&format!("resuming download of {uri}: {}/{n} chunks already on disk", have.iter().filter(|h| **h).count()));
        }
        let cs = loc.manifest.chunk_size;
        let res: Result<()> = stream::iter((0..n).filter(|i| !have[*i]))
            .map(|i| {
                let (file, loc, opener) = (file.clone(), &loc, &opener);
                async move {
                    let pt = self.plain_chunk(uri, loc, opener, i).await?;
                    tokio::task::spawn_blocking(move || near_drive_core::fsx::write_all_at(&file, &pt, i as u64 * cs)).await??;
                    Ok(())
                }
            })
            .buffer_unordered(self.parallelism.max(1))
            .try_collect()
            .await;
        if let Err(e) = res {
            let _ = file.sync_data();
            return Err(e.context(format!("download of {uri} interrupted; partial data kept in {}, run it again to resume", part.display())));
        }
        file.sync_all()?;
        std::fs::rename(&part, &path)?;
        let _ = std::fs::remove_file(&meta_path);
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

/// Incremental upload: bytes arrive in pieces (e.g. S3 multipart parts), each
/// full chunk is sealed and uploaded right away, up to `parallelism` at once.
/// Memory stays around `(parallelism + 2) × chunk_size`; nothing touches disk.
/// The last chunk is held back so it can be sealed as the final one, so an
/// object is only committed by [`ObjectWriter::finish`].
pub struct ObjectWriter {
    client: Arc<Client>,
    uri: NearUri,
    opts: PutOptions,
    sealer: Sealer,
    chunk_size: usize,
    buf: Vec<u8>,
    next_idx: u64,
    size: u64,
    inflight: std::collections::VecDeque<tokio::task::JoinHandle<Result<(u64, ChunkRef)>>>,
    refs: Vec<(u64, ChunkRef)>,
}

impl ObjectWriter {
    /// Plaintext bytes accepted so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    pub async fn write(&mut self, mut data: &[u8]) -> Result<()> {
        let cs = self.chunk_size;
        while !data.is_empty() {
            // Keep up to one full chunk buffered: it may turn out to be the last.
            let room = (2 * cs).saturating_sub(self.buf.len()).max(1);
            let take = room.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            self.size += take as u64;
            data = &data[take..];
            while self.buf.len() > cs {
                let rest = self.buf.split_off(cs);
                let chunk = std::mem::replace(&mut self.buf, rest);
                self.spawn(chunk, false).await?;
            }
        }
        Ok(())
    }

    async fn spawn(&mut self, pt: Vec<u8>, last: bool) -> Result<()> {
        while self.inflight.len() >= self.client.parallelism.max(1) {
            let done = self.inflight.pop_front().expect("non-empty").await??;
            self.refs.push(done);
        }
        let idx = self.next_idx;
        self.next_idx += 1;
        let (client, sealer, ns, class) = (self.client.clone(), self.sealer.clone(), self.uri.namespace.clone(), self.opts.class.clone());
        self.inflight.push_back(tokio::spawn(async move {
            let (cid, ct) = tokio::task::spawn_blocking(move || -> Result<(String, Vec<u8>)> {
                let ct = match sealer {
                    Sealer::Plain => pt,
                    Sealer::Enc(s) => s.seal(idx, last, &pt)?,
                };
                Ok((near_drive_core::cid(&ct), ct))
            })
            .await??;
            let r = client.upload_chunk(&ns, cid, ct.into(), class.as_deref()).await?;
            Ok((idx, r))
        }));
        Ok(())
    }

    /// Seal the last chunk, wait for every upload, and commit the object.
    pub async fn finish(mut self) -> Result<PointerRecord> {
        let tail = std::mem::take(&mut self.buf);
        self.spawn(tail, true).await?;
        while let Some(h) = self.inflight.pop_front() {
            let done = h.await??;
            self.refs.push(done);
        }
        self.refs.sort_by_key(|(i, _)| *i);
        let manifest = Manifest {
            version: 1,
            size: self.size,
            chunk_size: self.chunk_size as u64,
            chunks: std::mem::take(&mut self.refs).into_iter().map(|(_, r)| r).collect(),
            enc: match &self.sealer {
                Sealer::Plain => None,
                Sealer::Enc(s) => Some(s.enc_info().clone()),
            },
            content_type: self.opts.content_type.clone(),
        };
        self.client.commit_manifest(&self.uri, &manifest, self.opts.class.as_deref(), self.opts.expect_seq).await
    }
}

impl Drop for ObjectWriter {
    fn drop(&mut self) {
        // Abandoned (not finished): stop uploads still running.
        for h in &self.inflight {
            h.abort();
        }
    }
}

impl Client {
    /// Start an incremental upload of `uri` (see [`ObjectWriter`]).
    pub fn writer(self: &Arc<Self>, uri: &NearUri, opts: &PutOptions) -> Result<ObjectWriter> {
        NearUri::object(&uri.namespace, &uri.path)?;
        self.record_key()?;
        let cs = self.chunk_size;
        ensure!(cs > 0 && cs as u64 <= near_drive_core::manifest::MAX_CHUNK_BYTES, "bad chunk_size");
        Ok(ObjectWriter {
            client: self.clone(),
            uri: uri.clone(),
            opts: opts.clone(),
            sealer: self.new_sealer(opts)?,
            chunk_size: cs,
            buf: Vec::with_capacity(cs),
            next_idx: 0,
            size: 0,
            inflight: Default::default(),
            refs: vec![],
        })
    }
}
