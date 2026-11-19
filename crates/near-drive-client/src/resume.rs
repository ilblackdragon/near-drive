//! Upload journal: lets an interrupted [`crate::Client::put_file`] resume.
//!
//! One JSONL file per (account, URI, source file) under `PutOptions::resume_dir`:
//!
//! ```text
//! {"header": {... what was being uploaded, incl. the object's `enc` ...}}
//! {"i": 7, "ph": "<blake3 of chunk 7's plaintext>"}     before chunk 7 is sent (fsynced)
//! {"i": 7, "cid": "b3:...", "len": 4194320}            after the gateway stored it
//! ```
//!
//! Resuming reuses the object's key (`enc`, unwrapped with the owner's root
//! key), so identical plaintext re-encrypts to identical chunks and the ones
//! already stored are skipped. Sealing *different* plaintext under the same
//! chunk index would reuse a nonce, so a chunk is journaled with its
//! plaintext hash before it is ever sent, and on resume every journaled chunk
//! is checked against the file: any difference (the file changed) discards the
//! journal and the upload starts over with a fresh key.
use anyhow::{Context, Result};
use near_drive_core::{crypto::EncInfo, manifest::ChunkRef};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// What is being uploaded; a journal resumes only if all of it matches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JournalKey {
    pub account: String,
    pub uri: String,
    pub src: PathBuf,
    pub size: u64,
    pub mtime_ns: u64,
    pub chunk_size: u64,
    pub public: bool,
    pub class: Option<String>,
    pub share_with: Vec<String>,
    pub content_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    #[serde(flatten)]
    key: JournalKey,
    enc: Option<EncInfo>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Line {
    Header { header: Box<Header> },
    Done { i: u64, cid: String, len: u64 },
    Dispatched { i: u64, ph: String },
}

/// State recovered from an existing journal.
pub(crate) struct Resumed {
    pub enc: Option<EncInfo>,
    /// Chunk index -> plaintext hash, for every chunk that may have been sent.
    pub dispatched: HashMap<u64, String>,
    pub done: HashMap<u64, ChunkRef>,
}

pub(crate) fn journal_path(dir: &Path, key: &JournalKey) -> PathBuf {
    let id = blake3::hash(format!("{}\n{}\n{}", key.account, key.uri, key.src.display()).as_bytes());
    dir.join(format!("{}.jsonl", &id.to_hex()[..32]))
}

pub(crate) fn key_for(account: &str, uri: &str, src: &Path, chunk_size: u64, opts: &crate::PutOptions) -> Result<JournalKey> {
    let src = std::fs::canonicalize(src).with_context(|| format!("resolving {}", src.display()))?;
    let md = std::fs::metadata(&src)?;
    let mtime_ns = md.modified()?.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    Ok(JournalKey {
        account: account.to_string(),
        uri: uri.to_string(),
        src,
        size: md.len(),
        mtime_ns,
        chunk_size,
        public: opts.public,
        class: opts.class.clone(),
        share_with: opts.share_with.clone(),
        content_type: opts.content_type.clone(),
    })
}

/// Load a journal for exactly this upload; None if absent or for something else.
pub(crate) fn load(path: &Path, key: &JournalKey) -> Option<Resumed> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let Ok(Line::Header { header }) = serde_json::from_str(lines.next()?) else { return None };
    if header.key != *key {
        return None;
    }
    let mut r = Resumed { enc: header.enc, dispatched: HashMap::new(), done: HashMap::new() };
    // A torn final line (crash mid-write) fails to parse and is ignored.
    for l in lines {
        match serde_json::from_str(l) {
            Ok(Line::Dispatched { i, ph }) => {
                r.dispatched.insert(i, ph);
            }
            Ok(Line::Done { i, cid, len }) => {
                r.done.insert(i, ChunkRef { cid, len });
            }
            _ => {}
        }
    }
    // Only trust "done" for chunks whose plaintext hash was journaled first.
    r.done.retain(|i, _| r.dispatched.contains_key(i));
    Some(r)
}

/// Check every journaled chunk's plaintext hash against the file now.
pub(crate) fn file_unchanged(src: &Path, chunk_size: u64, r: &Resumed) -> Result<bool> {
    let f = std::fs::File::open(src)?;
    let len = f.metadata()?.len();
    let mut buf = vec![0u8; chunk_size as usize];
    for (&i, ph) in &r.dispatched {
        let n = near_drive_core::crypto::stream::chunk_plain_len(len, chunk_size, i) as usize;
        let b = &mut buf[..n];
        near_drive_core::fsx::read_exact_at(&f, b, i * chunk_size)?;
        if blake3::hash(b).to_hex().as_str() != ph {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn plain_hash(pt: &[u8]) -> String {
    blake3::hash(pt).to_hex().to_string()
}

pub(crate) struct Journal {
    pub path: PathBuf,
    file: std::sync::Mutex<std::fs::File>,
}

impl Journal {
    pub fn create(path: &Path, key: &JournalKey, enc: Option<EncInfo>) -> Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let mut f = std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let line = serde_json::to_string(&Line::Header { header: Box::new(Header { key: key.clone(), enc }) })?;
        writeln!(f, "{line}")?;
        f.sync_data()?;
        Ok(Self { path: path.to_path_buf(), file: std::sync::Mutex::new(f) })
    }

    pub fn append(path: &Path) -> Result<Self> {
        let f = std::fs::OpenOptions::new().append(true).open(path)?;
        Ok(Self { path: path.to_path_buf(), file: std::sync::Mutex::new(f) })
    }

    fn write(&self, line: &Line, sync: bool) -> Result<()> {
        let s = serde_json::to_string(line)?;
        let mut f = self.file.lock().unwrap();
        writeln!(f, "{s}")?;
        if sync {
            f.sync_data()?;
        }
        Ok(())
    }

    /// Before chunk `i` is sealed and sent: durable, so a resume can never
    /// seal different plaintext under this index.
    pub fn dispatched(&self, i: u64, ph: &str) -> Result<()> {
        self.write(&Line::Dispatched { i, ph: ph.to_string() }, true)
    }

    pub fn done(&self, i: u64, r: &ChunkRef) -> Result<()> {
        self.write(&Line::Done { i, cid: r.cid.clone(), len: r.len }, false)
    }

    pub fn finish(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
