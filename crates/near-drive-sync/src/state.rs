//! What the folder and the remote looked like after the last successful sync
//! of each file: the base of the three-way comparison.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Remote version.
    pub seq: u64,
    pub manifest_cid: String,
    /// Local file at that moment.
    pub size: u64,
    pub mtime_ns: u64,
    /// BLAKE3 of the content (tells a real edit from a touched mtime).
    pub hash: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// `near://<namespace>/<prefix>` this folder syncs with, and as whom.
    pub remote: String,
    pub account: String,
    pub files: BTreeMap<String, Entry>,
}

pub fn path(root: &Path) -> PathBuf {
    root.join(crate::local::META_DIR).join("state.json")
}

impl State {
    /// Load, or start empty. A folder already synced with another remote or
    /// account is refused rather than silently mixed.
    pub fn load(root: &Path, remote: &str, account: &str) -> Result<Self> {
        let p = path(root);
        match std::fs::read(&p) {
            Ok(b) => {
                let s: State = serde_json::from_slice(&b).with_context(|| format!("parsing {}", p.display()))?;
                if s.remote != remote || s.account != account {
                    bail!(
                        "{} is already synced with {} as {}; remove {} to sync it with {remote} instead",
                        root.display(),
                        s.remote,
                        s.account,
                        root.join(crate::local::META_DIR).display()
                    );
                }
                Ok(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State { version: 1, remote: remote.into(), account: account.into(), files: BTreeMap::new() }),
            Err(e) => Err(e.into()),
        }
    }

    /// Atomic replace (write a temp file, then rename).
    pub fn save(&self, root: &Path) -> Result<()> {
        let p = path(root);
        std::fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }
}
