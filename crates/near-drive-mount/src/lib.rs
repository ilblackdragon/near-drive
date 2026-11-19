//! NEAR Drive as a mounted drive, with files on demand.
//!
//! `mount()` shows a NEAR Drive prefix as a folder: the whole tree is listed,
//! but a file's bytes are downloaded only when it is opened, into a bounded
//! local cache (least recently used files are evicted). Writes go to a local
//! copy and are uploaded, end-to-end encrypted, when the file is closed.
//!
//! Platforms: Linux (FUSE, no extra library needed), macOS with macFUSE or
//! FUSE-T (`--features macfuse`), and Windows (Cloud Files API placeholders,
//! like OneDrive: the folder shows cloud icons and files download on open).
#[cfg(windows)]
mod cfapi;
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "macfuse")))]
mod fs;

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Where downloaded files are kept (plaintext; keep it on a private disk).
    pub cache_dir: PathBuf,
    /// Evict least recently used cached files above this size.
    pub cache_max_bytes: u64,
    /// Re-list the remote at most this often (also on change notifications).
    pub refresh: Duration,
    pub read_only: bool,
}

impl MountOptions {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self { cache_dir: cache_dir.into(), cache_max_bytes: 10 << 30, refresh: Duration::from_secs(5), read_only: false }
    }
}

/// Is mounting available in this build?
pub const SUPPORTED: bool = cfg!(any(windows, target_os = "linux", all(target_os = "macos", feature = "macfuse")));

#[cfg(windows)]
pub use cfapi::{mount, unregister, Mounted};

#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "macfuse")))]
pub use fs::{mount, Mounted};

#[cfg(not(any(windows, target_os = "linux", all(target_os = "macos", feature = "macfuse"))))]
pub struct Mounted;

#[cfg(not(any(windows, target_os = "linux", all(target_os = "macos", feature = "macfuse"))))]
impl Mounted {
    pub fn unmount(self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "linux", all(target_os = "macos", feature = "macfuse"))))]
pub fn mount(
    _client: std::sync::Arc<near_drive_client::Client>,
    _remote: near_drive_client::near_drive_core::NearUri,
    _mountpoint: &std::path::Path,
    _opts: MountOptions,
    _rt: tokio::runtime::Handle,
) -> anyhow::Result<Mounted> {
    if cfg!(target_os = "macos") {
        anyhow::bail!("this build has no mount support: install macFUSE or FUSE-T and build with `--features macfuse`, or use `near drive sync`")
    }
    anyhow::bail!("mounting is not available on this platform; use `near drive sync` (on Windows with --on-demand)")
}
