//! The local side: scanning the folder, names that are valid on this OS,
//! hashing, trash and conflicted copies.
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use unicode_normalization::UnicodeNormalization;

/// Folder for sync state, trash and temp files, inside the synced folder
/// (same filesystem, so moves are atomic renames). Never synced.
pub const META_DIR: &str = ".near-drive";

/// A file as found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub mtime_ns: u64,
}

pub fn stat(path: &Path) -> Result<Option<Stat>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(Some(Stat {
            size: m.len(),
            mtime_ns: m.modified()?.duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0),
        })),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Names never synced in either direction: editor/OS litter, partial
/// transfers, and our own metadata.
pub fn ignored(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name.starts_with(META_DIR)
        || name.ends_with(".drive-part")
        || name.ends_with(".drive-part.json")
        || name.ends_with(".drive-dl")
        || name.starts_with("~$")
        || name.starts_with(".~lock.")
        || matches!(lower.as_str(), ".ds_store" | "thumbs.db" | "desktop.ini" | ".directory")
        || lower.ends_with(".tmp")
        || lower.ends_with(".swp")
        || lower.ends_with(".crdownload")
        || lower.ends_with(".part")
}

/// Is `rel` (remote path relative to the synced prefix) usable as a local
/// path? `windows` selects the stricter Windows rules.
pub fn valid_local(rel: &str, windows: bool) -> Result<(), String> {
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err("empty, '.' or '..' path segment".into());
        }
        if ignored(seg) {
            return Err("ignored name".into());
        }
        if seg.chars().any(|c| c == '\0' || (windows && (c < ' ' || "<>:\"\\|?*".contains(c)))) {
            return Err(format!("{seg:?} has characters this OS does not allow in file names"));
        }
        if windows {
            if seg.ends_with('.') || seg.ends_with(' ') {
                return Err(format!("{seg:?} ends with a dot or space"));
            }
            let stem = seg.split('.').next().unwrap_or("").to_ascii_lowercase();
            if RESERVED.contains(&stem.as_str()) {
                return Err(format!("{seg:?} is a reserved name on Windows"));
            }
        }
    }
    Ok(())
}

/// Case-insensitive file systems (macOS, Windows by default): two remote
/// paths that differ only in case cannot both exist locally.
pub const CASE_INSENSITIVE: bool = cfg!(any(windows, target_os = "macos"));

pub fn fold(rel: &str) -> String {
    rel.to_lowercase()
}

/// `rel` ('/'-separated, NFC) under `root`.
pub fn local_path(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(rel.split('/'));
    p
}

/// A file found by [`scan`]. `path` is the real on-disk path, which can differ
/// from the relative name in Unicode normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFile {
    pub stat: Stat,
    pub path: PathBuf,
}

/// Every syncable file under `root`: relative path ('/'-separated, Unicode
/// NFC, so macOS's decomposed names match other devices) -> stat. Symlinks
/// and ignored names are skipped; names that are not UTF-8 are reported.
pub fn scan(root: &Path, skipped: &mut Vec<(String, String)>) -> Result<BTreeMap<String, LocalFile>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if dir == root => return Err(e).with_context(|| format!("reading {}", root.display())),
            Err(e) => {
                skipped.push((prefix.clone(), format!("cannot read folder: {e}")));
                continue;
            }
        };
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(|n| n.nfc().collect::<String>()) else {
                skipped.push((format!("{prefix}{}", e.file_name().to_string_lossy()), "name is not valid UTF-8".into()));
                continue;
            };
            if ignored(&name) {
                continue;
            }
            let rel = format!("{prefix}{name}");
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push((e.path(), format!("{rel}/")));
            } else if ft.is_file() {
                if let Some(stat) = stat(&e.path())? {
                    out.insert(rel, LocalFile { stat, path: e.path() });
                }
            }
        }
    }
    Ok(out)
}

/// BLAKE3 of a file's contents.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut h = blake3::Hasher::new();
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().to_hex().to_string())
}

/// `notes (conflicted copy from laptop 2026-11-19 210455).txt`
pub fn conflicted_name(rel: &str, host: &str, now: chrono::DateTime<chrono::Local>) -> String {
    let (dir, name) = match rel.rfind('/') {
        Some(i) => (&rel[..=i], &rel[i + 1..]),
        None => ("", rel),
    };
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    format!("{dir}{stem} (conflicted copy from {host} {}){ext}", now.format("%Y-%m-%d %H%M%S"))
}

/// Local time, as used in conflicted-copy names.
pub type Now = chrono::DateTime<chrono::Local>;

pub fn now() -> Now {
    chrono::Local::now()
}

pub fn host_name() -> String {
    for v in ["NEAR_DRIVE_DEVICE_NAME", "COMPUTERNAME", "HOSTNAME"] {
        if let Ok(h) = std::env::var(v) {
            if !h.trim().is_empty() {
                return h.trim().to_string();
            }
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    "this device".into()
}

/// Make `path`'s parent folders; fails if a file is in the way.
pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(p) = path.parent() {
        if p.is_file() {
            bail!("{} is a file, but a folder is needed there", p.display());
        }
        std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    }
    Ok(())
}

/// Remove folders left empty under `root`, walking up from `path`'s parent.
pub fn prune_empty_parents(root: &Path, path: &Path) {
    let mut cur = path.parent();
    while let Some(d) = cur {
        if d == root || !d.starts_with(root) || std::fs::remove_dir(d).is_err() {
            break;
        }
        cur = d.parent();
    }
}

/// Move a file into `<root>/.near-drive/trash/<timestamp>/<rel>` instead of
/// deleting it (remote deletes are permanent, so keep a local copy).
pub fn trash(root: &Path, rel: &str, src: &Path) -> Result<()> {
    let dst = local_path(&root.join(META_DIR).join("trash").join(chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()), rel);
    ensure_parent(&dst)?;
    std::fs::rename(src, &dst).with_context(|| format!("moving {} to the trash", src.display()))?;
    prune_empty_parents(root, src);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(ignored(".DS_Store") && ignored("Thumbs.db") && ignored("~$report.docx") && ignored("a.drive-part"));
        assert!(ignored(".near-drive") && !ignored("notes.txt") && !ignored(".bashrc"));
        assert!(valid_local("a/b.txt", true).is_ok());
        assert!(valid_local("a/con.txt", true).is_err() && valid_local("a/con.txt", false).is_ok());
        assert!(valid_local("what?.txt", true).is_err() && valid_local("what?.txt", false).is_ok());
        assert!(valid_local("trailing.", true).is_err());
        assert!(valid_local("a/../b", false).is_err() && valid_local("a//b", false).is_err());
    }

    #[test]
    fn conflict_names() {
        use chrono::TimeZone;
        let t = chrono::Local.with_ymd_and_hms(2026, 11, 19, 21, 4, 55).unwrap();
        assert_eq!(conflicted_name("docs/notes.txt", "laptop", t), "docs/notes (conflicted copy from laptop 2026-11-19 210455).txt");
        assert_eq!(conflicted_name("Makefile", "pc", t), "Makefile (conflicted copy from pc 2026-11-19 210455)");
        assert_eq!(conflicted_name(".env", "pc", t), ".env (conflicted copy from pc 2026-11-19 210455)");
    }

    #[test]
    fn scan_normalizes_and_skips() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("sub/deep")).unwrap();
        std::fs::write(d.path().join("sub/deep/x.txt"), "x").unwrap();
        std::fs::write(d.path().join("Cafe\u{301}.txt"), "nfd").unwrap(); // decomposed é
        std::fs::write(d.path().join(".DS_Store"), "").unwrap();
        std::fs::create_dir_all(d.path().join(META_DIR).join("trash")).unwrap();
        std::fs::write(d.path().join(META_DIR).join("state.json"), "{}").unwrap();
        let mut skipped = vec![];
        let s = scan(d.path(), &mut skipped).unwrap();
        assert_eq!(s.keys().cloned().collect::<Vec<_>>(), vec!["Caf\u{e9}.txt".to_string(), "sub/deep/x.txt".into()]);
    }
}
