//! The FUSE filesystem.
//!
//! - Tree: from `list(prefix)`, re-listed when older than `refresh` or after a
//!   change notification (`watch`). Inode numbers are stable per path.
//!   Folders exist implicitly (any file below them); `mkdir` makes local
//!   empty folders that exist until a file is put in them or they are removed.
//! - Reads: on open, the file's current version is downloaded into
//!   `cache_dir/<manifest id>` (verified, decrypted) unless already there.
//!   Listings are not verified, so a cached copy is reused only for a version
//!   this mount verified for that path (its own download or upload, or a
//!   verified head): a gateway cannot swap content between paths or roll a
//!   file back by reporting another manifest id in a listing.
//! - Writes: an open for writing works on a private copy; on close (flush /
//!   release) the copy is uploaded with `expect_seq` = the version it was
//!   based on. If someone else changed the file meanwhile, nothing is
//!   overwritten: the new content is uploaded as a "conflicted copy" next to it.
//! - Network calls never run while the tree lock is held.
use crate::MountOptions;
use anyhow::{Context, Result};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use near_drive_client::{near_drive_core::NearUri, Client, Conflict, PutOptions};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const ROOT: u64 = 1;

#[derive(Debug, Clone)]
struct Remote {
    size: u64,
    seq: u64,
    manifest_cid: String,
    mtime: SystemTime,
    /// `manifest_cid` is from a verified record for this path (not only from a listing).
    verified: bool,
}

#[derive(Debug, Clone)]
enum Kind {
    Dir,
    /// `remote` is None for a file created here and not uploaded yet.
    File { remote: Option<Remote>, size: u64 },
}

#[derive(Debug, Clone)]
struct Node {
    parent: u64,
    name: String,
    /// Path relative to the mounted prefix ("" for the root).
    path: String,
    kind: Kind,
}

struct Handle {
    ino: u64,
    file: Arc<File>,
    /// Private copy being written (None: reading the shared cache file).
    temp: Option<PathBuf>,
    dirty: bool,
}

struct Tree {
    nodes: HashMap<u64, Node>,
    by_path: HashMap<String, u64>,
    next_ino: u64,
    local_dirs: HashSet<String>,
    refreshed: Option<Instant>,
    handles: HashMap<u64, Handle>,
}

struct Fs {
    client: Arc<Client>,
    remote: NearUri,
    opts: MountOptions,
    rt: tokio::runtime::Handle,
    tree: Mutex<Tree>,
    stale: Arc<AtomicBool>,
    /// Inodes whose content changed remotely; the kernel's cached pages and
    /// attributes for them are dropped (outside request handlers).
    inval: tokio::sync::mpsc::UnboundedSender<u64>,
    next_fh: AtomicU64,
    uid: u32,
    gid: u32,
}

fn errno(e: &anyhow::Error) -> Errno {
    tracing::warn!("{e:#}");
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        if let Some(code) = io.raw_os_error() {
            return Errno::from_i32(code);
        }
    }
    Errno::EIO
}

fn parent_of(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..i])
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

impl Tree {
    fn ino_for(&mut self, path: &str, kind: Kind) -> u64 {
        if let Some(&i) = self.by_path.get(path) {
            if let Some(n) = self.nodes.get_mut(&i) {
                n.kind = kind;
            }
            return i;
        }
        let parent = if path.is_empty() { ROOT } else { self.ensure_dir(parent_of(path)) };
        let ino = self.next_ino;
        self.next_ino += 1;
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        self.nodes.insert(ino, Node { parent, name, path: path.to_string(), kind });
        self.by_path.insert(path.to_string(), ino);
        ino
    }

    fn ensure_dir(&mut self, path: &str) -> u64 {
        if path.is_empty() {
            return ROOT;
        }
        match self.by_path.get(path) {
            Some(&i) => i,
            None => self.ino_for(path, Kind::Dir),
        }
    }

    fn children(&self, dir: u64) -> Vec<(u64, &Node)> {
        let mut v: Vec<(u64, &Node)> = self.nodes.iter().filter(|(i, n)| n.parent == dir && **i != ROOT).map(|(i, n)| (*i, n)).collect();
        v.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        v
    }

    fn child(&self, dir: u64, name: &str) -> Option<u64> {
        let d = self.nodes.get(&dir)?;
        self.by_path.get(&join(&d.path, name)).copied()
    }

    fn remove(&mut self, ino: u64) {
        if let Some(n) = self.nodes.remove(&ino) {
            self.by_path.remove(&n.path);
            self.local_dirs.remove(&n.path);
        }
    }

    fn open_inos(&self) -> HashSet<u64> {
        self.handles.values().map(|h| h.ino).collect()
    }

    /// Replace the file set with a fresh listing, keeping inode numbers,
    /// local folders and files that are open or not uploaded yet.
    fn apply_listing(&mut self, files: HashMap<String, Remote>) -> Vec<u64> {
        let mut changed = vec![];
        let open = self.open_inos();
        let keep: Vec<u64> = self
            .nodes
            .iter()
            .filter(|(i, n)| {
                **i == ROOT
                    || open.contains(i)
                    || files.contains_key(&n.path)
                    || matches!(n.kind, Kind::File { remote: None, .. })
                    || (matches!(n.kind, Kind::Dir) && (self.local_dirs.contains(&n.path) || files.keys().any(|f| f.starts_with(&format!("{}/", n.path)))))
            })
            .map(|(i, _)| *i)
            .collect();
        let keep: HashSet<u64> = keep.into_iter().collect();
        let gone: Vec<u64> = self.nodes.keys().filter(|i| !keep.contains(i)).copied().collect();
        for i in gone {
            self.remove(i);
        }
        for (path, mut r) in files {
            let size = r.size;
            let ino = self.by_path.get(&path).copied();
            // An open, modified file keeps its local size until it is uploaded.
            if ino.is_some_and(|i| self.handles.values().any(|h| h.ino == i && h.dirty)) {
                continue;
            }
            let was = ino.and_then(|i| match &self.nodes.get(&i)?.kind {
                Kind::File { remote: Some(old), .. } => {
                    // Same version as one we verified: stays verified.
                    r.verified = old.verified && old.manifest_cid == r.manifest_cid && old.seq == r.seq;
                    Some(old.manifest_cid.clone())
                }
                _ => None,
            });
            let new_cid = r.manifest_cid.clone();
            let i = self.ino_for(&path, Kind::File { remote: Some(r), size });
            if was.is_some_and(|w| w != new_cid) {
                changed.push(i);
            }
        }
        self.refreshed = Some(Instant::now());
        changed
    }
}

impl Fs {
    fn uri(&self, path: &str) -> Result<NearUri> {
        Ok(NearUri::object(&self.remote.namespace, &format!("{}{path}", self.remote.path))?)
    }

    fn attr(&self, ino: u64, n: &Node, size_override: Option<u64>) -> FileAttr {
        let (kind, size, mtime, perm) = match &n.kind {
            Kind::Dir => (FileType::Directory, 0, UNIX_EPOCH, if self.opts.read_only { 0o555 } else { 0o755 }),
            Kind::File { remote, size } => (
                FileType::RegularFile,
                size_override.unwrap_or(*size),
                remote.as_ref().map_or_else(SystemTime::now, |r| r.mtime),
                if self.opts.read_only { 0o444 } else { 0o644 },
            ),
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Size of an open, modified copy (it wins over the remote size).
    fn live_size(&self, t: &Tree, ino: u64) -> Option<u64> {
        t.handles.values().find(|h| h.ino == ino && h.temp.is_some()).and_then(|h| h.file.metadata().ok()).map(|m| m.len())
    }

    /// Re-list the remote if the tree is old or a change was announced.
    fn refresh(&self, force: bool) {
        let due = {
            let t = self.tree.lock().unwrap();
            force || self.stale.swap(false, Ordering::SeqCst) || t.refreshed.is_none_or(|r| r.elapsed() >= self.opts.refresh)
        };
        if !due {
            return;
        }
        let listing = self.rt.block_on(self.client.list(&self.remote));
        match listing {
            Ok(entries) => {
                let files: HashMap<String, Remote> = entries
                    .into_iter()
                    .filter_map(|e| {
                        let rel = e.path.strip_prefix(&self.remote.path)?.to_string();
                        (!rel.is_empty() && !rel.ends_with('/') && !rel.split('/').any(|s| s.is_empty() || s == "." || s == "..")).then(|| {
                            let r = Remote { size: e.size, seq: e.seq, manifest_cid: e.manifest_cid.unwrap_or_default(), mtime: UNIX_EPOCH + Duration::from_millis(e.ts_ms), verified: false };
                            (rel, r)
                        })
                    })
                    .collect();
                let changed = self.tree.lock().unwrap().apply_listing(files);
                for i in changed {
                    let _ = self.inval.send(i);
                }
            }
            // Offline: keep showing what we know.
            Err(e) => tracing::warn!("listing {}: {e:#}", self.remote),
        }
    }

    fn cache_path(&self, manifest_cid: &str) -> PathBuf {
        self.opts.cache_dir.join(manifest_cid.trim_start_matches("b3:"))
    }

    /// The file's current content in the cache (downloading it if needed);
    /// returns the cache path and the version it holds.
    fn fetch(&self, ino: u64) -> Result<(PathBuf, Remote)> {
        let (path, remote) = {
            let t = self.tree.lock().unwrap();
            let n = t.nodes.get(&ino).context("no such file")?;
            match &n.kind {
                Kind::File { remote: Some(r), .. } => (n.path.clone(), r.clone()),
                Kind::File { remote: None, .. } => anyhow::bail!("not uploaded yet"),
                Kind::Dir => return Err(std::io::Error::from_raw_os_error(libc::EISDIR).into()),
            }
        };
        let uri = self.uri(&path)?;
        let set = |r: &Remote| {
            let mut t = self.tree.lock().unwrap();
            if let Some(n) = t.nodes.get_mut(&ino) {
                n.kind = Kind::File { remote: Some(r.clone()), size: r.size };
            }
        };
        let touch = |p: &Path| {
            let _ = File::options().write(true).open(p).and_then(|f| f.set_modified(SystemTime::now())); // LRU
        };
        let verified = |rec: &near_drive_client::near_drive_core::record::PointerRecord, size: u64| Remote {
            size,
            seq: rec.seq,
            manifest_cid: rec.manifest_cid.clone(),
            mtime: UNIX_EPOCH + Duration::from_millis(rec.ts_ms),
            verified: true,
        };
        let cached = self.cache_path(&remote.manifest_cid);
        if remote.verified && !remote.manifest_cid.is_empty() && cached.exists() {
            touch(&cached);
            return Ok((cached, remote));
        }
        // The version came from a listing: confirm it with a verified head
        // before serving a cached copy.
        if !remote.manifest_cid.is_empty() && cached.exists() {
            let head = self.rt.block_on(self.client.head(&uri))?.ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            let r = verified(&head.record, head.manifest.size);
            let cached = self.cache_path(&r.manifest_cid);
            if cached.exists() {
                touch(&cached);
                set(&r);
                return Ok((cached, r));
            }
        }
        std::fs::create_dir_all(self.opts.cache_dir.join("tmp"))?;
        let tmp = self.opts.cache_dir.join("tmp").join(format!("dl-{ino}-{}", self.next_fh.fetch_add(1, Ordering::SeqCst)));
        let head = self.rt.block_on(self.client.get_to_file(&uri, &tmp))?;
        let r = verified(&head.record, head.manifest.size);
        let dst = self.cache_path(&r.manifest_cid);
        std::fs::rename(&tmp, &dst)?;
        set(&r);
        self.evict();
        Ok((dst, r))
    }

    /// Keep the cache under `cache_max_bytes`: drop least recently used
    /// files that are not open.
    fn evict(&self) {
        let open: HashSet<PathBuf> = {
            let t = self.tree.lock().unwrap();
            t.handles.values().filter(|h| h.temp.is_none()).filter_map(|h| h.file.metadata().ok().map(|_| h.ino)).filter_map(|i| match &t.nodes.get(&i)?.kind {
                Kind::File { remote: Some(r), .. } => Some(self.cache_path(&r.manifest_cid)),
                _ => None,
            }).collect()
        };
        let Ok(rd) = std::fs::read_dir(&self.opts.cache_dir) else { return };
        let mut files: Vec<(SystemTime, u64, PathBuf)> = rd.flatten().filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| (m.modified().unwrap_or(UNIX_EPOCH), m.len(), e.path()))
        }).collect();
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        files.sort();
        for (_, len, p) in files {
            if total <= self.opts.cache_max_bytes {
                break;
            }
            if !open.contains(&p) && std::fs::remove_file(&p).is_ok() {
                total -= len;
            }
        }
    }

    /// A private, writable copy of the file (empty when truncating or new).
    fn writable_copy(&self, ino: u64, truncate: bool) -> Result<PathBuf> {
        std::fs::create_dir_all(self.opts.cache_dir.join("tmp"))?;
        let tmp = self.opts.cache_dir.join("tmp").join(format!("w-{ino}-{}", self.next_fh.fetch_add(1, Ordering::SeqCst)));
        let has_remote = matches!(self.tree.lock().unwrap().nodes.get(&ino).map(|n| &n.kind), Some(Kind::File { remote: Some(_), .. }));
        if truncate || !has_remote {
            File::create(&tmp)?;
        } else {
            let (src, _) = self.fetch(ino)?;
            std::fs::copy(src, &tmp)?;
        }
        Ok(tmp)
    }

    /// Upload a private copy as the new version of `ino`.
    fn upload(&self, ino: u64, tmp: &Path) -> Result<()> {
        let (path, base) = {
            let t = self.tree.lock().unwrap();
            let n = t.nodes.get(&ino).context("file vanished")?;
            let base = match &n.kind {
                Kind::File { remote, .. } => remote.as_ref().map_or(0, |r| r.seq),
                Kind::Dir => anyhow::bail!("is a folder"),
            };
            (n.path.clone(), base)
        };
        let opts = PutOptions { expect_seq: Some(base), ..Default::default() };
        let rec = match self.rt.block_on(self.client.put_file(tmp, &self.uri(&path)?, &opts)) {
            Ok(rec) => rec,
            Err(e) if e.downcast_ref::<Conflict>().is_some() => {
                // Changed elsewhere since we read it: keep both.
                let copy = near_drive_sync::local::conflicted_name(&path, &near_drive_sync::local::host_name(), near_drive_sync_now());
                tracing::warn!("{path} changed elsewhere; saved your version as {copy}");
                let rec = self.rt.block_on(self.client.put_file(tmp, &self.uri(&copy)?, &PutOptions { expect_seq: Some(0), ..Default::default() }))?;
                let size = std::fs::metadata(tmp)?.len();
                let mut t = self.tree.lock().unwrap();
                let r = Remote { size, seq: rec.seq, manifest_cid: rec.manifest_cid.clone(), mtime: SystemTime::now(), verified: true };
                t.ino_for(&copy, Kind::File { remote: Some(r), size });
                t.refreshed = None;
                drop(t);
                let _ = std::fs::copy(tmp, self.cache_path(&rec.manifest_cid));
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let size = std::fs::metadata(tmp)?.len();
        let _ = std::fs::copy(tmp, self.cache_path(&rec.manifest_cid));
        let mut t = self.tree.lock().unwrap();
        if let Some(n) = t.nodes.get_mut(&ino) {
            n.kind = Kind::File { remote: Some(Remote { size, seq: rec.seq, manifest_cid: rec.manifest_cid, mtime: SystemTime::now(), verified: true }), size };
        }
        t.local_dirs.retain(|d| !path.starts_with(&format!("{d}/")));
        Ok(())
    }

    /// Upload a handle's copy if it changed (on flush / release / fsync).
    fn commit(&self, fh: u64) -> Result<()> {
        let (ino, tmp) = {
            let mut t = self.tree.lock().unwrap();
            let Some(h) = t.handles.get_mut(&fh) else { return Ok(()) };
            if !h.dirty {
                return Ok(());
            }
            h.dirty = false;
            (h.ino, h.temp.clone().context("not writable")?)
        };
        let r = self.upload(ino, &tmp);
        if r.is_err() {
            if let Some(h) = self.tree.lock().unwrap().handles.get_mut(&fh) {
                h.dirty = true; // try again on the next flush / release
            }
        }
        r
    }

    fn new_handle(&self, ino: u64, file: File, temp: Option<PathBuf>, dirty: bool) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        self.tree.lock().unwrap().handles.insert(fh, Handle { ino, file: Arc::new(file), temp, dirty });
        fh
    }

    fn delete_remote(&self, path: &str, remote: &Option<Remote>) -> Result<()> {
        if let Some(r) = remote {
            match self.rt.block_on(self.client.delete_if(&self.uri(path)?, r.seq)) {
                Ok(()) => {}
                Err(e) if e.downcast_ref::<near_drive_client::GatewayError>().is_some_and(|g| g.status == 404) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Move one file: copy its content to the new path, then delete the old.
    fn rename_file(&self, ino: u64, new_path: &str) -> Result<()> {
        let (old_path, remote) = {
            let t = self.tree.lock().unwrap();
            let n = t.nodes.get(&ino).context("no such file")?;
            match &n.kind {
                Kind::File { remote, .. } => (n.path.clone(), remote.clone()),
                Kind::Dir => anyhow::bail!("is a folder"),
            }
        };
        if remote.is_some() {
            let (src, _) = self.fetch(ino)?;
            let target_seq = {
                let t = self.tree.lock().unwrap();
                t.by_path.get(new_path).and_then(|i| match &t.nodes.get(i)?.kind {
                    Kind::File { remote: Some(r), .. } => Some(r.seq),
                    _ => None,
                })
            };
            let rec = self.rt.block_on(self.client.put_file(&src, &self.uri(new_path)?, &PutOptions { expect_seq: Some(target_seq.unwrap_or(0)), ..Default::default() }))?;
            self.delete_remote(&old_path, &remote)?;
            let size = std::fs::metadata(&src)?.len();
            let mut t = self.tree.lock().unwrap();
            if let Some(old) = t.by_path.get(new_path).copied() {
                t.remove(old);
            }
            t.remove(ino);
            t.ino_for(new_path, Kind::File { remote: Some(Remote { size, seq: rec.seq, manifest_cid: rec.manifest_cid, mtime: SystemTime::now(), verified: true }), size });
        } else {
            // Not uploaded yet (open, new): rename locally; the close uploads it under the new name.
            let mut t = self.tree.lock().unwrap();
            if let Some(old) = t.by_path.get(new_path).copied() {
                t.remove(old);
            }
            let parent = t.ensure_dir(parent_of(new_path));
            t.by_path.remove(&old_path);
            if let Some(n) = t.nodes.get_mut(&ino) {
                n.path = new_path.to_string();
                n.name = new_path.rsplit('/').next().unwrap_or("").to_string();
                n.parent = parent;
            }
            t.by_path.insert(new_path.to_string(), ino);
        }
        Ok(())
    }
}

fn near_drive_sync_now() -> near_drive_sync::local::Now {
    near_drive_sync::local::now()
}

fn name_str(name: &OsStr) -> Result<&str, Errno> {
    let s = name.to_str().ok_or(Errno::EINVAL)?;
    if s.is_empty() || s.contains('/') || s == "." || s == ".." {
        return Err(Errno::EINVAL);
    }
    Ok(s)
}

impl Filesystem for Fs {
    fn init(&mut self, _req: &Request, config: &mut fuser::KernelConfig) -> std::io::Result<()> {
        // open(O_TRUNC) arrives as one open with O_TRUNC, not truncate-then-open
        // (which would upload an empty version first).
        let _ = config.add_capabilities(fuser::InitFlags::FUSE_ATOMIC_O_TRUNC);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Ok(name) = name_str(name) else { return reply.error(Errno::ENOENT) };
        self.refresh(false);
        let t = self.tree.lock().unwrap();
        match t.child(parent.0, name) {
            Some(i) => {
                let n = &t.nodes[&i];
                reply.entry(&TTL, &self.attr(i, n, self.live_size(&t, i)), Generation(0))
            }
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino.0 == ROOT {
            self.refresh(false);
        }
        let t = self.tree.lock().unwrap();
        match t.nodes.get(&ino.0) {
            Some(n) => reply.attr(&TTL, &self.attr(ino.0, n, self.live_size(&t, ino.0))),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Some(size) = size {
            if self.opts.read_only {
                return reply.error(Errno::EROFS);
            }
            let open = fh.and_then(|fh| {
                let mut t = self.tree.lock().unwrap();
                let h = t.handles.get_mut(&fh.0).filter(|h| h.temp.is_some())?;
                h.dirty = true;
                Some(h.file.clone())
            });
            let r = match open {
                Some(f) => f.set_len(size).map_err(anyhow::Error::from),
                // truncate(2) without an open file: rewrite it now.
                None => (|| {
                    let tmp = self.writable_copy(ino.0, size == 0)?;
                    File::options().write(true).open(&tmp)?.set_len(size)?;
                    let r = self.upload(ino.0, &tmp);
                    let _ = std::fs::remove_file(&tmp);
                    r
                })(),
            };
            if let Err(e) = r {
                return reply.error(errno(&e));
            }
        }
        let t = self.tree.lock().unwrap();
        match t.nodes.get(&ino.0) {
            Some(n) => reply.attr(&TTL, &self.attr(ino.0, n, self.live_size(&t, ino.0))),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        if self.opts.read_only {
            return reply.error(Errno::EROFS);
        }
        let Ok(name) = name_str(name) else { return reply.error(Errno::EINVAL) };
        let mut t = self.tree.lock().unwrap();
        let Some(dir) = t.nodes.get(&parent.0).map(|n| n.path.clone()) else { return reply.error(Errno::ENOENT) };
        let path = join(&dir, name);
        if t.by_path.contains_key(&path) {
            return reply.error(Errno::EEXIST);
        }
        let ino = t.ino_for(&path, Kind::Dir);
        t.local_dirs.insert(path);
        let n = t.nodes[&ino].clone();
        reply.entry(&TTL, &self.attr(ino, &n, None), Generation(0));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.opts.read_only {
            return reply.error(Errno::EROFS);
        }
        let Ok(name) = name_str(name) else { return reply.error(Errno::ENOENT) };
        let found = {
            let t = self.tree.lock().unwrap();
            t.child(parent.0, name).and_then(|i| match &t.nodes[&i].kind {
                Kind::File { remote, .. } => Some((i, t.nodes[&i].path.clone(), remote.clone())),
                Kind::Dir => None,
            })
        };
        let Some((ino, path, remote)) = found else { return reply.error(Errno::ENOENT) };
        match self.delete_remote(&path, &remote) {
            Ok(()) => {
                self.tree.lock().unwrap().remove(ino);
                reply.ok()
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Ok(name) = name_str(name) else { return reply.error(Errno::ENOENT) };
        let mut t = self.tree.lock().unwrap();
        let Some(ino) = t.child(parent.0, name) else { return reply.error(Errno::ENOENT) };
        if !matches!(t.nodes[&ino].kind, Kind::Dir) {
            return reply.error(Errno::ENOTDIR);
        }
        if !t.children(ino).is_empty() {
            return reply.error(Errno::ENOTEMPTY);
        }
        t.remove(ino);
        reply.ok()
    }

    fn rename(&self, _req: &Request, parent: INodeNo, name: &OsStr, newparent: INodeNo, newname: &OsStr, _flags: RenameFlags, reply: ReplyEmpty) {
        if self.opts.read_only {
            return reply.error(Errno::EROFS);
        }
        let (Ok(name), Ok(newname)) = (name_str(name), name_str(newname)) else { return reply.error(Errno::EINVAL) };
        let plan = {
            let t = self.tree.lock().unwrap();
            let (Some(ino), Some(dst_dir)) = (t.child(parent.0, name), t.nodes.get(&newparent.0).map(|n| n.path.clone())) else {
                return reply.error(Errno::ENOENT);
            };
            let src = t.nodes[&ino].path.clone();
            let dst = join(&dst_dir, newname);
            if matches!(t.nodes[&ino].kind, Kind::Dir) {
                // A folder: move every file below it.
                let files: Vec<(u64, String)> = t
                    .nodes
                    .iter()
                    .filter(|(_, n)| matches!(n.kind, Kind::File { .. }) && n.path.starts_with(&format!("{src}/")))
                    .map(|(i, n)| (*i, format!("{dst}{}", &n.path[src.len()..])))
                    .collect();
                let dirs: Vec<String> = t.local_dirs.iter().filter(|d| **d == src || d.starts_with(&format!("{src}/"))).map(|d| format!("{dst}{}", &d[src.len()..])).collect();
                (Some((ino, src, dst, dirs)), files)
            } else {
                (None, vec![(ino, dst)])
            }
        };
        let (dir, files) = plan;
        for (ino, dst) in files {
            if let Err(e) = self.rename_file(ino, &dst) {
                return reply.error(errno(&e));
            }
        }
        if let Some((ino, src, dst, dirs)) = dir {
            let mut t = self.tree.lock().unwrap();
            let gone: Vec<u64> = t.nodes.iter().filter(|(_, n)| n.path == src || n.path.starts_with(&format!("{src}/"))).map(|(i, _)| *i).filter(|i| *i != ino).collect();
            for g in gone {
                if matches!(t.nodes[&g].kind, Kind::Dir) {
                    t.remove(g);
                }
            }
            t.remove(ino);
            t.ensure_dir(&dst);
            for d in dirs {
                t.ensure_dir(&d);
                t.local_dirs.insert(d);
            }
            t.local_dirs.insert(dst);
        }
        reply.ok()
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let write = flags.acc_mode() != OpenAccMode::O_RDONLY;
        if write && self.opts.read_only {
            return reply.error(Errno::EROFS);
        }
        let r = if write {
            let truncate = flags.0 & libc::O_TRUNC != 0;
            self.writable_copy(ino.0, truncate).and_then(|tmp| {
                let f = File::options().read(true).write(true).open(&tmp)?;
                Ok(self.new_handle(ino.0, f, Some(tmp), truncate))
            })
        } else {
            // Open the newest version, even if the kernel answered the lookup from its cache.
            self.refresh(false);
            self.fetch(ino.0).and_then(|(p, _)| Ok(self.new_handle(ino.0, File::open(p)?, None, false)))
        };
        match r {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn read(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock: Option<LockOwner>, reply: ReplyData) {
        let Some(f) = self.tree.lock().unwrap().handles.get(&fh.0).map(|h| h.file.clone()) else { return reply.error(Errno::EBADF) };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let n = (size as u64).min(len.saturating_sub(offset)) as usize;
        let mut buf = vec![0u8; n];
        match near_drive_client::near_drive_core::fsx::read_exact_at(&f, &mut buf, offset) {
            Ok(()) => reply.data(&buf),
            Err(e) => reply.error(Errno::from(e)),
        }
    }

    fn write(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, offset: u64, data: &[u8], _wf: WriteFlags, _flags: OpenFlags, _lock: Option<LockOwner>, reply: ReplyWrite) {
        let f = {
            let mut t = self.tree.lock().unwrap();
            let Some(h) = t.handles.get_mut(&fh.0).filter(|h| h.temp.is_some()) else { return reply.error(Errno::EBADF) };
            h.dirty = true;
            h.file.clone()
        };
        match near_drive_client::near_drive_core::fsx::write_all_at(&f, data, offset) {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(Errno::from(e)),
        }
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _lock: LockOwner, reply: ReplyEmpty) {
        match self.commit(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.commit(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn release(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _flags: OpenFlags, _lock: Option<LockOwner>, _flush: bool, reply: ReplyEmpty) {
        let r = self.commit(fh.0);
        if let Some(h) = self.tree.lock().unwrap().handles.remove(&fh.0) {
            if let Some(tmp) = h.temp {
                let _ = std::fs::remove_file(tmp);
            }
        }
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        self.refresh(false);
        let t = self.tree.lock().unwrap();
        let Some(n) = t.nodes.get(&ino.0) else { return reply.error(Errno::ENOENT) };
        let mut entries: Vec<(u64, FileType, String)> = vec![(ino.0, FileType::Directory, ".".into()), (n.parent, FileType::Directory, "..".into())];
        for (i, c) in t.children(ino.0) {
            let kind = if matches!(c.kind, Kind::Dir) { FileType::Directory } else { FileType::RegularFile };
            entries.push((i, kind, c.name.clone()));
        }
        for (k, (i, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(i), (k + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        // Remote storage has no fixed size: report plenty of room.
        reply.statfs(1 << 40, 1 << 40, 1 << 40, 1 << 30, 1 << 30, 4096, 255, 4096);
    }

    fn create(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        if self.opts.read_only {
            return reply.error(Errno::EROFS);
        }
        let Ok(name) = name_str(name) else { return reply.error(Errno::EINVAL) };
        let r = (|| -> Result<(u64, u64, FileAttr)> {
            std::fs::create_dir_all(self.opts.cache_dir.join("tmp"))?;
            let ino = {
                let mut t = self.tree.lock().unwrap();
                let dir = t.nodes.get(&parent.0).map(|n| n.path.clone()).context("no such folder")?;
                let path = join(&dir, name);
                if let Some(&i) = t.by_path.get(&path) {
                    i // O_CREAT on an existing file: write over it
                } else {
                    t.ino_for(&path, Kind::File { remote: None, size: 0 })
                }
            };
            let tmp = self.opts.cache_dir.join("tmp").join(format!("w-{ino}-{}", self.next_fh.fetch_add(1, Ordering::SeqCst)));
            let f = File::options().read(true).write(true).create(true).truncate(true).open(&tmp)?;
            let fh = self.new_handle(ino, f, Some(tmp), true);
            let t = self.tree.lock().unwrap();
            let attr = self.attr(ino, &t.nodes[&ino], Some(0));
            Ok((ino, fh, attr))
        })();
        match r {
            Ok((_, fh, attr)) => reply.created(&TTL, &attr, Generation(0), FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(errno(&e)),
        }
    }
}

/// A mounted drive; unmounts on [`Mounted::unmount`] or drop.
pub struct Mounted {
    session: Option<fuser::BackgroundSession>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Mounted {
    pub fn unmount(mut self) -> Result<()> {
        self.stop.take();
        if let Some(s) = self.session.take() {
            s.umount_and_join()?;
        }
        Ok(())
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(s) = self.session.take() {
            let _ = s.umount_and_join();
        }
    }
}

/// Mount `remote` (a `near://<account>/<prefix>/`) at `mountpoint`.
pub fn mount(client: Arc<Client>, remote: NearUri, mountpoint: &Path, opts: MountOptions, rt: tokio::runtime::Handle) -> Result<Mounted> {
    anyhow::ensure!(remote.path.is_empty() || remote.path.ends_with('/'), "mount a folder: end the remote with /");
    std::fs::create_dir_all(&opts.cache_dir)?;
    let _ = std::fs::remove_dir_all(opts.cache_dir.join("tmp"));
    let stale = Arc::new(AtomicBool::new(true));
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let mut tree = Tree { nodes: HashMap::new(), by_path: HashMap::new(), next_ino: ROOT + 1, local_dirs: HashSet::new(), refreshed: None, handles: HashMap::new() };
    tree.nodes.insert(ROOT, Node { parent: ROOT, name: String::new(), path: String::new(), kind: Kind::Dir });
    tree.by_path.insert(String::new(), ROOT);
    let (inval_tx, mut inval_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
    let fs = Fs { client: client.clone(), remote: remote.clone(), opts: opts.clone(), rt: rt.clone(), tree: Mutex::new(tree), stale: stale.clone(), inval: inval_tx, next_fh: AtomicU64::new(1), uid, gid };
    let mut options = vec![MountOption::FSName(format!("near-drive:{remote}")), MountOption::Subtype("near-drive".into()), MountOption::NoDev, MountOption::NoSuid];
    options.push(if opts.read_only { MountOption::RO } else { MountOption::RW });
    let mut cfg = fuser::Config::default();
    cfg.mount_options = options;
    cfg.n_threads = Some(4);
    let session = fuser::spawn_mount(fs, mountpoint, &cfg).with_context(|| format!("mounting at {} (is FUSE available? Linux: fusermount3; macOS: macFUSE / FUSE-T)", mountpoint.display()))?;

    let notifier = session.notifier();
    rt.spawn(async move {
        while let Some(ino) = inval_rx.recv().await {
            let n = notifier.clone();
            // Blocking write to /dev/fuse: keep it off the async workers.
            let _ = tokio::task::spawn_blocking(move || n.inval_inode(INodeNo(ino), 0, -1)).await;
        }
    });
    // Change notifications mark the tree stale.
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    rt.spawn(async move {
        let mut cursor: Option<String> = None;
        loop {
            tokio::select! {
                _ = &mut stop_rx => return,
                r = client.watch(&remote, cursor.as_deref(), Duration::from_secs(25)) => match r {
                    Ok(Some(w)) => {
                        if w.changed {
                            stale.store(true, Ordering::SeqCst);
                        }
                        cursor = Some(w.cursor);
                    }
                    Ok(None) => return, // gateway without watch: the periodic re-list still runs
                    Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
                }
            }
        }
    });
    Ok(Mounted { session: Some(session), stop: Some(stop_tx) })
}
