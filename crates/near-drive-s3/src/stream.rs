//! Streaming multipart uploads.
//!
//! Each upload has an [`ObjectSink`] that encrypts and uploads data as it
//! arrives. Parts that arrive in order (part 1, 2, 3, …, as S3 SDKs send them)
//! are written straight to the sink; a part that arrives ahead of its turn
//! (clients upload several parts concurrently) is staged on disk until the
//! parts before it are in, then streamed. Local disk use is therefore bounded
//! by the client's concurrency × part size, not by the object size.
//!
//! Requests never wait on each other: a part that finds another part being
//! written is staged and returns; whoever finishes writing drains the staged
//! successors.
//!
//! Limits: a part number can't be replaced with different bytes after it was
//! streamed (identical retries are fine), CompleteMultipartUpload can't leave
//! out a part that was already streamed, and an upload doesn't survive a
//! restart of the endpoint (the client gets NoSuchUpload and starts over).
use crate::backend::{BackendError, ObjectSink};
use crate::error::{S3Error, S3Result};
use crate::multipart::PartInfo;
use axum::http::StatusCode;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct State {
    /// Next part number to stream (after the last streamed one).
    next: u32,
    /// Someone is writing to the sink right now.
    busy: bool,
    streamed: Vec<PartInfo>,
    staged: BTreeMap<u32, (PathBuf, PartInfo)>,
    /// A chunk upload failed: the upload can't complete.
    failed: Option<String>,
    touched: std::time::Instant,
}

pub struct Session<S> {
    state: Mutex<State>,
    sink: tokio::sync::Mutex<Option<S>>,
    dir: PathBuf,
}

pub struct Sessions<S> {
    map: Mutex<HashMap<String, Arc<Session<S>>>>,
}

impl<S> Default for Sessions<S> {
    fn default() -> Self {
        Self { map: Mutex::default() }
    }
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    hex::encode(md5::Md5::digest(data))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn invalid_part(n: u32, why: &str) -> S3Error {
    S3Error::new(StatusCode::BAD_REQUEST, "InvalidPart", format!("Part {n}: {why}"))
}

fn backend_err(e: BackendError) -> S3Error {
    crate::map_backend(e)
}

impl<S: ObjectSink> Sessions<S> {
    pub fn start(&self, id: &str, sink: S, dir: PathBuf) {
        let s = Session {
            state: Mutex::new(State { next: 1, busy: false, streamed: vec![], staged: BTreeMap::new(), failed: None, touched: std::time::Instant::now() }),
            sink: tokio::sync::Mutex::new(Some(sink)),
            dir,
        };
        self.map.lock().unwrap().insert(id.to_string(), Arc::new(s));
    }

    fn get(&self, id: &str) -> S3Result<Arc<Session<S>>> {
        self.map.lock().unwrap().get(id).cloned().ok_or_else(S3Error::no_such_upload)
    }

    /// Forget uploads idle for longer than `max_age` (abandoned by their
    /// client); returns their ids so their staged parts can be removed.
    pub fn prune(&self, max_age: std::time::Duration) -> Vec<String> {
        let mut map = self.map.lock().unwrap();
        let old: Vec<String> = map
            .iter()
            .filter(|(_, s)| s.state.lock().map(|st| !st.busy && st.touched.elapsed() > max_age).unwrap_or(false))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &old {
            map.remove(id);
        }
        old
    }

    pub fn remove(&self, id: &str) {
        self.map.lock().unwrap().remove(id);
    }

    /// Accept part `n`; returns its ETag (MD5, as S3).
    pub async fn put_part(&self, id: &str, n: u32, data: Vec<u8>) -> S3Result<String> {
        let s = self.get(id)?;
        let etag = md5_hex(&data);
        let info = PartInfo { number: n, etag: etag.clone(), size: data.len() as u64, modified_ms: now_ms() };
        enum Turn {
            Write,
            Stage,
            Done(S3Result<String>),
        }
        let turn = {
            let mut st = s.state.lock().unwrap();
            st.touched = std::time::Instant::now();
            if let Some(e) = &st.failed {
                Turn::Done(Err(S3Error::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", format!("upload failed earlier: {e}"))))
            } else if let Some(p) = st.streamed.iter().find(|p| p.number == n) {
                // A retry of a part already streamed: fine if identical.
                Turn::Done(if p.etag == etag { Ok(etag.clone()) } else { Err(invalid_part(n, "already uploaded with different content; abort and start over")) })
            } else if n == st.next && !st.busy {
                st.busy = true;
                Turn::Write
            } else {
                Turn::Stage
            }
        };
        let first = match turn {
            Turn::Done(r) => return r,
            Turn::Write => Some((n, data, info)),
            Turn::Stage => {
                // Not its turn (or another part is being written): stage it.
                let path = s.dir.join(format!("{n:05}.part"));
                tokio::fs::write(&path, data).await?;
                let drain = {
                    let mut st = s.state.lock().unwrap();
                    st.staged.insert(n, (path, info));
                    // Nobody is writing and the next part is staged: we drain.
                    let d = !st.busy && st.staged.contains_key(&st.next);
                    if d {
                        st.busy = true;
                    }
                    d
                };
                if !drain {
                    return Ok(etag);
                }
                None
            }
        };
        self.drain(&s, first).await?;
        Ok(etag)
    }

    /// Write `first` (if any) and then every staged part that is next in line.
    async fn drain(&self, s: &Session<S>, mut item: Option<(u32, Vec<u8>, PartInfo)>) -> S3Result<()> {
        let mut sink = s.sink.lock().await;
        loop {
            let (n, data, info) = match item.take() {
                Some(x) => x,
                None => {
                    let next = {
                        let mut st = s.state.lock().unwrap();
                        let next = st.next;
                        match st.staged.remove(&next) {
                            Some(x) => x,
                            None => {
                                st.busy = false;
                                return Ok(());
                            }
                        }
                    };
                    let (path, info) = next;
                    let data = tokio::fs::read(&path).await?;
                    let _ = tokio::fs::remove_file(&path).await;
                    (info.number, data, info)
                }
            };
            let r = match sink.as_mut() {
                Some(w) => w.write(data).await.map_err(backend_err),
                None => Err(S3Error::no_such_upload()),
            };
            let failed = {
                let mut st = s.state.lock().unwrap();
                match r {
                    Ok(()) => {
                        st.streamed.push(info);
                        st.next = n + 1;
                        None
                    }
                    Err(e) => {
                        st.failed = Some(format!("{}: {}", e.code, e.message));
                        st.busy = false;
                        Some(e)
                    }
                }
            };
            if let Some(e) = failed {
                return Err(e);
            }
        }
    }

    /// Streamed and staged parts, by number.
    pub fn parts(&self, id: &str) -> S3Result<Vec<PartInfo>> {
        let s = self.get(id)?;
        let st = s.state.lock().unwrap();
        let mut v: Vec<PartInfo> = st.streamed.iter().cloned().chain(st.staged.values().map(|(_, i)| i.clone())).collect();
        v.sort_by_key(|p| p.number);
        Ok(v)
    }

    /// Commit the upload with exactly the listed parts (ascending, ETags match).
    pub async fn complete(&self, id: &str, wanted: &[(u32, String)]) -> S3Result<S> {
        let s = self.get(id)?;
        if wanted.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        if wanted.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(S3Error::new(StatusCode::BAD_REQUEST, "InvalidPartOrder", "The list of parts was not in ascending order."));
        }
        // Wait for a writer in progress (it drains everything that's in order).
        let mut sink = s.sink.lock().await;
        let todo = {
            let mut st = s.state.lock().unwrap();
            plan_completion(&mut st, wanted)?
        };
        let w = sink.as_mut().ok_or_else(S3Error::no_such_upload)?;
        for (path, info) in todo {
            let data = tokio::fs::read(&path).await?;
            w.write(data).await.map_err(backend_err)?;
            let _ = tokio::fs::remove_file(&path).await;
            let mut st = s.state.lock().unwrap();
            st.staged.remove(&info.number);
            st.streamed.push(info);
            drop(st);
        }
        let w = sink.take().ok_or_else(S3Error::no_such_upload)?;
        drop(sink);
        self.remove(id);
        Ok(w)
    }
}

/// Check the completed part list against what was streamed / staged and
/// return the staged parts still to write, in order.
fn plan_completion(st: &mut State, wanted: &[(u32, String)]) -> S3Result<Vec<(PathBuf, PartInfo)>> {
    if let Some(e) = &st.failed {
        return Err(S3Error::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", format!("upload failed earlier: {e}")));
    }
    // The streamed parts must be exactly the start of the list.
    if st.streamed.len() > wanted.len() {
        return Err(invalid_part(st.streamed[wanted.len()].number, "was uploaded but is not in the completed list"));
    }
    for (p, (n, et)) in st.streamed.iter().zip(wanted) {
        if p.number != *n || p.etag != *et {
            return Err(invalid_part(*n, "could not be found or its ETag does not match"));
        }
    }
    // The rest must be staged; they are streamed in list order.
    let mut todo = vec![];
    for (n, et) in &wanted[st.streamed.len()..] {
        match st.staged.get(n) {
            Some((path, info)) if info.etag == *et => todo.push((path.clone(), info.clone())),
            _ => return Err(invalid_part(*n, "could not be found or its ETag does not match")),
        }
    }
    st.busy = true;
    Ok(todo)
}
